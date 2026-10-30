import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest
import urllib.request

from spanwatch.capture import read_pcap
from spanwatch.hostnames import (Collector, clean, netbios_decode, parse_dhcp, resolve,
                                 rev_to_ip, hosts_text, Directory)
from spanwatch.server import App, serve
from spanwatch.session import Session
from spanwatch.store import Store
from tests import synth

MAC_H = bytes.fromhex("8caa00112233")
MAC_R = bytes.fromhex("a04a5b000001")
BCAST = b"\xff" * 6
MDNS_MAC = bytes.fromhex("01005e0000fb")


def frame(dst_mac, src_mac, payload, et=0x0800):
    return dst_mac + src_mac + struct.pack("!H", et) + payload


def dhcp(op, mtype, mac, ciaddr="0.0.0.0", yiaddr="0.0.0.0", opts=b""):
    p = struct.pack("!BBBBIHH4s4s4s4s", op, 1, 6, 0, 0x1234, 0, 0x8000,
                    socket.inet_aton(ciaddr), socket.inet_aton(yiaddr),
                    b"\0" * 4, b"\0" * 4)
    p += mac + b"\0" * 10 + b"\0" * 64 + b"\0" * 128 + b"\x63\x82\x53\x63"
    p += bytes([53, 1, mtype]) + opts + b"\xff"
    return p


def opt(code, val):
    return bytes([code, len(val)]) + val


def nb_encode(name, suffix=0):
    raw = name.upper().ljust(15)[:15].encode() + bytes([suffix])
    return "".join(chr(65 + (b >> 4)) + chr(65 + (b & 15)) for b in raw)


def nbns_registration(name, ip, group=False):
    hdr = struct.pack("!HHHHHH", 0x55, (5 << 11) | 0x0110, 1, 0, 0, 1)
    q = synth.qname(nb_encode(name)) + struct.pack("!HH", 0x20, 1)
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 0x20, 1, 300000, 6)
    rr += struct.pack("!H", 0x8000 if group else 0) + socket.inet_aton(ip)
    return hdr + q + rr


def mdns_response(records):
    """records: (name, type, rdata)"""
    msg = struct.pack("!HHHHHH", 0, 0x8400, 0, len(records), 0, 0)
    for name, typ, rd in records:
        msg += synth.qname(name) + struct.pack("!HHIH", typ, 0x8001, 120, len(rd)) + rd
    return msg


def arp(mac, ip):
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac + socket.inet_aton(ip) + b"\0" * 6 + socket.inet_aton("192.168.1.1")


def lan_frames():
    H, R = "192.168.1.77", "192.168.1.1"
    fr = []
    # DHCP DISCOVER (no ip), REQUEST (requested ip), ACK from server
    fr.append(frame(BCAST, MAC_H, synth.ipv4("0.0.0.0", "255.255.255.255", 17, synth.udp(68, 67,
        dhcp(1, 1, MAC_H, opts=opt(12, b"JoBook Pro"))))))
    fr.append(frame(BCAST, MAC_H, synth.ipv4("0.0.0.0", "255.255.255.255", 17, synth.udp(68, 67,
        dhcp(1, 3, MAC_H, opts=opt(50, socket.inet_aton(H)) + opt(12, b"JoBook Pro"))))))
    fr.append(frame(MAC_H, MAC_R, synth.ipv4(R, H, 17, synth.udp(67, 68, dhcp(2, 5, MAC_H, yiaddr=H)))))
    # mDNS: the same host announces itself (A + reverse PTR), plus a sleep-proxy record for another host
    fr.append(frame(MDNS_MAC, MAC_H, synth.ipv4(H, "224.0.0.251", 17, synth.udp(5353, 5353, mdns_response([
        ("JoBook-Pro.local", 1, socket.inet_aton(H)),
        ("77.1.168.192.in-addr.arpa", 12, synth.qname("JoBook-Pro.local")),
        ("printer.local", 1, socket.inet_aton("192.168.1.40")),
        ("_ipp._tcp.local", 12, synth.qname("Printer._ipp._tcp.local")),
    ])))))
    # NetBIOS registration from a Windows box + a group name that must be ignored
    fr.append(frame(BCAST, bytes.fromhex("001122334455"), synth.ipv4("192.168.1.90", "192.168.1.255", 17,
        synth.udp(137, 137, nbns_registration("DESKTOP-ABC", "192.168.1.90")))))
    fr.append(frame(BCAST, bytes.fromhex("001122334455"), synth.ipv4("192.168.1.90", "192.168.1.255", 17,
        synth.udp(137, 137, nbns_registration("WORKGROUP", "192.168.1.90", group=True)))))
    # ARP from the Windows box
    fr.append(frame(BCAST, bytes.fromhex("001122334455"), arp(bytes.fromhex("001122334455"), "192.168.1.90"), et=0x0806))
    # reverse DNS answered by the router for a LAN address; and one for a public address (ignored)
    fr.append(synth.eth(synth.ipv4(R, H, 17, synth.udp(53, 50000, synth.dns_response(
        5, "50.1.168.192.in-addr.arpa", 12, [(12, synth.qname("tv.lan"))])))))
    fr.append(synth.eth(synth.ipv4(R, H, 17, synth.udp(53, 50001, synth.dns_response(
        6, "8.8.8.8.in-addr.arpa", 12, [(12, synth.qname("dns.google"))])))))
    # LLMNR answer
    fr.append(synth.eth(synth.ipv4("192.168.1.91", H, 17, synth.udp(5355, 50002, synth.dns_response(
        7, "nas", 1, [synth.a("192.168.1.91")])))))
    return fr


class UnitTests(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(clean("JoBook Pro.local."), "JoBook-Pro")
        self.assertEqual(clean("tv.lan"), "tv")
        self.assertEqual(clean("localhost"), "")
        self.assertEqual(clean("_ipp._tcp"), "")
        self.assertEqual(clean("bad name/with slash"), "")

    def test_rev(self):
        self.assertEqual(rev_to_ip("4.3.2.1.in-addr.arpa"), "1.2.3.4")
        six = ".".join(reversed("20010db8000000000000000000000001")) + ".ip6.arpa"
        self.assertEqual(rev_to_ip(six), "2001:db8::1")
        self.assertIsNone(rev_to_ip("example.com"))

    def test_netbios(self):
        self.assertEqual(netbios_decode(nb_encode("DESKTOP-ABC")), ("DESKTOP-ABC", 0))
        self.assertIsNone(netbios_decode("XYZ"))

    def test_dhcp_parse_and_garbage(self):
        d = parse_dhcp(dhcp(1, 3, MAC_H, opts=opt(50, socket.inet_aton("10.0.0.5")) + opt(12, b"box")))
        self.assertEqual((d["mac"], d["requested"], d["hostname"], d["type"]),
                         ("8c:aa:00:11:22:33", "10.0.0.5", "box", 3))
        fq = dhcp(1, 3, MAC_H, opts=opt(81, b"\x05\0\0" + synth.qname("laptop.corp.example")))
        self.assertEqual(parse_dhcp(fq)["fqdn"], "laptop.corp.example")
        good = dhcp(1, 1, MAC_H, opts=opt(12, b"x"))
        for n in range(len(good)):
            parse_dhcp(good[:n])
        c = Collector()
        for n in range(0, 400, 7):
            c.udp(bytearray(b"\xaa" * n + b"\0" * 20), "1.2.3.4", 5353, "5.6.7.8", 5353, 0, n, 1.0)
            c.udp(bytearray(b"\xaa" * n + b"\0" * 20), "1.2.3.4", 137, "5.6.7.8", 137, 0, n, 1.0)


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.s = Session(1, "test")
        for i, f in enumerate(lan_frames()):
            self.s.ingest(f, len(f), time.time() - 100 + i)
        obs, binds = self.s.host_rows()
        self.tab = resolve(obs, binds)

    def test_dhcp_mdns_agree(self):
        e = self.tab["192.168.1.77"]
        self.assertEqual(e["name"], "JoBook-Pro")
        self.assertEqual(e["conf"], 3)
        self.assertEqual(e["sources"], ["dhcp", "mdns"])
        self.assertEqual(e["mac"], "8c:aa:00:11:22:33")

    def test_others(self):
        self.assertEqual(self.tab["192.168.1.90"]["name"], "DESKTOP-ABC")
        self.assertEqual(self.tab["192.168.1.90"]["mac"], "00:11:22:33:44:55")
        self.assertEqual(self.tab["192.168.1.40"]["name"], "printer")       # sleep-proxy record, no mac
        self.assertEqual(self.tab["192.168.1.40"]["mac"], "")
        self.assertEqual(self.tab["192.168.1.50"]["name"], "tv")
        self.assertEqual(self.tab["192.168.1.91"]["conf"], 1)               # llmnr only
        self.assertNotIn("8.8.8.8", self.tab)
        self.assertFalse(any(e["name"].upper() == "WORKGROUP" for e in self.tab.values()))

    def test_text(self):
        txt = hosts_text(sorted(self.tab.values(), key=lambda r: r["ip"]))
        self.assertIn("192.168.1.77", txt)
        self.assertIn("JoBook-Pro", txt)
        self.assertNotIn("192.168.1.91", hosts_text(list(self.tab.values()), min_conf=2))


class ResolveTests(unittest.TestCase):
    def test_reassigned_address(self):
        now = time.time()
        obs = [("aa:aa:aa:aa:aa:01", "10.0.0.9", "old-phone", "dhcp", now - 500, now - 500, 1),
               ("aa:aa:aa:aa:aa:02", "", "new-laptop", "dhcp", now - 10, now - 10, 1)]
        binds = [("aa:aa:aa:aa:aa:01", "10.0.0.9", "dhcp", now - 500, now - 500, 1),
                 ("aa:aa:aa:aa:aa:02", "10.0.0.9", "arp", now - 5, now - 5, 1)]
        t = resolve(obs, binds, now)
        self.assertEqual(t["10.0.0.9"]["name"], "new-laptop")
        self.assertEqual(t["mac:aa:aa:aa:aa:aa:01"]["name"], "old-phone")

    def test_mac_only_and_stale(self):
        now = time.time()
        t = resolve([("aa:aa:aa:aa:aa:03", "", "lonely", "dhcp", now, now, 1),
                     ("", "10.0.0.4", "ancient", "mdns", 0, 1, 1)], [], now)
        self.assertIn("mac:aa:aa:aa:aa:aa:03", t)
        self.assertNotIn("10.0.0.4", t)

    def test_file_wins_and_uppercase_loses(self):
        now = time.time()
        obs = [("", "10.0.0.5", "DESKTOP-X", "netbios", now, now, 9),
               ("", "10.0.0.5", "desktop-x", "mdns", now, now, 1),
               ("", "10.0.0.6", "garbage", "mdns", now, now, 1),
               ("", "10.0.0.6", "fileserver", "file", now, now, 1)]
        t = resolve(obs, [], now)
        self.assertEqual(t["10.0.0.5"]["name"], "desktop-x")
        self.assertEqual(t["10.0.0.5"]["conf"], 3)
        self.assertEqual(t["10.0.0.6"]["name"], "fileserver")
        self.assertEqual(t["10.0.0.6"]["alts"], ["garbage"])


class StoreHttpTests(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            pcap = os.path.join(d, "lan.pcap")
            synth.write_pcap(pcap, lan_frames() + synth.sample_frames(), t0=time.time() - 60)
            st = Store(os.path.join(d, "x.db"))
            s = Session(st.next_id(), "pcap")
            read_pcap(pcap, s)
            st.save(s)
            st.save(s)  # idempotent-ish: upsert, hits accumulate
            obs, _ = st.host_rows()
            self.assertTrue(any(o[2] == "JoBook-Pro" and o[6] >= 2 for o in obs))
            hf = os.path.join(d, "hosts")
            with open(hf, "w") as fh:
                fh.write("# overrides\n192.168.1.40  laser-printer  # comment\n")
            app = App(st, "definitely-not-an-iface0", hosts_file=hf)
            httpd = serve(app, "127.0.0.1", 0)
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                get = lambda p: urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, p)).read()
                h = json.loads(get("/api/hosts"))
                by = {r["ip"]: r for r in h["rows"]}
                self.assertEqual(by["192.168.1.40"]["name"], "laser-printer")
                self.assertEqual(by["192.168.1.77"]["name"], "JoBook-Pro")
                self.assertEqual(len(json.loads(get("/api/hosts?q=desktop"))["rows"]), 1)
                txt = get("/api/hosts.txt").decode()
                self.assertIn("laser-printer", txt)
                self.assertIn("ip,name,conf", get("/api/hosts.csv").decode())
                flows = json.loads(get("/api/sessions/%d/flows?limit=5000" % s.id))["rows"]
                self.assertTrue(any(f["client_host"] == "JoBook-Pro" for f in flows))
                q = json.loads(get("/api/sessions/%d/flows?q=jobook" % s.id))
                self.assertGreater(q["total"], 0)
                dns = json.loads(get("/api/sessions/%d/dns" % s.id))["rows"]
                self.assertTrue(any(x["client_host"] == "JoBook-Pro" for x in dns))
                g = json.loads(get("/api/sessions/%d/graph" % s.id))
                self.assertTrue(any(n["host"] == "JoBook-Pro" for n in g["nodes"]))
                summ = json.loads(get("/api/sessions/%d" % s.id))
                self.assertTrue(any(t["host"] for t in summ["insights"]["talkers"]))
            finally:
                httpd.shutdown()


if __name__ == "__main__":
    unittest.main()
