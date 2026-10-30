import json
import os
import tempfile
import threading
import unittest
import urllib.request

from spanwatch.capture import read_pcap
from spanwatch.parse import parse_frame, parse_dns, KIND_IP, KIND_L2
from spanwatch.server import App, serve, dns_line
from spanwatch.session import Session
from spanwatch.store import Store
from tests import synth


def frame(f):
    return parse_frame(f, len(f))


class ParseTests(unittest.TestCase):
    def test_tcp_v4(self):
        p = frame(synth.eth(synth.ipv4("10.0.0.1", "10.0.0.2", 6, synth.tcp(1234, 80, 0x02))))
        self.assertEqual(p[:6], (KIND_IP, "10.0.0.1", "10.0.0.2", 6, 1234, 80))
        self.assertEqual(p[7], 0x02)

    def test_vlan_and_l2(self):
        p = frame(synth.eth(synth.ipv4("10.0.0.1", "10.0.0.2", 17, synth.udp(1, 2)), vlan=5))
        self.assertEqual(p[4:6], (1, 2))
        self.assertEqual(frame(synth.eth(b"\0" * 28, et=0x0806))[:2], (KIND_L2, 0x0806))
        self.assertIsNone(frame(b"\0" * 5))

    def test_ipv6(self):
        p = frame(synth.eth(synth.ipv6("2001:db8::1", "2001:db8::2", 17, synth.udp(5, 53)), et=0x86DD))
        self.assertEqual(p[1:6], ("2001:db8::1", "2001:db8::2", 17, 5, 53))

    def test_fragment_has_no_ports(self):
        p = frame(synth.eth(synth.ipv4("1.1.1.1", "2.2.2.2", 17, b"x" * 20, frag=10)))
        self.assertEqual(p[4:6], (None, None))

    def test_truncated_frames_dont_raise(self):
        f = synth.eth(synth.ipv4("10.0.0.1", "10.0.0.2", 6, synth.tcp(1, 2, 0x10, b"abc")))
        for n in range(len(f)):
            parse_frame(f, n)

    def test_dns(self):
        r = parse_dns(synth.dns_response(1, "a.example", 1, [synth.cname("b.example"), synth.a("1.2.3.4"), synth.aaaa("2001:db8::9")]))
        self.assertEqual(r["qname"], "a.example")
        self.assertEqual(r["answers"], ["CNAME b.example", "1.2.3.4", "2001:db8::9"])
        self.assertEqual(r["ips"], ["1.2.3.4", "2001:db8::9"])

    def test_dns_garbage(self):
        for blob in (b"", b"\0" * 11, b"\xff" * 40, synth.dns_query(1, "x.y")[:-3]):
            parse_dns(blob)  # must not raise


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.s = Session(1, "test")
        for f in synth.sample_frames():
            self.s.ingest(f, len(f), 1.0)
        self.s.finish()
        self.flows = {(f["client"], f["server"], f["proto"], f["port"]): f for f in self.s.flow_rows()}

    def test_ephemeral_ports_folded(self):
        f = self.flows[("192.168.1.50", "93.184.216.34", "TCP", 443)]
        self.assertEqual((f["pkts_cs"], f["pkts_sc"]), (4, 4))
        self.assertEqual(f["server_name"], "www.example.com")  # passive DNS

    def test_syn_orientation_beats_port_heuristic(self):
        self.assertIn(("192.168.1.50", "192.168.1.9", "TCP", 50505), self.flows)

    def test_icmp_echo_pairs(self):
        f = self.flows[("192.168.1.50", "192.168.1.1", "ICMP", 8)]
        self.assertEqual((f["pkts_cs"], f["pkts_sc"]), (1, 1))

    def test_dns_log(self):
        d = {e["qname"]: e for e in self.s.dns_rows()}
        self.assertEqual(d["www.example.com"]["answers"][1:], ["93.184.216.34", "93.184.216.35"])
        self.assertEqual(d["www.example.com"]["client"], "192.168.1.50")
        self.assertEqual(d["www.example.com"]["resolver"], "192.168.1.1")
        self.assertEqual(d["nope.invalid"]["rcode"], "NXDOMAIN")
        self.assertEqual(d["lost.example"]["rcode"], "NO-RESPONSE")
        self.assertEqual(d["lost.example"]["qtype"], "AAAA")
        self.assertIn("192.168.1.50 -> 192.168.1.1  A www.example.com = CNAME edge.example.net, 93.184.216.34", dns_line(d["www.example.com"]))

    def test_l2(self):
        bd = self.s.breakdown()
        l2 = {x["ethertype"]: x["frames"] for x in bd["l2"]}
        self.assertEqual(l2, {"ARP": 1, "LLDP": 1, "runt/invalid": 1})


class StoreAndHttpTests(unittest.TestCase):
    def test_pcap_roundtrip_and_api(self):
        with tempfile.TemporaryDirectory() as d:
            pcap = os.path.join(d, "t.pcap")
            synth.write_pcap(pcap, synth.sample_frames())
            st = Store(os.path.join(d, "db.sqlite"))
            s = read_pcap(pcap, Session(st.next_id(), "pcap"))
            st.save(s)
            self.assertEqual(len(st.flows(1)), len(s.flow_rows()))
            self.assertEqual(len(st.dns(1)), 3)

            app = App(st, "definitely-not-an-iface0")
            httpd = serve(app, "127.0.0.1", 0)
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                get = lambda p: json.load(urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, p)))
                self.assertEqual(get("/api/sessions")["sessions"][0]["id"], 1)
                self.assertEqual(get("/api/sessions/1/dns?q=nxdomain")["total"], 1)
                self.assertGreater(get("/api/sessions/1/flows")["total"], 5)
                self.assertIn("talkers", get("/api/sessions/1")["insights"])
                self.assertFalse(get("/api/status")["iface"]["present"])
                # POST without the action header is refused (CSRF guard)
                req = urllib.request.Request("http://127.0.0.1:%d/api/start" % port, data=b"{}", method="POST")
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    urllib.request.urlopen(req)
                self.assertEqual(cm.exception.code, 403)
                # starting on an absent iface is refused
                req = urllib.request.Request("http://127.0.0.1:%d/api/start" % port, data=b"{}",
                                             method="POST", headers={"X-Spanwatch-Action": "1"})
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    urllib.request.urlopen(req)
                self.assertEqual(cm.exception.code, 409)
                # DNS-rebinding guard
                req = urllib.request.Request("http://127.0.0.1:%d/api/status" % port, headers={"Host": "evil.example"})
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    urllib.request.urlopen(req)
                self.assertEqual(cm.exception.code, 421)
                txt = urllib.request.urlopen("http://127.0.0.1:%d/api/sessions/1/dns.txt" % port).read().decode()
                self.assertIn("NXDOMAIN", txt)
            finally:
                httpd.shutdown()


if __name__ == "__main__":
    unittest.main()
