import unittest

from spanwatch.classify import classify_payload, infer, graph, addr_kind
from spanwatch.session import Session
from tests import synth

C, S = "192.168.1.50", "93.184.216.34"


def tag(p, proto=17, sp=40000, dp=40001):
    g = classify_payload(p, proto, sp, dp)
    return (g[0], g[1]) if g else None


class PayloadSignatures(unittest.TestCase):
    def test_ssh(self):
        g = classify_payload(b"SSH-2.0-OpenSSH_9.6\r\n", 6, 2222, 50000)
        self.assertEqual(g[:3], ("ssh", 3, "SSH-2.0-OpenSSH_9.6"))

    def test_tls_sni(self):
        g = classify_payload(synth.client_hello("github.com"), 6, 50000, 443)
        self.assertEqual(g[:3], ("tls", 3, "sni github.com"))

    def test_wireguard(self):
        self.assertEqual(tag(b"\x01\0\0\0" + synth.rnd(144)), ("wireguard", 3))
        self.assertEqual(tag(b"\x04\0\0\0" + synth.rnd(76)), ("wireguard", 2))

    def test_quic(self):
        self.assertEqual(tag(b"\xc3\0\0\0\x01" + synth.rnd(1195), dp=443), ("quic", 3))

    def test_bittorrent(self):
        self.assertEqual(tag(b"\x13BitTorrent protocol" + b"\0" * 48, proto=6), ("bittorrent", 3))
        self.assertEqual(tag(b"d1:ad2:id20:" + b"a" * 20 + b"e1:q4:ping1:t2:aa1:y1:qe"), ("bittorrent-dht", 3))

    def test_openvpn(self):
        self.assertEqual(tag(bytes([7 << 3]) + synth.rnd(8) + b"\0" * 5), ("openvpn", 3))

    def test_stun(self):
        self.assertEqual(tag(b"\x00\x01\x00\x00\x21\x12\xa4\x42" + b"\0" * 12), ("stun", 3))

    def test_http_host(self):
        g = classify_payload(b"GET / HTTP/1.1\r\nHost: nas.lan\r\n\r\n", 6, 50000, 80)
        self.assertEqual(g[:3], ("http", 3, "host nas.lan"))

    def test_entropy_fallback(self):
        self.assertEqual(tag(b"\x99" + synth.rnd(400), sp=40000, dp=33333), ("encrypted", 1))
        self.assertEqual(tag(b"\x99" + synth.rnd(400), proto=6, sp=50000, dp=22), ("ssh", 1))
        self.assertIsNone(tag(b"hello world " * 20))


class SessionIntegration(unittest.TestCase):
    def test_split_client_hello_sni(self):
        s = Session(1, "t")
        hello = synth.client_hello("split.example.org", pad=2000)
        for f in (synth.eth(synth.ipv4(C, S, 6, synth.tcp(50000, 443, 0x02))),
                  synth.eth(synth.ipv4(C, S, 6, synth.tcp(50000, 443, 0x18, hello[:1400])))
                  , synth.eth(synth.ipv4(C, S, 6, synth.tcp(50000, 443, 0x18, hello[1400:])))):
            s.ingest(f, len(f), 1.0)
        r = s.flow_rows()[0]
        self.assertEqual((r["guess"], r["conf"], r["detail"]), ("tls", 3, "sni split.example.org"))
        self.assertEqual(r["server_name"], "split.example.org")

    def test_ssh_on_odd_port(self):
        s = Session(1, "t")
        for f in (synth.eth(synth.ipv4(C, S, 6, synth.tcp(50000, 2222, 0x02))),
                  synth.eth(synth.ipv4(S, C, 6, synth.tcp(2222, 50000, 0x18, b"SSH-2.0-dropbear\r\n")))):
            s.ingest(f, len(f), 1.0)
        self.assertEqual(s.flow_rows()[0]["guess"], "ssh")


def row(client, server, port, proto="UDP", guess="", conf=0, pk=10):
    return {"client": client, "server": server, "proto": proto, "port": port,
            "service": "", "guess": guess, "conf": conf, "detail": "",
            "pkts_cs": pk, "bytes_cs": pk * 100, "pkts_sc": pk, "bytes_sc": pk * 100,
            "client_name": "", "server_name": ""}


class Behaviour(unittest.TestCase):
    def test_port_and_proto_fallbacks(self):
        rows = infer([row(C, S, 51820), row(C, S, None, proto="ESP"), row(C, S, 22, proto="TCP")])
        self.assertEqual([(r["guess"], r["conf"]) for r in rows],
                         [("wireguard", 1), ("ipsec", 3), ("ssh", 1)])

    def test_fanout_p2p(self):
        rows = infer([row(C, "198.51.100.%d" % i, 20000 + i) for i in range(25)])
        self.assertTrue(all(r["guess"] == "p2p" for r in rows))

    def test_torrent_host_propagation(self):
        rows = infer([row(C, S, 40000, guess="bittorrent-dht", conf=3), row(C, "198.51.100.9", 31337)])
        self.assertEqual((rows[1]["guess"], rows[1]["conf"]), ("bittorrent", 2))

    def test_graph(self):
        g = graph([row(C, S, 443, pk=5), row(S, C, 8080, pk=7), row(C, "10.0.0.2", 53, pk=1)])
        self.assertEqual(len(g["edges"]), 2)
        self.assertEqual(g["edges"][0]["packets"], 24)
        self.assertEqual(g["edges"][0]["flows"], 2)
        self.assertEqual({n["kind"] for n in g["nodes"]}, {"local", "public"})
        self.assertEqual(addr_kind("100.101.1.1"), "cgnat")


if __name__ == "__main__":
    unittest.main()
