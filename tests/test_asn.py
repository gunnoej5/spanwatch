import gzip
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.request

from spanwatch.asn import AsnDB, Groups, parse, short_name
from spanwatch.capture import read_pcap
from spanwatch.server import App, serve
from spanwatch.session import Session
from spanwatch.store import Store
from tests import synth

TSV = (
    "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n"
    "1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n"
    "3.5.0.0\t3.5.255.255\t16509\tUS\tAMAZON-02 - Amazon.com, Inc.\n"
    "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE - Google LLC\n"
    "20.0.0.0\t20.31.255.255\t8075\tUS\tMICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation\n"
    "54.0.0.0\t54.0.0.255\t64512\tUS\tAMAZON-AES - Amazon.com, Inc.\n"
    "2607:f8b0::\t2607:f8b0:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE - Google LLC\n"
)
GZ = gzip.compress(TSV.encode())


class AsnTests(unittest.TestCase):
    def db(self, **kw):
        d = AsnDB(None, fetch=lambda url: GZ, **kw)
        self.assertTrue(d.refresh(force=True))
        return d

    def test_parse_skips_unrouted(self):
        s4, _e4, _i4, s6, _e6, _i6, recs = parse(TSV.splitlines(True))
        self.assertEqual((len(s4), len(s6)), (5, 1))
        self.assertNotIn(0, [r[0] for r in recs])

    def test_lookup_and_groups(self):
        d = self.db()
        g = lambda ip: (d.lookup(ip) or {}).get("grp")
        self.assertEqual(g("3.5.140.2"), "amazon")
        self.assertEqual(g("8.8.8.8"), "google")
        self.assertEqual(g("2607:f8b0:4009::200e"), "google")
        self.assertEqual(g("20.12.52.29"), "microsoft")
        self.assertEqual(g("1.0.0.1"), "other")
        self.assertEqual(g("54.0.0.9"), "amazon")      # unlisted ASN, matched by name
        self.assertIsNone(d.lookup("1.0.2.1"))          # unrouted
        self.assertIsNone(d.lookup("192.168.1.5"))      # private
        self.assertIsNone(d.lookup("9.9.9.9"))          # not in table
        self.assertEqual(d.lookup("3.5.1.1")["as_name"], "Amazon.com, Inc.")
        self.assertEqual(short_name("FOO"), "FOO")

    def test_custom_groups_file(self):
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "orgs.json")
            with open(p, "w") as fh:
                json.dump([{"id": "cf", "name": "Cloudflare", "asns": [13335]},
                           {"id": "goog", "name": "G", "match": "google"}], fh)
            gr = Groups.load(p)
            self.assertEqual([x["id"] for x in gr.public()], ["cf", "goog", "other"])
            d = self.db(groups=gr)
            self.assertEqual(d.lookup("1.0.0.1")["grp"], "cf")
            self.assertEqual(d.lookup("8.8.8.8")["grp"], "goog")
            self.assertEqual(d.lookup("3.5.1.1")["grp"], "other")
        self.assertEqual(len(Groups.load("/nonexistent").public()), 4)

    def test_cache_and_bad_download(self):
        with tempfile.TemporaryDirectory() as t:
            d = AsnDB(t, fetch=lambda url: GZ)
            d.refresh(force=True)
            d2 = AsnDB(t, fetch=lambda url: b"not gzip")
            self.assertTrue(d2.load_cached())
            self.assertEqual(d2.lookup("8.8.8.8")["asn"], 15169)
            self.assertFalse(d2.refresh(force=True))      # bad download keeps the old table
            self.assertEqual(d2.lookup("8.8.8.8")["asn"], 15169)
            self.assertTrue(d2.status()["error"])

    def test_graph_api(self):
        with tempfile.TemporaryDirectory() as t:
            pcap = os.path.join(t, "x.pcap")
            fr = [synth.eth(synth.ipv4("192.168.1.20", dst, 6, synth.tcp(50000 + i, 443, 0x18, b"x" * 50)))
                  for i, dst in enumerate(["3.5.1.1", "8.8.8.8", "20.1.1.1", "1.0.0.1"])]
            synth.write_pcap(pcap, fr, t0=time.time() - 60)
            st = Store(os.path.join(t, "x.db"))
            s = Session(st.next_id(), "pcap")
            read_pcap(pcap, s)
            st.save(s)
            app = App(st, "definitely-not-an-iface0", asn=self.db())
            httpd = serve(app, "127.0.0.1", 0)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                url = "http://127.0.0.1:%d/api/sessions/%d/graph" % (httpd.server_address[1], s.id)
                g = json.loads(urllib.request.urlopen(url).read())
                by = {n["id"]: n for n in g["nodes"]}
                self.assertEqual(by["3.5.1.1"]["grp"], "amazon")
                self.assertEqual(by["20.1.1.1"]["as_name"], "Microsoft Corporation")
                self.assertEqual(by["192.168.1.20"]["grp"], "other")
                self.assertNotIn("asn", by["192.168.1.20"])
                self.assertEqual([x["id"] for x in g["groups"]], ["amazon", "google", "microsoft", "other"])
                self.assertTrue(g["asn_loaded"])
            finally:
                httpd.shutdown()
                httpd.server_close()


if __name__ == "__main__":
    unittest.main()
