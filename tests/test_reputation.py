import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from spanwatch.reputation import Feeds, AbuseIPDB, Reputation, RangeSet, parse_feed
from spanwatch.server import App, serve
from spanwatch.store import Store
from tests import synth
from spanwatch.capture import read_pcap
from spanwatch.session import Session

FEEDS = [
    ("drop", "bad", "u1", "spamhaus", "drop"),
    ("scan", "watch", "u2", "lines", "scanners"),
    ("tor", "tor", "u3", "lines", "tor"),
]
BODY = {
    "u1": '{"cidr":"93.184.216.0/24","sblid":"SBL1"}\n{"cidr":"2001:db9::/32"}\n{"type":"metadata","timestamp":1}\n',
    "u2": "# scanners\n10.0.0.0/8\n192.168.0.0/16\n1.1.1.1\n8.8.8.8 ; comment\n",
    "u3": "162.159.200.1\n",
}


class Feed(unittest.TestCase):
    def test_parse_skips_bogons_and_metadata(self):
        self.assertEqual([str(n) for n in parse_feed(BODY["u2"], "lines")], ["1.1.1.1/32", "8.8.8.8/32"])
        self.assertEqual(len(parse_feed(BODY["u1"], "spamhaus")), 2)

    def test_rangeset_merges(self):
        import ipaddress as ia
        rs = RangeSet([ia.ip_network(x) for x in ("1.0.0.0/24", "1.0.1.0/24", "1.0.0.128/25")])
        self.assertEqual(len(rs.v[4][0]), 1)
        self.assertIn(ia.ip_address("1.0.1.255"), rs)
        self.assertNotIn(ia.ip_address("1.0.2.0"), rs)

    def test_refresh_cache_and_check(self):
        with tempfile.TemporaryDirectory() as d:
            f = Feeds(d, fetch=lambda u: BODY[u], feeds=FEEDS)
            self.assertEqual(sorted(f.refresh()), ["drop", "scan", "tor"])
            self.assertEqual(f.check("93.184.216.34"), [("drop", "bad")])
            self.assertEqual(f.check("192.168.1.5"), [])        # private never flagged
            self.assertEqual(f.check("2001:db9::5"), [("drop", "bad")])
            g = Feeds(d, fetch=lambda u: (_ for _ in ()).throw(OSError("offline")), feeds=FEEDS)
            self.assertEqual(g.check("1.1.1.1"), [("scan", "watch")])   # loaded from disk
            self.assertEqual(g.refresh(), [])                            # fresh, no fetch

    def test_empty_download_keeps_old(self):
        with tempfile.TemporaryDirectory() as d:
            body = dict(BODY)
            f = Feeds(d, fetch=lambda u: body[u], feeds=FEEDS)
            f.refresh()
            body["u2"] = "# nothing\n"
            f.refresh(force=True)
            self.assertEqual(f.check("8.8.8.8"), [("scan", "watch")])
            self.assertIn("empty", [s for s in f.status() if s["name"] == "scan"][0]["error"])


class Abuse(unittest.TestCase):
    def test_lookup_tiers_cache(self):
        calls = []
        def fake(ip, key):
            calls.append(ip)
            return {"data": {"abuseConfidenceScore": {"5.6.7.8": 90, "5.6.7.9": 30}.get(ip, 0), "totalReports": 4}}
        a = AbuseIPDB(None, key="k", fetch=fake)
        self.assertEqual(a.lookup("5.6.7.8")["tier"], "bad")
        self.assertEqual(a.lookup("5.6.7.9")["tier"], "watch")
        self.assertIsNone(a.lookup("5.6.7.10")["tier"])
        self.assertTrue(a.lookup("5.6.7.8")["cached"])
        self.assertEqual(len(calls), 3)
        with self.assertRaises(LookupError):
            a.lookup("192.168.1.1")
        with self.assertRaises(PermissionError):
            AbuseIPDB(None).lookup("5.6.7.8")
        rep = Reputation(Feeds(None, enabled=False, feeds=[]), a)
        self.assertEqual(rep.flag("5.6.7.8"), {"tier": "bad", "lists": ["abuseipdb:90%"]})
        self.assertIsNone(rep.flag("5.6.7.10"))


class Http(unittest.TestCase):
    def test_summary_flags_and_keyword_filter(self):
        with tempfile.TemporaryDirectory() as d:
            pcap = os.path.join(d, "t.pcap")
            synth.write_pcap(pcap, synth.sample_frames())
            st = Store(os.path.join(d, "db"))
            st.save(read_pcap(pcap, Session(1, "pcap")))
            feeds = Feeds(d, fetch=lambda u: BODY[u], feeds=FEEDS)
            feeds.refresh()
            app = App(st, "nope0", reputation=Reputation(feeds, AbuseIPDB(st)))
            httpd = serve(app, "127.0.0.1", 0)
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            get = lambda p: json.load(urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, p)))
            try:
                s = get("/api/sessions/1")
                self.assertEqual(s["flags"]["93.184.216.34"]["tier"], "bad")
                self.assertEqual(s["flags"]["162.159.200.1"]["tier"], "tor")
                self.assertEqual(s["flag_counts"].get("bad"), 2)    # .34 and .35 (DNS answer)
                rows = get("/api/sessions/1/flows?q=is:flagged")["rows"]
                servers = {r["server"] for r in rows}
                self.assertIn("93.184.216.34", servers)
                self.assertIn("1.1.1.1", servers)                 # watch tier counts as flagged
                self.assertNotIn("162.159.200.1", servers)        # tor alone does not
                self.assertTrue(all(r["server"] in s["flags"] for r in rows))
                self.assertEqual(get("/api/sessions/1/dns?q=is:bad")["total"], 1)
                self.assertEqual(get("/api/sessions/1/flows?q=is:tor")["total"], 1)
                self.assertEqual(get("/api/reputation?ip=93.184.216.34")["feeds"][0]["name"], "drop")
                csv = urllib.request.urlopen("http://127.0.0.1:%d/api/sessions/1/flows.csv" % port).read().decode()
                self.assertIn("bad:drop", csv)
                req = urllib.request.Request("http://127.0.0.1:%d/api/abuseipdb?ip=8.8.8.8" % port,
                                             headers={"X-Spanwatch-Action": "1"})
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    urllib.request.urlopen(req)
                self.assertEqual(cm.exception.code, 409)   # no key configured
                cm.exception.close()
            finally:
                httpd.shutdown()
                httpd.server_close()


if __name__ == "__main__":
    unittest.main()
