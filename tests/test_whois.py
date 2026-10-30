import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from spanwatch.server import App, serve
from spanwatch.store import Store
from spanwatch.whois import Whois, parse_cymru, parse_rdap

RDAP = {
    "handle": "NET-8-8-8-0-2", "name": "GOGL", "type": "DIRECT ALLOCATION",
    "startAddress": "8.8.8.0", "endAddress": "8.8.8.255", "port43": "whois.arin.net",
    "parentHandle": "NET-8-0-0-0-0",
    "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
    "events": [{"eventAction": "registration", "eventDate": "2014-03-14T15:52:05-04:00"},
               {"eventAction": "last changed", "eventDate": "2014-03-14T16:00:00-04:00"}],
    "links": [{"rel": "self", "href": "https://rdap.arin.net/registry/ip/8.8.8.0"}],
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]],
                  "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
                      ["fn", {}, "text", "Abuse"], ["email", {}, "text", "network-abuse@google.com"]]]}]}],
}
CYMRU = ("AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n"
         "15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2023-12-28 | GOOGLE, US\n")


class Parse(unittest.TestCase):
    def test_rdap(self):
        r = parse_rdap(RDAP)
        self.assertEqual((r["org"], r["abuse"], r["rir"]), ("Google LLC", "network-abuse@google.com", "ARIN"))
        self.assertEqual(r["cidrs"], ["8.8.8.0/24"])
        self.assertEqual(r["registered"], "2014-03-14")

    def test_rdap_rejects_non_https_link(self):
        d = dict(RDAP, links=[{"rel": "self", "href": "javascript:alert(1)"}])
        self.assertIsNone(parse_rdap(d)["rdap_url"])

    def test_cymru(self):
        self.assertEqual(parse_cymru(CYMRU)["asn"], 15169)
        self.assertIsNone(parse_cymru("garbage"))


class Lookup(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.dir = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.dir.name, "db"))
        self.w = Whois(self.store, rdap=lambda ip: (self.calls.append(ip) or (RDAP, "")),
                       cymru=lambda ip: CYMRU)

    def tearDown(self):
        self.dir.cleanup()

    def test_private_never_sent(self):
        for ip in ("192.168.1.1", "10.0.0.1", "100.64.1.1", "fe80::1", "224.0.0.251"):
            with self.assertRaises(LookupError):
                self.w.lookup(ip)
        self.assertEqual(self.calls, [])

    def test_cache_and_persist(self):
        a = self.w.lookup("8.8.8.8")
        self.assertEqual((a["short"], a["asn"]["asn"], a["cached"]), ("Google LLC", 15169, False))
        self.assertTrue(self.w.lookup("8.8.8.8")["cached"])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(Whois(self.store).short("8.8.8.8"), "Google LLC")  # reloaded from SQLite

    def test_partial_failure(self):
        def boom(ip):
            raise OSError("no route")
        w = Whois(None, rdap=boom, cymru=lambda ip: CYMRU)
        d = w.lookup("8.8.4.4")
        self.assertTrue(d["ok"])
        self.assertEqual(d["short"], "GOOGLE, US")
        self.assertIn("rdap", d["errors"][0])

    def test_disabled(self):
        with self.assertRaises(PermissionError):
            Whois(None, enabled=False).lookup("8.8.8.8")

    def test_http(self):
        app = App(self.store, "nope0", whois=self.w)
        httpd = serve(app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            url = "http://127.0.0.1:%d/api/whois?ip=" % port
            hdr = {"X-Spanwatch-Action": "1"}
            d = json.load(urllib.request.urlopen(urllib.request.Request(url + "8.8.8.8", headers=hdr)))
            self.assertEqual(d["rdap"]["org"], "Google LLC")
            for ip, code, h in (("8.8.8.8", 403, {}), ("192.168.1.5", 422, hdr), ("bogus", 400, hdr)):
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    urllib.request.urlopen(urllib.request.Request(url + ip, headers=h))
                self.assertEqual(cm.exception.code, code)
                cm.exception.close()
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
