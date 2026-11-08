import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from spanwatch.hostnames import Directory
from spanwatch.pihole import PiHole, lease_rows, device_rows, blocked_pairs, load_password
from spanwatch.server import App, filter_dns, dns_line
from spanwatch.store import Store

NOW = time.time()
PW = "app-pass"
SID = "s3cr3t-sid"
LEASES = {"leases": [
    {"expires": int(NOW) + 3600, "name": "five", "hwaddr": "2c:cf:67:13:80:fa", "ip": "192.168.1.90", "clientid": "x"},
    {"expires": 0, "name": "*", "hwaddr": "aa:bb:cc:00:00:01", "ip": "192.168.1.91", "clientid": "y"},
]}
DEVICES = {"devices": [
    {"id": 1, "hwaddr": "2c:cf:67:13:80:fa", "interface": "eth0", "firstSeen": NOW - 9000,
     "lastQuery": NOW - 10, "numQueries": 5, "macVendor": "Raspberry Pi (Trading) Ltd",
     "ips": [{"ip": "192.168.1.90", "name": "five.lan", "lastSeen": NOW - 10, "nameUpdated": NOW - 100}]},
    {"id": 2, "hwaddr": "ip-192.168.1.77", "interface": "eth0", "firstSeen": NOW - 50,
     "lastQuery": NOW - 5, "numQueries": 1, "macVendor": None,
     "ips": [{"ip": "192.168.1.77", "name": "ghost", "lastSeen": NOW - 5, "nameUpdated": NOW - 5}]},
]}
QUERIES = {"queries": [
    {"id": 1, "time": NOW - 30, "type": "A", "domain": "ads.example.com", "status": "GRAVITY",
     "client": {"ip": "192.168.1.90", "name": "five"}},
    {"id": 2, "time": NOW - 20, "type": "A", "domain": "ads.example.com", "status": "GRAVITY",
     "client": {"ip": "192.168.1.90", "name": "five"}},
    {"id": 3, "time": NOW - 10, "type": "A", "domain": "example.com", "status": "FORWARDED",
     "client": {"ip": "192.168.1.90", "name": "five"}},
    {"id": 4, "time": NOW - 5, "type": "AAAA", "domain": "Track.Example.NET.", "status": "REGEX",
     "client": {"ip": "192.168.1.91", "name": None}},
]}


class FakePihole(BaseHTTPRequestHandler):
    calls = []

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        b = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _authed(self):
        return self.headers.get("X-FTL-SID") == SID

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        FakePihole.calls.append(("POST", self.path))
        if self.path == "/api/auth" and body.get("password") == PW:
            return self._send(200, {"session": {"valid": True, "sid": SID, "validity": 1800}})
        return self._send(401, {"session": {"valid": False, "sid": None, "message": "password incorrect"}})

    def do_DELETE(self):
        FakePihole.calls.append(("DELETE", self.path))
        self.send_response(204 if self._authed() else 401)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        FakePihole.calls.append(("GET", self.path))
        if not self._authed():
            return self._send(401, {"error": {"key": "unauthorized", "message": "Unauthorized"}})
        p = self.path.split("?")[0]
        if p == "/api/dhcp/leases":
            return self._send(200, LEASES)
        if p == "/api/network/devices":
            return self._send(200, DEVICES)
        if p == "/api/queries":
            return self._send(200, QUERIES)
        return self._send(404, {"error": {"key": "not_found"}})


class Parse(unittest.TestCase):
    def test_leases(self):
        obs, binds = lease_rows(LEASES["leases"], NOW)
        self.assertEqual([o[2] for o in obs], ["five"])          # "*" = no name
        self.assertEqual(len(binds), 2)

    def test_devices_skip_pseudo_mac(self):
        obs, binds, vendors = device_rows(DEVICES["devices"], NOW)
        self.assertEqual({o[2] for o in obs}, {"five.lan", "ghost"})
        self.assertEqual([b[0] for b in binds], ["2c:cf:67:13:80:fa"])
        self.assertIn("2c:cf:67:13:80:fa", vendors)
        self.assertEqual([o[0] for o in obs if o[2] == "ghost"], [""])

    def test_blocked(self):
        b = blocked_pairs(QUERIES["queries"])
        self.assertEqual(set(b), {("192.168.1.90", "ads.example.com"), ("192.168.1.91", "track.example.net")})
        self.assertEqual(b[("192.168.1.90", "ads.example.com")]["n"], 2)

    def test_password_credential_dir(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pihole"), "w") as fh:
                fh.write(" pw \n")
            os.environ["CREDENTIALS_DIRECTORY"] = d
            try:
                self.assertEqual(load_password("/nonexistent"), "pw")
            finally:
                del os.environ["CREDENTIALS_DIRECTORY"]
        self.assertIsNone(load_password("/nonexistent"))


class Live(unittest.TestCase):
    def setUp(self):
        FakePihole.calls = []
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), FakePihole)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.srv.server_port
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def test_poll_feeds_hosts_and_dns(self):
        ph = PiHole(self.store, self.url + "/api/", PW)
        st = ph.poll()
        self.assertTrue(st["ok"], st)
        self.assertEqual((st["leases"], st["devices"], st["queries"]), (2, 2, 4))
        # logged in, read, logged out; never wrote anything else
        methods = [m for m, _ in FakePihole.calls]
        self.assertEqual(methods[0], "POST")
        self.assertEqual(methods[-1], "DELETE")
        self.assertEqual(set(methods[1:-1]), {"GET"})

        hosts = {r["ip"]: r for r in Directory(self.store).rows()}
        five = hosts["192.168.1.90"]
        self.assertEqual(five["conf"], 3)
        self.assertIn("pihole-dhcp", five["sources"])
        self.assertEqual(hosts["192.168.1.77"]["name"], "ghost")

        app = App(self.store, "definitely-not-an-iface0", pihole=ph)
        rows = [{"ts": NOW - 25, "client": "192.168.1.90", "resolver": "192.168.1.250",
                 "qname": "ads.example.com", "qtype": "A", "rcode": "NOERROR",
                 "answers": ["0.0.0.0"], "ms": 1, "ttl": 2},
                {"ts": NOW - 10, "client": "192.168.1.90", "resolver": "192.168.1.250",
                 "qname": "example.com", "qtype": "A", "rcode": "NOERROR",
                 "answers": ["93.184.215.14"], "ms": 9, "ttl": 300},
                {"ts": NOW - 9 * 86400, "client": "192.168.1.90", "resolver": "192.168.1.250",
                 "qname": "ads.example.com", "qtype": "A", "rcode": "NOERROR",
                 "answers": ["0.0.0.0"], "ms": 1, "ttl": 2}]
        app._live = lambda sid: type("L", (), {"dns_rows": lambda self: rows})()
        out = app.dns(1)
        self.assertEqual([d["blocked"] for d in out], ["GRAVITY", None, None])  # old row: outside window
        got, fq = app.rep_filter(out, "is:blocked", ())
        self.assertEqual((len(got), fq), (1, ""))
        self.assertIn("pihole:GRAVITY", dns_line(out[0]))
        self.assertEqual(filter_dns(out, "gravity")[0], 1)
        self.assertEqual(app.status()["pihole"]["blocked_pairs"], 2)
        self.assertEqual(app.host_rows("five")[0]["vendor"], "Raspberry Pi (Trading) Ltd")

        # persisted: a fresh instance knows the blocked pairs without polling
        ph2 = PiHole(self.store, self.url, PW)
        self.assertEqual(ph2.block_for("192.168.1.91", "track.example.net.", NOW - 5), "REGEX")

    def test_bad_password_reports_error(self):
        ph = PiHole(self.store, self.url, "wrong")
        st = ph.poll()
        self.assertFalse(st["ok"])
        self.assertIn("401", st["error"])
        self.assertNotIn("wrong", json.dumps(ph.status()))

    def test_disabled_without_password(self):
        ph = PiHole(self.store, self.url, None)
        self.assertFalse(ph.enabled)
        self.assertEqual(ph.poll()["ok"], None)
        self.assertEqual(FakePihole.calls, [])


if __name__ == "__main__":
    unittest.main()
