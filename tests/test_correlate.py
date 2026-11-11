import time
import unittest

from spanwatch.correlate import correlate, correlate_dns, flow_side, side_of

NOW = time.time()
WAN = "172.16.1.7"
LAN = ("192.168.0.0/21",)


def flow(client, server, proto="TCP", port=443, pcs=10, bcs=4000, psc=14, bsc=9000,
         first=None, last=None):
    first = NOW - 10 if first is None else first
    last = NOW - 2 if last is None else last
    return {"client": client, "server": server, "proto": proto, "port": port,
            "pkts_cs": pcs, "bytes_cs": bcs, "pkts_sc": psc, "bytes_sc": bsc,
            "first": first, "last": last}


class SideTests(unittest.TestCase):
    def test_side_of(self):
        self.assertEqual(side_of(WAN, {WAN}, LAN), "outside")
        self.assertEqual(side_of("192.168.1.20", {WAN}, LAN), "inside")
        self.assertIsNone(side_of("8.8.8.8", {WAN}, LAN))

    def test_flow_side(self):
        self.assertEqual(flow_side(flow("192.168.1.20", "8.8.8.8"), {WAN}, LAN), "inside")
        self.assertEqual(flow_side(flow(WAN, "8.8.8.8"), {WAN}, LAN), "outside")
        self.assertIsNone(flow_side(flow("8.8.4.4", "8.8.8.8"), {WAN}, LAN))


class CorrelateFlowsTests(unittest.TestCase):
    def test_disabled_without_wan_ip(self):
        rows = [flow("192.168.1.20", "8.8.8.8")]
        out = correlate(list(rows), [], LAN)
        self.assertEqual(out[0]["side"], None)
        self.assertNotIn("matched", out[0])

    def test_exact_match(self):
        i = flow("192.168.1.20", "140.82.1.4", pcs=10, bcs=4000, psc=14, bsc=9000)
        o = flow(WAN, "140.82.1.4", pcs=10, bcs=4050, psc=14, bsc=9010)  # tiny header delta
        out = correlate([dict(i), dict(o)], {WAN}, LAN)
        self.assertEqual(len(out), 1)                     # outside leg nested, not listed
        self.assertEqual(out[0]["side"], "inside")
        m = out[0]["matched"]
        self.assertEqual(m["confidence"], 3)
        self.assertFalse(m["ambiguous"])
        self.assertEqual(m["wan"], WAN)

    def test_no_match_different_dest(self):
        i = flow("192.168.1.20", "140.82.1.4")
        o = flow(WAN, "1.1.1.1")                          # different server: no join key
        out = correlate([dict(i), dict(o)], {WAN}, LAN)
        self.assertEqual(len(out), 2)
        inside = next(f for f in out if f["side"] == "inside")
        self.assertNotIn("matched", inside)

    def test_time_mismatch_no_match(self):
        i = flow("192.168.1.20", "140.82.1.4", first=NOW - 500, last=NOW - 490)
        o = flow(WAN, "140.82.1.4", first=NOW - 10, last=NOW - 2)
        out = correlate([dict(i), dict(o)], {WAN}, LAN)
        self.assertEqual(len(out), 2)

    def test_ambiguous_tie(self):
        i1 = flow("192.168.1.20", "199.9.9.9", pcs=5, bcs=1000, psc=5, bsc=1000)
        i2 = flow("192.168.1.21", "199.9.9.9", pcs=5, bcs=1000, psc=5, bsc=1000)
        o = flow(WAN, "199.9.9.9", pcs=5, bcs=1000, psc=5, bsc=1000)
        out = correlate([dict(i1), dict(i2), dict(o)], {WAN}, LAN)
        matched = [f for f in out if f.get("matched")]
        self.assertEqual(len(matched), 1)                 # only one outside leg to give away
        self.assertTrue(matched[0]["matched"]["ambiguous"])
        self.assertEqual(matched[0]["matched"]["ties"], 2)
        unmatched_inside = [f for f in out if f["side"] == "inside" and not f.get("matched")]
        self.assertEqual(len(unmatched_inside), 1)

    def test_unmatched_outside_stays_at_top_level(self):
        o = flow(WAN, "8.8.8.8")                           # router's own query, no inside leg
        out = correlate([dict(o)], {WAN}, LAN)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["side"], "outside")

    def test_lan_lan_flow_has_no_side(self):
        f = flow("192.168.1.20", "192.168.1.21", port=445)
        out = correlate([dict(f)], {WAN}, LAN)
        self.assertIsNone(out[0]["side"])


def dnsrow(client, resolver, qname, ts=None, rcode="NOERROR", answers=None):
    return {"ts": NOW - 20 if ts is None else ts, "client": client, "resolver": resolver,
            "qname": qname, "qtype": "A", "rcode": rcode, "answers": answers or ["1.2.3.4"]}


class CorrelateDnsTests(unittest.TestCase):
    def test_disabled_without_wan_ip(self):
        out = correlate_dns([dnsrow("192.168.1.20", "192.168.1.250", "x.com")], [])
        self.assertIsNone(out[0]["side"])

    def test_matches_same_question_shortly_after(self):
        d = dnsrow("192.168.1.20", "192.168.1.250", "example.com.", ts=NOW - 20)
        u = dnsrow(WAN, "9.9.9.9", "example.com", ts=NOW - 19.7)   # cache miss, resolver asks upstream
        out = correlate_dns([dict(d), dict(u)], {WAN})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["side"], "inside")
        m = out[0]["matched"]
        self.assertEqual(m["resolver"], "9.9.9.9")
        self.assertAlmostEqual(m["delay_ms"], 300, delta=5)
        self.assertEqual(m["confidence"], 3)

    def test_cache_hit_has_no_outside_match(self):
        d = dnsrow("192.168.1.20", "192.168.1.250", "cached.example")
        out = correlate_dns([dict(d)], {WAN})
        self.assertNotIn("matched", out[0])

    def test_too_late_does_not_match(self):
        d = dnsrow("192.168.1.20", "192.168.1.250", "slow.example", ts=NOW - 20)
        u = dnsrow(WAN, "9.9.9.9", "slow.example", ts=NOW - 5)   # 15s later: outside the slop window
        out = correlate_dns([dict(d), dict(u)], {WAN})
        self.assertEqual(len(out), 2)

    def test_resolver_own_lookup_not_confused_with_pihole_leg(self):
        # pihole itself resolving on the LAN is not an "outside" row (resolver isn't a wan ip)
        d = dnsrow(WAN, "9.9.9.9", "telemetry.example")
        out = correlate_dns([dict(d)], {WAN})
        self.assertEqual(out[0]["side"], "outside")


if __name__ == "__main__":
    unittest.main()
