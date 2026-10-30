import unittest

from spanwatch.iface import parse_lan

ADDR = [
    {"ifname": "lo", "addr_info": [{"local": "127.0.0.1", "prefixlen": 8}]},
    {"ifname": "enp4s0", "addr_info": [{"local": "192.168.1.86", "prefixlen": 21},
                                       {"local": "fe80::1", "prefixlen": 64},
                                       {"local": "2600:1700:1::86", "prefixlen": 64}]},
    {"ifname": "tailscale0", "addr_info": [{"local": "100.64.202.106", "prefixlen": 32}]},
    {"ifname": "span0", "addr_info": []},
]


class Lan(unittest.TestCase):
    def test_uplink_subnets_only(self):
        routes = [{"dst": "default", "dev": "enp4s0"}]
        self.assertEqual(parse_lan(ADDR, routes), ["192.168.0.0/21", "2600:1700:1::/64"])

    def test_no_default_route(self):
        self.assertEqual(parse_lan(ADDR, []), [])


if __name__ == "__main__":
    unittest.main()
