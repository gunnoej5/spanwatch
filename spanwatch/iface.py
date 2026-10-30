"""Read-only interface health: is the sniff port up, promiscuous, and
(critically) carrying no IP addresses?"""
import json
import os
import subprocess

IFF_UP = 0x1
IFF_NOARP = 0x80
IFF_PROMISC = 0x100


def _read(path, default=None):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return default


def addresses(iface):
    """All IPv4/IPv6 addresses on iface (via netlink through iproute2)."""
    try:
        out = subprocess.run(["ip", "-j", "addr", "show", "dev", iface],
                             capture_output=True, text=True, timeout=3)
        data = json.loads(out.stdout or "[]")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None
    addrs = []
    for link in data:
        for a in link.get("addr_info", []):
            addrs.append("%s/%s" % (a.get("local"), a.get("prefixlen")))
    return addrs


def status(iface):
    base = "/sys/class/net/%s" % iface
    if not os.path.isdir(base):
        return {"iface": iface, "present": False}
    flags = int(_read(base + "/flags", "0x0"), 16)
    stat = lambda k: int(_read("%s/statistics/%s" % (base, k), "0") or 0)
    speed = _read(base + "/speed")
    try:
        speed = int(speed)
    except (TypeError, ValueError):
        speed = None
    addrs = addresses(iface)
    ipv6_off = _read("/proc/sys/net/ipv6/conf/%s/disable_ipv6" % iface) == "1"
    return {
        "iface": iface, "present": True,
        "mac": _read(base + "/address"),
        "operstate": _read(base + "/operstate"),
        "carrier": _read(base + "/carrier") == "1",
        "up": bool(flags & IFF_UP),
        "promisc": bool(flags & IFF_PROMISC),
        "noarp": bool(flags & IFF_NOARP),
        "ipv6_disabled": ipv6_off,
        "speed_mbps": speed if speed and speed > 0 else None,
        "addresses": addrs,
        "rx_packets": stat("rx_packets"), "rx_bytes": stat("rx_bytes"),
        "rx_dropped": stat("rx_dropped"), "tx_packets": stat("tx_packets"),
        "driver": os.path.basename(os.path.realpath(base + "/device/driver"))
        if os.path.exists(base + "/device/driver") else None,
    }


def receive_only(st):
    """True when the port looks safely passive (no addresses at all)."""
    return bool(st.get("present")) and st.get("addresses") == []
