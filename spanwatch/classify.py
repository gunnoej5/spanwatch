"""Best-effort identification of encrypted / opaque traffic.

Two stages:
  classify_payload()  per packet, first few payload packets of each
                      conversation: protocol signatures (SSH banner, TLS
                      ClientHello + SNI, QUIC, WireGuard, OpenVPN, BitTorrent,
                      DHT, uTP, STUN, RDP, VNC, HTTP) then an entropy fallback.
  infer()             per session, at view time: port fallbacks, IPsec/GRE by
                      IP protocol, and behaviour (BitTorrent host propagation,
                      P2P fan-out / fan-in).

Confidence: 3 = protocol signature, 2 = strong structural/behavioural hint,
1 = heuristic (port number, entropy, fan-out). The UI shows conf 1 with "?".
"""
import ipaddress
import math
from collections import Counter, defaultdict
from functools import lru_cache

from .parse import SERVICES

TCP_PORTS = {
    22: "ssh", 443: "tls", 8443: "tls", 853: "dns-over-tls", 993: "tls",
    995: "tls", 465: "tls", 636: "tls", 5223: "tls", 3389: "rdp", 5900: "vnc",
    1194: "openvpn", 1723: "pptp-vpn", 51413: "bittorrent",
}
UDP_PORTS = {
    443: "quic", 1194: "openvpn", 51820: "wireguard", 41641: "wireguard",
    500: "ipsec", 4500: "ipsec", 1701: "l2tp-vpn", 3478: "stun",
    19302: "stun", 51413: "bittorrent",
}
for _p in range(6881, 6890):
    TCP_PORTS[_p] = UDP_PORTS[_p] = "bittorrent"

PROTO_NUM = {"TCP": 6, "UDP": 17}
FANOUT = 20   # distinct peers on unknown high ports from one client
FANIN = 10    # distinct clients hitting one unknown high port
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ",
                b"PATCH ", b"CONNECT ", b"HTTP/1.")
QUIC_VERSIONS = (b"\x00\x00\x00\x01", b"\x6b\x33\x43\xcf", b"\x00\x00\x00\x00")
TRACKER_MAGIC = b"\x00\x00\x04\x17\x27\x10\x19\x80"
CGNAT = ipaddress.ip_network("100.64.0.0/10")


def port_guess(proto, port):
    if port is None:
        return None
    if proto == 6:
        return TCP_PORTS.get(port)
    if proto == 17:
        return UDP_PORTS.get(port)
    return None


def entropy_ratio(b):
    """Shannon entropy normalised to the max achievable for this length."""
    n = len(b)
    if n < 2:
        return 0.0
    h = 0.0
    for v in Counter(b).values():
        p = v / n
        h -= p * math.log2(p)
    return h / min(8.0, math.log2(n))


def tls_client_hello(p):
    """Returns (sni, complete). complete=False means the hello is cut off
    before the extensions were fully seen (spans TCP segments)."""
    rec_len = (p[3] << 8) | p[4]
    complete = len(p) >= 5 + rec_len
    try:
        i = 5 + 4 + 2 + 32               # record hdr, hs hdr, version, random
        i += 1 + p[i]                    # session id
        i += 2 + ((p[i] << 8) | p[i + 1])  # cipher suites
        i += 1 + p[i]                    # compression
        end = min(i + 2 + ((p[i] << 8) | p[i + 1]), len(p))
        i += 2
        while i + 4 <= end:
            t = (p[i] << 8) | p[i + 1]
            ln = (p[i + 2] << 8) | p[i + 3]
            i += 4
            if t == 0 and i + 5 <= end:
                nl = (p[i + 3] << 8) | p[i + 4]
                if i + 5 + nl <= len(p):
                    return p[i + 5:i + 5 + nl].decode("ascii", "replace"), True
            i += ln
    except IndexError:
        pass
    return "", complete


def _openvpn(p):
    """P_CONTROL_HARD_RESET_{CLIENT,SERVER}_V2/V3 without tls-auth."""
    if len(p) < 14:
        return False
    op, key = p[0] >> 3, p[0] & 7
    return op in (7, 8, 10) and key == 0 and p[9] == 0 and p[10:14] == b"\0\0\0\0"


def classify_payload(p, proto, sport, dport):
    """-> (tag, conf, detail, want_more) or None."""
    n = len(p)
    if n < 4:
        return None
    if p[:4] == b"SSH-":
        banner = p[:64].split(b"\n")[0].rstrip(b"\r").decode("ascii", "replace")
        return ("ssh", 3, banner, False)

    if proto == 6:
        if p[0] == 0x16 and p[1] == 3 and n >= 6:
            if p[5] == 1:
                sni, complete = tls_client_hello(p)
                if sni:
                    return ("tls", 3, "sni " + sni, False)
                if not complete:
                    return ("tls", 2, "", True)   # wait for next segment
                return ("tls", 3, "no sni", False)
            return ("tls", 2, "", False)
        if p[0] in (0x14, 0x15, 0x17) and p[1] == 3 and p[2] <= 4:
            return ("tls", 2, "", False)
        if p[:20] == b"\x13BitTorrent protocol":
            return ("bittorrent", 3, "peer handshake", False)
        if p.startswith(HTTP_METHODS):
            host = ""
            j = p.find(b"\r\nHost: ")
            if j >= 0:
                host = p[j + 8:p.find(b"\r\n", j + 8)].decode("ascii", "replace")[:80]
            return ("http", 3, ("host " + host) if host else "plaintext", False)
        if p[:4] == b"RFB ":
            return ("vnc", 3, p[:12].decode("ascii", "replace").strip(), False)
        if p[0] == 3 and p[1] == 0 and n >= 11 and ((p[2] << 8) | p[3]) == n and p[5] & 0xF0 == 0xE0:
            return ("rdp", 3, "x.224 connect", False)
        if n >= 16 and ((p[0] << 8) | p[1]) == n - 2 and _openvpn(p[2:]):
            return ("openvpn", 3, "tcp hard-reset", False)

    elif proto == 17:
        if n >= 20 and p[0] & 0xC0 == 0xC0 and p[1:5] in QUIC_VERSIONS:
            return ("quic", 3, "long header", False)
        if p[1:4] == b"\0\0\0" and 1 <= p[0] <= 4:
            if (p[0], n) in ((1, 148), (2, 92), (3, 64)):
                return ("wireguard", 3, ("", "handshake init", "handshake resp", "cookie")[p[0]], False)
            if p[0] == 4 and n >= 32 and (n - 16) % 16 == 0:
                return ("wireguard", 2, "transport data", False)
        if p[:2] in (b"d1", b"d2") and b":id20:" in p[:40]:
            return ("bittorrent-dht", 3, "DHT", False)
        if b"BitTorrent protocol" in p[:64]:
            return ("bittorrent", 3, "uTP handshake", False)
        if n == 16 and p[:8] == TRACKER_MAGIC:
            return ("bittorrent", 3, "UDP tracker", False)
        if n >= 20 and p[0] & 0xC0 == 0 and p[4:8] == b"\x21\x12\xa4\x42":
            return ("stun", 3, "WebRTC/VoIP/NAT traversal", False)
        if _openvpn(p):
            return ("openvpn", 3, "udp hard-reset", False)
        if n >= 20 and p[0] in (0x01, 0x11, 0x21, 0x41) and p[1] in (0, 1, 2) \
                and sport >= 1024 and dport >= 1024:
            return ("bittorrent", 1, "uTP-like header", False)

    if n >= 96 and entropy_ratio(p[:512]) > 0.9:
        g = port_guess(proto, dport) or port_guess(proto, sport)
        if g:
            return (g, 1, "high-entropy payload on known port", False)
        return ("encrypted", 1, "high-entropy payload", False)
    return None


@lru_cache(maxsize=65536)
def addr_kind(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "other"
    if a.is_multicast or ip == "255.255.255.255":
        return "multicast"
    if a.version == 4 and a in CGNAT:
        return "cgnat"
    if a.is_loopback:
        return "loopback"
    if a.is_unspecified:
        return "other"
    if a.is_private or a.is_link_local:
        return "local"
    return "public"


def _high(r):
    p = r["port"]
    return (r["proto"] in PROTO_NUM and p is not None and p >= 1024
            and p not in SERVICES)


def infer(rows):
    """Fill guesses from protocol/port/behaviour. Mutates and returns rows."""
    for r in rows:
        r["guess"] = r.get("guess") or ""
        r["conf"] = r.get("conf") or 0
        r["detail"] = r.get("detail") or ""
        if r["conf"]:
            continue
        if r["proto"] in ("ESP", "AH"):
            r["guess"], r["conf"], r["detail"] = "ipsec", 3, r["proto"]
        elif r["proto"] == "GRE":
            r["guess"], r["conf"], r["detail"] = "gre", 1, "GRE tunnel (PPTP/other)"
        else:
            g = port_guess(PROTO_NUM.get(r["proto"]), r["port"])
            if g:
                r["guess"], r["conf"], r["detail"] = g, 1, "port %s" % r["port"]

    torrent_hosts = set()
    for r in rows:
        if r["guess"].startswith("bittorrent") and r["conf"] >= 2:
            for ip in (r["client"], r["server"]):
                if addr_kind(ip) == "local":
                    torrent_hosts.add(ip)

    cand = [r for r in rows if r["conf"] < 2 and _high(r)]
    fan, fanin = defaultdict(set), defaultdict(set)
    for r in cand:
        if r["client"] in torrent_hosts or r["server"] in torrent_hosts:
            r["guess"], r["conf"], r["detail"] = "bittorrent", 2, "host also speaks BitTorrent"
        fan[r["client"]].add(r["server"])
        fanin[(r["server"], r["proto"], r["port"])].add(r["client"])
    for r in cand:
        if r["conf"] >= 2:
            continue
        n = len(fan[r["client"]])
        m = len(fanin[(r["server"], r["proto"], r["port"])])
        if n >= FANOUT:
            r["guess"], r["conf"], r["detail"] = "p2p", 1, "client talks to %d peers on high ports" % n
        elif m >= FANIN:
            r["guess"], r["conf"], r["detail"] = "p2p", 1, "%d peers hit this high port" % m
    return rows


def graph(rows, limit=150):
    """Aggregate conversations into undirected IP-pair edges."""
    pairs = {}
    names = {}
    nodes = defaultdict(lambda: [0, 0])
    for r in rows:
        a, b = r["client"], r["server"]
        if r.get("client_name"):
            names.setdefault(a, r["client_name"])
        if r.get("server_name"):
            names.setdefault(b, r["server_name"])
        key = (a, b) if a <= b else (b, a)
        pk = r["pkts_cs"] + r["pkts_sc"]
        by = r["bytes_cs"] + r["bytes_sc"]
        e = pairs.get(key)
        if e is None:
            e = pairs[key] = {"a": key[0], "b": key[1], "packets": 0, "bytes": 0,
                              "flows": 0, "_lab": Counter(), "_g": Counter()}
        e["packets"] += pk
        e["bytes"] += by
        e["flows"] += 1
        lab = "%s/%s" % (r["proto"], r["port"]) if r["port"] is not None else r["proto"]
        if r.get("guess"):
            lab += " " + r["guess"] + ("?" if r["conf"] <= 1 else "")
            e["_g"][r["guess"]] += pk
        elif r.get("service"):
            lab += " " + r["service"]
        e["_lab"][lab] += pk
    edges = sorted(pairs.values(), key=lambda e: e["packets"], reverse=True)
    total = len(edges)
    edges = edges[:limit]
    for e in edges:
        e["labels"] = [k for k, _ in e.pop("_lab").most_common(6)]
        g = e.pop("_g")
        e["guess"] = g.most_common(1)[0][0] if g else ""
        for ip in (e["a"], e["b"]):
            nodes[ip][0] += e["packets"]
            nodes[ip][1] += e["bytes"]
    return {
        "total_edges": total,
        "edges": edges,
        "nodes": [{"id": ip, "name": names.get(ip, ""), "kind": addr_kind(ip),
                   "packets": v[0], "bytes": v[1]} for ip, v in nodes.items()],
    }
