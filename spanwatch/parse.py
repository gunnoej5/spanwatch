"""Frame parsing: Ethernet/VLAN -> IPv4/IPv6 -> TCP/UDP/ICMP, plus DNS.

Stdlib only. Everything is defensive: malformed frames return None (or a
partial result) instead of raising, because a SPAN port sees everything.
"""
import struct
from socket import inet_ntop, AF_INET, AF_INET6

PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6-in-IP", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM", 112: "VRRP",
    132: "SCTP",
}

ETHERTYPES = {
    0x0806: "ARP", 0x8035: "RARP", 0x88CC: "LLDP", 0x888E: "EAPOL",
    0x8863: "PPPoE-disc", 0x8864: "PPPoE-sess", 0x88E1: "HomePlug-AV",
    0x893A: "IEEE-1905", 0x88F7: "PTP", 0x9000: "Loopback", 0x8809: "Slow (LACP)",
    0x88E5: "MACsec", 0x8847: "MPLS", 0x0842: "Wake-on-LAN",
}

# Port -> service label (display + "which side is the server" heuristic).
SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 88: "kerberos", 110: "pop3",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 500: "isakmp",
    514: "syslog", 546: "dhcpv6", 547: "dhcpv6", 554: "rtsp", 587: "submission",
    631: "ipp", 636: "ldaps", 853: "dns-over-tls", 993: "imaps", 995: "pop3s",
    1194: "openvpn", 1883: "mqtt", 1900: "ssdp", 3074: "xbox-live",
    3306: "mysql", 3389: "rdp", 3478: "stun", 3702: "ws-discovery",
    4500: "ipsec-nat-t", 5060: "sip", 5222: "xmpp", 5228: "google-push",
    5353: "mdns", 5355: "llmnr", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8008: "http-alt", 8080: "http-alt", 8443: "https-alt", 8883: "mqtts",
    9100: "jetdirect", 10001: "ubnt-discovery", 32400: "plex",
    41641: "tailscale", 51820: "wireguard",
}

KIND_IP = 0
KIND_L2 = 1

TCP_SYN = 0x02
TCP_ACK = 0x10


def service_name(proto, port):
    if port is None:
        return ""
    if proto == 17 and port == 443:
        return "quic"
    if proto in (1, 58):
        return ICMP_TYPES.get((proto, port), "")
    return SERVICES.get(port, "")


ICMP_TYPES = {
    (1, 0): "echo-reply", (1, 3): "unreachable", (1, 5): "redirect",
    (1, 8): "echo", (1, 11): "ttl-exceeded",
    (58, 1): "unreachable", (58, 2): "too-big", (58, 3): "time-exceeded",
    (58, 128): "echo", (58, 129): "echo-reply", (58, 133): "router-solicit",
    (58, 134): "router-advert", (58, 135): "neighbor-solicit",
    (58, 136): "neighbor-advert", (58, 143): "mld-report",
}


def parse_frame(buf, n):
    """Parse one Ethernet frame held in buf[0:n].

    Returns one of:
      (KIND_IP, src, dst, proto, sport, dport, ip_len, tcp_flags, pay_off, pay_end)
        sport/dport are None when not applicable (non-first fragment, unknown
        L4). For ICMP/ICMPv6, sport is None and dport is the ICMP type.
        pay_off/pay_end delimit the L4 payload (TCP/UDP only, else 0/0).
      (KIND_L2, ethertype, n)
      None for runts / garbage.
    """
    if n < 14:
        return None
    et = (buf[12] << 8) | buf[13]
    off = 14
    # 802.1Q / 802.1ad / QinQ tags
    while et in (0x8100, 0x88A8, 0x9100) and off + 4 <= n:
        et = (buf[off + 2] << 8) | buf[off + 3]
        off += 4

    if et == 0x0800:
        if n < off + 20:
            return None
        vihl = buf[off]
        ihl = (vihl & 0x0F) * 4
        if (vihl >> 4) != 4 or ihl < 20:
            return None
        tot = (buf[off + 2] << 8) | buf[off + 3]
        frag_off = ((buf[off + 6] << 8) | buf[off + 7]) & 0x1FFF
        proto = buf[off + 9]
        src = inet_ntop(AF_INET, buf[off + 12:off + 16])
        dst = inet_ntop(AF_INET, buf[off + 16:off + 20])
        length = tot if tot else n - off
        end = min(n, off + tot) if tot else n
        l4 = off + ihl
        if frag_off:
            return (KIND_IP, src, dst, proto, None, None, length, 0, 0, 0)
    elif et == 0x86DD:
        if n < off + 40:
            return None
        if (buf[off] >> 4) != 6:
            return None
        plen = (buf[off + 4] << 8) | buf[off + 5]
        proto = buf[off + 6]
        src = inet_ntop(AF_INET6, buf[off + 8:off + 24])
        dst = inet_ntop(AF_INET6, buf[off + 24:off + 40])
        length = plen + 40 if plen else n - off  # plen 0 = jumbogram
        end = min(n, off + 40 + plen) if plen else n
        l4 = off + 40
        hops = 0
        while proto in (0, 43, 44, 51, 60) and hops < 8:
            hops += 1
            if l4 + 8 > end:
                return (KIND_IP, src, dst, proto, None, None, length, 0, 0, 0)
            nxt = buf[l4]
            if proto == 44:  # fragment header
                fo = ((buf[l4 + 2] << 8) | buf[l4 + 3]) >> 3
                l4 += 8
                proto = nxt
                if fo:
                    return (KIND_IP, src, dst, proto, None, None, length, 0, 0, 0)
                continue
            hl = (buf[l4 + 1] + 2) * 4 if proto == 51 else (buf[l4 + 1] + 1) * 8
            l4 += hl
            proto = nxt
    else:
        return (KIND_L2, et, n)

    sport = dport = None
    flags = 0
    pay_off = pay_end = 0
    if proto == 6:
        if l4 + 14 <= end:
            sport, dport = struct.unpack_from("!HH", buf, l4)
            flags = buf[l4 + 13]
            doff = (buf[l4 + 12] >> 4) * 4
            if doff >= 20 and l4 + doff <= end:
                pay_off, pay_end = l4 + doff, end
    elif proto == 17:
        if l4 + 8 <= end:
            sport, dport = struct.unpack_from("!HH", buf, l4)
            pay_off, pay_end = l4 + 8, end
    elif proto == 132:
        if l4 + 4 <= end:
            sport, dport = struct.unpack_from("!HH", buf, l4)
    elif proto in (1, 58):
        if l4 + 1 <= end:
            dport = buf[l4]
    return (KIND_IP, src, dst, proto, sport, dport, length, flags, pay_off, pay_end)


# ---------------------------------------------------------------- DNS

QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG",
    47: "NSEC", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 255: "ANY", 257: "CAA",
}
RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
    5: "REFUSED",
}


def qtype_name(t):
    return QTYPES.get(t, "TYPE%d" % t)


def _name(msg, off):
    """Decode a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels = []
    resume = None
    jumps = 0
    ln = len(msg)
    while True:
        if off >= ln:
            raise ValueError("name runs off end")
        c = msg[off]
        if c == 0:
            off += 1
            break
        if c & 0xC0 == 0xC0:
            if off + 1 >= ln:
                raise ValueError("bad pointer")
            if resume is None:
                resume = off + 2
            off = ((c & 0x3F) << 8) | msg[off + 1]
            jumps += 1
            if jumps > 32:
                raise ValueError("pointer loop")
            continue
        if c & 0xC0:
            raise ValueError("bad label type")
        off += 1
        labels.append(bytes(msg[off:off + c]).decode("ascii", "replace"))
        off += c
        if len(labels) > 127:
            raise ValueError("too many labels")
    return (".".join(labels) or "."), (resume if resume is not None else off)


def parse_dns(msg):
    """Parse a DNS message (bytes). Returns dict or None. Answers are short
    strings: IPs for A/AAAA, 'CNAME x', 'PTR x', 'MX 10 x', etc."""
    if len(msg) < 12:
        return None
    try:
        tid, flags, qd, an, _ns, _ar = struct.unpack_from("!HHHHHH", msg)
    except struct.error:
        return None
    out = {
        "id": tid, "qr": flags >> 15, "opcode": (flags >> 11) & 0xF,
        "rcode": flags & 0xF, "qname": None, "qtype": None, "answers": [],
        "ips": [], "ttl": None,
    }
    off = 12
    try:
        for i in range(min(qd, 4)):
            name, off = _name(msg, off)
            qt, _qc = struct.unpack_from("!HH", msg, off)
            off += 4
            if i == 0:
                out["qname"], out["qtype"] = name, qt
        answers = out["answers"]
        for _ in range(min(an, 64)):
            _rname, off = _name(msg, off)
            typ, _cls, ttl, rdlen = struct.unpack_from("!HHIH", msg, off)
            off += 10
            rd = off
            off += rdlen
            if off > len(msg):
                break
            if out["ttl"] is None or ttl < out["ttl"]:
                out["ttl"] = ttl
            if typ == 1 and rdlen == 4:
                ip = inet_ntop(AF_INET, msg[rd:rd + 4])
                answers.append(ip)
                out["ips"].append(ip)
            elif typ == 28 and rdlen == 16:
                ip = inet_ntop(AF_INET6, msg[rd:rd + 16])
                answers.append(ip)
                out["ips"].append(ip)
            elif typ in (2, 5, 12):
                answers.append("%s %s" % (qtype_name(typ), _name(msg, rd)[0]))
            elif typ == 15 and rdlen >= 3:
                pref = struct.unpack_from("!H", msg, rd)[0]
                answers.append("MX %d %s" % (pref, _name(msg, rd + 2)[0]))
            elif typ == 33 and rdlen >= 7:
                _p, _w, port = struct.unpack_from("!HHH", msg, rd)
                answers.append("SRV %s:%d" % (_name(msg, rd + 6)[0], port))
            elif typ == 16 and rdlen >= 1:
                t = bytes(msg[rd + 1:rd + 1 + msg[rd]]).decode("utf-8", "replace")
                answers.append("TXT " + (t[:60] + "…" if len(t) > 60 else t))
            elif typ in (64, 65) and rdlen >= 3:
                prio = struct.unpack_from("!H", msg, rd)[0]
                tgt = _name(msg, rd + 2)[0]
                answers.append("%s %d %s" % (qtype_name(typ), prio, tgt))
            else:
                answers.append(qtype_name(typ))
    except (ValueError, struct.error, IndexError):
        pass  # keep whatever we got
    return out
