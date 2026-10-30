"""Build synthetic Ethernet frames / pcaps for tests (no root needed)."""
import socket
import struct

MAC_A = b"\x02\x00\x00\x00\x00\x0a"
MAC_B = b"\x02\x00\x00\x00\x00\x0b"


def eth(payload, et=0x0800, vlan=None):
    hdr = MAC_B + MAC_A
    if vlan is not None:
        hdr += struct.pack("!HH", 0x8100, vlan)
    return hdr + struct.pack("!H", et) + payload


def ipv4(src, dst, proto, l4, frag=0):
    tot = 20 + len(l4)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, 1, frag, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + l4


def ipv6(src, dst, nh, l4):
    return struct.pack("!IHBB16s16s", 6 << 28, len(l4), nh, 64,
                       socket.inet_pton(socket.AF_INET6, src),
                       socket.inet_pton(socket.AF_INET6, dst)) + l4


def udp(sp, dp, data=b""):
    return struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data


def tcp(sp, dp, flags, data=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, 1, 0, 5 << 4, flags, 65535, 0, 0) + data


def icmp(t, code=0):
    return struct.pack("!BBHI", t, code, 0, 0)


def qname(name):
    out = b""
    for p in name.strip(".").split("."):
        out += bytes([len(p)]) + p.encode()
    return out + b"\0"


def dns_query(tid, name, qtype=1):
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qname(name) + struct.pack("!HH", qtype, 1)


def dns_response(tid, name, qtype, answers, rcode=0):
    """answers: list of (type, rdata_bytes). Uses name compression ptr 0xc00c."""
    msg = struct.pack("!HHHHHH", tid, 0x8180 | rcode, 1, len(answers), 0, 0)
    msg += qname(name) + struct.pack("!HH", qtype, 1)
    for typ, rd in answers:
        msg += b"\xc0\x0c" + struct.pack("!HHIH", typ, 1, 300, len(rd)) + rd
    return msg


def a(ip):
    return (1, socket.inet_aton(ip))


def aaaa(ip):
    return (28, socket.inet_pton(socket.AF_INET6, ip))


def cname(name):
    return (5, qname(name))


def write_pcap(path, frames, t0=1_700_000_000.0, step=0.001):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, f in enumerate(frames):
            ts = t0 + i * step
            fh.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(f), len(f)))
            fh.write(f)


def sample_frames():
    C, R, S = "192.168.1.50", "192.168.1.1", "93.184.216.34"
    fr = []
    # DNS: query + response with CNAME chain
    fr.append(eth(ipv4(C, R, 17, udp(51000, 53, dns_query(0x1234, "www.example.com")))))
    fr.append(eth(ipv4(R, C, 17, udp(53, 51000, dns_response(
        0x1234, "www.example.com", 1, [cname("edge.example.net"), a(S), a("93.184.216.35")])))))
    # NXDOMAIN
    fr.append(eth(ipv4(C, R, 17, udp(51001, 53, dns_query(7, "nope.invalid")))))
    fr.append(eth(ipv4(R, C, 17, udp(53, 51001, dns_response(7, "nope.invalid", 1, [], rcode=3)))))
    # unanswered AAAA
    fr.append(eth(ipv4(C, "1.1.1.1", 17, udp(51002, 53, dns_query(9, "lost.example", 28)))))
    # TCP 443 handshake + data from two ephemeral ports -> one conversation
    for sp in (40000, 40001):
        fr.append(eth(ipv4(C, S, 6, tcp(sp, 443, 0x02))))
        fr.append(eth(ipv4(S, C, 6, tcp(443, sp, 0x12))))
        fr.append(eth(ipv4(C, S, 6, tcp(sp, 443, 0x18, b"x" * 100))))
        fr.append(eth(ipv4(S, C, 6, tcp(443, sp, 0x18, b"y" * 1000))))
    # server on a high port (seen via SYN) must be oriented correctly
    fr.append(eth(ipv4(C, "192.168.1.9", 6, tcp(443, 50505, 0x02))))
    fr.append(eth(ipv4("192.168.1.9", C, 6, tcp(50505, 443, 0x12))))
    # ICMP echo + reply
    fr.append(eth(ipv4(C, R, 1, icmp(8))))
    fr.append(eth(ipv4(R, C, 1, icmp(0))))
    # VLAN-tagged UDP NTP
    fr.append(eth(ipv4(C, "162.159.200.1", 17, udp(123, 123, b"\0" * 48)), vlan=10))
    # IPv6 QUIC
    fr.append(eth(ipv6("2001:db8::50", "2606:4700::1", 17, udp(55555, 443, b"q" * 64)), et=0x86DD))
    # IPv4 non-first fragment
    fr.append(eth(ipv4(C, S, 17, b"z" * 40, frag=185)))
    # ARP + LLDP
    fr.append(eth(b"\0" * 28, et=0x0806))
    fr.append(eth(b"\0" * 40, et=0x88CC))
    # garbage
    fr.append(b"\x01\x02")
    return fr


def client_hello(sni, pad=0):
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    exts = struct.pack("!HH", 0x0015, pad) + b"\0" * pad + sni_ext
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def rnd(n, seed=1):
    import random
    r = random.Random(seed)
    return bytes(r.getrandbits(8) for _ in range(n))
