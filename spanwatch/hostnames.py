"""Passive local hostname discovery.

Hosts announce their own names on the wire. A SPAN port sees that chatter, so
the sniffer can learn names without credentials or queries:

  dhcp     option 12 (hostname) / 81 (client FQDN) in client messages; ACKs and
           renewals bind the client MAC to its leased IP
  mdns     A/AAAA (and reverse PTR) records in multicast DNS responses (*.local)
  netbios  NBNS name registration/refresh broadcasts and positive responses
  llmnr    LLMNR responses (a host answering for its own name)
  dns-ptr  plain-DNS reverse lookups of private addresses answered by a resolver
  arp      sender MAC/IP pairs (binding only, no names)
  file     an optional /etc/hosts-format override file (always wins)

Observations are keyed by (mac, ip, name, source). Names attach to IPs either
directly or through MAC->IP bindings (DHCP ACK, ARP, self-announcements), so a
DHCP DISCOVER that only carries a MAC still ends up on the right address.
Everything here is defensive: a SPAN port sees garbage too.
"""
import ipaddress
import os
import re
import struct
import threading
import time
from collections import Counter, defaultdict
from socket import inet_ntop, AF_INET, AF_INET6

from .parse import _name

HOST_PORTS = frozenset((67, 68, 137, 5353, 5355))
WEIGHT = {"file": 3, "dhcp": 2, "mdns": 2, "netbios": 2, "dns-ptr": 2, "llmnr": 1}
STALE = 30 * 86400          # ignore observations older than this
MAX_OBS = 50_000
MAX_BIND = 50_000
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".localdomain", ".home.arpa",
                  ".internal", ".localnet")
JUNK = {"", "localhost", "unknown", "(none)", "none", "null", "*", "-"}
_OK = re.compile(r"^[\w][\w.-]{0,252}$")
ZERO4 = b"\0\0\0\0"


def mac_str(b):
    return ":".join("%02x" % x for x in b)


def clean(name):
    """Display form: trimmed, spaces -> '-', local suffix removed, case kept.
    Returns '' for junk."""
    n = str(name or "").strip().strip("\0").rstrip(".").replace(" ", "-")
    low = n.lower()
    for suf in LOCAL_SUFFIXES:
        if low.endswith(suf) and len(low) > len(suf):
            n = n[:-len(suf)]
            low = low[:-len(suf)]
            break
    if low in JUNK or not _OK.match(n) or n.startswith("_"):
        return ""
    return n


def norm(name):
    return clean(name).lower()


def rev_to_ip(qname):
    """'4.3.2.1.in-addr.arpa' -> '1.2.3.4'; nibble ip6.arpa -> IPv6. Else None."""
    q = str(qname or "").lower().rstrip(".")
    try:
        if q.endswith(".in-addr.arpa"):
            p = q[:-13].split(".")
            if len(p) == 4:
                return str(ipaddress.IPv4Address(".".join(reversed(p))))
        elif q.endswith(".ip6.arpa"):
            p = q[:-9].split(".")
            if len(p) == 32:
                return str(ipaddress.IPv6Address(int("".join(reversed(p)), 16)))
    except ValueError:
        pass
    return None


def is_local_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_private or a.is_link_local) and not (a.is_loopback or a.is_unspecified
                                                        or a.is_multicast)


# ---------------------------------------------------------------- parsers

def parse_dhcp(p):
    """BOOTP/DHCPv4 payload -> dict or None."""
    if len(p) < 240 or p[236:240] != b"\x63\x82\x53\x63":
        return None
    if p[1] != 1 or p[2] != 6:          # Ethernet hardware addresses only
        return None
    opts = {}
    i, n = 240, len(p)
    while i < n:
        c = p[i]
        if c == 0:
            i += 1
            continue
        if c == 255 or i + 1 >= n:
            break
        ln = p[i + 1]
        v = p[i + 2:i + 2 + ln]
        if len(v) < ln:
            break
        opts.setdefault(c, bytes(v))
        i += 2 + ln
    host = ""
    if 12 in opts:
        host = opts[12].split(b"\0", 1)[0].decode("utf-8", "replace")
    fqdn = ""
    v = opts.get(81)
    if v and len(v) > 3:
        if v[0] & 0x04:                  # E flag: canonical wire format
            try:
                fqdn = _name(v, 3)[0]
            except (ValueError, IndexError):
                fqdn = ""
            if fqdn == ".":
                fqdn = ""
        else:
            fqdn = v[3:].split(b"\0", 1)[0].decode("utf-8", "replace")
    req = opts.get(50)
    mt = opts.get(53)
    return {
        "op": p[0], "type": mt[0] if mt else 0, "mac": mac_str(p[28:34]),
        "ciaddr": inet_ntop(AF_INET, p[12:16]) if p[12:16] != ZERO4 else "",
        "yiaddr": inet_ntop(AF_INET, p[16:20]) if p[16:20] != ZERO4 else "",
        "requested": inet_ntop(AF_INET, req) if req and len(req) == 4 and req != ZERO4 else "",
        "hostname": host, "fqdn": fqdn,
    }


def dns_records(msg, sections=(1, 2, 3)):
    """Walk a DNS-format message. Returns (header, [(section, name, type, (off, len))]).
    section: 1 answer, 2 authority, 3 additional."""
    if len(msg) < 12:
        return None, []
    tid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", msg)
    hdr = {"id": tid, "qr": flags >> 15, "opcode": (flags >> 11) & 0xF,
           "rcode": flags & 0xF, "counts": (qd, an, ns, ar)}
    out = []
    off = 12
    try:
        for _ in range(min(qd, 16)):
            _qn, off = _name(msg, off)
            off += 4
        for sec, cnt in ((1, an), (2, ns), (3, ar)):
            for _ in range(min(cnt, 128)):
                name, off = _name(msg, off)
                typ, _cls, _ttl, rdlen = struct.unpack_from("!HHIH", msg, off)
                off += 10
                if off + rdlen > len(msg):
                    return hdr, out
                if sec in sections:
                    out.append((sec, name, typ, (off, rdlen)))
                off += rdlen
    except (ValueError, struct.error, IndexError):
        pass
    return hdr, out


def netbios_decode(label):
    """First-level-encoded NetBIOS label -> (name, suffix) or None."""
    if len(label) != 32 or any(c < "A" or c > "P" for c in label):
        return None
    raw = bytes(((ord(label[i]) - 65) << 4) | (ord(label[i + 1]) - 65) for i in range(0, 32, 2))
    name = raw[:15].rstrip(b" \0")
    if not name or any(b < 0x21 or b > 0x7E for b in name):
        return None
    return name.decode("ascii"), raw[15]


def l2_arp_offset(buf, n):
    """Offset of the ARP header in an Ethernet(/VLAN) frame, else None."""
    if n < 14:
        return None
    et = (buf[12] << 8) | buf[13]
    off = 14
    while et in (0x8100, 0x88A8, 0x9100) and off + 4 <= n:
        et = (buf[off + 2] << 8) | buf[off + 3]
        off += 4
    return off if et == 0x0806 else None


# ---------------------------------------------------------------- collector

class Collector:
    """Per-session observation buffer. Callers hold the session lock."""

    def __init__(self):
        self.obs = {}    # (mac, ip, name, source) -> [first, last, hits]
        self.binds = {}  # (mac, ip) -> [source, first, last, hits]

    def __len__(self):
        return len(self.obs)

    def observe(self, mac, ip, name, source, ts):
        name = clean(name)
        if not name:
            return
        k = (mac or "", ip or "", name, source)
        o = self.obs.get(k)
        if o is None:
            if len(self.obs) >= MAX_OBS:
                return
            self.obs[k] = [ts, ts, 1]
        else:
            o[1] = max(o[1], ts)
            o[2] += 1

    def bind(self, mac, ip, source, ts):
        if not mac or not ip or mac == "00:00:00:00:00:00":
            return
        if int(mac[:2], 16) & 1:          # multicast/broadcast MAC
            return
        k = (mac, ip)
        b = self.binds.get(k)
        if b is None:
            if len(self.binds) >= MAX_BIND:
                return
            self.binds[k] = [source, ts, ts, 1]
        else:
            b[2] = max(b[2], ts)
            b[3] += 1

    # --- feeds
    def arp(self, buf, n, ts):
        off = l2_arp_offset(buf, n)
        if off is None or off + 28 > n:
            return
        if bytes(buf[off:off + 6]) != b"\x00\x01\x08\x00\x06\x04":
            return
        spa = bytes(buf[off + 14:off + 18])
        if spa == ZERO4:                  # ARP probe: no address yet
            return
        self.bind(mac_str(buf[off + 8:off + 14]), inet_ntop(AF_INET, spa), "arp", ts)

    def udp(self, buf, src, sport, dst, dport, poff, pend, ts):
        pay = bytes(buf[poff:pend])
        smac = mac_str(buf[6:12])
        try:
            if sport in (67, 68) or dport in (67, 68):
                self._dhcp(pay, ts)
            elif sport == 5353 or dport == 5353:
                self._addr_records(pay, src, smac, "mdns", ts, ptr=True)
            elif sport == 5355:
                self._addr_records(pay, src, smac, "llmnr", ts)
            elif sport == 137 or dport == 137:
                self._nbns(pay, src, smac, ts)
        except (ValueError, struct.error, IndexError):
            pass

    def _dhcp(self, pay, ts):
        d = parse_dhcp(pay)
        if not d:
            return
        name = d["hostname"] or d["fqdn"]
        mac = d["mac"]
        if d["op"] == 1:
            if d["ciaddr"]:               # renew/rebind/inform: client owns ciaddr
                self.bind(mac, d["ciaddr"], "dhcp", ts)
            ip = d["ciaddr"] or (d["requested"] if d["type"] == 3 else "")
            if name:
                self.observe(mac, ip, name, "dhcp", ts)
        elif d["op"] == 2 and d["type"] == 5 and d["yiaddr"]:   # ACK
            self.bind(mac, d["yiaddr"], "dhcp", ts)
            if name:
                self.observe(mac, d["yiaddr"], name, "dhcp", ts)

    def _addr_records(self, msg, src, smac, source, ts, ptr=False):
        hdr, rrs = dns_records(msg)
        if not hdr or hdr["qr"] != 1 or hdr["opcode"] != 0 or hdr["rcode"] != 0:
            return
        for _sec, name, typ, (o, ln) in rrs:
            ip = None
            if typ == 1 and ln == 4:
                ip = inet_ntop(AF_INET, msg[o:o + 4])
            elif typ == 28 and ln == 16:
                ip = inet_ntop(AF_INET6, msg[o:o + 16])
            elif typ == 12 and ptr:
                ip = rev_to_ip(name)
                if ip:
                    name = _name(msg, o)[0]
            if not ip:
                continue
            if source == "mdns" and not name.lower().endswith(".local"):
                continue
            mine = ip == src
            self.observe(smac if mine else "", ip, name, source, ts)
            if mine:
                self.bind(smac, ip, source, ts)

    def _nbns(self, pay, src, smac, ts):
        hdr, rrs = dns_records(pay)
        if not hdr:
            return
        op, qr = hdr["opcode"], hdr["qr"]
        # registration/refresh requests (the host itself), or positive answers
        if not ((qr == 0 and op in (5, 8, 9)) or (qr == 1 and op == 0 and hdr["rcode"] == 0)):
            return
        for _sec, name, typ, (o, ln) in rrs:
            if typ != 0x20:
                continue
            nb = netbios_decode(name.split(".", 1)[0])
            if not nb or nb[1] != 0x00:   # workstation service names only
                continue
            for i in range(o, o + ln - 5, 6):
                if pay[i] & 0x80:         # group name (WORKGROUP etc.)
                    continue
                ip = inet_ntop(AF_INET, pay[i + 2:i + 6])
                if ip == "0.0.0.0":
                    continue
                mine = qr == 0 and ip == src
                self.observe(smac if mine else "", ip, nb[0], "netbios", ts)
                if mine:
                    self.bind(smac, ip, "netbios", ts)

    def ptr(self, qname, answers, ts):
        """Plain DNS reverse lookup answered by a resolver (port 53)."""
        ip = rev_to_ip(qname)
        if not ip or not is_local_ip(ip):
            return
        for a in answers:
            if a.startswith("PTR "):
                self.observe("", ip, a[4:], "dns-ptr", ts)

    # --- export
    def obs_rows(self):
        return [(k[0], k[1], k[2], k[3], v[0], v[1], v[2]) for k, v in self.obs.items()]

    def bind_rows(self):
        return [(k[0], k[1], v[0], v[1], v[2], v[3]) for k, v in self.binds.items()]


# ---------------------------------------------------------------- resolution

def read_hosts_file(path):
    """/etc/hosts format -> [(ip, name)]. Missing file -> []."""
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split("#", 1)[0].split()
                if len(parts) < 2:
                    continue
                try:
                    ip = str(ipaddress.ip_address(parts[0]))
                except ValueError:
                    continue
                for nm in parts[1:]:
                    out.append((ip, nm))
    except OSError:
        pass
    return out


def resolve(obs, binds, now=None, stale=STALE):
    """obs: [(mac, ip, name, source, first, last, hits)]
    binds: [(mac, ip, source, first, last, hits)]
    Returns {key: entry}; key is the IP, or 'mac:<mac>' when no IP is known."""
    now = now or time.time()
    ip_mac = {}                      # ip -> (mac, last) newest claimant
    for mac, ip, _src, _f, last, _h in binds:
        if now - last > stale:
            continue
        cur = ip_mac.get(ip)
        if cur is None or last > cur[1]:
            ip_mac[ip] = (mac, last)
    mac_ips = defaultdict(set)
    for ip, (mac, _l) in ip_mac.items():
        mac_ips[mac].add(ip)

    cand = defaultdict(lambda: defaultdict(lambda: {"src": set(), "first": 0, "last": 0,
                                                     "hits": 0, "forms": Counter(), "macs": set()}))
    for mac, ip, name, src, first, last, hits in obs:
        if src != "file" and now - last > stale:
            continue
        key = norm(name)
        if not key:
            continue
        targets = set()
        if ip:
            cur = ip_mac.get(ip)
            # the address has since been claimed by a different MAC: stale
            if not (mac and cur and cur[0] != mac and cur[1] > last):
                targets.add(ip)
        if mac:
            targets |= mac_ips.get(mac, set())
        if not targets and mac:
            targets.add("mac:" + mac)
        for t in targets:
            c = cand[t][key]
            c["src"].add(src)
            c["first"] = min(c["first"] or first, first)
            c["last"] = max(c["last"], last)
            c["hits"] += hits
            c["forms"][clean(name)] += hits
            if mac:
                c["macs"].add(mac)

    def score(item):
        c = item[1]
        return ("file" in c["src"], sum(WEIGHT.get(s, 1) for s in c["src"]), c["last"])

    out = {}
    for t, names in cand.items():
        ranked = sorted(names.items(), key=score, reverse=True)
        _key, c = ranked[0]
        forms = c["forms"].most_common()
        disp = next((f for f, _ in forms if not f.isupper()), forms[0][0])
        if "file" in c["src"] or len(c["src"]) >= 2:
            conf = 3
        else:
            conf = 2 if max(WEIGHT.get(s, 1) for s in c["src"]) >= 2 else 1
        ip = "" if t.startswith("mac:") else t
        if not ip:
            mac = t[4:]
        else:
            mac = ip_mac.get(ip, ("",))[0] or next(iter(sorted(c["macs"])), "")
        out[t] = {
            "ip": ip, "name": disp, "conf": conf, "sources": sorted(c["src"]),
            "mac": mac, "alts": [n["forms"].most_common(1)[0][0] for _k, n in ranked[1:6]],
            "first": c["first"], "last": c["last"], "hits": c["hits"],
        }
    return out


class Directory:
    """Global hostname table: SQLite history + live session + override file."""

    def __init__(self, store, hosts_file=None, live=None, ttl=5.0):
        self.store = store
        self.hosts_file = hosts_file
        self.live = live or (lambda: ([], []))
        self.ttl = ttl
        self.lock = threading.Lock()
        self._cache = (0.0, {})
        self._file = (None, [])

    def _file_obs(self):
        p = self.hosts_file
        if not p:
            return []
        try:
            mt = os.stat(p).st_mtime
        except OSError:
            return []
        if self._file[0] != mt:
            self._file = (mt, read_hosts_file(p))
        now = time.time()
        return [("", ip, nm, "file", now, now, 1) for ip, nm in self._file[1]]

    def table(self, fresh=False):
        with self.lock:
            ts, tab = self._cache
            if fresh or time.time() - ts > self.ttl:
                obs, binds = self.store.host_rows()
                lo, lb = self.live()
                tab = resolve(obs + lo + self._file_obs(), binds + lb)
                self._cache = (time.time(), tab)
            return tab

    def lookup(self):
        """ip -> name, for labelling rows."""
        return {k: v["name"] for k, v in self.table().items() if v["ip"]}

    def rows(self, q=""):
        rows = list(self.table().values())
        q = q.strip().lower()
        if q:
            rows = [r for r in rows if q in r["ip"].lower() or q in r["name"].lower()
                    or q in r["mac"] or any(q in a.lower() for a in r["alts"])
                    or any(q in s for s in r["sources"])]
        rows.sort(key=lambda r: (r["ip"] == "", _ipkey(r["ip"]), r["mac"]))
        return rows


def _ipkey(ip):
    try:
        a = ipaddress.ip_address(ip)
        return (a.version, int(a))
    except ValueError:
        return (9, 0)


def hosts_text(rows, min_conf=1):
    lines = ["# spanwatch: passively learned local hostnames (%s)"
             % time.strftime("%Y-%m-%d %H:%M:%S"),
             "# conf 3 = 2+ sources agree or override file, 2 = one strong source, 1 = weak"]
    for r in rows:
        if not r["ip"] or r["conf"] < min_conf:
            continue
        note = "conf %d %s" % (r["conf"], ",".join(r["sources"]))
        if r["mac"]:
            note += " " + r["mac"]
        if r["alts"]:
            note += " aka " + ",".join(r["alts"])
        lines.append("%-40s %-32s # %s" % (r["ip"], r["name"], note))
    return "\n".join(lines) + "\n"
