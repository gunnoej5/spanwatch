"""On-demand registry lookups for public IPs.

RDAP is bootstrapped through rdap.arin.net, which answers ARIN space itself and
redirects to RIPE / APNIC / LACNIC / AFRINIC for theirs. Origin ASN + AS name
come from Team Cymru's IP-to-ASN whois (TCP/43). Nothing is looked up unless the
user asks; private/reserved addresses are never sent anywhere.
"""
import ipaddress
import json
import socket
import threading
import time
import urllib.request

RDAP_URL = "https://rdap.arin.net/registry/ip/%s"
CYMRU = ("whois.cymru.com", 43)
TTL = 7 * 86400      # good answers
FAIL_TTL = 300       # failures: don't hammer
MIN_GAP = 1.0        # seconds between outbound RDAP queries (ARIN rate-limits)
UA = "spanwatch (+https://github.com/gunnoej5/spanwatch)"
RIRS = {"whois.arin.net": "ARIN", "whois.ripe.net": "RIPE NCC",
        "whois.apnic.net": "APNIC", "whois.lacnic.net": "LACNIC",
        "whois.afrinic.net": "AFRINIC"}


def public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


def fetch_rdap(ip, timeout=8):
    req = urllib.request.Request(RDAP_URL % ip, headers={
        "Accept": "application/rdap+json, application/json", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(2_000_000)), r.geturl()


def fetch_cymru(ip, timeout=6):
    with socket.create_connection(CYMRU, timeout=timeout) as s:
        s.sendall((" -v %s\n" % ip).encode())
        buf = b""
        while len(buf) < 65536:
            b = s.recv(4096)
            if not b:
                break
            buf += b
    return buf.decode("utf-8", "replace")


def parse_cymru(txt):
    for line in txt.splitlines():
        p = [x.strip() for x in line.split("|")]
        if len(p) >= 7 and p[0].isdigit():
            return {"asn": int(p[0]), "bgp_prefix": p[2], "cc": p[3],
                    "registry": p[4].upper(), "allocated": p[5], "as_name": p[6]}
    return None


def _vcard(ent, key):
    v = ent.get("vcardArray")
    if not (isinstance(v, list) and len(v) > 1 and isinstance(v[1], list)):
        return None
    for item in v[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == key:
            val = item[3]
            if isinstance(val, list):
                val = " ".join(str(x) for x in val if x)
            return str(val).strip() or None
    return None


def _walk(ents, depth=0):
    for e in ents or []:
        if isinstance(e, dict):
            yield e
            if depth < 3:
                yield from _walk(e.get("entities"), depth + 1)


def parse_rdap(d, url=""):
    out = {"handle": d.get("handle"), "name": d.get("name"), "type": d.get("type"),
           "country": d.get("country"), "parent": d.get("parentHandle")}
    s, e = d.get("startAddress"), d.get("endAddress")
    out["range"] = "%s - %s" % (s, e) if s and e else None
    out["cidrs"] = ["%s/%s" % (c.get("v4prefix") or c.get("v6prefix"), c.get("length"))
                    for c in d.get("cidr0_cidrs") or [] if isinstance(c, dict)]
    for ev in d.get("events") or []:
        a, dt = ev.get("eventAction"), (ev.get("eventDate") or "")[:10]
        if a == "registration":
            out["registered"] = dt
        elif a == "last changed":
            out["updated"] = dt
    org = abuse = fallback = None
    for ent in _walk(d.get("entities")):
        roles = ent.get("roles") or []
        if org is None and "registrant" in roles:
            org = _vcard(ent, "fn")
        if fallback is None and ("administrative" in roles or "technical" in roles):
            fallback = _vcard(ent, "fn")
        if abuse is None and "abuse" in roles:
            abuse = _vcard(ent, "email")
    out["org"] = org or fallback
    out["abuse"] = abuse
    p43 = (d.get("port43") or "").lower()
    out["rir"] = RIRS.get(p43, p43 or None)
    self_link = next((l.get("href") for l in d.get("links") or []
                      if isinstance(l, dict) and l.get("rel") == "self"), None)
    link = self_link or url or ""
    out["rdap_url"] = link if link.startswith("https://") else None
    return out


def _err(e):
    return ("%s: %s" % (type(e).__name__, e))[:200]


class Whois:
    def __init__(self, store=None, enabled=True, rdap=fetch_rdap, cymru=fetch_cymru):
        self.store = store
        self.enabled = enabled
        self.rdap, self.cymru = rdap, cymru
        self.lock = threading.Lock()
        self.sem = threading.Semaphore(2)
        self.last = 0.0
        self.inflight = {}
        self.mem = store.whois_all() if store is not None else {}

    def short(self, ip):
        d = self.mem.get(ip)
        return (d or {}).get("short", "")

    def lookup(self, ip, refresh=False):
        if not self.enabled:
            raise PermissionError("whois lookups are disabled (--no-whois)")
        ip = str(ipaddress.ip_address(str(ip).strip()))   # ValueError if junk
        if not public(ip):
            raise LookupError("%s is private/reserved: no public registry record, not sent anywhere" % ip)
        with self.lock:
            d = self.mem.get(ip)
            if d and not refresh and time.time() - d["ts"] < (TTL if d.get("ok") else FAIL_TTL):
                return dict(d, cached=True)
            ev = self.inflight.get(ip)
            owner = ev is None
            if owner:
                ev = self.inflight[ip] = threading.Event()
        if not owner:
            ev.wait(25)
            d = self.mem.get(ip)
            return dict(d, cached=True) if d else {"ip": ip, "ok": False, "errors": ["timed out"]}
        try:
            d = self._fetch(ip)
        finally:
            with self.lock:
                self.inflight.pop(ip, None)
            ev.set()
        return dict(d, cached=False)

    def _fetch(self, ip):
        res = {"ip": ip, "ts": time.time(), "errors": []}
        with self.sem:
            with self.lock:
                now = time.time()
                wait = self.last + MIN_GAP - now
                self.last = max(now, self.last + MIN_GAP)
            if wait > 0:
                time.sleep(wait)
            try:
                d, url = self.rdap(ip)
                res["rdap"] = parse_rdap(d, url)
            except Exception as e:
                res["errors"].append("rdap: " + _err(e))
        try:
            res["asn"] = parse_cymru(self.cymru(ip))
        except Exception as e:
            res["errors"].append("cymru: " + _err(e))
        r, a = res.get("rdap") or {}, res.get("asn") or {}
        res["ok"] = bool(r or a)
        res["short"] = r.get("org") or a.get("as_name") or r.get("name") or ""
        self.mem[ip] = res
        if res["ok"] and self.store is not None:
            try:
                self.store.whois_put(ip, res)
            except Exception:
                pass
        return res
