"""IP reputation: local threat-feed matching plus optional AbuseIPDB checks.

Feeds are downloaded about once a day into <data>/feeds/ and matched locally,
so observed traffic never leaves the box. Tiers:
  bad    high-confidence lists (hijacked netblocks, botnet C2)  -> red background
  watch  noisier lists (scanners, brute-forcers, attack sources) -> red outline
  tor    Tor exit relays (informational, not malicious by itself)
AbuseIPDB (optional, needs a key) is only queried for one public IP at a time
when the analyst asks; cached results then feed the same tiers by score.
"""
import bisect
import ipaddress
import json
import os
import threading
import time
import urllib.parse
import urllib.request

UA = "spanwatch (+https://github.com/gunnoej5/spanwatch)"
REFRESH = 86400        # seconds between feed downloads
RETRY = 3600           # after a failed download
MAX_BYTES = 20_000_000

FEEDS = [
    # name, tier, url, format, note
    ("spamhaus-drop", "bad", "https://www.spamhaus.org/drop/drop_v4.json", "spamhaus",
     "Spamhaus DROP: hijacked / criminal netblocks"),
    ("spamhaus-drop6", "bad", "https://www.spamhaus.org/drop/drop_v6.json", "spamhaus",
     "Spamhaus DROPv6"),
    ("feodo", "bad", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "lines",
     "abuse.ch Feodo Tracker: botnet C2 servers"),
    ("firehol-l1", "bad", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
     "lines", "FireHOL level1: curated attack/malware sources (bogons ignored)"),
    ("et-block", "watch", "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", "lines",
     "Emerging Threats block list (DShield top attackers + C2)"),
    ("cins", "watch", "https://cinsscore.com/list/ci-badguys.txt", "lines",
     "CINS Army: scanners and attackers seen by Sentinel IPS"),
    ("blocklist-de", "watch", "https://lists.blocklist.de/lists/all.txt", "lines",
     "blocklist.de: brute-force / attack reports (24-48h)"),
    ("tor-exit", "tor", "https://check.torproject.org/torbulkexitlist", "lines",
     "Tor exit relays"),
]
TIER_RANK = {"bad": 3, "watch": 2, "tor": 1}


def public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


def parse_feed(text, fmt):
    """-> list of ip_network (global space only)."""
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        if fmt == "spamhaus":
            try:
                tok = json.loads(line).get("cidr")
            except ValueError:
                continue
            if not tok:
                continue
        else:
            tok = line.split()[0].split(";")[0].strip()
        try:
            n = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            continue
        # FireHOL level1 carries bogons (10/8, 192.168/16...): never flag those
        if not n.network_address.is_global or n.network_address.is_multicast:
            continue
        nets.append(n)
    return nets


class RangeSet:
    """Merged integer ranges per IP version; O(log n) membership."""

    def __init__(self, nets):
        self.v = {}
        for ver in (4, 6):
            rs = sorted((int(n.network_address), int(n.broadcast_address))
                        for n in nets if n.version == ver)
            starts, ends = [], []
            for s, e in rs:
                if ends and s <= ends[-1] + 1:
                    ends[-1] = max(ends[-1], e)
                else:
                    starts.append(s)
                    ends.append(e)
            self.v[ver] = (starts, ends)
        self.count = len(nets)

    def __contains__(self, addr):
        starts, ends = self.v[addr.version]
        i = bisect.bisect_right(starts, int(addr)) - 1
        return i >= 0 and int(addr) <= ends[i]


class Feeds:
    def __init__(self, data_dir, enabled=True, fetch=None, feeds=FEEDS):
        self.dir = os.path.join(data_dir, "feeds") if data_dir else None
        self.enabled = enabled
        self.feeds = feeds
        self.fetch = fetch or self._http
        self.pace = 0.5 if fetch is None else 0.0   # be polite to feed hosts
        self.sets = {}           # name -> RangeSet
        self.meta = {}           # name -> {updated, count, error, checked}
        self.lock = threading.Lock()
        self._stop = threading.Event()
        if self.dir:
            os.makedirs(self.dir, exist_ok=True)
            for f in feeds:
                self._load_cached(f)

    @staticmethod
    def _http(url):
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read(MAX_BYTES).decode("utf-8", "replace")

    def _paths(self, name):
        return os.path.join(self.dir, name + ".txt"), os.path.join(self.dir, name + ".json")

    def _load_cached(self, f):
        name, _tier, _url, fmt, _note = f
        txt, meta = self._paths(name)
        try:
            with open(meta) as fh:
                m = json.load(fh)
            with open(txt) as fh:
                rs = RangeSet(parse_feed(fh.read(), fmt))
        except (OSError, ValueError):
            return
        with self.lock:
            self.sets[name] = rs
            self.meta[name] = dict(m, count=rs.count)

    def refresh(self, force=False):
        """Download stale feeds. Returns names updated."""
        done = []
        for f in self.feeds:
            name, _tier, url, fmt, _note = f
            m = self.meta.get(name, {})
            age = time.time() - m.get("checked", 0)
            if not force and age < (REFRESH if not m.get("error") else RETRY):
                continue
            try:
                text = self.fetch(url)
                rs = RangeSet(parse_feed(text, fmt))
                if rs.count == 0 and self.sets.get(name):
                    raise ValueError("feed came back empty; keeping previous copy")
                m = {"updated": time.time(), "checked": time.time(), "count": rs.count, "error": None}
                if self.dir:
                    txt, meta = self._paths(name)
                    with open(txt + ".tmp", "w") as fh:
                        fh.write(text)
                    os.replace(txt + ".tmp", txt)
                    with open(meta, "w") as fh:
                        json.dump(m, fh)
                with self.lock:
                    self.sets[name] = rs
                    self.meta[name] = m
                done.append(name)
            except Exception as e:
                with self.lock:
                    self.meta[name] = dict(m, checked=time.time(),
                                           error=("%s: %s" % (type(e).__name__, e))[:200])
            if self.pace:
                time.sleep(self.pace)
        return done

    def start(self):
        if not self.enabled:
            return

        def loop():
            while not self._stop.is_set():
                try:
                    self.refresh()
                except Exception:
                    pass
                self._stop.wait(600)

        threading.Thread(target=loop, name="feeds", daemon=True).start()

    def stop(self):
        self._stop.set()

    def check(self, ip):
        """-> list of (name, tier) for feeds containing ip."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return []
        if not public(ip):
            return []
        with self.lock:
            sets = list(self.sets.items())
        tiers = {f[0]: f[1] for f in self.feeds}
        return [(n, tiers[n]) for n, rs in sets if a in rs]

    def status(self):
        with self.lock:
            return [{"name": n, "tier": t, "note": note, "url": u,
                     **{k: self.meta.get(n, {}).get(k) for k in ("updated", "count", "error")}}
                    for n, t, u, _fmt, note in self.feeds]


# ---------------------------------------------------------------- AbuseIPDB

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSE_TTL = 86400
ABUSE_BAD, ABUSE_WATCH = 75, 25


def load_key(path=None):
    cands = []
    cd = os.environ.get("CREDENTIALS_DIRECTORY")
    if cd:
        cands.append(os.path.join(cd, "abuseipdb"))
    if path:
        cands.append(path)
    for p in cands:
        try:
            with open(p) as fh:
                k = fh.read().strip()
            if k:
                return k
        except OSError:
            continue
    return os.environ.get("SPANWATCH_ABUSEIPDB_KEY", "").strip() or None


def fetch_abuse(ip, key, timeout=10):
    url = ABUSE_URL + "?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    req = urllib.request.Request(url, headers={"Key": key, "Accept": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(1_000_000))


def abuse_tier(score):
    if score is None:
        return None
    return "bad" if score >= ABUSE_BAD else "watch" if score >= ABUSE_WATCH else None


class AbuseIPDB:
    def __init__(self, store=None, key=None, fetch=fetch_abuse):
        self.store, self.key, self.fetch = store, key, fetch
        self.lock = threading.Lock()
        self.last = 0.0
        self.mem = store.kv_all("abuseipdb") if store is not None else {}

    @property
    def enabled(self):
        return bool(self.key)

    def cached(self, ip):
        d = self.mem.get(ip)
        return d if d and d.get("ok") else None

    def lookup(self, ip, refresh=False):
        if not self.key:
            raise PermissionError("AbuseIPDB is not configured (no API key)")
        ip = str(ipaddress.ip_address(str(ip).strip()))
        if not public(ip):
            raise LookupError("%s is private/reserved: not sent anywhere" % ip)
        d = self.mem.get(ip)
        if d and not refresh and time.time() - d["ts"] < (ABUSE_TTL if d.get("ok") else 300):
            return dict(d, cached=True)
        with self.lock:
            wait = self.last + 1.0 - time.time()
            self.last = max(time.time(), self.last + 1.0)
        if wait > 0:
            time.sleep(wait)
        res = {"ip": ip, "ts": time.time()}
        try:
            data = (self.fetch(ip, self.key) or {}).get("data") or {}
            keep = ("abuseConfidenceScore", "totalReports", "numDistinctUsers", "lastReportedAt",
                    "usageType", "isp", "domain", "countryCode", "isTor", "isWhitelisted")
            res.update({k: data.get(k) for k in keep}, ok=True, error=None)
        except Exception as e:
            msg = "%s: %s" % (type(e).__name__, e)
            if getattr(e, "code", None) == 429:
                msg = "AbuseIPDB daily quota reached (HTTP 429)"
            elif getattr(e, "code", None) in (401, 403):
                msg = "AbuseIPDB rejected the API key (HTTP %s)" % e.code
            res.update(ok=False, error=msg[:200])
        res["tier"] = abuse_tier(res.get("abuseConfidenceScore")) if res.get("ok") else None
        self.mem[ip] = res
        if res["ok"] and self.store is not None:
            try:
                self.store.kv_put("abuseipdb", ip, res)
            except Exception:
                pass
        return dict(res, cached=False)


class Reputation:
    """Combines feeds + cached AbuseIPDB into per-IP flags."""

    def __init__(self, feeds, abuse):
        self.feeds, self.abuse = feeds, abuse

    def flag(self, ip):
        hits = self.feeds.check(ip)
        lists = [n for n, _ in hits]
        tier = max((t for _, t in hits), key=TIER_RANK.get, default=None)
        a = self.abuse.cached(ip)
        if a:
            at = a.get("tier")
            if at and (tier is None or TIER_RANK[at] > TIER_RANK[tier]):
                tier = at
            if at:
                lists.append("abuseipdb:%s%%" % a.get("abuseConfidenceScore"))
            if a.get("isTor") and tier is None:
                tier = "tor"
        if not tier:
            return None
        return {"tier": tier, "lists": lists}

    def flags(self, ips):
        out = {}
        for ip in ips:
            f = self.flag(ip)
            if f:
                out[ip] = f
        return out

    def detail(self, ip):
        notes = {f[0]: f[4] for f in self.feeds.feeds}
        meta = {s["name"]: s for s in self.feeds.status()}
        return {
            "ip": ip, "public": public(ip), "flag": self.flag(ip),
            "feeds": [{"name": n, "tier": t, "note": notes.get(n, ""), "updated": meta.get(n, {}).get("updated")}
                      for n, t in self.feeds.check(ip)],
            "abuseipdb": self.abuse.cached(ip), "abuseipdb_enabled": self.abuse.enabled,
        }
