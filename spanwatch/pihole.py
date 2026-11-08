"""Pi-hole v6 API integration (read-only use of an admin credential).

Pi-hole is the LAN's DHCP and DNS server, so it knows things the SPAN port can
only guess at:

  pihole-dhcp  active DHCP leases (MAC, IP, hostname): authoritative
  pihole       FTL's network table (MAC -> IPs with resolved names)
  blocked      which (client, domain) pairs Pi-hole blocked, and why

Every poll logs in with the app password, reads, and logs out again, so no
long-lived session holds one of FTL's limited API slots. Only GET endpoints
are used after login. The password is an admin credential (Pi-hole v6 has no
read-only scope), so it comes from the systemd credential directory or a
root-only file and is never logged or exposed through the dashboard.

Lease and device data feed the hostname directory (host_obs/host_bind).
Blocked queries are kept in the kv table (ns "pihole-blocked", key
"client|domain") and used to mark rows in the DNS log.
"""
import ipaddress
import json
import os
import threading
import time
import urllib.error
import urllib.request

BLOCKED = frozenset((
    "GRAVITY", "REGEX", "DENYLIST", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME",
    "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA",
    "EXTERNAL_BLOCKED_EDE15", "SPECIAL_DOMAIN",
))
NS = "pihole-blocked"
KEEP = 30 * 86400          # blocked pairs not seen for this long are dropped
SLOP = 120                 # seconds of clock/latency slack when matching DNS rows
PAGE = 5000


def load_password(path=None):
    cands = []
    cd = os.environ.get("CREDENTIALS_DIRECTORY")
    if cd:
        cands.append(os.path.join(cd, "pihole"))
    if path:
        cands.append(path)
    for p in cands:
        try:
            with open(p) as fh:
                pw = fh.read().strip()
            if pw:
                return pw
        except OSError:
            continue
    return None


class ApiError(Exception):
    pass


class Client:
    def __init__(self, url, password, timeout=10):
        self.base = url.rstrip("/")
        if self.base.endswith("/api"):
            self.base = self.base[:-4]
        self.password = password
        self.timeout = timeout
        self.sid = None

    def _req(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + "/api" + path, data=data, method=method)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "spanwatch")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.sid:
            req.add_header("X-FTL-SID", self.sid)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            msg = ""
            try:
                msg = json.loads(e.read() or b"{}").get("error", {}).get("message", "")
            except (ValueError, AttributeError, OSError):
                pass
            finally:
                e.close()
            raise ApiError("HTTP %d %s%s" % (e.code, path.split("?")[0], (": " + msg) if msg else "")) from None
        except (urllib.error.URLError, OSError) as e:
            raise ApiError("%s: %s" % (path.split("?")[0], getattr(e, "reason", e))) from None
        return json.loads(raw) if raw else {}

    def login(self):
        d = self._req("POST", "/auth", {"password": self.password})
        s = d.get("session") or {}
        if not s.get("valid"):
            raise ApiError("login rejected: %s" % (s.get("message") or "bad password"))
        self.sid = s.get("sid")  # None when Pi-hole has no password set at all

    def logout(self):
        if self.sid:
            try:
                self._req("DELETE", "/auth")
            except ApiError:
                pass
        self.sid = None

    def get(self, path):
        return self._req("GET", path)


def _ip(s):
    try:
        return str(ipaddress.ip_address(str(s).split("%")[0]))
    except ValueError:
        return None


def _mac(s):
    s = str(s or "").lower()
    # FTL uses pseudo-MACs like "ip-192.168.1.5" for clients it never saw via ARP
    if len(s) == 17 and s.count(":") == 5 and s != "00:00:00:00:00:00":
        return s
    return ""


def lease_rows(leases, now):
    """/api/dhcp/leases -> (obs, binds) rows for Store.host_merge."""
    obs, binds = [], []
    for l in leases or []:
        ip, mac = _ip(l.get("ip")), _mac(l.get("hwaddr"))
        if not ip:
            continue
        name = (l.get("name") or "").strip()
        if name and name != "*":
            obs.append((mac, ip, name, "pihole-dhcp", now, now, 1))
        if mac:
            binds.append((mac, ip, "pihole-dhcp", now, now, 1))
    return obs, binds


def device_rows(devices, now):
    """/api/network/devices -> (obs, binds, vendors). Uses FTL's own timestamps."""
    obs, binds, vendors = [], [], {}
    for d in devices or []:
        mac = _mac(d.get("hwaddr"))
        if mac and d.get("macVendor"):
            vendors[mac] = d["macVendor"]
        first = d.get("firstSeen") or now
        for a in d.get("ips") or []:
            ip = _ip(a.get("ip"))
            if not ip:
                continue
            last = a.get("lastSeen") or d.get("lastQuery") or now
            if a.get("name"):
                obs.append((mac, ip, a["name"], "pihole", min(first, last), last, 1))
            if mac:
                binds.append((mac, ip, "pihole", min(first, last), last, 1))
    return obs, binds, vendors


def blocked_pairs(queries):
    """/api/queries rows -> {(client, domain): {first, last, n, status}} for blocked ones."""
    out = {}
    for q in queries or []:
        st = q.get("status")
        if st not in BLOCKED:
            continue
        ip = _ip((q.get("client") or {}).get("ip"))
        dom = (q.get("domain") or "").lower().rstrip(".")
        ts = q.get("time")
        if not ip or not dom or not isinstance(ts, (int, float)):
            continue
        e = out.setdefault((ip, dom), {"first": ts, "last": ts, "n": 0, "status": st})
        e["first"] = min(e["first"], ts)
        if ts >= e["last"]:
            e["last"], e["status"] = ts, st
        e["n"] += 1
    return out


class PiHole:
    def __init__(self, store, url=None, password=None, interval=300, enabled=True):
        self.store = store
        self.url = url
        self.client = Client(url, password) if (url and password) else None
        self.enabled = bool(enabled and self.client)
        self.interval = max(60, int(interval))
        self.lock = threading.Lock()
        self.vendors = {}
        self.blocked = {}          # (client, domain) -> {first, last, n, status}
        self.since = time.time() - 86400   # first poll backfills a day of queries
        self.state = {"ok": None, "error": None, "last_poll": None, "leases": 0,
                      "devices": 0, "queries": 0}
        self._stop = threading.Event()
        if store is not None and self.enabled:
            self._load()

    def _load(self):
        for k, d in self.store.kv_all(NS).items():
            c, _, dom = k.partition("|")
            self.blocked[(c, dom)] = d
        if self.blocked:
            self.since = max(self.since, max(d["last"] for d in self.blocked.values()))

    # ------------------------------------------------------------ polling
    def start(self):
        if not self.enabled:
            return
        threading.Thread(target=self._loop, name="pihole", daemon=True).start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.poll()
            except Exception as e:  # never let the poller die silently
                with self.lock:
                    self.state.update(ok=False, error="internal: %s" % e, last_poll=time.time())
            self._stop.wait(self.interval)

    def poll(self, now=None):
        if not self.enabled:
            return self.state
        now = now or time.time()
        c = self.client
        try:
            c.login()
            try:
                leases = c.get("/dhcp/leases").get("leases") or []
                devices = c.get("/network/devices?max_devices=999&max_addresses=24").get("devices") or []
                queries = self._queries(c, now)
            finally:
                c.logout()
        except (ApiError, ValueError) as e:
            with self.lock:
                self.state.update(ok=False, error=str(e), last_poll=now)
            return self.state
        lo, lb = lease_rows(leases, now)
        do, db, vendors = device_rows(devices, now)
        self.store.host_merge(lo + do, lb + db)
        new = blocked_pairs(queries)
        with self.lock:
            self.vendors = vendors
            for k, e in new.items():
                cur = self.blocked.get(k)
                if cur:
                    e = {"first": min(cur["first"], e["first"]), "last": max(cur["last"], e["last"]),
                         "n": cur["n"] + e["n"],
                         "status": e["status"] if e["last"] >= cur["last"] else cur["status"]}
                e["ts"] = e["last"]
                self.blocked[k] = e
                self.store.kv_put(NS, "%s|%s" % k, e)
            if queries:
                self.since = max(self.since, max(q.get("time") or 0 for q in queries))
            cut = now - KEEP
            for k in [k for k, e in self.blocked.items() if e["last"] < cut]:
                del self.blocked[k]
            self.store.kv_prune(NS, cut)
            self.state.update(ok=True, error=None, last_poll=now, leases=len(leases),
                              devices=len(devices), queries=len(queries))
        return self.state

    def _queries(self, c, now):
        """Queries since the last poll, paged. Capped so one poll can't run away."""
        out, start = [], 0
        frm = int(self.since)
        while len(out) < 50 * PAGE:
            d = c.get("/queries?from=%d&until=%d&length=%d&start=%d" % (frm, int(now) + 1, PAGE, start))
            rows = d.get("queries") or []
            out.extend(rows)
            if len(rows) < PAGE:
                break
            start += len(rows)
        return out

    # ------------------------------------------------------------ lookups
    def block_for(self, client, qname, ts):
        """Pi-hole status if it blocked this client's lookup of qname around ts."""
        if not self.blocked:
            return None
        e = self.blocked.get((client, (qname or "").lower().rstrip(".")))
        if e and e["first"] - SLOP <= ts <= e["last"] + SLOP:
            return e["status"]
        return None

    def status(self):
        with self.lock:
            return dict(self.state, enabled=self.enabled, url=self.url if self.enabled else None,
                        interval=self.interval, blocked_pairs=len(self.blocked))
