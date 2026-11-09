"""IP -> network owner (ASN) from a local copy of iptoasn.com, plus org groups.

The combined IPv4+IPv6 table (~11 MB gzip, ~720k ranges) is downloaded about
once a day into <data>/feeds/ and looked up locally, so observed addresses
never leave the box. It answers "whose network is this address on" (the AS
that announces it), which is not always whose service it is: plenty of SaaS
runs on Amazon or Google Cloud and will land in their group.

Groups put owners into a few named buckets for the graph's org wedges. The
default is Amazon, Google, Microsoft and everyone else; an optional JSON file
(--orgs-file, default /etc/spanwatch/orgs.json) replaces the list:

  [{"id": "apple", "name": "Apple", "asns": [714, 6185], "match": "apple",
    "color": "#c9d4d8"}, ...]

"match" is a case-insensitive regex tried against the AS description when the
ASN isn't listed. A catch-all "other" group is appended when missing. Wedges
are drawn in list order, clockwise from 12 o'clock, in equal slices.
"""
import bisect
import gzip
import io
import ipaddress
import json
import os
import re
import threading
import time
import urllib.request
from array import array

URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
UA = "spanwatch (+https://github.com/gunnoej5/spanwatch)"
REFRESH = 86400
RETRY = 3600
MAX_BYTES = 60_000_000
FILE = "ip2asn-combined.tsv.gz"

DEFAULT_GROUPS = [
    {"id": "amazon", "name": "Amazon", "color": "#ff9f43",
     "asns": [16509, 14618, 8987, 7224, 38895, 10124], "match": r"\bamazon\b"},
    {"id": "google", "name": "Google", "color": "#6cb6ff",
     "asns": [15169, 396982, 36040, 36384, 36385, 36492, 43515, 19527, 139070, 16550, 16591],
     "match": r"\bgoogle\b|\byoutube\b"},
    {"id": "microsoft", "name": "Microsoft", "color": "#b69cff",
     "asns": [8075, 8068, 8069, 12076, 3598, 6584], "match": r"\bmicrosoft\b"},
    {"id": "other", "name": "Others", "color": "#7f8f96"},
]


def short_name(desc):
    """'AMAZON-02 - Amazon.com, Inc.' -> 'Amazon.com, Inc.'"""
    desc = (desc or "").strip()
    head, sep, tail = desc.partition(" - ")
    return tail.strip() if sep and tail.strip() else desc


class Groups:
    def __init__(self, groups=None):
        gs = [dict(g) for g in (groups or DEFAULT_GROUPS) if isinstance(g, dict) and g.get("id")]
        if not any(g["id"] == "other" for g in gs):
            gs.append(dict(DEFAULT_GROUPS[-1]))
        # catch-all always last so it fills the final slice
        gs = [g for g in gs if g["id"] != "other"] + [g for g in gs if g["id"] == "other"]
        self.groups = gs
        self.by_asn = {}
        self.rx = []
        for g in gs:
            g.setdefault("name", g["id"].title())
            g.setdefault("color", "#7f8f96")
            for a in g.get("asns") or []:
                try:
                    self.by_asn.setdefault(int(a), g["id"])
                except (TypeError, ValueError):
                    pass
            if g.get("match") and g["id"] != "other":
                try:
                    self.rx.append((re.compile(g["match"], re.I), g["id"]))
                except re.error:
                    pass

    @classmethod
    def load(cls, path=None):
        if path:
            try:
                with open(path) as fh:
                    data = json.load(fh)
                if isinstance(data, list) and data:
                    return cls(data)
            except (OSError, ValueError):
                pass
        return cls()

    def of(self, asn, desc=""):
        if asn:
            g = self.by_asn.get(asn)
            if g:
                return g
            for rx, gid in self.rx:
                if rx.search(desc or ""):
                    return gid
        return "other"

    def public(self):
        return [{"id": g["id"], "name": g["name"], "color": g["color"]} for g in self.groups]


def parse(lines):
    """iptoasn TSV lines -> (v4 starts, v4 ends, v4 idx, v6 starts, v6 ends, v6 idx, recs).
    recs[i] = (asn, cc, desc). Unrouted (AS0) ranges are skipped."""
    s4, e4, i4 = array("I"), array("I"), array("I")
    s6, e6, i6 = [], [], []
    recs, rec_ix = [], {}
    for line in lines:
        if isinstance(line, bytes):
            line = line.decode("utf-8", "replace")
        p = line.rstrip("\n").split("\t")
        if len(p) < 5 or p[2] == "0":
            continue
        try:
            a, b, asn = ipaddress.ip_address(p[0]), ipaddress.ip_address(p[1]), int(p[2])
        except ValueError:
            continue
        key = (asn, p[3], p[4])
        ix = rec_ix.get(key)
        if ix is None:
            ix = rec_ix[key] = len(recs)
            recs.append(key)
        if a.version == 4:
            s4.append(int(a)); e4.append(int(b)); i4.append(ix)
        else:
            s6.append(int(a)); e6.append(int(b)); i6.append(ix)
    return s4, e4, i4, s6, e6, i6, recs


class AsnDB:
    def __init__(self, data_dir, enabled=True, fetch=None, url=URL, groups=None):
        self.dir = os.path.join(data_dir, "feeds") if data_dir else None
        self.enabled = enabled
        self.url = url
        self.fetch = fetch or self._http
        self.groups = groups or Groups()
        self.tab = None
        self.meta = {"updated": None, "count": 0, "error": None, "checked": 0}
        self.lock = threading.Lock()
        self._stop = threading.Event()
        if self.dir:
            os.makedirs(self.dir, exist_ok=True)

    @staticmethod
    def _http(url):
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.read(MAX_BYTES)

    def _path(self):
        return os.path.join(self.dir, FILE) if self.dir else None

    def load_bytes(self, gz):
        with gzip.GzipFile(fileobj=io.BytesIO(gz)) as fh:
            tab = parse(fh)
        n = len(tab[0]) + len(tab[3])
        if n == 0:
            raise ValueError("empty ip2asn table")
        with self.lock:
            self.tab = tab
            self.meta["count"] = n
        return n

    def load_cached(self):
        p = self._path()
        if not p:
            return False
        try:
            with open(p, "rb") as fh:
                self.load_bytes(fh.read())
            st = os.stat(p).st_mtime
            with self.lock:
                self.meta.update(updated=st, checked=st, error=None)
            return True
        except (OSError, ValueError, EOFError) as e:
            if os.path.exists(p):
                with self.lock:
                    self.meta["error"] = ("cached copy unreadable: %s" % e)[:200]
            return False

    def refresh(self, force=False):
        m = self.meta
        age = time.time() - (m.get("checked") or 0)
        if not force and self.tab is not None and age < (RETRY if m.get("error") else REFRESH):
            return False
        try:
            gz = self.fetch(self.url)
            self.load_bytes(gz)
            p = self._path()
            if p:
                with open(p + ".tmp", "wb") as fh:
                    fh.write(gz)
                os.replace(p + ".tmp", p)
            with self.lock:
                self.meta.update(updated=time.time(), checked=time.time(), error=None)
            return True
        except Exception as e:
            with self.lock:
                self.meta.update(checked=time.time(), error=("%s: %s" % (type(e).__name__, e))[:200])
            return False

    def start(self):
        if not self.enabled:
            return

        def loop():
            self.load_cached()
            while not self._stop.is_set():
                try:
                    self.refresh()
                except Exception:
                    pass
                self._stop.wait(600)

        threading.Thread(target=loop, name="asn", daemon=True).start()

    def stop(self):
        self._stop.set()

    def lookup(self, ip):
        """-> {asn, cc, as_desc, as_name, grp} for public IPs in the table, else None."""
        tab = self.tab
        if tab is None:
            return None
        try:
            a = ipaddress.ip_address(str(ip).split("%")[0])
        except ValueError:
            return None
        if not a.is_global or a.is_multicast:
            return None
        s, e, ix = (tab[0], tab[1], tab[2]) if a.version == 4 else (tab[3], tab[4], tab[5])
        n = int(a)
        i = bisect.bisect_right(s, n) - 1
        if i < 0 or n > e[i]:
            return None
        asn, cc, desc = tab[6][ix[i]]
        return {"asn": asn, "cc": cc, "as_desc": desc, "as_name": short_name(desc),
                "grp": self.groups.of(asn, desc)}

    def status(self):
        with self.lock:
            return dict(self.meta, enabled=self.enabled, loaded=self.tab is not None)
