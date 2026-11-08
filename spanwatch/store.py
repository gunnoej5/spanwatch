"""SQLite persistence for finished sessions."""
import json
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY,
  iface TEXT, note TEXT, started REAL, ended REAL, duration REAL,
  status TEXT, error TEXT, packets INTEGER, bytes INTEGER,
  kernel_drops INTEGER, kernel_seen INTEGER, flow_count INTEGER,
  dns_count INTEGER, truncated_flows INTEGER, breakdown TEXT
);
CREATE TABLE IF NOT EXISTS flows (
  session_id INTEGER, client TEXT, server TEXT, proto TEXT, port INTEGER,
  service TEXT, pkts_cs INTEGER, bytes_cs INTEGER, pkts_sc INTEGER,
  bytes_sc INTEGER, first REAL, last REAL, client_name TEXT, server_name TEXT,
  guess TEXT, conf INTEGER, detail TEXT
);
CREATE INDEX IF NOT EXISTS flows_sid ON flows(session_id);
CREATE TABLE IF NOT EXISTS dns (
  session_id INTEGER, ts REAL, client TEXT, resolver TEXT, qname TEXT,
  qtype TEXT, rcode TEXT, answers TEXT, ms REAL, ttl INTEGER
);
CREATE INDEX IF NOT EXISTS dns_sid ON dns(session_id);
CREATE TABLE IF NOT EXISTS whois (ip TEXT PRIMARY KEY, ts REAL, data TEXT);
CREATE TABLE IF NOT EXISTS kv (ns TEXT, k TEXT, ts REAL, data TEXT, PRIMARY KEY (ns, k));
CREATE TABLE IF NOT EXISTS host_obs (
  mac TEXT, ip TEXT, name TEXT, source TEXT, first REAL, last REAL, hits INTEGER,
  PRIMARY KEY (mac, ip, name, source)
);
CREATE TABLE IF NOT EXISTS host_bind (
  mac TEXT, ip TEXT, source TEXT, first REAL, last REAL, hits INTEGER,
  PRIMARY KEY (mac, ip)
);
"""

FLOW_COLS = ("client", "server", "proto", "port", "service", "pkts_cs",
             "bytes_cs", "pkts_sc", "bytes_sc", "first", "last",
             "client_name", "server_name", "guess", "conf", "detail")
DNS_COLS = ("ts", "client", "resolver", "qname", "qtype", "rcode", "answers",
            "ms", "ttl")
SUMMARY_COLS = ("id", "iface", "note", "started", "ended", "duration",
                "status", "error", "packets", "bytes", "kernel_drops",
                "kernel_seen", "flow_count", "dns_count", "truncated_flows")


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        have = {r[1] for r in self.db.execute("PRAGMA table_info(flows)")}
        for col, typ in (("guess", "TEXT"), ("conf", "INTEGER"), ("detail", "TEXT")):
            if col not in have:
                self.db.execute("ALTER TABLE flows ADD COLUMN %s %s" % (col, typ))
        self.lock = threading.Lock()

    def next_id(self):
        with self.lock:
            r = self.db.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM sessions").fetchone()
        return r[0]

    def save(self, sess):
        s = sess.summary()
        flows = sess.flow_rows()
        dns = sess.dns_rows()
        bd = json.dumps(sess.breakdown())
        with self.lock, self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO sessions (%s, breakdown) VALUES (%s)"
                % (",".join(SUMMARY_COLS), ",".join("?" * (len(SUMMARY_COLS) + 1))),
                [s[c] for c in SUMMARY_COLS] + [bd])
            self.db.execute("DELETE FROM flows WHERE session_id=?", (sess.id,))
            self.db.execute("DELETE FROM dns WHERE session_id=?", (sess.id,))
            self.db.executemany(
                "INSERT INTO flows (session_id,%s) VALUES (?,%s)"
                % (",".join(FLOW_COLS), ",".join("?" * len(FLOW_COLS))),
                ([sess.id] + [f[c] for c in FLOW_COLS] for f in flows))
            self.db.executemany(
                "INSERT INTO dns (session_id,%s) VALUES (?,%s)"
                % (",".join(DNS_COLS), ",".join("?" * len(DNS_COLS))),
                ([sess.id] + [json.dumps(d[c]) if c == "answers" else d[c]
                              for c in DNS_COLS] for d in dns))
        hosts = getattr(sess, "host_rows", None)
        if hosts:
            self.host_merge(*hosts())

    def host_merge(self, obs, binds):
        """Upsert hostname observations + MAC/IP bindings (cumulative, not per session)."""
        with self.lock, self.db:
            self.db.executemany(
                "INSERT INTO host_obs VALUES (?,?,?,?,?,?,?) ON CONFLICT(mac, ip, name, source) DO UPDATE SET "
                "first=MIN(first, excluded.first), last=MAX(last, excluded.last), hits=hits+excluded.hits",
                obs)
            self.db.executemany(
                "INSERT INTO host_bind VALUES (?,?,?,?,?,?) ON CONFLICT(mac, ip) DO UPDATE SET "
                "source=CASE WHEN excluded.last >= last THEN excluded.source ELSE source END, "
                "first=MIN(first, excluded.first), last=MAX(last, excluded.last), hits=hits+excluded.hits",
                binds)

    def host_rows(self):
        with self.lock:
            obs = self.db.execute("SELECT mac, ip, name, source, first, last, hits FROM host_obs").fetchall()
            binds = self.db.execute("SELECT mac, ip, source, first, last, hits FROM host_bind").fetchall()
        return obs, binds

    def host_prune(self, before):
        with self.lock, self.db:
            n = self.db.execute("DELETE FROM host_obs WHERE last < ?", (before,)).rowcount
            n += self.db.execute("DELETE FROM host_bind WHERE last < ?", (before,)).rowcount
        return n

    def sessions(self):
        with self.lock:
            rows = self.db.execute(
                "SELECT %s FROM sessions ORDER BY id DESC" % ",".join(SUMMARY_COLS)).fetchall()
        out = []
        for r in rows:
            d = dict(zip(SUMMARY_COLS, r))
            d["elapsed"] = (d["ended"] or d["started"]) - d["started"]
            out.append(d)
        return out

    def session(self, sid):
        with self.lock:
            r = self.db.execute(
                "SELECT %s, breakdown FROM sessions WHERE id=?" % ",".join(SUMMARY_COLS),
                (sid,)).fetchone()
        if not r:
            return None, None
        d = dict(zip(SUMMARY_COLS, r[:-1]))
        d["elapsed"] = (d["ended"] or d["started"]) - d["started"]
        return d, json.loads(r[-1] or "{}")

    def flows(self, sid):
        with self.lock:
            rows = self.db.execute(
                "SELECT %s FROM flows WHERE session_id=?" % ",".join(FLOW_COLS), (sid,)).fetchall()
        return [dict(zip(FLOW_COLS, r)) for r in rows]

    def dns(self, sid):
        with self.lock:
            rows = self.db.execute(
                "SELECT %s FROM dns WHERE session_id=? ORDER BY ts" % ",".join(DNS_COLS),
                (sid,)).fetchall()
        out = []
        for r in rows:
            d = dict(zip(DNS_COLS, r))
            d["answers"] = json.loads(d["answers"] or "[]")
            out.append(d)
        return out

    def whois_all(self):
        with self.lock:
            rows = self.db.execute("SELECT ip, data FROM whois").fetchall()
        out = {}
        for ip, data in rows:
            try:
                out[ip] = json.loads(data)
            except ValueError:
                pass
        return out

    def kv_all(self, ns):
        with self.lock:
            rows = self.db.execute("SELECT k, data FROM kv WHERE ns=?", (ns,)).fetchall()
        out = {}
        for k, data in rows:
            try:
                out[k] = json.loads(data)
            except ValueError:
                pass
        return out

    def kv_put(self, ns, k, d):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO kv VALUES (?,?,?,?)",
                            (ns, k, d.get("ts", 0), json.dumps(d)))

    def kv_prune(self, ns, before):
        with self.lock, self.db:
            return self.db.execute("DELETE FROM kv WHERE ns=? AND ts < ?", (ns, before)).rowcount

    def whois_put(self, ip, d):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO whois VALUES (?,?,?)",
                            (ip, d["ts"], json.dumps(d)))

    def delete(self, sid):
        with self.lock, self.db:
            for t in ("flows", "dns"):
                self.db.execute("DELETE FROM %s WHERE session_id=?" % t, (sid,))
            n = self.db.execute("DELETE FROM sessions WHERE id=?", (sid,)).rowcount
        return n > 0

    def prune(self, keep):
        with self.lock:
            ids = [r[0] for r in self.db.execute(
                "SELECT id FROM sessions ORDER BY id DESC LIMIT -1 OFFSET ?", (keep,))]
        for sid in ids:
            self.delete(sid)
        if ids:
            with self.lock:
                self.db.execute("VACUUM")
        return ids
