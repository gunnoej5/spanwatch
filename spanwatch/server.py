"""Dashboard HTTP server + capture controller. Stdlib only."""
import csv
import io
import json
import os
import re
import threading
import time
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import iface as ifmod
from .capture import LiveCapture
from .session import Session

STATIC = os.path.join(os.path.dirname(__file__), "static")


class ApiError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


class App:
    def __init__(self, store, iface, dns_ports=(53,), max_duration=3600,
                 keep=50, allow_addressed=False):
        self.store = store
        self.iface = iface
        self.dns_ports = tuple(dns_ports)
        self.max_duration = max_duration
        self.keep = keep
        self.allow_addressed = allow_addressed
        self.current = None
        self.capture = None
        self.lock = threading.Lock()
        self._next_id = store.next_id()

    # ------------------------------------------------------------ control
    def start(self, duration, note=""):
        with self.lock:
            if self.current and self.current.status == "running":
                raise ApiError(409, "a session is already running")
            st = ifmod.status(self.iface)
            if not st.get("present"):
                raise ApiError(409, "interface %s is not present" % self.iface)
            if not self.allow_addressed:
                if st.get("addresses") is None:
                    raise ApiError(409, "could not verify %s has no IP addresses" % self.iface)
                if st["addresses"]:
                    raise ApiError(409, "refusing: %s carries addresses %s; a sniff port must be address-less"
                                   % (self.iface, ", ".join(st["addresses"])))
            duration = max(5, min(int(duration), self.max_duration))
            sid = max(self._next_id, self.store.next_id())
            self._next_id = sid + 1
            sess = Session(sid, self.iface, note=str(note)[:200],
                           dns_ports=self.dns_ports, duration=duration)
            cap = LiveCapture(sess, self.iface, duration, on_done=self._done)
            self.current, self.capture = sess, cap
            cap.start()
            return sess.summary()

    def stop(self):
        with self.lock:
            cap = self.capture
        if not cap or not cap.is_alive():
            raise ApiError(409, "no session running")
        cap.stop()
        cap.join(5)
        return self.current.summary()

    def _done(self, sess):
        try:
            self.store.save(sess)
            sess.saved = True
            self.store.prune(self.keep)
        except Exception as e:  # keep server alive; serve from memory
            sess.error = "save failed: %s" % e

    def shutdown(self):
        if self.capture and self.capture.is_alive():
            self.capture.stop()
            self.capture.join(5)

    # ------------------------------------------------------------ data
    def _live(self, sid):
        s = self.current
        # in-memory until persisted (covers the finish->save window too)
        return s if s is not None and s.id == sid and not s.saved else None

    def summary(self, sid):
        live = self._live(sid)
        if live:
            return live.summary(), live.breakdown()
        s, bd = self.store.session(sid)
        if s is None:
            raise ApiError(404, "no such session")
        return s, bd

    def flows(self, sid):
        live = self._live(sid)
        return live.flow_rows() if live else self.store.flows(sid)

    def dns(self, sid):
        live = self._live(sid)
        return live.dns_rows() if live else self.store.dns(sid)

    def status(self):
        cur = self.current
        st = ifmod.status(self.iface)
        return {
            "iface": st, "receive_only": ifmod.receive_only(st),
            "current": cur.summary() if cur else None,
            "max_duration": self.max_duration, "dns_ports": list(self.dns_ports),
            "host": os.uname().nodename, "now": time.time(),
        }


# ---------------------------------------------------------------- helpers

def _match(q, *fields):
    return any(q in (str(f).lower() if f is not None else "") for f in fields)


FLOW_SORTS = {
    "bytes": lambda f: f["bytes_cs"] + f["bytes_sc"],
    "pkts": lambda f: f["pkts_cs"] + f["pkts_sc"],
    "last": lambda f: f["last"], "first": lambda f: f["first"],
    "port": lambda f: (f["port"] is None, f["port"] or 0),
}


def filter_flows(rows, q="", sort="bytes", limit=500):
    q = q.strip().lower()
    if q:
        rows = [f for f in rows if _match(q, f["client"], f["server"], f["proto"],
                                          f["port"], f["service"], f["client_name"],
                                          f["server_name"])]
    key = FLOW_SORTS.get(sort, FLOW_SORTS["bytes"])
    rows.sort(key=key, reverse=sort not in ("port",))
    return len(rows), rows[:limit]


def filter_dns(rows, q="", limit=1000):
    q = q.strip().lower()
    if q:
        rows = [d for d in rows if _match(q, d["client"], d["resolver"], d["qname"],
                                          d["qtype"], d["rcode"], " ".join(d["answers"]))]
    rows = rows[::-1]  # newest first
    return len(rows), rows[:limit]


def dns_line(d):
    t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d["ts"]))
    ans = ", ".join(d["answers"]) if d["answers"] else "-"
    extra = d["rcode"] + (" %.0fms" % d["ms"] if d.get("ms") is not None else "")
    return "%s  %s -> %s  %s %s = %s  (%s)" % (
        t, d["client"], d["resolver"], d["qtype"], d["qname"], ans, extra)


def insights(flows, dns, n=12):
    talk = Counter()
    for f in flows:
        b = f["bytes_cs"] + f["bytes_sc"]
        talk[f["client"]] += b
        talk[f["server"]] += b
    names = {}
    for f in flows:
        names.setdefault(f["client"], f["client_name"])
        names.setdefault(f["server"], f["server_name"])
    svc = Counter()
    for f in flows:
        label = "%s/%s" % (f["proto"], f["port"]) if f["port"] is not None else f["proto"]
        if f["service"]:
            label += " " + f["service"]
        svc[label] += f["bytes_cs"] + f["bytes_sc"]
    qn, clients, resolvers, rcodes = Counter(), Counter(), Counter(), Counter()
    for d in dns:
        qn[d["qname"]] += 1
        clients[d["client"]] += 1
        resolvers[d["resolver"]] += 1
        rcodes[d["rcode"]] += 1
    top = lambda c: [{"key": k, "value": v} for k, v in c.most_common(n)]
    return {
        "talkers": [{"key": k, "value": v, "name": names.get(k, "")}
                    for k, v in talk.most_common(n)],
        "services": top(svc), "qnames": top(qn), "dns_clients": top(clients),
        "resolvers": top(resolvers), "rcodes": top(rcodes),
    }


# ---------------------------------------------------------------- HTTP

ROUTE = re.compile(r"^/api/sessions/(\d+)(?:/(flows|dns|summary|flows\.csv|dns\.csv|dns\.txt))?$")


class Handler(BaseHTTPRequestHandler):
    app = None
    allowed_hosts = ()
    server_version = "spanwatch"

    def log_message(self, fmt, *args):  # quiet; systemd journal gets errors only
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        if not isinstance(body, (bytes, bytearray)):
            body = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _host_ok(self):
        host = (self.headers.get("Host") or "").lower()
        hostname = host.rsplit(":", 1)[0] if not host.endswith("]") else host
        return hostname in self.allowed_hosts

    def _dispatch(self, method):
        if not self._host_ok():
            return self._send(421, {"error": "unexpected Host header"})
        u = urlparse(self.path)
        qs = {k: v[-1] for k, v in parse_qs(u.query).items()}
        try:
            if method == "GET":
                return self._get(u.path, qs)
            if self.headers.get("X-Spanwatch-Action") is None:
                raise ApiError(403, "missing X-Spanwatch-Action header")
            if method == "POST":
                return self._post(u.path)
            if method == "DELETE":
                m = ROUTE.match(u.path)
                if m and not m.group(2):
                    sid = int(m.group(1))
                    if self.app._live(sid):
                        raise ApiError(409, "stop the session first")
                    if not self.app.store.delete(sid):
                        raise ApiError(404, "no such session")
                    return self._send(200, {"deleted": sid})
            raise ApiError(404, "not found")
        except ApiError as e:
            self._send(e.code, {"error": str(e)})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _post(self, path):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(min(n, 65536)) or b"{}") if n else {}
        if path == "/api/start":
            return self._send(200, self.app.start(body.get("duration", 60), body.get("note", "")))
        if path == "/api/stop":
            return self._send(200, self.app.stop())
        raise ApiError(404, "not found")

    def _get(self, path, qs):
        app = self.app
        if path in ("/", "/index.html"):
            with open(os.path.join(STATIC, "index.html"), "rb") as fh:
                return self._send(200, fh.read(), "text/html; charset=utf-8")
        if path == "/api/status":
            return self._send(200, app.status())
        if path == "/api/sessions":
            sessions = app.store.sessions()
            cur = app.current
            if cur and not cur.saved:
                sessions.insert(0, cur.summary())
            return self._send(200, {"sessions": sessions})
        m = ROUTE.match(path)
        if not m:
            raise ApiError(404, "not found")
        sid, what = int(m.group(1)), m.group(2) or "summary"
        limit = max(1, min(int(qs.get("limit", 500)), 20000))
        q = qs.get("q", "")
        if what == "summary":
            s, bd = app.summary(sid)
            return self._send(200, {"session": s, "breakdown": bd,
                                    "insights": insights(app.flows(sid), app.dns(sid))})
        if what == "flows":
            app.summary(sid)
            total, rows = filter_flows(app.flows(sid), q, qs.get("sort", "bytes"), limit)
            return self._send(200, {"total": total, "rows": rows})
        if what == "dns":
            app.summary(sid)
            total, rows = filter_dns(app.dns(sid), q, limit)
            return self._send(200, {"total": total, "rows": rows})
        # exports: unfiltered unless q given, no row limit
        fn = "spanwatch-%d-%s" % (sid, what.replace(".", "-"))
        disp = {"Content-Disposition": 'attachment; filename="%s.%s"' % (fn, what.split(".")[1])}
        app.summary(sid)
        if what == "dns.txt":
            _, rows = filter_dns(app.dns(sid), q, 10**9)
            txt = "\n".join(dns_line(d) for d in reversed(rows)) + "\n"
            return self._send(200, txt.encode(), "text/plain; charset=utf-8", disp)
        buf = io.StringIO()
        w = csv.writer(buf)
        if what == "flows.csv":
            _, rows = filter_flows(app.flows(sid), q, qs.get("sort", "bytes"), 10**9)
            cols = ["client", "client_name", "server", "server_name", "proto", "port",
                    "service", "pkts_cs", "bytes_cs", "pkts_sc", "bytes_sc", "first", "last"]
        else:
            _, rows = filter_dns(app.dns(sid), q, 10**9)
            rows = rows[::-1]
            cols = ["ts", "client", "resolver", "qtype", "qname", "rcode", "ms", "ttl", "answers"]
        w.writerow(cols)
        for r in rows:
            w.writerow([" ".join(r[c]) if c == "answers" else r[c] for c in cols])
        return self._send(200, buf.getvalue().encode(), "text/csv; charset=utf-8", disp)


def serve(app, host, port, extra_hosts=()):
    allowed = {"127.0.0.1", "localhost", "[::1]", host.lower()}
    allowed.update(h.lower() for h in extra_hosts)
    Handler.app = app
    Handler.allowed_hosts = frozenset(allowed)
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    return httpd
