"""In-memory aggregation for one capture session.

Conversations are keyed (client, server, proto, service_port): ephemeral
client ports are folded away so 400 HTTPS connections to one host are one row.
Bytes/packets are tracked in both directions (client->server, server->client).
"""
import threading
import time
from collections import Counter

from .parse import (KIND_IP, KIND_L2, ETHERTYPES, PROTO_NAMES, SERVICES,
                    TCP_SYN, TCP_ACK, parse_frame, parse_dns, qtype_name,
                    RCODES, service_name)

MAX_FLOWS = 250_000
MAX_DNS = 100_000
MAX_SERVERS = 200_000
MAX_NAMES = 200_000
DNS_TIMEOUT = 5.0


def _rank(port):
    """Lower = more likely to be the server side of a conversation."""
    if port in SERVICES:
        return 0
    if port < 1024:
        return 1
    if port < 32768:
        return 2
    return 3


class Session:
    def __init__(self, sid, iface, note="", dns_ports=(53,), duration=None):
        self.id = sid
        self.iface = iface
        self.note = note
        self.duration = duration
        self.dns_ports = frozenset(dns_ports)
        self.started = time.time()
        self.ended = None
        self.status = "running"
        self.error = None
        self.saved = False
        self.lock = threading.Lock()
        self.flows = {}      # key -> [pk_cs, by_cs, pk_sc, by_sc, first, last]
        self.servers = set()  # (ip, proto, port) seen answering a SYN
        self.dns_pending = {}  # (client, cport, resolver, txid) -> query info
        self.dns = []
        self.names = {}       # ip -> name learned from DNS answers this session
        self.protos = Counter()      # proto name -> packets
        self.proto_bytes = Counter()
        self.l2 = Counter()           # non-IP ethertypes -> frames
        self.packets = 0
        self.bytes = 0
        self.kernel_drops = 0
        self.kernel_seen = 0
        self.truncated_flows = 0
        self._last_expire = 0.0

    # ------------------------------------------------------------ ingest
    def ingest(self, buf, n, ts):
        p = parse_frame(buf, n)
        with self.lock:
            self.packets += 1
            self.bytes += n
            if p is None:
                self.l2["runt/invalid"] += 1
                return
            if p[0] == KIND_L2:
                et = p[1]
                self.l2[ETHERTYPES.get(et, "0x%04x" % et)] += 1
                return
            _, src, dst, proto, sport, dport, length, flags, poff, pend = p
            pname = PROTO_NAMES.get(proto, "IP/%d" % proto)
            self.protos[pname] += 1
            self.proto_bytes[pname] += length

            # --- orient the conversation: who is client, who is server?
            if proto in (6, 17, 132) and sport is not None:
                if proto == 6 and flags & TCP_SYN:
                    if flags & TCP_ACK:
                        srv = (src, 6, sport)
                    else:
                        srv = (dst, 6, dport)
                    if len(self.servers) < MAX_SERVERS:
                        self.servers.add(srv)
                if (dst, proto, dport) in self.servers:
                    fwd = True
                elif (src, proto, sport) in self.servers:
                    fwd = False
                else:
                    rd, rs = _rank(dport), _rank(sport)
                    fwd = rd < rs or (rd == rs and dport <= sport)
                port = dport if fwd else sport
            elif proto in (1, 58) and dport is not None:
                # echo-reply belongs to the echo conversation, reversed
                if (proto, dport) in ((1, 0), (58, 129)):
                    fwd, port = False, (8 if proto == 1 else 128)
                else:
                    fwd, port = True, dport
            else:
                fwd, port = True, None

            if fwd:
                key = (src, dst, proto, port)
            else:
                key = (dst, src, proto, port)
            f = self.flows.get(key)
            if f is None:
                if len(self.flows) >= MAX_FLOWS:
                    self.truncated_flows += 1
                else:
                    self.flows[key] = ([1, length, 0, 0, ts, ts] if fwd
                                       else [0, 0, 1, length, ts, ts])
            elif fwd:
                f[0] += 1
                f[1] += length
                f[5] = ts
            else:
                f[2] += 1
                f[3] += length
                f[5] = ts

            # --- DNS
            if poff and (sport in self.dns_ports or dport in self.dns_ports):
                msg = bytes(buf[poff:pend])
                if proto == 6:
                    msg = msg[2:]  # TCP length prefix; best-effort, one msg/segment
                self._dns(src, sport, dst, dport, msg, ts)

            if ts - self._last_expire > 1.0:
                self._expire_dns(ts)

    def _dns(self, src, sport, dst, dport, msg, ts):
        d = parse_dns(msg)
        if d is None or d["qname"] is None or d["opcode"] != 0:
            return
        if d["qr"] == 0:
            k = (src, sport, dst, d["id"])
            self.dns_pending[k] = (ts, d["qname"], d["qtype"])
            return
        k = (dst, dport, src, d["id"])
        q = self.dns_pending.pop(k, None)
        ms = round((ts - q[0]) * 1000, 1) if q else None
        answers = d["answers"]
        self._log_dns(q[0] if q else ts, dst, src, d["qname"], d["qtype"],
                      RCODES.get(d["rcode"], "RCODE%d" % d["rcode"]),
                      answers, ms, d["ttl"])
        for ip in d["ips"]:
            if len(self.names) < MAX_NAMES:
                self.names[ip] = d["qname"]

    def _log_dns(self, ts, client, resolver, qname, qtype, rcode, answers, ms, ttl):
        if len(self.dns) >= MAX_DNS:
            return
        self.dns.append({
            "ts": ts, "client": client, "resolver": resolver, "qname": qname,
            "qtype": qtype_name(qtype) if qtype is not None else "?",
            "rcode": rcode, "answers": answers, "ms": ms, "ttl": ttl,
        })

    def _expire_dns(self, now):
        self._last_expire = now
        if not self.dns_pending:
            return
        dead = [k for k, v in self.dns_pending.items() if now - v[0] > DNS_TIMEOUT]
        for k in dead:
            ts, qname, qtype = self.dns_pending.pop(k)
            self._log_dns(ts, k[0], k[2], qname, qtype, "NO-RESPONSE", [], None, None)

    def finish(self, status="done", error=None):
        with self.lock:
            # anything still pending at stop time never got an answer we saw
            for k, (ts, qname, qtype) in list(self.dns_pending.items()):
                self._log_dns(ts, k[0], k[2], qname, qtype, "NO-RESPONSE", [], None, None)
            self.dns_pending.clear()
            self.dns.sort(key=lambda e: e["ts"])
            self.ended = time.time()
            self.status = status
            self.error = error

    # ------------------------------------------------------------ views
    def summary(self):
        end = self.ended or time.time()
        return {
            "id": self.id, "iface": self.iface, "note": self.note,
            "started": self.started, "ended": self.ended,
            "duration": self.duration, "elapsed": end - self.started,
            "status": self.status, "error": self.error,
            "packets": self.packets, "bytes": self.bytes,
            "kernel_drops": self.kernel_drops, "kernel_seen": self.kernel_seen,
            "flow_count": len(self.flows), "dns_count": len(self.dns),
            "truncated_flows": self.truncated_flows,
        }

    def flow_rows(self):
        with self.lock:
            items = list(self.flows.items())
            names = dict(self.names)
        return [flow_row(k, v, names) for k, v in items]

    def dns_rows(self):
        with self.lock:
            return list(self.dns)

    def breakdown(self):
        with self.lock:
            return {
                "protos": [{"proto": k, "packets": v, "bytes": self.proto_bytes[k]}
                           for k, v in self.protos.most_common()],
                "l2": [{"ethertype": k, "frames": v} for k, v in self.l2.most_common()],
            }

    def names_snapshot(self):
        with self.lock:
            return dict(self.names)


def flow_row(k, v, names):
    client, server, proto, port = k
    return {
        "client": client, "server": server,
        "proto": PROTO_NAMES.get(proto, "IP/%d" % proto),
        "port": port, "service": service_name(proto, port),
        "pkts_cs": v[0], "bytes_cs": v[1], "pkts_sc": v[2], "bytes_sc": v[3],
        "first": v[4], "last": v[5],
        "client_name": names.get(client, ""), "server_name": names.get(server, ""),
    }
