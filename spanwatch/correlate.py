"""Correlate inside/outside captures of the same NAT'd conversation.

With one capture seeing both sides of a NAT hop (LAN switch mirror + WAN-side
mirror on the same span port), every internet conversation shows up twice:
  inside   real LAN device  <-> public server   (the device's own address)
  outside  router WAN address <-> same server   (after NAT rewrites the source)

NAT changes addresses and sometimes the source port, but not payload, so
packet and byte counts survive the translation almost exactly. That is the
join key: same public endpoint + port + protocol, overlapping in time, with
matching counts. This is a best-effort match, not ground truth — a NAT
table or flow-export log from the router would be exact; this is the
"close enough, flag ties, let a human look" version.

side_of() needs --wan-ip (repeatable): the router's own WAN-facing address
seen on the wire (e.g. the Orbi's public-side IP). Without it, every flow's
side is "lan-lan"/"public" with no outside leg, and correlate() is a no-op.

DNS correlation is weaker and sparser: an inside query (device -> resolver)
and the resolver's own outside upstream query (router WAN -> 9.9.9.9/Quad9/
etc) are two different conversations, one hop apart, linked only by asking
the same question moments apart (cache misses only — most queries never
reach the outside leg at all).
"""
import time

TIME_SLOP = 5.0        # seconds of allowed drift when matching (clock + latency)
DNS_SLOP = 8.0          # resolver upstream lookups lag the client query slightly more
BYTE_TOL = 0.03         # relative byte tolerance (small header-length differences)


def side_of(ip, wan_ips, lan_nets):
    if ip in wan_ips:
        return "outside"
    for n in lan_nets:
        try:
            if "/" in n:
                import ipaddress
                if __import__("ipaddress").ip_address(ip) in __import__("ipaddress").ip_network(n):
                    return "inside"
        except ValueError:
            continue
    return None


def _overlaps(a0, a1, b0, b1, slop):
    return a0 - slop <= b1 and b0 - slop <= a1


def flow_side(f, wan_ips, lan_nets):
    """"inside"/"outside" only for a LAN<->public or WAN<->public pair: the shape a
    NAT'd conversation actually has. LAN<->LAN, WAN<->WAN or public<->public (none of
    the addresses are ours) aren't part of this correlation and get None."""
    cs, ss = side_of(f["client"], wan_ips, lan_nets), side_of(f["server"], wan_ips, lan_nets)
    if cs is None and ss == "outside":
        return "outside"
    if ss is None and cs == "outside":
        return "outside"
    if cs is None and ss == "inside":
        return "inside"
    if ss is None and cs == "inside":
        return "inside"
    return None


def _flow_score(i, o):
    """0..1: how well an outside flow explains an inside flow (same key already)."""
    def close(a, b):
        if a == b == 0:
            return 1.0
        m = max(a, b, 1)
        return max(0.0, 1 - abs(a - b) / m)
    pk = min(close(i["pkts_cs"], o["pkts_cs"]), close(i["pkts_sc"], o["pkts_sc"]))
    by = min(close(i["bytes_cs"], o["bytes_cs"]), close(i["bytes_sc"], o["bytes_sc"]))
    if not _overlaps(i["first"], i["last"], o["first"], o["last"], TIME_SLOP):
        return 0.0
    return 0.5 * pk + 0.5 * by


def correlate(flows, wan_ips, lan_nets=("192.168.0.0/16",)):
    """Tag each flow's side; nest matched outside flows under their inside
    counterpart as f["matched"]. Returns the flows to show at top level
    (matched outside flows are removed, since they'd otherwise double-count).

    Ambiguity is scored per outside flow, not per inside flow: if two inside
    flows explain one outside flow about equally well (same destination, same
    counts, overlapping time — e.g. two devices hitting a popular CDN IP at
    once), only the better of the two is matched, and it's flagged
    ambiguous with the tie count, rather than silently guessing.
    """
    if not wan_ips:
        for f in flows:
            f["side"] = None
        return flows
    wan_ips = set(wan_ips)
    for f in flows:
        f["side"] = flow_side(f, wan_ips, lan_nets)
    key = lambda f: (f["server"], f["port"], f["proto"])
    outside_by_key, inside_by_key = {}, {}
    for f in flows:
        if f["side"] == "outside":
            outside_by_key.setdefault(key(f), []).append(f)
        elif f["side"] == "inside":
            inside_by_key.setdefault(key(f), []).append(f)
    used_outside, matched_inside = set(), set()
    for k, insides in inside_by_key.items():
        outsides = outside_by_key.get(k)
        if not outsides:
            continue
        pairs = [(_flow_score(i, o), i, o) for i in insides for o in outsides]
        pairs = [p for p in pairs if p[0] > 0.5]
        pairs.sort(key=lambda p: -p[0])
        for score, i, o in pairs:
            if id(i) in matched_inside or id(o) in used_outside:
                continue
            ties = sum(1 for s2, _i2, o2 in pairs if o2 is o and s2 >= score - 0.1)
            conf = 3 if score > 0.97 and ties == 1 else 2 if score > 0.85 else 1
            i["matched"] = {
                "wan": o["client"] if o["client"] in wan_ips else o["server"],
                "pkts_cs": o["pkts_cs"], "pkts_sc": o["pkts_sc"],
                "bytes_cs": o["bytes_cs"], "bytes_sc": o["bytes_sc"],
                "first": o["first"], "last": o["last"],
                "score": round(score, 3), "confidence": conf,
                "ambiguous": ties > 1, "ties": ties,
            }
            matched_inside.add(id(i))
            used_outside.add(id(o))
    return [f for f in flows if not (f["side"] == "outside" and id(f) in used_outside)]


def _norm_qname(q):
    return (q or "").lower().rstrip(".")


def correlate_dns(rows, wan_ips):
    """Nest a resolver's own outside upstream lookup under the inside query
    that (probably) triggered it: same question, asked moments later."""
    if not wan_ips:
        for d in rows:
            d["side"] = None
        return rows
    wan_ips = set(wan_ips)
    for d in rows:
        d["side"] = "outside" if d["client"] in wan_ips else ("inside" if d["resolver"] not in wan_ips else None)
    by_q = {}
    for d in rows:
        if d["side"] == "outside":
            by_q.setdefault(_norm_qname(d["qname"]), []).append(d)
    used = set()
    out = []
    for d in rows:
        if d["side"] != "inside":
            continue
        cands = [o for o in by_q.get(_norm_qname(d["qname"]), []) if id(o) not in used]
        cands = [o for o in cands if d["ts"] - 0.05 <= o["ts"] <= d["ts"] + DNS_SLOP]
        if cands:
            best = min(cands, key=lambda o: o["ts"] - d["ts"])
            used.add(id(best))
            tie = len(cands)
            d["matched"] = {
                "wan": best["client"], "resolver": best["resolver"], "rcode": best["rcode"],
                "answers": best["answers"], "delay_ms": round((best["ts"] - d["ts"]) * 1000, 1),
                "confidence": 3 if tie == 1 else 1, "ambiguous": tie > 1, "ties": tie,
            }
        out.append(d)
    for d in rows:
        if d["side"] == "outside" and id(d) not in used:
            out.append(d)
    return out
