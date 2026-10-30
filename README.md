# spanwatch

Passive LAN traffic summarizer for a switch **SPAN / mirror port**. It runs short,
bounded capture sessions on a dedicated, address-less sniff NIC and summarizes them
in a small local dashboard:

- **Conversations**: client → server, protocol, *service* port (ephemeral client
  ports are folded away), packets and bytes in both directions. Server IPs are
  labelled with names learned from DNS answers in the same session (passive DNS).
- **DNS log**: one line per query: `requestor → provider  TYPE name = answers  (rcode, ms)`.
  Unanswered queries are logged as `NO-RESPONSE`.
- **Breakdown**: top talkers, protocols, services, traffic guesses, DNS names,
  requestors, providers, rcodes, and non-IP frames (ARP, LLDP, …).
- **IP relationship graph** (under Breakdown): an undirected force layout of IP pairs.
  Line width runs from 1px (seen least) to 6px (seen most). Choose packets,
  conversations, or bytes, on a log or linear scale. Line colour shows the
  traffic guess, node colour shows the address class, and node size shows volume.
  Hover a node to highlight its peers, click it to filter on it, or drag it.
- **Traffic guesses** for encrypted/opaque flows (see below).
- Export CSV, plus DNS as plain text.

There are no third-party dependencies, only Python 3 stdlib. Capture uses
`AF_PACKET` directly, so neither libpcap nor tshark is needed.

```
2026-10-30 12:01:02  192.168.1.50 -> 192.168.1.1  A www.example.com = CNAME edge.example.net, 93.184.216.34  (NOERROR 12ms)
```

## Traffic guesses

Each conversation's first 8 payload packets are inspected. Every new TCP
connection in that conversation gets 5 more probes. Guesses carry a confidence:

| conf | UI | Evidence |
|---|---|---|
| 3 | filled badge | protocol signature: SSH banner, TLS ClientHello (**SNI** extracted, split hellos reassembled), QUIC long header, WireGuard handshake, OpenVPN hard-reset, BitTorrent handshake/DHT/UDP tracker, STUN, RDP, VNC, HTTP (Host extracted), ESP/AH |
| 2 | outline | structural or behavioural: TLS records mid-stream, WireGuard transport packets, unknown high-port traffic from a host already seen speaking BitTorrent |
| 1 | dashed, `?` | heuristic: well-known port, high-entropy payload (`encrypted?`), uTP-like headers, P2P fan-out (≥20 peers) or fan-in (≥10 clients) on unknown high ports |

These are guesses. Known blind spots: VPNs over TLS/443 (SSTP, OpenConnect)
look like TLS. OpenVPN with `tls-auth`/`tls-crypt` lacks a signature and falls
back to port. Encrypted BitTorrent (MSE) is only caught by behaviour. QUIC SNI
is not decrypted.

## Receive-only by design

The sniff port must never take part in the network. That is enforced in layers:

| Layer | What | Kind |
|---|---|---|
| udev guard | USB Ethernet NICs get `NM_UNMANAGED=1`, so NetworkManager never DHCPs them on plug-in | policy |
| udev pin | the adapter's MAC is pinned to the name `span0`, which is unmanaged | policy |
| sysctl | `disable_ipv6=1`, `accept_ra=0`, `autoconf=0`: no link-local, no SLAAC | kernel |
| link | `arp off`, `multicast off`, addresses flushed | kernel |
| **nftables netdev egress hook** | `policy drop` on every frame transmitted on `span0` | **hard** |
| app | capture refuses to start if the interface has any IPv4/IPv6 address | check |
| dashboard | chips for `no IP ✓`, promisc, and `tx` packet counter (should stay 0) | visibility |

## Privilege model

- `spanwatch.service` runs as a systemd **DynamicUser** that holds only
  `CAP_NET_RAW`. It also gets `ProtectSystem=strict`, `ProtectHome`, a syscall
  filter, and restricted address families.
- The code it runs is a **root-owned copy in `/opt/spanwatch`**. A capability-holding
  service never executes user-writable files.
- `spanwatch-iface@span0.service` (root, oneshot) does the link setup. It is tied to the
  device unit, so it runs again on every hotplug.
- The dashboard listens on `127.0.0.1:9595` only. It checks the Host header (DNS-rebinding
  guard), and mutating calls need an `X-Spanwatch-Action` header (CSRF guard).
- Data lives in `/var/lib/spanwatch` (SQLite). By default the newest 50 sessions are kept.

## Install

```sh
git clone https://github.com/gunnoej5/spanwatch && cd spanwatch
python3 -m unittest            # 13 tests, no root needed
sudo deploy/install.sh install # BEFORE plugging the adapter in
# plug the 2.5G adapter into this host and the SPAN port
ip -br link                    # find it, e.g. enx00e04c68xxxx
sudo deploy/install.sh pin enx00e04c68xxxx
```

Then open http://127.0.0.1:9595, pick a duration (30s to 60m), and click **Capture**.

To ship code changes: `sudo deploy/install.sh update`. To remove everything:
`sudo deploy/install.sh uninstall`, which keeps the data.

Options live in `/etc/spanwatch/spanwatch.env`, for example
`SPANWATCH_ARGS=--dns-ports 53,5353,5355 --keep 100`.

### Offline / dev

```sh
python3 -m spanwatch import some.pcap --data ./data   # classic pcap, Ethernet or Linux SLL
python3 -m spanwatch serve --listen 127.0.0.1:9596 --data ./data
python3 -m spanwatch status --iface span0             # exit 0 iff present and address-less
```

## Limits and caveats

- **DNS visibility.** Only plaintext DNS on the configured ports (default 53) is
  visible. DoH (443) and DoT (853) show up only as conversations; DoT is labelled
  `dns-over-tls`. DNS over TCP is parsed best-effort, one message per segment.
- **Throughput.** Python parse+aggregate benchmarks at about 730k pps on one core. That
  is well above 2.5G line rate for full-size frames (about 206k pps), but small-packet
  floods can exceed it. Kernel drops appear in the meter. A TPACKET_V3 mmap ring
  would be the next step up.
- **What gets mirrored.** The SPAN config decides what you see. If you mirror
  both directions of the uplink, every packet is seen once. If you mirror several access
  ports, packets between them are counted twice.
- **Fragments.** Non-first IP fragments carry no ports, so they show as a portless row.
- Session memory is capped at 250k conversations and 100k DNS records.
