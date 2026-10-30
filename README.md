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
  Scroll to zoom around the cursor (labels for every node appear at about 1.8×),
  drag the background to pan, and double-click or press **fit** to reset.
  Line widths keep their 1–6px meaning at any zoom level.
- **Local hostnames** (Hosts tab): learned passively from DHCP, mDNS, NetBIOS, LLMNR and reverse DNS; exportable as a hosts file (see below).
- **Whois quick view**: the ⓘ next to any public IP, or right-clicking a graph node,
  opens a side panel. It shows the org, network name/handle, range/CIDR, origin
  ASN + AS name, BGP prefix, country, RIR, abuse contact, and dates, with links to
  the RDAP JSON, ARIN search, and bgp.he.net. Looked-up orgs then label talkers and
  graph nodes.
- **Traffic guesses** for encrypted/opaque flows (see below).
- **Address colours** are the same everywhere (tables, breakdown, graph):
  green for the local LAN, localhost, link-local, and multicast; orange for other
  internal space (VPN/Tailscale CGNAT 100.64/10, RFC1918 outside the LAN, IPv6
  ULA, Docker); red for public. "Local LAN" is the subnet of whichever interface
  holds the default route, detected automatically. Add more with
  `SPANWATCH_ARGS=--lan 10.20.0.0/16` (repeatable).
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

## Whois lookups (outbound traffic)

These are the only thing spanwatch sends off the box, and only when you click.

- Public IPs only. RFC1918, CGNAT/Tailscale, link-local, multicast, and
  documentation ranges are refused server-side and never sent anywhere.
- RDAP goes to `rdap.arin.net`, which redirects to RIPE/APNIC/LACNIC/AFRINIC
  for their space. Origin ASN comes from Team Cymru (`whois.cymru.com:43`).
- Results are cached in SQLite for 7 days and failures for 5 minutes. Queries are
  paced at 1/s, at most 2 run at once, and duplicate concurrent requests are merged.
- The endpoint requires the `X-Spanwatch-Action` header, so other sites can't
  trigger lookups through your browser.
- Lookups leave through the normal uplink; `span0` has no address and drops all
  egress. To disable them entirely: `SPANWATCH_ARGS=--no-whois`.
- RDAP shows who *holds the address block*, and that can differ from who runs
  the service. 1.1.1.1, for example, is registered to APNIC Research and
  Development but announced by Cloudflare (AS13335). The panel shows both.

## Local hostnames (Hosts tab)

Learned passively from chatter that LAN devices broadcast about themselves. No
router credentials, no queries, nothing transmitted:

| source | what it reads | weight |
|---|---|---|
| `dhcp` | option 12 (hostname) / 81 (client FQDN) from DISCOVER/REQUEST/INFORM; ACKs and renewals bind MAC → leased IP | strong |
| `mdns` | A/AAAA and reverse-PTR records for `*.local` in multicast DNS responses | strong |
| `netbios` | NBNS name registration/refresh broadcasts (workstation names only, groups like WORKGROUP skipped) | strong |
| `dns-ptr` | reverse lookups of private addresses answered by your resolver | strong |
| `llmnr` | LLMNR responses | weak |
| `arp` | sender MAC/IP (binding only, no names) | — |
| `file` | `/etc/spanwatch/hosts` overrides in hosts-file format; always wins, re-read on change | override |

Names attach to addresses directly or through MAC→IP bindings, so a DHCP
DISCOVER that carries only a MAC still lands on the right IP once that MAC is
seen in an ARP or ACK. When an address changes hands, the newest MAC wins.
Observations accumulate across sessions in SQLite. Anything not seen for 30 days
is ignored, and anything older than 90 days is pruned. Confidence: **confirmed** means 2+ sources
agree or an override exists, **likely** means one strong source, **weak** means LLMNR only.

Learned names show in green under IPs in Conversations, DNS, top talkers, and
the graph, and the filter box matches them. Labels use *current* knowledge, so a
months-old session can show today's owner of a recycled DHCP address.

Export a hosts table:

```
curl -s 'http://127.0.0.1:9595/api/hosts.txt?min_conf=2'   # hosts-file format, provenance in comments
curl -s http://127.0.0.1:9595/api/hosts.csv
curl -s http://127.0.0.1:9595/api/hosts                    # JSON
sudo python3 -m spanwatch hosts --data /var/lib/private/spanwatch   # offline, from /opt/spanwatch
```

Coverage depends on what the mirror carries. DHCP happens at join/renew time
(lease length), mDNS and NetBIOS are near-constant, and devices that do none of
these (some IoT) stay nameless. Pin those in the override file. DHCPv6 is not
parsed.

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
