"""spanwatch CLI.

  python3 -m spanwatch serve  --iface span0 --listen 127.0.0.1:9595 --data DIR
  python3 -m spanwatch import capture.pcap --data DIR [--note "..."]
  python3 -m spanwatch status --iface span0
"""
import argparse
import json
import os
import signal
import sys

from . import __version__
from . import iface as ifmod
from .capture import read_pcap
from .hostnames import Directory, hosts_text
from .server import App, serve
from .session import Session
from .store import Store
from .whois import Whois
from .reputation import Reputation, Feeds, AbuseIPDB, load_key
from .pihole import PiHole, load_password


def _data_dir(p):
    p = p or os.environ.get("STATE_DIRECTORY") or os.path.expanduser("~/.local/share/spanwatch")
    p = p.split(":")[0]
    os.makedirs(p, exist_ok=True)
    return p


def _ports(s):
    return tuple(int(x) for x in s.split(",") if x.strip())


def main(argv=None):
    ap = argparse.ArgumentParser(prog="spanwatch")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sv = sub.add_parser("serve", help="run dashboard + capture controller")
    sv.add_argument("--iface", default="span0")
    sv.add_argument("--listen", default="127.0.0.1:9595")
    sv.add_argument("--data")
    sv.add_argument("--dns-ports", default="53", help="comma list, e.g. 53,5353,5355")
    sv.add_argument("--max-duration", type=int, default=3600)
    sv.add_argument("--keep", type=int, default=50, help="sessions to retain")
    sv.add_argument("--allow-host", action="append", default=[],
                    help="extra Host header names to accept (e.g. a tailnet name)")
    sv.add_argument("--allow-addressed", action="store_true",
                    help="DANGER/testing: allow capture on an interface with IPs")
    sv.add_argument("--lan", action="append", default=[],
                    help="extra CIDR to colour as local LAN (repeatable); the uplink's "
                         "subnet is detected automatically")
    sv.add_argument("--hosts-file", default="/etc/spanwatch/hosts",
                    help="/etc/hosts-format overrides for learned local hostnames "
                         "(optional; re-read when it changes)")
    sv.add_argument("--no-feeds", action="store_true",
                    help="disable daily threat-feed downloads (reputation flags)")
    sv.add_argument("--abuseipdb-key-file", default="/etc/spanwatch/abuseipdb.key",
                    help="AbuseIPDB API key file (systemd passes it as a credential)")
    sv.add_argument("--pihole-url", default="",
                    help="Pi-hole v6 base URL, e.g. http://172.30.250.2 (enables lease/device/"
                         "blocked-query import; off when empty)")
    sv.add_argument("--pihole-key-file", default="/etc/spanwatch/pihole.key",
                    help="Pi-hole app password file (systemd passes it as a credential)")
    sv.add_argument("--pihole-interval", type=int, default=300, help="seconds between Pi-hole polls")
    sv.add_argument("--no-whois", action="store_true",
                    help="disable on-demand RDAP/Cymru lookups (no outbound traffic)")

    im = sub.add_parser("import", help="load a classic .pcap as a session")
    im.add_argument("pcap")
    im.add_argument("--data")
    im.add_argument("--note", default="")
    im.add_argument("--dns-ports", default="53")

    hs = sub.add_parser("hosts", help="print learned local hostnames (hosts-file format)")
    hs.add_argument("--data")
    hs.add_argument("--hosts-file", default="/etc/spanwatch/hosts")
    hs.add_argument("--min-conf", type=int, default=1)
    hs.add_argument("--json", action="store_true")

    st = sub.add_parser("status", help="print interface health")
    st.add_argument("--iface", default="span0")

    a = ap.parse_args(argv)

    if a.cmd == "status":
        s = ifmod.status(a.iface)
        s["receive_only"] = ifmod.receive_only(s)
        print(json.dumps(s, indent=2))
        return 0 if s["receive_only"] else 1

    store = Store(os.path.join(_data_dir(a.data), "spanwatch.db"))

    if a.cmd == "hosts":
        rows = Directory(store, a.hosts_file or None).rows()
        if a.json:
            print(json.dumps(rows, indent=2))
        else:
            sys.stdout.write(hosts_text(rows, a.min_conf))
        return 0

    if a.cmd == "import":
        sess = Session(store.next_id(), "pcap:" + os.path.basename(a.pcap),
                       note=a.note or os.path.basename(a.pcap), dns_ports=_ports(a.dns_ports))
        read_pcap(a.pcap, sess)
        store.save(sess)
        print(json.dumps(sess.summary()))
        return 0

    host, _, port = a.listen.rpartition(":")
    feeds = Feeds(_data_dir(a.data), enabled=not a.no_feeds)
    reputation = Reputation(feeds, AbuseIPDB(store, load_key(a.abuseipdb_key_file)))
    pw = load_password(a.pihole_key_file) if a.pihole_url else None
    if a.pihole_url and not pw:
        print("pihole: --pihole-url set but no password in credential/%s; disabled" % a.pihole_key_file,
              flush=True)
    pihole = PiHole(store, a.pihole_url, pw, a.pihole_interval)
    app = App(store, a.iface, _ports(a.dns_ports), a.max_duration, a.keep, a.allow_addressed,
              whois=Whois(store, enabled=not a.no_whois), lan=a.lan,
              hosts_file=a.hosts_file or None, reputation=reputation, pihole=pihole)
    feeds.start()
    pihole.start()
    httpd = serve(app, host.strip("[]"), int(port), a.allow_host)

    def bye(*_):
        app.shutdown()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, bye)
    print("spanwatch %s on http://%s  iface=%s" % (__version__, a.listen, a.iface), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        app.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
