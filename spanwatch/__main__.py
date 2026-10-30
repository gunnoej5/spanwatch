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
from .server import App, serve
from .session import Session
from .store import Store
from .whois import Whois


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
    sv.add_argument("--no-whois", action="store_true",
                    help="disable on-demand RDAP/Cymru lookups (no outbound traffic)")

    im = sub.add_parser("import", help="load a classic .pcap as a session")
    im.add_argument("pcap")
    im.add_argument("--data")
    im.add_argument("--note", default="")
    im.add_argument("--dns-ports", default="53")

    st = sub.add_parser("status", help="print interface health")
    st.add_argument("--iface", default="span0")

    a = ap.parse_args(argv)

    if a.cmd == "status":
        s = ifmod.status(a.iface)
        s["receive_only"] = ifmod.receive_only(s)
        print(json.dumps(s, indent=2))
        return 0 if s["receive_only"] else 1

    store = Store(os.path.join(_data_dir(a.data), "spanwatch.db"))

    if a.cmd == "import":
        sess = Session(store.next_id(), "pcap:" + os.path.basename(a.pcap),
                       note=a.note or os.path.basename(a.pcap), dns_ports=_ports(a.dns_ports))
        read_pcap(a.pcap, sess)
        store.save(sess)
        print(json.dumps(sess.summary()))
        return 0

    host, _, port = a.listen.rpartition(":")
    app = App(store, a.iface, _ports(a.dns_ports), a.max_duration, a.keep, a.allow_addressed,
              whois=Whois(store, enabled=not a.no_whois))
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
