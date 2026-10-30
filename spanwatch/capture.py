"""Live capture over AF_PACKET (needs CAP_NET_RAW) and offline pcap replay."""
import socket
import struct
import threading
import time

ETH_P_ALL = 0x0003
SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_STATISTICS = 6
SNAP = 65536


class LiveCapture(threading.Thread):
    """Reads frames from iface into a Session until stopped or deadline."""

    def __init__(self, session, iface, seconds, on_done=None):
        super().__init__(name="capture-%s" % session.id, daemon=True)
        self.session = session
        self.iface = iface
        self.deadline = time.time() + seconds
        self.on_done = on_done
        self._stop_evt = threading.Event()

    def stop(self):
        self._stop_evt.set()

    def _stats(self, s):
        try:
            seen, drops = struct.unpack("II", s.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))
        except OSError:
            return
        sess = self.session
        with sess.lock:
            sess.kernel_seen += seen
            sess.kernel_drops += drops

    def run(self):
        sess = self.session
        status, err = "done", None
        s = None
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            for opt in (getattr(socket, "SO_RCVBUFFORCE", 33), socket.SO_RCVBUF):
                try:
                    s.setsockopt(socket.SOL_SOCKET, opt, 64 << 20)
                    break
                except OSError:
                    continue
            s.bind((self.iface, ETH_P_ALL))
            idx = socket.if_nametoindex(self.iface)
            s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                         struct.pack("iHH8s", idx, PACKET_MR_PROMISC, 0, b""))
            s.settimeout(0.25)
            buf = bytearray(SNAP)
            recv_into = s.recv_into
            ingest = sess.ingest
            now = time.time
            last_stats = now()
            while not self._stop_evt.is_set():
                t = now()
                if t >= self.deadline:
                    break
                if t - last_stats >= 1.0:
                    self._stats(s)
                    last_stats = t
                try:
                    n = recv_into(buf)
                except socket.timeout:
                    with sess.lock:
                        sess._expire_dns(now())
                    continue
                ingest(buf, n, now())
            self._stats(s)
        except Exception as e:  # surface to UI instead of dying silently
            status, err = "error", "%s: %s" % (type(e).__name__, e)
        finally:
            if s is not None:
                s.close()  # dropping the socket also drops our promisc ref
            sess.finish(status, err)
            if self.on_done:
                self.on_done(sess)


def read_pcap(path, session):
    """Replay a classic libpcap file (not pcapng) into a Session."""
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            raise ValueError("not a pcap file")
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            e = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            e = ">"
        elif magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError("pcapng not supported; convert with: tcpdump -r in.pcapng -w out.pcap")
        else:
            raise ValueError("not a pcap file")
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(e + "I", gh[20:24])[0] & 0x0FFFFFFF
        if linktype not in (1, 113, 276):
            raise ValueError("unsupported linktype %d (need Ethernet/SLL)" % linktype)
        rec = struct.Struct(e + "IIII")
        first = None
        while True:
            h = fh.read(16)
            if len(h) < 16:
                break
            sec, frac, incl, _orig = rec.unpack(h)
            data = fh.read(incl)
            if len(data) < incl:
                break
            ts = sec + frac / (1e9 if nano else 1e6)
            if first is None:
                first = ts
                session.started = ts
            if linktype == 113 and len(data) >= 16:      # Linux cooked v1
                data = b"\0" * 12 + data[14:16] + data[16:]
            elif linktype == 276 and len(data) >= 20:    # Linux cooked v2
                data = b"\0" * 12 + data[0:2] + data[20:]
            session.ingest(data, len(data), ts)
            last = ts
        session.finish("done")
        if first is not None:
            session.ended = last
    return session
