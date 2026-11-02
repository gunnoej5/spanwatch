#!/bin/sh
# spanwatch installer. Run with sudo from the repo root.
#
#   sudo deploy/install.sh install        # do this BEFORE plugging the adapter in
#   sudo deploy/install.sh pin <ifname>   # after plugging in: pin its MAC -> span0
#   sudo deploy/install.sh update         # resync code to /opt/spanwatch, restart
#   sudo deploy/install.sh uninstall      # remove units/rules/code (keeps data)
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
SRC="$(cd "$(dirname "$0")/.." && pwd)"
IFNAME=span0
GUARD=/etc/udev/rules.d/89-spanwatch-usb-guard.rules
PIN=/etc/udev/rules.d/90-spanwatch-span0.rules

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m!!\033[0m %s\n' "$*" >&2; exit 1; }

sync_code() {
  say "copying code -> /opt/spanwatch (root-owned: the CAP_NET_RAW service never runs user-writable code)"
  install -d -m 0755 /opt/spanwatch
  rm -rf /opt/spanwatch/spanwatch
  cp -r "$SRC/spanwatch" /opt/spanwatch/
  find /opt/spanwatch -name __pycache__ -prune -exec rm -rf {} +
  chown -R root:root /opt/spanwatch
  chmod -R u=rwX,go=rX /opt/spanwatch
}

install_units() {
  install -d -m 0755 /etc/spanwatch
  [ -e /etc/spanwatch/abuseipdb.key ] || install -m 0600 -o root -g root /dev/null /etc/spanwatch/abuseipdb.key
  install -m 0755 "$SRC/deploy/spanwatch-iface" /usr/local/sbin/spanwatch-iface
  install -m 0644 "$SRC/deploy/spanwatch-iface@.service" "$SRC/deploy/spanwatch.service" /etc/systemd/system/
  systemctl daemon-reload
}

cmd_install() {
  say "udev guard: NetworkManager will not manage USB Ethernet NICs (no DHCP/SLAAC on plug-in)"
  cat > "$GUARD" <<'EOF'
# spanwatch: keep NetworkManager's hands off USB Ethernet adapters so a freshly
# plugged sniff adapter never DHCPs/SLAACs. Delete this file to undo.
SUBSYSTEM=="net", ACTION=="add|change|move", ENV{ID_BUS}=="usb", ENV{DEVTYPE}!="wlan", ENV{NM_UNMANAGED}="1"
EOF
  udevadm control --reload
  install -d -m 0755 /etc/spanwatch
  [ -e /etc/spanwatch/spanwatch.env ] || install -m 0644 "$SRC/deploy/spanwatch.env.example" /etc/spanwatch/spanwatch.env
  install_units
  sync_code
  systemctl enable "spanwatch-iface@$IFNAME.service" >/dev/null
  systemctl enable --now spanwatch.service
  say "dashboard: http://127.0.0.1:9595"
  say "next: plug the adapter in, find it with 'ip -br link', then: sudo $0 pin <ifname>"
}

cmd_pin() {
  dev="${1:-}"
  [ -n "$dev" ] || die "usage: $0 pin <ifname>   (see: ip -br link)"
  [ -d "/sys/class/net/$dev" ] || die "no such interface: $dev"
  if ip route show default | grep -qw "dev $dev"; then die "$dev carries the default route — that's your uplink, not a sniff port"; fi
  bus=$(udevadm info -q property -p "/sys/class/net/$dev" | sed -n 's/^ID_BUS=//p')
  [ "$bus" = usb ] || printf 'warning: %s is not a USB device (ID_BUS=%s)\n' "$dev" "$bus"
  mac=$(cat "/sys/class/net/$dev/address")
  drv=$(basename "$(readlink -f "/sys/class/net/$dev/device/driver")")
  say "pinning $dev ($mac, $drv) -> $IFNAME"
  cat > "$PIN" <<EOF
# spanwatch: the sniff adapter, by MAC. Named $IFNAME, unmanaged by NetworkManager.
SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="$mac", NAME="$IFNAME", ENV{NM_UNMANAGED}="1"
EOF
  udevadm control --reload
  nmcli device set "$dev" managed no 2>/dev/null || true
  if [ "$dev" != "$IFNAME" ]; then
    ip link set dev "$dev" down
    ip addr flush dev "$dev" || true
    ip link set dev "$dev" name "$IFNAME"
  fi
  udevadm trigger --action=add "/sys/class/net/$IFNAME"
  udevadm settle
  systemctl restart "spanwatch-iface@$IFNAME.service"
  sleep 1
  say "state:"
  ip -br addr show dev "$IFNAME"
  ip -s link show dev "$IFNAME"
  if ip -o addr show dev "$IFNAME" | grep -q .; then die "$IFNAME still has addresses!"; fi
  if nft list table netdev "spanwatch_$IFNAME" >/dev/null 2>&1; then say "egress drop: active"; else echo "egress drop: NOT active"; fi
  say "receive-only. Dashboard: http://127.0.0.1:9595"
}

cmd_update() {
  install_units
  sync_code
  systemctl restart spanwatch.service
  say "updated + restarted"
}

cmd_uninstall() {
  systemctl disable --now spanwatch.service "spanwatch-iface@$IFNAME.service" 2>/dev/null || true
  rm -f /etc/systemd/system/spanwatch.service /etc/systemd/system/spanwatch-iface@.service \
        /usr/local/sbin/spanwatch-iface "$GUARD" "$PIN"
  rm -rf /opt/spanwatch
  systemctl daemon-reload
  udevadm control --reload
  say "removed. Data kept in /var/lib/private/spanwatch; config in /etc/spanwatch."
}

case "${1:-}" in
  install) cmd_install ;;
  pin) cmd_pin "${2:-}" ;;
  update) cmd_update ;;
  uninstall) cmd_uninstall ;;
  *) sed -n '2,8p' "$0"; exit 2 ;;
esac
