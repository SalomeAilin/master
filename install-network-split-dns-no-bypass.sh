#!/bin/zsh
set -euo pipefail

PF_CONF="/etc/pf.conf"
PF_ANCHOR="/etc/pf.anchors/com.local.network-split-dns"
PF_MARKER='anchor "com.local.network-split-dns"'
CHROME_POLICY="/Library/Managed Preferences/com.google.Chrome.plist"
FIREWALL_PLIST="/Library/LaunchDaemons/com.local.network-split-dns-firewall.plist"
STAMP="$(/bin/date +%Y%m%d-%H%M%S)"
SOURCE_DIR="${0:A:h}"

/bin/mkdir -p "${CHROME_POLICY:h}"
/bin/cp "$SOURCE_DIR/com.local.network-split-dns.pf" "$PF_ANCHOR"
/bin/cp "$SOURCE_DIR/com.google.Chrome.plist" "$CHROME_POLICY"
/bin/cp "$SOURCE_DIR/com.local.network-split-dns-firewall.plist" "$FIREWALL_PLIST"
/usr/bin/plutil -lint "$CHROME_POLICY"
/usr/bin/plutil -lint "$FIREWALL_PLIST"

if ! /usr/bin/grep -Fq "$PF_MARKER" "$PF_CONF"; then
  /bin/cp "$PF_CONF" "${PF_CONF}.bak.${STAMP}"
  /bin/echo '' >> "$PF_CONF"
  /bin/echo 'anchor "com.local.network-split-dns"' >> "$PF_CONF"
  /bin/echo 'load anchor "com.local.network-split-dns" from "/etc/pf.anchors/com.local.network-split-dns"' >> "$PF_CONF"
fi

/sbin/pfctl -nf "$PF_CONF"
/bin/launchctl bootout system "$FIREWALL_PLIST" >/dev/null 2>&1 || true
/bin/launchctl bootstrap system "$FIREWALL_PLIST"
/bin/sleep 1

# Keep a checked rollback path if the local resolver is not reachable.
if ! /usr/bin/dig +time=2 +tries=1 +short A @192.168.1.100 www.douyin.com | /usr/bin/grep -Eq '^[0-9]+\.'; then
  /sbin/pfctl -a com.local.network-split-dns -F all
  exit 1
fi
