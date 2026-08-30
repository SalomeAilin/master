#!/bin/zsh
set -euo pipefail

/sbin/pfctl -a com.local.network-split-dns -F all
/bin/launchctl bootout system /Library/LaunchDaemons/com.local.network-split-dns-firewall.plist >/dev/null 2>&1 || true
/bin/rm -f /Library/LaunchDaemons/com.local.network-split-dns-firewall.plist /etc/pf.anchors/com.local.network-split-dns
/usr/bin/sed -i '' '/anchor "com\.local\.network-split-dns"/d; /load anchor "com\.local\.network-split-dns"/d' /etc/pf.conf
/sbin/pfctl -nf /etc/pf.conf
/sbin/pfctl -f /etc/pf.conf
