#!/bin/zsh
set -euo pipefail

SOURCE_DIR="${0:A:h}"
AGENT_TARGET="/usr/local/sbin/network-split-dns-event-route-agent.py"
PLIST_TARGET="/Library/LaunchDaemons/com.local.network-split-dns-event-route-agent.plist"
DNS_CONFIG="/usr/local/etc/dnsmasq-network-split.conf"
DNS_BINARY="/usr/local/sbin/dnsmasq-network-split"
DNS_LOG="/var/log/dnsmasq-network-split-query.log"
STAMP="$(/bin/date +%Y%m%d-%H%M%S)"

/bin/cp "$SOURCE_DIR/network-split-dns-event-route-agent.py" "$AGENT_TARGET"
/bin/chmod 755 "$AGENT_TARGET"
/bin/cp "$SOURCE_DIR/com.local.network-split-dns-event-route-agent.plist" "$PLIST_TARGET"
/usr/bin/plutil -lint "$PLIST_TARGET"

/bin/cp "$DNS_CONFIG" "${DNS_CONFIG}.bak.${STAMP}"
/bin/cp "$DNS_CONFIG" "${DNS_CONFIG}.new"
/usr/bin/grep -qx 'log-queries=extra' "${DNS_CONFIG}.new" || /bin/echo 'log-queries=extra' >> "${DNS_CONFIG}.new"
/usr/bin/grep -qx "log-facility=$DNS_LOG" "${DNS_CONFIG}.new" || /bin/echo "log-facility=$DNS_LOG" >> "${DNS_CONFIG}.new"
"$DNS_BINARY" --test -C "${DNS_CONFIG}.new"
/bin/mv "${DNS_CONFIG}.new" "$DNS_CONFIG"
/usr/bin/touch "$DNS_LOG"
/bin/chmod 644 "$DNS_LOG"

/bin/launchctl bootout system "$PLIST_TARGET" >/dev/null 2>&1 || true
/bin/launchctl bootstrap system "$PLIST_TARGET"
/bin/launchctl kickstart -k system/homebrew.mxcl.dnsmasq
