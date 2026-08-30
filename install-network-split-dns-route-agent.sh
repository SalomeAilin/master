#!/bin/zsh
set -euo pipefail

AGENT_SOURCE="/Users/alsay/Documents/master/network-split-dns-route-agent.py"
PLIST_SOURCE="/Users/alsay/Documents/master/com.local.network-split-dns-route-agent.plist"
AGENT_TARGET="/usr/local/sbin/network-split-dns-route-agent.py"
PLIST_TARGET="/Library/LaunchDaemons/com.local.network-split-dns-route-agent.plist"
DNS_CONFIG="/usr/local/etc/dnsmasq-network-split.conf"
DNS_BINARY="/usr/local/sbin/dnsmasq-network-split"
STAMP="$(/bin/date +%Y%m%d-%H%M%S)"

/bin/cp "$AGENT_SOURCE" "$AGENT_TARGET"
/bin/chmod 755 "$AGENT_TARGET"
/bin/cp "$PLIST_SOURCE" "$PLIST_TARGET"
/usr/bin/plutil -lint "$PLIST_TARGET"

/bin/launchctl bootout system "$PLIST_TARGET" >/dev/null 2>&1 || true
/bin/launchctl bootstrap system "$PLIST_TARGET"
/bin/sleep 1

# The local proxy must prove it can bind a domestic answer before dnsmasq is changed.
/usr/bin/dig +time=2 +tries=1 +short A @127.0.0.1 -p 5353 www.douyin.com | /usr/bin/grep -Eq '^[0-9]+\.'

/bin/cp "$DNS_CONFIG" "${DNS_CONFIG}.bak.${STAMP}"
/usr/bin/awk -F/ '
  $1 == "server=" && ($3 == "223.5.5.5" || $3 == "119.29.29.29") {
    if (!seen[$2]++) print "server=/" $2 "/127.0.0.1#5353"
    next
  }
  { print }
' "$DNS_CONFIG" > "${DNS_CONFIG}.new"

"$DNS_BINARY" --test -C "${DNS_CONFIG}.new"
/bin/mv "${DNS_CONFIG}.new" "$DNS_CONFIG"
/bin/launchctl kickstart -k system/homebrew.mxcl.dnsmasq
