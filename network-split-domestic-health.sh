#!/bin/zsh

# Keep active CDN recovery outside the DNS forwarding path. The passive TTL
# limit still handles ordinary rotation; this only reacts to sustained errors.
set -u

PATH="/usr/bin:/bin:/usr/sbin:/sbin"
DNS_SERVER="192.168.1.100"
ETH_GW="192.168.1.1"
ETH_IF="en0"
DNSMASQ_BIN="/usr/local/sbin/dnsmasq-network-split"
ROOT_GUARD="/usr/local/sbin/network-split-guard.sh"
PROBE_DOMAIN="live.douyin.com"
PROBE_URL="https://live.douyin.com/"
MAX_SECONDS="4.0"
FAILURES_BEFORE_REFRESH=2
REFRESH_COOLDOWN_SECONDS=300
STATE_FILE="/var/db/network-split-domestic-health.state"
LOCK_DIR="/var/run/network-split-domestic-health.lock"
LOG_FILE="/var/log/network-split-domestic-health.log"

log() {
  /bin/echo "$(/bin/date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
}

if ! /bin/mkdir "$LOCK_DIR" 2>/dev/null; then
  exit 0
fi
trap '/bin/rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

failure_count=0
last_refresh=0
if [ -r "$STATE_FILE" ]; then
  failure_count="$(/usr/bin/awk -F= '/^failure_count=/{print $2; exit}' "$STATE_FILE")"
  last_refresh="$(/usr/bin/awk -F= '/^last_refresh=/{print $2; exit}' "$STATE_FILE")"
fi
case "$failure_count" in (*[!0-9]*|'') failure_count=0 ;; esac
case "$last_refresh" in (*[!0-9]*|'') last_refresh=0 ;; esac

write_state() {
  tmp_file="${STATE_FILE}.tmp.$$"
  /usr/bin/printf 'failure_count=%s\nlast_refresh=%s\n' "$failure_count" "$last_refresh" > "$tmp_file"
  /bin/chmod 600 "$tmp_file"
  /bin/mv "$tmp_file" "$STATE_FILE"
}

first_ipv4() {
  /usr/bin/dig +time=2 +tries=1 +short A @"$DNS_SERVER" "$1" 2>/dev/null | \
    /usr/bin/awk -F. 'NF == 4 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ {print; exit}'
}

route_ok() {
  target="$1"
  route_info="$(/sbin/route -n get "$target" 2>/dev/null | /usr/bin/awk '
    /gateway:/{gateway=$2}
    /interface:/{iface=$2}
    END{print gateway "/" iface}
  ')"
  [ "$route_info" = "${ETH_GW}/${ETH_IF}" ]
}

probe_result="$(/usr/bin/curl --noproxy '*' -4 -L -sS -o /dev/null --connect-timeout 4 --max-time 10 -w '%{http_code}:%{time_total}' "$PROBE_URL" 2>/dev/null || true)"
http_code="${probe_result%%:*}"
http_seconds="${probe_result#*:}"
ip="$(first_ipv4 "$PROBE_DOMAIN")"

healthy=1
reason="ok"
if [ -z "$ip" ]; then
  healthy=0
  reason="dns_empty"
elif ! route_ok "$ip"; then
  healthy=0
  reason="route_drift"
elif ! /bin/echo "$http_code" | /usr/bin/grep -Eq '^(2[0-9][0-9]|3[0-9][0-9]|401|403)$'; then
  healthy=0
  reason="http_${http_code:-000}"
elif ! /usr/bin/awk -v value="$http_seconds" -v limit="$MAX_SECONDS" 'BEGIN { exit !(value + 0 <= limit) }'; then
  healthy=0
  reason="slow_${http_seconds}s"
fi

if [ "$healthy" -eq 1 ]; then
  if [ "$failure_count" -gt 0 ]; then
    log "recovered domain=$PROBE_DOMAIN ip=$ip http=$http_code time=${http_seconds}s prior_failures=$failure_count"
  fi
  failure_count=0
  write_state
  exit 0
fi

failure_count=$((failure_count + 1))
now="$(/bin/date +%s)"
log "unhealthy domain=$PROBE_DOMAIN ip=${ip:-none} reason=$reason http=${http_code:-000} time=${http_seconds:-none}s failures=$failure_count"

if [ "$reason" = "route_drift" ]; then
  "$ROOT_GUARD" >/dev/null 2>&1 || true
fi

if [ "$failure_count" -ge "$FAILURES_BEFORE_REFRESH" ] && [ $((now - last_refresh)) -ge "$REFRESH_COOLDOWN_SECONDS" ]; then
  dnsmasq_pid="$(/usr/bin/pgrep -f "^${DNSMASQ_BIN}( |$)" | /usr/bin/head -n 1)"
  if [ -n "$dnsmasq_pid" ]; then
    /bin/kill -HUP "$dnsmasq_pid" 2>/dev/null || true
  fi
  /usr/bin/dscacheutil -flushcache 2>/dev/null || true
  /usr/bin/killall -HUP mDNSResponder 2>/dev/null || true
  "$ROOT_GUARD" >/dev/null 2>&1 || true
  last_refresh="$now"
  failure_count=0
  log "action=refresh_dns_cache domain=$PROBE_DOMAIN reason=$reason dnsmasq_pid=${dnsmasq_pid:-none} cooldown=${REFRESH_COOLDOWN_SECONDS}s"
fi

write_state
