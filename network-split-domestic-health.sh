#!/bin/zsh

# Observe the actual HTTP endpoint; only route drift triggers route recovery.
set -u

PATH="/usr/bin:/bin:/usr/sbin:/sbin"
ETH_GW="192.168.1.1"
ETH_IF="en0"
ROOT_GUARD="/usr/local/sbin/network-split-guard.sh"
PROBE_DOMAIN="live.douyin.com"
PROBE_URL="https://live.douyin.com/"
MAX_SECONDS="4.0"
STATE_FILE="/var/db/network-split-domestic-health.state"
LOCK_FILE="/var/run/network-split-domestic-health.flock"
LOG_FILE="/var/log/network-split-domestic-health.log"

log() {
  /bin/echo "$(/bin/date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
}

# Kernel lock is released even if this process is killed without cleanup.
umask 077
zmodload zsh/system || exit 1
: >> "$LOCK_FILE" || exit 1
if ! zsystem flock -t 0 -f lock_fd "$LOCK_FILE"; then
  log "probe skipped: lock busy or unavailable"
  exit 1
fi

failure_count=0
if [ -r "$STATE_FILE" ]; then
  failure_count="$(/usr/bin/awk -F= '/^failure_count=/{print $2; exit}' "$STATE_FILE")"
fi
case "$failure_count" in (*[!0-9]*|'') failure_count=0 ;; esac

write_state() {
  tmp_file="${STATE_FILE}.tmp.$$"
  /usr/bin/printf 'failure_count=%s\n' "$failure_count" > "$tmp_file"
  /bin/chmod 600 "$tmp_file"
  /bin/mv "$tmp_file" "$STATE_FILE"
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

probe_result="$(/usr/bin/curl --noproxy '*' -4 -L -sS -o /dev/null --connect-timeout 4 --max-time 10 -w '%{http_code}|%{time_total}|%{remote_ip}|%{local_ip}' "$PROBE_URL" 2>/dev/null)"
curl_exit=$?
IFS='|' read -r http_code http_seconds ip local_ip <<< "$probe_result"

healthy=1
reason="ok"
if [ -n "$ip" ] && ! route_ok "$ip"; then
  healthy=0
  reason="route_drift"
elif [ "$curl_exit" -ne 0 ]; then
  healthy=0
  reason="curl_${curl_exit}"
elif [ -z "$ip" ]; then
  healthy=0
  reason="missing_remote_ip"
elif ! /bin/echo "$http_code" | /usr/bin/grep -Eq '^(2[0-9][0-9]|3[0-9][0-9]|401|403)$'; then
  healthy=0
  reason="http_${http_code:-000}"
elif ! /usr/bin/awk -v value="$http_seconds" -v limit="$MAX_SECONDS" 'BEGIN { exit !(value + 0 <= limit) }'; then
  healthy=0
  reason="slow_${http_seconds}s"
fi

if [ "$healthy" -eq 1 ]; then
  if [ "$failure_count" -gt 0 ]; then
    log "recovered domain=$PROBE_DOMAIN ip=$ip local_ip=$local_ip curl_exit=$curl_exit http=$http_code time=${http_seconds}s prior_failures=$failure_count"
  fi
  failure_count=0
  write_state
  exit 0
fi

failure_count=$((failure_count + 1))
log "unhealthy domain=$PROBE_DOMAIN ip=${ip:-none} local_ip=${local_ip:-none} curl_exit=$curl_exit reason=$reason http=${http_code:-000} time=${http_seconds:-none}s failures=$failure_count"

if [ "$reason" = "route_drift" ]; then
  "$ROOT_GUARD" >/dev/null 2>&1 || true
fi

write_state
