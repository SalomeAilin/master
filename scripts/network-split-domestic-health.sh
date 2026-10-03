#!/bin/zsh

# Observe the actual HTTP endpoint; only route drift triggers route recovery.
set -u

PATH="/usr/bin:/bin:/usr/sbin:/sbin"
ETH_GW="192.168.1.1"
ETH_IF="en0"
GUARD_SERVICE="system/com.local.network-split-guard"
PROBE_DOMAIN="live.douyin.com"
PROBE_URL="https://live.douyin.com/"
MAX_SECONDS="4.0"
STATE_FILE="/var/db/network-split-domestic-health.state"
LOCK_FILE="/var/run/network-split-domestic-health.flock"
LOG_FILE="/var/log/network-split-domestic-health.log"

log() {
  /bin/echo "$(/bin/date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
}

reset_probe_schedule() {
  failure_count=0
  probe_interval=30
  last_probe=0
  cooldown_until=0
  baseline_ms=0
  slow_count=0
  probe_samples=()
}

load_probe_schedule() {
  local key value sample
  local -A saved file_stat
  local -a samples
  [[ -f "$STATE_FILE" && ! -L "$STATE_FILE" ]] || return 1
  zmodload -F zsh/stat b:zstat || return 1
  zstat -H file_stat -- "$STATE_FILE" || return 1
  (( file_stat[size] <= 4096 )) || return 1
  while IFS='=' read -r key value; do
    case "$key" in
      version|failure_count|probe_interval|last_probe|cooldown_until|baseline_ms|slow_count)
        [[ -n "$value" && "$value" != *[^0-9]* && ${#value} -le 10 ]] || return 1
        ;;
      probe_samples)
        [[ ${#value} -le 35 && "$value" != *[^0-9,]* ]] || return 1
        ;;
      *) return 1 ;;
    esac
    [[ -z "${saved[$key]+present}" ]] || return 1
    saved[$key]="$value"
  done < "$STATE_FILE"
  (( ${#saved} == 8 )) && [[ "$saved[version]" = 1 ]] || return 1
  case "$saved[probe_interval]" in 30|60|120) ;; *) return 1 ;; esac
  samples=("${(@s:,:)saved[probe_samples]}")
  [[ -z "$saved[probe_samples]" ]] && samples=()
  (( ${#samples} <= 6 )) || return 1
  for sample in "${samples[@]}"; do
    [[ -n "$sample" && ${#sample} -le 5 ]] || return 1
    (( 10#$sample <= 10000 )) || return 1
  done
  (( 10#$saved[failure_count] <= 1000000 && 10#$saved[baseline_ms] <= 10000 &&
     10#$saved[slow_count] < 3 && 10#$saved[last_probe] <= now &&
     now - 10#$saved[last_probe] <= 600 && 10#$saved[cooldown_until] <= now + 600 )) || return 1
  (( saved[probe_interval] == 30 || 10#$saved[cooldown_until] <= now )) || return 1
  failure_count=$(( 10#$saved[failure_count] ))
  probe_interval=$saved[probe_interval]
  last_probe=$(( 10#$saved[last_probe] ))
  cooldown_until=$(( 10#$saved[cooldown_until] ))
  baseline_ms=$(( 10#$saved[baseline_ms] ))
  slow_count=$(( 10#$saved[slow_count] ))
  probe_samples=()
  for sample in "${samples[@]}"; do probe_samples+=($(( 10#$sample ))); done
  return 0
}

write_state() {
  local tmp_file="${STATE_FILE}.tmp.$$"
  if ! /usr/bin/printf '%s\n' 'version=1' "failure_count=$failure_count" \
      "probe_interval=$probe_interval" "last_probe=$last_probe" \
      "cooldown_until=$cooldown_until" "baseline_ms=$baseline_ms" \
      "slow_count=$slow_count" "probe_samples=${(j:,:)probe_samples}" > "$tmp_file"; then
    /bin/rm -f "$tmp_file"
    return 1
  fi
  if ! /bin/chmod 600 "$tmp_file" || ! /bin/mv "$tmp_file" "$STATE_FILE"; then
    /bin/rm -f "$tmp_file"
    return 1
  fi
}

probe_due() {
  (( last_probe == 0 || now - last_probe >= probe_interval ))
}

record_probe_sample() {
  local sample_ok="$1" elapsed_ms="$2" sample_reason="$3"
  local old_interval=$probe_interval threshold median
  local -a ordered
  last_probe=$now
  if (( sample_ok )); then
    probe_samples+=("$elapsed_ms")
    (( ${#probe_samples} > 6 )) && probe_samples=("${probe_samples[@]: -6}")
    if (( ${#probe_samples} == 6 )); then
      ordered=("${(@on)probe_samples}")
      median=$(( (ordered[3] + ordered[4]) / 2 ))
    fi
  fi
  if (( sample_ok && probe_interval > 30 )); then
    # A relative AND absolute margin avoids reacting to ordinary timing noise.
    threshold=$(( baseline_ms + 250 ))
    (( baseline_ms * 3 / 2 > threshold )) && threshold=$(( baseline_ms * 3 / 2 ))
    if (( elapsed_ms > threshold )); then
      slow_count=$(( slow_count + 1 ))
    else
      slow_count=0
    fi
    if (( slow_count >= 3 || (${#probe_samples} == 6 && median > threshold) )); then
      sample_ok=0
      sample_reason=latency_regression
    fi
  fi
  if (( ! sample_ok )); then
    probe_interval=30
    cooldown_until=$(( now + 600 ))
    baseline_ms=0
    slow_count=0
    probe_samples=()
    if (( old_interval != 30 )); then
      log "probe schedule rollback interval=${old_interval}->30 reason=$sample_reason cooldown=600s"
    fi
    return 0
  fi

  if (( ${#probe_samples} == 6 && now >= cooldown_until )); then
    if (( probe_interval == 30 )); then
      baseline_ms=$median
      probe_interval=60
    elif (( probe_interval == 60 && median <= threshold && slow_count == 0 )); then
      probe_interval=120
    fi
    if (( old_interval != probe_interval )); then
      probe_samples=()
      log "probe schedule trial interval=${old_interval}->${probe_interval} baseline_ms=$baseline_ms median_ms=$median samples=6"
    elif (( probe_interval == 120 )); then
      probe_samples=()
      log "probe schedule verified interval=120 baseline_ms=$baseline_ms median_ms=$median samples=6"
    fi
  fi
  return 0
}

# Kernel lock is released even if this process is killed without cleanup.
umask 077
# Recover abandoned temporary states through the Go maintenance tool before
# acquiring the same writer lock. The active state file is never a candidate.
if maintenance_result="$(/usr/local/sbin/network-domain-proxy-deploy cleanup-health-state 2>&1)"; then
  [[ -z "$maintenance_result" ]] || log "$maintenance_result"
else
  log "state cleanup deferred: $maintenance_result"
fi
unset maintenance_result
zmodload zsh/system || exit 1
: >> "$LOCK_FILE" || exit 1
if ! zsystem flock -t 0 -f lock_fd "$LOCK_FILE"; then
  log "probe skipped: lock busy or unavailable"
  exit 1
fi

zmodload zsh/datetime || exit 1
now=$EPOCHSECONDS
reset_probe_schedule
load_probe_schedule || reset_probe_schedule
probe_due || exit 0

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
http_ms="$(/usr/bin/awk -v value="$http_seconds" 'BEGIN {
  if (value !~ /^[0-9]+([.][0-9]+)?$/ || value + 0 > 10) print -1;
  else printf "%.0f", value * 1000;
}')"

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
elif (( http_ms < 0 )); then
  healthy=0
  reason="invalid_timing"
elif (( http_ms > MAX_SECONDS * 1000 )); then
  healthy=0
  reason="slow_${http_seconds}s"
fi

# Authentication/challenge replies demonstrate connectivity, not a tuning baseline.
sample_ok=0
sample_reason="$reason"
if (( healthy )); then
  case "$http_code" in
    2[0-9][0-9]|3[0-9][0-9]) sample_ok=1 ;;
    *) sample_reason="http_$http_code" ;;
  esac
fi
record_probe_sample "$sample_ok" "$http_ms" "$sample_reason"

if [ "$healthy" -eq 1 ]; then
  if [ "$failure_count" -gt 0 ]; then
    log "recovered domain=$PROBE_DOMAIN ip=$ip local_ip=$local_ip curl_exit=$curl_exit http=$http_code time=${http_seconds}s prior_failures=$failure_count"
  fi
  failure_count=0
  write_state || exit 1
  exit 0
fi

(( failure_count < 1000000 )) && failure_count=$((failure_count + 1))
log "unhealthy domain=$PROBE_DOMAIN ip=${ip:-none} local_ip=${local_ip:-none} curl_exit=$curl_exit reason=$reason http=${http_code:-000} time=${http_seconds:-none}s failures=$failure_count"

if [ "$reason" = "route_drift" ]; then
  # No -k: an in-progress repair must finish without being restarted.
  if ! /bin/launchctl kickstart "$GUARD_SERVICE" >/dev/null 2>&1; then
    log "route recovery request failed service=$GUARD_SERVICE; no direct retry"
  fi
fi

write_state
