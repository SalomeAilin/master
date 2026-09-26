#!/bin/zsh
set -eu
cd "${0:A:h}/.."
eval "$(sed -n '/^HEALTH_CHECK_TARGETS=/p' china-route.sh)"
[[ ${#HEALTH_CHECK_TARGETS} -eq 5 ]]
for target in $HEALTH_CHECK_TARGETS; do [[ "$target" != *' '* ]]; done
print 'PASS five independent health targets'

eval "$(sed -n '/^check_domestic_domains() {/,/^}/p' network-split-guard.sh)"
DOMESTIC_DOMAIN_LIST=/nonexistent/network-split-test
calls=0
check_domestic_domain() {
  calls=$((calls + 1))
  [[ "$1" = baidu.com ]] && return 2
  [[ "$1" = bilibili.com && "$route_failure" = yes ]] && return 1
  return 0
}
route_failure=no
if ! check_domestic_domains; then exit 1; fi
[[ $calls -gt 2 ]]
route_failure=yes
if check_domestic_domains; then exit 1; fi
print 'PASS DNS failure does not request rebuild or stop later checks'

eval "$(sed -n '/^ensure_foreign_default_route() {/,/^}/p' network-split-guard.sh)"
ETH_GW=192.168.1.1
ETH_IF=en0
WIFI_IF=en1
trace=''
read_default_route() { print '192.168.1.1 en0'; }
wifi_gateway_ready() { [[ $scenario != down && $scenario != block_failure ]]; }
active_wifi_gateway() { print 172.20.10.1; }
ensure_foreign_block_routes() {
  trace+=block,
  [[ $scenario != block_failure ]]
}
ensure_wired_fallback_route() { trace+=wired,; }
default_route_matches() { [[ $trace = *wifi,* && $scenario != repair_failure ]]; }
rebuild_default_route() { trace+=wifi,; }
remove_foreign_block_routes() { trace+=unblock,; }
log_if_not_quiet() { :; }
for scenario in down block_failure recover repair_failure; do
  trace=''
  if ensure_foreign_default_route; then result=0; else result=$?; fi
  case $scenario in
    down) [[ $trace = block,wired, && $result = 1 ]] ;;
    block_failure) [[ $trace = block, && $result = 1 ]] ;;
    recover) [[ $trace = block,wifi,unblock, && $result = 0 ]] ;;
    repair_failure) [[ $trace = block,wifi, && $result = 1 ]] ;;
  esac
done
print 'PASS switching order and fail-closed error branches'

# Wi-Fi can recover during the domestic scan, with reject routes still present.
(
  eval "$(sed -n '/^protect_foreign_priority() {/,/^}/p' network-split-guard.sh)"
  read_default_route() { print '172.20.10.1 en1'; }
  foreign_default_route_active() { return 0; }
  default_route_matches() { return 0; }
  remove_foreign_block_routes() {
    trace+=unblock,
    [[ "$scenario" != cleanup_failure ]]
  }
  wifi_route_label() { print '172.20.10.1/en1'; }
  log() { :; }
  for scenario in recovered_during_scan cleanup_failure down; do
    trace=''
    if protect_foreign_priority; then result=0; else result=$?; fi
    case $scenario in
      recovered_during_scan) [[ "$trace" = unblock, && "$result" = 0 ]] ;;
      cleanup_failure) [[ "$trace" = unblock, && "$result" = 1 ]] ;;
      down) [[ -z "$trace" && "$result" = 0 ]] ;;
    esac
  done
)
print 'PASS end-of-scan recovery reconciles reject routes even with a Wi-Fi default'

# Exercise the actual guard entry lock without reaching network mutations.
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/network-recovery-test.XXXXXXXX")
lock_path="$test_dir/guard.flock"
ready_path="$test_dir/ready"
owner=''
cleanup() {
  if [[ -n "$owner" ]]; then
    kill "$owner" 2>/dev/null || true
    wait "$owner" 2>/dev/null || true
  fi
  rm -r "$test_dir"
}
trap cleanup EXIT
guard_lock=$(sed -n '/^umask 077$/,/^zsystem flock /p' network-split-guard.sh)
[[ "$guard_lock" = *'zsystem flock -t 0 -f lock_fd "$LOCK_FILE" || exit 0'* ]]
zsh -c 'LOCK_FILE="$1"; eval "$3"; touch "$2"; zmodload zsh/zselect; zselect -t 1000' test "$lock_path" "$ready_path" "$guard_lock" &
owner=$!
for attempt in {1..50}; do
  [[ -e "$ready_path" ]] && break
  sleep 0.05
done
[[ -e "$ready_path" ]]
zsh -c 'LOCK_FILE="$1"; eval "$3"; touch "$2"' test "$lock_path" "$test_dir/overlap" "$guard_lock"
[[ ! -e "$test_dir/overlap" ]]
[[ "$(stat -f %Lp "$lock_path")" = 600 ]]
kill -KILL "$owner"
wait "$owner" 2>/dev/null || true
owner=''
zsh -c 'LOCK_FILE="$1"; eval "$3"; touch "$2"' test "$lock_path" "$test_dir/recovered" "$guard_lock"
[[ -e "$test_dir/recovered" ]]
print 'PASS actual guard lock excludes overlap and recovers after SIGKILL'

# A health failure must not start a second script or kill an existing guard.
eval "$(sed -n '/^GUARD_SERVICE=/p' network-split-domestic-health.sh)"
recovery=$(sed -n '/^if \[ "$reason" = "route_drift" \]; then/,/^fi$/p' network-split-domestic-health.sh)
[[ "$recovery" != *ROOT_GUARD* && "$recovery" = *'/bin/launchctl kickstart "$GUARD_SERVICE"'* ]]
recovery=${recovery//\/bin\/launchctl/mock_launchctl}
mock_launchctl() { launch_calls+=("$*"); return "$launch_result"; }
log() { recovery_logs+=("$*"); }
for reason in route_drift curl_28 slow_5s http_503; do
  launch_calls=()
  recovery_logs=()
  launch_result=0
  eval "$recovery"
  if [[ "$reason" = route_drift ]]; then
    [[ ${#launch_calls} = 1 && "$launch_calls[1]" = "kickstart $GUARD_SERVICE" ]]
  else
    [[ ${#launch_calls} = 0 ]]
  fi
  [[ ${#recovery_logs} = 0 ]]
done
reason=route_drift
launch_result=1
launch_calls=()
recovery_logs=()
eval "$recovery"
[[ ${#launch_calls} = 1 && ${#recovery_logs} = 1 ]]
print 'PASS health recovery uses one non-restarting launchd request, only for drift'

# Exercise adaptive scheduling with a fake clock, never the live health service.
(
  for name in reset_probe_schedule load_probe_schedule write_state probe_due record_probe_sample; do
    eval "$(sed -n "/^${name}() {/,/^}/p" network-split-domestic-health.sh)"
  done
  STATE_FILE="$test_dir/health.state"
  schedule_logs=()
  log() { schedule_logs+=("$*"); }
  now=1000
  reset_probe_schedule
  probe_due
  for attempt in {1..5}; do
    now=$((now + 30))
    record_probe_sample 1 100 ok
    [[ $probe_interval = 30 ]]
  done
  now=$((now + 30))
  record_probe_sample 1 100 ok
  [[ $probe_interval = 60 && $baseline_ms = 100 && ${#probe_samples} = 0 ]]
  now=$((now + 30))
  if probe_due; then exit 1; fi
  now=$((now + 30))
  probe_due
  for attempt in {1..6}; do
    record_probe_sample 1 100 ok
    now=$((now + 60))
  done
  [[ $probe_interval = 120 ]]
  for attempt in {1..2}; do
    record_probe_sample 1 500 ok
    [[ $probe_interval = 120 ]]
    now=$((now + 120))
  done
  record_probe_sample 1 500 ok
  [[ $probe_interval = 30 && $cooldown_until = $((now + 600)) && $baseline_ms = 0 ]]
  for attempt in {1..19}; do
    now=$((now + 30))
    record_probe_sample 1 100 ok
    [[ $probe_interval = 30 ]]
  done
  now=$((now + 30))
  record_probe_sample 1 100 ok
  [[ $probe_interval = 60 ]]
  record_probe_sample 0 -1 curl_28
  [[ $probe_interval = 30 && ${#probe_samples} = 0 ]]
  print 'PASS measured baseline, staged backoff, sustained regression and cooldown'

  reset_probe_schedule
  for attempt in {1..6}; do
    now=$((now + 30))
    record_probe_sample 1 100 ok
  done
  for duration in 500 100 100 100 100 100; do
    now=$((now + 60))
    record_probe_sample 1 "$duration" ok
    [[ $probe_interval != 30 ]]
  done
  [[ $probe_interval = 120 ]]
  for duration in 500 500 100 500 500 100; do
    now=$((now + 120))
    record_probe_sample 1 "$duration" ok
  done
  [[ $probe_interval = 30 ]]
  reset_probe_schedule
  for attempt in {1..6}; do
    now=$((now + 30))
    record_probe_sample 1 1000 ok
  done
  for attempt in {1..6}; do
    now=$((now + 60))
    record_probe_sample 1 1400 ok
  done
  [[ $probe_interval = 120 ]]
  record_probe_sample 0 -1 http_503
  print 'PASS one outlier is tolerated; bad window rolls back; both timing margins apply'

  # Round-trip only a bounded, versioned data format; never source shell state.
  write_state
  saved_now=$now
  reset_probe_schedule
  load_probe_schedule
  [[ $last_probe = $saved_now && $cooldown_until = $((now + 600)) ]]
  [[ "$(stat -f %Lp "$STATE_FILE")" = 600 ]]
  [[ ! -e "${STATE_FILE}.tmp.$$" ]]
  valid_state="$(<"$STATE_FILE")"
  now=$((saved_now - 1))
  if load_probe_schedule; then exit 1; fi
  now=$((saved_now + 601))
  if load_probe_schedule; then exit 1; fi
  now=$saved_now
  for corrupt in 'failure_count=2' 'version=99' 'version=$(touch forbidden)' 'version=999999999999999999999'; do
    print -r -- "$corrupt" > "$STATE_FILE"
    if load_probe_schedule; then exit 1; fi
  done
  for corrupt in "${valid_state/probe_interval=30/probe_interval=999}" \
      "${valid_state/failure_count=0/failure_count=1000001}" \
      "${valid_state/slow_count=0/slow_count=3}" \
      "${valid_state/baseline_ms=0/baseline_ms=10001}" \
      "${valid_state/probe_samples=/probe_samples=100,,200}" \
      "${valid_state/probe_samples=/probe_samples=100,}" \
      "${valid_state/probe_samples=/probe_samples=10001}" \
      "${valid_state/probe_samples=/probe_samples=1,2,3,4,5,6,7}" \
      "${valid_state}"$'\nversion=1'; do
    print -r -- "$corrupt" > "$STATE_FILE"
    if load_probe_schedule; then exit 1; fi
  done
  print -r -- "$valid_state" > "$STATE_FILE"
  load_probe_schedule
  previous_writer=$functions[write_state]
  functions[write_state]=${previous_writer//\/bin\/mv/fail_rename}
  fail_rename() { return 1; }
  if write_state; then exit 1; fi
  [[ "$(<"$STATE_FILE")" = "$valid_state" && ! -e "${STATE_FILE}.tmp.$$" ]]
  functions[write_state]=$previous_writer
  print 'PASS private atomic state, old/corrupt state and clock/sleep reset'
)

# Run the whole existing health program with only its external effects mocked.
(
  health_state="$test_dir/integration.state"
  health_lock="$test_dir/integration.lock"
  health_log="$test_dir/integration.log"
  requests="$test_dir/requests"
  recovery_requests="$test_dir/recovery-requests"
  body="$(sed -e 's|^STATE_FILE=.*|STATE_FILE="$health_state"|' \
    -e 's|^LOCK_FILE=.*|LOCK_FILE="$health_lock"|' \
    -e 's|^LOG_FILE=.*|LOG_FILE="$health_log"|' \
    -e 's|^now=\$EPOCHSECONDS$|now=$fake_now|' \
    -e 's|/usr/bin/curl|mock_curl|g' \
    -e 's|/sbin/route|mock_route|g' \
    -e 's|/bin/launchctl|mock_launchctl|g' network-split-domestic-health.sh)"
  mock_curl() {
    print called >> "$requests"
    print "$response|223.5.5.5|192.0.2.1"
    return "$curl_status"
  }
  mock_route() { print "gateway: $route_gateway\ninterface: en0"; }
  mock_launchctl() { print "$*" >> "$recovery_requests"; }
  run_health() ( set +e; eval "$body" )
  response='200|0.100000'
  route_gateway=192.168.1.1
  curl_status=0
  for fake_now in {1000..4600..30}; do run_health; done
  # 121 scheduled invocations: six at 30s, six at 60s, then 25 at 120s.
  [[ $(wc -l < "$requests") -eq 37 ]]
  [[ ! -e "$recovery_requests" ]]
  [[ "$(<"$health_state")" = *'probe_interval=120'* ]]
  print 'PASS replay: 37 HTTP probes versus 121 fixed-cadence probes, no route repair'

  # A failed trial immediately restores the original cadence, without repair.
  fake_now=4720
  response='000|10.000000'
  curl_status=28
  run_health
  [[ "$(<"$health_state")" = *'probe_interval=30'* ]]
  [[ ! -e "$recovery_requests" ]]
  # HTTP challenges must not qualify as a healthy performance baseline.
  response='403|0.010000'
  curl_status=0
  for fake_now in {4750..5500..30}; do run_health; done
  [[ "$(<"$health_state")" = *'probe_interval=30'* ]]
  [[ ! -e "$recovery_requests" ]]
  # Known route drift still requests exactly the original, non-restarting guard.
  fake_now=5530
  response='200|0.100000'
  route_gateway=192.0.2.254
  run_health
  [[ "$(<"$recovery_requests")" = 'kickstart system/com.local.network-split-guard' ]]
  [[ "$(<"$health_state")" = *'probe_interval=30'* ]]
  print 'PASS timeout/challenge rollback and route-drift-only recovery integration'

  fake_now=5560
  route_gateway=192.168.1.1
  response='200|not-a-duration'
  run_health
  [[ "$(<"$health_state")" = *'probe_interval=30'* ]]
  [[ "$(<"$health_log")" = *'reason=invalid_timing'* ]]
  [[ $(wc -l < "$recovery_requests") -eq 1 ]]
  # A stale/corrupt schedule must run a fresh probe rather than suppress checks.
  before=$(wc -l < "$requests")
  print 'version=invalid' > "$health_state"
  fake_now=5570
  response='200|0.100000'
  run_health
  [[ $(wc -l < "$requests") -eq $((before + 1)) ]]
  [[ "$(<"$health_state")" = *'probe_interval=30'* ]]
  fake_now=6200
  run_health
  [[ "$(<"$health_state")" = *'probe_samples=100'* ]]
  [[ ! -e "${health_state}.tmp.$$" ]]
  print 'PASS malformed timing, persisted-state reset and task-file cleanup'
)
