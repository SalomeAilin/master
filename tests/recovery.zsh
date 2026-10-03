#!/bin/zsh
set -eu
cd "${0:A:h}/.."
eval "$(sed -n '/^HEALTH_CHECK_TARGETS=/p' scripts/china-route.sh)"
[[ ${#HEALTH_CHECK_TARGETS} -eq 5 ]]
for target in $HEALTH_CHECK_TARGETS; do [[ "$target" != *' '* ]]; done
print 'PASS five independent health targets'

eval "$(sed -n '/^check_domestic_domains() {/,/^}/p' scripts/network-split-guard.sh)"
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

eval "$(sed -n '/^ensure_foreign_default_route() {/,/^}/p' scripts/network-split-guard.sh)"
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
  eval "$(sed -n '/^protect_foreign_priority() {/,/^}/p' scripts/network-split-guard.sh)"
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
guard_lock=$(sed -n '/^umask 077$/,/^zsystem flock /p' scripts/network-split-guard.sh)
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

# Reap the actual child and preserve launchctl's failure instead of reporting success.
(
  body=$(sed -n '/^kickstart_system_service() {/,/^}/p' scripts/network-split-guard.sh)
  eval "${body//exec \/bin\/launchctl/mock_launchctl}"
  KICKSTART_TIMEOUT_SECONDS=2
  log() { print -r -- "$*" >> "$test_dir/kickstart.log"; }
  mock_launchctl() { return "$launch_result"; }
  for launch_result in 0 5; do
    if kickstart_system_service start test.fixture; then result=0; else result=$?; fi
    [[ $result = $launch_result ]]
  done
  grep -q 'exit=5' "$test_dir/kickstart.log"
  mock_launchctl() { while true; do :; done; }
  KICKSTART_TIMEOUT_SECONDS=0
  if kickstart_system_service start test.fixture; then exit 1; fi
  [[ -z "$(jobs -p)" ]]
)
print 'PASS service start failures propagate and timed-out children are reaped'

# Native health scheduling and recovery are covered in engine/internal/healthcheck.
