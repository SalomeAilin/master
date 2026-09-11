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

# Exercise the real kernel lock, including owner death, without system services.
lock_path=$(mktemp)
ready_path=$(mktemp)
rm "$ready_path"
trap 'rm -f "$lock_path" "$ready_path"' EXIT
zsh -c 'zmodload zsh/system; zsystem flock -t 0 -f fd "$1" || exit 1; touch "$2"; sleep 10' test "$lock_path" "$ready_path" &
owner=$!
for attempt in {1..50}; do
  [[ -e "$ready_path" ]] && break
  sleep 0.05
done
[[ -e "$ready_path" ]]
zmodload zsh/system
if zsystem flock -t 0 -f fd "$lock_path" 2>/dev/null; then exit 1; fi
kill -KILL "$owner"
wait "$owner" 2>/dev/null || true
zsystem flock -t 0 -f fd "$lock_path"
zsystem flock -u "$fd"
print 'PASS lock exclusion and recovery after SIGKILL'
