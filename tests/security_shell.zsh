#!/bin/zsh
set -eu
cd "${0:A:h}/.."

# Exercise the real Go policy with repository address lists, never the live router.
work=$(mktemp -d "${TMPDIR:-/tmp}/network-policy-test.XXXXXXXX")
cleanup() {
  (( ZSH_SUBSHELL == 0 )) || return 0
  rm -rf "$work"
}
trap cleanup EXIT ZERR
(cd engine && go build -o "$work/network-split-policy" ./cmd/network-split-policy)
policy_check() {
  "$work/network-split-policy" -policy-file config/china_ip_list.txt -policy-file config/domestic_extra_routes.txt "$@"
}
eval "$(sed -n '/^add_domestic_host_route() {/,/^}/p' scripts/network-split-guard.sh | sed 's|/usr/local/sbin/network-split-policy|policy_check|g; s|/sbin/route|forbidden_route|g')"
# Return value alone is insufficient: record any route call in a temporary file.
trace="$work/trace"
forbidden_route() { print called >> "$trace"; return 99; }
for ip in 8.8.8.8 127.0.0.1 999.1.1.1; do
  add_domestic_host_route evil.cn "$ip"
done
[[ ! -s "$trace" ]]
print 'PASS shell sink rejects foreign and malformed answers before route access'

for script in scripts/china-route.sh; do
  # Check the actual DNS pipeline routes its output through the shared policy.
  body=$(sed -n '/^ipv4s_for_domain() {/,/^}/p' "$script")
  [[ "$body" = *'/usr/local/sbin/network-split-policy'* ]]
done
eval "$(sed -n '/^check_domestic_domain() {/,/^}/p' scripts/network-split-guard.sh | sed 's|/usr/local/sbin/network-split-policy|policy_check|g')"
ipv4s_for_domain() { print 8.8.8.8; }
log() { print logged >> "$trace"; }
check_route() { print route_checked >> "$trace"; return 1; }
check_domestic_domain evil.cn
[[ ! -s "$trace" ]]
print 'PASS denied DNS answer neither logs DNS failure nor triggers repair'
ipv4s_for_domain() { return 0; }
DNS_SERVER=192.168.1.100
if check_domestic_domain missing.cn; then exit 1; else [[ $? = 2 ]]; fi
[[ -s "$trace" ]]
print 'PASS actual empty DNS response remains distinguishable'

# One helper must filter the complete answer batch without losing valid answers.
policy_calls="$work/policy-calls"
functions[real_policy_check]=$functions[policy_check]
policy_check() { print called >> "$policy_calls"; real_policy_check "$@"; }
ipv4s_for_domain() { print '8.8.8.8\n223.5.5.5\n127.0.0.1\n119.29.29.29'; }
ETH_GW=192.168.1.1
ETH_IF=en0
checked=()
check_route() { checked+=("$1"); return 0; }
check_domestic_domain mixed.cn
[[ $(wc -l < "$policy_calls") -eq 1 ]]
[[ "${(j: :)checked}" = '223.5.5.5 119.29.29.29' ]]
print 'PASS one batch invocation preserves allowed answers and rejects others'
policy_check() { return 1; }
checked=()
check_domestic_domain unavailable.cn
[[ ${#checked} = 0 ]]
print 'PASS failed policy helper cannot trigger route lookups or repairs'

# Run the real recovery functions in isolation; never execute the live guard.
(
  recovery_calls="$work/dns-recovery-calls"
  DNSMASQ_BIN="$work/fixed-dnsmasq"
  DNSMASQ_CONFIG="$work/dnsmasq.conf"
  DNSMASQ_CELLAR_DIR="$work/cellar"
  DNSMASQ_LABEL=test.dnsmasq
  mkdir -p "$DNSMASQ_CELLAR_DIR/test/sbin"
  cp /usr/bin/true "$DNSMASQ_CELLAR_DIR/test/sbin/dnsmasq"
  log() { :; }
  mock_stat() { [[ $metadata != fail ]] || return 1; print -r -- "$metadata"; }
  mock_install() { print imported >> "$recovery_calls"; /bin/cp "$DNSMASQ_CELLAR_DIR/test/sbin/dnsmasq" "$DNSMASQ_BIN"; }
  mock_dnsmasq() { print -r -- "test $*" >> "$recovery_calls"; return "$config_result"; }
  route_error_text() { print -r -- "$*"; }
  kickstart_system_service() { print -r -- "restart $*" >> "$recovery_calls"; }
  dnsmasq_running() { [[ $running = yes ]]; }
  dnsmasq_responds() { probes=$((probes + 1)); [[ $responding = yes ]]; }
  body=$(sed -n '/^ensure_dnsmasq_binary() {/,/^}/p' scripts/network-split-guard.sh)
  body=${body//\/usr\/bin\/stat/mock_stat}
  eval "${body//\/usr\/bin\/install/mock_install}"
  body=$(sed -n '/^dnsmasq_config_ok() {/,/^}/p' scripts/network-split-guard.sh)
  eval "${body//\"\$DNSMASQ_BIN\" --test/mock_dnsmasq --test}"
  eval "$(sed -n '/^ensure_dnsmasq() {/,/^}/p' scripts/network-split-guard.sh)"
  body=$(sed -n '/^ensure_dns_responds() {/,/^}/p' scripts/network-split-guard.sh)
  eval "${body//\/bin\/sleep/:}"
  running=no
  responding=no
  config_result=0
  for scenario in missing nonexecutable symlink directory user_owned writable metadata_failure; do
    rm -rf "$DNSMASQ_BIN"
    : > "$recovery_calls"
    metadata='0:0:555'
    case $scenario in
      missing) ;;
      directory) mkdir "$DNSMASQ_BIN" ;;
      symlink) ln -s "$DNSMASQ_CELLAR_DIR/test/sbin/dnsmasq" "$DNSMASQ_BIN" ;;
      *) cp /usr/bin/true "$DNSMASQ_BIN"; chmod 555 "$DNSMASQ_BIN" ;;
    esac
    case $scenario in
      nonexecutable) chmod 444 "$DNSMASQ_BIN" ;;
      user_owned) metadata='501:20:555' ;;
      writable) metadata='0:0:777' ;;
      metadata_failure) metadata=fail ;;
    esac
    if ensure_dnsmasq; then print -u2 "unsafe recovery accepted: $scenario"; exit 1; fi
    probes=0
    if ensure_dns_responds; then exit 1; fi
    [[ $probes = 3 && ! -s "$recovery_calls" ]]
  done
  rm -rf "$DNSMASQ_BIN"
  cp /usr/bin/true "$DNSMASQ_BIN"
  chmod 555 "$DNSMASQ_BIN"
  metadata='0:0:555'
  : > "$recovery_calls"
  ensure_dnsmasq
  expected="test --test --conf-file=$DNSMASQ_CONFIG
restart restart $DNSMASQ_LABEL"
  [[ "$(<$recovery_calls)" = "$expected" ]]
  : > "$recovery_calls"
  probes=0
  if ensure_dns_responds; then exit 1; fi
  [[ $probes = 3 && "$(<$recovery_calls)" = "$expected" ]]
  : > "$recovery_calls"
  config_result=1
  if ensure_dnsmasq; then exit 1; fi
  [[ "$(<$recovery_calls)" = "test --test --conf-file=$DNSMASQ_CONFIG" ]]
  : > "$recovery_calls"
  running=yes
  responding=yes
  ensure_dnsmasq
  ensure_dns_responds
  [[ ! -s "$recovery_calls" ]]
)
print 'PASS DNS recovery refuses untrusted binaries and preserves bounded trusted restarts'

# Route coordination stays under root-only paths, and the query log stays private.
china=$(<scripts/china-route.sh)
guard=$(<scripts/network-split-guard.sh)
[[ "$china$guard" != *'/tmp/china-route'* ]]
[[ "$china" = *'zsystem flock -t 0 -f lock_fd "$LOCK_FILE"'* ]]
for script in "$china" "$guard"; do
  [[ "$script" = *'FORCE_REBUILD_FILE="/var/db/china-route-force-rebuild"'* ]]
done
installer=$(<scripts/install-network-split-dns-event-route-agent.sh)
[[ "$installer" = *'/bin/chmod 660 "$DNS_LOG"'* && "$installer" != *'/bin/chmod 644 "$DNS_LOG"'* ]]
print 'PASS route coordination and query-log permissions stay private'

# Exercise deployment selection and agent reload without running installation.
selection=$(sed -n -e "/^binaries=(/p" -e "/^scripts=(/p" -e "/^legacy=(/p" scripts/deploy-security-update.zsh)
eval "$selection"
[[ "${(j: :)binaries}" = 'network-split-policy network-split-dns-event-route-agent network-domain-proxy-deploy' ]]
[[ "${(j: :)scripts}" = 'china-route.sh network-split-guard.sh' ]]
[[ "${(j: :)legacy}" = 'network_split_policy.py network-split-dns-event-route-agent.py network-domain-proxy-deploy.py' ]]
for file in $scripts; do [[ -f "scripts/$file" ]]; done
for binary in $binaries; do [[ -f "engine/cmd/$binary/main.go" ]]; done
for file in $legacy; do [[ ! -e "scripts/$file" ]]; done
print 'PASS deployment installs the current Go programs and scripts and retires the Python files'

reload=$(sed -n '/^# reload-agent-begin/,/^# reload-agent-end/p' scripts/deploy-security-update.zsh)
reload=${reload//\/bin\/launchctl/mock_launchctl}
reload=${reload//\/bin\/sleep/:}
label=com.local.network-split-dns-event-route-agent
plist=/Library/LaunchDaemons/$label.plist
sbin=/usr/local/sbin
# Calls are recorded in a file because the verification runs in a subshell.
launch_calls="$work/launchctl-calls"
mock_launchctl() {
  print -r -- "$*" >> "$launch_calls"
  if [[ "$1" = print ]]; then
    (( agent_status == 0 )) && print "program = $sbin/network-split-dns-event-route-agent\nstate = running"
    return "$agent_status"
  fi
  return 0
}
: > "$launch_calls"
agent_status=1
agent_loaded=0
eval "$reload"
[[ "$(<$launch_calls)" = "print system/$label" && $agent_loaded = 0 ]]
print 'PASS unloaded event agent is not started'
: > "$launch_calls"
agent_status=0
eval "$reload"
expected="print system/$label
bootout system/$label
bootstrap system $plist
print system/$label"
[[ "$(<$launch_calls)" = "$expected" && $agent_loaded = 1 ]]
print 'PASS a loaded event agent is reloaded from its new definition and verified'
