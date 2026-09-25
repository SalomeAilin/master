#!/bin/zsh
set -eu
cd "${0:A:h}/.."

# Exercise the real policy with repository address lists, never the live router.
policy_check() {
  python3 -B -c 'import sys; import network_split_policy as p; p.POLICY_FILES=("china_ip_list.txt", "domestic_extra_routes.txt"); sys.exit(0 if p.allowed(sys.argv[1]) else 1)' "$1"
}
eval "$(sed -n '/^add_domestic_host_route() {/,/^}/p' network-split-guard.sh | sed 's|/usr/local/bin/python3 /usr/local/sbin/network_split_policy.py|policy_check|g; s|/sbin/route|forbidden_route|g')"
forbidden_route() { print 'FAIL route reached' >&2; return 99; }
# Return value alone is insufficient: record any route call in a temporary file.
trace=$(mktemp)
trap 'rm -f "$trace"' EXIT
forbidden_route() { print called >> "$trace"; return 99; }
for ip in 8.8.8.8 127.0.0.1 999.1.1.1; do
  add_domestic_host_route evil.cn "$ip"
done
[[ ! -s "$trace" ]]
print 'PASS shell sink rejects foreign and malformed answers before route access'

for script in china-route.sh; do
  # Check the actual DNS pipeline routes its output through the shared policy.
  body=$(sed -n '/^ipv4s_for_domain() {/,/^}/p' "$script")
  [[ "$body" = *'/usr/local/sbin/network_split_policy.py'* ]]
done
eval "$(sed -n '/^check_domestic_domain() {/,/^}/p' network-split-guard.sh | sed 's|/usr/local/bin/python3 /usr/local/sbin/network_split_policy.py|policy_check|g')"
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

# Exercise deployment selection and restart handling without running installation.
selection=$(sed -n '/^files=(/p' deploy-security-update.zsh)
eval "$selection"
expected_files=(network_split_policy.py network-split-dns-event-route-agent.py china-route.sh network-split-guard.sh)
[[ "${(j: :)files}" = "${(j: :)expected_files}" ]]
for file in $files; do [[ -f "$file" ]]; done
print 'PASS deployment selects only the four current source files'

restart=$(sed -n '/^label=/,/^fi$/p' deploy-security-update.zsh)
restart=${restart//\/bin\/launchctl/mock_launchctl}
mock_launchctl() {
  launch_calls+=("$*")
  if [[ "$1" = print ]]; then return "$agent_status"; fi
  return 0
}
launch_calls=()
agent_status=1
eval "$restart"
[[ ${#launch_calls} = 1 && "$launch_calls[1]" = 'print system/com.local.network-split-dns-event-route-agent' ]]
print 'PASS unloaded event agent is not started'
launch_calls=()
agent_status=0
eval "$restart"
[[ ${#launch_calls} = 2 && "$launch_calls[1]" = 'print system/com.local.network-split-dns-event-route-agent' && "$launch_calls[2]" = 'kickstart -k system/com.local.network-split-dns-event-route-agent' ]]
print 'PASS only the loaded current event agent is restarted'
