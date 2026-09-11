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
