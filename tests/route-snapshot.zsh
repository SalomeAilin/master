#!/bin/zsh
set -eu
cd "${0:A:h}/.."

# Extract only the functions under test; never execute the system guard.
eval "$(sed -n '/^check_route() {/,/^}/p' network-split-guard.sh | sed 's|/sbin/route|mock_route|g')"
eval "$(sed -n '/^add_domestic_host_route() {/,/^}/p' network-split-guard.sh | sed 's|/sbin/route|mock_route|g')"
trace=$(mktemp)
trap 'rm -f "$trace"' EXIT
log() { :; }
mock_route() {
  print -r -- "$*" >> "$trace"
  [[ "$*" = '-n get 192.0.2.1' ]] || return 99
  if [[ "$scenario" = wired ]]; then
    print 'gateway: 192.168.1.1\ninterface: en0'
  elif [[ "$scenario" = switching && $(wc -l < "$trace") -eq 1 ]]; then
    print 'gateway: 192.168.1.1\ninterface: en0'
  else
    print 'gateway: 172.20.10.1\ninterface: en1'
  fi
}

scenario=switching
gateway=sentinel
iface=sentinel
check_route 192.0.2.1 192.168.1.1 en0
[[ $(wc -l < "$trace") -eq 1 ]]
[[ "$gateway" = sentinel && "$iface" = sentinel ]]
print 'PASS single snapshot during transition; caller variables preserved'

scenario=wifi
if check_route 192.0.2.1 192.168.1.1 en0; then exit 1; fi
print 'PASS wrong route rejected'

scenario=wired
ETH_GW=192.168.1.1
ETH_IF=en0
add_domestic_host_route example.cn 192.0.2.1
[[ $(wc -l < "$trace") -eq 3 ]]
print 'PASS concurrent repair causes no route mutation'
