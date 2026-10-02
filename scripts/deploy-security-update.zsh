#!/bin/zsh
# Install the route guards, the Go address policy and DNS event agent, and the
# proxy deployment tool from this script's staging directory, without
# restarting DNS or flushing routes. Stage the files first; see README.md.
set -euo pipefail
[[ $EUID -eq 0 ]] || { print -u2 'Administrator authorization required'; exit 1; }
stage=${0:A:h}
sbin=/usr/local/sbin
label=com.local.network-split-dns-event-route-agent
plist=/Library/LaunchDaemons/$label.plist
binaries=(network-split-policy network-split-dns-event-route-agent network-domain-proxy-deploy)
scripts=(china-route.sh network-split-guard.sh)
legacy=(network_split_policy.py network-split-dns-event-route-agent.py network-domain-proxy-deploy.py)
for file in $binaries $scripts $label.plist; do
  [[ -f "$stage/$file" && ! -L "$stage/$file" ]] || { print -u2 "Missing staged file: $file"; exit 1; }
done
for file in $scripts; do
  /bin/zsh -n "$stage/$file"
done
/usr/bin/plutil -lint "$stage/$label.plist" >/dev/null
# The staged policy must accept a known domestic resolver and refuse a foreign one.
"$stage/network-split-policy" 223.5.5.5
if "$stage/network-split-policy" 8.8.8.8; then
  print -u2 'Staged policy authorized a foreign address; nothing installed'
  exit 1
fi
"$stage/network-split-dns-event-route-agent" -check >/dev/null
# Do not replace a script while a route rebuild is in progress.
for attempt in {1..60}; do
  if ! /usr/bin/pgrep -f '/usr/local/sbin/(china-route|network-split-guard)\.sh' >/dev/null; then
    break
  fi
  /bin/sleep 1
done
if /usr/bin/pgrep -f '/usr/local/sbin/(china-route|network-split-guard)\.sh' >/dev/null; then
  print -u2 'Route repair still active; nothing installed'
  exit 1
fi
umask 077
backup=$(/usr/bin/mktemp -d /var/db/network-split-backup.XXXXXXXX)
for file in $binaries $scripts $legacy; do
  if [[ -e "$sbin/$file" ]]; then
    /bin/cp -p "$sbin/$file" "$backup/$file"
  fi
done
if [[ -e "$plist" ]]; then
  /bin/cp -p "$plist" "$backup/$label.plist"
fi
work=$(/usr/bin/mktemp -d "$sbin/.network-split-stage.XXXXXXXX")
plist_new="/Library/LaunchDaemons/.$label.plist.new"
published=0
agent_loaded=0
# Runs at top level only: a failure inside a function would skip this trap.
finish() {
  local code=$?
  setopt localoptions no_err_exit no_err_return
  /bin/rm -rf "$work" "$plist_new"
  if (( code != 0 && published )); then
    print -u2 "Installation failed; restoring the previous files from $backup"
    for file in $binaries $scripts $legacy; do
      if [[ -e "$backup/$file" ]]; then
        /bin/cp -p "$backup/$file" "$sbin/$file"
      else
        /bin/rm -f "$sbin/$file"
      fi
    done
    if [[ -e "$backup/$label.plist" ]]; then
      /bin/cp -p "$backup/$label.plist" "$plist"
    fi
    if (( agent_loaded )); then
      /bin/launchctl bootout "system/$label" >/dev/null 2>&1
      /bin/launchctl bootstrap system "$plist"
    fi
  fi
}
trap finish EXIT
for file in $binaries $scripts; do
  /usr/bin/install -o root -g wheel -m 755 "$stage/$file" "$work/$file"
done
/usr/bin/install -o root -g wheel -m 644 "$stage/$label.plist" "$plist_new"
published=1
# Publish the policy before the guards that call it; each replacement is an atomic rename.
/bin/mv -f "$work/network-split-policy" "$sbin/network-split-policy"
for file in $scripts network-split-dns-event-route-agent network-domain-proxy-deploy; do
  /bin/mv -f "$work/$file" "$sbin/$file"
done
/bin/mv -f "$plist_new" "$plist"
/usr/sbin/chown nobody:wheel /var/log/dnsmasq-network-split-query.log
/bin/chmod 660 /var/log/dnsmasq-network-split-query.log
# reload-agent-begin: the new definition needs a fresh bootstrap; an unloaded agent stays unloaded.
if /bin/launchctl print "system/$label" >/dev/null 2>&1; then
  agent_loaded=1
  /bin/launchctl bootout "system/$label"
  for attempt in {1..10}; do
    if /bin/launchctl bootstrap system "$plist"; then
      break
    fi
    /bin/sleep 0.5
  done
  for attempt in {1..50}; do
    details=$(/bin/launchctl print "system/$label" 2>/dev/null || true)
    if [[ "$details" = *"program = $sbin/network-split-dns-event-route-agent"* && "$details" = *'state = running'* ]]; then
      break
    fi
    if (( attempt == 50 )); then
      print -u2 'Event agent is not running the new program'
      exit 1
    fi
    /bin/sleep 0.1
  done
fi
# reload-agent-end
for file in $legacy; do
  /bin/rm -f "$sbin/$file"
done
for file in $binaries $scripts; do
  /usr/bin/cmp "$stage/$file" "$sbin/$file"
done
/usr/bin/cmp "$stage/$label.plist" "$plist"
published=0
print "Installed ${#binaries} programs, ${#scripts} scripts and the agent definition; removed legacy Python files. Backup: $backup"
