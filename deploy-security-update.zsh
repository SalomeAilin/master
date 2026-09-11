#!/bin/zsh
# Deploy the reviewed security patch without restarting DNS or flushing routes.
set -euo pipefail
[[ $EUID -eq 0 ]] || { print -u2 'Administrator authorization required'; exit 1; }
source_dir=${0:A:h}
files=(network_split_policy.py network-split-dns-event-route-agent.py network-split-dns-route-agent.py china-route.sh network-split-guard.sh)
for file in $files; do
  [[ -f "$source_dir/$file" ]] || exit 1
done
for file in china-route.sh network-split-guard.sh; do
  /bin/zsh -n "$source_dir/$file"
done
/usr/local/bin/python3 -B "$source_dir/tests/security_policy.py"
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
stage=$(/usr/bin/mktemp -d /usr/local/sbin/.network-split-stage.XXXXXXXX)
trap '/bin/rm -rf "$stage"' EXIT
for file in $files; do
  if [[ -e "/usr/local/sbin/$file" ]]; then
    /bin/cp -p "/usr/local/sbin/$file" "$backup/$file"
  fi
  /usr/bin/install -o root -g wheel -m 755 "$source_dir/$file" "$stage/$file"
done
/bin/chmod 644 "$stage/network_split_policy.py"
# Publish the dependency first; each replacement is an atomic rename.
for file in $files; do
  /bin/mv -f "$stage/$file" "/usr/local/sbin/$file"
done
/usr/sbin/chown nobody:wheel /var/log/dnsmasq-network-split-query.log
/bin/chmod 660 /var/log/dnsmasq-network-split-query.log
for label in com.local.network-split-dns-event-route-agent com.local.network-split-dns-route-agent; do
  if /bin/launchctl print "system/$label" >/dev/null 2>&1; then
    /bin/launchctl kickstart -k "system/$label"
  fi
done
for file in $files; do
  /usr/bin/cmp "$source_dir/$file" "/usr/local/sbin/$file"
done
print "Installed and compared all five files. Backup: $backup"
