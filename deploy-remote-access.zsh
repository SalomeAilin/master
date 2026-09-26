#!/bin/zsh
# Install, inspect or remove remote-access reply routing and the SSH hardening
# drop-in. Remote Login, the router port forward and client keys stay manual.
set -euo pipefail
[[ $EUID -eq 0 ]] || { print -u2 'Administrator authorization required'; exit 1; }

action=${1:-install}
source_dir=${0:A:h}
label=com.local.network-remote-access
anchor=com.apple/400.RemoteAccess
loader=/usr/local/sbin/network-remote-access-pf.sh
rules=/usr/local/etc/network-remote-access.pf.conf
plist=/Library/LaunchDaemons/$label.plist
sshd_dropin=/etc/ssh/sshd_config.d/050-remote-access.conf
state_dir=/var/db/network-remote-access
log_file=/var/log/network-remote-access.log
remote_user=${REMOTE_USER:-${SUDO_USER:-}}
stage=''
trap 'if [[ -n $stage ]]; then /bin/rm -rf "$stage"; fi' EXIT

# A throwaway host key lets sshd check the configuration even before Remote
# Login has generated the system host keys.
sshd_check() {
  local keydir result
  keydir=$(/usr/bin/mktemp -d /var/db/network-remote-access-sshd.XXXXXXXX)
  /usr/bin/ssh-keygen -q -t ed25519 -N '' -f "$keydir/key" >/dev/null
  if /usr/sbin/sshd "$@" -h "$keydir/key"; then result=0; else result=$?; fi
  /bin/rm -rf "$keydir"
  return $result
}

show_status() {
  print "pf: $(/sbin/pfctl -s info 2>/dev/null | /usr/bin/awk '/^Status:/ {print $2; exit}')"
  print "anchor $anchor:"
  /sbin/pfctl -a "$anchor" -s rules 2>/dev/null | /usr/bin/sed 's/^/  /' || true
  print "blocked sources: $(/sbin/pfctl -a "$anchor" -t remote_access_abusers -T show 2>/dev/null | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
  if /bin/launchctl print "system/$label" >/dev/null 2>&1; then
    print "launchd: $label loaded"
  else
    print "launchd: $label not loaded"
  fi
  print "sshd settings for an outside connection as ${remote_user:-nobody}:"
  sshd_check -T -C "user=${remote_user:-nobody},host=remote.invalid,addr=203.0.113.1" 2>/dev/null |
    /usr/bin/grep -iE '^(passwordauthentication|kbdinteractiveauthentication|authenticationmethods|permitrootlogin|allowusers) ' |
    /usr/bin/sed 's/^/  /' || true
  print "recent log:"
  /usr/bin/tail -n 5 "$log_file" 2>/dev/null | /usr/bin/sed 's/^/  /' || true
}

install_all() {
  local file previous='' attempt
  if [[ -z "$remote_user" || "$remote_user" = root || ! "$remote_user" =~ '^[A-Za-z0-9._-]+$' ]]; then
    print -u2 'Run with sudo from the account that will log in remotely, or set REMOTE_USER'
    exit 1
  fi
  /usr/bin/id "$remote_user" >/dev/null
  for file in network-remote-access-pf.sh network-remote-access.pf.conf "$label.plist" sshd-remote-access.conf; do
    [[ -f "$source_dir/$file" ]] || { print -u2 "Missing $source_dir/$file; nothing installed"; exit 1; }
  done
  /bin/zsh -n "$source_dir/network-remote-access-pf.sh"
  if ! /sbin/pfctl -n -a "$anchor" -f "$source_dir/network-remote-access.pf.conf" 2>/dev/null; then
    print -u2 'pf rejected network-remote-access.pf.conf; nothing installed'
    exit 1
  fi
  /usr/bin/plutil -lint -s "$source_dir/$label.plist"

  umask 022
  # Stage on the same volume so each replacement below is an atomic rename.
  stage=$(/usr/bin/mktemp -d /usr/local/.network-remote-access-stage.XXXXXXXX)
  /usr/bin/sed "s/__REMOTE_USER__/$remote_user/" "$source_dir/sshd-remote-access.conf" > "$stage/sshd.src"
  /usr/bin/install -o root -g wheel -m 644 "$stage/sshd.src" "$stage/sshd"
  /usr/bin/install -o root -g wheel -m 644 "$source_dir/network-remote-access.pf.conf" "$stage/rules"
  /usr/bin/install -o root -g wheel -m 755 "$source_dir/network-remote-access-pf.sh" "$stage/loader"
  /usr/bin/install -o root -g wheel -m 644 "$source_dir/$label.plist" "$stage/plist"

  # SSH hardening goes first and must pass sshd's own check before anything
  # that makes the port reachable from outside is activated.
  if [[ -e "$sshd_dropin" ]]; then
    previous="$stage/sshd.previous"
    /bin/cp -p "$sshd_dropin" "$previous"
  fi
  /bin/mv -f "$stage/sshd" "$sshd_dropin"
  if ! sshd_check -t; then
    if [[ -n "$previous" ]]; then /bin/mv -f "$previous" "$sshd_dropin"; else /bin/rm -f "$sshd_dropin"; fi
    print -u2 'sshd rejected the drop-in; previous SSH configuration restored, nothing else installed'
    exit 1
  fi

  /bin/mkdir -p /usr/local/etc /usr/local/sbin
  /bin/mv -f "$stage/rules" "$rules"
  /bin/mv -f "$stage/loader" "$loader"
  /bin/mv -f "$stage/plist" "$plist"
  if /bin/launchctl print "system/$label" >/dev/null 2>&1; then
    /bin/launchctl kickstart -k "system/$label"
  else
    /bin/launchctl bootstrap system "$plist"
  fi
  for attempt in {1..10}; do
    /sbin/pfctl -a "$anchor" -s rules 2>/dev/null | /usr/bin/grep -q 'reply-to' && break
    /bin/sleep 1
  done
  show_status
  if ! /sbin/pfctl -a "$anchor" -s rules 2>/dev/null | /usr/bin/grep -q 'reply-to'; then
    print -u2 "Remote-access anchor did not load; see $log_file"
    exit 1
  fi
}

uninstall_all() {
  if /bin/launchctl print "system/$label" >/dev/null 2>&1; then
    /bin/launchctl bootout "system/$label" || true
  fi
  /sbin/pfctl -a "$anchor" -F all >/dev/null 2>&1 || true
  # Release only the pf reference the loader took; other pf users keep theirs.
  if [[ -r "$state_dir/pf-token" ]]; then
    /sbin/pfctl -X "$(<"$state_dir/pf-token")" >/dev/null 2>&1 || true
  fi
  /bin/rm -f "$plist" "$loader" "$rules" "$sshd_dropin"
  /bin/rm -rf "$state_dir"
  print 'Removed the remote-access anchor, loader, launchd job and SSH drop-in.'
  print 'Remote Login and the router port forward are unchanged. If Remote Login stays on,'
  print "sshd now accepts password logins again; turn it and the port forward off if unused."
}

case $action in
  install) install_all ;;
  status) show_status ;;
  uninstall) uninstall_all ;;
  *) print -u2 "Usage: sudo zsh ${0:t} [install|status|uninstall]"; exit 2 ;;
esac
