#!/bin/zsh
# Install, inspect or remove the SSH hardening drop-in used for remote access.
# Remote Login, the router port forward and client keys stay manual.
set -euo pipefail

source_dir=${0:A:h}
# Tests point REMOTE_ACCESS_SSH_DIR at a scratch copy of /etc/ssh.
ssh_dir=${REMOTE_ACCESS_SSH_DIR:-/etc/ssh}
sshd_main=$ssh_dir/sshd_config
sshd_dropin=$ssh_dir/sshd_config.d/050-remote-access.conf
template=$source_dir/../config/sshd-remote-access.conf
marker='# Installed as /etc/ssh/sshd_config.d/050-remote-access.conf by deploy-remote-access.zsh.'
required=(passwordauthentication:no kbdinteractiveauthentication:no
  authenticationmethods:publickey permitrootlogin:no)
remote_user=''
stage=''

cleanup() {
  # Command substitutions are subshells; only the main shell owns the stage.
  (( ZSH_SUBSHELL == 0 )) || return 0
  if [[ -n $stage ]]; then /bin/rm -rf "$stage"; stage=''; fi
}
# zsh skips the EXIT trap when errexit fires inside a function; ZERR covers that.
trap cleanup EXIT
trap cleanup ZERR

usage() {
  print -u2 "Usage: sudo zsh ${0:t} install|status|uninstall"
  exit 2
}

# A throwaway host key lets sshd evaluate the configuration even before Remote
# Login has generated the system host keys.
sshd_check() {
  local keydir result
  keydir=$(/usr/bin/mktemp -d -t remote-access-sshd)
  /usr/bin/ssh-keygen -q -t ed25519 -N '' -f "$keydir/key" >/dev/null
  if /usr/sbin/sshd "$@" -h "$keydir/key"; then result=0; else result=$?; fi
  /bin/rm -rf "$keydir"
  return $result
}

# Settings sshd would apply to a connection from outside, in lower case.
effective_settings() {
  local out
  out=$(sshd_check -T -f "$1" -C "user=$2,host=remote.invalid,addr=203.0.113.1") || return 1
  print -r -- "${(L)out}"
}

settings_ok() {
  local effective=$'\n'$1$'\n' item
  for item in $required "allowusers:${(L)2}"; do
    [[ $effective == *$'\n'"${item%%:*} ${item#*:}"$'\n'* ]] || return 1
  done
}

dropin_user() {
  /usr/bin/awk '$1 == "AllowUsers" {print $2; exit}' "$sshd_dropin"
}

# Evaluate the real main configuration and the other drop-ins with the
# candidate in place, inside the stage, before anything goes live.
validate_candidate() {
  local check=$stage/check file
  /bin/mkdir -p "$check/sshd_config.d"
  for file in "$ssh_dir"/sshd_config.d/*(N); do
    [[ $file = "$sshd_dropin" ]] || /bin/cp -p "$file" "$check/sshd_config.d/"
  done
  /bin/cp "$1" "$check/sshd_config.d/${sshd_dropin:t}"
  /usr/bin/sed "s|^Include $ssh_dir/sshd_config.d/\*\$|Include $check/sshd_config.d/*|" "$sshd_main" > "$check/sshd_config"
  if ! /usr/bin/grep -Fqx "Include $check/sshd_config.d/*" "$check/sshd_config"; then
    print -u2 "$sshd_main no longer includes $ssh_dir/sshd_config.d/*"
    return 1
  fi
  sshd_check -t -f "$check/sshd_config" || return 1
  if ! settings_ok "$(effective_settings "$check/sshd_config" "$remote_user")" "$remote_user"; then
    print -u2 'Another sshd setting overrides the drop-in'
    return 1
  fi
}

# sshd's StrictModes ignores keys when these are writable by group or others.
strict_ok() {
  local mode owner
  read -r mode owner <<< "$(/usr/bin/stat -f '%Lp %Su' "$1")"
  [[ $owner = "$2" || $owner = root ]] && (( (8#$mode & 8#022) == 0 ))
}

show_status() {
  local user=$remote_user effective home keys path pubkeys
  if [[ ! -f $sshd_dropin ]]; then
    print 'drop-in: not installed'
  elif [[ $(/usr/bin/head -n 1 "$sshd_dropin") = "$marker" ]]; then
    [[ -n $user ]] || user=$(dropin_user)
    print "drop-in: $sshd_dropin (AllowUsers $(dropin_user))"
  else
    print "drop-in: $sshd_dropin exists but was not installed by ${0:t}"
  fi
  [[ -n $user ]] || user=${REMOTE_USER:-${SUDO_USER:-}}
  if /bin/launchctl print system/com.openssh.sshd >/dev/null 2>&1; then
    print 'remote login: on'
  else
    print 'remote login: off'
  fi
  pubkeys=("$ssh_dir"/ssh_host_*_key.pub(N))
  if (( ${#pubkeys} )); then
    for path in $pubkeys; do print "host key: $(/usr/bin/ssh-keygen -lf "$path")"; done
  else
    print 'host keys: not generated yet (Remote Login creates them on first start)'
  fi
  [[ -n $user ]] || return 0
  if effective=$(effective_settings "$sshd_main" "$user"); then
    if settings_ok "$effective" "$user"; then
      print "sshd: key-only login for $user"
    else
      print 'sshd: WARNING the effective settings are weaker than the drop-in'
    fi
    print -r -- "$effective" |
      /usr/bin/grep -E '^(passwordauthentication|kbdinteractiveauthentication|authenticationmethods|permitrootlogin|allowusers) ' |
      /usr/bin/sed 's/^/  /' || true
  else
    print 'sshd: WARNING sshd -T failed; the configuration does not load'
  fi
  home=$(/usr/bin/dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '{print $2}') || home=''
  keys=$home/.ssh/authorized_keys
  if [[ ! -f $keys ]]; then
    print "authorized keys: none yet ($keys is missing)"
  elif strict_ok "$home" "$user" && strict_ok "$home/.ssh" "$user" && strict_ok "$keys" "$user"; then
    print "authorized keys: $(/usr/bin/grep -cvE '^[[:space:]]*(#|$)' "$keys" || true) in $keys"
  else
    print "authorized keys: WARNING $keys or a parent is writable by others; sshd will ignore it"
  fi
  if /usr/sbin/dseditgroup -o checkmember -m "$user" com.apple.access_ssh >/dev/null 2>&1; then
    print "Remote Login access list: $user allowed"
  else
    print "Remote Login access list: check that $user is allowed in System Settings"
  fi
}

install_dropin() {
  local previous='' existing=''
  remote_user=${REMOTE_USER:-${SUDO_USER:-}}
  if [[ -z $remote_user || $remote_user = root || ! $remote_user =~ '^[A-Za-z0-9._-]+$' ]]; then
    print -u2 'Run with sudo from the account that will log in remotely, or set REMOTE_USER'
    exit 1
  fi
  /usr/bin/id "$remote_user" >/dev/null
  [[ -f $template ]] || { print -u2 "Missing $template; nothing installed"; exit 1; }
  # A reinstall from another admin account must not silently hand SSH access over.
  if [[ -f $sshd_dropin ]]; then
    existing=$(dropin_user)
    if [[ -n $existing && $existing != "$remote_user" && -z ${REMOTE_USER:-} ]]; then
      print -u2 "$sshd_dropin allows $existing; rerun with REMOTE_USER=$remote_user to change that"
      exit 1
    fi
  fi
  print "Remote login account: $remote_user"

  umask 022
  # Stage beside the drop-in directory, not inside it, so a concurrent sshd
  # never includes a half-written file; the final mv is an atomic rename.
  stage=$(/usr/bin/mktemp -d "$ssh_dir/.remote-access-stage.XXXXXXXX")
  /usr/bin/sed "s/__REMOTE_USER__/$remote_user/" "$template" > "$stage/dropin"
  /bin/chmod 644 "$stage/dropin"
  if (( EUID == 0 )); then /usr/sbin/chown root:wheel "$stage/dropin"; fi
  if ! validate_candidate "$stage/dropin"; then
    print -u2 'Nothing installed'
    exit 1
  fi
  if [[ -e $sshd_dropin ]]; then
    previous=$stage/previous
    /bin/cp -p "$sshd_dropin" "$previous"
  fi
  /bin/mv -f "$stage/dropin" "$sshd_dropin"
  # Check the live configuration too, in case it changed after validation.
  if ! settings_ok "$(effective_settings "$sshd_main" "$remote_user")" "$remote_user"; then
    if [[ -n $previous ]]; then /bin/mv -f "$previous" "$sshd_dropin"; else /bin/rm -f "$sshd_dropin"; fi
    print -u2 'Live sshd check failed; the previous SSH configuration is back in place'
    exit 1
  fi
  show_status
}

uninstall_dropin() {
  if [[ ! -e $sshd_dropin ]]; then
    print "Nothing to remove: $sshd_dropin is not installed"
    return 0
  fi
  if [[ $(/usr/bin/head -n 1 "$sshd_dropin") != "$marker" ]]; then
    print -u2 "$sshd_dropin was not installed by ${0:t}; left in place"
    exit 1
  fi
  /bin/rm -f "$sshd_dropin"
  sshd_check -t -f "$sshd_main"
  print "Removed $sshd_dropin."
  print 'If Remote Login stays on, sshd accepts password logins again; turn it and the'
  print 'router port forward off if remote access is no longer needed.'
}

(( $# == 1 )) || usage
if [[ $ssh_dir = /etc/ssh && $EUID -ne 0 ]]; then
  print -u2 'Administrator authorization required'
  exit 1
fi
case $1 in
  install) install_dropin ;;
  status) show_status ;;
  uninstall) uninstall_dropin ;;
  *) usage ;;
esac
