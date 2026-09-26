#!/bin/zsh

set -u

PFCTL="/sbin/pfctl"
STOCK_PF_CONF="/etc/pf.conf"
ANCHOR="com.apple/400.RemoteAccess"
RULES_FILE="/usr/local/etc/network-remote-access.pf.conf"
ABUSER_TABLE="remote_access_abusers"
ABUSER_EXPIRE_SECONDS=3600
STATE_DIR="/var/db/network-remote-access"
TOKEN_FILE="$STATE_DIR/pf-token"
LOADED_HASH_FILE="$STATE_DIR/rules.sha256"
LOG_FILE="/var/log/network-remote-access.log"

log() {
  /bin/echo "$(/bin/date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
}

pf_enabled() {
  "$PFCTL" -s info 2>/dev/null | /usr/bin/grep -q '^Status: Enabled'
}

# Take a reference only while pf is off, so other pf users keep their own.
ensure_pf_enabled() {
  local output token
  pf_enabled && return 0
  output="$("$PFCTL" -E 2>&1)"
  token="$(print -r -- "$output" | /usr/bin/awk '/Token/ {print $NF; exit}')"
  if ! pf_enabled; then
    log "failed to enable pf: ${output//$'\n'/ }"
    return 1
  fi
  [[ -n "$token" ]] && print -r -- "$token" > "$TOKEN_FILE"
  log "enabled pf token=${token:-none}"
}

main_ruleset_hooks_anchor() {
  "$PFCTL" -s rules 2>/dev/null | /usr/bin/grep -Fq 'anchor "com.apple/*"'
}

ensure_main_ruleset() {
  local output
  main_ruleset_hooks_anchor && return 0
  if output="$("$PFCTL" -f "$STOCK_PF_CONF" 2>&1)" && main_ruleset_hooks_anchor; then
    log "restored main ruleset from $STOCK_PF_CONF"
    return 0
  fi
  log "failed to restore main ruleset: ${output//$'\n'/ }"
  return 1
}

rules_hash() {
  /usr/bin/shasum -a 256 "$RULES_FILE" 2>/dev/null | /usr/bin/awk '{print $1}'
}

anchor_loaded() {
  [[ -n "$("$PFCTL" -a "$ANCHOR" -s rules 2>/dev/null)" ]]
}

# Reload when the file changed or the anchor was emptied, e.g. by a pf.conf reload.
ensure_anchor_rules() {
  local current loaded='' output
  current="$(rules_hash)"
  if [[ -z "$current" ]]; then
    log "missing rules file $RULES_FILE"
    return 1
  fi
  [[ -r "$LOADED_HASH_FILE" ]] && loaded="$(<"$LOADED_HASH_FILE")"
  if [[ "$current" = "$loaded" ]] && anchor_loaded; then
    return 0
  fi
  if output="$("$PFCTL" -a "$ANCHOR" -f "$RULES_FILE" 2>&1)" && anchor_loaded; then
    print -r -- "$current" > "$LOADED_HASH_FILE"
    log "loaded anchor=$ANCHOR rules_sha256=$current"
    return 0
  fi
  log "failed to load anchor=$ANCHOR: ${output//$'\n'/ }"
  return 1
}

expire_abusers() {
  "$PFCTL" -a "$ANCHOR" -t "$ABUSER_TABLE" -T expire "$ABUSER_EXPIRE_SECONDS" >/dev/null 2>&1 || true
}

main() {
  local result=0
  /bin/mkdir -p "$STATE_DIR" || return 1
  ensure_pf_enabled || result=1
  ensure_main_ruleset || result=1
  ensure_anchor_rules || result=1
  expire_abusers
  return $result
}

# The log stays world-readable so status checks need no administrator rights.
umask 022
main
exit $?
