#!/bin/zsh
set -eu
cd "${0:A:h}/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail() { print -u2 "FAIL $*"; exit 1; }

for script in network-remote-access-pf.sh deploy-remote-access.zsh; do /bin/zsh -n "$script"; done
plutil -lint -s com.local.network-remote-access.plist
print 'PASS scripts and launchd plist parse'

# Parsing with -n needs no administrator rights and loads nothing.
normalized=$(/sbin/pfctl -nv -a com.apple/400.RemoteAccess -f network-remote-access.pf.conf 2>/dev/null)
eval "$(sed -n -E '/^(ETH_IF|ETH_GW|ETH_IP)=/p' network-split-guard.sh)"
block="block drop in quick on $ETH_IF inet proto tcp from <remote_access_abusers> to $ETH_IP port = 22"
pass="pass in quick on $ETH_IF reply-to ($ETH_IF $ETH_GW) inet proto tcp from ! ${ETH_IP%.*}.0/24 to $ETH_IP port = 22 flags S/SA keep state"
[[ $normalized == *"$block"*"$pass"* ]] || fail 'rules must block overloaded sources before the reply-to pass'
[[ $normalized == *"overload <remote_access_abusers> flush global"* ]]
print 'PASS pf rules parse and follow the guard wired interface'

eval "$(sed -n -E '/^(label|anchor|loader|rules|sshd_dropin)=/p' deploy-remote-access.zsh)"
eval "$(sed -n -E '/^(ANCHOR|RULES_FILE|ABUSER_TABLE)=/p' network-remote-access-pf.sh)"
[[ $(/usr/libexec/PlistBuddy -c 'Print :Label' com.local.network-remote-access.plist) = $label ]]
[[ $(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' com.local.network-remote-access.plist) = $loader ]]
[[ $ANCHOR = $anchor && $RULES_FILE = $rules && $normalized == *"<$ABUSER_TABLE>"* ]]
print 'PASS launchd job, deploy script and loader agree on paths and anchor'

# sshd keeps the first value it reads, so the drop-in must sort before Apple's.
[[ ${sshd_dropin:t} < 100-macos.conf ]]
mkdir "$tmp/sshd_config.d"
sed "s/__REMOTE_USER__/$USER/" sshd-remote-access.conf > "$tmp/sshd_config.d/${sshd_dropin:t}"
cp /etc/ssh/sshd_config.d/100-macos.conf "$tmp/sshd_config.d/"
sed "s|/etc/ssh/sshd_config.d/\*|$tmp/sshd_config.d/*|" /etc/ssh/sshd_config > "$tmp/sshd_config"
ssh-keygen -q -t ed25519 -N '' -f "$tmp/hostkey"
# Newer sshd prints keywords in mixed case, so compare in lower case.
effective=$'\n'${(L)"$(/usr/sbin/sshd -T -f "$tmp/sshd_config" -h "$tmp/hostkey" \
  -C "user=$USER,host=remote.invalid,addr=203.0.113.1")"}$'\n'
for setting in 'passwordauthentication no' 'kbdinteractiveauthentication no' \
  'authenticationmethods publickey' 'permitrootlogin no' "allowusers ${(L)USER}"; do
  [[ $effective == *$'\n'"$setting"$'\n'* ]] || fail "sshd effective setting missing: $setting"
done
print 'PASS sshd accepts the drop-in and allows key-only login for one account'

for fn in log pf_enabled ensure_pf_enabled main_ruleset_hooks_anchor ensure_main_ruleset \
  rules_hash anchor_loaded ensure_anchor_rules expire_abusers main; do
  eval "$(sed -n "/^$fn() {/,/^}/p" network-remote-access-pf.sh)"
done
PFCTL=$tmp/pfctl
STOCK_PF_CONF=/etc/pf.conf
RULES_FILE=$tmp/rules.conf
ABUSER_EXPIRE_SECONDS=3600
STATE_DIR=$tmp/state
TOKEN_FILE=$STATE_DIR/pf-token
LOADED_HASH_FILE=$STATE_DIR/rules.sha256
LOG_FILE=$tmp/loader.log
pf=$tmp/pf
mkdir "$pf"
cp network-remote-access.pf.conf "$RULES_FILE"
# The stub keeps simulated pf state in files; reloading pf.conf empties the anchor.
cat > "$PFCTL" <<'EOF'
#!/bin/zsh
pf=${0:h}/pf
print -r -- "$*" >> "$pf/calls"
case "$*" in
  '-s info') [[ -e $pf/enabled ]] && print 'Status: Enabled for 0 days 00:00:01' || print 'Status: Disabled' ;;
  '-E') touch "$pf/enabled"; print 'pf enabled'; print 'Token : 4242' ;;
  '-s rules') [[ -e $pf/hooked ]] && print 'anchor "com.apple/*" all' ;;
  '-f /etc/pf.conf') touch "$pf/hooked"; rm -f "$pf/anchor" ;;
  '-a com.apple/400.RemoteAccess -s rules') [[ -e $pf/anchor ]] && cat "$pf/anchor" ;;
  '-a com.apple/400.RemoteAccess -f '*) [[ -e $pf/fail_load ]] && { print -u2 'syntax error'; exit 1; }; cp "${@[-1]}" "$pf/anchor" ;;
  '-a com.apple/400.RemoteAccess -t remote_access_abusers -T expire 3600') ;;
  *) print -u2 "unexpected pfctl $*"; exit 3 ;;
esac
exit 0
EOF
chmod +x "$PFCTL"
loads() { grep -cE -- '(^| )-f ' "$pf/calls" || true; }

main || fail 'cold start'
[[ $(grep -cx -- '-E' "$pf/calls") = 1 && $(<"$TOKEN_FILE") = 4242 ]]
grep -qx -- '-f /etc/pf.conf' "$pf/calls"
cmp -s "$pf/anchor" "$RULES_FILE"
[[ $(<"$LOADED_HASH_FILE") = $(shasum -a 256 "$RULES_FILE" | awk '{print $1}') ]]
grep -qx -- '-a com.apple/400.RemoteAccess -t remote_access_abusers -T expire 3600' "$pf/calls"
grep -q 'enabled pf token=4242' "$LOG_FILE"
grep -q 'restored main ruleset' "$LOG_FILE"
grep -q 'loaded anchor=com.apple/400.RemoteAccess' "$LOG_FILE"
print 'PASS cold start enables pf once, restores the hook and loads the anchor'

: > "$pf/calls"; : > "$LOG_FILE"
main || fail 'steady state'
[[ $(loads) = 0 && ! -s $LOG_FILE ]] || fail 'steady state must not reload or log'
if grep -qx -- '-E' "$pf/calls"; then fail 'steady state took another pf reference'; fi
print 'PASS steady state changes nothing and logs nothing'

rm "$pf/anchor"
main || fail 'emptied anchor'
cmp -s "$pf/anchor" "$RULES_FILE"
rm "$pf/hooked"; : > "$pf/calls"
main || fail 'lost hook'
grep -qx -- '-f /etc/pf.conf' "$pf/calls"
cmp -s "$pf/anchor" "$RULES_FILE"
print 'PASS an emptied anchor or a lost com.apple hook is repaired'

print '# edited' >> "$RULES_FILE"
main || fail 'changed rules'
cmp -s "$pf/anchor" "$RULES_FILE"
touch "$pf/fail_load"
print '# broken edit' >> "$RULES_FILE"
if main; then fail 'a rejected rules file must fail'; fi
grep -q 'failed to load anchor=com.apple/400.RemoteAccess: .*syntax error' "$LOG_FILE"
rm "$pf/fail_load"
print 'PASS changed rules are reloaded and a rejected load is reported'

rm -rf "$pf"/* "$STATE_DIR"
touch "$pf/enabled" "$pf/hooked"
main || fail 'pf enabled elsewhere'
[[ ! -e $TOKEN_FILE ]]
if grep -qx -- '-E' "$pf/calls"; then fail 'took a pf reference while pf was enabled'; fi
print 'PASS no pf reference is taken while pf is already enabled'
