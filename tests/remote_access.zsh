#!/bin/zsh
set -eu
cd "${0:A:h}/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail() { print -u2 "FAIL $*"; exit 1; }

/bin/zsh -n scripts/deploy-remote-access.zsh
eval "$(sed -n -E '/^(ssh_dir|sshd_dropin|marker)=/p' scripts/deploy-remote-access.zsh)"
[[ $(head -n 1 config/sshd-remote-access.conf) = "$marker" ]] || fail 'template must start with the marker uninstall checks'
# sshd keeps the first value it reads, so the drop-in must sort before Apple's.
[[ ${sshd_dropin:h} = /etc/ssh/sshd_config.d && ${sshd_dropin:t} < 100-macos.conf ]]
grep -qx 'Include /etc/ssh/sshd_config.d/\*' /etc/ssh/sshd_config
print 'PASS drop-in carries the marker, is included and precedes 100-macos.conf'

# The native routing tests verify gateway reject routes for scoped SSH replies.

if env -u REMOTE_ACCESS_SSH_DIR zsh scripts/deploy-remote-access.zsh status >/dev/null 2>&1; then
  fail 'the real /etc/ssh must require administrator rights'
fi
print 'PASS the real /etc/ssh requires administrator rights'

# A scratch copy of /etc/ssh: the real main file with its Include redirected,
# plus the real drop-ins other than ours.
tree=$tmp/etc-ssh
mkdir -p "$tree/sshd_config.d"
for file in /etc/ssh/sshd_config.d/*(N); do
  [[ ${file:t} = ${sshd_dropin:t} ]] || cp "$file" "$tree/sshd_config.d/"
done
sed "s|^Include /etc/ssh/sshd_config.d/\*\$|Include $tree/sshd_config.d/*|" /etc/ssh/sshd_config > "$tree/sshd_config"
grep -Fqx "Include $tree/sshd_config.d/*" "$tree/sshd_config" || fail 'could not redirect the Include line'
dropin=$tree/sshd_config.d/${sshd_dropin:t}
run() { env -u SUDO_USER -u REMOTE_USER REMOTE_ACCESS_SSH_DIR="$tree" "$@"; }
ssh-keygen -q -t ed25519 -N '' -f "$tmp/hostkey"
# Newer sshd prints keywords in mixed case, so compare in lower case.
effective() {
  print -r -- $'\n'${(L)"$(/usr/sbin/sshd -T -f "$tree/sshd_config" -h "$tmp/hostkey" \
    -C "user=$1,host=remote.invalid,addr=203.0.113.1")"}$'\n'
}

if run zsh scripts/deploy-remote-access.zsh >/dev/null 2>&1; then fail 'no action must not install'; else code=$?; fi
[[ $code = 2 && ! -e $dropin ]]
print 'PASS running without an action prints usage and changes nothing'

out=$(run REMOTE_USER="$USER" zsh scripts/deploy-remote-access.zsh install 2>&1) || fail "install: $out"
[[ $(head -n 1 "$dropin") = "$marker" ]] && grep -qx "AllowUsers $USER" "$dropin"
[[ -z $(print -l "$tree"/.remote-access-stage.*(N)) ]] || fail 'stage directory left behind'
eff=$(effective "$USER")
for setting in 'passwordauthentication no' 'kbdinteractiveauthentication no' \
  'authenticationmethods publickey' 'permitrootlogin no' "allowusers ${(L)USER}"; do
  [[ $eff == *$'\n'"$setting"$'\n'* ]] || fail "effective setting missing after install: $setting"
done
[[ $out == *"sshd: key-only login for $USER"* ]] || fail "install status: $out"
run REMOTE_USER="$USER" zsh scripts/deploy-remote-access.zsh install >/dev/null 2>&1 || fail 'reinstall for the same account'
print 'PASS install activates key-only login for one account and cleans its stage'

before=$(shasum "$dropin")
if run SUDO_USER=daemon zsh scripts/deploy-remote-access.zsh install >/dev/null 2>&1; then
  fail 'a reinstall from another sudo account changed AllowUsers'
fi
[[ $(shasum "$dropin") = "$before" ]]
print 'PASS a reinstall from another account cannot silently change AllowUsers'

print 'AuthenticationMethods any' > "$tree/sshd_config.d/010-weaker.conf"
if run REMOTE_USER="$USER" zsh scripts/deploy-remote-access.zsh install >/dev/null 2>&1; then
  fail 'install accepted an earlier drop-in that overrides it'
fi
[[ $(shasum "$dropin") = "$before" ]]
out=$(run REMOTE_USER="$USER" zsh scripts/deploy-remote-access.zsh status 2>&1)
[[ $out == *'WARNING the effective settings are weaker'* ]] || fail "status must flag the override: $out"
rm "$tree/sshd_config.d/010-weaker.conf"
print 'PASS an earlier drop-in that weakens login blocks install and shows in status'

cp "$dropin" "$tmp/ours"
print '# not ours' > "$dropin"
if run zsh scripts/deploy-remote-access.zsh uninstall >/dev/null 2>&1; then fail 'uninstall removed a foreign file'; fi
[[ -f $dropin ]]
cp "$tmp/ours" "$dropin"
run zsh scripts/deploy-remote-access.zsh uninstall >/dev/null 2>&1 || fail 'uninstall'
[[ ! -e $dropin ]]
print 'PASS uninstall removes only its own drop-in'
