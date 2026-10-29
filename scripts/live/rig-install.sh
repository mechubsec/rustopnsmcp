#!/usr/bin/env bash
# Minimal manual install of rustopnsmcp into a P3 test rig. Superseded by packaging/lxc/install.sh once P2 lands.
#   rig-install.sh <rig> <binary>
# Needs RIG_PVE (node ssh alias), LAB_HOST (dev host ssh alias), LAB_ENV_FILE (path on the dev host).
# Credentials stream dev host -> rig through pipes: never an argument, a variable, a file here, or output.
set -euo pipefail
set +x
here=$(cd "$(dirname "$0")" && pwd); root=$(git -C "$here" rev-parse --show-toplevel)
# shellcheck source=scripts/live/rig-lib.sh
. "$here/rig-lib.sh"
rig="${1:?rig}"; binary="${2:?binary}"
: "${RIG_PVE:?}" "${LAB_HOST:?}" "${LAB_ENV_FILE:?}"
require_match RIG_PVE "$RIG_PVE" "$alias_re"
require_match LAB_HOST "$LAB_HOST" "$alias_re"
require_match LAB_ENV_FILE "$LAB_ENV_FILE" "$abs_path_re"
vmid=$("$here/rig-ctl.sh" vmid "$rig")
# Ids get recycled: before every operation on the rig, prove the name still resolves to the same disposable guest.
same_guest() {
  [ "$("$here/rig-ctl.sh" vmid "$rig" 2>/dev/null)" = "$vmid" ] || { echo "$rig no longer resolves to the same guest; refusing" >&2; exit 1; }
}
inrig() { same_guest; ssh -n "$RIG_PVE" pct exec "$vmid" -- "$@"; }
ip=$(inrig hostname -I | awk '{print $1}')
[[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "$rig has no IPv4 address" >&2; exit 1; }
mode=""; [ "$rig" = test-labmode-opns ] && mode="--lab-mode"
emit() { ssh "$LAB_HOST" env "LAB_ENV_FILE=$LAB_ENV_FILE" bash -s -- "$1" < "$here/emit-credential.sh"; }
tmp=$(ssh -n "$RIG_PVE" mktemp -d); local_tmp=$(mktemp -d)
require_match "node temp dir" "$tmp" "$abs_path_re"
trap 'ssh -n "$RIG_PVE" rm -rf "$tmp"; rm -rf "$local_tmp"' EXIT
sed -e "s/@RIG_IP@/$ip/g" -e "s/@RIG_NAME@/$rig/g" -e "s/@LAB_MODE@/$mode/" "$here/rig-override.conf.in" > "$local_tmp/override.conf"
cp "$binary" "$local_tmp/rustopnsmcp"
scp -q "$local_tmp/rustopnsmcp" "$root/packaging/systemd/rustopnsmcp.service" "$root/packaging/systemd/rustopnsmcp.sysusers" \
  "$root/packaging/systemd/rustopnsmcp.tmpfiles" "$local_tmp/override.conf" "$RIG_PVE:$tmp/"
# shellcheck disable=SC2029 # vmid and paths are expanded locally on purpose
push() { same_guest; ssh -n "$RIG_PVE" pct push "$vmid" "$tmp/$1" "$2" --perms "$3"; }
inrig mkdir -p /etc/systemd/system/rustopnsmcp.service.d
push rustopnsmcp /usr/local/bin/rustopnsmcp 0755
push rustopnsmcp.service /etc/systemd/system/rustopnsmcp.service 0644
push override.conf /etc/systemd/system/rustopnsmcp.service.d/override.conf 0644
push rustopnsmcp.sysusers /usr/lib/sysusers.d/rustopnsmcp.conf 0644
push rustopnsmcp.tmpfiles /usr/lib/tmpfiles.d/rustopnsmcp.conf 0644
inrig systemd-sysusers
inrig systemd-tmpfiles --create
inrig install -d -m 0700 -o rustopnsmcp -g rustopnsmcp /etc/rustopnsmcp/credentials
# umask 077 and the stream: the file is created 0600; ownership is fixed afterwards. The guest check runs
# before the remote command starts, so nothing is sent to a recycled id. This is the only ssh to the node that
# reads stdin (the credential stream); every other one takes -n, or it would swallow the stream first.
# shellcheck disable=SC2029 # vmid and the path are expanded locally on purpose
put() { same_guest </dev/null; ssh "$RIG_PVE" "pct exec $vmid -- sh -c 'umask 077; cat > $1'"; inrig chown rustopnsmcp:rustopnsmcp "$1"; }
emit key    | put /etc/rustopnsmcp/credentials/api-key
emit secret | put /etc/rustopnsmcp/credentials/api-secret
emit ca     | put /etc/rustopnsmcp/credentials/ca.pem
emit endpoint | python3 -I "$here/make-devices-json.py" | put /etc/rustopnsmcp/devices.json
inrig systemctl daemon-reload
# Up after any rig start. Not started here: it needs a token (rig-token.sh) and then a restart.
inrig systemctl enable rustopnsmcp
# Sizes and modes only; a zero size means the rig did not forward stdin (see the plan's fallback). The node's
# shell re-splits ssh arguments, so the whole remote command goes as one string with the stat format quoted.
same_guest
# shellcheck disable=SC2029 # vmid is expanded locally on purpose
report=$(ssh -n "$RIG_PVE" "pct exec $vmid -- stat -c '%a %U %s %n' /etc/rustopnsmcp/devices.json /etc/rustopnsmcp/credentials/api-key /etc/rustopnsmcp/credentials/api-secret /etc/rustopnsmcp/credentials/ca.pem" \
  | sed 's#/etc/rustopnsmcp/##')
printf '%s\n' "$report"
if [ "$(printf '%s\n' "$report" | wc -l)" != 4 ] || printf '%s\n' "$report" | awk '$3 + 0 == 0 { bad = 1 } END { exit !bad }'; then
  echo "install failed: a credential file or devices.json is missing or empty on $rig" >&2; exit 1
fi
