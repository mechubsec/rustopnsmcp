#!/usr/bin/env bash
# Mint a bearer token on a rig for opnsense-lab and print it alone on stdout, for command substitution.
#   rig-token.sh <rig> <token-name> agent|human
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scripts/live/rig-lib.sh
. "$here/rig-lib.sh"
rig="${1:?rig}"; name="${2:?name}"; actor="${3:?agent|human}"
: "${RIG_PVE:?}"
require_match RIG_PVE "$RIG_PVE" "$alias_re"
require_match "token name" "$name" "$token_name_re"
case "$actor" in agent|human) ;; *) echo "actor must be agent or human" >&2; exit 2 ;; esac
vmid=$("$here/rig-ctl.sh" vmid "$rig")
# Ids get recycled: prove the same guest still answers to the name immediately before minting.
[ "$("$here/rig-ctl.sh" vmid "$rig" 2>/dev/null)" = "$vmid" ] || { echo "$rig no longer resolves to the same guest; refusing" >&2; exit 1; }
ssh "$RIG_PVE" pct exec "$vmid" -- runuser -u rustopnsmcp -- /usr/local/bin/rustopnsmcp token add \
  --tokens-file /var/lib/rustopnsmcp/tokens.json --name "$name" --devices opnsense-lab --tools '\*' --actor-type "$actor"
