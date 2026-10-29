#!/usr/bin/env bash
# Mint a bearer token on a rig for opnsense-lab and print it alone on stdout, for command substitution.
#   rig-token.sh <rig> <token-name> agent|human [tool,tool,...]
# The default tool scope is the wildcard, which by design excludes every write tool; a write-capable token
# names its tools. Names are not checked here: `token add` validates them against the server's own tool list.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scripts/live/rig-lib.sh
. "$here/rig-lib.sh"
rig="${1:?rig}"; name="${2:?name}"; actor="${3:?agent|human}"; tools="${4:-*}"
: "${RIG_PVE:?}"
require_match RIG_PVE "$RIG_PVE" "$alias_re"
require_match "token name" "$name" "$token_name_re"
[ "$tools" = "*" ] || require_match "tool list" "$tools" "$tool_list_re"
case "$actor" in agent|human) ;; *) echo "actor must be agent or human" >&2; exit 2 ;; esac
vmid=$("$here/rig-ctl.sh" vmid "$rig")
# Ids get recycled: prove the same guest still answers to the name immediately before minting.
[ "$("$here/rig-ctl.sh" vmid "$rig" 2>/dev/null)" = "$vmid" ] || { echo "$rig no longer resolves to the same guest; refusing" >&2; exit 1; }
# The node shell re-splits the arguments: escape the bare wildcard so it is not globbed there.
tools_arg=$tools; [ "$tools" != "*" ] || tools_arg='\*'
ssh -n "$RIG_PVE" pct exec "$vmid" -- runuser -u rustopnsmcp -- /usr/local/bin/rustopnsmcp token add \
  --tokens-file /var/lib/rustopnsmcp/tokens.json --name "$name" --devices opnsense-lab --tools "$tools_arg" --actor-type "$actor"
