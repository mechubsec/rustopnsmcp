#!/usr/bin/env bash
# Mint a bearer token on a rig for opnsense-lab and print it alone on stdout, for command substitution.
#   rig-token.sh <rig> <token-name> agent|human
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
rig="${1:?rig}"; name="${2:?name}"; actor="${3:?agent|human}"
vmid=$("$here/rig-ctl.sh" vmid "$rig")
ssh "$RIG_PVE" pct exec "$vmid" -- runuser -u rustopnsmcp -- /usr/local/bin/rustopnsmcp token add \
  --tokens-file /var/lib/rustopnsmcp/tokens.json --name "$name" --devices opnsense-lab --tools '\*' --actor-type "$actor"
