#!/usr/bin/env bash
# Rotation must rename the audit file AND signal the server, or the renamed
# file keeps growing while the new audit.jsonl stays empty forever.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
fragment=$root/packaging/logrotate/rustopnsmcp-audit
# No vacuous pass: a missing logrotate is a failure, not a skip.
command -v logrotate >/dev/null || { echo "FAIL: logrotate not installed"; exit 1; }

scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin" "$scratch/var"
cat >"$scratch/bin/systemctl" <<EOS
#!/bin/sh
echo "\$@" >> "$scratch/systemctl.log"
EOS
chmod +x "$scratch/bin/systemctl"
head -c 2000 /dev/zero | tr '\0' 'x' >"$scratch/var/audit.jsonl"

# Same directives, scratch path, no ownership change (not root here).
sed -e "s#/var/lib/rustopnsmcp/audit.jsonl#$scratch/var/audit.jsonl#" \
    -e '/^[[:space:]]*create /d' -e '/^[[:space:]]*su /d' "$fragment" >"$scratch/rotate.conf"
PATH="$scratch/bin:$PATH" logrotate --force --state "$scratch/state" "$scratch/rotate.conf"

[[ -f "$scratch/var/audit.jsonl.1" ]] || { echo "FAIL: audit.jsonl was not rotated"; exit 1; }
[[ -f "$scratch/systemctl.log" ]] || { echo "FAIL: postrotate did not signal the server"; exit 1; }
grep -q -- '--signal=HUP rustopnsmcp.service' "$scratch/systemctl.log" \
    || { echo "FAIL: postrotate did not signal the server"; exit 1; }
grep -q -- '--kill-whom=main' "$scratch/systemctl.log" \
    || { echo "FAIL: signal must target only the main process"; exit 1; }
echo "logrotate: ok"
