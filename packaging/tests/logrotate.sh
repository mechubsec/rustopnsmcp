#!/usr/bin/env bash
# Rotation must rename the audit file AND signal the server, or the renamed
# file keeps growing while the new audit.jsonl stays empty forever. An inactive
# unit must rotate cleanly without a kill; a failed kill of an active one must
# fail the rotation; and a global copytruncate must not leak into the block.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
fragment=${FRAGMENT:-$root/packaging/logrotate/rustopnsmcp-audit}
# No vacuous pass: a missing logrotate is a failure, not a skip.
command -v logrotate >/dev/null || { echo "FAIL: logrotate not installed"; exit 1; }

scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin"
# STUB_ACTIVE_RC=<n> -> is-active exits n (3 inactive, 4 no such unit); STUB_KILL_FAIL=1 -> kill exits 1.
cat >"$scratch/bin/systemctl" <<EOS
#!/bin/sh
echo "\$@" >> "$scratch/systemctl.log"
case "\$1" in
    is-active) exit "\${STUB_ACTIVE_RC:-0}" ;;
    kill) [ "\${STUB_KILL_FAIL:-0}" = 1 ] && exit 1; exit 0 ;;
esac
EOS
chmod +x "$scratch/bin/systemctl"

# Same directives, scratch path, no ownership change (not root here). A global
# copytruncate precedes the block, as on hosts that set it in logrotate.conf.
# $1 = case name; env STUB_* passes through. Prints nothing; sets rc.
rotate() {
    rm -rf "${scratch:?}/var" "$scratch/state" "$scratch/systemctl.log"; mkdir -p "$scratch/var"
    head -c 2000 /dev/zero | tr '\0' 'x' >"$scratch/var/audit.jsonl"
    { echo copytruncate
      sed -e "s#/var/lib/rustopnsmcp/audit.jsonl#$scratch/var/audit.jsonl#" \
          -e '/^[[:space:]]*create /d' -e '/^[[:space:]]*su /d' "$fragment"; } >"$scratch/rotate.conf"
    inode_before=$(stat -c %i "$scratch/var/audit.jsonl")
    PATH="$scratch/bin:$PATH" logrotate --force --state "$scratch/state" "$scratch/rotate.conf" 2>"$scratch/err"
}

# Active unit: rotates by rename and signals main only.
rotate || { echo "FAIL: rotation failed with an active unit"; cat "$scratch/err"; exit 1; }
[[ -f "$scratch/var/audit.jsonl.1" ]] || { echo "FAIL: audit.jsonl was not rotated"; exit 1; }
# Rename mode gives the live path a new inode; copytruncate keeps the old one.
[[ "$(stat -c %i "$scratch/var/audit.jsonl" 2>/dev/null || echo gone)" != "$inode_before" ]] \
    || { echo "FAIL: audit.jsonl kept its inode (copytruncate leaked in?)"; exit 1; }
[[ -f "$scratch/systemctl.log" ]] || { echo "FAIL: postrotate did not signal the server"; exit 1; }
grep -qxF 'kill --kill-whom=main --signal=HUP rustopnsmcp.service' "$scratch/systemctl.log" \
    || { echo "FAIL: postrotate did not signal the server (whole-line match)"; exit 1; }

# Inactive unit: rotation succeeds, nothing is killed.
STUB_ACTIVE_RC=3 rotate || { echo "FAIL: rotation failed with an inactive unit"; cat "$scratch/err"; exit 1; }
[[ -f "$scratch/var/audit.jsonl.1" ]] || { echo "FAIL: inactive case did not rotate"; exit 1; }
if grep -q '^kill ' "$scratch/systemctl.log"; then echo "FAIL: killed an inactive unit"; exit 1; fi

# Unknown unit (4) is quiet too; a failed QUERY (any other status) must fail the
# rotation, with no kill, rather than leave a live server on the rotated file.
STUB_ACTIVE_RC=4 rotate || { echo "FAIL: rotation failed with an unknown unit"; cat "$scratch/err"; exit 1; }
if grep -q '^kill ' "$scratch/systemctl.log"; then echo "FAIL: killed an unknown unit"; exit 1; fi
for rc in 1 2 5 255; do
    if STUB_ACTIVE_RC=$rc rotate; then echo "FAIL: is-active query failure ($rc) was treated as inactive"; exit 1; fi
    if grep -q '^kill ' "$scratch/systemctl.log"; then echo "FAIL: signalled after a failed query"; exit 1; fi
done

# Active unit whose kill fails: the rotation must report failure.
if STUB_KILL_FAIL=1 rotate; then echo "FAIL: failed kill of an active unit was swallowed"; exit 1; fi
echo "logrotate: ok"
