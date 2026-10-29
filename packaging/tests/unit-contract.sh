#!/usr/bin/env bash
# The stock unit is loopback-only with the audit baseline and no placeholders.
# The site override example restates every flag, because a systemd drop-in can
# only replace ExecStart, never append to it: an override that forgets
# --audit-redact silently turns redaction off.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
unit=$root/packaging/systemd/rustopnsmcp.service
override=$root/packaging/systemd/rustopnsmcp.override.conf.example
tmpfiles=$root/packaging/systemd/rustopnsmcp.tmpfiles
fail() { echo "FAIL: $*" >&2; exit 1; }

# The last non-empty ExecStart= with its line continuations joined.
exec_line() {
    sed -e ':a' -e '/\\$/{N;s/\\\n//;ba' -e '}' "$1" | grep -E '^ExecStart=.' | tail -n 1
}
flags_of() { grep -oE -- ' --[a-z0-9-]+' | sort -u; }

stock=$(exec_line "$unit")
site=$(exec_line "$override")

# 1. No placeholders: the installer no longer rewrites the unit.
if grep -qE '@[A-Z][A-Z_]*@' "$unit"; then fail "unit still carries @PLACEHOLDER@ tokens"; fi

# 2. The stock unit says exactly what spec 3.2 says.
for needle in \
    '--device-mapping /etc/rustopnsmcp/devices.json' \
    '--tokens-file /var/lib/rustopnsmcp/tokens.json' \
    '--state-file /var/lib/rustopnsmcp/changeset-state.json' \
    '--inventory-readonly' \
    '--host 127.0.0.1' \
    '--audit-format json' \
    '--audit-journald' \
    '--audit-redact devices=hmac' \
    '--audit-hmac-key-file /etc/rustopnsmcp/audit-hmac.key'; do
    grep -qF -- "$needle" <<<"$stock" || fail "stock unit lacks: $needle"
done
for forbidden in '--audit-log-file' 'changesets.json' '--tls-cert' '--tls-key' \
    '--allowed-host' '--allowed-origin' '--lab-mode' '--allow-direct-commit'; do
    if grep -qF -- "$forbidden" <<<"$stock"; then fail "stock unit must not contain: $forbidden"; fi
done
grep -qx 'EnvironmentFile=-/etc/rustopnsmcp/credentials.env' "$unit" \
    || fail "EnvironmentFile must be -/etc/rustopnsmcp/credentials.env"
if grep -q 'secrets.env' "$unit"; then fail "secrets.env was renamed credentials.env"; fi

# 3. The override example resets ExecStart first, then restates every stock flag.
grep -qx 'ExecStart=' "$override" || fail "override example must clear ExecStart= before setting it"
missing=$(comm -23 <(flags_of <<<"$stock") <(flags_of <<<"$site"))
[[ -z "$missing" ]] || fail "override example drops stock flags:$missing"
for needle in '--tls-cert' '--tls-key' '--allowed-host' '--allowed-origin' \
    '--audit-redact devices=hmac' '--audit-hmac-key-file /etc/rustopnsmcp/audit-hmac.key'; do
    grep -qF -- "$needle" <<<"$site" || fail "override example lacks: $needle"
done

# 4. tmpfiles needs no change for the rework; pin the two lines it relies on.
grep -qx 'd /etc/rustopnsmcp 0750 root rustopnsmcp -' "$tmpfiles" || fail "tmpfiles /etc line changed"
grep -qx 'd /var/lib/rustopnsmcp 0700 rustopnsmcp rustopnsmcp -' "$tmpfiles" || fail "tmpfiles /var/lib line changed"

# 5. systemd agrees the stock unit is well formed. The binary is not installed
# where the unit names it, which is the one diagnostic mecmcp's R5 also drops.
if command -v systemd-analyze >/dev/null; then
    scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
    cp "$unit" "$scratch/rustopnsmcp.service"
    problems=$(systemd-analyze verify "$scratch/rustopnsmcp.service" 2>&1 \
        | grep -v 'is not executable: No such file or directory' || true)
    [[ -z "$problems" ]] || fail "systemd-analyze verify: $problems"
fi
echo "unit-contract: ok"
