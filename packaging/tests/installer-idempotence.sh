#!/usr/bin/env bash
# The installer, run twice into a staged root: creates what Installer
# requirements 3-6 name, never overwrites state, refuses a damaged package,
# keeps a modified unit, and installs a config that can boot. Ownership/apt/
# systemd are not exercised here (test mode); the dry-run install on a real
# guest covers those.
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
fail() { echo "FAIL: $*" >&2; exit 1; }
binary=${CARGO_TARGET_DIR:-target}/release/rustopnsmcp
[[ -x "$binary" ]] || fail "build $binary first"

scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
OPNSMCP_PACKAGE_SKIP_BUILD=1 OPNSMCP_PACKAGE_OUTPUT_DIR="$scratch/dist" scripts/package-lxc.sh >/dev/null
tar -xzf "$scratch"/dist/rustopnsmcp-v*.tar.gz -C "$scratch"
pkg=$(find "$scratch" -maxdepth 1 -type d -name 'rustopnsmcp-v*' | head -n 1)
target=$scratch/target
install_into() { OPNSMCP_INSTALL_TEST_ROOT="$target" "$pkg/packaging/lxc/install.sh"; }
mode_of() { stat -c '%a' "$target$1"; }

# 0. Check-only validates and prints, and writes nothing.
OPNSMCP_INSTALL_CHECK_ONLY=1 OPNSMCP_INSTALL_TEST_ROOT="$scratch/checkonly" "$pkg/packaging/lxc/install.sh" >"$scratch/check.log"
[[ "$(cat "$scratch/check.log")" == 'package ok' ]] || fail "check-only should print exactly 'package ok'"
[[ ! -e "$scratch/checkonly" ]] || fail "check-only modified the host"

# 1. Fresh install.
install_into >"$scratch/first.log"
[[ -x "$target/usr/local/bin/rustopnsmcp" ]] || fail "binary not installed"
[[ "$(mode_of /var/lib/rustopnsmcp/tokens.json)" == 600 ]] || fail "tokens.json must be 0600"
[[ "$(cat "$target/var/lib/rustopnsmcp/tokens.json")" == '{"version":1,"tokens":[]}' ]] || fail "tokens.json content"
[[ "$(mode_of /etc/rustopnsmcp/audit-hmac.key)" == 600 ]] || fail "audit-hmac.key must be 0600"
[[ "$(stat -c %s "$target/etc/rustopnsmcp/audit-hmac.key")" -eq 32 ]] || fail "audit-hmac.key must be exactly 32 bytes"
[[ "$(mode_of /etc/rustopnsmcp/devices.json)" == 600 ]] || fail "devices.json must be 0600"
[[ "$(mode_of /etc/rustopnsmcp/credentials.env)" == 600 ]] || fail "credentials.env must be 0600"
[[ -f "$target/etc/rustopnsmcp/devices.example.json" ]] || fail "example inventory missing"
[[ -f "$target/usr/lib/sysusers.d/rustopnsmcp.conf" && -f "$target/usr/lib/tmpfiles.d/rustopnsmcp.conf" ]] \
    || fail "sysusers/tmpfiles files not installed"
[[ -d "$target/etc/systemd/system/rustopnsmcp.service.d" ]] || fail "drop-in directory not created (conformance R4)"
[[ ! -e "$target/etc/systemd/system/rustopnsmcp.service.d/override.conf" ]] || fail "installer must not write the site override"
[[ -f "$target/etc/logrotate.d/rustopnsmcp-audit" ]] || fail "logrotate fragment missing"
# A config that can boot: the shipped devices.json parses.
jq -e '.version == 1 and (.devices | type == "object")' "$target/etc/rustopnsmcp/devices.json" >/dev/null \
    || fail "devices.json is not a valid inventory"
grep -q 'systemctl start rustopnsmcp' "$scratch/first.log" || fail "first install must print start"
if grep -q 'systemctl restart' "$scratch/first.log"; then fail "first install must not print restart"; fi
grep -q 'as root' "$scratch/first.log" || fail "next steps must say they run as root"
grep -q 'runuser -u rustopnsmcp -- rustopnsmcp token add' "$scratch/first.log" || fail "token hint must use runuser"
if grep -q 'sudo' "$scratch/first.log"; then fail "token hint must not need sudo"; fi
# The write-token hint names real write tools (checked against the source list).
for write_tool in create approve apply confirm cancel; do
    name=${write_tool}_opnsense_change_set
    grep -q "$name" "$scratch/first.log" || fail "write-token hint lacks $name"
    grep -q "\"$name\"" rustopnsmcp-core/src/tools/mod.rs || fail "$name is not a tool name in the source"
done
# Test mode skips systemctl, so assert on the script itself.
if grep -nE '^[[:space:]]*systemctl[[:space:]]+(enable|start|restart)' "$pkg/packaging/lxc/install.sh"; then
    fail "installer must never enable or start the service"
fi

# 2. State is never overwritten on a re-run.
printf 'SENTINEL-TOKENS\n' >"$target/var/lib/rustopnsmcp/tokens.json"
printf 'SENTINEL-STATE\n'  >"$target/var/lib/rustopnsmcp/changeset-state.json"
printf 'SENTINEL-KEY\n'    >"$target/etc/rustopnsmcp/audit-hmac.key"
printf '{"version":1,"devices":{"x":{}}}\n' >"$target/etc/rustopnsmcp/devices.json"
printf 'SENTINEL-CREDS\n'  >"$target/etc/rustopnsmcp/credentials.env"
chmod 600 "$target"/var/lib/rustopnsmcp/* "$target"/etc/rustopnsmcp/{audit-hmac.key,devices.json,credentials.env}
install_into >"$scratch/second.log"
for pair in "var/lib/rustopnsmcp/tokens.json:SENTINEL-TOKENS" "var/lib/rustopnsmcp/changeset-state.json:SENTINEL-STATE" \
            "etc/rustopnsmcp/audit-hmac.key:SENTINEL-KEY" "etc/rustopnsmcp/credentials.env:SENTINEL-CREDS"; do
    [[ "$(cat "$target/${pair%%:*}")" == "${pair##*:}" ]] || fail "re-run overwrote ${pair%%:*}"
done
grep -q '"x"' "$target/etc/rustopnsmcp/devices.json" || fail "re-run overwrote devices.json"
# An upgrade must print restart: start is a no-op on the running old process.
grep -q 'systemctl restart rustopnsmcp' "$scratch/second.log" || fail "upgrade must print restart"
if grep -q 'systemctl start rustopnsmcp' "$scratch/second.log"; then fail "upgrade must not print start"; fi

# 3. A symlink where a state file belongs is refused, not followed.
rm "$target/var/lib/rustopnsmcp/tokens.json"; ln -s /etc/passwd "$target/var/lib/rustopnsmcp/tokens.json"
if install_into >/dev/null 2>"$scratch/symlink.err"; then fail "installer followed a tokens.json symlink"; fi
grep -q 'is a symlink' "$scratch/symlink.err" || fail "symlink refusal should say so"
rm "$target/var/lib/rustopnsmcp/tokens.json"
mkdir "$target/var/lib/rustopnsmcp/tokens.json"
if install_into >/dev/null 2>"$scratch/nonreg.err"; then fail "installer accepted a directory as tokens.json"; fi
grep -q 'not a regular file' "$scratch/nonreg.err" || fail "non-regular refusal should say so"
rmdir "$target/var/lib/rustopnsmcp/tokens.json"
printf '{"version":1,"tokens":[]}\n' >"$target/var/lib/rustopnsmcp/tokens.json"; chmod 600 "$target/var/lib/rustopnsmcp/tokens.json"

# 3b. Preflight: a bad destination anywhere refuses before ANY mutation, even
# the last-provisioned path (credentials.env) or changeset-state.json.
for victim in etc/rustopnsmcp/credentials.env var/lib/rustopnsmcp/changeset-state.json; do
    pre=$scratch/pre-$(basename "$victim")
    mkdir -p "$pre/etc/rustopnsmcp" "$pre/var/lib/rustopnsmcp"
    chmod 750 "$pre/etc/rustopnsmcp"; chmod 700 "$pre/var/lib/rustopnsmcp"
    ln -s /etc/passwd "$pre/$victim"
    before=$(find "$pre" | sort)
    if OPNSMCP_INSTALL_TEST_ROOT="$pre" "$pkg/packaging/lxc/install.sh" >/dev/null 2>"$scratch/pre.err"; then
        fail "preflight accepted a symlink at $victim"
    fi
    [[ "$(find "$pre" | sort)" == "$before" ]] || fail "refusal at $victim left files behind"
done
# An existing file with the wrong mode or owner is refused with the exact fix,
# and left exactly as it was.
chmod 644 "$target/var/lib/rustopnsmcp/tokens.json"
if install_into >/dev/null 2>"$scratch/mode.err"; then fail "installer accepted a 0644 tokens.json"; fi
grep -q 'chmod 600' "$scratch/mode.err" || fail "wrong-mode refusal should name the fix"
[[ "$(mode_of /var/lib/rustopnsmcp/tokens.json)" == 644 ]] || fail "installer changed the operator's file"
chmod 600 "$target/var/lib/rustopnsmcp/tokens.json"
if OPNSMCP_INSTALL_TEST_EXPECT_OWNER=nobody:nogroup install_into >/dev/null 2>"$scratch/owner.err"; then
    fail "installer accepted a wrong-owner state file"
fi
grep -q 'chown nobody:nogroup' "$scratch/owner.err" || fail "wrong-owner refusal should name the fix"
# Ownership is set by install at creation. Test mode cannot chown, so assert
# the script: no chown command at all, and the owner flags are on install.
if grep -nE '^[[:space:]]*chown[[:space:]]' "$pkg/packaging/lxc/install.sh"; then
    fail "installer must not chown a path after creating it"
fi
grep -qF "owner_args=(-o \"\$svc\" -g \"\$svc\")" "$pkg/packaging/lxc/install.sh" || fail "owner flags missing"
grep -qF "install \"\${owner_args[@]}\" -m \"\$mode\"" "$pkg/packaging/lxc/install.sh" || fail "provision must create with owner flags"

# 4. A modified installed unit is kept as .bak-*, and the new unit is stock (R11).
unit=$target/etc/systemd/system/rustopnsmcp.service
printf '\n# SITE-EDIT\n' >>"$unit"
install_into >"$scratch/unit.log"
cmp -s "$unit" "$pkg/packaging/systemd/rustopnsmcp.service" || fail "reinstall did not restore the stock unit"
mapfile -t backups < <(find "$target/etc/systemd/system" -maxdepth 1 -name 'rustopnsmcp.service.bak-*')
[[ ${#backups[@]} -eq 1 ]] || fail "expected exactly one unit backup, got ${#backups[@]}"
grep -q 'SITE-EDIT' "${backups[0]}" || fail "backup does not hold the modified unit"
# An unmodified unit makes no further backup.
install_into >/dev/null
mapfile -t backups < <(find "$target/etc/systemd/system" -maxdepth 1 -name 'rustopnsmcp.service.bak-*')
[[ ${#backups[@]} -eq 1 ]] || fail "a stock unit must not create another backup"

# 4b. A package for another architecture is refused before anything is written.
case $(uname -m) in x86_64) other=aarch64 ;; *) other=x86_64 ;; esac
for machine in "$other" riscv64; do
    fresh=$scratch/fresh-machine-$machine
    if OPNSMCP_INSTALL_TEST_MACHINE=$machine OPNSMCP_INSTALL_TEST_ROOT="$fresh" "$pkg/packaging/lxc/install.sh" >/dev/null 2>"$scratch/arch.err"; then
        fail "installer accepted a package on a $machine host"
    fi
    [[ ! -e "$fresh" ]] || fail "$machine: the host was modified before the refusal"
    grep -q 'architecture\|needs' "$scratch/arch.err" || fail "arch refusal should say so"
done
# And the matching machine passes (the default path, plus an explicit override).
OPNSMCP_INSTALL_TEST_MACHINE=$(uname -m) install_into >/dev/null

# 5. A damaged package is refused before anything is written.
for damage in tamper-binary drop-build-info drop-sbom bad-sbom floor-too-high; do
    copy=$scratch/damaged-$damage; cp -a "$pkg" "$copy"
    case $damage in
        tamper-binary) printf 'x' >>"$copy/bin/rustopnsmcp" ;;
        drop-build-info) rm "$copy/BUILD-INFO" ;;
        drop-sbom) rm "$copy/SBOM.cdx.json" ;;
        bad-sbom) printf "{}\n" >"$copy/SBOM.cdx.json" ;;
        floor-too-high) sed -i 's/^glibc_floor=.*/glibc_floor=99.0/' "$copy/BUILD-INFO" ;;
    esac
    fresh=$scratch/fresh-$damage
    if OPNSMCP_INSTALL_TEST_ROOT="$fresh" "$copy/packaging/lxc/install.sh" >/dev/null 2>"$scratch/$damage.err"; then
        fail "installer accepted a package with $damage"
    fi
    [[ ! -e "$fresh" ]] || fail "$damage: the host was modified before the refusal"
done
grep -q 'glibc' "$scratch/floor-too-high.err" || fail "floor refusal should name glibc"
echo "installer-idempotence: ok"
