#!/usr/bin/env bash
# The installer must add exactly one numbered journald drop-in, never an
# unnumbered one, and never touch an existing one.
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
fail() { echo "FAIL: $*" >&2; exit 1; }
binary=${CARGO_TARGET_DIR:-target}/release/rustopnsmcp
[[ -x "$binary" ]] || fail "build $binary first"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
OPNSMCP_PACKAGE_SKIP_BUILD=1 OPNSMCP_PACKAGE_OUTPUT_DIR="$scratch/dist" scripts/package-lxc.sh >/dev/null
tar -xzf "$scratch"/dist/rustopnsmcp-v*.tar.gz -C "$scratch"
pkg=$(find "$scratch" -maxdepth 1 -type d -name 'rustopnsmcp-v*' | head -n 1)

dir=$scratch/fresh/etc/systemd/journald.conf.d
OPNSMCP_INSTALL_TEST_ROOT="$scratch/fresh" "$pkg/packaging/lxc/install.sh" >/dev/null
mapfile -t files < <(find "$dir" -type f -printf '%f\n' | sort)
[[ "${files[*]}" == "20-audit-retention.conf" ]] || fail "fresh install must add exactly 20-audit-retention.conf, got: ${files[*]}"
grep -q '^Storage=persistent' "$dir/20-audit-retention.conf" || fail "Storage=persistent missing"
if grep -qi '^Seal=yes' "$dir/20-audit-retention.conf"; then fail "Seal=yes cannot initialise in an unprivileged LXC"; fi

# An existing fleet file is left exactly as it is, and nothing unnumbered appears.
mkdir -p "$scratch/site/etc/systemd/journald.conf.d"
printf '[Journal]\nSystemMaxUse=128M\n' >"$scratch/site/etc/systemd/journald.conf.d/20-audit-retention.conf"
OPNSMCP_INSTALL_TEST_ROOT="$scratch/site" "$pkg/packaging/lxc/install.sh" >/dev/null
grep -qx 'SystemMaxUse=128M' "$scratch/site/etc/systemd/journald.conf.d/20-audit-retention.conf" \
    || fail "existing 20-audit-retention.conf was overwritten"
unnumbered=$(find "$scratch/site/etc/systemd/journald.conf.d" -type f ! -name '[0-9][0-9]-*' | head -n 1)
[[ -z "$unnumbered" ]] || fail "installer created an unnumbered drop-in: $unnumbered"
echo "journald-dropin-ordering: ok"
