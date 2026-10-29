#!/usr/bin/env bash
# Packaging a prebuilt binary must say so: rustc=unknown (...), never a
# workstation toolchain that did not compile it, and binary_sha256 must match
# the bytes in the archive (mecmcp conformance R3).
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
binary=${CARGO_TARGET_DIR:-target}/release/rustopnsmcp
[[ -x "$binary" ]] || { echo "build $binary first (cargo build --release --locked -p rustopnsmcp)"; exit 1; }

out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
OPNSMCP_PACKAGE_SKIP_BUILD=1 OPNSMCP_PACKAGE_OUTPUT_DIR="$out" scripts/package-lxc.sh >/dev/null
archive=$(find "$out" -name 'rustopnsmcp-v*.tar.gz' | head -n 1)
[[ -n "$archive" ]] || { echo "FAIL: no archive produced"; exit 1; }

mkdir "$out/x"; tar -xzf "$archive" -C "$out/x"
info=$(find "$out/x" -name BUILD-INFO)
rustc_line=$(sed -n 's/^rustc=//p' "$info")
case "$rustc_line" in
    "unknown ("*) ;;
    *) echo "FAIL: skip-build BUILD-INFO names a toolchain: $rustc_line"; exit 1 ;;
esac
recorded=$(sed -n 's/^binary_sha256=//p' "$info")
actual=$(sha256sum "$(dirname "$info")/bin/rustopnsmcp" | cut -d' ' -f1)
[[ "$recorded" == "$actual" ]] || { echo "FAIL: binary_sha256 does not match the archived binary"; exit 1; }
echo "skip-build-provenance: ok"
