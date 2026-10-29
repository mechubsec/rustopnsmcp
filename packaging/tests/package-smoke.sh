#!/usr/bin/env bash
# RELEASE-ARTIFACTS §8: assert a built archive's shape without installing it.
# Usage: package-smoke.sh <rustopnsmcp-v*.tar.gz>   (needs the .sha256 beside it)
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }

# Resolve everything from the repo BEFORE any cd; an unreadable pin is a failure,
# never a skipped check (an unrun guard is an inert guard).
repo_root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
cargo_toml=$repo_root/Cargo.toml
[[ -r "$cargo_toml" ]] || fail "cannot read $cargo_toml (needed for the mecmcp_ref check)"
mapfile -t declared_refs < <(grep -oP 'tag = "\K[^"]+' "$cargo_toml" | sort -u)
[[ ${#declared_refs[@]} -eq 1 ]] || fail "Cargo.toml must declare exactly one mecmcp tag, found: ${declared_refs[*]:-none}"
declared_ref=${declared_refs[0]}
expected_mecmcp=$(grep -cE '^mecmcp-[a-z]+ += ' "$cargo_toml" || true)
[[ "$expected_mecmcp" -gt 0 ]] || fail "no mecmcp-* dependencies found in Cargo.toml"

archive_arg=${1:?usage: package-smoke.sh <rustopnsmcp-v*.tar.gz>}
[[ -f "$archive_arg" ]] || fail "archive not found: $archive_arg"
archive=$(cd -- "$(dirname -- "$archive_arg")" && pwd -P)/$(basename -- "$archive_arg")
archive_name=$(basename -- "$archive")
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT

# 1. Checksum is bare-named and verifies from the archive's own directory.
[[ -f "$archive.sha256" ]] || fail "missing $archive_name.sha256"
[[ "$(awk '{print $2}' "$archive.sha256")" == "$archive_name" ]] || fail "checksum filename is not the bare archive name"
(cd "$(dirname -- "$archive")" && sha256sum -c "$archive_name.sha256" >/dev/null 2>&1) || fail "checksum mismatch"

# 2. gzip and POSIX tar.
gzip -t "$archive" || fail "not gzip"
tar -tzvf "$archive" --numeric-owner >"$scratch/listing" || fail "not a tar archive"
tar -tzf "$archive" >"$scratch/names"

# 3. No unsafe paths, no links or special members, no setuid/world-writable, root-owned.
while IFS= read -r name; do
    case "$name" in /* | ../* | */../* | */.. | ..) fail "unsafe member path: $name" ;; esac
done <"$scratch/names"
while read -r perms owner _; do
    [[ "$perms" =~ ^[-d] ]] || fail "archive contains a non-file member (${perms:0:1})"
    [[ "$owner" == 0/0 ]] || fail "member not owned by 0/0: $owner"
    [[ "${perms:5:1}${perms:8:1}" == -- ]] || fail "member is group/world writable: $perms"
    [[ "${perms:3:1}${perms:6:1}${perms:9:1}" != *[sStT]* ]] || fail "member has a setuid/setgid/sticky bit: $perms"
done <"$scratch/listing"

# 4. Exactly one root directory, named for the archive.
mapfile -t roots < <(cut -d/ -f1 "$scratch/names" | sort -u)
[[ ${#roots[@]} -eq 1 ]] || fail "expected one root directory, found: ${roots[*]}"
root_dir=${roots[0]}
expected_root=$(sed -E 's/^(rustopnsmcp-v[0-9][^-]*(-[0-9A-Za-z.]+)?)-[a-z0-9_]+-unknown-linux-gnu\.tar\.gz$/\1/' <<<"$archive_name")
[[ "$root_dir" == "$expected_root" ]] || fail "root $root_dir does not match archive name (expected $expected_root)"
# Executables are exactly the binary and installer; every other file is 0644.
while read -r perms _ _ _ _ name; do
    [[ "${perms:0:1}" == - ]] || continue
    case "${name#"$root_dir"/}" in
        bin/rustopnsmcp | packaging/lxc/install.sh) want=-rwxr-xr-x ;;
        *) want=-rw-r--r-- ;;
    esac
    [[ "$perms" == "$want" ]] || fail "$name has mode $perms, want $want"
done <"$scratch/listing"

tar -xzf "$archive" -C "$scratch" --no-same-owner
cd "$scratch/$root_dir"

# 5. Required files, non-empty.
for required in bin/rustopnsmcp packaging/lxc/install.sh packaging/systemd/rustopnsmcp.service \
    packaging/systemd/rustopnsmcp.sysusers packaging/systemd/rustopnsmcp.tmpfiles \
    packaging/systemd/rustopnsmcp.override.conf.example packaging/journald/mecmcp.conf \
    packaging/logrotate/rustopnsmcp-audit config/devices.json.example docs/operations.md \
    BUILD-INFO SBOM.cdx.json README.md LICENSE SECURITY.md; do
    [[ -s "$required" ]] || fail "missing $required"
done

# 6. BUILD-INFO keys and formats. (binary_sha256 is verified by install.sh below.)
info() { sed -n "s/^$1=//p" BUILD-INFO | head -n 1; }
for key in release_status version git_commit git_dirty source_date_epoch target mecmcp_ref glibc_floor rustc binary_sha256; do
    [[ -n "$(info "$key")" ]] || fail "BUILD-INFO lacks $key"
done
[[ "$(info release_status)" =~ ^(public|lab-only)$ ]] || fail "release_status is not public|lab-only"
[[ "$(info git_commit)" =~ ^[0-9a-f]{40}$ ]] || fail "git_commit is not a bare 40-hex sha"
[[ "$(info git_dirty)" =~ ^(true|false)$ ]] || fail "git_dirty is not true|false"
[[ "$(info release_status)" != public || "$(info git_dirty)" == false ]] || fail "public package built from a dirty tree"
[[ "$(info source_date_epoch)" =~ ^[0-9]+$ ]] || fail "source_date_epoch is not an integer"
[[ "$(info glibc_floor)" =~ ^[0-9]+\.[0-9]+ ]] || fail "glibc_floor is not a version"
[[ "$(info binary_sha256)" =~ ^[0-9a-f]{64}$ ]] || fail "binary_sha256 is not 64-hex"
[[ "$(info version)" == "${root_dir#rustopnsmcp-v}" ]] || fail "BUILD-INFO version differs from the archive name"
[[ "$archive_name" == "$root_dir-$(info target).tar.gz" ]] || fail "BUILD-INFO target differs from the archive name"
case "$(info rustc)" in "rustc "* | "unknown ("*) ;; *) fail "rustc must be 'rustc …' or 'unknown (…)'" ;; esac

# 7. mecmcp_ref is the tag Cargo.toml pins.
[[ "$(info mecmcp_ref)" == "$declared_ref" ]] || fail "mecmcp_ref $(info mecmcp_ref) != Cargo.toml tag $declared_ref"

# 8. SBOM: CycloneDX, named for the binary, exactly the pinned mecmcp crates at mecmcp_ref.
jq -e --arg ver "${declared_ref#v}" --argjson want "$expected_mecmcp" '
    .bomFormat == "CycloneDX" and .metadata.component.name == "rustopnsmcp"
    and (.components | length) > 0
    and ([.components[] | select(.name? | strings | startswith("mecmcp-"))] | length) == $want
    and ([.components[] | select(.name? | strings | startswith("mecmcp-")) | .version] | unique) == [$ver]' \
    SBOM.cdx.json >/dev/null || fail "SBOM component set is wrong"

# 9. No absolute builder paths in the SBOM.
if grep -Eq '"/(home|workspace|workspaces|tmp)/' SBOM.cdx.json; then fail "SBOM contains an absolute path"; fi

# 10. Installer parses, validates its own package (files, BUILD-INFO keys,
# binary_sha256, SBOM, glibc floor) without mutating, and the binary runs.
bash -n packaging/lxc/install.sh || fail "install.sh has a syntax error"
install_out=$(OPNSMCP_INSTALL_CHECK_ONLY=1 packaging/lxc/install.sh 2>&1) || fail "installer rejected its own package: $install_out"
[[ "$install_out" == 'package ok' ]] || fail "installer check-only printed: $install_out"
./bin/rustopnsmcp --version | grep -q '^rustopnsmcp ' || fail "bin/rustopnsmcp --version"
echo "package-smoke: ok ($root_dir)"
