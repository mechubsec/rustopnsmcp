#!/usr/bin/env bash
# Build dist/rustopnsmcp-v<version>-<target>.tar.gz and its .sha256
# (mecmcp docs/RELEASE-ARTIFACTS.md).
#
# OPNSMCP_PACKAGE_SKIP_BUILD=1   package an existing release binary without
#                                compiling it; BUILD-INFO then records
#                                rustc=unknown (...), never a toolchain that
#                                did not produce the binary (conformance R3).
# OPNSMCP_PACKAGE_OUTPUT_DIR     output directory (default: dist).
# OPNSMCP_RELEASE_STATUS         public | lab-only (default: lab-only).
set -euo pipefail
# Archive modes must not depend on the builder's umask (also pinned via tar --mode).
umask 022

fail() { echo "package-lxc: $*" >&2; exit 1; }
repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root"

version=$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -n 1)
[[ -n "$version" ]] || fail "cannot read the version from Cargo.toml"
case "$(uname -m)" in
    x86_64) target=x86_64-unknown-linux-gnu ;;
    aarch64) target=aarch64-unknown-linux-gnu ;;
    *) fail "unsupported architecture $(uname -m)" ;;
esac
release_status=${OPNSMCP_RELEASE_STATUS:-lab-only}
case "$release_status" in public | lab-only) ;; *) fail "OPNSMCP_RELEASE_STATUS must be public or lab-only" ;; esac

# Derived, never hardcoded: a package built from one ref must not be installed
# by a script expecting another.
mapfile -t mecmcp_refs < <(grep -oP 'tag = "\K[^"]+' Cargo.toml | sort -u)
[[ ${#mecmcp_refs[@]} -eq 1 ]] || fail "expected exactly one mecmcp tag, found: ${mecmcp_refs[*]:-none}"
mecmcp_ref=${mecmcp_refs[0]}

git_commit=$(git rev-parse HEAD)
# Units, docs, installer and the binary come from the working tree, not HEAD.
if [[ -n "$(git status --porcelain)" ]]; then
    [[ "$release_status" != public ]] || fail "working tree is dirty; a public package must be built from a clean checkout"
    git_commit=${git_commit}-dirty
fi
skip_build=${OPNSMCP_PACKAGE_SKIP_BUILD:-0}
# A prebuilt binary is unrelated to HEAD by construction, so it cannot be public.
if [[ "$skip_build" == 1 && "$release_status" == public ]]; then
    fail "OPNSMCP_RELEASE_STATUS=public cannot be combined with OPNSMCP_PACKAGE_SKIP_BUILD=1"
fi
if [[ "$skip_build" != 1 ]]; then
    cargo build --release --locked -p rustopnsmcp --bin rustopnsmcp
fi
binary=${CARGO_TARGET_DIR:-target}/release/rustopnsmcp
[[ -x "$binary" ]] || fail "missing executable $binary"

glibc_floor=$(objdump -T "$binary" | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sed 's/GLIBC_//' | sort -Vu | tail -n 1)
[[ -n "$glibc_floor" ]] || fail "cannot measure the glibc floor of $binary"
source_date_epoch=$(git log -1 --format=%ct)
if [[ "$skip_build" == 1 ]]; then
    rustc_line="unknown (binary supplied prebuilt via OPNSMCP_PACKAGE_SKIP_BUILD; not compiled by this script)"
else
    rustc_line=$(rustc -vV | tr '\n' ' ' | sed 's/[[:space:]]*$//')
fi

pkg=rustopnsmcp-v${version}
archive_name=${pkg}-${target}.tar.gz
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pkg_root=$work/$pkg
mkdir -p "$pkg_root"/{bin,docs,config,packaging/lxc,packaging/systemd,packaging/journald,packaging/logrotate}

install -m 0755 "$binary" "$pkg_root/bin/rustopnsmcp"
install -m 0755 packaging/lxc/install.sh "$pkg_root/packaging/lxc/install.sh"
for unit_file in rustopnsmcp.service rustopnsmcp.sysusers rustopnsmcp.tmpfiles rustopnsmcp.override.conf.example; do
    install -m 0644 "packaging/systemd/$unit_file" "$pkg_root/packaging/systemd/$unit_file"
done
install -m 0644 packaging/journald/mecmcp.conf "$pkg_root/packaging/journald/mecmcp.conf"
install -m 0644 packaging/logrotate/rustopnsmcp-audit "$pkg_root/packaging/logrotate/rustopnsmcp-audit"
install -m 0644 packaging/examples/devices.example.json "$pkg_root/config/devices.json.example"
install -m 0644 docs/OPERATIONS.md "$pkg_root/docs/operations.md"
install -m 0644 -t "$pkg_root" LICENSE SECURITY.md
sed -e "s|@VERSION@|$version|g" -e "s|@ARCHIVE@|$archive_name|g" \
    -e "s|@GIT_COMMIT@|$git_commit|g" -e "s|@MECMCP_REF@|$mecmcp_ref|g" \
    -e "s|@GLIBC_FLOOR@|$glibc_floor|g" packaging/package-README.md.in >"$pkg_root/README.md"

# SBOM from a directory that holds only Cargo.lock, scanned under the name
# "rustopnsmcp": no absolute path, no nested checkout, and a metadata
# component named after the binary (RELEASE-ARTIFACTS §4).
command -v trivy >/dev/null || fail "trivy is required to generate SBOM.cdx.json (CI installs a pinned, checksum-verified copy)"
mkdir -p "$work/sbom-src/rustopnsmcp"
cp Cargo.lock "$work/sbom-src/rustopnsmcp/"
(cd "$work/sbom-src" && trivy filesystem --quiet --scanners vuln --format cyclonedx \
    --output "$pkg_root/SBOM.cdx.json" rustopnsmcp)

expected_mecmcp=$(grep -c '^mecmcp-' <<<"$(grep -oE '^mecmcp-[a-z]+ += ' Cargo.toml)")
jq -e --arg ver "${mecmcp_ref#v}" --argjson want "$expected_mecmcp" '
    .bomFormat == "CycloneDX"
    and .metadata.component.name == "rustopnsmcp"
    and (.components | length) > 0
    and ([.components[] | select(.name? | strings | startswith("mecmcp-"))] | length) == $want
    and ([.components[] | select(.name? | strings | startswith("mecmcp-")) | .version] | unique) == [$ver]' \
    "$pkg_root/SBOM.cdx.json" >/dev/null \
    || fail "SBOM does not list exactly the $expected_mecmcp mecmcp crates at ${mecmcp_ref#v}"
if grep -Eq '"/(home|workspace|workspaces|tmp)/' "$pkg_root/SBOM.cdx.json"; then
    fail "SBOM contains an absolute path"
fi

binary_sha256=$(sha256sum "$pkg_root/bin/rustopnsmcp" | cut -d' ' -f1)
cat >"$pkg_root/BUILD-INFO" <<EOT
release_status=$release_status
version=$version
git_commit=$git_commit
source_date_epoch=$source_date_epoch
target=$target
mecmcp_ref=$mecmcp_ref
glibc_floor=$glibc_floor
rustc=$rustc_line
binary_sha256=$binary_sha256
EOT

output_dir=${OPNSMCP_PACKAGE_OUTPUT_DIR:-dist}
mkdir -p "$output_dir"; dist_dir=$(cd "$output_dir" && pwd -P)
archive=$dist_dir/$archive_name
# Reproducible: sorted names, no host uid/gid, commit-time mtimes, no atime/ctime.
(cd "$work" && find "$pkg" -print0 | LC_ALL=C sort -z \
    | tar --create --gzip --file="$archive" --format=posix --sort=name \
        --owner=0 --group=0 --numeric-owner --mode='u+rwX,go+rX,go-w' --mtime="@$source_date_epoch" \
        --pax-option=delete=atime,delete=ctime --no-recursion --null --files-from=-)
# From inside the output directory so the filename field is bare.
(cd "$dist_dir" && sha256sum "$archive_name" >"$archive_name.sha256" && sha256sum -c "$archive_name.sha256")
echo "package-lxc: wrote $archive"
