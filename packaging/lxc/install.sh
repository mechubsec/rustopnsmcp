#!/usr/bin/env bash
# Installer for rustopnsmcp on Debian 13 (unprivileged LXC, nesting=1).
# Run from an extracted archive: sudo packaging/lxc/install.sh
#
# It validates the package before touching the host, never overwrites state,
# never enables or starts the service (config and credentials must exist
# first), and installs a config that can boot.
set -euo pipefail

svc=rustopnsmcp
die() { printf '%s installer: %s\n' "$svc" "$*" >&2; exit 1; }

# Test hooks (packaging/tests): CHECK_ONLY validates the package and stops.
# TEST_ROOT stages every destination under a directory and skips root, Debian,
# apt, systemd-sysusers/tmpfiles, chown and systemctl.
check_only=${OPNSMCP_INSTALL_CHECK_ONLY:-0}
test_root=${OPNSMCP_INSTALL_TEST_ROOT:-}
dest() { printf '%s%s' "$test_root" "$1"; }

package_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$package_dir"

# --- 1. Validate the package (no host mutation) ------------------------------
for required in bin/rustopnsmcp BUILD-INFO SBOM.cdx.json README.md LICENSE SECURITY.md \
    packaging/systemd/rustopnsmcp.service packaging/systemd/rustopnsmcp.sysusers \
    packaging/systemd/rustopnsmcp.tmpfiles packaging/systemd/rustopnsmcp.override.conf.example \
    packaging/journald/mecmcp.conf packaging/logrotate/rustopnsmcp-audit config/devices.json.example; do
    [[ -s "$required" && ! -L "$required" ]] || die "package is missing $required"
done
[[ -x bin/rustopnsmcp ]] || die 'bin/rustopnsmcp is not executable'
build_info() { sed -n "s/^$1=//p" BUILD-INFO | head -n 1; }
for key in release_status version git_commit source_date_epoch target mecmcp_ref glibc_floor rustc binary_sha256; do
    [[ -n "$(build_info "$key")" ]] || die "BUILD-INFO lacks $key"
done
case "$(build_info rustc)" in "rustc "* | "unknown ("*) ;; *) die 'BUILD-INFO rustc is invalid' ;; esac
recorded_sha=$(build_info binary_sha256)
[[ "$recorded_sha" =~ ^[0-9a-f]{64}$ ]] || die 'BUILD-INFO binary_sha256 is invalid'
actual_sha=$(sha256sum bin/rustopnsmcp | cut -d' ' -f1)
[[ "$actual_sha" == "$recorded_sha" ]] || die 'BUILD-INFO binary_sha256 does not match bin/rustopnsmcp'
grep -q '"bomFormat": *"CycloneDX"' SBOM.cdx.json || die 'SBOM.cdx.json is not CycloneDX'
# The glibc floor is a property of the binary; refuse a host that is too old
# rather than install something that dies at first start.
floor=$(build_info glibc_floor)
host_glibc=$(getconf GNU_LIBC_VERSION | awk '{print $2}')
oldest=$(printf '%s\n%s\n' "$floor" "$host_glibc" | sort -V | head -n 1)
[[ "$oldest" == "$floor" ]] || die "this package needs glibc >= $floor; this host has $host_glibc"
if [[ "$check_only" == 1 ]]; then echo 'package ok'; exit 0; fi

# --- 2. Host checks ----------------------------------------------------------
if [[ -z "$test_root" ]]; then
    [[ "$(id -u)" -eq 0 ]] || die 'must run as root'
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ "${ID:-}" == debian && "${VERSION_ID:-}" == 13 ]] \
        || die "requires Debian 13 (detected ${ID:-unknown} ${VERSION_ID:-unknown})"
fi
# The binary is never executed here, so BUILD-INFO target is the only guard
# against an archive built for another architecture.
machine=$(uname -m)
[[ -z "$test_root" ]] || machine=${OPNSMCP_INSTALL_TEST_MACHINE:-$machine}
case "$machine" in
    x86_64) want_target=x86_64-unknown-linux-gnu ;;
    aarch64) want_target=aarch64-unknown-linux-gnu ;;
    *) die "unsupported machine architecture: $machine" ;;
esac
[[ "$(build_info target)" == "$want_target" ]] \
    || die "this package targets $(build_info target); this host ($machine) needs $want_target"

# An existing binary means this is an upgrade: a plain start would be a no-op
# on the running old process, so the printed steps must say restart.
start_verb=start
[[ ! -e "$(dest /usr/local/bin/rustopnsmcp)" ]] || start_verb=restart

# --- 3. Preflight: refuse a bad destination before the first mutation ---------
# Owners are only checkable as root; in test mode the invoking user stands in,
# and OPNSMCP_INSTALL_TEST_EXPECT_OWNER lets a test exercise the refusal.
me="$(id -un):$(id -gn)"
expect_file_owner="$svc:$svc"; expect_etc_owner="root:$svc"
if [[ -n "$test_root" ]]; then
    expect_file_owner=${OPNSMCP_INSTALL_TEST_EXPECT_OWNER:-$me}
    expect_etc_owner=${OPNSMCP_INSTALL_TEST_EXPECT_OWNER:-$me}
fi
# A wrong existing file is refused, never silently changed: it is the operator's.
check_existing() { # <path> <kind: file|dir> <mode> <owner:group>
    local path=$1 kind=$2 mode=$3 owner=$4 actual
    [[ -e "$path" || -L "$path" ]] || return 0
    if [[ -L "$path" ]]; then die "$path is a symlink; refusing"; fi
    if [[ "$kind" == file && ! -f "$path" ]]; then die "$path is not a regular file; refusing"; fi
    if [[ "$kind" == dir && ! -d "$path" ]]; then die "$path is not a directory; refusing"; fi
    actual=$(stat -c '%U:%G %a' -- "$path")
    [[ "$actual" == "$owner $mode" ]] \
        || die "$path is $actual, expected $owner $mode; fix with: chown ${owner} $path && chmod $mode $path"
}
check_existing "$(dest /etc/rustopnsmcp)" dir 750 "$expect_etc_owner"
check_existing "$(dest /var/lib/rustopnsmcp)" dir 700 "$expect_file_owner"
check_existing "$(dest /var/lib/rustopnsmcp/tokens.json)" file 600 "$expect_file_owner"
check_existing "$(dest /var/lib/rustopnsmcp/changeset-state.json)" file 600 "$expect_file_owner"
check_existing "$(dest /etc/rustopnsmcp/audit-hmac.key)" file 600 "$expect_file_owner"
check_existing "$(dest /etc/rustopnsmcp/devices.json)" file 600 "$expect_file_owner"
check_existing "$(dest /etc/rustopnsmcp/credentials.env)" file 600 "$expect_file_owner"

echo "==> Installing $svc $(build_info version)"
install -d "$(dest /usr/lib/sysusers.d)" "$(dest /usr/lib/tmpfiles.d)"
install -m 0644 packaging/systemd/rustopnsmcp.sysusers "$(dest /usr/lib/sysusers.d/rustopnsmcp.conf)"
install -m 0644 packaging/systemd/rustopnsmcp.tmpfiles "$(dest /usr/lib/tmpfiles.d/rustopnsmcp.conf)"
if [[ -z "$test_root" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates
    systemd-sysusers /usr/lib/sysusers.d/rustopnsmcp.conf
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/rustopnsmcp.conf
else
    mkdir -p "$(dest /etc/rustopnsmcp)" "$(dest /var/lib/rustopnsmcp)"
    chmod 0750 "$(dest /etc/rustopnsmcp)"; chmod 0700 "$(dest /var/lib/rustopnsmcp)"
fi
# Ownership is set by install at creation, never by a later chown: the state
# directory is service-writable, so a path-based chown could be raced into
# following a symlink. Only unprivileged test mode cannot set an owner.
owner_args=(-o "$svc" -g "$svc")
[[ -z "$test_root" ]] || owner_args=()

install -d "$(dest /usr/local/bin)"
install -m 0755 bin/rustopnsmcp "$(dest /usr/local/bin/rustopnsmcp)"

# Provision a file only if absent. The preflight already refused a bad
# existing file; this re-checks the type in case it changed since.
provision() { # <dest> <mode> <source file>
    local path=$1 mode=$2 source=$3
    if [[ -L "$path" ]] || { [[ -e "$path" ]] && [[ ! -f "$path" ]]; }; then
        die "$path is not a regular file; refusing"
    fi
    if [[ -e "$path" ]]; then echo "    $path exists; not overwriting"; return 0; fi
    install "${owner_args[@]}" -m "$mode" "$source" "$path"
}
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT

printf '%s\n' '{"version":1,"tokens":[]}' >"$scratch/tokens.json"
provision "$(dest /var/lib/rustopnsmcp/tokens.json)" 0600 "$scratch/tokens.json"

# 32 random bytes; the service refuses a key it does not own, so this must be
# rustopnsmcp-owned 0600 and is never regenerated.
head -c 32 /dev/urandom >"$scratch/audit-hmac.key"
provision "$(dest /etc/rustopnsmcp/audit-hmac.key)" 0600 "$scratch/audit-hmac.key"

# A minimal inventory the service can start on (do not install a config that
# cannot boot). The example, with placeholder names, is beside it.
printf '%s\n' '{"version":1,"devices":{}}' >"$scratch/devices.json"
provision "$(dest /etc/rustopnsmcp/devices.json)" 0600 "$scratch/devices.json"
install -m 0644 config/devices.json.example "$(dest /etc/rustopnsmcp/devices.example.json)"
printf '%s\n' '# OPNSENSE_FW_1_API_KEY=' '# OPNSENSE_FW_1_API_SECRET=' >"$scratch/credentials.env"
provision "$(dest /etc/rustopnsmcp/credentials.env)" 0600 "$scratch/credentials.env"

# The unit is package-owned: site changes belong in override.conf. If the
# installed unit differs from the one shipped, keep a copy rather than lose it.
unit_path=$(dest /etc/systemd/system/rustopnsmcp.service)
install -d "$(dest /etc/systemd/system)" "$(dest /etc/systemd/system/rustopnsmcp.service.d)"
if [[ -f "$unit_path" ]] && ! cmp -s "$unit_path" packaging/systemd/rustopnsmcp.service; then
    backup="$unit_path.bak-$(date +%Y%m%d%H%M%S)"
    cp -p "$unit_path" "$backup"
    echo "    NOTE: the installed unit differed from the packaged one; kept as $backup"
    echo "          Put site changes (bind address, TLS, allowed hosts) in"
    echo "          /etc/systemd/system/rustopnsmcp.service.d/override.conf"
fi
install -m 0644 packaging/systemd/rustopnsmcp.service "$unit_path"

# Fleet journald policy, by its numbered name, only if no such file exists. A
# numbered file sorts before an unnumbered one and would otherwise be overridden.
journald_dir=$(dest /etc/systemd/journald.conf.d)
install -d "$journald_dir"
if [[ ! -e "$journald_dir/20-audit-retention.conf" ]]; then
    install -m 0644 packaging/journald/mecmcp.conf "$journald_dir/20-audit-retention.conf"
fi
install -d "$(dest /etc/logrotate.d)"
install -m 0644 packaging/logrotate/rustopnsmcp-audit "$(dest /etc/logrotate.d/rustopnsmcp-audit)"

if [[ -z "$test_root" ]]; then
    systemctl daemon-reload
    systemctl reload-or-restart systemd-journald.service
fi

cat <<EOF

==> Installation complete. Nothing has been started or restarted. Next steps (run them as root):
  1. Edit /etc/rustopnsmcp/devices.json (see devices.example.json beside it);
     keep it mode 0600, owned by rustopnsmcp:rustopnsmcp.
  2. Put the OPNsense API key and secret in /etc/rustopnsmcp/credentials.env
     (mode 0600), named as the inventory's api_key_env / api_secret_env say.
  3. Mint a token (run as the service user; runuser is part of util-linux; the
     absolute path is needed because a root shell may lack /usr/local/bin on PATH).
     Read-only: '*' means every read tool and NO write tool:
       runuser -u rustopnsmcp -- /usr/local/bin/rustopnsmcp token add \\
           --tokens-file /var/lib/rustopnsmcp/tokens.json \\
           --name operator --devices '*' --tools '*'
     To create, approve and apply change sets, name the write tools AND the reads
     the workflow needs (create needs the fingerprint). A tool list is exact: no
     wildcard mixing, so '*' cannot be combined with names:
       runuser -u rustopnsmcp -- /usr/local/bin/rustopnsmcp token add \\
           --tokens-file /var/lib/rustopnsmcp/tokens.json \\
           --name changer --devices '*' \\
           --tools 'get_opnsense_config_fingerprint,get_opnsense_change_set_status,list_opnsense_change_sets,create_opnsense_change_set,approve_opnsense_change_set,apply_opnsense_change_set,confirm_opnsense_change_set,cancel_opnsense_change_set'
  4. For a non-loopback bind or TLS, create the drop-in ($package_dir/docs/operations.md):
       cp "$package_dir/packaging/systemd/rustopnsmcp.override.conf.example" \
          /etc/systemd/system/rustopnsmcp.service.d/override.conf   # then edit it
  5. systemctl $start_verb rustopnsmcp && curl -fsS http://127.0.0.1:30037/readyz
  6. systemctl enable rustopnsmcp
Before an upgrade, snapshot this container.
EOF
