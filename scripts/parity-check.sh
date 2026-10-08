#!/usr/bin/env bash
# P1 gate (spec §4): compare rustopnsmcp with rustjunosmcp on CLI flags,
# subcommands, tool-name patterns, shipped packaging files and the unit's file
# paths. Every difference must be explained by an active entry in
# scripts/parity-allowlist.txt; anything else fails the gate.
#
# Usage: scripts/parity-check.sh --junos-src DIR [--phase P1|P2|...|P7]
#   DIR is a checkout of mechubsec/rustjunosmcp at the ref being compared.
#   Both binaries are built with cargo (debug profile).
set -euo pipefail

phase="P1"
junos_src=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --junos-src) junos_src="$2"; shift 2 ;;
    --phase) phase="$2"; shift 2 ;;
    *) echo "usage: $0 --junos-src DIR [--phase P1..P7]" >&2; exit 2 ;;
  esac
done
case "$phase" in P[1-7]) ;; *) echo "--phase must be P1..P7" >&2; exit 2 ;; esac
if [ -z "$junos_src" ] || [ ! -f "$junos_src/rust-junosmcp/Cargo.toml" ]; then
  echo "--junos-src must point at a mechubsec/rustjunosmcp checkout" >&2
  exit 2
fi

root="$(git rev-parse --show-toplevel)"
allowlist="$root/scripts/parity-allowlist.txt"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
phase_number="${phase#P}"

# --- collect ----------------------------------------------------------------

cargo build -q --locked --manifest-path "$root/Cargo.toml" -p rustopnsmcp
cargo build -q --locked --manifest-path "$junos_src/Cargo.toml" -p rust-junosmcp
opns_bin="$root/target/debug/rustopnsmcp"
junos_bin="$junos_src/target/debug/rust-junosmcp"

flags() {
  "$1" --help | grep -oE '^\s+(-[A-Za-z], )?--[a-z0-9][a-z0-9-]*' \
    | grep -oE -- '--[a-z0-9-]+' | sort -u
}
subcommands() {
  "$1" --help | awk '/^Commands:/ {inside=1; next} /^$/ {inside=0} inside {print $1}' \
    | grep -vx help | sort -u
}
tool_names() {
  grep -rhoE '^\s+name = "[a-z0-9_]+"' "$@" | sed -E 's/.*"(.*)"/\1/' | sort -u
}
packaging_files() {
  git -C "$1" ls-files --cached --others --exclude-standard packaging scripts .github/workflows \
    | grep -v '^packaging/tests/fixtures/' \
    | sed -E 's/rust-junosmcp|rustopnsmcp/SVC/g' | sort -u
}
unit_paths() {
  grep -oE -- '--[a-z-]+ /[^ \\]+' "$1" \
    | sed -E 's#/(etc|var/lib)/(jmcp|rust-junosmcp|rustopnsmcp)(/|$)#/\1/SVC\3#' | sort -u
}

# The names every mechub server shares: fleet meta and the change-set flow.
PARITY_TOOLS='^(get_device_list|gather_device_facts|add_device|reload_devices|VENDORmcp_status|(create|approve|apply|confirm|cancel)_VENDOR_change_set|get_VENDOR_change_set_status|list_VENDOR_change_sets|get_VENDOR_[a-z_]*fingerprint)$'
# Every rustopnsmcp tool must have one of these shapes (spec §3.1).
OPNS_SHAPES='^((list|get)_VENDOR_[a-z0-9_]+|(create|approve|apply|confirm|cancel)_VENDOR_change_set|list_VENDOR_change_sets|get_device_list|gather_device_facts|add_device|reload_devices|VENDORmcp_status|upgrade_VENDOR_firmware|revert_VENDOR_config_backup|update_VENDOR_ids_rules)$'

flags "$opns_bin" > "$work/opns.flag"
flags "$junos_bin" > "$work/junos.flag"
subcommands "$opns_bin" > "$work/opns.subcommand"
subcommands "$junos_bin" > "$work/junos.subcommand"
tool_names "$root/rustopnsmcp/src/server" \
  | sed -E 's/opnsmcp/VENDORmcp/; s/opnsense/VENDOR/' | sort -u > "$work/opns.all-tools"
tool_names "$junos_src/rust-junosmcp/src" \
  | sed -E 's/srxmcp/VENDORmcp/; s/junos/VENDOR/' | sort -u > "$work/junos.all-tools"
{ grep -E "$PARITY_TOOLS" "$work/opns.all-tools" || true; } > "$work/opns.tool"
{ grep -E "$PARITY_TOOLS" "$work/junos.all-tools" || true; } > "$work/junos.tool"
packaging_files "$root" > "$work/opns.file"
packaging_files "$junos_src" > "$work/junos.file"
unit_paths "$root/packaging/systemd/rustopnsmcp.service" > "$work/opns.unit-path"
unit_paths "$junos_src/packaging/systemd/rust-junosmcp.service" > "$work/junos.unit-path"

# --- allowlist --------------------------------------------------------------
# kind|side|item|until|reason
#   kind:  flag, subcommand, tool, file, unit-path
#   side:  only-opns or only-junos
#   until: P2..P7 (accepted while the phase is earlier) or never

active="$work/allowlist.active"
: > "$active"
while IFS='|' read -r kind side item until reason; do
  case "$kind" in ''|'#'*) continue ;; esac
  if [ -z "${reason// /}" ]; then
    echo "FAIL[allowlist] entry has no reason: $kind|$side|$item"
    exit 1
  fi
  if [ "$until" != "never" ] && [ "$phase_number" -ge "${until#P}" ]; then
    continue
  fi
  printf '%s|%s|%s\n' "$kind" "$side" "$item" >> "$active"
done < "$allowlist"

# --- compare ----------------------------------------------------------------

failures=0
report() { # kind side item
  if grep -qxF -- "$1|$2|$3" "$active"; then
    echo "ok[$1] $2 (allowlisted): $3"
  else
    echo "FAIL[$1] $2: $3"
    failures=$((failures + 1))
  fi
}
for kind in flag subcommand tool file unit-path; do
  while IFS= read -r item; do
    [ -n "$item" ] && report "$kind" only-opns "$item"
  done < <(comm -23 "$work/opns.$kind" "$work/junos.$kind")
  while IFS= read -r item; do
    [ -n "$item" ] && report "$kind" only-junos "$item"
  done < <(comm -13 "$work/opns.$kind" "$work/junos.$kind")
done

while IFS= read -r tool; do
  if ! grep -qE "$OPNS_SHAPES" <<< "$tool"; then
    echo "FAIL[shape] tool name outside spec §3.1: $tool"
    failures=$((failures + 1))
  fi
done < "$work/opns.all-tools"

while IFS='|' read -r kind side item; do
  if [ "$side" = "only-opns" ]; then
    differs=$(comm -23 "$work/opns.$kind" "$work/junos.$kind" | grep -cxF -- "$item" || true)
  else
    differs=$(comm -13 "$work/opns.$kind" "$work/junos.$kind" | grep -cxF -- "$item" || true)
  fi
  [ "$differs" -gt 0 ] || echo "WARN[allowlist] no longer differs; remove the entry: $kind|$side|$item"
done < "$active"

if [ "$failures" -ne 0 ]; then
  echo "parity-check $phase: $failures unexplained difference(s)"
  exit 1
fi
echo "parity-check $phase: no unexplained differences"
