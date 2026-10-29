#!/usr/bin/env bash
# Build rustopnsmcp for Debian 13 in the official Rust image, at the toolchain in rust-toolchain.toml.
# The workstation's glibc is newer than Debian 13's, so a host-built binary does not start on a rig.
# Builds only; nothing is pushed anywhere.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
version=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$root/rust-toolchain.toml")
cache="${P3_BUILD_CACHE:-$HOME/.cache/rustopnsmcp-p3-trixie}"; mkdir -p "$cache/target" "$cache/cargo"
docker run --rm --user "$(id -u):$(id -g)" \
  -e HOME=/tmp -e RUSTUP_HOME=/usr/local/rustup -e RUSTUP_TOOLCHAIN="$version" \
  -e CARGO_HOME=/cache/cargo -e CARGO_TARGET_DIR=/cache/target \
  -v "$root":/src:ro -v "$cache":/cache -w /src "rust:${version}-trixie" \
  cargo build --release --locked -p rustopnsmcp
bin="$cache/target/release/rustopnsmcp"
glibc=$(objdump -T "$bin" | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -1)
echo "$bin needs $glibc"
[ "$(printf '%s\nGLIBC_2.41\n' "$glibc" | sort -V | tail -1)" = GLIBC_2.41 ] \
  || { echo "needs glibc newer than Debian 13's 2.41" >&2; exit 1; }
