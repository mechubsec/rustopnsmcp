# OPNsense MCP server container image
#
# Multi-stage build producing a distroless image with no shell and no external
# binaries. The runtime has no package manager, no shell, and no GNU userland —
# only libc and the statically-linked server binary.
#
# Builder glibc generation must be <= runtime generation: Debian 13 (trixie) on
# both sides satisfies this. Building on a newer base (Debian 14+) would link
# against a newer glibc that the Debian 13 runtime does not carry.

# Builder stage: Debian 13 slim with Rust 1.98.1, matching rust-toolchain.toml.
# Pinned to the multi-arch image index digest (matches what `rust:1.98-slim-trixie`
# resolves to as of this pin; same digest rustunifimcp pins for that floating tag).
FROM rust:1.98.1-slim-trixie@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7 AS builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy workspace manifests first for better layer caching.
COPY Cargo.toml Cargo.lock ./
COPY rustopnsmcp/Cargo.toml rustopnsmcp/
COPY rustopnsmcp-core/Cargo.toml rustopnsmcp-core/

# Create stub sources to cache dependencies.
RUN mkdir -p rustopnsmcp/src rustopnsmcp-core/src && \
    echo 'fn main() {}' > rustopnsmcp/src/main.rs && \
    echo '' > rustopnsmcp-core/src/lib.rs && \
    cargo build --release && \
    rm -rf rustopnsmcp/src rustopnsmcp-core/src

# Copy source and build the real binary.
COPY rustopnsmcp/ rustopnsmcp/
COPY rustopnsmcp-core/ rustopnsmcp-core/
RUN touch rustopnsmcp/src/main.rs rustopnsmcp-core/src/lib.rs && \
    cargo build --release --locked

# Directories the nonroot runtime must own. Distroless has no shell to create
# them, and a named volume mounted over a missing path would be root-owned and
# unwritable by uid 65532. COPY keeps the mode, and a named volume seeded from
# the image inherits it, so set the packaging/FILESYSTEM.md modes here and again on the COPY
# (the destination directory does not always take the source mode).
RUN mkdir -p /image/etc/rustopnsmcp /image/var/lib/rustopnsmcp && \
    chmod 0750 /image/etc/rustopnsmcp && \
    chmod 0700 /image/var/lib/rustopnsmcp

# Runtime stage: distroless Debian 13 with nonroot user. Pinned to the
# multi-arch image index digest (same digest rustunifimcp pins for `nonroot`).
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e

USER 65532:65532

# No HEALTHCHECK: distroless has no shell and no utilities, so there is
# nothing for a healthcheck command to run. Orchestrators supervise the
# process via the container runtime.

COPY --from=builder /build/target/release/rustopnsmcp /usr/local/bin/rustopnsmcp
COPY --from=builder --chown=65532:65532 --chmod=0750 /image/etc/rustopnsmcp /etc/rustopnsmcp
COPY --from=builder --chown=65532:65532 --chmod=0700 /image/var/lib/rustopnsmcp /var/lib/rustopnsmcp

VOLUME ["/etc/rustopnsmcp", "/var/lib/rustopnsmcp"]

LABEL org.opencontainers.image.title="rustopnsmcp"
LABEL org.opencontainers.image.description="OPNsense MCP server"
LABEL org.opencontainers.image.source="https://github.com/mechubsec/rustopnsmcp"
LABEL org.opencontainers.image.licenses="MIT"

# ENTRYPOINT carries what must always hold: config paths, the state file, and
# the audit baseline. Docker replaces CMD when the caller supplies arguments,
# so none of these may live there. --audit-journald is absent on purpose:
# there is no journald socket in a container, and --audit-format json writes
# to stdout for the runtime to collect. The key lives in the state volume (the
# only writable mount) and the binary creates it on first start.
ENTRYPOINT ["/usr/local/bin/rustopnsmcp", \
    "--device-mapping", "/etc/rustopnsmcp/devices.json", \
    "--tokens-file", "/var/lib/rustopnsmcp/tokens.json", \
    "--state-file", "/var/lib/rustopnsmcp/changeset-state.json", \
    "--inventory-readonly", \
    "--audit-format", "json", \
    "--audit-redact", "devices=hmac", \
    "--audit-hmac-key-file", "/var/lib/rustopnsmcp/audit-hmac.key"]
# CMD carries only what an operator is expected to replace.
CMD ["--transport", "streamable-http", \
    "--host", "127.0.0.1", \
    "--port", "30037"]
