# OPNsense MCP server container image
#
# Multi-stage build producing a distroless image with no shell and no external
# binaries. The runtime has no package manager, no shell, and no GNU userland —
# only libc, libgcc_s and the server binary.
#
# Builder glibc generation must be <= runtime generation: Debian 13 (trixie) on
# both sides satisfies this. Building on a newer base (Debian 14+) would link
# against a newer glibc that the Debian 13 runtime does not carry.

# Source of libgcc-s1 only; the runtime is base-nossl, which lacks it. Kept
# ahead of the builder so the runtime stays the last FROM.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:29ee70762214fe8190cea04ef1c0a84a8365879e047ce8f911ae5a5ab2355fa2 AS libgcc

# Builder stage: Debian 13 slim with Rust 1.98.1, matching rust-toolchain.toml.
# Pinned to the multi-arch image index digest (matches what `rust:1.98-slim-trixie`
# resolves to as of this pin; same digest rustunifimcp pins for that floating tag).
FROM rust:1.99.1-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7 AS builder

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
# unwritable by uid 65532. A named volume seeded from the image inherits the
# directory modes, so set the packaging/FILESYSTEM.md modes here. The COPYs
# below take the parent directories (holding only rustopnsmcp/): copying an
# empty directory's contents creates the destination 0755 and drops the mode,
# whereas a copied entry keeps its own.
RUN mkdir -p /image/etc/rustopnsmcp /image/var/lib/rustopnsmcp && \
    chmod 0750 /image/etc/rustopnsmcp && \
    chmod 0700 /image/var/lib/rustopnsmcp

# libgcc_s.so.1 is the one library the binary needs beyond glibc, and
# base-nossl does not ship it. Stage it with its dpkg records (status.d) so
# Trivy and the SBOM still see libgcc-s1 and gcc-14-base. The multiarch
# directory comes from the builder's own triplet (x86_64 or aarch64).
COPY --from=libgcc / /cc/
RUN triplet="$(gcc -dumpmachine | sed 's/-pc-/-/')" \
    && install -d "/stage-libgcc/usr/lib/${triplet}" /stage-libgcc/var/lib/dpkg/status.d \
    && cp -a "/cc/usr/lib/${triplet}/libgcc_s.so.1" "/stage-libgcc/usr/lib/${triplet}/" \
    && cp -a /cc/var/lib/dpkg/status.d/libgcc-s1 /cc/var/lib/dpkg/status.d/libgcc-s1.md5sums \
        /cc/var/lib/dpkg/status.d/gcc-14-base /cc/var/lib/dpkg/status.d/gcc-14-base.md5sums \
        /stage-libgcc/var/lib/dpkg/status.d/

# Runtime stage: distroless base-nossl, Debian 13, nonroot user. No
# libssl3t64/libcrypto: the binary is rustls-only, and libssl3t64 carries
# unfixed CVE-2026-124709. Pinned to the multi-arch image index digest.
FROM gcr.io/distroless/base-nossl-debian13:nonroot@sha256:89815d620ac01d8de13cdaf04d19ed874447ca2296d4985b14b818f6e5e47854

USER 65532:65532

# No HEALTHCHECK: distroless has no shell and no utilities, so there is
# nothing for a healthcheck command to run. Orchestrators supervise the
# process via the container runtime.

COPY --from=builder /stage-libgcc/ /
COPY --from=builder /build/target/release/rustopnsmcp /usr/local/bin/rustopnsmcp
COPY --from=builder --chown=65532:65532 /image/etc/ /etc/
COPY --from=builder --chown=65532:65532 /image/var/lib/ /var/lib/

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
