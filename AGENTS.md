# Notes for coding agents

`rustopnsmcp` is an MCP server for OPNsense. This file is what an agent needs
to build, test and change it safely. Humans: see [CONTRIBUTING.md](CONTRIBUTING.md).

## Build and test

```sh
cargo build --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
```

`/tmp` is often a small tmpfs. A workspace build is large, so point cargo at a
disk with room before the first build:

```sh
export CARGO_TARGET_DIR="$HOME/.cache/rustopnsmcp-target"
```

The scripts honour `CARGO_TARGET_DIR`. Do not leave a `target/` inside a git
worktree on a small `/tmp`.

Rust is pinned in `rust-toolchain.toml`; the minimum supported version is in
`Cargo.toml` (`rust-version`) and CI checks it.

## Layout

Two crates in one workspace:

- `rustopnsmcp-core/` holds the OPNsense side and no server code: the HTTP
  client (`client.rs`), endpoint paths (`endpoints.rs`), device inventory
  (`inventory.rs`), errors, the tool-name registry (`tools/`) and the
  change-set logic (`changeset/`: fingerprint, pre-image, diff, validation,
  sequential apply and rollback).
- `rustopnsmcp/` is the binary: CLI (`cli.rs`), startup decisions
  (`startup.rs`), the HTTP transport and its preflight (`http_transport.rs`), the
  change-set state file (`changeset_state.rs`) and the MCP server
  (`server/`: tool handlers, the change-set lifecycle, per-call audit).

Everything shared (authentication, transport, audit, redaction, change control)
comes from the `mecmcp-*` crates at one pinned tag. Do not reimplement it here.

Packaging and docs live outside the crates: `packaging/` (systemd unit and
override example, installer, logrotate fragment, container Compose example,
packaging tests), `scripts/`, `docs/`, and the `Dockerfile`.

## Gates to run before you finish

- The four cargo commands above.
- `scripts/check-mecmcp-pin.sh`: one mecmcp tag for every shared crate.
- `scripts/check-docs.sh`: documentation hygiene, links, flags and the
  embedded override example. Needs the debug binary.
- `scripts/parity-check.sh --junos-src <rustjunosmcp checkout>`: compares this
  server with `rustjunosmcp` on flags, subcommands, tool names, shipped files and
  unit paths. Every difference must be an entry in
  `scripts/parity-allowlist.txt`. A new file or flag may need an entry.
- For packaging changes: `shellcheck` and the scripts in `packaging/tests/`.

Prove a new test can fail: break the code it covers, watch it fail, then
restore the code. A green run says nothing about a change the test cannot see.

## Rules that are easy to break

- **No real addresses, hostnames or credential paths in the repository.** Use
  `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and `example.org`. The
  lab device is "opnsense-lab". Never print or commit a secret.
- **A flag that is accepted but ignored is worse than one that is absent.**
  If the build cannot honour a flag, refuse startup and say why (see
  `refuse_unwired_flags` in `rustopnsmcp/src/startup.rs`).
- **No tool description may call a change set atomic.** OPNsense has no
  candidate configuration; a partial apply is a reachable outcome (a test
  enforces the wording).
- **Do not edit `ExecStart` in the packaged unit to add site settings.** That
  belongs in the override; keep the override example a superset of the stock
  flags (`packaging/tests/unit-contract.sh` checks it).
- **Documentation is code.** Run every command you document.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`
  when an agent made them, and stay small enough to review in one sitting.
