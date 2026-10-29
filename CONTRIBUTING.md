# Contributing

Thanks for helping. This is a community project; a maintainer reviews every
change. Security issues go through [SECURITY.md](SECURITY.md), not a public
issue.

## Before you open a pull request

Run these from the repository root. CI runs the same commands, and a pull
request cannot merge while any fails.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked
```

Run `cargo fmt --all` first if the format check fails. Two more gates are
plain scripts:

```sh
scripts/check-mecmcp-pin.sh
scripts/check-docs.sh
```

`scripts/check-docs.sh` needs the debug binary (`cargo build -p rustopnsmcp`
builds it). If you touch shell scripts or packaging, also run `shellcheck` on
`packaging/lxc/install.sh`, `scripts/*.sh` and `packaging/tests/*.sh`, and the
tests in `packaging/tests/`. They are listed in the `conformance` job of
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Keep the repository public-safe

This repository is public. Never commit a real IP address, hostname, credential
path, token or secret, in code, tests, fixtures or documentation. Use the
documentation values: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and
`example.org` or `*.example.org`. The lab device is called "opnsense-lab" in
text and its credentials are described, never quoted. The documentation gate
rejects any other IPv4 address (private ranges included), a `.local`, `.lan` or
similar name, any name under `mechub.org`, and a credential-looking path. A
secret scan runs on every push; do not bypass it.

## One mecmcp pin

Every `mecmcp-*` crate must resolve to the same git tag. Change them together
in `Cargo.toml`, with no `rev =` entries, and run `scripts/check-mecmcp-pin.sh`.
Two refs would give two copies of shared types the compiler treats as unrelated.

## Documentation

Every command, flag and path in the documentation must exist. The gate checks
flags against `rustopnsmcp --help` (and each subcommand's), relative links, and
`packaging/…` paths. A new file in `docs/` must be linked from the
README's Documentation list. The site override example inside
`docs/HOW-TO-SETUP-LXC.md` must stay identical to
`packaging/systemd/rustopnsmcp.override.conf.example`.

## Commits

Keep a commit small enough to review in one sitting. Commits made with Claude end
with the trailer:

```
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
```

Describe the change and the reason in the message. Add an entry to the
Unreleased section of [CHANGELOG.md](CHANGELOG.md) for anything an operator
would notice.
