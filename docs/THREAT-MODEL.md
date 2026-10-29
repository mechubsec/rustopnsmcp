# Threat model

What `rustopnsmcp` protects, where it trusts and does not trust, and what each
control is enforced by. It describes this build. Controls that are planned but
not present are not listed as controls. Report a vulnerability as
[SECURITY.md](../SECURITY.md) describes.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| OPNsense API key and secret | Environment variables or owner-only files named by `devices.json`; `credentials.env` under systemd | They authenticate to the firewall with whatever privileges the OPNsense user has. |
| Bearer tokens | `/var/lib/rustopnsmcp/tokens.json` (a digest and scopes; the secret is shown once at mint) | A token is the caller's authority: its tool and device scope. |
| Audit HMAC key | `/etc/rustopnsmcp/audit-hmac.key` (`/var/lib/rustopnsmcp/` in Docker) | Links audit pseudonyms to device names. |
| Change-set state | `/var/lib/rustopnsmcp/changeset-state.json` | Plans, digests, approvals and outcomes; an approval is only as good as this file. |
| Device inventory | `/etc/rustopnsmcp/devices.json` | Decides which firewalls the server talks to. |
| The audit trail | journald, optionally a file and forwarded segments | The evidence of who did what. |

## Trust boundaries

1. **MCP caller to server.** Callers, including LLM agents, are untrusted. They
   present a bearer token over HTTP. Nothing a caller sends is trusted for
   identity or scope; client-asserted fields (`client_name`, `model_id`) are
   recorded as asserted.
2. **Server to OPNsense.** The server holds the API credentials and speaks HTTPS
   to the device API, always verifying the certificate. Device responses are
   untrusted content: output is redacted and marked as such before it reaches
   the caller.
3. **Operator (root on the guest) to server.** Root is trusted. The service
   user is not: it cannot write `/etc/rustopnsmcp`, so a compromised or
   manipulated server cannot change which devices it manages.

## Threats and controls

| Threat | Control | Enforced in |
|---|---|---|
| **Scope escape**: a token calls a tool or device it was not granted. | Tool and device scopes on every token. A wildcard tool scope covers reads only; the mutating tools must be named. The device argument is checked against the token's device scope in a preflight with no I/O, and malformed arguments are denied rather than skipped. A refusal is audited (`insufficient_scope`). | `build_preflight` in `rustopnsmcp/src/http_transport.rs`; `WRITE_TOOLS` in `rustopnsmcp-core/src/tools/mod.rs`. |
| **Credential exposure**: the device key or secret reaches a log, an error or a tool result. | Credentials are held as `OutboundSecret` values and joined into the Basic header inside one such value; error text from the device goes through the shared redactor; tool output is redacted. Inventory and credential files must be owner-only (`0600`) or the loader refuses them. Tokens are stored as digests. There is no option to skip TLS verification. | `rustopnsmcp-core/src/client.rs`, `inventory.rs`; `mecmcp-secret`, `mecmcp-redact`. |
| **Caller reaches the API surface from the network**: wrong host, wrong origin, plain-text token. | A non-loopback bind refuses to start without `--allowed-host` and `--allowed-origin`, and without TLS or an explicit `--allow-insecure-bind`. Requests with other `Host` or `Origin` get 421 / 403. Rate and concurrency limits return 429. | `mecmcp-transport`; the packaged unit binds loopback. |
| **A change applies only partly.** OPNsense has no candidate configuration: each write persists to `config.xml` at once, and only `reconfigure` loads them, so a failure midway is a reachable state. | Applied sequentially with the pre-image kept. A partial apply is reported as `partial` (or `partial_rollback_failed` when the rollback also failed) with the succeeded, attempted-and-failed and never-attempted mutations listed, and the change set is recorded `Failed`, never `Applied`. If `reconfigure` itself fails the writes are rolled back (`not_loaded`). The word "atomic" is never used for it (a test checks every tool description). | `rustopnsmcp-core/src/changeset/apply.rs`; `settled_state` in `rustopnsmcp/src/server/lifecycle.rs`. |
| **A GUI edit rides along with `reconfigure`.** Reconfigure loads the device's configuration, not only the server's writes. | A fingerprint of every alias and filter rule is taken at plan time and must match at apply, so an edit made between the two is refused (`refused_stale`) with nothing written; the approval window is bounded (`--approval-timeout-secs`, default 3600, from creation). **Residual:** a change an administrator saved but did not apply *before* the plan is part of the baseline and will be loaded. Check for pending changes in the GUI before planning. | `check_fingerprint` and `config_fingerprint`; `apply_sequentially`. |
| **Stale or substituted plan**: approving or applying something other than what was reviewed. | `expected_digest` is required on approve and apply and must equal the plan's digest; `expected_fingerprint` is required on apply. The approver must be a second principal with actor type `human`; the creator cannot approve and an agent or unattributed (stdio) caller cannot. Only `--lab-mode` waives approval, and the record then shows `approver: null`. | `rustopnsmcp/src/server/mod.rs`; `mecmcp-changeset`. |
| **Audit tampering**: someone with the service, or the guest, rewrites the trail. | Records go to journald, which the service cannot rewrite; forward the journal off the guest ([HOW-TO-SETUP-LXC.md](HOW-TO-SETUP-LXC.md)). Device names are keyed-hash pseudonyms. The optional evidence sinks ship hash-chained segments, signed when a key is given. An `--audit-log-file` is service-owned and **can** be rewritten by the service, so treat it as a convenience copy. | `mecmcp-audit`; the unit's `--audit-journald`. |
| **Inventory or state tampering through the server.** | `/etc/rustopnsmcp` is read-only to the service (`ProtectSystem=strict`), so adding a device is a root edit. `--inventory-readonly` makes `add_device` and `reload_devices` refuse. | The packaged unit; [FILESYSTEM.md](../packaging/FILESYSTEM.md). |
| **Metrics exposure.** | `/metrics` is off by default and, when on, answers loopback callers only ([METRICS.md](METRICS.md)). | `--enable-metrics`; `mecmcp-transport`. |
| **Supply chain**: a tampered or drifted build, dependency or action. | One `mecmcp` git pin for every shared crate, checked in CI (`scripts/check-mecmcp-pin.sh`). Release archives and images are signed keyless with cosign, and the archive carries a CycloneDX SBOM and a `BUILD-INFO` that the installer checks against the binary. Actions are pinned to commit SHAs, base images to digests; RustSec, `cargo-deny`, Trivy and a secret scan run in CI. | `.github/workflows/`; `scripts/package-lxc.sh`; `packaging/lxc/install.sh`. |

## Limits

- **`IPAddressAllow` is inert in an unprivileged LXC.** The unit sets
  `IPAddressDeny=any` and an allow list; systemd accepts and reports them, but
  cannot attach the cgroup BPF program there, so nothing is enforced
  ([OPERATIONS.md](OPERATIONS.md)). Do not count them as protection on an LXC.
- **There is no candidate configuration on OPNsense.** Nothing can be staged,
  checked and discarded on the device. Controls above reduce and report the
  consequence of a failure; they cannot prevent one.
- **No sandbox replaces a network ACL.** The unit's hardening (seccomp filter,
  no capabilities, read-only filesystem) limits what a compromised process can
  do on the guest, not who it can talk to. Restrict the guest at the network
  edge so it can reach only the management interfaces of the firewalls it
  manages, and only from the clients that should call it.
- **A token is bearer authority.** Anyone holding the secret has its scope. Mint
  narrow tokens, rotate them (`token rotate`), and revoke them (`token revoke`).
- **`--tools '*'` and `--devices '*'` are the widest scopes you can mint.** Name
  what is needed instead.
