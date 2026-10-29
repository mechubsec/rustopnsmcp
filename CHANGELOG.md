# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will
follow [Semantic Versioning](https://semver.org/) once it has a release. Nothing
has been released yet, so everything is under Unreleased.

## [Unreleased]

### Added

- OPNsense read tools over the REST API, with the API key and secret taken from
  the environment or an owner-only file and TLS always verified.
- Governed writes through `mecmcp-changeset`: firewall aliases, then firewall
  filter rules, with a plan digest, a second-principal approval and a drift
  check at apply.
- Read tools renamed to the `list_opnsense_*` / `get_opnsense_*` convention, with
  `limit`, `offset` and `max_bytes` on every list tool.
- `get_opnsense_config_fingerprint`; `approve_opnsense_change_set` requires
  `expected_digest`; `apply_opnsense_change_set` binds the plan digest and the
  live fingerprint; confirm, cancel, status and list complete the change-set
  surface.
- Fleet tools: `get_device_list`, `gather_device_facts`, `opnsmcp_status`, and
  `add_device` with hardened credential handling.
- One audit record per `tools/call`, including calls rejected before a handler
  runs.
- The SSDF evidence pipeline and `--approval-digest-key-file`.
- Startup creates a missing audit HMAC key at first start.
- `/readyz` fails while a device refuses the API key.
- LXC packaging: a loopback systemd unit carrying the audit baseline, a site
  override example, a logrotate fragment for the audit file, and a reproducible
  tarball with `BUILD-INFO` and an SBOM.
- The LXC installer: it validates the package first, creates files already
  owned by the service user, preflights every destination, and refuses a wrong
  owner or mode instead of changing it.
- A container image brought to the Docker standard, and a Compose example.
- Operator documentation: an operations guide, the filesystem layout, setup
  guides for LXC and Docker, and audit, metrics and threat-model references.
- CI: package conformance on the real tarball and image; release workflows for
  the image (GHCR and Docker Hub) and the LXC tarball; a Trivy security
  workflow and Dependabot; a documentation gate (`scripts/check-docs.sh`).
- `scripts/parity-check.sh`, the gate that compares this server with
  `rustjunosmcp`.

### Changed

- All tool output goes through `mecmcp-redact`.
- A single `mecmcp` pin is enforced in CI; the pin is now `v0.30.1`.
- Startup refusals converge on the shared validator's exit helper.
- `BUILD-INFO` keeps `git_commit` a bare SHA and records a dirty tree in
  `git_dirty`.
- The README carries an under-construction notice and an affiliation
  disclaimer.

### Security

- Dependencies updated for published security fixes.
- The server refuses to start on an existing audit HMAC key that is unsafe
  (symlink, not a regular file, readable by others, or not owned by the service
  user); a new key is published only once complete.
- `token add --device-selector` is refused until the server supplies device
  attributes, rather than accepted and ignored.
- `add_device` credential handling and concurrent-write safety hardened.
- Release images and tarballs are signed keyless with cosign.
