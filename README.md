<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rustopnsmcp</h1>

<p align="center"><strong>Enterprise MCP server for OPNsense — curated tools, scoped access, audited change control</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This is an independent community project and does not claim affiliation with or endorsement by Deciso B.V. or the OPNsense project. Product names and trademarks are used only to identify the systems with which the software interoperates.

---

`rustopnsmcp` is the OPNsense member of the mechub MCP server family. It does
for OPNsense what [`rustjunosmcp`](https://github.com/mechubsec/rustjunosmcp)
does for Junos, [`rustpanosmcp`](https://github.com/mechubsec/rustpanosmcp)
for PAN-OS and [`rustunifimcp`](https://github.com/mechubsec/rustunifimcp)
for UniFi: a curated, scoped, audited MCP surface over one vendor's management
API.

It is built **mecmcp-native**: authentication, transport, audit, policy,
inventory, redaction and change control all come from
[`mecmcp`](https://github.com/mechubsec/mecmcp), the shared Rust foundation.
What lives here is the OPNsense resource model, the tool surface and the
workflows.

## Status

**Verified against OPNsense 26.7.5 (opnsense-lab):** reads, the configuration
fingerprint, alias and filter-rule change sets, and a forced partial apply.

v1.0 will cover OPNsense reads, governed alias and filter-rule writes through
mecmcp change sets (plan, digest, approval, apply with a drift check), scoped
tokens and audit, all over the OPNsense REST API with an API key and secret
from the environment or an owner-only file; TLS is always verified.

Limits, stated plainly:

- Writes persist to `config.xml` immediately and take effect on `apply`; a
  partial apply is a reachable, reported outcome.
- `confirm_timeout_mins` is refused until filter-rule commit-confirm lands.
- Automatic and legacy filter rules can be listed but not changed.
- NAT port forwards are not listed yet (deferred to P4/P5.2).
- Not yet released or packaged.

### Tools

| Group | Tools |
|---|---|
| Fleet | `get_device_list`, `gather_device_facts`, `opnsmcp_status`, `add_device`, `reload_devices` |
| Reads | `get_opnsense_system_status`, `get_opnsense_firmware_status`, `list_opnsense_interfaces`, `list_opnsense_firewall_rules`, `list_opnsense_aliases`, `list_opnsense_nat_rules`, `list_opnsense_routes`, `list_opnsense_gateways`, `list_opnsense_dhcp_leases` |
| Change control | `get_opnsense_config_fingerprint`, `create_opnsense_change_set`, `approve_opnsense_change_set`, `apply_opnsense_change_set`, `confirm_opnsense_change_set`, `cancel_opnsense_change_set`, `get_opnsense_change_set_status`, `list_opnsense_change_sets` |

Design and scope: [mecmcp#425](https://github.com/mechubsec/mecmcp/issues/425).

## License

Licensed under [MIT](LICENSE).

## Documentation

- [Operating rustopnsmcp](docs/OPERATIONS.md): SIGHUP reload, health, audit, upgrades.
- [Filesystem layout](packaging/FILESYSTEM.md): paths, owners and modes for the LXC package.
- [Set up in a Debian 13 LXC](docs/HOW-TO-SETUP-LXC.md): download, install, token, TLS override, journal forwarding.
- [Set up in Docker](docs/HOW-TO-SETUP-DOCKER.md): prepare mounts, mint a token, run, TLS, Compose.
- [Audit records](docs/AUDIT.md): fields, device pseudonyms, key custody, evidence pipeline flags.
- [Metrics](docs/METRICS.md): the `/metrics` endpoint and the series it returns.
- [Threat model](docs/THREAT-MODEL.md): assets, trust boundaries, controls and limits.
- [Changelog](CHANGELOG.md): what has changed, under Unreleased until the first release.
- [Contributing](CONTRIBUTING.md): the gates a change must pass and the public-repo rules.
