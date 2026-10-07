//! The MCP tool surface.
//!
//! Reads follow the mechub convention: `list_opnsense_<noun>` for
//! collections and `get_opnsense_<noun>` for single objects or status (spec
//! §3.1). Change-set tools govern writes to firewall aliases and filter rules.

pub mod changeset;
pub mod read;

/// The sentence every tool description carries (spec §3.1: "Every tool
/// description states its redaction contract").
pub const REDACTION_CONTRACT: &str = "Output is redacted: values matching known secret \
    patterns (API keys and secrets, pre-shared keys, private keys, certificates, password \
    hashes) are replaced before being returned, and device-sourced content is marked as \
    untrusted.";

/// Every tool this server registers.
///
/// Kept in one place so `filter_tools_for_scope` and the registry guard read
/// the same list.
pub const TOOL_NAMES: &[&str] = &[
    "get_opnsense_system_status",
    "get_opnsense_firmware_status",
    "list_opnsense_interfaces",
    "list_opnsense_firewall_rules",
    "list_opnsense_aliases",
    "list_opnsense_nat_rules",
    "list_opnsense_routes",
    "list_opnsense_gateways",
    "list_opnsense_dhcp_leases",
    "get_opnsense_config_fingerprint",
    "create_opnsense_change_set",
    "approve_opnsense_change_set",
    "apply_opnsense_change_set",
    "opnsense_get_change_set",
];

/// The mutating tools, passed to `mecmcp_server::authorize_call`.
///
/// `opnsense_get_change_set` stays here until Task 14 replaces it with the
/// read-scope `get_opnsense_change_set_status`.
pub const WRITE_TOOLS: &[&str] = &[
    "create_opnsense_change_set",
    "approve_opnsense_change_set",
    "apply_opnsense_change_set",
    "opnsense_get_change_set",
];
