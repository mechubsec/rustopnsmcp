//! OPNsense REST API paths used by phase 1's read tools.
//!
//! OPNsense's core API follows a `/api/<module>/<controller>/<command>`
//! convention (<https://docs.opnsense.org/development/api.html>). The paths
//! below follow that documented convention and the module/controller names
//! OPNsense's own core plugins use. Read paths are verified against a live
//! OPNsense 26.7.5 (opnsense-lab); write verbs are not yet.
//!
//! Search-style endpoints (`search_*`) are OPNsense's paginated list
//! convention: a `POST` with a JSON body (`current`, `rowCount`, `searchPhrase`)
//! and a response shaped `{"rows": [...], "rowCount": N, "total": N, ...}`.

/// System status. Module `core`, controller `system`.
pub const SYSTEM_STATUS: &str = "/api/core/system/status";

/// System time: uptime, load average, boot time. Module `diagnostics`,
/// controller `system`.
pub const SYSTEM_TIME: &str = "/api/diagnostics/system/systemTime";

/// Firmware and installed-version status. Module `core`, controller `firmware`.
pub const FIRMWARE_STATUS: &str = "/api/core/firmware/status";

/// Interface overview. Module `interfaces`, controller `overview`.
pub const INTERFACES_OVERVIEW: &str = "/api/interfaces/overview/interfacesInfo";

/// Firewall filter rules, paginated search. Module `firewall`, controller `filter`.
///
/// `search_rule` iterates only the MVC ("automation") rule set. Legacy GUI
/// rules are merged in starting with OPNsense 25.1; on 24.7 and earlier this
/// endpoint returns a partial or empty list with nothing in the response to
/// signal the gap.
pub const FIREWALL_RULES_SEARCH: &str = "/api/firewall/filter/search_rule";

/// Firewall aliases, paginated search. Module `firewall`, controller `alias`.
pub const ALIASES_SEARCH: &str = "/api/firewall/alias/search_item";

/// Per-alias `pf` table size and last-update time, keyed by alias name under
/// `details`. Module `firewall`, controller `alias`. Read-only.
pub const ALIASES_TABLE_SIZE: &str = "/api/firewall/alias/getTableSize";

/// The live `pf` table entries of one alias. Module `firewall`, controller
/// `alias_util`; `listAction($alias)` pages like `search_*` and treats
/// `rowCount: -1` as "all rows". `alias` must already have passed
/// `crate::tools::feed::validate_alias_name`, since it is interpolated.
#[must_use]
pub fn alias_util_list(alias: &str) -> String {
    format!("/api/firewall/alias_util/list/{alias}")
}

/// Create a firewall alias. Module `firewall`, controller `alias`.
///
/// Persists to `config.xml` immediately but does not take effect in the live
/// `pf` tables until [`ALIASES_RECONFIGURE`] runs — OPNsense's write API has
/// no discardable candidate, only a write-then-load two-step. A `POST` here
/// can still return HTTP 200 with `{"result": "failed", "validations": {...}}`
/// in the body; a caller must check `result`, not just the status code.
pub const ALIASES_ADD_ITEM: &str = "/api/firewall/alias/addItem";

/// Fetch one firewall alias by UUID. Module `firewall`, controller `alias`.
///
/// # Panics
///
/// Never: `uuid` must already have passed [`crate::client::validate_uuid`]
/// before this is called, since it is interpolated into the path.
#[must_use]
pub fn aliases_get_item(uuid: &str) -> String {
    format!("/api/firewall/alias/getItem/{uuid}")
}

/// Update a firewall alias by UUID. Module `firewall`, controller `alias`.
///
/// Same immediate-persist-but-not-loaded semantics as [`ALIASES_ADD_ITEM`].
#[must_use]
pub fn aliases_set_item(uuid: &str) -> String {
    format!("/api/firewall/alias/setItem/{uuid}")
}

/// Delete a firewall alias by UUID. Module `firewall`, controller `alias`.
#[must_use]
pub fn aliases_del_item(uuid: &str) -> String {
    format!("/api/firewall/alias/delItem/{uuid}")
}

/// Load staged alias definitions from `config.xml` into the live `pf` alias
/// tables. Module `firewall`, controller `alias`.
///
/// This is the closest thing OPNsense's alias API has to a commit: nothing
/// written by [`ALIASES_ADD_ITEM`], [`aliases_set_item`], or
/// [`aliases_del_item`] is live until this runs.
pub const ALIASES_RECONFIGURE: &str = "/api/firewall/alias/reconfigure";

/// Create a firewall filter rule. Module `firewall`, controller `filter`.
///
/// Same immediate-persist-but-not-loaded semantics as [`ALIASES_ADD_ITEM`]:
/// this writes to `config.xml` but has no effect on the live `pf` ruleset
/// until [`FILTER_APPLY`] runs. Targets the MVC ("automation") rule set —
/// see the [`FIREWALL_RULES_SEARCH`] caveat about legacy GUI rules.
pub const FILTER_ADD_RULE: &str = "/api/firewall/filter/addRule";

/// Fetch one firewall filter rule by UUID. Module `firewall`, controller `filter`.
///
/// # Panics
///
/// Never: `uuid` must already have passed [`crate::client::validate_uuid`]
/// before this is called, since it is interpolated into the path.
#[must_use]
pub fn filter_get_rule(uuid: &str) -> String {
    format!("/api/firewall/filter/getRule/{uuid}")
}

/// Update a firewall filter rule by UUID. Module `firewall`, controller `filter`.
///
/// Same immediate-persist-but-not-loaded semantics as [`FILTER_ADD_RULE`].
#[must_use]
pub fn filter_set_rule(uuid: &str) -> String {
    format!("/api/firewall/filter/setRule/{uuid}")
}

/// Delete a firewall filter rule by UUID. Module `firewall`, controller `filter`.
#[must_use]
pub fn filter_del_rule(uuid: &str) -> String {
    format!("/api/firewall/filter/delRule/{uuid}")
}

/// Load staged filter rule changes from `config.xml` into the live `pf`
/// ruleset. Module `firewall`, controller `filter`.
///
/// This is the closest thing OPNsense's filter API has to a commit: nothing
/// written by [`FILTER_ADD_RULE`], [`filter_set_rule`], or [`filter_del_rule`]
/// is live until this runs.
pub const FILTER_APPLY: &str = "/api/firewall/filter/apply";

/// Outbound NAT rules, paginated search. Module `firewall`, controller `source_nat`.
pub const NAT_OUTBOUND_SEARCH: &str = "/api/firewall/source_nat/search_rule";

/// 1:1 NAT rules, paginated search. Module `firewall`, controller `one_to_one`.
///
/// Outbound and 1:1 NAT only. Port forwards (destination NAT) have no
/// covering endpoint here — `DNatController` exists only on core master, not
/// on any released branch this phase targets.
pub const NAT_ONE_TO_ONE_SEARCH: &str = "/api/firewall/one_to_one/search_rule";

/// Static routes, paginated search. Module `routes`, controller `routes`.
pub const ROUTES_SEARCH: &str = "/api/routes/routes/search_route";

/// Gateway status. Module `routes`, controller `gateway`.
pub const GATEWAYS_STATUS: &str = "/api/routes/gateway/status";

/// Legacy ISC DHCPv4 leases. **Absent on 26.7.5** (404 seen on opnsense-lab);
/// used only when neither Dnsmasq nor Kea is enabled.
pub const DHCP_LEASES_SEARCH: &str = "/api/dhcpv4/leases/search_lease";

/// Dnsmasq settings. `dnsmasq.enable` is `"1"` when the Dnsmasq service is on. Seen on 26.7.5.
pub const DNSMASQ_SETTINGS_GET: &str = "/api/dnsmasq/settings/get";
/// Dnsmasq DHCP leases, paginated search. Seen on 26.7.5 (envelope with `rows`, `total`, `interfaces`).
pub const DNSMASQ_LEASES_SEARCH: &str = "/api/dnsmasq/leases/search";
/// Kea DHCPv4 settings. `dhcpv4.general.enabled` is `"1"` when Kea DHCPv4 is on. Seen on 26.7.5.
pub const KEA_DHCPV4_GET: &str = "/api/kea/dhcpv4/get";
/// Kea DHCPv4 leases, paginated search. Seen on 26.7.5 (envelope plus `stats` and `interfaces`).
pub const KEA_LEASES4_SEARCH: &str = "/api/kea/leases4/search";

/// Default page size for `search_*` endpoints when a tool call omits one.
pub const DEFAULT_ROW_COUNT: u32 = 200;
