//! The nine read tools.
//!
//! Each function is transport-independent: it takes an already-resolved
//! [`OpnsenseClient`] and returns JSON, so the MCP wiring in the binary crate
//! is the only place that knows about `rmcp`.

use crate::client::OpnsenseClient;
use crate::endpoints;
use crate::error::OpnsenseError;
use crate::model::{SearchResponse, require_object};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Arguments shared by every read tool: which device to query.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
}

/// Arguments for every `list_opnsense_*` tool.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
    /// Free-text filter, matched against the resource's usual search fields.
    /// Refused by tools whose device endpoint cannot search.
    #[serde(default)]
    pub search_phrase: Option<String>,
    /// Page size, 1 to 1000. Defaults to 200.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Rows to skip. Must be a multiple of `limit`, because OPNsense pages by
    /// page number. Defaults to 0.
    #[serde(default)]
    pub offset: Option<u32>,
    /// Upper bound, in bytes, on the page's serialized rows: 1024 to 524288.
    /// Rows past the bound are dropped from the end and the result says
    /// `truncated_to_fit_max_bytes: true`.
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

/// Upper bound on `limit`.
const MAX_LIMIT: u32 = 1_000;

/// Upper bound on `search_phrase`, in bytes.
const MAX_SEARCH_PHRASE_BYTES: usize = 256;

/// Default and upper bound for `max_bytes`: the server's device-output cap.
pub const MAX_BYTES_CEILING: usize = 512 * 1024;

/// Lower bound for `max_bytes`: below this not even one row is useful.
pub const MIN_MAX_BYTES: usize = 1024;

/// A validated page request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRequest {
    /// Page size.
    pub limit: u32,
    /// Rows skipped; a multiple of `limit`.
    pub offset: u32,
    /// Byte bound on the page's serialized rows.
    pub max_bytes: usize,
}

/// One page of a collection, as every `list_opnsense_*` tool returns it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Page {
    /// The rows on this page.
    pub rows: Vec<serde_json::Value>,
    /// The collection's size, when the device reports it.
    pub total: Option<u32>,
    /// The page size requested.
    pub limit: u32,
    /// The offset requested.
    pub offset: u32,
    /// Where the next page starts; `null` on the last page or after
    /// truncation.
    pub next_offset: Option<u32>,
    /// Whether rows were dropped to fit `max_bytes`.
    pub truncated_to_fit_max_bytes: bool,
}

/// Validate a list request. Fail closed: nothing is clamped.
///
/// # Errors
/// Returns [`OpnsenseError::Config`] naming the first bound exceeded.
pub fn page_request(args: &ListArgs) -> Result<PageRequest, OpnsenseError> {
    let limit = args.limit.unwrap_or(endpoints::DEFAULT_ROW_COUNT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(OpnsenseError::Config(format!(
            "limit must be between 1 and {MAX_LIMIT}, got {limit}"
        )));
    }
    let offset = args.offset.unwrap_or(0);
    if !offset.is_multiple_of(limit) {
        return Err(OpnsenseError::Config(format!(
            "offset must be a multiple of limit ({limit}), got {offset}"
        )));
    }
    let max_bytes = args.max_bytes.unwrap_or(MAX_BYTES_CEILING);
    if !(MIN_MAX_BYTES..=MAX_BYTES_CEILING).contains(&max_bytes) {
        return Err(OpnsenseError::Config(format!(
            "max_bytes must be between {MIN_MAX_BYTES} and {MAX_BYTES_CEILING}, got {max_bytes}"
        )));
    }
    if let Some(phrase) = &args.search_phrase
        && phrase.len() > MAX_SEARCH_PHRASE_BYTES
    {
        return Err(OpnsenseError::Config(format!(
            "search_phrase must be at most {MAX_SEARCH_PHRASE_BYTES} bytes, got {}",
            phrase.len()
        )));
    }
    Ok(PageRequest {
        limit,
        offset,
        max_bytes,
    })
}

/// The `search_*` request body for a page.
fn search_body(args: &ListArgs, page: &PageRequest) -> serde_json::Value {
    serde_json::json!({
        "current": page.offset / page.limit + 1,
        "rowCount": page.limit,
        "searchPhrase": args.search_phrase.clone().unwrap_or_default(),
    })
}

/// Refuse `search_phrase` on a tool whose endpoint cannot search, instead of
/// ignoring it.
fn refuse_search_phrase(args: &ListArgs, tool: &str) -> Result<(), OpnsenseError> {
    if args.search_phrase.is_some() {
        return Err(OpnsenseError::Config(format!(
            "search_phrase is not supported by {tool}"
        )));
    }
    Ok(())
}

/// Build a page from one device page of rows, fitting it to `max_bytes`.
#[must_use]
pub fn page_from(rows: Vec<serde_json::Value>, total: Option<u32>, page: &PageRequest) -> Page {
    let fetched = rows.len();
    let sizes: Vec<usize> = rows
        .iter()
        .map(|row| serde_json::to_vec(row).map_or(usize::MAX, |bytes| bytes.len()))
        .collect();

    let mut kept = rows.len();
    let array_bytes = |count: usize| -> usize {
        let body: usize = sizes[..count]
            .iter()
            .fold(0, |sum, size| sum.saturating_add(*size));
        body.saturating_add(2)
            .saturating_add(count.saturating_sub(1))
    };
    while kept > 0 && array_bytes(kept) > page.max_bytes {
        kept -= 1;
    }
    let truncated = kept < fetched;
    let mut rows = rows;
    rows.truncate(kept);

    let end = page
        .offset
        .saturating_add(u32::try_from(fetched).unwrap_or(u32::MAX));
    let next_offset = match (truncated, total) {
        (true, _) => None,
        (false, Some(total)) if end < total => Some(end),
        (false, Some(_)) => None,
        (false, None) if fetched == page.limit as usize => Some(end),
        (false, None) => None,
    };

    Page {
        rows,
        total,
        limit: page.limit,
        offset: page.offset,
        next_offset,
        truncated_to_fit_max_bytes: truncated,
    }
}

/// Page a collection the device returns whole.
#[must_use]
pub fn page_slice(all: Vec<serde_json::Value>, page: &PageRequest) -> Page {
    let total = u32::try_from(all.len()).unwrap_or(u32::MAX);
    let start = (page.offset as usize).min(all.len());
    let end = start.saturating_add(page.limit as usize).min(all.len());
    let rows = all[start..end].to_vec();
    page_from(rows, Some(total), page)
}

/// Run one `search_*` page and shape it.
async fn search_page(
    client: &OpnsenseClient,
    path: &str,
    args: &ListArgs,
    page: &PageRequest,
) -> Result<Page, OpnsenseError> {
    let raw = client.post(path, &search_body(args, page)).await?;
    let parsed = SearchResponse::parse(&raw)?;
    Ok(page_from(parsed.rows, parsed.total, page))
}

fn to_json(page: &Page) -> Result<serde_json::Value, OpnsenseError> {
    serde_json::to_value(page).map_err(|error| OpnsenseError::Malformed(error.to_string()))
}

/// `get_opnsense_system_status`: the device's system status.
///
/// # Errors
/// Returns [`OpnsenseError`] on a transport failure, a non-2xx response, or a
/// response that is not a JSON object.
pub async fn system_status(client: &OpnsenseClient) -> Result<serde_json::Value, OpnsenseError> {
    let raw = client.get(endpoints::SYSTEM_STATUS).await?;
    require_object(&raw)?;
    Ok(raw)
}

/// `get_opnsense_firmware_status`: installed firmware and available-update status.
///
/// # Errors
/// As [`system_status`].
pub async fn firmware_status(client: &OpnsenseClient) -> Result<serde_json::Value, OpnsenseError> {
    let raw = client.get(endpoints::FIRMWARE_STATUS).await?;
    require_object(&raw)?;
    Ok(raw)
}

/// `list_opnsense_interfaces`: the interfaces overview, paged here.
///
/// The overview answers with `rows` as an object keyed by interface
/// identifier. Each entry becomes a row carrying that key as `identifier`,
/// sorted by identifier so pages are stable.
///
/// # Errors
/// As [`system_status`], and [`OpnsenseError::Config`] for a bad page request
/// or any `search_phrase`.
pub async fn list_interfaces(
    client: &OpnsenseClient,
    args: &ListArgs,
) -> Result<serde_json::Value, OpnsenseError> {
    refuse_search_phrase(args, "list_opnsense_interfaces")?;
    let page = page_request(args)?;
    let raw = client.get(endpoints::INTERFACES_OVERVIEW).await?;
    require_object(&raw)?;
    let mut all: Vec<serde_json::Value> = match raw.get("rows") {
        Some(serde_json::Value::Object(map)) => map
            .iter()
            .map(|(identifier, body)| {
                let mut row = body.clone();
                if let Some(object) = row.as_object_mut() {
                    object.insert(
                        "identifier".to_owned(),
                        serde_json::Value::String(identifier.clone()),
                    );
                }
                row
            })
            .collect(),
        Some(serde_json::Value::Array(rows)) => rows.clone(),
        _ => {
            return Err(OpnsenseError::Malformed(
                "interfacesInfo response has no rows".to_owned(),
            ));
        }
    };
    all.sort_by(|left, right| {
        let key = |row: &serde_json::Value| {
            row.get("identifier")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        key(left).cmp(&key(right))
    });
    to_json(&page_slice(all, &page))
}

/// `list_opnsense_gateways`: gateway status, paged here.
///
/// # Errors
/// As [`list_interfaces`].
pub async fn list_gateways(
    client: &OpnsenseClient,
    args: &ListArgs,
) -> Result<serde_json::Value, OpnsenseError> {
    refuse_search_phrase(args, "list_opnsense_gateways")?;
    let page = page_request(args)?;
    let raw = client.get(endpoints::GATEWAYS_STATUS).await?;
    require_object(&raw)?;
    let Some(items) = raw.get("items").and_then(serde_json::Value::as_array) else {
        return Err(OpnsenseError::Malformed(
            "gateway status response has no items".to_owned(),
        ));
    };
    to_json(&page_slice(items.clone(), &page))
}

/// `list_opnsense_firewall_rules`: firewall filter rules, one page.
///
/// # Errors
/// Returns [`OpnsenseError`] on a transport failure, a non-2xx response, or a
/// response missing the `rows` envelope.
pub async fn list_firewall_rules(
    client: &OpnsenseClient,
    args: &ListArgs,
) -> Result<serde_json::Value, OpnsenseError> {
    let page = page_request(args)?;
    to_json(&search_page(client, endpoints::FIREWALL_RULES_SEARCH, args, &page).await?)
}

/// `list_opnsense_aliases`: firewall aliases, one page.
///
/// # Errors
/// As [`list_firewall_rules`].
pub async fn list_aliases(
    client: &OpnsenseClient,
    args: &ListArgs,
) -> Result<serde_json::Value, OpnsenseError> {
    let page = page_request(args)?;
    to_json(&search_page(client, endpoints::ALIASES_SEARCH, args, &page).await?)
}

/// `list_opnsense_routes`: static routes, one page.
///
/// # Errors
/// As [`list_firewall_rules`].
pub async fn list_routes(
    client: &OpnsenseClient,
    args: &ListArgs,
) -> Result<serde_json::Value, OpnsenseError> {
    let page = page_request(args)?;
    to_json(&search_page(client, endpoints::ROUTES_SEARCH, args, &page).await?)
}

/// `list_opnsense_dhcp_leases`: DHCPv4 leases, one page.
///
/// # Errors
/// As [`list_firewall_rules`].
pub async fn list_dhcp_leases(
    client: &OpnsenseClient,
    args: &ListArgs,
) -> Result<serde_json::Value, OpnsenseError> {
    let page = page_request(args)?;
    to_json(&search_page(client, endpoints::DHCP_LEASES_SEARCH, args, &page).await?)
}

/// `list_opnsense_nat_rules`: outbound and 1:1 NAT rules, one page each.
///
/// OPNsense splits NAT across two controllers with no combined listing
/// endpoint, so this tool fetches both and returns them side by side rather
/// than making a caller learn the split to see NAT at all.
///
/// # Errors
/// As [`list_firewall_rules`], for either sub-request.
pub async fn list_nat_rules(
    client: &OpnsenseClient,
    args: &ListArgs,
) -> Result<serde_json::Value, OpnsenseError> {
    let page = page_request(args)?;
    // Two collections share one result, so each gets half the byte budget.
    let half = PageRequest {
        max_bytes: page.max_bytes / 2,
        ..page
    };
    let outbound = search_page(client, endpoints::NAT_OUTBOUND_SEARCH, args, &half).await?;
    let one_to_one = search_page(client, endpoints::NAT_ONE_TO_ONE_SEARCH, args, &half).await?;
    Ok(serde_json::json!({
        "outbound": to_json(&outbound)?,
        "one_to_one": to_json(&one_to_one)?,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn args(limit: Option<u32>, offset: Option<u32>, max_bytes: Option<usize>) -> ListArgs {
        ListArgs {
            device: "fw".to_owned(),
            search_phrase: None,
            limit,
            offset,
            max_bytes,
        }
    }

    fn rows(count: usize) -> Vec<serde_json::Value> {
        (0..count)
            .map(|index| serde_json::json!({ "uuid": format!("row-{index}") }))
            .collect()
    }

    #[test]
    fn defaults_are_the_first_page_of_200_under_the_ceiling() {
        let page = page_request(&args(None, None, None)).unwrap();
        assert_eq!(
            (page.limit, page.offset, page.max_bytes),
            (endpoints::DEFAULT_ROW_COUNT, 0, MAX_BYTES_CEILING)
        );
    }

    #[test]
    fn an_offset_that_is_not_a_multiple_of_limit_is_refused() {
        assert!(page_request(&args(Some(50), Some(75), None)).is_err());
        assert!(page_request(&args(Some(50), Some(100), None)).is_ok());
    }

    #[test]
    fn limit_and_max_bytes_are_bounded_without_clamping() {
        assert!(page_request(&args(Some(0), None, None)).is_err());
        assert!(page_request(&args(Some(MAX_LIMIT + 1), None, None)).is_err());
        assert!(page_request(&args(None, None, Some(MIN_MAX_BYTES - 1))).is_err());
        assert!(page_request(&args(None, None, Some(MAX_BYTES_CEILING + 1))).is_err());
    }

    #[test]
    fn the_search_body_asks_for_the_page_the_offset_names() {
        let list = ListArgs {
            search_phrase: Some("wan".to_owned()),
            ..args(Some(50), Some(100), None)
        };
        let page = page_request(&list).unwrap();
        let body = search_body(&list, &page);
        assert_eq!(body["current"], 3);
        assert_eq!(body["rowCount"], 50);
        assert_eq!(body["searchPhrase"], "wan");
    }

    #[test]
    fn next_offset_follows_the_total() {
        let page = page_request(&args(Some(2), Some(0), None)).unwrap();
        assert_eq!(page_from(rows(2), Some(5), &page).next_offset, Some(2));
        let last = page_request(&args(Some(2), Some(4), None)).unwrap();
        assert_eq!(page_from(rows(1), Some(5), &last).next_offset, None);
    }

    #[test]
    fn a_page_over_max_bytes_drops_rows_and_says_so() {
        let page = page_request(&args(Some(200), None, Some(MIN_MAX_BYTES))).unwrap();
        let fitted = page_from(rows(200), Some(1000), &page);
        assert!(fitted.truncated_to_fit_max_bytes);
        assert!(fitted.rows.len() < 200);
        assert_eq!(fitted.next_offset, None);
        assert!(serde_json::to_vec(&fitted.rows).unwrap().len() <= MIN_MAX_BYTES);
    }

    #[test]
    fn page_slice_pages_a_collection_the_device_does_not_page() {
        let page = page_request(&args(Some(2), Some(2), None)).unwrap();
        let sliced = page_slice(rows(5), &page);
        assert_eq!(sliced.rows, rows(5)[2..4].to_vec());
        assert_eq!(sliced.total, Some(5));
        assert_eq!(sliced.next_offset, Some(4));
    }

    #[test]
    fn search_phrase_is_bounded() {
        let too_long = ListArgs {
            search_phrase: Some("x".repeat(MAX_SEARCH_PHRASE_BYTES + 1)),
            ..args(None, None, None)
        };
        assert!(page_request(&too_long).is_err());
    }
}
