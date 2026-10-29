//! `get_opnsense_feed_status`: which mecfeedmcp feeds a device subscribes to.
//!
//! On OPNsense a subscription is a URL-table alias whose URL path is one of
//! mecfeed-serve's `/feeds/opnsense-url-table/{address,prefix,domain}`. The
//! tool is read-only and reports, per matching URL, what the alias says and
//! what the firewall actually loaded.
//!
//! # `content_etag`
//!
//! mecfeed-serve's ETag is `"sha256-<hex>"` (quotes included) over the body
//! `render_feed` produces: the entries of one kind, as canonical text, sorted
//! byte-wise, joined by `\n`, with one trailing `\n` (empty body when there are
//! no entries). We rebuild that body from the alias's live pf table entries
//! (`alias_util/list`), applying these normalisations:
//!
//! - pf prints a host as a bare address, so for `address` a bare address, `/32`
//!   or `/128` all become the bare address (`IpAddr` display, as serve's
//!   canonical form is). Any other prefix length cannot be an address entry.
//! - for `prefix`, a bare address becomes `addr/32` or `addr/128`, and entries
//!   print as `addr/len`, as serve's canonical CIDR form does. A prefix with
//!   host bits set is not something serve emits, so the digest is withheld.
//! - for `domain`, pf tables hold resolved addresses, not names, so the body
//!   cannot be reproduced and the digest is always `null`.
//!
//! It is also `null` when the entry count disagrees with `table_count`, when
//! `table_count` is unknown (table not loaded), when the table is above
//! [`MAX_DIGEST_ENTRIES`], when the alias holds more than one URL (its table is
//! then a union of feeds), or when any entry fails the rules above. A wrong
//! digest would read as drift or as sync that is not real, so there is no
//! approximation.
//!
//! # Fetch errors
//!
//! Upstream (stable/26.7) logs a URL-table download failure to syslog only
//! (`alias resolve error`) and keeps the previous content. No API returns it,
//! so there is no `last_error` field.

use crate::client::OpnsenseClient;
use crate::endpoints;
use crate::error::OpnsenseError;
use crate::model::SearchResponse;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::net::IpAddr;

/// The path prefix every mecfeed-serve OPNsense document lives under.
const FEED_PATH_PREFIX: &str = "/feeds/opnsense-url-table/";

/// Above this many pf entries the digest is not computed (the table is not
/// downloaded at all); `content_etag` is `null`.
pub const MAX_DIGEST_ENTRIES: u64 = 50_000;

/// What a feed document holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedKind {
    /// Single IP addresses.
    Address,
    /// CIDR prefixes.
    Prefix,
    /// DNS names.
    Domain,
}

impl FeedKind {
    fn from_path(path: &str) -> Option<Self> {
        match path.strip_prefix(FEED_PATH_PREFIX)? {
            "address" => Some(Self::Address),
            "prefix" => Some(Self::Prefix),
            "domain" => Some(Self::Domain),
            _ => None,
        }
    }
}

/// One subscription: a URL-table alias and one mecfeed URL in its content.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FeedSubscription {
    /// Alias name.
    pub alias: String,
    /// Alias UUID.
    pub uuid: String,
    /// Whether the alias is enabled.
    pub enabled: bool,
    /// Feed URL without userinfo, query or fragment.
    pub url: String,
    /// Document kind.
    pub kind: FeedKind,
    /// Refresh interval in days (`updatefreq`), if set.
    pub update_frequency_days: Option<f64>,
    /// `authtype` (for example `Basic`). Credentials are never reported.
    pub auth: Option<String>,
    /// Entries the search row reports for the alias.
    pub current_items: Option<u64>,
    /// When OPNsense last refreshed the alias, as it reports it.
    pub last_updated: Option<String>,
    /// Entries in the loaded pf table; `null` when the table is not loaded.
    pub table_count: Option<u64>,
    /// The pf table's update time, as `getTableSize` reports it.
    pub table_updated: Option<Value>,
    /// mecfeed-serve's ETag recomputed from the pf table; see the module docs.
    pub content_etag: Option<String>,
}

/// An alias that was not examined, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedAlias {
    /// The alias name as the device gave it, cut to 64 characters.
    pub alias: String,
    /// Why it was skipped.
    pub reason: String,
}

/// The tool's result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FeedStatus {
    /// Subscriptions found.
    pub feeds: Vec<FeedSubscription>,
    /// Aliases not examined; absent when there are none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<SkippedAlias>,
}

/// Check an alias name against OPNsense's own rule before it is placed in a
/// URL path.
///
/// Mirrors `AliasNameField` (opnsense/core `stable/26.7`, validation regex
/// `^([a-zA-Z]|(([_a-zA-Z][a-zA-Z0-9]|[a-zA-Z][_a-zA-Z0-9])[_a-zA-Z0-9]{0,29}))$`):
/// ASCII letters, digits and underscore, 1 to 31 characters, starting with a
/// letter or a single underscore.
///
/// # Errors
/// Returns the reason the name is refused.
pub fn validate_alias_name(name: &str) -> Result<(), &'static str> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 31 {
        return Err("alias name must be 1 to 31 characters");
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return Err("alias name has characters outside [A-Za-z0-9_]");
    }
    let starts_ok = match bytes {
        [first] => first.is_ascii_alphabetic(),
        [b'_', second, ..] => second.is_ascii_alphanumeric(),
        [first, ..] => first.is_ascii_alphabetic(),
        [] => false,
    };
    if starts_ok {
        Ok(())
    } else {
        Err("alias name must start with a letter or a single underscore")
    }
}

/// Every URL line in a URL-table alias's content.
fn url_lines(content: &str) -> Vec<url::Url> {
    content
        .lines()
        .filter_map(|line| url::Url::parse(line.trim()).ok())
        .collect()
}

/// The mecfeed URLs in `content`, userinfo, query and fragment removed.
fn matching_urls(content: &str) -> Vec<(FeedKind, String)> {
    url_lines(content)
        .into_iter()
        .filter_map(|mut parsed| {
            let kind = FeedKind::from_path(parsed.path())?;
            parsed.host_str()?;
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.set_query(None);
            parsed.set_fragment(None);
            Some((kind, parsed.to_string()))
        })
        .collect()
}

fn text(row: &Value, key: &str) -> Option<String> {
    row.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// Parse a pf entry as `(address, prefix length)`; a bare address gets its
/// full length. `None` for anything else.
fn parse_entry(entry: &str) -> Option<(IpAddr, u8)> {
    let (address, length) = match entry.split_once('/') {
        Some((address, length)) => (address, Some(length.parse::<u8>().ok()?)),
        None => (entry, None),
    };
    let address: IpAddr = address.parse().ok()?;
    let full = if address.is_ipv4() { 32 } else { 128 };
    let length = length.unwrap_or(full);
    (length <= full).then_some((address, length))
}

fn host_bits_clear(address: IpAddr, length: u8) -> bool {
    match address {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(length)).unwrap_or(0);
            u32::from(v4) & !mask == 0
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(length)).unwrap_or(0);
            u128::from(v6) & !mask == 0
        }
    }
}

/// Rebuild mecfeed-serve's document from pf entries; `None` when it cannot be
/// reproduced exactly. See the module docs for the rules.
fn render_body(kind: FeedKind, entries: &[String]) -> Option<String> {
    let mut lines = Vec::with_capacity(entries.len());
    for entry in entries {
        let (address, length) = parse_entry(entry)?;
        let full = if address.is_ipv4() { 32 } else { 128 };
        match kind {
            FeedKind::Domain => return None,
            FeedKind::Address if length == full => lines.push(address.to_string()),
            FeedKind::Address => return None,
            FeedKind::Prefix if host_bits_clear(address, length) => {
                lines.push(format!("{address}/{length}"));
            }
            FeedKind::Prefix => return None,
        }
    }
    lines.sort_unstable();
    if lines.is_empty() {
        return Some(String::new());
    }
    let mut body = lines.join("\n");
    body.push('\n');
    Some(body)
}

/// mecfeed-serve's ETag for `body`, quotes included.
fn etag_of(body: &str) -> String {
    let digest = Sha256::digest(body.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("\"sha256-{hex}\"")
}

/// An alias row that holds at least one mecfeed URL, before table data.
struct Candidate {
    subscriptions: Vec<FeedSubscription>,
    /// Whether the alias content is exactly one URL line.
    single_url: bool,
}

/// Pick the subscriptions out of the alias search rows. Pure.
fn candidates(rows: &[Value]) -> (Vec<Candidate>, Vec<SkippedAlias>) {
    let mut found = Vec::new();
    let mut skipped = Vec::new();
    for row in rows {
        if row.get("type").and_then(Value::as_str) != Some("urltable") {
            continue;
        }
        let content = text(row, "content").unwrap_or_default();
        let urls = matching_urls(&content);
        if urls.is_empty() {
            continue;
        }
        let name = text(row, "name").unwrap_or_default();
        if let Err(reason) = validate_alias_name(&name) {
            skipped.push(SkippedAlias {
                alias: name.chars().take(64).collect(),
                reason: reason.to_owned(),
            });
            continue;
        }
        let single_url = url_lines(&content).len() == 1;
        let frequency = text(row, "updatefreq")
            .and_then(|value| value.parse::<f64>().ok())
            .filter(|value| value.is_finite());
        let subscriptions = urls
            .into_iter()
            .map(|(kind, url)| FeedSubscription {
                alias: name.clone(),
                uuid: text(row, "uuid").unwrap_or_default(),
                enabled: text(row, "enabled").as_deref() == Some("1"),
                url,
                kind,
                update_frequency_days: frequency,
                auth: text(row, "authtype"),
                current_items: text(row, "current_items").and_then(|value| value.parse().ok()),
                last_updated: text(row, "last_updated"),
                table_count: None,
                table_updated: None,
                content_etag: None,
            })
            .collect();
        found.push(Candidate {
            subscriptions,
            single_url,
        });
    }
    (found, skipped)
}

/// Fetch every pf entry of `alias`, or `None` when the device returns fewer
/// rows than `total` or a row without `ip`.
async fn table_entries(
    client: &OpnsenseClient,
    alias: &str,
) -> Result<Option<Vec<String>>, OpnsenseError> {
    let raw = client
        .post(
            &endpoints::alias_util_list(alias),
            &serde_json::json!({ "current": 1, "rowCount": -1, "searchPhrase": "" }),
        )
        .await?;
    let parsed = SearchResponse::parse(&raw)?;
    let entries: Option<Vec<String>> = parsed.rows.iter().map(|row| text(row, "ip")).collect();
    let complete = parsed
        .total
        .is_none_or(|total| usize::try_from(total).is_ok_and(|total| total == parsed.rows.len()));
    Ok(entries.filter(|_| complete))
}

/// `get_opnsense_feed_status`: the device's mecfeedmcp subscriptions.
///
/// # Errors
/// As [`crate::tools::read::system_status`]; the alias search, the table-size
/// read and each table listing must succeed.
pub async fn feed_status(client: &OpnsenseClient) -> Result<Value, OpnsenseError> {
    let raw = client
        .post(
            endpoints::ALIASES_SEARCH,
            &serde_json::json!({ "current": 1, "rowCount": -1, "searchPhrase": "" }),
        )
        .await?;
    let (found, skipped) = candidates(&SearchResponse::parse(&raw)?.rows);
    let mut feeds = Vec::new();
    if !found.is_empty() {
        let sizes = client.get(endpoints::ALIASES_TABLE_SIZE).await?;
        for candidate in found {
            let single_url = candidate.single_url;
            for mut subscription in candidate.subscriptions {
                let detail = sizes
                    .get("details")
                    .and_then(|details| details.get(&subscription.alias));
                subscription.table_count = detail
                    .and_then(|detail| detail.get("count"))
                    .and_then(Value::as_u64);
                subscription.table_updated = detail
                    .and_then(|detail| detail.get("updated"))
                    .filter(|updated| !updated.is_null())
                    .cloned();
                if single_url
                    && subscription.kind != FeedKind::Domain
                    && subscription
                        .table_count
                        .is_some_and(|count| count <= MAX_DIGEST_ENTRIES)
                    && let Some(entries) = table_entries(client, &subscription.alias).await?
                    && Some(entries.len() as u64) == subscription.table_count
                    && let Some(body) = render_body(subscription.kind, &entries)
                {
                    subscription.content_etag = Some(etag_of(&body));
                }
                feeds.push(subscription);
            }
        }
    }
    serde_json::to_value(FeedStatus { feeds, skipped })
        .map_err(|error| OpnsenseError::Malformed(error.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A live row from `aliases.json` (the shape is real); `type`, `content`,
    /// `updatefreq` and `authtype` are overwritten with synthetic URL-table
    /// values on RFC 5737 / example.org names, because the lab has no
    /// URL-table alias to capture.
    fn row(name: &str, content: &str) -> Value {
        let mut row = crate::testing::fixture("aliases")["rows"][0].clone();
        row["name"] = json!(name);
        row["type"] = json!("urltable");
        row["content"] = json!(content);
        row["updatefreq"] = json!("1");
        row["authtype"] = json!("Basic");
        row
    }

    fn urls(content: &str) -> Vec<(FeedKind, String)> {
        matching_urls(content)
    }

    #[test]
    fn only_the_three_exact_paths_match() {
        let base = "https://feeds.example.org:8443";
        for (kind, path) in [
            (FeedKind::Address, "address"),
            (FeedKind::Prefix, "prefix"),
            (FeedKind::Domain, "domain"),
        ] {
            let url = format!("{base}/feeds/opnsense-url-table/{path}");
            assert_eq!(urls(&url), vec![(kind, url.clone())]);
        }
        for miss in [
            "/feeds/opnsense-url-table/address/extra",
            "/feeds/opnsense-url-table/",
            "/feeds/opnsense-url-table/address/",
            "/feeds/panos-edl/address",
            "/x/feeds/opnsense-url-table/address",
            "/feeds/opnsense-url-table/ADDRESS",
        ] {
            assert!(urls(&format!("{base}{miss}")).is_empty(), "{miss}");
        }
    }

    #[test]
    fn userinfo_query_and_fragment_are_stripped() {
        let found = urls(
            "https://user:EXAMPLE@feeds.example.org/feeds/opnsense-url-table/prefix?token=abc#frag",
        );
        assert_eq!(
            found,
            vec![(
                FeedKind::Prefix,
                "https://feeds.example.org/feeds/opnsense-url-table/prefix".to_owned()
            )]
        );
    }

    #[test]
    fn every_matching_url_is_reported_and_others_are_ignored() {
        let content = "https://a.example.org/feeds/opnsense-url-table/address\r\n\
                       https://b.example.org/other\n\
                       not a url\n\
                       https://c.example.org/feeds/opnsense-url-table/prefix";
        assert_eq!(urls(content).len(), 2);
        let (found, _) = candidates(&[row("multi", content)]);
        assert_eq!(found[0].subscriptions.len(), 2);
        assert!(!found[0].single_url);
    }

    #[test]
    fn non_urltable_types_are_ignored() {
        let mut other = row(
            "hosts",
            "https://feeds.example.org/feeds/opnsense-url-table/address",
        );
        other["type"] = json!("url");
        assert!(candidates(&[other]).0.is_empty());
    }

    #[test]
    fn fields_are_mapped_and_credentials_never_appear() {
        let mut subscribed = row(
            "feed_a",
            "https://feeds.example.org:8443/feeds/opnsense-url-table/address",
        );
        subscribed["username"] = json!("synthetic-user");
        subscribed["password"] = json!("synthetic-pass");
        subscribed["last_updated"] = json!("2026-10-29 01:02:03");
        let (found, skipped) = candidates(&[subscribed]);
        assert!(skipped.is_empty());
        let rendered = serde_json::to_string(&found[0].subscriptions).unwrap();
        assert!(!rendered.contains("synthetic-user"), "username leaked");
        assert!(!rendered.contains("synthetic-pass"), "password leaked");
        let feed = &found[0].subscriptions[0];
        assert_eq!(feed.auth.as_deref(), Some("Basic"));
        assert_eq!(feed.update_frequency_days, Some(1.0));
        assert_eq!(feed.current_items, Some(3052));
        assert!(feed.enabled);
        assert_eq!(feed.last_updated.as_deref(), Some("2026-10-29 01:02:03"));
    }

    #[test]
    fn hostile_alias_names_are_skipped_with_a_reason() {
        let content = "https://feeds.example.org/feeds/opnsense-url-table/address";
        let rows: Vec<Value> = [
            "a/b",
            "..",
            "a%2Fb",
            "x/../y",
            "",
            &"a".repeat(32),
            "__x",
            "_",
        ]
        .iter()
        .map(|name| row(name, content))
        .collect();
        let (found, skipped) = candidates(&rows);
        assert!(found.is_empty());
        assert_eq!(skipped.len(), rows.len());
        for name in ["a", "_a", "a_", "A1_b", &"a".repeat(31)] {
            assert!(validate_alias_name(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn etag_matches_an_independently_computed_digest() {
        // printf '192.0.2.1\n192.0.2.9\n2001:db8::1\n' | sha256sum
        let entries: Vec<String> = ["2001:db8::1/128", "192.0.2.9", "192.0.2.1/32"]
            .map(str::to_owned)
            .to_vec();
        let body = render_body(FeedKind::Address, &entries).unwrap();
        assert_eq!(body, "192.0.2.1\n192.0.2.9\n2001:db8::1\n");
        assert_eq!(
            etag_of(&body),
            "\"sha256-89cb5847af66072db0628804bf9e87f0f688733e28db26d82774e270489e03a9\""
        );
        // printf '198.51.100.0/24\n203.0.113.0/25\n203.0.113.200/32\n' | sha256sum
        let prefixes: Vec<String> = ["203.0.113.200", "203.0.113.0/25", "198.51.100.0/24"]
            .map(str::to_owned)
            .to_vec();
        let body = render_body(FeedKind::Prefix, &prefixes).unwrap();
        assert_eq!(
            etag_of(&body),
            "\"sha256-df1673acabc54ab3b99ddbca160abf0be7e9ea5a8e362a32cb47d2cb9245b741\""
        );
        // printf '' | sha256sum
        assert_eq!(
            etag_of(&render_body(FeedKind::Address, &[]).unwrap()),
            "\"sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\""
        );
    }

    #[test]
    fn irreproducible_tables_give_no_body() {
        let one = |entry: &str| vec![entry.to_owned()];
        assert!(render_body(FeedKind::Domain, &one("192.0.2.1")).is_none());
        assert!(render_body(FeedKind::Address, &one("192.0.2.0/24")).is_none());
        assert!(render_body(FeedKind::Prefix, &one("192.0.2.72/24")).is_none());
        assert!(render_body(FeedKind::Prefix, &one("not-an-address")).is_none());
        assert!(render_body(FeedKind::Address, &one("192.0.2.1/33")).is_none());
    }

    #[test]
    fn the_live_table_fixtures_have_the_shape_we_read() {
        let list = crate::testing::fixture("alias_util_list");
        assert_eq!(list["rows"][0]["ip"], "192.0.2.72/24");
        let sizes = crate::testing::fixture("alias_table_size");
        assert!(sizes["details"]["lab_clients"]["count"].is_u64());
    }
}
