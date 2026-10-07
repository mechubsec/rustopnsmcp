//! The configuration fingerprint a change set is planned and applied against.

use crate::client::OpnsenseClient;
use crate::endpoints;
use crate::error::OpnsenseError;
use crate::model::SearchResponse;
use serde_json::Value;

/// Fields OPNsense recomputes on its own schedule. They say nothing about
/// what an operator configured, and would make every plan read as stale.
/// Checked against opnsense-lab in P3.
pub const VOLATILE_FIELDS: &[&str] = &["current_items", "last_updated"];

/// The fingerprint of the governed configuration on `client`'s device: every
/// alias and every filter rule.
///
/// # Errors
///
/// Returns the transport or shape error of either listing, and
/// [`OpnsenseError::Malformed`] when a listing's rows fall short of its
/// `total`, or when the device reports no `total` at all.
pub async fn config_fingerprint(client: &OpnsenseClient) -> Result<String, OpnsenseError> {
    let aliases = whole_collection(client, endpoints::ALIASES_SEARCH).await?;
    let rules = whole_collection(client, endpoints::FIREWALL_RULES_SEARCH).await?;
    fingerprint_collections(&aliases, &rules)
}

/// Fetch every row of a `search_*` collection in one request.
///
/// `rowCount: -1` asks OPNsense for all rows. The result is checked against
/// `total`, so a device that ignores `-1` is caught and not trusted. A
/// response with no `total` at all is refused rather than treated as
/// complete, since a partial read could otherwise look complete.
async fn whole_collection(
    client: &OpnsenseClient,
    path: &str,
) -> Result<Vec<Value>, OpnsenseError> {
    let raw = client
        .post(
            path,
            &serde_json::json!({ "current": 1, "rowCount": -1, "searchPhrase": "" }),
        )
        .await?;
    let parsed = SearchResponse::parse(&raw)?;
    let total = parsed.total.ok_or_else(|| {
        OpnsenseError::Malformed(format!(
            "{path} did not report a total; refusing to fingerprint a listing that cannot be \
             shown complete"
        ))
    })?;
    if usize::try_from(total).ok() != Some(parsed.rows.len()) {
        return Err(OpnsenseError::Malformed(format!(
            "{path} returned {} of {total} rows; refusing to fingerprint a partial listing",
            parsed.rows.len()
        )));
    }
    Ok(parsed.rows)
}

/// The canonical fingerprint of an alias collection and a rule collection.
///
/// # Errors
///
/// Returns [`OpnsenseError::Malformed`] if the canonical form cannot be
/// serialized.
pub fn fingerprint_collections(
    aliases: &[Value],
    rules: &[Value],
) -> Result<String, OpnsenseError> {
    let mut document = serde_json::Map::new();
    document.insert("aliases".to_owned(), Value::Array(canonical_rows(aliases)));
    document.insert("rules".to_owned(), Value::Array(canonical_rows(rules)));
    let encoded = serde_json::to_vec(&Value::Object(document)).map_err(|error| {
        OpnsenseError::Malformed(format!("could not fingerprint the configuration: {error}"))
    })?;
    Ok(format!(
        "sha256:{}",
        mecmcp_changeset::digest::digest_hex(&encoded)
    ))
}

/// Rows in canonical form, sorted by `uuid`.
fn canonical_rows(rows: &[Value]) -> Vec<Value> {
    let mut canonical: Vec<Value> = rows.iter().map(canonical).collect();
    canonical.sort_by(|left, right| uuid_of(left).cmp(uuid_of(right)));
    canonical
}

fn uuid_of(row: &Value) -> &str {
    row.get("uuid").and_then(Value::as_str).unwrap_or_default()
}

/// Keys sorted at every depth, volatile fields removed.
fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = serde_json::Map::new();
            for key in keys {
                if VOLATILE_FIELDS.contains(&key.as_str()) {
                    continue;
                }
                sorted.insert(key.clone(), canonical(&map[key]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn alias(uuid: &str, content: &str) -> serde_json::Value {
        json!({ "uuid": uuid, "name": format!("a_{uuid}"), "type": "host", "content": content })
    }

    #[test]
    fn the_fingerprint_is_a_lifecycle_valid_sha256() {
        let fingerprint = fingerprint_collections(&[alias("1", "192.0.2.1")], &[]).unwrap();
        mecmcp_changeset::digest::validate_fingerprint(&fingerprint).unwrap();
    }

    #[test]
    fn key_order_and_row_order_do_not_change_the_fingerprint() {
        let forward = vec![alias("1", "192.0.2.1"), alias("2", "192.0.2.2")];
        let reordered_keys: serde_json::Value = serde_json::from_str(
            r#"{"content":"192.0.2.2","type":"host","name":"a_2","uuid":"2"}"#,
        )
        .unwrap();
        let backward = vec![reordered_keys, alias("1", "192.0.2.1")];
        assert_eq!(
            fingerprint_collections(&forward, &[]).unwrap(),
            fingerprint_collections(&backward, &[]).unwrap()
        );
    }

    #[test]
    fn volatile_fields_do_not_change_the_fingerprint() {
        let mut refreshed = alias("1", "192.0.2.1");
        refreshed["current_items"] = json!("12");
        refreshed["last_updated"] = json!("2026-09-30T12:00:00");
        assert_eq!(
            fingerprint_collections(&[alias("1", "192.0.2.1")], &[]).unwrap(),
            fingerprint_collections(&[refreshed], &[]).unwrap()
        );
    }

    #[test]
    fn a_content_change_or_a_rule_change_does_change_it() {
        let base = fingerprint_collections(&[alias("1", "192.0.2.1")], &[]).unwrap();
        let edited = fingerprint_collections(&[alias("1", "192.0.2.9")], &[]).unwrap();
        let with_rule =
            fingerprint_collections(&[alias("1", "192.0.2.1")], &[json!({ "uuid": "r" })]).unwrap();
        assert_ne!(base, edited);
        assert_ne!(base, with_rule);
    }
}
