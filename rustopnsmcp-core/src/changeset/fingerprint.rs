//! The configuration fingerprint a change set is planned and applied against.

use crate::client::OpnsenseClient;
use crate::endpoints;
use crate::error::OpnsenseError;
use crate::model::SearchResponse;
use serde_json::Value;

/// Fields OPNsense recomputes on its own schedule. They say nothing about
/// what an operator configured, and would make every plan read as stale.
///
/// Stripped at record level only. pf evaluation counters and table sizes: re-read on every request
/// (`eval_nomatch` seen ticking on opnsense-lab within 20 s). Not
/// configuration; the alias `counters` option that enables them is, and is
/// deliberately absent.
pub const VOLATILE_FIELDS: &[&str] = &[
    "current_items",
    "last_updated",
    "eval_nomatch",
    "eval_match",
    "in_block_p",
    "in_block_b",
    "in_pass_p",
    "in_pass_b",
    "out_block_p",
    "out_block_b",
    "out_pass_p",
    "out_pass_b",
];

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

/// A record in canonical form: volatile fields removed at record level only
/// (the top-level object of a search row or of an unwrapped `getItem` body),
/// keys sorted at every depth. Below record level nothing is dropped: option
/// maps there are keyed by user-chosen names that can collide with a counter
/// name, and an unseen nested counter must fail closed (a refusal), never
/// read as "same configuration".
pub(super) fn canonical(record: &Value) -> Value {
    match sorted(record) {
        Value::Object(mut map) => {
            map.retain(|key, _| !VOLATILE_FIELDS.contains(&key.as_str()));
            Value::Object(map)
        }
        other => other,
    }
}

/// Keys sorted at every depth; nothing removed.
fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut ordered = serde_json::Map::new();
            for key in keys {
                ordered.insert(key.clone(), sorted(&map[key]));
            }
            Value::Object(ordered)
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
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

    #[test]
    fn pf_counters_do_not_change_the_fingerprint() {
        for field in [
            "eval_nomatch",
            "eval_match",
            "in_block_p",
            "in_block_b",
            "in_pass_p",
            "in_pass_b",
            "out_block_p",
            "out_block_b",
            "out_pass_p",
            "out_pass_b",
        ] {
            let mut ticked = alias("1", "192.0.2.1");
            ticked[field] = json!("17");
            assert_eq!(
                fingerprint_collections(&[alias("1", "192.0.2.1")], &[]).unwrap(),
                fingerprint_collections(&[ticked], &[]).unwrap(),
                "{field} is a live counter"
            );
        }
    }

    #[test]
    fn configuration_fields_including_counters_option_change_the_fingerprint() {
        let base = fingerprint_collections(&[alias("1", "192.0.2.1")], &[]).unwrap();
        for (field, value) in [
            ("counters", "1"),
            ("enabled", "0"),
            ("content", "192.0.2.9"),
        ] {
            let mut changed = alias("1", "192.0.2.1");
            changed[field] = json!(value);
            assert_ne!(
                base,
                fingerprint_collections(&[changed], &[]).unwrap(),
                "{field}"
            );
        }
    }

    #[test]
    fn a_member_named_like_a_counter_is_configuration_not_a_counter() {
        let body = |member: &str| {
            json!({ "uuid": "1", "name": "grp", "eval_nomatch": "1",
                "content": { member: { "value": member, "selected": 1 },
                             "eval_match": { "value": "eval_match", "selected": 1 },
                             "current_items": { "value": "current_items", "selected": 1 } } })
        };
        let base = body("alias_a");
        assert_ne!(
            fingerprint_collections(std::slice::from_ref(&base), &[]).unwrap(),
            fingerprint_collections(&[body("alias_b")], &[]).unwrap()
        );
        let mut dropped = base.clone();
        dropped["content"]
            .as_object_mut()
            .unwrap()
            .remove("eval_match");
        assert_ne!(
            fingerprint_collections(std::slice::from_ref(&base), &[]).unwrap(),
            fingerprint_collections(std::slice::from_ref(&dropped), &[]).unwrap()
        );
        assert!(!crate::changeset::same_configuration(&base, &dropped));
    }
}
