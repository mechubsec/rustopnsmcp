//! One audit record per `tools/call` (spec §3.3).
//!
//! Opened in `ServerHandler::call_tool` before dispatch, so it covers a call
//! whose arguments rmcp rejects before any handler runs, and a tool added
//! later cannot forget its record. `AuditScope` emits on drop.

use mecmcp_audit::AuditScope;
use mecmcp_auth::{CallerCtx, NoGrant};
use rmcp::model::{CallToolResponse, JsonObject};
use rustopnsmcp_core::tools::{TOOL_NAMES, WRITE_TOOLS};

/// The registered `&'static str` for `tool`, or `"unknown_tool"`.
///
/// `AuditScope` wants a static name. Mapping through the registry, rather
/// than leaking the caller's string, also keeps caller input out of the
/// `tool` field.
pub(crate) fn static_name(tool: &str) -> &'static str {
    TOOL_NAMES
        .iter()
        .copied()
        .find(|known| *known == tool)
        .unwrap_or("unknown_tool")
}

/// The audit `action` for a tool: `"write"` for a mutating tool, otherwise
/// `"read"`.
pub(crate) fn action_for(tool: &str) -> &'static str {
    if WRITE_TOOLS.contains(&tool) {
        "write"
    } else {
        "read"
    }
}

/// The longest a caller-supplied hint may be before the audit record
/// truncates it. The value is attacker-controlled free text (there is no
/// registry lookup at this choke point to resolve it to a known name
/// first), so it needs a bound independent of whatever the caller sends.
const HINT_MAX_BYTES: usize = 128;

/// Truncate `value` to at most [`HINT_MAX_BYTES`] bytes, on a char boundary.
fn bounded(mut value: String) -> String {
    if value.len() <= HINT_MAX_BYTES {
        return value;
    }
    let mut cut = HINT_MAX_BYTES;
    while !value.is_char_boundary(cut) {
        cut -= 1;
    }
    value.truncate(cut);
    value
}

/// The call's `device` argument, when it carries a string one.
pub(crate) fn device_hint(arguments: Option<&JsonObject>) -> Option<String> {
    arguments
        .and_then(|arguments| arguments.get("device"))
        .and_then(serde_json::Value::as_str)
        .map(|value| bounded(value.to_owned()))
}

/// The call's `change_set_id` argument, when it carries a string one.
pub(crate) fn change_set_id_hint(arguments: Option<&JsonObject>) -> Option<String> {
    arguments
        .and_then(|arguments| arguments.get("change_set_id"))
        .and_then(serde_json::Value::as_str)
        .map(|value| bounded(value.to_owned()))
}

/// Open the scope for one call.
pub(crate) fn open(
    caller: Option<&CallerCtx<NoGrant>>,
    tool: &str,
    arguments: Option<&JsonObject>,
) -> AuditScope {
    mecmcp_server::audit_scope(
        caller,
        static_name(tool),
        action_for(tool),
        device_hint(arguments).into_iter().collect(),
    )
}

/// Record the call's outcome.
///
/// The error text is not copied into the record. It can carry device-sourced
/// detail, and the audit trail needs the outcome, not the prose.
pub(crate) fn settle(audit: &mut AuditScope, result: &Result<CallToolResponse, rmcp::ErrorData>) {
    match result {
        Ok(CallToolResponse::Complete(done)) if done.is_error != Some(true) => audit.succeed(),
        Ok(CallToolResponse::Complete(_)) => {
            audit.fail_kind("tool_error", "the tool returned an error result");
        }
        Ok(_) => audit.fail_kind("unexpected_response", "the tool did not complete"),
        Err(_) => audit.fail_kind("rejected", "the call was rejected before the tool ran"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unregistered_name_maps_to_unknown_tool() {
        assert_eq!(static_name("definitely_not_a_tool"), "unknown_tool");
    }

    #[test]
    fn every_registered_name_maps_to_itself() {
        for tool in TOOL_NAMES {
            assert_eq!(static_name(tool), *tool);
        }
    }

    #[test]
    fn write_tools_are_audited_as_writes() {
        for tool in WRITE_TOOLS {
            assert_eq!(action_for(tool), "write", "{tool}");
        }
    }

    #[test]
    fn device_hint_reads_only_a_string_device() {
        let with = serde_json::json!({ "device": "fw-1" });
        let without = serde_json::json!({ "device": 7 });
        assert_eq!(device_hint(with.as_object()), Some("fw-1".to_owned()));
        assert_eq!(device_hint(without.as_object()), None);
        assert_eq!(device_hint(None), None);
    }

    #[test]
    fn change_set_id_hint_reads_only_a_string_change_set_id() {
        let with = serde_json::json!({ "change_set_id": "cs-1" });
        let without = serde_json::json!({ "change_set_id": 7 });
        assert_eq!(
            change_set_id_hint(with.as_object()),
            Some("cs-1".to_owned())
        );
        assert_eq!(change_set_id_hint(without.as_object()), None);
        assert_eq!(change_set_id_hint(None), None);
    }

    #[test]
    fn hints_are_bounded_regardless_of_caller_input_length() {
        let long = "x".repeat(HINT_MAX_BYTES * 4);
        let device = serde_json::json!({ "device": long });
        let hint = device_hint(device.as_object()).expect("device hint present");
        assert_eq!(hint.len(), HINT_MAX_BYTES);

        let change_set = serde_json::json!({ "change_set_id": long });
        let hint =
            change_set_id_hint(change_set.as_object()).expect("change_set_id hint present");
        assert_eq!(hint.len(), HINT_MAX_BYTES);
    }
}
