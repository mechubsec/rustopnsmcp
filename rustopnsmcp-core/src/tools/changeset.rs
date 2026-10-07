//! Change-set lifecycle tools for OPNsense firewall aliases and filter
//! rules.
//!
//! OPNsense's alias and filter controllers have no candidate configuration,
//! no dry-run validation, and no checkpoint to roll back to. The tools below
//! implement the change-control lifecycle (plan, digest, human approve,
//! apply with drift check) over that immediate-write REST API as a
//! best-effort approximation, and say plainly what cannot be guaranteed.
//! Each change set carries actions against exactly one resource kind; see
//! [`crate::changeset::ResourceKind`].

use crate::changeset::{ResourceKind, StagedMutation};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Arguments for `get_opnsense_config_fingerprint`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FingerprintArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
}

/// Arguments for `create_opnsense_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateChangeSetArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
    /// The fingerprint from `get_opnsense_config_fingerprint` that this plan
    /// was written against. Refused if the configuration has changed since.
    pub expected_fingerprint: String,
    /// The actions, all against the same resource kind.
    pub actions: Vec<MutationSpec>,
}

/// One action, addressed to one firewall alias or filter rule.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum MutationSpec {
    /// Create a new resource.
    Create {
        /// Which resource controller this action targets.
        resource: ResourceKind,
        /// The resource body: for an alias, at minimum `name` and `type`;
        /// for a rule, at minimum `action` and `interface`.
        body: serde_json::Value,
    },
    /// Update an existing resource.
    Update {
        /// Which resource controller this action targets.
        resource: ResourceKind,
        /// The resource UUID.
        uuid: String,
        /// The fields to change.
        body: serde_json::Value,
    },
    /// Delete an existing resource.
    Delete {
        /// Which resource controller this action targets.
        resource: ResourceKind,
        /// The resource UUID.
        uuid: String,
    },
}

impl MutationSpec {
    /// The staged mutation this action describes.
    #[must_use]
    pub fn into_mutation(self) -> StagedMutation {
        match self {
            Self::Create { resource, body } => StagedMutation::create(resource, body),
            Self::Update {
                resource,
                uuid,
                body,
            } => StagedMutation::update(resource, uuid, body),
            Self::Delete { resource, uuid } => StagedMutation::delete(resource, uuid),
        }
    }
}

/// Arguments for `approve_opnsense_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveChangeSetArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
    /// The change set ID to approve.
    pub change_set_id: String,
    /// The plan digest the approver read, as create or status reports it.
    /// Required: the approval is refused if the plan's digest is different.
    pub expected_digest: String,
}

/// Arguments for `opnsense_apply_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyChangeSetArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
    /// The change set ID to apply.
    pub change_set_id: String,
}

/// Arguments for `opnsense_get_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetChangeSetArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
    /// The change set ID to retrieve.
    pub change_set_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_takes_exactly_device_fingerprint_and_actions() {
        let valid = serde_json::json!({
            "device": "fw-1",
            "expected_fingerprint": "sha256:00",
            "actions": [{ "operation": "delete", "resource": "alias",
                          "uuid": "33333333-3333-3333-3333-333333333333" }],
        });
        assert!(serde_json::from_value::<CreateChangeSetArgs>(valid).is_ok());

        let with_description = serde_json::json!({
            "device": "fw-1", "expected_fingerprint": "sha256:00", "actions": [],
            "description": "old parameter",
        });
        assert!(serde_json::from_value::<CreateChangeSetArgs>(with_description).is_err());
    }

    #[test]
    fn an_unknown_field_inside_an_action_is_refused() {
        let smuggled = serde_json::json!({
            "device": "fw-1", "expected_fingerprint": "sha256:00",
            "actions": [{ "operation": "delete", "resource": "alias",
                          "uuid": "33333333-3333-3333-3333-333333333333",
                          "force": true }],
        });
        assert!(serde_json::from_value::<CreateChangeSetArgs>(smuggled).is_err());
    }

    #[test]
    fn approve_requires_expected_digest() {
        let without = serde_json::json!({
            "device": "fw-1",
            "change_set_id": "0000000000000000000000000000000000000000000000000000000000000000",
        });
        assert!(serde_json::from_value::<ApproveChangeSetArgs>(without).is_err());
    }
}
