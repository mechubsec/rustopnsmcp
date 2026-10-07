//! Change-set gates as plain functions, so each decision is testable without
//! a device or an MCP session.

use mecmcp_changeset::{ChangeSetOutput, ChangeSetRecord, ChangeSetState, ChangesetCoordinator};

/// Seconds since the Unix epoch; 0 for a clock before it, which makes every
/// deadline look passed (the safe direction for a gate).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Refuse a plan or an apply whose expected fingerprint is not the live one.
///
/// # Errors
///
/// Returns a message naming both fingerprints.
pub(crate) fn check_fingerprint(expected: &str, live: &str) -> Result<(), String> {
    if expected == live {
        return Ok(());
    }
    Err(format!(
        "the configuration changed since fingerprint {expected} was read; it is now {live}. \
         Read it again with get_opnsense_config_fingerprint and re-plan."
    ))
}

/// One pending change set per principal per device, as the coordinator's own
/// `create_change_set` enforces. This server inserts records itself (they
/// carry a preview), so it applies the same rule here.
///
/// # Errors
///
/// Returns a message naming the blocking change set.
pub(crate) async fn ensure_no_pending(
    coordinator: &ChangesetCoordinator,
    owner: &str,
    device: &str,
) -> Result<(), String> {
    let now = now_unix();
    let blocker = coordinator.change_sets().await.into_iter().find(|record| {
        record.owner == owner
            && record.device == device
            && match record.state {
                ChangeSetState::Applying => true,
                ChangeSetState::Planned | ChangeSetState::Approved => now < record.expires_at_unix,
                _ => false,
            }
    });
    match blocker {
        Some(record) => Err(format!(
            "change set {} on '{device}' is still {}; apply or cancel it before creating another",
            record.id,
            record.state.as_str()
        )),
        None => Ok(()),
    }
}

/// Persist a new, complete change set; under lab mode, waive its approval.
///
/// The waiver is `ChangesetCoordinator::waive_approval`, which records
/// `approver: None` and a lab-mode `WaiverRecord`. No approver is invented.
///
/// # Errors
///
/// Returns the coordinator's refusal, naming the field it objected to.
pub(crate) async fn finish_creation(
    coordinator: &ChangesetCoordinator,
    record: ChangeSetRecord,
) -> Result<ChangeSetOutput, String> {
    let (id, device, owner, digest) = (
        record.id.clone(),
        record.device.clone(),
        record.owner.clone(),
        record.digest.clone(),
    );
    coordinator
        .insert_change_set(record.clone())
        .await
        .map_err(|error| {
            format!(
                "failed to store the change set ({}): {}",
                error.field(),
                error.message()
            )
        })?;
    if !coordinator.lab_mode() {
        return Ok(ChangeSetOutput::from(record));
    }
    coordinator
        .waive_approval(id, device, owner, digest)
        .await
        .map_err(|error| {
            format!(
                "the change set was stored but the lab-mode waiver failed ({}): {}; cancel it \
                 with cancel_opnsense_change_set",
                error.field(),
                error.message()
            )
        })
}

/// Approve a change set as a second, human principal.
///
/// The coordinator checks the digest, the actor type, the state and the
/// expiry under its own lock. This adds the two refusals it cannot phrase:
/// a lab-mode change set was already approved by its waiver, and the owner
/// is never their own second principal, lab mode or not.
///
/// # Errors
///
/// Returns the refusal, naming the field the coordinator objected to.
pub(crate) async fn approve(
    coordinator: &ChangesetCoordinator,
    change_set_id: &str,
    device: &str,
    approver: &str,
    approver_actor_type: mecmcp_audit::ActorType,
    expected_digest: &str,
) -> Result<ChangeSetOutput, String> {
    let record = coordinator
        .change_set(change_set_id, device)
        .await
        .map_err(|error| {
            format!(
                "change set {change_set_id} on {device} ({}): {}",
                error.field(),
                error.message()
            )
        })?;
    if record
        .approval
        .as_ref()
        .and_then(|approval| approval.waived.as_ref())
        .is_some()
    {
        return Err(
            "this change set was approved by a lab-mode waiver at creation; there is nothing to \
             approve"
                .to_owned(),
        );
    }
    if record.owner == approver {
        return Err(
            "two-person control: the creating principal cannot approve its own change set"
                .to_owned(),
        );
    }
    coordinator
        .approve_change_set(
            change_set_id.to_owned(),
            device.to_owned(),
            approver.to_owned(),
            expected_digest.to_owned(),
            approver_actor_type,
        )
        .await
        .map_err(|error| format!("approval refused ({}): {}", error.field(), error.message()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use mecmcp_changeset::{ChangeSetState, change_set_digest};
    use rustopnsmcp_core::changeset::{Preimage, ResourceKind, StagedMutation, actions_for};

    const FINGERPRINT: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn coordinator(lab_mode: bool) -> std::sync::Arc<ChangesetCoordinator> {
        crate::changeset_state::build_coordinator(
            None,
            std::time::Duration::from_secs(3600),
            lab_mode,
        )
        .unwrap()
    }

    fn record(owner: &str, device: &str, kind: ResourceKind) -> ChangeSetRecord {
        let body = match kind {
            ResourceKind::Alias => {
                serde_json::json!({ "name": "test_alias", "type": "host", "content": "192.0.2.1" })
            }
            ResourceKind::Rule => {
                serde_json::json!({ "action": "pass", "interface": "lan", "description": "t" })
            }
        };
        let mutations = vec![StagedMutation::create(kind, body)];
        let actions: Vec<serde_json::Value> =
            actions_for(&mutations, &Preimage::from_resources(Vec::new()))
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<_, _>>()
                .unwrap();
        let digest = change_set_digest(owner, device, FINGERPRINT, &actions).unwrap();
        ChangeSetRecord {
            id: crate::changeset_state::new_change_set_id(),
            owner: owner.to_owned(),
            device: device.to_owned(),
            expected_candidate_fingerprint: FINGERPRINT.to_owned(),
            actions,
            digest,
            state: ChangeSetState::Planned,
            approver: None,
            approval: None,
            expires_at_unix: u64::MAX / 2,
            operation_id: None,
            policy_signature: String::new(),
            targets: Vec::new(),
            preview: Some(mecmcp_changeset::PreviewRecord {
                digest: mecmcp_changeset::preview_digest("preview"),
                artifact: "preview".to_owned(),
                job_id: None,
            }),
            task_id: None,
            apply_without_handle: false,
        }
    }

    #[test]
    fn a_stale_fingerprint_is_refused_with_both_values() {
        let live = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let error = check_fingerprint(FINGERPRINT, live).unwrap_err();
        assert!(
            error.contains(FINGERPRINT) && error.contains(live),
            "{error}"
        );
        assert!(check_fingerprint(FINGERPRINT, FINGERPRINT).is_ok());
    }

    #[tokio::test]
    async fn lab_mode_waives_at_creation_without_inventing_an_approver() {
        let coordinator = coordinator(true);
        let planned = record("alice", "fw-1", ResourceKind::Alias);
        let id = planned.id.clone();

        let created = finish_creation(&coordinator, planned).await.unwrap();
        assert_eq!(created.state, ChangeSetState::Approved);
        assert_eq!(created.approver, None);
        assert_eq!(created.approval_waiver.as_deref(), Some("lab-mode"));

        let stored = coordinator.change_set(&id, "fw-1").await.unwrap();
        let approval = stored.approval.unwrap();
        assert_eq!(approval.approver, None);
        assert_eq!(approval.waived.unwrap().reason, "lab-mode");
        assert_eq!(stored.approver, None);
    }

    #[tokio::test]
    async fn without_lab_mode_creation_awaits_a_second_principal() {
        let coordinator = coordinator(false);
        let created = finish_creation(&coordinator, record("alice", "fw-1", ResourceKind::Alias))
            .await
            .unwrap();
        assert_eq!(created.state, ChangeSetState::Planned);
        assert_eq!(created.approval_waiver, None);
    }

    #[tokio::test]
    async fn a_pending_plan_blocks_a_second_one_for_the_same_owner_and_device() {
        let coordinator = coordinator(false);
        finish_creation(&coordinator, record("alice", "fw-1", ResourceKind::Alias))
            .await
            .unwrap();
        assert!(
            ensure_no_pending(&coordinator, "alice", "fw-1")
                .await
                .is_err()
        );
        assert!(ensure_no_pending(&coordinator, "bob", "fw-1").await.is_ok());
        assert!(
            ensure_no_pending(&coordinator, "alice", "fw-2")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn approving_with_a_stale_digest_is_refused_and_leaves_the_plan_planned() {
        let coordinator = coordinator(false);
        let planned = record("alice", "fw-1", ResourceKind::Alias);
        let id = planned.id.clone();
        coordinator.insert_change_set(planned).await.unwrap();

        let stale = format!("sha256:{}", "0".repeat(64));
        let error = approve(
            &coordinator,
            &id,
            "fw-1",
            "bob",
            mecmcp_audit::ActorType::Human,
            &stale,
        )
        .await
        .unwrap_err();
        assert!(error.contains("expected_digest"), "{error}");
        let stored = coordinator.change_set(&id, "fw-1").await.unwrap();
        assert_eq!(stored.state, ChangeSetState::Planned);
        assert_eq!(stored.approver, None);
    }

    #[tokio::test]
    async fn the_owner_cannot_approve_even_in_lab_mode() {
        let coordinator = coordinator(true);
        let planned = record("alice", "fw-1", ResourceKind::Alias);
        let (id, digest) = (planned.id.clone(), planned.digest.clone());
        coordinator.insert_change_set(planned).await.unwrap();

        let error = approve(
            &coordinator,
            &id,
            "fw-1",
            "alice",
            mecmcp_audit::ActorType::Human,
            &digest,
        )
        .await
        .unwrap_err();
        assert!(error.contains("two-person control"), "{error}");
    }

    #[tokio::test]
    async fn a_waived_change_set_has_nothing_left_to_approve() {
        let coordinator = coordinator(true);
        let planned = record("alice", "fw-1", ResourceKind::Alias);
        let (id, digest) = (planned.id.clone(), planned.digest.clone());
        finish_creation(&coordinator, planned).await.unwrap();

        let error = approve(
            &coordinator,
            &id,
            "fw-1",
            "bob",
            mecmcp_audit::ActorType::Human,
            &digest,
        )
        .await
        .unwrap_err();
        assert!(error.contains("lab-mode waiver"), "{error}");
    }

    #[tokio::test]
    async fn a_human_second_principal_with_the_current_digest_approves() {
        let coordinator = coordinator(false);
        let planned = record("alice", "fw-1", ResourceKind::Alias);
        let (id, digest) = (planned.id.clone(), planned.digest.clone());
        coordinator.insert_change_set(planned).await.unwrap();

        let approved = approve(
            &coordinator,
            &id,
            "fw-1",
            "bob",
            mecmcp_audit::ActorType::Human,
            &digest,
        )
        .await
        .unwrap();
        assert_eq!(approved.state, ChangeSetState::Approved);
        assert_eq!(approved.approver.as_deref(), Some("bob"));
    }
}
