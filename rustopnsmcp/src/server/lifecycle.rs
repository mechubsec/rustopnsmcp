//! Change-set gates as plain functions, so each decision is testable without
//! a device or an MCP session.

use mecmcp_changeset::{ChangeSetOutput, ChangeSetRecord, ChangeSetState, ChangesetCoordinator};
use rustopnsmcp_core::changeset::{ResourceKind, StagedMutation, State, mutations_of};

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

/// Refuse `confirm_timeout_mins` rather than ignore it (spec §3.4): OPNsense
/// offers commit-confirmed apply only for filter rules, and this build does
/// not wire savepoints for it yet.
///
/// # Errors
///
/// Returns the refusal for any `Some`.
pub(crate) fn check_confirm_timeout(
    kind: ResourceKind,
    confirm_timeout_mins: Option<u32>,
) -> Result<(), String> {
    if confirm_timeout_mins.is_none() {
        return Ok(());
    }
    match kind {
        ResourceKind::Rule => Err(
            "confirm_timeout_mins: commit-confirmed apply for firewall filter rules is not \
             available in this build; omit it"
                .to_owned(),
        ),
        other => Err(format!(
            "confirm_timeout_mins is refused for {}: OPNsense offers commit-confirmed only for \
             firewall filter rules",
            other.noun()
        )),
    }
}

/// Everything apply can refuse about a stored plan without touching the
/// device: the digest the caller named, the fingerprint the plan was built
/// against, and `confirm_timeout_mins`.
///
/// # Errors
///
/// Returns the first refusal.
pub(crate) fn pre_apply_gate(
    record: &ChangeSetRecord,
    expected_digest: &str,
    expected_fingerprint: &str,
    confirm_timeout_mins: Option<u32>,
) -> Result<(), String> {
    let mutations =
        mutations_of(&record.actions).map_err(|error| format!("stored change set: {error}"))?;
    let Some(kind) = mutations.first().map(StagedMutation::kind) else {
        return Err("stored change set has no actions".to_owned());
    };
    check_confirm_timeout(kind, confirm_timeout_mins)?;
    if record.digest != expected_digest {
        return Err(format!(
            "apply refused: the plan digest is {}, not the {expected_digest} you named; read the \
             change set again",
            record.digest
        ));
    }
    if record.expected_candidate_fingerprint != expected_fingerprint {
        return Err(format!(
            "apply refused: this change set was planned against fingerprint {}, not \
             {expected_fingerprint}",
            record.expected_candidate_fingerprint
        ));
    }
    Ok(())
}

/// Default and maximum page size for `list_opnsense_change_sets`.
const DEFAULT_LIST_LIMIT: u32 = 50;
const MAX_LIST_LIMIT: u32 = 200;

/// One change set as status and list report it.
///
/// `include_preview` for callers who may approve; `include_actions` only
/// under `--web-enabled-approver`. The preview and actions carry device
/// pre-images, so the preview is tagged as untrusted.
pub(crate) fn status_view(
    record: &ChangeSetRecord,
    include_preview: bool,
    include_actions: bool,
) -> serde_json::Value {
    let mut view = serde_json::json!({
        "change_set_id": record.id,
        "device": record.device,
        "owner": record.owner,
        "state": record.state.as_str(),
        "approver": record.approval.as_ref().and_then(|approval| approval.approver.clone()),
        "approval_waiver": record
            .approval
            .as_ref()
            .and_then(|approval| approval.waived.as_ref())
            .map(|waiver| waiver.reason.clone()),
        "expires_at_unix": record.expires_at_unix,
        "plan_digest": record.digest,
        "expected_fingerprint": record.expected_candidate_fingerprint,
        "action_count": record.actions.len(),
    });
    let Some(object) = view.as_object_mut() else {
        return view;
    };
    if include_preview && let Some(preview) = record.preview.as_ref() {
        object.insert(
            "preview".to_owned(),
            serde_json::Value::String(
                mecmcp_redact::Untrusted::new(preview.artifact.as_str())
                    .render_tagged("get_opnsense_change_set_status.preview"),
            ),
        );
    }
    if include_actions {
        object.insert(
            "actions".to_owned(),
            serde_json::Value::Array(record.actions.clone()),
        );
    }
    view
}

/// A page of one device's change sets, latest expiry first.
///
/// # Errors
///
/// Returns a message when `limit` is outside 1..=200.
pub(crate) fn list_view(
    records: Vec<ChangeSetRecord>,
    device: &str,
    limit: Option<u32>,
    offset: Option<u32>,
) -> Result<serde_json::Value, String> {
    let limit = limit.unwrap_or(DEFAULT_LIST_LIMIT);
    if !(1..=MAX_LIST_LIMIT).contains(&limit) {
        return Err(format!(
            "limit must be between 1 and {MAX_LIST_LIMIT}, got {limit}"
        ));
    }
    let offset = offset.unwrap_or(0) as usize;

    let mut mine: Vec<ChangeSetRecord> = records
        .into_iter()
        .filter(|record| record.device == device)
        .collect();
    mine.sort_by(|left, right| {
        right
            .expires_at_unix
            .cmp(&left.expires_at_unix)
            .then_with(|| left.id.cmp(&right.id))
    });

    let total = mine.len();
    let rows: Vec<serde_json::Value> = mine
        .iter()
        .skip(offset)
        .take(limit as usize)
        .map(|record| status_view(record, false, false))
        .collect();
    let end = offset.saturating_add(rows.len());
    let next_offset = (end < total).then_some(end);

    Ok(serde_json::json!({
        "rows": rows,
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_offset": next_offset,
    }))
}

/// Why `confirm_opnsense_change_set` refuses in this build.
pub(crate) fn refuse_confirm(device: &str, operation_id: &str) -> String {
    if let Err(error) = mecmcp_changeset::OperationId::new(operation_id.to_owned()) {
        return format!("operation_id is not a valid operation id: {error}");
    }
    format!(
        "no commit-confirmed apply is pending for operation {operation_id} on '{device}': this \
         build applies without a confirm window"
    )
}

/// The recorded state and the reported word for an apply outcome.
///
/// Only a clean apply is `Applied`. Every partial or refused outcome is
/// `Failed`, so the store never says a partial apply succeeded.
pub(crate) fn settled_state(state: State) -> (ChangeSetState, &'static str) {
    match state {
        State::Applied => (ChangeSetState::Applied, "applied"),
        State::AppliedUnverified => (ChangeSetState::Applied, "applied_unverified"),
        State::Partial => (ChangeSetState::Failed, "partial"),
        State::PartialRollbackFailed => (ChangeSetState::Failed, "partial_rollback_failed"),
        State::RefusedStale => (ChangeSetState::Failed, "refused_stale"),
        State::NotLoaded => (ChangeSetState::Failed, "not_loaded"),
    }
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

    #[test]
    fn confirm_timeout_mins_is_refused_for_an_alias_change_set() {
        let planned = record("alice", "fw-1", ResourceKind::Alias);
        let error = pre_apply_gate(&planned, &planned.digest, FINGERPRINT, Some(5)).unwrap_err();
        assert!(error.contains("refused for alias"), "{error}");
    }

    #[test]
    fn confirm_timeout_mins_is_refused_for_rules_until_savepoints_land() {
        let planned = record("alice", "fw-1", ResourceKind::Rule);
        let error = pre_apply_gate(&planned, &planned.digest, FINGERPRINT, Some(5)).unwrap_err();
        assert!(error.contains("not available in this build"), "{error}");
        assert!(pre_apply_gate(&planned, &planned.digest, FINGERPRINT, None).is_ok());
    }

    #[test]
    fn apply_is_refused_on_a_digest_the_plan_does_not_carry() {
        let planned = record("alice", "fw-1", ResourceKind::Alias);
        let stale = format!("sha256:{}", "0".repeat(64));
        let error = pre_apply_gate(&planned, &stale, FINGERPRINT, None).unwrap_err();
        assert!(error.contains("plan digest"), "{error}");
    }

    #[test]
    fn apply_is_refused_when_the_live_fingerprint_has_drifted() {
        let planned = record("alice", "fw-1", ResourceKind::Alias);
        let drifted = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
        // The caller names a fingerprint the plan was not built against.
        assert!(pre_apply_gate(&planned, &planned.digest, drifted, None).is_err());
        // The caller names the plan's fingerprint, but the device has moved on.
        assert!(check_fingerprint(&planned.expected_candidate_fingerprint, drifted).is_err());
    }

    #[test]
    fn status_hides_the_plan_from_a_read_only_caller() {
        let planned = record("alice", "fw-1", ResourceKind::Alias);
        let view = status_view(&planned, false, false);
        assert_eq!(view["plan_digest"], planned.digest.as_str());
        assert!(view.get("preview").is_none());
        assert!(view.get("actions").is_none());

        let approver_view = status_view(&planned, true, false);
        assert!(
            approver_view["preview"]
                .as_str()
                .unwrap()
                .contains("untrusted-device-content")
        );
        assert!(approver_view.get("actions").is_none());

        let web_view = status_view(&planned, true, true);
        assert!(web_view["actions"].is_array());
    }

    #[test]
    fn list_filters_by_device_and_pages() {
        let mut records = vec![
            record("alice", "fw-1", ResourceKind::Alias),
            record("bob", "fw-1", ResourceKind::Rule),
            record("carol", "fw-2", ResourceKind::Alias),
        ];
        records[0].expires_at_unix = 10;
        records[1].expires_at_unix = 20;

        let page = list_view(records.clone(), "fw-1", Some(1), None).unwrap();
        assert_eq!(page["total"], 2);
        assert_eq!(page["rows"][0]["owner"], "bob");
        assert_eq!(page["next_offset"], 1);

        let second = list_view(records, "fw-1", Some(1), Some(1)).unwrap();
        assert_eq!(second["rows"][0]["owner"], "alice");
        assert_eq!(second["next_offset"], serde_json::Value::Null);
    }

    #[test]
    fn list_limit_is_bounded() {
        assert!(list_view(Vec::new(), "fw-1", Some(0), None).is_err());
        assert!(list_view(Vec::new(), "fw-1", Some(201), None).is_err());
    }

    #[test]
    fn confirm_refuses_because_no_confirm_window_is_ever_open() {
        let message = refuse_confirm("fw-1", &"a".repeat(64));
        assert!(
            message.contains("no commit-confirmed apply is pending"),
            "{message}"
        );
        let malformed = refuse_confirm("fw-1", "../etc");
        assert!(malformed.contains("operation_id"), "{malformed}");
    }

    #[tokio::test]
    async fn cancel_frees_the_pending_slot() {
        let coordinator = coordinator(false);
        let planned = record("alice", "fw-1", ResourceKind::Alias);
        let id = planned.id.clone();
        finish_creation(&coordinator, planned).await.unwrap();
        assert!(
            ensure_no_pending(&coordinator, "alice", "fw-1")
                .await
                .is_err()
        );

        coordinator
            .cancel_change_set(id, "fw-1".to_owned(), "alice".to_owned())
            .await
            .unwrap();
        assert!(
            ensure_no_pending(&coordinator, "alice", "fw-1")
                .await
                .is_ok()
        );
    }

    #[test]
    fn settled_state_never_records_a_partial_apply_as_applied() {
        for state in [
            State::Partial,
            State::PartialRollbackFailed,
            State::RefusedStale,
            State::NotLoaded,
        ] {
            let (settled, _) = settled_state(state);
            assert_eq!(settled, ChangeSetState::Failed, "{state:?}");
        }
        assert_eq!(settled_state(State::Partial).1, "partial");
        assert_eq!(
            settled_state(State::PartialRollbackFailed).1,
            "partial_rollback_failed"
        );
        assert_eq!(settled_state(State::Applied).0, ChangeSetState::Applied);
        assert_eq!(
            settled_state(State::AppliedUnverified).1,
            "applied_unverified"
        );
    }
}
