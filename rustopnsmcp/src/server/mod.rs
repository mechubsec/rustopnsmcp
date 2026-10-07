//! The MCP server handler.

mod audit;
mod lifecycle;
mod respond;

use mecmcp_auth::NoGrant;
use mecmcp_changeset::{
    ApplyHandle, ChangeSetRecord, ChangeSetState, ChangesetCoordinator, PreviewRecord,
    change_set_digest, preview_digest,
};
use mecmcp_redact::Untrusted;
use mecmcp_server::{
    OutputRedaction, ResultFormat, ResultLimits, authorize_call, caller_from_extensions,
    filter_tools_for_scope, tool_error, tool_result,
};
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, tool::ToolCallContext, wrapper::Parameters},
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerConfig,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use rustopnsmcp_core::{
    changeset::{
        OpnsenseTransaction, Outcome, Preimage, StagedMutation, State, actions_for,
        apply_sequentially, canonicalize_mutations, check_single_resource_kind,
        check_writable_fields, config_fingerprint, diff_against_preimage, mutations_of,
        preimage_of, validate_locally,
    },
    client::OpnsenseClient,
    error::OpnsenseError,
    inventory::DeviceRegistry,
    tools::{WRITE_TOOLS, changeset, fleet, read},
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Result size limits for MCP tool responses.
const RESULT_LIMITS: ResultLimits = ResultLimits {
    max_text_bytes: 512 * 1024,
    max_json_bytes: 512 * 1024,
};

/// This server's extensions to `mecmcp-redact`'s generic denylist-and-shape
/// scan.
///
/// Empty today: none of OPNsense's nine read-tool resources or two
/// mutable-resource kinds (aliases, filter rules) has a field name that both
/// collides with the generic denylist by substring and is not a secret, and
/// none embeds a vendor-rendered body the generic scan cannot see into. A
/// `const` is declared anyway, matching every other vendor server in this
/// family, so a future OPNsense resource that does need an exemption (a
/// paging cursor, a BGP community on a routing-protocol integration) is a
/// one-line change here rather than a re-plumb of every call site below.
const OPNSENSE_PROFILE: mecmcp_redact::Profile = mecmcp_redact::Profile::new(&[], &[]);

/// Seconds since the Unix epoch.
///
/// A clock before the epoch is not a case worth branching on; it reports 0,
/// which makes every approval look old and therefore expired — the safe
/// direction for a gate.
fn unix_seconds_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Operator choices the server consults per call.
#[derive(Debug, Clone, Copy)]
pub struct ServerOptions {
    /// `--web-enabled-approver`: include staged actions in status output.
    pub web_enabled_approver: bool,
    /// `--inventory-readonly`: refuse `add_device` and `reload_devices`.
    pub inventory_readonly: bool,
    /// `--allow-direct-commit`, as the shared policy type.
    pub direct_commit: mecmcp_audit::DirectCommitPolicy,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            web_enabled_approver: false,
            inventory_readonly: false,
            direct_commit: mecmcp_audit::DirectCommitPolicy::new(false),
        }
    }
}

/// The OPNsense MCP server.
#[derive(Clone)]
pub struct OpnsenseServer {
    /// Device inventory.
    registry: Arc<DeviceRegistry>,
    /// Clients per device. `RwLock` allows rebuild on SIGHUP.
    clients: Arc<std::sync::RwLock<BTreeMap<String, OpnsenseClient>>>,
    /// Operator choices from the command line.
    ///
    /// `web_enabled_approver`, `inventory_readonly`, and `direct_commit` are
    /// not yet read by any handler (Tasks 14-17 wire them in); `lab_mode`
    /// was the only field read here, and Task 12 removed it from this
    /// struct now that the coordinator is its sole holder.
    #[allow(dead_code)]
    options: ServerOptions,
    /// The change-set lifecycle.
    ///
    /// `mecmcp-changeset`'s coordinator, not a map: it owns the transition
    /// policy, the claim-before-apply, and the preview-bound approval, and
    /// the approval TTL that `--approval-timeout-secs` configures.
    coordinator: Arc<ChangesetCoordinator>,
    /// When this server was built, for `opnsmcp_status`.
    started: std::time::Instant,
    /// Tool router.
    tool_router: ToolRouter<Self>,
}

impl OpnsenseServer {
    /// Create a new server with the given registry, lab mode, and
    /// coordinator.
    ///
    /// # Errors
    ///
    /// Returns an error if any device's client cannot be built.
    pub fn new(
        registry: Arc<DeviceRegistry>,
        options: ServerOptions,
        coordinator: Arc<ChangesetCoordinator>,
    ) -> Result<Self, OpnsenseError> {
        let clients = Self::build_clients(&registry)?;
        Ok(Self {
            registry,
            clients: Arc::new(std::sync::RwLock::new(clients)),
            options,
            coordinator,
            started: std::time::Instant::now(),
            tool_router: Self::opns_tool_router(),
        })
    }

    /// Build HTTP clients for all devices in the registry.
    fn build_clients(
        registry: &DeviceRegistry,
    ) -> Result<BTreeMap<String, OpnsenseClient>, OpnsenseError> {
        let mut clients = BTreeMap::new();
        for name in registry.names() {
            let device = registry.get(&name)?;
            clients.insert(name.clone(), OpnsenseClient::new(device)?);
        }
        Ok(clients)
    }

    /// Rebuild all clients from the current registry state.
    ///
    /// Called on SIGHUP after the registry has been reloaded, so that
    /// configuration changes (endpoint, credential, CA) take effect without
    /// restarting the server.
    ///
    /// # Errors
    ///
    /// Returns an error if any client cannot be built. On error, the previous
    /// clients are retained.
    pub fn rebuild_clients(&self) -> Result<usize, OpnsenseError> {
        let new_clients = Self::build_clients(&self.registry)?;
        let count = new_clients.len();

        let mut clients = self
            .clients
            .write()
            .map_err(|_| OpnsenseError::Malformed("clients lock poisoned".to_owned()))?;

        *clients = new_clients;
        Ok(count)
    }

    /// Get a reference to the client for a device.
    fn client_for(&self, device: &str) -> Result<OpnsenseClient, Box<CallToolResult>> {
        let clients = self
            .clients
            .read()
            .map_err(|_| Box::new(tool_error("clients lock poisoned".to_owned())))?;

        clients
            .get(device)
            .cloned()
            .ok_or_else(|| Box::new(tool_error(format!("unknown device: {device}"))))
    }

    /// The shared body of every device read: scope, client, read, respond.
    async fn read_device<F, Fut>(
        &self,
        context: &RequestContext<RoleServer>,
        tool: &'static str,
        device: &str,
        read: F,
    ) -> CallToolResult
    where
        F: FnOnce(OpnsenseClient) -> Fut,
        Fut: std::future::Future<Output = Result<serde_json::Value, OpnsenseError>>,
    {
        let caller = Self::caller(context);
        if let Err(error) = authorize_call(caller.as_ref(), tool, Some(device), WRITE_TOOLS) {
            return tool_error(error);
        }
        let client = match self.client_for(device) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        respond::respond_device(tool, read(client).await)
    }

    /// Recover the caller from the request context.
    fn caller(context: &RequestContext<RoleServer>) -> Option<mecmcp_auth::CallerCtx<NoGrant>> {
        caller_from_extensions::<NoGrant>(&context.extensions).cloned()
    }

    /// The principal behind this call.
    fn principal(caller: Option<&mecmcp_auth::CallerCtx<NoGrant>>) -> String {
        caller.map_or_else(|| "unknown".to_owned(), |ctx| ctx.token_name.clone())
    }

    /// Map a caller's server-verified `mecmcp_auth::ActorType` to the
    /// `mecmcp_audit::ActorType` `approve_change_set` requires.
    ///
    /// `None` — no authenticated caller context, i.e. the stdio transport —
    /// maps to `Unknown` rather than `Human`. Inventing `Human` for an
    /// unattributed caller would let stdio silently satisfy the human-approver
    /// gate; `Unknown` is the honest fact, and `approve_change_set` refuses it
    /// exactly like it refuses `Agent`.
    fn approver_actor_type(
        caller: Option<&mecmcp_auth::CallerCtx<NoGrant>>,
    ) -> mecmcp_audit::ActorType {
        match caller {
            Some(ctx) => match ctx.actor_type {
                mecmcp_auth::ActorType::Human => mecmcp_audit::ActorType::Human,
                mecmcp_auth::ActorType::Agent => mecmcp_audit::ActorType::Agent,
                mecmcp_auth::ActorType::Unknown => mecmcp_audit::ActorType::Unknown,
            },
            None => mecmcp_audit::ActorType::Unknown,
        }
    }

    /// Fetch a change set, refusing a device that does not own it.
    async fn record_for(
        &self,
        change_set_id: &str,
        device: &str,
    ) -> Result<ChangeSetRecord, Box<CallToolResult>> {
        self.coordinator
            .change_set(change_set_id, device)
            .await
            .map_err(|error| {
                Box::new(tool_error(format!(
                    "change set {change_set_id} on {device} ({}): {}",
                    error.field(),
                    error.message()
                )))
            })
    }

    /// Read the plan back off a stored record.
    fn plan_of(
        record: &ChangeSetRecord,
    ) -> Result<(Vec<StagedMutation>, Preimage), Box<CallToolResult>> {
        let mutations = mutations_of(&record.actions)
            .map_err(|error| Box::new(tool_error(format!("stored change set: {error}"))))?;
        let preimage = preimage_of(&record.actions)
            .map_err(|error| Box::new(tool_error(format!("stored change set: {error}"))))?;
        Ok((mutations, preimage))
    }

    /// Render the preview an approver signs off on.
    ///
    /// The atomicity declaration is part of the preview on purpose. OPNsense
    /// offers no atomic apply, no dry run and no guaranteed rollback, and an
    /// approver who is not told that is approving something else.
    fn render_preview(
        device: &str,
        mutations: &[StagedMutation],
        preimage: &Preimage,
    ) -> Result<String, Box<CallToolResult>> {
        let diff = diff_against_preimage(preimage, mutations)
            .map_err(|error| Box::new(tool_error(format!("failed to compute diff: {error}"))))?;
        let atomicity = OpnsenseTransaction::atomicity();
        let noun = mutations
            .first()
            .map_or("alias", |mutation| mutation.kind().noun());
        let commit_verb = mutations
            .first()
            .map_or("reconfigure", |mutation| mutation.kind().commit_verb());
        let identity_field = if noun == "alias" {
            "name"
        } else {
            "description"
        };

        let mut rendered = serde_json::json!({
            "device": device,
            "staged_count": mutations.len(),
            "atomicity": {
                "atomic_apply": atomicity.atomic_apply,
                "dry_run_validation": atomicity.dry_run_validation,
                "guaranteed_rollback": atomicity.guaranteed_rollback,
                "note": format!(
                    "OPNsense writes each {noun} to config.xml immediately and only loads it \
                     into the live pf tables/ruleset on {commit_verb}: a partial apply is \
                     reachable and rollback is best-effort. {commit_verb} loads every pending \
                     {noun} edit currently in config.xml into the live pf tables/ruleset, not \
                     only this change set's mutations — including any unapproved edit made \
                     through the OPNsense GUI since this change set was created. Reconciling a \
                     create whose response was lost to a transport failure searches for a \
                     {noun} by {identity_field}; a concurrent GUI create with the same \
                     {identity_field} can be mistaken for this change set's own write and \
                     later deleted on rollback.",
                ),
            },
            "changes": diff.changes,
        });

        // The preview is returned to callers and persisted in the change-set
        // store; scrub secret-shaped values before either happens.
        mecmcp_redact::redact_json_value_with_profile(&mut rendered, &OPNSENSE_PROFILE);

        serde_json::to_string_pretty(&rendered)
            .map_err(|error| Box::new(tool_error(format!("failed to render the preview: {error}"))))
    }

    /// Build the complete, immutable record for a new change set.
    ///
    /// The digest binds `(owner, device, fingerprint, actions)`; the
    /// fingerprint is the live configuration fingerprint the caller named and
    /// the server just re-read.
    fn plan_record(
        &self,
        owner: &str,
        device: &str,
        fingerprint: &str,
        mutations: &[StagedMutation],
        preimage: &Preimage,
    ) -> Result<ChangeSetRecord, Box<CallToolResult>> {
        let actions = actions_for(mutations, preimage)
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| Box::new(tool_error(format!("failed to store the plan: {error}"))))?;
        let digest = change_set_digest(owner, device, fingerprint, &actions)
            .map_err(|error| Box::new(tool_error(format!("failed to digest the plan: {error}"))))?;
        let artifact = Self::render_preview(device, mutations, preimage)?;
        Ok(ChangeSetRecord {
            id: crate::changeset_state::new_change_set_id(),
            owner: owner.to_owned(),
            device: device.to_owned(),
            expected_candidate_fingerprint: fingerprint.to_owned(),
            actions,
            digest,
            state: ChangeSetState::Planned,
            approver: None,
            approval: None,
            expires_at_unix: unix_seconds_now()
                .saturating_add(self.coordinator.approval_ttl().as_secs()),
            operation_id: None,
            policy_signature: String::new(),
            targets: Vec::new(),
            preview: Some(PreviewRecord {
                digest: preview_digest(&artifact),
                artifact,
                job_id: None,
            }),
            task_id: None,
            apply_without_handle: false,
        })
    }

    /// Refuse a plan the state file could not be reloaded with.
    fn check_plan_limits(record: &ChangeSetRecord) -> Result<(), Box<CallToolResult>> {
        let limits = crate::changeset_state::limits();

        mecmcp_changeset::validate_change_set_actions(&record.actions, &limits).map_err(
            |error| {
                Box::new(tool_error(format!(
                    "staged plan refused ({}): {}",
                    error.field(),
                    error.message()
                )))
            },
        )?;

        if let Some(preview) = record.preview.as_ref()
            && preview.artifact.len() > limits.max_preview_bytes
        {
            return Err(Box::new(tool_error(format!(
                "the preview for this change set is {} bytes, over the {} the store \
                 accepts; stage fewer changes at once",
                preview.artifact.len(),
                limits.max_preview_bytes
            ))));
        }

        Ok(())
    }

    /// The `opnsmcp_status` body, as rustjunosmcp's `srxmcp_status` shapes it.
    pub(crate) fn opnsmcp_status_body(started: std::time::Instant) -> serde_json::Value {
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "endpoint": "opnsmcp",
            "uptime_seconds": std::time::Instant::now()
                .saturating_duration_since(started)
                .as_secs(),
        })
    }
}

#[tool_router(router = opns_tool_router, vis = "pub(crate)")]
impl OpnsenseServer {
    #[tool(
        name = "get_device_list",
        description = "The OPNsense devices visible to this caller, by name. Returns an \
                       empty list when the caller's device scope matches nothing in the \
                       inventory. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn get_device_list(
        &self,
        Parameters(_): Parameters<fleet::EmptyArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(caller.as_ref(), "get_device_list", None, WRITE_TOOLS) {
            return tool_error(error);
        }
        let names = mecmcp_auth::filter_device_names(caller.as_ref(), self.registry.names());
        tool_result(
            Ok::<_, String>(serde_json::json!({ "names": names })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "gather_device_facts",
        description = "Fact sheet for one OPNsense device: product name and version, latest \
                       available version, series, whether an upgrade needs a reboot, uptime, \
                       CPU and load. Read-only; never probes the update mirror. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn gather_device_facts(
        &self,
        Parameters(args): Parameters<fleet::GatherFactsArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let device = args.device.clone();
        self.read_device(
            &context,
            "gather_device_facts",
            &device,
            move |client| async move {
                let system = read::system_status(&client).await?;
                let firmware = read::firmware_status(&client).await?;
                Ok::<_, OpnsenseError>(fleet::facts_from(&args.device, &system, &firmware))
            },
        )
        .await
    }

    #[tool(
        name = "opnsmcp_status",
        description = "This server's version, endpoint name and uptime in seconds. Touches \
                       no device. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn opnsmcp_status(
        &self,
        Parameters(_): Parameters<fleet::EmptyArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(caller.as_ref(), "opnsmcp_status", None, WRITE_TOOLS) {
            return tool_error(error);
        }
        tool_result(
            Ok::<_, String>(Self::opnsmcp_status_body(self.started)),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "get_opnsense_system_status",
        description = "OPNsense system status: product version, uptime, CPU and load. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn get_opnsense_system_status(
        &self,
        Parameters(args): Parameters<read::DeviceArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.read_device(
            &context,
            "get_opnsense_system_status",
            &args.device,
            |client| async move { read::system_status(&client).await },
        )
        .await
    }

    #[tool(
        name = "get_opnsense_firmware_status",
        description = "OPNsense installed firmware version and available-update status. \
                       Read-only: never asks the device to probe its update mirror. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn get_opnsense_firmware_status(
        &self,
        Parameters(args): Parameters<read::DeviceArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.read_device(
            &context,
            "get_opnsense_firmware_status",
            &args.device,
            |client| async move { read::firmware_status(&client).await },
        )
        .await
    }

    #[tool(
        name = "list_opnsense_interfaces",
        description = "OPNsense interfaces overview. \
                       One page per call: limit (1-1000, default 200), offset (a multiple of \
                       limit), and max_bytes (1024-507904) bound the result; next_offset is \
                       null on the last page. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn list_opnsense_interfaces(
        &self,
        Parameters(args): Parameters<read::ListArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let device = args.device.clone();
        self.read_device(
            &context,
            "list_opnsense_interfaces",
            &device,
            move |client| async move { read::list_interfaces(&client, &args).await },
        )
        .await
    }

    #[tool(
        name = "list_opnsense_gateways",
        description = "OPNsense gateway status. \
                       One page per call: limit (1-1000, default 200), offset (a multiple of \
                       limit), and max_bytes (1024-507904) bound the result; next_offset is \
                       null on the last page. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn list_opnsense_gateways(
        &self,
        Parameters(args): Parameters<read::ListArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let device = args.device.clone();
        self.read_device(
            &context,
            "list_opnsense_gateways",
            &device,
            move |client| async move { read::list_gateways(&client, &args).await },
        )
        .await
    }

    #[tool(
        name = "list_opnsense_firewall_rules",
        description = "OPNsense firewall filter rules, optionally filtered by search_phrase. \
                       The result's coverage field is read from the firmware version: \
                       complete on 25.1 and later, mvc_only before 25.1 (legacy GUI rules are \
                       missing), unknown if the version could not be read. \
                       One page per call: limit (1-1000, default 200), offset (a multiple of \
                       limit), and max_bytes (1024-507904) bound the result; next_offset is \
                       null on the last page. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn list_opnsense_firewall_rules(
        &self,
        Parameters(args): Parameters<read::ListArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let device = args.device.clone();
        self.read_device(
            &context,
            "list_opnsense_firewall_rules",
            &device,
            move |client| async move { read::list_firewall_rules(&client, &args).await },
        )
        .await
    }

    #[tool(
        name = "list_opnsense_aliases",
        description = "OPNsense firewall aliases, optionally filtered by search_phrase. \
                       One page per call: limit (1-1000, default 200), offset (a multiple of \
                       limit), and max_bytes (1024-507904) bound the result; next_offset is \
                       null on the last page. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn list_opnsense_aliases(
        &self,
        Parameters(args): Parameters<read::ListArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let device = args.device.clone();
        self.read_device(
            &context,
            "list_opnsense_aliases",
            &device,
            move |client| async move { read::list_aliases(&client, &args).await },
        )
        .await
    }

    #[tool(
        name = "list_opnsense_nat_rules",
        description = "OPNsense outbound and 1:1 NAT rules, side by side. Port forwards \
                       (destination NAT) are NOT included. \
                       One page per call: limit (1-1000, default 200), offset (a multiple of \
                       limit), and max_bytes (1024-507904) bound the result; next_offset is \
                       null on the last page. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn list_opnsense_nat_rules(
        &self,
        Parameters(args): Parameters<read::ListArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let device = args.device.clone();
        self.read_device(
            &context,
            "list_opnsense_nat_rules",
            &device,
            move |client| async move { read::list_nat_rules(&client, &args).await },
        )
        .await
    }

    #[tool(
        name = "list_opnsense_routes",
        description = "OPNsense static routes, optionally filtered by search_phrase. \
                       One page per call: limit (1-1000, default 200), offset (a multiple of \
                       limit), and max_bytes (1024-507904) bound the result; next_offset is \
                       null on the last page. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn list_opnsense_routes(
        &self,
        Parameters(args): Parameters<read::ListArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let device = args.device.clone();
        self.read_device(
            &context,
            "list_opnsense_routes",
            &device,
            move |client| async move { read::list_routes(&client, &args).await },
        )
        .await
    }

    #[tool(
        name = "list_opnsense_dhcp_leases",
        description = "OPNsense DHCPv4 leases, optionally filtered by search_phrase. ISC \
                       DHCPv4 only; Kea and Dnsmasq leases are NOT covered. \
                       One page per call: limit (1-1000, default 200), offset (a multiple of \
                       limit), and max_bytes (1024-507904) bound the result; next_offset is \
                       null on the last page. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn list_opnsense_dhcp_leases(
        &self,
        Parameters(args): Parameters<read::ListArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let device = args.device.clone();
        self.read_device(
            &context,
            "list_opnsense_dhcp_leases",
            &device,
            move |client| async move { read::list_dhcp_leases(&client, &args).await },
        )
        .await
    }

    #[tool(
        name = "get_opnsense_config_fingerprint",
        description = "Fingerprint of the governed OPNsense configuration (every firewall \
                       alias and filter rule), as sha256:<hex>, for use by the change-set \
                       tools to detect a configuration change since this fingerprint was \
                       taken. OPNsense has no candidate configuration: this fingerprints the \
                       running one. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn get_opnsense_config_fingerprint(
        &self,
        Parameters(args): Parameters<changeset::FingerprintArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let device = args.device.clone();
        self.read_device(
            &context,
            "get_opnsense_config_fingerprint",
            &device,
            move |client| async move {
                let fingerprint = config_fingerprint(&client).await?;
                Ok::<_, OpnsenseError>(serde_json::json!({
                    "device": args.device,
                    "fingerprint": fingerprint,
                    "covers": ["firewall_aliases", "firewall_filter_rules"],
                }))
            },
        )
        .await
    }

    #[tool(
        name = "create_opnsense_change_set",
        description = "Plans a change set of firewall alias or filter rule creates, updates \
                       or deletes in one call; all actions must target one resource kind. \
                       expected_fingerprint must come from get_opnsense_config_fingerprint; \
                       the plan is refused if the configuration changed since. Nothing is \
                       written to the device: OPNsense has no candidate configuration, so \
                       the plan is held here with a pre-image of every resource it touches. \
                       Returns change_set_id, plan_digest and the preview an approver \
                       reviews. Under --lab-mode the approval is waived at creation and \
                       recorded as approval_waiver lab-mode with no approver. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn create_opnsense_change_set(
        &self,
        Parameters(args): Parameters<changeset::CreateChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "create_opnsense_change_set",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }
        let owner = Self::principal(caller.as_ref());
        let client = match self.client_for(&args.device) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        if args.actions.is_empty() {
            return tool_error("a change set needs at least one action");
        }
        let mut mutations: Vec<StagedMutation> = args
            .actions
            .into_iter()
            .map(changeset::MutationSpec::into_mutation)
            .collect();
        if let Err(error) = check_single_resource_kind(&mutations) {
            return tool_error(format!("change set refused: {error}"));
        }
        // Canonicalize before the digest, the preview and verification ever
        // see the values, so a value that lands correctly cannot read as a
        // mismatch because of the order or separator the caller used.
        canonicalize_mutations(&mut mutations);
        // Before the pre-image: a disallowed field must never enter a plan a
        // human could approve.
        if let Err(error) = check_writable_fields(&mutations) {
            return tool_error(format!("change set refused: {error}"));
        }
        if let Err(refusal) =
            lifecycle::ensure_no_pending(&self.coordinator, &owner, &args.device).await
        {
            return tool_error(refusal);
        }

        let live = match config_fingerprint(&client).await {
            Ok(live) => live,
            Err(error) => return respond::respond_device("create_opnsense_change_set", Err(error)),
        };
        if let Err(refusal) = lifecycle::check_fingerprint(&args.expected_fingerprint, &live) {
            return tool_error(refusal);
        }

        let preimage = match Preimage::capture(&client, &mutations).await {
            Ok(preimage) => preimage,
            Err(error) => return respond::respond_device("create_opnsense_change_set", Err(error)),
        };
        if let Err(error) = validate_locally(&preimage, &mutations) {
            return tool_error(format!("change set refused: {error}"));
        }

        let record = match self.plan_record(&owner, &args.device, &live, &mutations, &preimage) {
            Ok(record) => record,
            Err(result) => return *result,
        };
        if let Err(result) = Self::check_plan_limits(&record) {
            return *result;
        }
        let preview = record
            .preview
            .as_ref()
            .map(|preview| preview.artifact.clone())
            .unwrap_or_default();

        let created = match lifecycle::finish_creation(&self.coordinator, record).await {
            Ok(created) => created,
            Err(refusal) => return tool_error(refusal),
        };

        let result = serde_json::json!({
            "change_set_id": created.change_set_id,
            "plan_digest": created.digest,
            "expected_fingerprint": live,
            "state": created.state.as_str(),
            "approver": created.approver,
            "approval_waiver": created.approval_waiver,
            "expires_at_unix": created.expires_at_unix,
            "preview": Untrusted::new(preview.as_str()).render_tagged("create_opnsense_change_set.preview"),
        });
        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "approve_opnsense_change_set",
        description = "Approves a change set for apply. expected_digest is required and must \
                       be the plan_digest you reviewed; the approval is refused if the plan \
                       differs. The approver must be a second, human principal: the creating \
                       token can never approve its own change set. Under --lab-mode change \
                       sets are approved by a waiver at creation and there is nothing to \
                       approve. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn approve_opnsense_change_set(
        &self,
        Parameters(args): Parameters<changeset::ApproveChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "approve_opnsense_change_set",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let approver = Self::principal(caller.as_ref());

        let record = match self.record_for(&args.change_set_id, &args.device).await {
            Ok(record) => record,
            Err(result) => return *result,
        };

        if record.actions.is_empty() {
            return tool_error("change set has nothing staged; there is nothing to approve");
        }

        let Some(preview) = record.preview.clone() else {
            return tool_error(
                "approval refused: this change set has no stored preview, so there is \
                 nothing to review. Create it again.",
            );
        };

        let (approval_mutations, _) = match Self::plan_of(&record) {
            Ok(plan) => plan,
            Err(result) => return *result,
        };
        if let Err(e) = check_writable_fields(&approval_mutations) {
            return tool_error(format!("approval refused: {e}"));
        }

        let approver_actor_type = Self::approver_actor_type(caller.as_ref());

        let outcome = match lifecycle::approve(
            &self.coordinator,
            &args.change_set_id,
            &args.device,
            &approver,
            approver_actor_type,
            &args.expected_digest,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(refusal) => return tool_error(refusal),
        };

        let result = serde_json::json!({
            "change_set_id": outcome.change_set_id,
            "state": outcome.state.as_str(),
            "approved_by": outcome.approver,
            "approval_waiver": outcome.approval_waiver,
            "expires_at_unix": outcome.expires_at_unix,
            "approved_digest": outcome.digest,
            "preview": preview.artifact,
        });
        // `preview.artifact` was already redacted when `render_preview` built
        // it, but redacting again here is what keeps this call site correct
        // on its own rather than relying on staging-time behavior a future
        // change could quietly break.
        Self::already_redacted_result("approve_opnsense_change_set", result)
    }

    #[tool(
        name = "apply_opnsense_change_set",
        description = "Applies an approved change set. expected_digest and \
                       expected_fingerprint are required; apply is refused, with nothing \
                       written, if the plan digest differs or the live configuration \
                       fingerprint has changed since the plan was built. confirm_timeout_mins \
                       is refused: OPNsense offers commit-confirmed apply only for firewall \
                       filter rules, and not yet in this build. The writes are a sequence of \
                       independent REST calls followed by one reconfigure/apply: OPNsense has \
                       no candidate configuration, so a partial failure is a reachable outcome \
                       and is reported as partial, and rollback replays a stored pre-image \
                       best-effort. reconfigure/apply also loads any unapproved edit already \
                       in config.xml. Output is redacted: values matching known secret \
                       patterns (API keys and secrets, pre-shared keys, private keys, \
                       certificates, password hashes) are replaced before being returned, and \
                       device-sourced content is marked as untrusted."
    )]
    async fn apply_opnsense_change_set(
        &self,
        Parameters(args): Parameters<changeset::ApplyChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "apply_opnsense_change_set",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.device) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        // Everything refusable without the device or a claim, up front.
        let record = match self.record_for(&args.change_set_id, &args.device).await {
            Ok(record) => record,
            Err(result) => return *result,
        };
        if let Err(refusal) = lifecycle::pre_apply_gate(
            &record,
            &args.expected_digest,
            &args.expected_fingerprint,
            args.confirm_timeout_mins,
        ) {
            return tool_error(refusal);
        }

        // The drift check OPNsense does not provide: re-read the live
        // configuration fingerprint and compare it to the one the plan was
        // built against.
        let live = match config_fingerprint(&client).await {
            Ok(live) => live,
            Err(error) => return respond::respond_device("apply_opnsense_change_set", Err(error)),
        };
        if let Err(refusal) = lifecycle::check_fingerprint(&args.expected_fingerprint, &live) {
            return tool_error(format!("apply refused: {refusal}"));
        }

        // Claim last, and only now. The claim is the single legal route from
        // `Approved` to `Applying`, and it does the check and the write
        // under one lock, so two concurrent applies cannot both observe
        // `Approved` and both proceed.
        if let Err(error) = self
            .coordinator
            .change_set_status(args.change_set_id.clone(), args.device.clone())
            .await
        {
            return tool_error(format!(
                "apply refused ({}): {}",
                error.field(),
                error.message()
            ));
        }

        let claimed = match self
            .coordinator
            .claim_change_set_for_apply(&args.change_set_id, &args.device, ApplyHandle::None)
            .await
        {
            Ok(record) => record,
            Err(error) => {
                return tool_error(format!(
                    "apply refused ({}): {}",
                    error.field(),
                    error.message()
                ));
            }
        };

        if unix_seconds_now() >= claimed.expires_at_unix {
            let deadline = claimed.expires_at_unix;
            self.settle_failed(
                claimed,
                "an expired change set could not be settled after its claim",
            )
            .await;
            return tool_error(format!(
                "apply refused: the approval window closed at {deadline}; nothing was \
                 written. Re-plan and re-approve before applying."
            ));
        }

        let (mutations, preimage) = match Self::plan_of(&claimed) {
            Ok(plan) => plan,
            Err(result) => {
                self.settle_failed(
                    claimed,
                    "a claimed change set could not be settled after its \
                     plan failed to read",
                )
                .await;
                return *result;
            }
        };

        if let Err(e) = check_writable_fields(&mutations) {
            self.settle_failed(
                claimed,
                "a claimed change set could not be settled after its \
                     writable-field check failed",
            )
            .await;
            return tool_error(format!("apply refused: {e}"));
        }

        let outcome = apply_sequentially(&client, &preimage, &mutations).await;
        let (settled_state, _) = lifecycle::settled_state(outcome.state);

        let mut settled = claimed;
        settled.state = settled_state;

        // The device has acted, so this cannot fail closed — refusing now
        // would not un-act it. Reported instead.
        if let Err(error) = self.coordinator.update_change_set(settled).await {
            tracing::error!(
                change_set_id = %args.change_set_id,
                field = error.field(),
                message = error.message(),
                "the apply outcome could not be recorded"
            );
        }

        Self::apply_outcome_response(&args.change_set_id, &outcome)
    }

    /// Settle a claimed change set as `Failed` before any device write.
    async fn settle_failed(&self, mut claimed: ChangeSetRecord, why: &'static str) {
        let id = claimed.id.clone();
        claimed.state = ChangeSetState::Failed;
        if let Err(error) = self.coordinator.update_change_set(claimed).await {
            tracing::error!(
                change_set_id = %id,
                field = error.field(),
                message = error.message(),
                "{why}; it will stay Applying"
            );
        }
    }

    /// Build the tool result for a finished apply.
    ///
    /// The body always carries the outcome counts, applied or not: the
    /// caller needs to know what landed either way. But the audit choke
    /// point in `call_tool` settles purely from `is_error` on the returned
    /// `CallToolResult`, so a partial or rollback-failed apply must set it
    /// -- that record is the one a SOC reviews after an incident that
    /// half-applied a change, and it must not read as a plain success.
    fn apply_outcome_response(change_set_id: &str, outcome: &Outcome) -> CallToolResult {
        let state_str = match outcome.state {
            State::Applied => "applied",
            State::AppliedUnverified => "applied_unverified",
            State::Partial => "partial",
            State::PartialRollbackFailed => "partial_rollback_failed",
            State::RefusedStale => "refused_stale",
            State::NotLoaded => "not_loaded",
        };
        let succeeded = matches!(outcome.state, State::Applied | State::AppliedUnverified);

        let result = serde_json::json!({
            "change_set_id": change_set_id,
            "state": state_str,
            "succeeded": outcome.succeeded.len(),
            "failed": outcome.failed.len(),
            "attempted_and_failed": outcome.attempted_and_failed.len(),
            "never_attempted": outcome.never_attempted.len(),
            "rollback_failures": outcome.rollback_failures,
            "verification_failure": outcome.verification_failure,
        });

        let mut response = tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        );
        if !succeeded {
            response.is_error = Some(true);
        }
        response
    }

    #[tool(
        name = "opnsense_get_change_set",
        description = "Returns the current status and contents of a change set. \
                       Output is redacted: values matching known secret patterns (API keys \
                       and secrets, pre-shared keys, private keys, certificates, password \
                       hashes) are replaced before being returned, and device-sourced \
                       content is marked as untrusted."
    )]
    async fn opnsense_get_change_set(
        &self,
        Parameters(args): Parameters<changeset::GetChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_get_change_set",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        if let Err(error) = self
            .coordinator
            .change_set_status(args.change_set_id.clone(), args.device.clone())
            .await
        {
            return tool_error(format!(
                "change set {} on {} ({}): {}",
                args.change_set_id,
                args.device,
                error.field(),
                error.message()
            ));
        }

        let record = match self.record_for(&args.change_set_id, &args.device).await {
            Ok(record) => record,
            Err(result) => return *result,
        };

        let result = serde_json::json!({
            "change_set_id": record.id,
            "device": record.device,
            "creator": record.owner,
            "approver": record.approval.as_ref().and_then(|a| a.approver.clone()),
            "approval_waiver": record
                .approval
                .as_ref()
                .and_then(|a| a.waived.as_ref())
                .map(|waiver| waiver.kind.as_str()),
            "state": record.state.as_str(),
            "mutation_count": record.actions.len(),
            "expires_at_unix": record.expires_at_unix,
            "plan_digest": record.digest,
            "expected_preimage_fingerprint": record.expected_candidate_fingerprint,
            "preview": record.preview.as_ref().map(|preview| preview.artifact.clone()),
        });

        Self::already_redacted_result("opnsense_get_change_set", result)
    }
}

impl OpnsenseServer {
    /// Redact `value` with [`OPNSENSE_PROFILE`] and wrap it as a tool result
    /// tagged `OutputRedaction::AlreadyRedacted`.
    ///
    /// This is the single call site every `AlreadyRedacted`-tagged tool
    /// result goes through — each change-set tool that redacts inline
    /// before returning its own result shape. Routing every one of them
    /// through the same function is what lets a unit test exercise the
    /// exact code the handlers run: if a future edit dropped the
    /// redaction call from here, every caller — and the test — would
    /// fail together, rather than a handler drifting from a copy of this
    /// logic the test never touches.
    fn already_redacted_result(tool: &'static str, mut value: serde_json::Value) -> CallToolResult {
        mecmcp_redact::redact_json_value_with_profile(&mut value, &OPNSENSE_PROFILE);
        tool_result(
            Ok::<_, String>(value),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::AlreadyRedacted {
                tool,
                redacted_by: "OPNSENSE_PROFILE",
            },
        )
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for OpnsenseServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "rustopnsmcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "OPNsense MCP server. Device-addressed tools take (device, ...); the server \
                 routes to the device by name from devices.json. Governed writes to firewall \
                 aliases and filter rules follow get_opnsense_config_fingerprint -> \
                 create_opnsense_change_set -> approve_opnsense_change_set (second, human \
                 principal) -> apply_opnsense_change_set with the plan digest and fingerprint. \
                 OPNsense has no candidate configuration: a partial apply is reachable and is \
                 reported.",
            )
    }

    /// Audit and scope-check every call at one choke point.
    ///
    /// Defined by hand, which suppresses the `call_tool` `#[tool_handler]`
    /// would generate. The body is the generated one with the audit scope
    /// around it.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&context.extensions);
        let tool = request.name.to_string();
        let mut audit = audit::open(caller, &tool, request.arguments.as_ref());
        let device = audit::device_hint(request.arguments.as_ref());
        if let Some(change_set_id) = audit::change_set_id_hint(request.arguments.as_ref()) {
            audit.meta("change_set_id", change_set_id);
        }

        if let Err(error) = authorize_call(caller, &tool, device.as_deref(), WRITE_TOOLS) {
            audit.deny("scope");
            return Ok(CallToolResponse::Complete(tool_error(error)));
        }

        let call = ToolCallContext::new(self, request, context);
        let result = self.tool_router.call(call).await;
        audit::settle(&mut audit, &result);
        result
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&context.extensions);
        let all_tools = self.tool_router.list_all();
        let visible = filter_tools_for_scope(all_tools, caller, WRITE_TOOLS);
        Ok(ListToolsResult::with_all_items(visible))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustopnsmcp_core::changeset::{ResourceKind, fingerprint_of};

    /// The router and the registry must agree, in both directions.
    #[test]
    fn the_router_serves_exactly_the_registered_tools() {
        use rustopnsmcp_core::tools::TOOL_NAMES;
        use std::collections::BTreeSet;

        let router = OpnsenseServer::opns_tool_router();
        let all_tools = router.list_all();
        let served_names: BTreeSet<String> =
            all_tools.iter().map(|tool| tool.name.to_string()).collect();
        let registered_names: BTreeSet<String> =
            TOOL_NAMES.iter().map(|s| (*s).to_owned()).collect();

        assert_eq!(
            served_names, registered_names,
            "TOOL_NAMES and the tool router must list exactly the same tools"
        );
    }

    #[test]
    fn opnsmcp_status_reports_version_endpoint_and_uptime() {
        let body = OpnsenseServer::opnsmcp_status_body(std::time::Instant::now());
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(body["endpoint"], "opnsmcp");
        assert!(body["uptime_seconds"].is_u64());
    }

    /// Spec §3.1: every tool description states its redaction contract.
    #[test]
    fn every_tool_description_states_the_redaction_contract() {
        let router = OpnsenseServer::opns_tool_router();
        for tool in router.list_all() {
            let description = tool.description.as_deref().unwrap_or_default();
            assert!(
                description.contains(rustopnsmcp_core::tools::REDACTION_CONTRACT),
                "{} does not state the redaction contract: {description}",
                tool.name
            );
        }
    }

    /// The published max_bytes range must match the ceiling `page_request`
    /// actually enforces, or a model that follows the description gets
    /// refused on its first call.
    #[test]
    fn list_tool_descriptions_state_the_real_max_bytes_range() {
        let expected = format!(
            "max_bytes ({}-{})",
            rustopnsmcp_core::tools::read::MIN_MAX_BYTES,
            rustopnsmcp_core::tools::read::MAX_BYTES_CEILING
        );
        let router = OpnsenseServer::opns_tool_router();
        for tool in router.list_all() {
            let description = tool.description.as_deref().unwrap_or_default();
            if description.contains("max_bytes") {
                assert!(
                    description.contains(&expected),
                    "{} does not state the real max_bytes range ({expected}): {description}",
                    tool.name
                );
            }
        }
    }

    /// Spec §3.1: reads are `list_opnsense_*` or `get_opnsense_*`; the old
    /// `opnsense_*` prefix does not survive.
    #[test]
    fn no_tool_keeps_the_old_opnsense_prefix_for_reads() {
        for name in rustopnsmcp_core::tools::TOOL_NAMES {
            let is_old_read = name.starts_with("opnsense_") && !name.ends_with("_change_set");
            assert!(!is_old_read, "{name} still uses the pre-v1 read prefix");
        }
    }

    /// The only content a result carries, so a test can assert on it.
    fn text_of(result: &CallToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(|block| block.as_text().map(|text| text.text.clone()))
            .collect()
    }

    fn outcome_with_state(state: State) -> Outcome {
        Outcome {
            state,
            succeeded: Vec::new(),
            failed: Vec::new(),
            attempted_and_failed: Vec::new(),
            never_attempted: Vec::new(),
            rollback_failures: Vec::new(),
            verification_failure: None,
        }
    }

    /// A fully applied outcome reaches the audit choke point as a success:
    /// `call_tool`'s `audit::settle` reads `is_error` off the result rmcp
    /// delivers, so this is the one place that mapping can be checked
    /// without standing up the whole stdio server.
    #[test]
    fn a_fully_applied_outcome_is_not_an_audit_error() {
        for state in [State::Applied, State::AppliedUnverified] {
            let response =
                OpnsenseServer::apply_outcome_response("cs-1", &outcome_with_state(state));
            assert_ne!(response.is_error, Some(true), "{state:?}");
        }
    }

    /// A partial apply, a rollback that itself failed, a stale refusal, and
    /// a config-xml write that never reached `pf` are all end states where
    /// the device was not left as approved. None of them may settle as a
    /// success at the audit choke point -- before this test, `is_error` was
    /// never set and every one of these reached the SIEM as `succeeded`.
    #[test]
    fn a_non_applied_outcome_is_an_audit_error_and_keeps_its_change_set_id() {
        for state in [
            State::Partial,
            State::PartialRollbackFailed,
            State::RefusedStale,
            State::NotLoaded,
        ] {
            let response =
                OpnsenseServer::apply_outcome_response("cs-partial-1", &outcome_with_state(state));
            assert_eq!(response.is_error, Some(true), "{state:?}");
            assert!(
                text_of(&response).contains("cs-partial-1"),
                "{state:?}: {}",
                text_of(&response)
            );
        }
    }

    /// The eleven read tools, all redacted through the shared
    /// [`respond::respond_device`] path with [`OPNSENSE_PROFILE`].
    const RESPOND_REDACTED_TOOLS: &[&str] = &[
        "gather_device_facts",
        "get_opnsense_system_status",
        "get_opnsense_firmware_status",
        "list_opnsense_interfaces",
        "list_opnsense_gateways",
        "list_opnsense_firewall_rules",
        "list_opnsense_aliases",
        "list_opnsense_nat_rules",
        "list_opnsense_routes",
        "list_opnsense_dhcp_leases",
        "get_opnsense_config_fingerprint",
    ];

    /// The two read-shaped change-set tools that redact their own result
    /// with [`OPNSENSE_PROFILE`] before `tool_result`, tagging
    /// `OutputRedaction::AlreadyRedacted` because the unconditional generic
    /// pass `OutputRedaction::Apply` runs would otherwise be a silent
    /// re-redaction of already-clean data.
    const ALREADY_REDACTED_TOOLS: &[&str] =
        &["approve_opnsense_change_set", "opnsense_get_change_set"];

    /// The two change-set lifecycle tools that carry no caller-controlled
    /// free text of their own (ids, digests, counts) and rely on
    /// `tool_result`'s unconditional `OutputRedaction::Apply` pass.
    const APPLY_REDACTED_TOOLS: &[&str] = &[
        "create_opnsense_change_set",
        "apply_opnsense_change_set",
        "get_device_list",
        "opnsmcp_status",
    ];

    /// Every registered tool must be accounted for by exactly one of the
    /// three redaction strategies above. A tool added to the router without
    /// being added to one of these lists — and so without a considered
    /// redaction choice — fails this test rather than silently returning
    /// unredacted device data.
    #[test]
    fn every_registered_tool_has_a_named_redaction_strategy() {
        use rustopnsmcp_core::tools::TOOL_NAMES;
        use std::collections::BTreeSet;

        let registered: BTreeSet<&str> = TOOL_NAMES.iter().copied().collect();
        let accounted: Vec<&str> = RESPOND_REDACTED_TOOLS
            .iter()
            .chain(ALREADY_REDACTED_TOOLS)
            .chain(APPLY_REDACTED_TOOLS)
            .copied()
            .collect();
        let accounted_set: BTreeSet<&str> = accounted.iter().copied().collect();

        assert_eq!(
            accounted.len(),
            accounted_set.len(),
            "a tool name appears in more than one redaction-strategy list"
        );
        assert_eq!(
            accounted_set, registered,
            "every tool in TOOL_NAMES must appear in exactly one redaction-strategy list above"
        );
    }

    /// A response containing a distinct, synthetic secret for each of the
    /// ten read tools comes back redacted, and no tool's rendered output
    /// contains any planted secret — not just the one its own fixture
    /// plants, so a tool that leaked the *wrong* secret would still be
    /// caught (mirrors `mecmcp_redact::testing::tools_leaking_secrets`'s own
    /// coverage rationale).
    ///
    /// The marker (`PLANTX<tool>Q9`) contains none of
    /// `mecmcp_redact`'s denylisted words (no "secret", "token", "key", ...),
    /// so a match here proves the `password` field or the `key=value` free-text
    /// shape was actually recognised.
    #[test]
    fn respond_redacts_every_known_opnsense_secret_shape() {
        let secrets: Vec<String> = RESPOND_REDACTED_TOOLS
            .iter()
            .map(|tool| format!("PLANTX{tool}Q9"))
            .collect();
        let secret_refs: Vec<&str> = secrets.iter().map(String::as_str).collect();

        let leaking = mecmcp_redact::testing::tools_leaking_secrets(
            RESPOND_REDACTED_TOOLS,
            &secret_refs,
            |tool| {
                // `respond_device` takes `tool: &'static str`; look the
                // caller's borrowed name back up in the `'static` registry
                // instead of leaking a fresh allocation per call.
                let static_name = RESPOND_REDACTED_TOOLS
                    .iter()
                    .copied()
                    .find(|name| *name == tool)
                    .expect("tool is drawn from this same registry");
                let secret = format!("PLANTX{tool}Q9");
                let value = serde_json::json!({
                    // Denylisted key: caught regardless of value shape.
                    "password": secret,
                    // Free text under a non-denylisted key: only the
                    // `key=value` shape scan catches this one.
                    "description": format!("rollout notes: password={secret}"),
                    "note": "unrelated clean field",
                });
                let result = respond::respond_device(static_name, Ok(value));
                text_of(&result)
            },
        );

        // `leaking` is a list of tool names (from the registry), never a
        // secret value, but CodeQL's taint tracking still treats it as
        // tainted because `secret` flowed into the exercised closure
        // upstream. A bare `assert!` (no format-args message) keeps the
        // tainted value out of any panic/log sink entirely, rather than
        // just out of the message text.
        assert!(leaking.is_empty());
    }

    /// The change-set tools that redact inline with `OPNSENSE_PROFILE` before
    /// tagging `OutputRedaction::AlreadyRedacted` must not let a
    /// secret-shaped value in a caller-supplied free-text field (a
    /// description or a rendered preview) survive that inline pass.
    ///
    /// This drives [`OpnsenseServer::already_redacted_result`] — the exact
    /// function every `AlreadyRedacted` call site calls — rather than calling
    /// `mecmcp_redact::redact_json_value_with_profile` directly, so a handler
    /// that stopped routing through it would fail this test too, not just a
    /// copy of its logic the test never touches.
    #[test]
    fn already_redacted_change_set_tools_strip_secret_shaped_free_text() {
        let secrets: Vec<String> = ALREADY_REDACTED_TOOLS
            .iter()
            .map(|tool| format!("PLANTX{tool}Q9"))
            .collect();
        let secret_refs: Vec<&str> = secrets.iter().map(String::as_str).collect();

        let leaking = mecmcp_redact::testing::tools_leaking_secrets(
            ALREADY_REDACTED_TOOLS,
            &secret_refs,
            |tool| {
                let static_name = ALREADY_REDACTED_TOOLS
                    .iter()
                    .copied()
                    .find(|name| *name == tool)
                    .expect("tool is drawn from this same registry");
                let secret = format!("PLANTX{tool}Q9");
                let value = serde_json::json!({
                    "description": format!("rollout notes: password={secret}"),
                    "preview": {
                        "artifact": format!("plan text mentioning password={secret}"),
                    },
                    "state": "planned",
                });
                let result = OpnsenseServer::already_redacted_result(static_name, value);
                text_of(&result)
            },
        );

        // See the matching note in `respond_redacts_every_known_opnsense_secret_shape`:
        // a bare `assert!` avoids any format-args sink for the tainted value.
        assert!(leaking.is_empty());
    }

    /// The four change-set lifecycle tools are the only mutating surface;
    /// this is meant to stay visible rather than silently assumed.
    #[test]
    fn write_tools_covers_the_change_set_lifecycle() {
        assert_eq!(WRITE_TOOLS.len(), 4);
        assert!(WRITE_TOOLS.contains(&"create_opnsense_change_set"));
    }

    /// A stdio caller carries no verified token entry, so its actor type
    /// must map to `Unknown` rather than `Human` — approving with that
    /// identity must fail exactly as an agent's approval would.
    #[test]
    fn approver_actor_type_maps_stdio_to_unknown_not_human() {
        assert_eq!(
            OpnsenseServer::approver_actor_type(None),
            mecmcp_audit::ActorType::Unknown
        );
    }

    /// The preview is returned to callers and persisted in the change-set
    /// store, so a secret-shaped value in a staged body must be scrubbed.
    #[test]
    fn render_preview_redacts_secret_shaped_text_in_a_staged_body() {
        let preimage = Preimage::from_resources(Vec::new());
        let mutations = vec![StagedMutation::create(
            ResourceKind::Alias,
            serde_json::json!({
                "name": "test_alias",
                "type": "host",
                "description": "rollout notes: password=hunter2",
            }),
        )];

        let artifact =
            OpnsenseServer::render_preview("home", &mutations, &preimage).expect("renders");

        assert!(!artifact.contains("hunter2"), "{artifact}");
        assert!(artifact.contains("REDACTED"), "{artifact}");
    }

    fn coordinator_at(path: Option<&std::path::Path>) -> Arc<ChangesetCoordinator> {
        crate::changeset_state::build_coordinator(path, std::time::Duration::from_secs(300), true)
            .expect("coordinator")
    }

    fn planned_record(owner: &str, device: &str, ttl: u64) -> ChangeSetRecord {
        let mutations = vec![StagedMutation::create(
            ResourceKind::Alias,
            serde_json::json!({
                "name": "test_alias",
                "type": "host",
                "content": "10.0.0.1"
            }),
        )];
        let preimage = Preimage::from_resources(Vec::new());
        let actions = actions_for(&mutations, &preimage);
        let fingerprint = fingerprint_of(&actions).expect("fingerprint");
        let stored_actions: Vec<serde_json::Value> = actions
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<_, _>>()
            .expect("serialize");
        let digest =
            change_set_digest(owner, device, &fingerprint, &stored_actions).expect("digest");

        ChangeSetRecord {
            id: crate::changeset_state::new_change_set_id(),
            owner: owner.to_owned(),
            device: device.to_owned(),
            expected_candidate_fingerprint: fingerprint,
            actions: stored_actions,
            digest,
            state: ChangeSetState::Planned,
            approver: None,
            approval: None,
            expires_at_unix: unix_seconds_now().saturating_add(ttl),
            operation_id: None,
            policy_signature: String::new(),
            targets: Vec::new(),
            preview: Some(PreviewRecord {
                digest: preview_digest("preview"),
                artifact: "preview".to_owned(),
                job_id: None,
            }),
            task_id: None,
            apply_without_handle: false,
        }
    }

    /// An unapproved change set must not be claimable for apply: the claim
    /// is the coordinator's single legal route from `Approved` to
    /// `Applying`, and a `Planned` record has no business reaching it.
    #[tokio::test]
    async fn an_unapproved_change_set_cannot_be_claimed_for_apply() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        let error = coordinator
            .claim_change_set_for_apply(&id, "home", ApplyHandle::None)
            .await
            .expect_err("a planned change set cannot be claimed");
        assert!(error.message().contains("Approved"), "{}", error.message());
    }

    /// Two-person control: the owner cannot approve their own plan outside
    /// lab mode, and the coordinator itself enforces this — not just this
    /// server's UI-level check.
    #[tokio::test]
    async fn the_owner_cannot_approve_their_own_plan() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        let digest = record.digest.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        let error = coordinator
            .approve_change_set(
                id,
                "home".to_owned(),
                "alice".to_owned(),
                digest,
                mecmcp_audit::ActorType::Human,
            )
            .await
            .expect_err("self-approval must be refused");
        assert!(error.message().contains("own plan"), "{}", error.message());
    }

    /// An agent or unattributed caller cannot serve as the second principal,
    /// even naming the right digest and a different owner: the house rule is
    /// a human approves, not merely "not the owner".
    #[tokio::test]
    async fn only_a_human_actor_type_can_approve() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        let digest = record.digest.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        let error = coordinator
            .approve_change_set(
                id,
                "home".to_owned(),
                "bob".to_owned(),
                digest,
                mecmcp_audit::ActorType::Agent,
            )
            .await
            .expect_err("an agent approver must be refused");
        assert!(error.field() == "approver_actor_type", "{}", error.field());
    }

    /// A waiver requires lab mode; without it, waiving is refused exactly
    /// like a bare self-approval would be.
    #[tokio::test]
    async fn a_waiver_is_refused_when_lab_mode_is_off() {
        let coordinator = crate::changeset_state::build_coordinator(
            None,
            std::time::Duration::from_secs(300),
            false,
        )
        .expect("coordinator");
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        let digest = record.digest.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        let error = coordinator
            .waive_approval(id, "home".to_owned(), "alice".to_owned(), digest)
            .await
            .expect_err("lab mode is off");
        assert!(error.message().contains("lab mode"), "{}", error.message());
    }

    /// An approval naming a digest the plan has since moved past must be
    /// refused: the whole point of `expected_digest` is that it binds to a
    /// plan the approver actually read.
    #[tokio::test]
    async fn approving_a_digest_the_plan_has_moved_past_is_refused() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        let error = coordinator
            .approve_change_set(
                id,
                "home".to_owned(),
                "bob".to_owned(),
                format!("sha256:{}", "0".repeat(64)),
                mecmcp_audit::ActorType::Human,
            )
            .await
            .expect_err("a stale digest must be refused");
        assert!(error.field() == "expected_digest", "{}", error.field());
    }

    /// A change set is not reachable from a device it was not planned
    /// against — the coordinator addresses records by `(id, device)`.
    #[tokio::test]
    async fn a_change_set_is_not_reachable_from_another_device() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        assert!(coordinator.change_set(&id, "home").await.is_ok());
        assert!(coordinator.change_set(&id, "office").await.is_err());
    }
}
