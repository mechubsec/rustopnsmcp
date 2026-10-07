#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! Every registered tool emits exactly the audit record spec §3.3 requires,
//! including a call rmcp rejects before any handler runs.
//!
//! The server is driven in process over an in-memory duplex pipe, the same
//! stdio path `main` serves. Each call runs on a current-thread runtime inside
//! `run_with_capture`, so the audit event lands in the capture buffer.

use mecmcp_audit::testutil::{run_with_capture, tools_without_audit_events};
use rmcp::ServiceExt as _;
use rmcp::model::CallToolRequestParams;
use rustopnsmcp::server::OpnsenseServer;
use rustopnsmcp_core::inventory::DeviceRegistry;
use rustopnsmcp_core::tools::TOOL_NAMES;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;
use std::time::Duration;

fn empty_registry(dir: &tempfile::TempDir) -> Arc<DeviceRegistry> {
    let path = dir.path().join("devices.json");
    std::fs::write(&path, r#"{"version":1,"devices":{}}"#).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    Arc::new(DeviceRegistry::load(&path).unwrap())
}

fn server() -> (tempfile::TempDir, OpnsenseServer) {
    let dir = tempfile::tempdir().unwrap();
    let registry = empty_registry(&dir);
    let coordinator =
        rustopnsmcp::changeset_state::build_coordinator(None, Duration::from_secs(3600), false)
            .unwrap();
    let server = OpnsenseServer::new(registry, false, coordinator).unwrap();
    (dir, server)
}

/// Call `tool` once, in process, with `arguments`.
fn call(tool: &str, arguments: serde_json::Value) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (_dir, server) = server();
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let serving = tokio::spawn(async move {
            let running = server.serve(tokio::io::split(server_io)).await.unwrap();
            let _ = running.waiting().await;
        });
        let client = ().serve(tokio::io::split(client_io)).await.unwrap();
        let serde_json::Value::Object(arguments) = arguments else {
            panic!("arguments must be a JSON object")
        };
        let _ = client
            .call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments))
            .await;
        client.cancel().await.unwrap();
        let _ = serving.await;
    });
}

#[test]
fn every_registered_tool_emits_an_audit_event() {
    let missing = tools_without_audit_events(TOOL_NAMES, |tool| {
        call(tool, serde_json::json!({ "device": "absent" }));
    });
    assert!(missing.is_empty(), "tools with no audit event: {missing:?}");
}

#[test]
fn a_call_rejected_for_unknown_arguments_is_still_audited() {
    let tool = TOOL_NAMES
        .iter()
        .find(|name| name.contains("aliases"))
        .unwrap();
    let captured = run_with_capture(|| {
        call(
            tool,
            serde_json::json!({ "device": "absent", "not_a_field": true }),
        );
    });
    assert!(captured.contains(&format!("tool={tool}")), "{captured}");
}

#[test]
fn an_unregistered_tool_name_is_audited_as_unknown() {
    let captured = run_with_capture(|| {
        call("no_such_tool", serde_json::json!({}));
    });
    assert!(captured.contains("tool=unknown_tool"), "{captured}");
}
