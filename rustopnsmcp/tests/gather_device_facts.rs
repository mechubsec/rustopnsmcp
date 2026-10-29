#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! `gather_device_facts` through the server's tool-call path, against a mock
//! device serving the 26.7 response shapes. This is what pins the server's own
//! wiring: a handler still reading the old system-status fields would return
//! null uptime and load while every core-crate test stayed green.

use rmcp::ServiceExt as _;
use rmcp::model::CallToolRequestParams;
use rustopnsmcp::server::OpnsenseServer;
use rustopnsmcp_core::endpoints as ep;
use rustopnsmcp_core::inventory::DeviceRegistry;
use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;
use std::time::Duration;

/// Serve `routes` (path to JSON body) over TLS from a background thread,
/// one request per connection. Returns the port.
fn serve_tls(
    server_config: rustls::ServerConfig,
    routes: HashMap<String, serde_json::Value>,
) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(server_config);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let connection = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
            let mut tls = rustls::StreamOwned::new(connection, stream);
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while tls.read_exact(&mut byte).is_ok() {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&head);
            let path = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");
            let (status, body) = match routes.get(path) {
                Some(body) => (200, body.to_string()),
                None => (404, r#"{"error":"no fixture"}"#.to_owned()),
            };
            let response = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = tls.write_all(response.as_bytes());
            let _ = tls.flush();
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    port
}

fn write_private(path: &std::path::Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Call `gather_device_facts` on a mock device and return the facts object
/// from inside the untrusted-content envelope.
async fn facts_json(routes: HashMap<String, serde_json::Value>) -> serde_json::Value {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();
    let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.der().clone()], key_der)
    .unwrap();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let port = serve_tls(server_config, routes);

    let dir = tempfile::tempdir().unwrap();
    let (ca, key, secret) = (
        dir.path().join("ca.pem"),
        dir.path().join("key"),
        dir.path().join("secret"),
    );
    write_private(&ca, &cert.pem());
    write_private(&key, "test-key");
    write_private(&secret, "test-secret");
    let devices = dir.path().join("devices.json");
    write_private(
        &devices,
        &serde_json::json!({ "version": 1, "devices": { "fw-1": {
            "endpoint": format!("https://localhost:{port}"),
            "api_key_file": key, "api_secret_file": secret, "ca_pem_path": ca } } })
        .to_string(),
    );

    let registry = Arc::new(DeviceRegistry::load(&devices).unwrap());
    let coordinator =
        rustopnsmcp::changeset_state::build_coordinator(None, Duration::from_secs(3600), false)
            .unwrap();
    let server = OpnsenseServer::new(
        registry,
        rustopnsmcp::server::ServerOptions::default(),
        coordinator,
    )
    .unwrap();
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let serving = tokio::spawn(async move {
        let running = server.serve(tokio::io::split(server_io)).await.unwrap();
        let _ = running.waiting().await;
    });
    let client = ().serve(tokio::io::split(client_io)).await.unwrap();
    let arguments = serde_json::json!({ "device": "fw-1" });
    let serde_json::Value::Object(arguments) = arguments else {
        unreachable!()
    };
    let result = client
        .call_tool(CallToolRequestParams::new("gather_device_facts").with_arguments(arguments))
        .await
        .unwrap();
    client.cancel().await.unwrap();
    let _ = serving.await;
    assert_ne!(result.is_error, Some(true), "{result:?}");
    let text = serde_json::to_value(&result.content).unwrap()[0]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    let facts_line = text.lines().find(|line| line.starts_with('{')).unwrap();
    serde_json::from_str(facts_line).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tool_reports_uptime_load_and_product_name_from_26_7_shapes() {
    let routes = HashMap::from([
        (
            ep::SYSTEM_STATUS.to_owned(),
            serde_json::json!({ "metadata": { "system": { "status": 2, "message": "ok", "title": "t" },
                "translations": {}, "subsystems": [] } }),
        ),
        (
            ep::SYSTEM_TIME.to_owned(),
            serde_json::json!({ "uptime": "3 days, 04:12", "loadavg": "0.12, 0.09, 0.05",
                "datetime": "x", "boottime": "x", "config": "x" }),
        ),
        (
            ep::FIRMWARE_STATUS.to_owned(),
            serde_json::json!({ "status": "none", "product": { "product_name": "OPNsense",
                "product_version": "26.7.5", "product_latest": "26.7.5", "product_series": "26.7" } }),
        ),
    ]);
    let facts = facts_json(routes).await;
    assert_eq!(facts["product_name"], "OPNsense");
    assert_eq!(facts["uptime"], "3 days, 04:12");
    assert_eq!(facts["load_average"], "0.12, 0.09, 0.05");
    assert!(facts.get("cpu_type").is_none(), "{facts}");
}
