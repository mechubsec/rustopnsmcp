#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! `get_opnsense_feed_status` through the server's tool-call path, against a
//! mock device. The alias rows have the live row shape from `aliases.json`;
//! their URL-table values and the pf table entries are synthetic (RFC 5737),
//! because the lab has no URL-table alias to capture.

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

/// Call `get_opnsense_feed_status` on a mock device and return the result
/// object from inside the untrusted-content envelope.
async fn status_json(routes: HashMap<String, serde_json::Value>) -> serde_json::Value {
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
        .call_tool(CallToolRequestParams::new("get_opnsense_feed_status").with_arguments(arguments))
        .await
        .unwrap();
    client.cancel().await.unwrap();
    let _ = serving.await;
    assert_ne!(result.is_error, Some(true), "{result:?}");
    let text = serde_json::to_value(&result.content).unwrap()[0]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    let line = text.lines().find(|line| line.starts_with('{')).unwrap();
    assert!(!text.contains("synthetic-user"), "credentials leaked");
    serde_json::from_str(line).unwrap()
}

fn urltable_row(name: &str, content: &str) -> serde_json::Value {
    let mut row = rustopnsmcp_core::testing::fixture("aliases")["rows"][0].clone();
    row["name"] = name.into();
    row["uuid"] = format!("synthetic-{name}").into();
    row["type"] = "urltable".into();
    row["content"] = content.into();
    row["updatefreq"] = "1".into();
    row["authtype"] = "Basic".into();
    row["username"] = "synthetic-user".into();
    row
}

fn table(entries: &[&str]) -> serde_json::Value {
    let rows: Vec<_> = entries
        .iter()
        .map(|entry| serde_json::json!({ "ip": entry }))
        .collect();
    serde_json::json!({ "total": rows.len(), "rowCount": rows.len(), "current": 1, "rows": rows })
}

#[tokio::test(flavor = "multi_thread")]
async fn reports_subscriptions_with_etag_only_where_it_is_exact() {
    let feed = "https://feeds.example.org:8443/feeds/opnsense-url-table";
    let rows = vec![
        urltable_row(
            "feed_a",
            &format!("https://user:EXAMPLE@{}/address?x=1", &feed[8..]),
        ),
        urltable_row("feed_b", &format!("{feed}/prefix")),
        urltable_row("bad/../name", &format!("{feed}/address")),
        urltable_row("plain", "https://example.org/list.txt"),
    ];
    let mut sizes = rustopnsmcp_core::testing::fixture("alias_table_size");
    sizes["details"]["feed_a"] =
        serde_json::json!({ "count": 3, "updated": "2026-10-29T01:02:03" });
    sizes["details"]["feed_b"] = serde_json::json!({ "count": 5, "updated": null });
    let routes = HashMap::from([
        (
            ep::ALIASES_SEARCH.to_owned(),
            serde_json::json!({ "rows": rows, "total": 4, "rowCount": 4, "current": 1 }),
        ),
        (ep::ALIASES_TABLE_SIZE.to_owned(), sizes),
        (
            ep::alias_util_list("feed_a"),
            table(&["2001:db8::1/128", "192.0.2.9", "192.0.2.1/32"]),
        ),
        // Two entries against a table_count of 5: not the whole document.
        (
            ep::alias_util_list("feed_b"),
            table(&["198.51.100.0/24", "203.0.113.0/25"]),
        ),
    ]);
    let status = status_json(routes).await;
    let feeds = status["feeds"].as_array().unwrap();
    assert_eq!(feeds.len(), 2, "{status}");
    assert_eq!(feeds[0]["alias"], "feed_a");
    assert_eq!(
        feeds[0]["url"],
        "https://feeds.example.org:8443/feeds/opnsense-url-table/address"
    );
    assert_eq!(feeds[0]["kind"], "address");
    assert_eq!(feeds[0]["auth"], "Basic");
    assert_eq!(feeds[0]["table_count"], 3);
    // printf '192.0.2.1\n192.0.2.9\n2001:db8::1\n' | sha256sum
    assert_eq!(
        feeds[0]["content_etag"],
        "\"sha256-89cb5847af66072db0628804bf9e87f0f688733e28db26d82774e270489e03a9\""
    );
    assert_eq!(feeds[1]["alias"], "feed_b");
    assert_eq!(feeds[1]["table_count"], 5);
    assert!(feeds[1]["content_etag"].is_null(), "{status}");
    assert!(feeds[1]["table_updated"].is_null());
    let skipped = status["skipped"].as_array().unwrap();
    assert_eq!(skipped.len(), 1, "{status}");
    assert_eq!(skipped[0]["alias"], "bad/../name");
    assert!(
        skipped[0]["reason"]
            .as_str()
            .unwrap()
            .contains("[A-Za-z0-9_]")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_subscription_gives_an_empty_feed_list() {
    let routes = HashMap::from([(
        ep::ALIASES_SEARCH.to_owned(),
        rustopnsmcp_core::testing::fixture("aliases"),
    )]);
    assert_eq!(
        status_json(routes).await,
        serde_json::json!({ "feeds": [] })
    );
}
