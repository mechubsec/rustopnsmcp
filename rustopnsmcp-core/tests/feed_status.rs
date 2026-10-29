//! `get_opnsense_feed_status` against a recording mock device: every request's
//! path and body is kept, so the tests can prove what the tool asked for.
//! Alias rows have the live row shape from `aliases.json`; URL-table values and
//! pf entries are synthetic (RFC 5737, example.org).

use rustopnsmcp_core::client::OpnsenseClient;
use rustopnsmcp_core::endpoints as ep;
use rustopnsmcp_core::error::OpnsenseError;
use rustopnsmcp_core::inventory::Device;
use rustopnsmcp_core::tools::feed;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Seen = Arc<Mutex<Vec<(String, String)>>>;

/// Generate a self-signed `localhost` certificate and a matching rustls
/// server config, ALPN-pinned to `http/1.1`.
fn tls_material() -> (String, rustls::ServerConfig) {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");

    let cert_pem = cert.pem();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der)
        .expect("server config");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    (cert_pem, server_config)
}

fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

async fn bind_local() -> (tokio::net::TcpListener, u16) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    (listener, port)
}

fn write_pem(pem: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(pem.as_bytes()).expect("write pem");
    file.flush().expect("flush");
    file
}

fn write_secret(value: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(value.as_bytes()).expect("write secret");
    file.flush().expect("flush");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(file.path())
            .expect("metadata")
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(file.path(), perms).expect("chmod");
    }
    file
}

fn device_for(
    port: u16,
    ca_pem_path: &std::path::Path,
    api_key_file: &std::path::Path,
    api_secret_file: &std::path::Path,
) -> Device {
    serde_json::from_value(serde_json::json!({
        "endpoint": format!("https://localhost:{port}"),
        "api_key_file": api_key_file,
        "api_secret_file": api_secret_file,
        "ca_pem_path": ca_pem_path,
    }))
    .expect("device parses")
}

/// Serve `routes` (path to JSON; `{"__status": N}` answers that status),
/// recording `(path, request body)` for every request.
fn serve_recording(
    listener: tokio::net::TcpListener,
    server_config: rustls::ServerConfig,
    routes: HashMap<String, Value>,
    seen: Seen,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let routes = Arc::new(routes);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let routes = Arc::clone(&routes);
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while tls.read_exact(&mut byte).await.is_ok() {
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let path = head
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_owned();
                let length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                let mut body = vec![0u8; length];
                let _ = tls.read_exact(&mut body).await;
                seen.lock()
                    .expect("seen lock")
                    .push((path.clone(), String::from_utf8_lossy(&body).into_owned()));
                let (status, body) = match routes.get(&path) {
                    Some(fixture) => (
                        fixture
                            .get("__status")
                            .and_then(Value::as_u64)
                            .unwrap_or(200),
                        fixture.to_string(),
                    ),
                    None => (404, r#"{"error":"no fixture"}"#.to_owned()),
                };
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.flush().await;
            });
        }
    });
}

async fn client_against(routes: HashMap<String, Value>, seen: Seen) -> OpnsenseClient {
    ensure_crypto_provider();
    let (cert_pem, server_config) = tls_material();
    let (listener, port) = bind_local().await;
    serve_recording(listener, server_config, routes, seen);

    let ca_file = write_pem(&cert_pem);
    let key_file = write_secret("test-key");
    let secret_file = write_secret("test-secret");
    let device = device_for(port, ca_file.path(), key_file.path(), secret_file.path());

    // Leak the temp files for the test's lifetime; they are cleaned up when
    // the process exits, and the client needs them to outlive this function.
    std::mem::forget(ca_file);
    std::mem::forget(key_file);
    std::mem::forget(secret_file);

    OpnsenseClient::new(device).expect("client builds")
}

const FEED: &str = "https://feeds.example.org:8443/feeds/opnsense-url-table";

fn urltable_row(name: &str, content: &str) -> Value {
    let mut row = rustopnsmcp_core::testing::fixture("aliases")["rows"][0].clone();
    row["name"] = name.into();
    row["uuid"] = format!("synthetic-{name}").into();
    row["type"] = "urltable".into();
    row["content"] = content.into();
    row["updatefreq"] = "1".into();
    row["authtype"] = "Basic".into();
    row
}

fn table(entries: &[&str]) -> Value {
    let rows: Vec<_> = entries.iter().map(|entry| json!({ "ip": entry })).collect();
    json!({ "total": rows.len(), "rowCount": rows.len(), "current": 1, "rows": rows })
}

/// Routes for the given `(alias row, table count, pf entries)` triples.
fn routes(aliases: &[(Value, u64, Value)]) -> HashMap<String, Value> {
    let rows: Vec<Value> = aliases.iter().map(|(row, _, _)| row.clone()).collect();
    let mut sizes = rustopnsmcp_core::testing::fixture("alias_table_size");
    let mut map = HashMap::new();
    for (row, count, entries) in aliases {
        let name = row["name"].as_str().unwrap();
        sizes["details"][name] = json!({ "count": count, "updated": null });
        map.insert(ep::alias_util_list(name), entries.clone());
    }
    map.insert(
        ep::ALIASES_SEARCH.to_owned(),
        json!({ "rows": rows, "total": rows.len(), "rowCount": rows.len(), "current": 1 }),
    );
    map.insert(ep::ALIASES_TABLE_SIZE.to_owned(), sizes);
    map
}

async fn run(map: HashMap<String, Value>, limit: u64) -> (Result<Value, OpnsenseError>, Seen) {
    let seen: Seen = Arc::default();
    let client = client_against(map, Arc::clone(&seen)).await;
    (feed::feed_status_with_limit(&client, limit).await, seen)
}

fn etag_of(status: &Value, index: usize) -> &Value {
    &status["feeds"][index]["content_etag"]
}

const ADDRESS_ETAG: &str =
    "\"sha256-89cb5847af66072db0628804bf9e87f0f688733e28db26d82774e270489e03a9\"";

fn good_address() -> (Value, u64, Value) {
    (
        urltable_row("feed_a", &format!("{FEED}/address")),
        3,
        table(&["2001:db8::1/128", "192.0.2.9", "192.0.2.1/32"]),
    )
}

#[tokio::test]
async fn a_complete_address_table_gets_the_serve_etag() {
    let (result, _) = run(routes(&[good_address()]), 50_000).await;
    assert_eq!(etag_of(&result.unwrap(), 0), ADDRESS_ETAG);
}

#[tokio::test]
async fn a_count_mismatch_nulls_the_etag() {
    let (row, _, entries) = good_address();
    let (result, _) = run(routes(&[(row, 4, entries)]), 50_000).await;
    assert!(etag_of(&result.unwrap(), 0).is_null());
}

#[tokio::test]
async fn a_domain_feed_has_no_etag_and_reads_no_table() {
    let row = urltable_row("feed_d", &format!("{FEED}/domain"));
    let (result, seen) = run(routes(&[(row, 1, table(&["192.0.2.1"]))]), 50_000).await;
    assert!(etag_of(&result.unwrap(), 0).is_null());
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .all(|(path, _)| !path.contains("alias_util"))
    );
}

#[tokio::test]
async fn a_table_over_the_cap_is_not_downloaded() {
    let (row, count, entries) = good_address();
    let (result, seen) = run(routes(&[(row, count, entries)]), 2).await;
    let status = result.unwrap();
    assert!(etag_of(&status, 0).is_null());
    assert_eq!(status["feeds"][0]["table_count"], 3);
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .all(|(path, _)| !path.contains("alias_util"))
    );
}

#[tokio::test]
async fn a_multi_url_alias_has_no_etag_on_any_entry() {
    let content = format!("{FEED}/address\nhttps://other.example.org/list.txt");
    let row = urltable_row("feed_m", &content);
    let (_, _, entries) = good_address();
    let (result, _) = run(routes(&[(row, 3, entries)]), 50_000).await;
    let status = result.unwrap();
    assert_eq!(status["feeds"].as_array().unwrap().len(), 1);
    assert!(etag_of(&status, 0).is_null());
    let both = format!("{FEED}/address\n{FEED}/prefix");
    let row = urltable_row("feed_m", &both);
    let (result, _) = run(routes(&[(row, 3, good_address().2)]), 50_000).await;
    let status = result.unwrap();
    assert_eq!(status["feeds"].as_array().unwrap().len(), 2);
    assert!(etag_of(&status, 0).is_null() && etag_of(&status, 1).is_null());
}

#[tokio::test]
async fn a_prefix_with_host_bits_set_has_no_etag() {
    let row = urltable_row("feed_p", &format!("{FEED}/prefix"));
    let (result, _) = run(routes(&[(row, 1, table(&["192.0.2.72/24"]))]), 50_000).await;
    assert!(etag_of(&result.unwrap(), 0).is_null());
}

#[tokio::test]
async fn both_listings_ask_for_all_rows() {
    let (result, seen) = run(routes(&[good_address()]), 50_000).await;
    result.unwrap();
    let seen = seen.lock().unwrap();
    for wanted in [ep::ALIASES_SEARCH.to_owned(), ep::alias_util_list("feed_a")] {
        let (_, body) = seen.iter().find(|(path, _)| *path == wanted).unwrap();
        let body: Value = serde_json::from_str(body).unwrap();
        assert_eq!(body["rowCount"], -1, "listing must ask for every row");
    }
}

#[tokio::test]
async fn a_failed_table_listing_costs_only_that_feed_its_etag() {
    let (good, count, entries) = good_address();
    let broken = urltable_row("feed_b", &format!("{FEED}/prefix"));
    let mut map = routes(&[(good, count, entries), (broken, 1, table(&[]))]);
    map.insert(
        ep::alias_util_list("feed_b"),
        json!({ "__status": 500, "detail": "boom" }),
    );
    let (result, _) = run(map, 50_000).await;
    let status = result.unwrap();
    assert_eq!(etag_of(&status, 0), ADDRESS_ETAG);
    assert!(etag_of(&status, 1).is_null());
    assert_eq!(
        status["feeds"][1]["etag_unavailable"],
        "pf table listing failed"
    );
    assert!(!status.to_string().contains("boom"), "device text echoed");
    assert!(status["feeds"][0].get("etag_unavailable").is_none());
}

#[tokio::test]
async fn an_auth_failure_on_a_table_listing_fails_the_call() {
    for code in [401, 403] {
        let (row, count, entries) = good_address();
        let mut map = routes(&[(row, count, entries)]);
        map.insert(ep::alias_util_list("feed_a"), json!({ "__status": code }));
        let (result, _) = run(map, 50_000).await;
        assert!(matches!(result, Err(OpnsenseError::Upstream { .. })));
    }
}

#[tokio::test]
async fn a_partial_alias_search_is_an_error() {
    let mut map = routes(&[good_address()]);
    let rows = map[ep::ALIASES_SEARCH]["rows"].clone();
    map.insert(
        ep::ALIASES_SEARCH.to_owned(),
        json!({ "rows": rows, "total": 5, "rowCount": 1, "current": 1 }),
    );
    let (result, _) = run(map, 50_000).await;
    assert!(matches!(result, Err(OpnsenseError::Malformed(_))));
}
