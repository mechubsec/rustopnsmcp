//! Fixture-based, end-to-end tests for the phase 1 read tools.
//!
//! There is no live OPNsense lab device behind this crate. A local TLS
//! server stands in for one, answering each of the nine tools' requests with
//! a synthetic fixture keyed by request path. This is also where
//! `Device::ca_pem_path` — "TLS always verified, private CA replaces public
//! roots" — is exercised end to end: the mock's self-signed certificate is
//! trusted only because it is named as the device's CA, and a client that
//! trusts a *different* CA must be refused rather than falling back to the
//! public root store.

use rustopnsmcp_core::client::OpnsenseClient;
use rustopnsmcp_core::inventory::Device;
use rustopnsmcp_core::tools::read::{self, ListArgs};
use std::collections::HashMap;
use std::io::Write as _;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

/// Serve fixture responses, keyed by request path, until the process exits.
///
/// One connection per request: reads the request line and headers, drains
/// any request body per `Content-Length`, then answers with the fixture
/// registered for that path (or 404 for anything else) and closes.
fn serve_fixtures(
    listener: tokio::net::TcpListener,
    server_config: rustls::ServerConfig,
    routes: HashMap<String, serde_json::Value>,
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
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };

                let mut header_bytes = Vec::new();
                let mut byte = [0u8; 1];
                while tls.read_exact(&mut byte).await.is_ok() {
                    header_bytes.push(byte[0]);
                    if header_bytes.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let headers = String::from_utf8_lossy(&header_bytes);
                let path = headers
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_owned();

                if let Some(content_length) = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                {
                    let mut body = vec![0u8; content_length];
                    let _ = tls.read_exact(&mut body).await;
                }

                let response = match routes.get(&path) {
                    Some(fixture) => {
                        let body = fixture.to_string();
                        // A fixture of {"__status": N} makes the mock answer with that status.
                        let status = fixture
                            .get("__status")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or(200);
                        format!(
                            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    }
                    None => {
                        let body = format!(r#"{{"error":"no fixture for {path}"}}"#);
                        format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    }
                };
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.flush().await;
            });
        }
    });
}

/// Like [`serve_fixtures`], but also records the HTTP method of the first
/// request received for each path into `methods`.
fn serve_fixtures_recording_methods(
    listener: tokio::net::TcpListener,
    server_config: rustls::ServerConfig,
    routes: HashMap<String, serde_json::Value>,
    methods: Arc<std::sync::Mutex<HashMap<String, String>>>,
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
            let methods = Arc::clone(&methods);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };

                let mut header_bytes = Vec::new();
                let mut byte = [0u8; 1];
                while tls.read_exact(&mut byte).await.is_ok() {
                    header_bytes.push(byte[0]);
                    if header_bytes.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let headers = String::from_utf8_lossy(&header_bytes);
                let request_line = headers.lines().next().unwrap_or("");
                let method = request_line
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_owned();
                let path = request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_owned();

                methods
                    .lock()
                    .expect("methods lock")
                    .entry(path.clone())
                    .or_insert(method);

                if let Some(content_length) = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                {
                    let mut body = vec![0u8; content_length];
                    let _ = tls.read_exact(&mut body).await;
                }

                let response = match routes.get(&path) {
                    Some(fixture) => {
                        let body = fixture.to_string();
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    }
                    None => {
                        let body = format!(r#"{{"error":"no fixture for {path}"}}"#);
                        format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    }
                };
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.flush().await;
            });
        }
    });
}

/// Answer every request with a fixed status and an empty JSON-ish body,
/// regardless of path. Used to prove a non-2xx status becomes an error
/// rather than being parsed as a success.
fn serve_fixed_status(
    listener: tokio::net::TcpListener,
    server_config: rustls::ServerConfig,
    status_line: &'static str,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };

                let mut header_bytes = Vec::new();
                let mut byte = [0u8; 1];
                while tls.read_exact(&mut byte).await.is_ok() {
                    header_bytes.push(byte[0]);
                    if header_bytes.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }

                let body = "redirected";
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nLocation: https://localhost/elsewhere\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.flush().await;
            });
        }
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

fn default_routes() -> HashMap<String, serde_json::Value> {
    use rustopnsmcp_core::endpoints as ep;
    let fixture = rustopnsmcp_core::testing::fixture;
    HashMap::from([
        (ep::SYSTEM_STATUS.to_owned(), fixture("system_status")),
        (ep::FIRMWARE_STATUS.to_owned(), fixture("firmware_status")),
        (ep::INTERFACES_OVERVIEW.to_owned(), fixture("interfaces")),
        (ep::GATEWAYS_STATUS.to_owned(), fixture("gateways")),
        (
            ep::FIREWALL_RULES_SEARCH.to_owned(),
            fixture("firewall_rules"),
        ),
        (ep::ALIASES_SEARCH.to_owned(), fixture("aliases")),
        (ep::NAT_OUTBOUND_SEARCH.to_owned(), fixture("nat_outbound")),
        (
            ep::NAT_ONE_TO_ONE_SEARCH.to_owned(),
            fixture("nat_one_to_one"),
        ),
        (ep::ROUTES_SEARCH.to_owned(), fixture("routes")),
        (ep::DHCP_LEASES_SEARCH.to_owned(), fixture("dhcp_leases")),
    ])
}

async fn client_against(routes: HashMap<String, serde_json::Value>) -> OpnsenseClient {
    ensure_crypto_provider();
    let (cert_pem, server_config) = tls_material();
    let (listener, port) = bind_local().await;
    serve_fixtures(listener, server_config, routes);

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

fn no_filter() -> ListArgs {
    ListArgs {
        device: "fw".to_owned(),
        search_phrase: None,
        limit: None,
        offset: None,
        max_bytes: None,
    }
}

#[tokio::test]
async fn system_status_reads_the_fixture() {
    let client = client_against(default_routes()).await;
    let status = read::system_status(&client).await.expect("system status");
    assert_eq!(status["product_version"], "24.7");
}

/// The rewiring behind `gather_device_facts`: the three 26.7 shapes in, a fact
/// sheet with uptime, load and product name out, and no `cpu_type`.
#[tokio::test]
async fn device_facts_come_from_system_time_and_firmware_status() {
    use rustopnsmcp_core::endpoints as ep;
    let mut routes = default_routes();
    routes.insert(
        ep::SYSTEM_TIME.to_owned(),
        serde_json::json!({ "uptime": "3 days, 04:12", "loadavg": "0.12, 0.09, 0.05",
            "datetime": "x", "boottime": "x", "config": "x" }),
    );
    routes.insert(
        ep::FIRMWARE_STATUS.to_owned(),
        serde_json::json!({ "status": "none", "product": { "product_name": "OPNsense",
            "product_version": "26.7.5", "product_latest": "26.7.5", "product_series": "26.7" } }),
    );
    let client = client_against(routes).await;
    let facts = read::device_facts(&client, "fw-1").await.expect("facts");
    assert_eq!(facts["product_name"], "OPNsense");
    assert_eq!(facts["uptime"], "3 days, 04:12");
    assert_eq!(facts["load_average"], "0.12, 0.09, 0.05");
    assert!(facts.get("cpu_type").is_none());
}

#[tokio::test]
async fn firmware_status_reads_the_fixture() {
    let client = client_against(default_routes()).await;
    let status = read::firmware_status(&client)
        .await
        .expect("firmware status");
    assert_eq!(status["status"], "ok");
}

#[tokio::test]
async fn list_interfaces_pages_the_overview_by_identifier() {
    let client = client_against(default_routes()).await;
    let interfaces = read::list_interfaces(&client, &no_filter())
        .await
        .expect("list interfaces");
    assert_eq!(interfaces["total"], 2);
    assert_eq!(interfaces["rows"][0]["identifier"], "lan");
    assert_eq!(interfaces["rows"][1]["identifier"], "wan");
    assert_eq!(interfaces["next_offset"], serde_json::Value::Null);
}

#[tokio::test]
async fn list_gateways_pages_the_status_items() {
    let client = client_against(default_routes()).await;
    let gateways = read::list_gateways(&client, &no_filter())
        .await
        .expect("list gateways");
    assert_eq!(gateways["rows"][0]["name"], "WAN_DHCP");
    assert_eq!(gateways["offset"], 0);
}

#[tokio::test]
async fn a_search_phrase_on_a_tool_that_cannot_search_is_refused() {
    let client = client_against(default_routes()).await;
    let filtered = ListArgs {
        search_phrase: Some("wan".to_owned()),
        ..no_filter()
    };
    assert!(read::list_gateways(&client, &filtered).await.is_err());
}

#[tokio::test]
async fn list_firewall_rules_parses_the_search_envelope() {
    let client = client_against(default_routes()).await;
    let rules = read::list_firewall_rules(&client, &no_filter())
        .await
        .expect("list firewall rules");
    assert_eq!(rules["total"], 2);
    assert_eq!(rules["rows"].as_array().expect("rows array").len(), 2);
    // The firmware fixture reports 24.7, which predates legacy-rule merging.
    assert_eq!(rules["coverage"], "mvc_only");
    assert_eq!(rules["product_version"], "24.7");
}

#[tokio::test]
async fn list_aliases_parses_the_search_envelope() {
    let client = client_against(default_routes()).await;
    let aliases = read::list_aliases(&client, &no_filter())
        .await
        .expect("list aliases");
    assert_eq!(aliases["rows"][0]["name"], "rfc1918");
}

#[tokio::test]
async fn list_routes_parses_the_search_envelope() {
    let client = client_against(default_routes()).await;
    let routes = read::list_routes(&client, &no_filter())
        .await
        .expect("list routes");
    assert_eq!(routes["rows"][0]["network"], "198.51.100.0/24");
}

#[tokio::test]
async fn list_dhcp_leases_parses_the_search_envelope() {
    let client = client_against(default_routes()).await;
    let leases = read::list_dhcp_leases(&client, &no_filter())
        .await
        .expect("list dhcp leases");
    assert_eq!(leases["rows"][0]["hostname"], "example-host");
}

/// Routes for a device; `None` leaves that backend's settings endpoint absent (404).
/// ISC is served only when `isc` is true.
fn dhcp_routes(
    dnsmasq_enabled: Option<&str>,
    kea_enabled: Option<&str>,
    isc: bool,
) -> HashMap<String, serde_json::Value> {
    use rustopnsmcp_core::endpoints as ep;
    let mut routes = default_routes();
    routes.remove(ep::DHCP_LEASES_SEARCH);
    if isc {
        routes.insert(
            ep::DHCP_LEASES_SEARCH.to_owned(),
            rustopnsmcp_core::testing::fixture("dhcp_leases"),
        );
    }
    if let Some(enabled) = dnsmasq_enabled {
        routes.insert(
            ep::DNSMASQ_SETTINGS_GET.to_owned(),
            serde_json::json!({ "dnsmasq": { "enable": enabled } }),
        );
    }
    if let Some(enabled) = kea_enabled {
        routes.insert(
            ep::KEA_DHCPV4_GET.to_owned(),
            serde_json::json!({ "dhcpv4": { "general": { "enabled": enabled } } }),
        );
    }
    routes.insert(
        ep::DNSMASQ_LEASES_SEARCH.to_owned(),
        serde_json::json!({ "rows": [{ "address": "192.0.2.50" }], "rowCount": 1, "total": 1, "current": 1 }),
    );
    routes.insert(
        ep::KEA_LEASES4_SEARCH.to_owned(),
        serde_json::json!({ "rows": [], "rowCount": 0, "total": 0, "current": 1,
                            "stats": { "active": 0, "inactive": 0, "total": 0 } }),
    );
    routes
}

async fn dhcp_backend_for(
    dnsmasq: Option<&str>,
    kea: Option<&str>,
    isc: bool,
) -> Result<serde_json::Value, rustopnsmcp_core::error::OpnsenseError> {
    let client = client_against(dhcp_routes(dnsmasq, kea, isc)).await;
    read::list_dhcp_leases(&client, &no_filter()).await
}

#[tokio::test]
async fn dhcp_leases_come_from_dnsmasq_when_it_is_the_enabled_backend() {
    let leases = dhcp_backend_for(Some("1"), Some("0"), false)
        .await
        .expect("leases");
    assert_eq!(leases["backend"], "dnsmasq");
    assert_eq!(leases["rows"][0]["address"], "192.0.2.50");
}

#[tokio::test]
async fn dhcp_leases_come_from_dnsmasq_when_kea_is_not_installed() {
    let leases = dhcp_backend_for(Some("1"), None, false)
        .await
        .expect("leases");
    assert_eq!(leases["backend"], "dnsmasq");
}

#[tokio::test]
async fn dhcp_leases_come_from_kea_when_it_is_the_enabled_backend() {
    let leases = dhcp_backend_for(Some("0"), Some("1"), false)
        .await
        .expect("leases");
    assert_eq!(leases["backend"], "kea");
    let leases = dhcp_backend_for(None, Some("1"), false)
        .await
        .expect("leases");
    assert_eq!(leases["backend"], "kea");
}

#[tokio::test]
async fn two_enabled_dhcp_backends_both_return_their_pages() {
    let leases = dhcp_backend_for(Some("1"), Some("1"), true)
        .await
        .expect("leases");
    assert_eq!(leases["backend"], "dnsmasq+kea");
    assert_eq!(leases["dnsmasq"]["rows"][0]["address"], "192.0.2.50");
    assert_eq!(leases["kea"]["rows"].as_array().expect("kea rows").len(), 0);
    assert_eq!(leases["dnsmasq"]["total"], 1);
}

#[tokio::test]
async fn a_failing_settings_probe_is_an_error_not_a_fallthrough_to_isc() {
    use rustopnsmcp_core::endpoints as ep;
    for status in [401, 500] {
        for path in [ep::DNSMASQ_SETTINGS_GET, ep::KEA_DHCPV4_GET] {
            let mut routes = dhcp_routes(None, None, true);
            routes.insert(path.to_owned(), serde_json::json!({ "__status": status }));
            let client = client_against(routes).await;
            let error = read::list_dhcp_leases(&client, &no_filter())
                .await
                .expect_err("probe failure must surface");
            assert!(
                error.to_string().contains(&status.to_string()),
                "{path} {error}"
            );
        }
    }
}

#[tokio::test]
async fn neither_backend_enabled_falls_back_to_isc_when_it_answers() {
    for (dnsmasq, kea) in [
        (None, None),
        (Some("0"), None),
        (None, Some("0")),
        (Some("0"), Some("0")),
    ] {
        let leases = dhcp_backend_for(dnsmasq, kea, true).await.expect("leases");
        assert_eq!(leases["backend"], "isc", "{dnsmasq:?} {kea:?}");
        assert_eq!(leases["rows"][0]["hostname"], "example-host");
    }
}

#[tokio::test]
async fn neither_backend_enabled_and_no_isc_says_no_supported_backend_is_enabled() {
    for (dnsmasq, kea) in [
        (None, None),
        (Some("0"), None),
        (None, Some("0")),
        (Some("0"), Some("0")),
    ] {
        let error = dhcp_backend_for(dnsmasq, kea, false)
            .await
            .expect_err("no backend");
        let message = error.to_string();
        assert!(
            message.contains("no supported DHCP backend is enabled"),
            "{message}"
        );
        for name in ["Dnsmasq", "Kea", "ISC"] {
            assert!(message.contains(name), "{message}");
        }
    }
}

/// NAT has no combined endpoint on OPNsense, so this tool fetches both the
/// outbound and 1:1 controllers and must return both.
#[tokio::test]
async fn list_nat_rules_combines_outbound_and_one_to_one() {
    let client = client_against(default_routes()).await;
    let nat = read::list_nat_rules(&client, &no_filter())
        .await
        .expect("list nat rules");
    assert_eq!(nat["outbound"]["rows"][0]["interface"], "wan");
    assert_eq!(
        nat["one_to_one"]["rows"].as_array().expect("array").len(),
        0
    );
}

/// A device cert not signed by the device's configured `ca_pem_path` must be
/// refused -- proving `extra_root_certificates` *replaces* the trust store
/// rather than adding to it. Regressing to "add" would keep every test above
/// passing for the wrong reason: the public root store, not the configured
/// CA, would be doing the trusting.
#[tokio::test]
async fn a_cert_the_configured_private_ca_did_not_issue_is_refused() {
    ensure_crypto_provider();
    let (configured_ca_pem, _unused_server_config) = tls_material();
    let (_unrelated_cert_pem, servers_actual_config) = tls_material();

    let (listener, port) = bind_local().await;
    serve_fixtures(listener, servers_actual_config, default_routes());

    let ca_file = write_pem(&configured_ca_pem);
    let key_file = write_secret("test-key");
    let secret_file = write_secret("test-secret");
    let device = device_for(port, ca_file.path(), key_file.path(), secret_file.path());
    let client = OpnsenseClient::new(device).expect("client builds");

    let result = read::system_status(&client).await;
    assert!(
        result.is_err(),
        "a cert not signed by the configured private CA must be refused, but the request succeeded"
    );
}

/// An endpoint the mock has no fixture for answers 404, which must surface
/// as an `Upstream` error rather than a parsed empty success.
#[tokio::test]
async fn an_unmapped_path_surfaces_as_an_upstream_error() {
    let client = client_against(HashMap::new()).await;
    let result = read::system_status(&client).await;
    assert!(result.is_err());
}

/// `firmware_status` must stay a GET. In OPNsense's `FirmwareController`, a
/// POST to `statusAction` runs `configd firmware probe`, which makes the
/// firewall contact its update mirror -- a side effect a read tool must never
/// trigger. A future change that swaps this to POST (as the `search_*` tools
/// use) must fail this test rather than ship silently.
#[tokio::test]
async fn firmware_status_uses_get_not_post() {
    ensure_crypto_provider();
    let (cert_pem, server_config) = tls_material();
    let (listener, port) = bind_local().await;
    let methods = Arc::new(std::sync::Mutex::new(HashMap::new()));
    serve_fixtures_recording_methods(
        listener,
        server_config,
        default_routes(),
        Arc::clone(&methods),
    );

    let ca_file = write_pem(&cert_pem);
    let key_file = write_secret("test-key");
    let secret_file = write_secret("test-secret");
    let device = device_for(port, ca_file.path(), key_file.path(), secret_file.path());
    let client = OpnsenseClient::new(device).expect("client builds");

    read::firmware_status(&client)
        .await
        .expect("firmware status");

    let recorded = methods.lock().expect("methods lock");
    assert_eq!(
        recorded.get(rustopnsmcp_core::endpoints::FIRMWARE_STATUS),
        Some(&"GET".to_owned()),
        "firmware_status must issue a GET, not a POST"
    );
}

/// A 302 response must be treated as an `Upstream` error, not parsed as a
/// success -- `mecmcp-http` does not auto-follow redirects, and this proves
/// the client's own `status >= 300` check actually rejects one rather than
/// only being exercised by a same-process closure.
#[tokio::test]
async fn a_redirect_response_is_an_upstream_error() {
    ensure_crypto_provider();
    let (cert_pem, server_config) = tls_material();
    let (listener, port) = bind_local().await;
    serve_fixed_status(listener, server_config, "302 Found");

    let ca_file = write_pem(&cert_pem);
    let key_file = write_secret("test-key");
    let secret_file = write_secret("test-secret");
    let device = device_for(port, ca_file.path(), key_file.path(), secret_file.path());
    let client = OpnsenseClient::new(device).expect("client builds");

    let result = read::system_status(&client).await;
    match result {
        Err(rustopnsmcp_core::error::OpnsenseError::Upstream { status, .. }) => {
            assert_eq!(status, 302);
        }
        Ok(_) => panic!("expected Upstream {{ status: 302, .. }}, got Ok"),
        Err(_) => panic!("expected Upstream {{ status: 302, .. }}, got a different error variant"),
    }
}

#[tokio::test]
async fn the_config_fingerprint_covers_aliases_and_rules() {
    use rustopnsmcp_core::changeset::{config_fingerprint, fingerprint_collections};
    let fixture = rustopnsmcp_core::testing::fixture;
    let client = client_against(default_routes()).await;
    let live = config_fingerprint(&client).await.expect("fingerprint");
    let aliases = fixture("aliases")["rows"].as_array().expect("rows").clone();
    let rules = fixture("firewall_rules")["rows"]
        .as_array()
        .expect("rows")
        .clone();
    assert_eq!(
        live,
        fingerprint_collections(&aliases, &rules).expect("fingerprint")
    );
}

#[tokio::test]
async fn a_partial_listing_is_refused_rather_than_fingerprinted() {
    let mut routes = default_routes();
    routes.insert(
        rustopnsmcp_core::endpoints::ALIASES_SEARCH.to_owned(),
        serde_json::json!({ "rows": [], "rowCount": 0, "total": 5, "current": 1 }),
    );
    let client = client_against(routes).await;
    let error = rustopnsmcp_core::changeset::config_fingerprint(&client)
        .await
        .expect_err("0 of 5 rows must not be fingerprinted");
    assert!(error.to_string().contains("0 of 5"), "{error}");
}

#[tokio::test]
async fn a_listing_with_no_total_is_refused_rather_than_fingerprinted() {
    let mut routes = default_routes();
    routes.insert(
        rustopnsmcp_core::endpoints::ALIASES_SEARCH.to_owned(),
        serde_json::json!({ "rows": [], "rowCount": 0, "current": 1 }),
    );
    let client = client_against(routes).await;
    let error = rustopnsmcp_core::changeset::config_fingerprint(&client)
        .await
        .expect_err("a listing with no total must not be fingerprinted");
    assert!(
        error.to_string().contains("did not report a total"),
        "{error}"
    );
}
