#![allow(clippy::unwrap_used)]
//! `/readyz` reports a device that refuses the configured API key.
//!
//! The probe is passive: a server that has made no request is ready; the
//! first 401 makes it not ready; the next 2xx makes it ready again. A 403
//! (a key that works but lacks one privilege) must not change anything.

use rmcp::ServiceExt as _;
use rmcp::model::CallToolRequestParams;
use rustopnsmcp::server::{OpnsenseServer, ServerOptions};
use rustopnsmcp_core::inventory::DeviceRegistry;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn tls_material() -> (String, rustls::ServerConfig) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der)
        .unwrap();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    (cert.pem(), server_config)
}

/// A TLS device that answers every request with the status in `status`.
async fn mock_device(status: Arc<AtomicU16>) -> (u16, String) {
    let (cert_pem, server_config) = tls_material();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let status = Arc::clone(&status);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut seen = Vec::new();
                let mut byte = [0u8; 1];
                while tls.read_exact(&mut byte).await.is_ok() {
                    seen.push(byte[0]);
                    if seen.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let code = status.load(Ordering::SeqCst);
                let body = r#"{"status":"ok"}"#;
                let reply = format!(
                    "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(reply.as_bytes()).await;
                let _ = tls.flush().await;
            });
        }
    });
    (port, cert_pem)
}

fn secret(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, "test-value").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn server_for(port: u16, cert_pem: &str, dir: &std::path::Path) -> OpnsenseServer {
    let ca = dir.join("ca.pem");
    std::fs::File::create(&ca)
        .unwrap()
        .write_all(cert_pem.as_bytes())
        .unwrap();
    let inventory = dir.join("devices.json");
    std::fs::write(
        &inventory,
        serde_json::json!({"version":1,"devices":{"fw-1":{
            "endpoint": format!("https://localhost:{port}"),
            "api_key_file": secret(dir, "key"),
            "api_secret_file": secret(dir, "secret"),
            "ca_pem_path": ca,
        }}})
        .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&inventory, std::fs::Permissions::from_mode(0o600)).unwrap();
    let registry = Arc::new(DeviceRegistry::load(&inventory).unwrap());
    let coordinator =
        rustopnsmcp::changeset_state::build_coordinator(None, Duration::from_secs(3600), false)
            .unwrap();
    OpnsenseServer::new(registry, ServerOptions::default(), coordinator).unwrap()
}

/// One in-process call to a read tool, so the client sees the device's reply.
async fn call_status(server: &OpnsenseServer) {
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let serving = server.clone();
    let task = tokio::spawn(async move {
        let running = serving.serve(tokio::io::split(server_io)).await.unwrap();
        let _ = running.waiting().await;
    });
    let client = ().serve(tokio::io::split(client_io)).await.unwrap();
    let serde_json::Value::Object(arguments) = serde_json::json!({"device":"fw-1"}) else {
        unreachable!()
    };
    let _ = client
        .call_tool(
            CallToolRequestParams::new("get_opnsense_system_status".to_owned())
                .with_arguments(arguments),
        )
        .await;
    client.cancel().await.unwrap();
    let _ = task.await;
}

/// `GET /readyz` against the router, over a real socket.
async fn readyz(server: &OpnsenseServer) -> (u16, String) {
    let plan = rustopnsmcp::http_transport::build_http_router(
        server.clone(),
        None,
        vec![],
        vec![],
        mecmcp_transport::LimitsConfig::default(),
        false,
        false,
        tokio_util::sync::CancellationToken::new(),
    )
    .unwrap();
    // `serve_router_on_listener` is not re-exported, so reserve a port and
    // hand its address over; the window between drop and bind is tiny and a
    // collision fails the connect below, never passes silently.
    let address = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let serving = tokio::spawn(mecmcp_transport::serve_router(
        plan,
        address,
        None,
        Duration::from_secs(1),
    ));
    let mut attempts = 0;
    let mut stream = loop {
        match tokio::net::TcpStream::connect(address).await {
            Ok(stream) => break stream,
            Err(error) if attempts < 50 => {
                attempts += 1;
                let _ = error;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(error) => panic!("router never listened: {error}"),
        }
    };
    stream
        .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.unwrap();
    serving.abort();
    let code = raw.split_whitespace().nth(1).unwrap().parse().unwrap();
    (code, raw)
}

#[tokio::test]
async fn readyz_follows_the_device_refusing_and_accepting_the_key() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let status = Arc::new(AtomicU16::new(200));
    let (port, cert_pem) = mock_device(Arc::clone(&status)).await;
    let dir = tempfile::tempdir().unwrap();
    let server = server_for(port, &cert_pem, dir.path());

    assert_eq!(readyz(&server).await.0, 200, "no request yet: ready");

    status.store(401, Ordering::SeqCst);
    call_status(&server).await;
    let (code, raw) = readyz(&server).await;
    assert_eq!(code, 503, "a refused key must fail readiness: {raw}");
    assert!(raw.contains("opnsense_auth"), "{raw}");
    assert!(!raw.contains("localhost") && !raw.contains("fw-1"), "{raw}");

    status.store(403, Ordering::SeqCst);
    call_status(&server).await;
    assert_eq!(
        readyz(&server).await.0,
        503,
        "403 must not clear a prior 401"
    );

    status.store(200, Ordering::SeqCst);
    call_status(&server).await;
    assert_eq!(
        readyz(&server).await.0,
        200,
        "an accepted key recovers readiness"
    );
}

#[tokio::test]
async fn a_403_alone_never_fails_readiness() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let status = Arc::new(AtomicU16::new(403));
    let (port, cert_pem) = mock_device(Arc::clone(&status)).await;
    let dir = tempfile::tempdir().unwrap();
    let server = server_for(port, &cert_pem, dir.path());
    call_status(&server).await;
    assert_eq!(readyz(&server).await.0, 200);
}
