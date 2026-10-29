//! End-to-end regression test for the delete-rollback idempotency fix.
//!
//! `rollback_mutation`'s `Delete` arm runs whenever an indeterminate delete's
//! reconciliation read `NotApplied` or errored outright — either of which can
//! be wrong. Before this fix it unconditionally re-created the resource from
//! the pre-image via `addItem`/`addRule`. If the delete had in fact landed,
//! that recreated a resource `apply_sequentially` believed it had removed; if
//! the delete had *not* landed (the resource is still there under its
//! original uuid), a `setItem`/`setRule`-style re-create is not idempotent
//! the way an update's rollback is — OPNsense either rejects a duplicate
//! alias name or, for firewall rules, which have no name uniqueness, would
//! create a live duplicate rule.
//!
//! This drives the real [`OpnsenseClient`] (not the `apply.rs` mock) against
//! a local TLS fixture server, the same harness `read_tools.rs` uses. The
//! `addItem`/`addRule` route is deliberately left unregistered in the
//! still-exists cases: if the fix regresses and rollback re-creates the
//! resource anyway, that request has nowhere to land and the call errors
//! instead of silently passing. Both `ResourceKind::Alias` (phase 2a) and
//! `ResourceKind::Rule` (phase 2b) are covered, since the dispatch in
//! `rollback_mutation` is per-kind and a rule-only regression would not show
//! up in the alias cases.

use rustopnsmcp_core::changeset::{ControllerOps, ResourceKind, StagedMutation};
use rustopnsmcp_core::client::OpnsenseClient;
use rustopnsmcp_core::inventory::Device;
use std::collections::HashMap;
use std::io::Write as _;
use std::sync::Arc;
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncWriteExt as _;

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

/// Serve fixture responses keyed by request path; anything unmapped answers
/// 404, which is exactly what proves an unwanted `addItem` call would fail
/// rather than silently succeed.
///
/// `swaps` maps a trigger path to `(path, body)`: once the trigger is
/// requested, `path` answers `body` from then on — a device whose state the
/// write just changed.
fn serve_fixtures(
    listener: tokio::net::TcpListener,
    server_config: rustls::ServerConfig,
    routes: HashMap<String, serde_json::Value>,
    swaps: HashMap<String, (String, serde_json::Value)>,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let routes = Arc::new(std::sync::Mutex::new(routes));
    let swaps = Arc::new(swaps);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let routes = Arc::clone(&routes);
            let swaps = Arc::clone(&swaps);
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

                let fixture = {
                    let mut routes = routes.lock().expect("routes lock");
                    let fixture = routes.get(&path).cloned();
                    if let Some((target, body)) = swaps.get(&path) {
                        routes.insert(target.clone(), body.clone());
                    }
                    fixture
                };
                let response = match fixture {
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

async fn client_against(routes: HashMap<String, serde_json::Value>) -> OpnsenseClient {
    client_against_with_swaps(routes, HashMap::new()).await
}

async fn client_against_with_swaps(
    routes: HashMap<String, serde_json::Value>,
    swaps: HashMap<String, (String, serde_json::Value)>,
) -> OpnsenseClient {
    ensure_crypto_provider();
    let (cert_pem, server_config) = tls_material();
    let (listener, port) = bind_local().await;
    serve_fixtures(listener, server_config, routes, swaps);

    let ca_file = write_pem(&cert_pem);
    let key_file = write_secret("test-key");
    let secret_file = write_secret("test-secret");
    let device = device_for(port, ca_file.path(), key_file.path(), secret_file.path());

    std::mem::forget(ca_file);
    std::mem::forget(key_file);
    std::mem::forget(secret_file);

    OpnsenseClient::new(device).expect("client builds")
}

/// Rolling back a delete whose reconciliation could not confirm it landed,
/// when the alias in fact still exists, must be a no-op — not an attempt to
/// re-create it. Before the fix, this unconditionally called `addItem`,
/// which has no fixture registered here and would fail the request.
#[tokio::test]
async fn rollback_of_a_delete_that_still_exists_is_a_noop_not_a_recreate() {
    let uuid = "11111111-1111-4111-8111-111111111111";
    let mut routes = HashMap::new();
    routes.insert(
        rustopnsmcp_core::endpoints::aliases_get_item(uuid),
        serde_json::json!({
            "alias": {
                "name": "still_here",
                "type": {"host": {"value": "Host(s)", "selected": 1}},
            }
        }),
    );
    // Deliberately no ALIASES_ADD_ITEM route.
    let client = client_against(routes).await;

    let mutation = StagedMutation::delete(ResourceKind::Alias, uuid);
    let prior = serde_json::json!({"uuid": uuid, "name": "still_here", "type": "host"});

    client
        .rollback_mutation(&mutation, Some(&prior), None)
        .await
        .expect(
            "rollback of a delete whose alias still exists must be a no-op, not attempt a \
             re-create against a device with no addItem fixture",
        );
}

/// The mirror case: the alias is genuinely gone, so rollback must actually
/// re-create it from the pre-image.
#[tokio::test]
async fn rollback_of_a_delete_that_landed_recreates_the_alias() {
    let uuid = "22222222-2222-4222-8222-222222222222";
    let mut routes = HashMap::new();
    routes.insert(
        rustopnsmcp_core::endpoints::aliases_get_item(uuid),
        serde_json::json!([]),
    );
    routes.insert(
        rustopnsmcp_core::endpoints::ALIASES_ADD_ITEM.to_owned(),
        serde_json::json!({"result": "saved", "uuid": "33333333-3333-4333-8333-333333333333"}),
    );
    let client = client_against(routes).await;

    let mutation = StagedMutation::delete(ResourceKind::Alias, uuid);
    let prior = serde_json::json!({"uuid": uuid, "name": "gone", "type": "host"});

    client
        .rollback_mutation(&mutation, Some(&prior), None)
        .await
        .expect("rollback of a delete that actually landed must re-create the alias");
}

/// The same idempotency guarantee, exercised for phase 2b's `ResourceKind::Rule`:
/// a rule delete whose reconciliation could not confirm it landed, but whose
/// rule is still present under its original uuid, must not attempt a
/// `addRule` re-create. Firewall rules have no name-uniqueness constraint
/// like aliases do, so a wrongly-taken re-create path here would silently
/// leave a live duplicate rule rather than erroring the way a duplicate
/// alias name would.
#[tokio::test]
async fn rollback_of_a_rule_delete_that_still_exists_is_a_noop_not_a_recreate() {
    let uuid = "44444444-4444-4444-8444-444444444444";
    let mut routes = HashMap::new();
    routes.insert(
        rustopnsmcp_core::endpoints::filter_get_rule(uuid),
        serde_json::json!({
            "rule": {
                "description": "still_here",
                "action": {"pass": {"value": "Pass", "selected": 1}},
                "interface": {"lan": {"value": "LAN", "selected": 1}},
            }
        }),
    );
    // Deliberately no FILTER_ADD_RULE route.
    let client = client_against(routes).await;

    let mutation = StagedMutation::delete(ResourceKind::Rule, uuid);
    let prior = serde_json::json!({
        "uuid": uuid,
        "description": "still_here",
        "action": "pass",
        "interface": "lan",
    });

    client
        .rollback_mutation(&mutation, Some(&prior), None)
        .await
        .expect(
            "rollback of a rule delete whose rule still exists must be a no-op, not attempt a \
             re-create against a device with no addRule fixture",
        );
}

/// The rule mirror of `rollback_of_a_delete_that_landed_recreates_the_alias`:
/// the rule is genuinely gone, so rollback must actually re-create it via
/// `addRule` from the pre-image.
#[tokio::test]
async fn rollback_of_a_rule_delete_that_landed_recreates_the_rule() {
    let uuid = "55555555-5555-4555-8555-555555555555";
    let mut routes = HashMap::new();
    routes.insert(
        rustopnsmcp_core::endpoints::filter_get_rule(uuid),
        serde_json::json!([]),
    );
    routes.insert(
        rustopnsmcp_core::endpoints::FILTER_ADD_RULE.to_owned(),
        serde_json::json!({"result": "saved", "uuid": "66666666-6666-4666-8666-666666666666"}),
    );
    let client = client_against(routes).await;

    let mutation = StagedMutation::delete(ResourceKind::Rule, uuid);
    let prior = serde_json::json!({
        "uuid": uuid,
        "description": "gone",
        "action": "pass",
        "interface": "lan",
    });

    client
        .rollback_mutation(&mutation, Some(&prior), None)
        .await
        .expect("rollback of a rule delete that actually landed must re-create the rule");
}

/// OPNsense reports a validation failure as HTTP 200 with
/// `{"result":"failed","validations":{...}}`. Through the real client and TLS
/// stack, that must be a refusal carrying the validation text, never a save.
#[tokio::test]
async fn a_200_with_result_failed_on_set_rule_is_a_refusal() {
    let uuid = "44444444-4444-4444-4444-444444444444";
    let routes = HashMap::from([(
        rustopnsmcp_core::endpoints::filter_set_rule(uuid),
        serde_json::json!({
            "result": "failed",
            "validations": { "rule.interface": "Please specify a valid interface." },
        }),
    )]);
    let client = client_against(routes).await;

    let error = client
        .set_rule(uuid, &serde_json::json!({ "interface": "nonexistent" }))
        .await
        .expect_err("a 200 carrying result=failed must not be treated as saved");

    assert!(
        matches!(
            error,
            rustopnsmcp_core::error::OpnsenseError::WriteRefused(_)
        ),
        "{error:?}"
    );
    assert!(error.to_string().contains("rule.interface"), "{error}");
}

/// What OPNsense 26.7.5 answers `getItem/{uuid}` with for an alias uuid it
/// does not have (deleted, or never existed): HTTP 200 and the default alias
/// template, not `[]`.
///
/// Built from the real sanitized capture `alias_get_item.json`: `name` set to
/// `""`, every selected `content` entry (the record's own values) removed so
/// nothing is selected, and `categories` set to `[]`. Everything else — the
/// description, the other choice maps and their selections, the pf counters —
/// is left as captured, so only the blanked record tells the template apart
/// from a stored alias.
fn alias_template() -> serde_json::Value {
    let mut template = rustopnsmcp_core::testing::fixture("alias_get_item");
    let alias = &mut template["alias"];
    alias["name"] = serde_json::json!("");
    alias["categories"] = serde_json::json!([]);
    alias["content"]
        .as_object_mut()
        .expect("content is a choice map")
        .retain(|_, choice| choice["selected"] != 1);
    template
}

/// The template is not an alias: reading it as one makes every verified
/// delete look like it left the alias in place.
#[tokio::test]
async fn fetch_resource_reads_the_alias_default_template_as_not_found() {
    let uuid = "55555555-5555-4555-8555-555555555555";
    let routes = HashMap::from([(
        rustopnsmcp_core::endpoints::aliases_get_item(uuid),
        alias_template(),
    )]);
    let client = client_against(routes).await;

    let fetched = client
        .fetch_resource(ResourceKind::Alias, uuid)
        .await
        .expect("a template is an answer, not an error");

    assert!(fetched.is_none(), "{fetched:?}");
}

/// The other side of the rule: a stored alias, with its non-empty name, is
/// still found.
#[tokio::test]
async fn fetch_resource_still_returns_a_real_alias() {
    let uuid = "66666666-6666-4666-8666-666666666666";
    let routes = HashMap::from([(
        rustopnsmcp_core::endpoints::aliases_get_item(uuid),
        rustopnsmcp_core::testing::fixture("alias_get_item"),
    )]);
    let client = client_against(routes).await;

    let fetched = client
        .fetch_resource(ResourceKind::Alias, uuid)
        .await
        .expect("fetch")
        .expect("a real alias is found");

    assert_eq!(fetched["name"], "lab_clients");
    assert_eq!(fetched["uuid"], uuid);
}

/// The live defect: the delete landed, `getItem` then answered the template,
/// and the apply was recorded as `AppliedUnverified` ("still exists").
#[tokio::test]
async fn a_delete_followed_by_the_default_template_is_applied() {
    use rustopnsmcp_core::changeset::{Preimage, State, apply_sequentially};
    use rustopnsmcp_core::endpoints as ep;

    let uuid = "77777777-7777-4777-8777-777777777777";
    let routes = HashMap::from([
        (
            ep::aliases_get_item(uuid),
            rustopnsmcp_core::testing::fixture("alias_get_item"),
        ),
        (
            ep::aliases_del_item(uuid),
            serde_json::json!({"result": "deleted"}),
        ),
        (
            ep::ALIASES_RECONFIGURE.to_owned(),
            serde_json::json!({"status": "ok"}),
        ),
    ]);
    let swaps = HashMap::from([(
        ep::aliases_del_item(uuid),
        (ep::aliases_get_item(uuid), alias_template()),
    )]);
    let client = client_against_with_swaps(routes, swaps).await;

    let mutations = [StagedMutation::delete(ResourceKind::Alias, uuid)];
    let preimage = Preimage::capture(&client, &mutations)
        .await
        .expect("the alias exists before the delete");
    let outcome = apply_sequentially(&client, &preimage, &mutations).await;

    assert_eq!(outcome.state, State::Applied, "{outcome:?}");
    assert_eq!(outcome.verification_failure, None);
}

/// `create_opnsense_change_set` captures the pre-image of every update and
/// delete target, and a not-found there is its refusal (the server answers
/// "the device returned HTTP 404" with the detail "not found"). The template
/// must take that path rather than be captured as if it were the alias.
#[tokio::test]
async fn capturing_a_preimage_of_a_missing_alias_is_refused_as_not_found() {
    use rustopnsmcp_core::changeset::Preimage;
    use rustopnsmcp_core::error::OpnsenseError;

    let uuid = "88888888-8888-4888-8888-888888888888";
    let routes = HashMap::from([(
        rustopnsmcp_core::endpoints::aliases_get_item(uuid),
        alias_template(),
    )]);
    let client = client_against(routes).await;

    // Static labels: CodeQL rust/cleartext-logging flags uuid-derived assert messages.
    for (label, mutation) in [
        (
            "update",
            StagedMutation::update(
                ResourceKind::Alias,
                uuid,
                serde_json::json!({"description": "x"}),
            ),
        ),
        ("delete", StagedMutation::delete(ResourceKind::Alias, uuid)),
    ] {
        let error = Preimage::capture(&client, std::slice::from_ref(&mutation))
            .await
            .expect_err("a missing alias must not be captured");
        assert!(
            matches!(
                &error,
                OpnsenseError::Upstream { status: 404, detail } if detail == "not found"
            ),
            "{label}: a missing alias must be refused as 404 not found"
        );
    }
}

/// Upstream's filter apply returns configd's raw output, `"OK\n\n"`, not
/// `"ok"` (26.7.5, live).
#[tokio::test]
async fn reconfigure_filter_accepts_configds_uppercase_ok() {
    let routes = HashMap::from([(
        rustopnsmcp_core::endpoints::FILTER_APPLY.to_owned(),
        serde_json::json!({"status": "OK\n\n"}),
    )]);
    let client = client_against(routes).await;

    client
        .reconfigure_filter()
        .await
        .expect("configd's OK is success");
}

/// The live defect: a created rule whose apply answered `"OK\n\n"` was
/// recorded `NotLoaded` and rolled back.
#[tokio::test]
async fn a_rule_create_whose_apply_answers_configd_ok_is_applied() {
    use rustopnsmcp_core::changeset::{Preimage, State, apply_sequentially};
    use rustopnsmcp_core::endpoints as ep;

    let uuid = "99999999-9999-4999-8999-999999999999";
    let routes = HashMap::from([
        (
            ep::FILTER_ADD_RULE.to_owned(),
            serde_json::json!({"result": "saved", "uuid": uuid}),
        ),
        (
            ep::filter_get_rule(uuid),
            serde_json::json!({"rule": {
                "description": "p3-live",
                "action": {"pass": {"value": "Pass", "selected": 1}},
                "interface": {"lan": {"value": "LAN", "selected": 1}},
            }}),
        ),
        (
            ep::FILTER_APPLY.to_owned(),
            serde_json::json!({"status": "OK\n\n"}),
        ),
    ]);
    let client = client_against(routes).await;

    let mutations = [StagedMutation::create(
        ResourceKind::Rule,
        serde_json::json!({"description": "p3-live", "action": "pass", "interface": "lan"}),
    )];
    let preimage = Preimage::capture(&client, &mutations)
        .await
        .expect("capture");
    let outcome = apply_sequentially(&client, &preimage, &mutations).await;

    assert_eq!(outcome.state, State::Applied, "{outcome:?}");
}
