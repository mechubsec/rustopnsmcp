#![allow(clippy::unwrap_used)]
//! `--audit-forward-ca-file` names the trust anchor for the audit-forward
//! sink, a different host than SSDF with its own certificate. Before this
//! fix, `main` built one `EvidenceHttpTransport` from the SSDF CA and reused
//! it for the forward sink too (`EvidenceService::start_with_transport`), so
//! the flag parsed but was never read -- every forward delivery would have
//! failed its TLS handshake with nothing but a `warn!` to say why. This
//! starts the server with a forward CA file that cannot be read and expects
//! the dedicated "building the audit-forward transport" refusal, which only
//! exists once the flag reaches its own transport.

use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

fn password_file(directory: &std::path::Path, name: &str) -> std::path::PathBuf {
    let path = directory.join(name);
    std::fs::write(&path, "not-a-live-password").expect("write password file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod password file");
    path
}

#[test]
fn an_unreadable_forward_ca_file_refuses_startup_naming_the_forward_transport() {
    let directory = tempfile::tempdir().expect("temp dir");
    let inventory_path = directory.path().join("devices.json");
    std::fs::write(&inventory_path, r#"{"version":1,"devices":{}}"#).expect("write inventory");

    let missing_forward_ca = directory.path().join("forward-ca.pem");
    assert!(
        !missing_forward_ca.exists(),
        "forward CA path must not exist for this test"
    );

    let ssdf_password = password_file(directory.path(), "ssdf-password");
    let ssdf_verify_password = password_file(directory.path(), "ssdf-verify-password");

    let output = Command::new(env!("CARGO_BIN_EXE_rustopnsmcp"))
        .args([
            "--device-mapping",
            inventory_path.to_str().expect("inventory path is UTF-8"),
            "--transport",
            "stdio",
            "--ssdf-audit-endpoint",
            "http://127.0.0.1:9",
            "--ssdf-audit-server-id",
            "test-server",
            "--ssdf-audit-password-file",
            ssdf_password.to_str().unwrap(),
            "--ssdf-audit-verify-password-file",
            ssdf_verify_password.to_str().unwrap(),
            "--ssdf-audit-outbox",
            directory.path().join("ssdf-outbox").to_str().unwrap(),
            "--ssdf-audit-ledger",
            directory.path().join("ssdf-ledger").to_str().unwrap(),
            "--audit-forward-endpoint",
            "http://127.0.0.1:9",
            "--audit-forward-outbox",
            directory.path().join("forward-outbox").to_str().unwrap(),
            "--audit-forward-ledger",
            directory.path().join("forward-ledger").to_str().unwrap(),
            "--audit-forward-ca-file",
            missing_forward_ca
                .to_str()
                .expect("forward ca path is UTF-8"),
        ])
        .output()
        .expect("run rustopnsmcp");

    assert!(
        !output.status.success(),
        "an unreadable forward CA file must refuse startup"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("building the audit-forward transport"),
        "expected the forward-transport refusal to name itself, got: {stderr}"
    );
}
