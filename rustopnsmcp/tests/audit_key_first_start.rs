#![allow(clippy::unwrap_used)]
//! The binary creates a missing audit HMAC key on first start. A unit test of
//! the helper cannot prove `main` calls it; this starts the real binary.

use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};

#[test]
fn first_start_creates_the_key_and_a_second_start_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let inventory = dir.path().join("devices.json");
    std::fs::write(&inventory, r#"{"version":1,"devices":{}}"#).unwrap();
    std::fs::set_permissions(&inventory, std::fs::Permissions::from_mode(0o600)).unwrap();
    let key = dir.path().join("audit-hmac.key");

    let start = || {
        Command::new(env!("CARGO_BIN_EXE_rustopnsmcp"))
            .args([
                "--device-mapping",
                inventory.to_str().unwrap(),
                "--transport",
                "stdio",
                "--audit-format",
                "json",
                "--audit-redact",
                "devices=hmac",
                "--audit-hmac-key-file",
                key.to_str().unwrap(),
            ])
            .stdin(Stdio::null()) // EOF on stdin ends the stdio server
            .output()
            .unwrap()
    };

    // A stdio server whose stdin is already closed exits non-zero
    // ("connection closed: initialize request"). That is expected: the key is
    // created during startup, before the handshake, and is all this test reads.
    let first = start();
    let generated = std::fs::read(&key).unwrap_or_else(|error| {
        panic!(
            "no key created ({error}); stderr: {}",
            String::from_utf8_lossy(&first.stderr)
        )
    });
    assert_eq!(generated.len(), 32);
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let _ = start();
    assert_eq!(
        std::fs::read(&key).unwrap(),
        generated,
        "second start rotated the key"
    );
}
