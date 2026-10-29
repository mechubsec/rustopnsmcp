//! `token add --device-selector` must refuse: this server's HTTP path supplies
//! no device attributes, so such a token would address no device at all.

use std::process::{Command, Output};

fn token_add(tokens_file: &std::path::Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rustopnsmcp"))
        .args(["token", "add", "--tokens-file"])
        .arg(tokens_file)
        .args(["--name", "t1", "--devices", "opnsense-lab", "--tools", "*"])
        .args(extra)
        .output()
        .expect("spawn rustopnsmcp")
}

#[test]
fn device_selector_is_refused_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tokens_file = dir.path().join("tokens.json");

    let refused = token_add(&tokens_file, &["--device-selector", "site=lab-*"]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--devices"),
        "stderr: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(!tokens_file.exists(), "refusal must write nothing");

    let accepted = token_add(&tokens_file, &[]);
    assert!(
        accepted.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert!(tokens_file.exists());
}
