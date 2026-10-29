//! Test helper for loading OPNsense API responses.
//!
//! Most fixtures under `tests/fixtures/` are sanitized captures from
//! opnsense-lab on 26.7.5 (see `scripts/sanitize-fixture.sh`). `nat_one_to_one`,
//! `routes` and `dhcp_leases` are synthetic: those collections are empty on the
//! baseline, so there is nothing to capture.

use std::path::PathBuf;

/// Load a synthetic fixture by name (without the `.json` extension).
///
/// # Panics
///
/// Panics if the fixture is absent or is not valid JSON. Both are
/// test-authoring errors, and a panic naming the path is the fastest way to
/// fix them.
#[must_use]
pub fn fixture(name: &str) -> serde_json::Value {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "fixtures",
        &format!("{name}.json"),
    ]
    .iter()
    .collect();

    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("no fixture at {}: {error}", path.display()));

    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("fixture {} is not JSON: {error}", path.display()))
}
