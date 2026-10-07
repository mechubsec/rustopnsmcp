//! OPNsense device inventory.
//!
//! `devices.json` is read through `mecmcp-inventory`'s hardened loader, which
//! requires mode 0600, a regular file, and ownership by the service user.
//!
//! OPNsense authenticates with an API key *and* an API secret (HTTP Basic:
//! key as username, secret as password). Neither ever appears in this file.
//! Each device names an environment variable or a separate 0600 file for
//! each, loaded through `mecmcp-secret` into an `OutboundSecret` that
//! zeroizes on drop and implements neither `Debug` nor `Serialize`.
//! `deny_unknown_fields` makes an inline key or secret a parse error rather
//! than an ignored field.

use crate::error::OpnsenseError;
use mecmcp_inventory::{FileInventory, Inventory, InventoryError};
use mecmcp_secret::{OutboundSecret, SecretLimits, load_from_env, load_from_file};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One OPNsense device.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    /// Base URL including scheme, e.g. `https://fw.example.org`.
    pub endpoint: String,
    /// Environment variable holding the OPNsense API key.
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// File holding the OPNsense API key. Mutually exclusive with the env form.
    #[serde(default)]
    pub api_key_file: Option<PathBuf>,
    /// Environment variable holding the OPNsense API secret.
    #[serde(default)]
    pub api_secret_env: Option<String>,
    /// File holding the OPNsense API secret. Mutually exclusive with the env form.
    #[serde(default)]
    pub api_secret_file: Option<PathBuf>,
    /// PEM trust anchor, for a device behind a private CA.
    ///
    /// `mecmcp-http` offers no insecure-skip-verify at any layer, so this is
    /// the only way to reach such a device.
    #[serde(default)]
    pub ca_pem_path: Option<PathBuf>,
}

impl Device {
    /// Redact userinfo, query, and fragment from an endpoint before including
    /// it in an error message.
    ///
    /// A misconfigured `https://user:pass@host` would otherwise leak
    /// credentials into logs. Strip what could be sensitive, leaving only
    /// scheme and authority.
    fn redact_endpoint(endpoint: &str) -> String {
        url::Url::parse(endpoint)
            .ok()
            .and_then(|mut u| {
                u.set_username("").ok()?;
                let _ = u.set_password(None);
                u.set_query(None);
                u.set_fragment(None);
                Some(u.to_string())
            })
            .unwrap_or_else(|| "<unparseable-endpoint>".to_owned())
    }

    /// Check the invariants `serde` cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`OpnsenseError::Config`] if the endpoint is not `https://`, or
    /// if the device names both credential sources or neither, for either
    /// the API key or the API secret.
    pub fn validate(&self) -> Result<(), OpnsenseError> {
        if !self.endpoint.starts_with("https://") {
            let redacted = Self::redact_endpoint(&self.endpoint);
            return Err(OpnsenseError::Config(format!(
                "device endpoint must be https://, got {redacted}"
            )));
        }
        match (&self.api_key_env, &self.api_key_file) {
            (Some(_), Some(_)) => {
                return Err(OpnsenseError::Config(
                    "device names both api_key_env and api_key_file; name exactly one".to_owned(),
                ));
            }
            (None, None) => {
                return Err(OpnsenseError::Config(
                    "device names neither api_key_env nor api_key_file".to_owned(),
                ));
            }
            _ => {}
        }
        match (&self.api_secret_env, &self.api_secret_file) {
            (Some(_), Some(_)) => Err(OpnsenseError::Config(
                "device names both api_secret_env and api_secret_file; name exactly one".to_owned(),
            )),
            (None, None) => Err(OpnsenseError::Config(
                "device names neither api_secret_env nor api_secret_file".to_owned(),
            )),
            _ => Ok(()),
        }
    }

    /// Load the API key through `mecmcp-secret`'s hardened loader.
    ///
    /// # Errors
    ///
    /// Returns [`OpnsenseError::Secret`] if the file is a symlink, is group-
    /// or world-accessible, is oversized, or is absent.
    pub fn load_api_key(&self) -> Result<OutboundSecret, OpnsenseError> {
        self.validate()?;
        let limits = SecretLimits::default();
        if let Some(var) = &self.api_key_env {
            return Ok(load_from_env(var, limits)?);
        }
        let path = self
            .api_key_file
            .as_ref()
            .ok_or_else(|| OpnsenseError::Config("no api key source".to_owned()))?;
        Ok(load_from_file(path, limits)?)
    }

    /// Load the API secret through `mecmcp-secret`'s hardened loader.
    ///
    /// # Errors
    ///
    /// As [`Self::load_api_key`], for the API secret.
    pub fn load_api_secret(&self) -> Result<OutboundSecret, OpnsenseError> {
        self.validate()?;
        let limits = SecretLimits::default();
        if let Some(var) = &self.api_secret_env {
            return Ok(load_from_env(var, limits)?);
        }
        let path = self
            .api_secret_file
            .as_ref()
            .ok_or_else(|| OpnsenseError::Config("no api secret source".to_owned()))?;
        Ok(load_from_file(path, limits)?)
    }
}

/// The loaded device inventory, hot-reloadable on SIGHUP.
pub struct DeviceRegistry {
    inner: FileInventory<Device, ()>,
}

impl DeviceRegistry {
    /// Load `devices.json` through the hardened loader.
    ///
    /// # Errors
    /// Returns [`InventoryError`] when the file is missing, wrongly
    /// permissioned, not a regular file, or structurally invalid.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, InventoryError> {
        Ok(Self {
            inner: FileInventory::load(path)?,
        })
    }

    /// Re-read the file in place, returning the number of devices loaded.
    ///
    /// # Errors
    /// Returns [`InventoryError`] on any load failure. The previous contents
    /// remain in effect when a reload fails.
    pub fn reload(&self) -> Result<usize, InventoryError> {
        self.inner.reload()
    }

    /// All device names, in stable order.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.inner.names()
    }

    /// Resolve one device by exact name.
    ///
    /// # Errors
    /// Returns [`OpnsenseError::Config`] when the name is absent.
    pub fn get(&self, name: &str) -> Result<Device, OpnsenseError> {
        self.inner
            .get_device(name)
            .map_err(|_| OpnsenseError::Config(format!("unknown device: {name}")))
    }

    /// Add a device to `devices.json` and reload.
    ///
    /// The file is rewritten through a same-directory temporary created
    /// `0600` with `O_EXCL`, fsynced and renamed into place, so it keeps the
    /// mode the hardened loader requires. Only the canonical
    /// `{"version": 1, "devices": {...}}` shape is edited; any other shape is
    /// refused rather than rewritten.
    ///
    /// # Errors
    ///
    /// Returns [`OpnsenseError`] for an invalid name or device, a duplicate
    /// name, a non-canonical file, or any I/O failure.
    pub fn add_device(&self, name: &str, device: Device) -> Result<usize, OpnsenseError> {
        mecmcp_inventory::validate_device_name(name)
            .map_err(|error| OpnsenseError::Config(error.to_string()))?;
        device.validate()?;
        if self.inner.get_device(name).is_ok() {
            return Err(OpnsenseError::Config(format!(
                "device {name} already exists"
            )));
        }

        let path = self.inner.source();
        let bytes = mecmcp_secret::read_hardened_file(&path, mecmcp_secret::FileLimits::default())?;
        let mut document: serde_json::Value = serde_json::from_slice(bytes.expose())
            .map_err(|error| OpnsenseError::Malformed(format!("devices.json: {error}")))?;
        let Some(devices) = document
            .get_mut("devices")
            .and_then(serde_json::Value::as_object_mut)
        else {
            return Err(OpnsenseError::Config(
                "devices.json is not in the canonical {\"version\": 1, \"devices\": {...}} \
                 shape; add the device by hand"
                    .to_owned(),
            ));
        };
        let entry = serde_json::to_value(&device)
            .map_err(|error| OpnsenseError::Malformed(error.to_string()))?;
        devices.insert(name.to_owned(), entry);

        write_owner_only(&path, &document)?;
        Ok(self.inner.reload()?)
    }
}

/// Replace `path` with `document`, keeping it `0600`.
fn write_owner_only(path: &Path, document: &serde_json::Value) -> Result<(), OpnsenseError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let io = |what: &str, error: std::io::Error| {
        OpnsenseError::Config(format!("{what} {}: {error}", path.display()))
    };
    let parent = path.parent().ok_or_else(|| {
        OpnsenseError::Config(format!("{} has no parent directory", path.display()))
    })?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    let temporary = parent.join(format!(".devices-{}-{nanos}.tmp", std::process::id()));

    let bytes = serde_json::to_vec_pretty(document)
        .map_err(|error| OpnsenseError::Malformed(error.to_string()))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| io("cannot write next to", error))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io("cannot write next to", error))?;
    drop(file);
    std::fs::rename(&temporary, path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        io("cannot replace", error)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::Device;

    /// Neither the API key nor the API secret must ever be storable in the
    /// inventory file. `serde`'s `deny_unknown_fields` is what enforces it, so
    /// an inline value has to be a hard parse error rather than a silently
    /// ignored field.
    #[test]
    fn inline_credentials_are_rejected_at_parse_time() {
        for field in ["api_key", "api_secret"] {
            let raw = format!(
                r#"{{
                    "endpoint": "https://fw.example.org",
                    "{field}": "secret-value-that-must-not-parse"
                }}"#
            );
            let parsed: Result<Device, _> = serde_json::from_str(&raw);
            assert!(parsed.is_err(), "an inline {field} must not deserialize");
        }
    }

    /// A top-level credential must also be rejected: an envelope-level
    /// `deny_unknown_fields` gap would let one hide outside any device entry.
    #[test]
    fn a_top_level_api_key_is_rejected_at_load_time() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let raw = r#"{
            "version": 1,
            "api_key": "secret-at-top-level",
            "devices": {
                "test": {
                    "endpoint": "https://fw.example.org",
                    "api_key_env": "OPNSENSE_API_KEY",
                    "api_secret_env": "OPNSENSE_API_SECRET"
                }
            }
        }"#;

        let mut tmp = NamedTempFile::new().expect("temp file");
        tmp.write_all(raw.as_bytes()).expect("write");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(tmp.path(), perms).expect("chmod");
        }

        let result = super::DeviceRegistry::load(tmp.path());
        assert!(
            result.is_err(),
            "a top-level api_key must be rejected by the inventory loader"
        );
    }

    /// Naming both sources for either credential is ambiguous, and ambiguity
    /// about which credential was used is not something to resolve by
    /// precedence.
    #[test]
    fn naming_both_key_sources_is_an_error() {
        let raw = r#"{
            "endpoint": "https://fw.example.org",
            "api_key_env": "OPNSENSE_API_KEY",
            "api_key_file": "/etc/rustopnsmcp/api.key",
            "api_secret_env": "OPNSENSE_API_SECRET"
        }"#;
        let device: Device = serde_json::from_str(raw).expect("parses");
        assert!(device.validate().is_err());
    }

    #[test]
    fn naming_both_secret_sources_is_an_error() {
        let raw = r#"{
            "endpoint": "https://fw.example.org",
            "api_key_env": "OPNSENSE_API_KEY",
            "api_secret_env": "OPNSENSE_API_SECRET",
            "api_secret_file": "/etc/rustopnsmcp/api.secret"
        }"#;
        let device: Device = serde_json::from_str(raw).expect("parses");
        assert!(device.validate().is_err());
    }

    /// Naming neither source leaves nothing to authenticate with.
    #[test]
    fn naming_no_key_source_is_an_error() {
        let raw = r#"{
            "endpoint": "https://fw.example.org",
            "api_secret_env": "OPNSENSE_API_SECRET"
        }"#;
        let device: Device = serde_json::from_str(raw).expect("parses");
        assert!(device.validate().is_err());
    }

    #[test]
    fn naming_no_secret_source_is_an_error() {
        let raw = r#"{
            "endpoint": "https://fw.example.org",
            "api_key_env": "OPNSENSE_API_KEY"
        }"#;
        let device: Device = serde_json::from_str(raw).expect("parses");
        assert!(device.validate().is_err());
    }

    /// `mecmcp-http` rejects non-https at request construction, but failing
    /// here names the config file rather than the twentieth request.
    #[test]
    fn a_plaintext_endpoint_is_rejected_by_validate() {
        let raw = r#"{
            "endpoint": "http://fw.example.org",
            "api_key_env": "OPNSENSE_API_KEY",
            "api_secret_env": "OPNSENSE_API_SECRET"
        }"#;
        let device: Device = serde_json::from_str(raw).expect("parses");
        assert!(device.validate().is_err());
    }

    /// The shipped example inventory must be loadable through the real
    /// loader. An example that cannot load teaches the wrong format.
    #[test]
    fn the_example_inventory_is_valid() {
        use std::io::Write;
        use std::path::PathBuf;
        use tempfile::NamedTempFile;

        let example_path: PathBuf = [
            env!("CARGO_MANIFEST_DIR"),
            "..",
            "packaging",
            "examples",
            "devices.example.json",
        ]
        .iter()
        .collect();

        let example_content = std::fs::read_to_string(&example_path)
            .expect("example file must exist at packaging/examples/devices.example.json");

        let mut tmp = NamedTempFile::new().expect("temp file");
        tmp.write_all(example_content.as_bytes()).expect("write");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(tmp.path(), perms).expect("chmod");
        }

        let result = super::DeviceRegistry::load(tmp.path());
        assert!(
            result.is_ok(),
            "the example inventory must load cleanly: {:?}",
            result.err()
        );
    }

    fn canonical_inventory(dir: &tempfile::TempDir) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.path().join("devices.json");
        std::fs::write(
            &path,
            r#"{"version":1,"devices":{"fw-1":{"endpoint":"https://fw-1.example.org","api_key_env":"K1","api_secret_env":"S1"}}}"#,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn new_device(endpoint: &str) -> Device {
        serde_json::from_value(serde_json::json!({
            "endpoint": endpoint,
            "api_key_env": "K2",
            "api_secret_env": "S2",
        }))
        .unwrap()
    }

    #[test]
    fn add_device_persists_owner_only_and_reloads() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = canonical_inventory(&dir);
        let registry = super::DeviceRegistry::load(&path).unwrap();

        let count = registry
            .add_device("fw-2", new_device("https://fw-2.example.org"))
            .unwrap();
        assert_eq!(count, 2);
        assert!(registry.get("fw-2").is_ok());

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(
            super::DeviceRegistry::load(&path)
                .unwrap()
                .get("fw-2")
                .is_ok()
        );
    }

    #[test]
    fn add_device_refuses_a_duplicate_a_bad_name_and_a_plaintext_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let registry = super::DeviceRegistry::load(canonical_inventory(&dir)).unwrap();
        assert!(
            registry
                .add_device("fw-1", new_device("https://x.example.org"))
                .is_err()
        );
        assert!(
            registry
                .add_device("../fw", new_device("https://x.example.org"))
                .is_err()
        );
        assert!(
            registry
                .add_device("fw-3", new_device("http://x.example.org"))
                .is_err()
        );
        assert_eq!(registry.names(), vec!["fw-1".to_owned()]);
    }
}
