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
use std::sync::Mutex;

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

    /// Confirm every credential source actually loads, without building an
    /// HTTP client.
    ///
    /// `add_device` calls this before persisting, so a device whose key,
    /// secret, or CA cannot be loaded (missing file, unset env var, wrong
    /// permissions) never reaches `devices.json`. Writing it first and
    /// discovering this on the next reload would leave a dead entry that
    /// fails every future `reload_devices` and the next server restart.
    ///
    /// # Errors
    ///
    /// As [`Self::load_api_key`] and [`Self::load_api_secret`], plus an I/O
    /// error if `ca_pem_path` is set but unreadable.
    pub fn probe_credentials(&self) -> Result<(), OpnsenseError> {
        self.load_api_key()?;
        self.load_api_secret()?;
        if let Some(path) = &self.ca_pem_path {
            std::fs::read_to_string(path).map_err(|error| {
                OpnsenseError::Config(format!("ca_pem_path {}: {error}", path.display()))
            })?;
        }
        Ok(())
    }
}

/// The loaded device inventory, hot-reloadable on SIGHUP.
pub struct DeviceRegistry {
    inner: FileInventory<Device, ()>,
    /// Serializes the read-modify-write-reload in [`Self::add_device`].
    ///
    /// Without it, two concurrent `add_device` calls (or one racing a
    /// `reload_devices`) each read the file, insert into their own copy, and
    /// write it back — the second write silently discards the first's
    /// addition. Holding this for the whole operation, including the reload
    /// that observes the write, makes `add_device` calls serialize instead.
    write_lock: Mutex<()>,
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
            write_lock: Mutex::new(()),
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
    /// Three invariants a model-callable add must not be able to break:
    /// - its credential and CA files must resolve under the dedicated
    ///   `credentials` directory beside the inventory, not at an arbitrary
    ///   owner-only path, and must not already be used by another device;
    /// - the duplicate-name check is against the freshly read file, not a
    ///   possibly stale in-memory view; and
    /// - the credentials must actually load *before* anything is written, so
    ///   a bad entry never reaches disk.
    ///
    /// # Errors
    ///
    /// Returns [`OpnsenseError`] for an invalid name or device, a credential
    /// path outside the credentials directory, a reused credential, a
    /// duplicate name, a credential that fails to load, a non-canonical
    /// file, or any I/O failure.
    pub fn add_device(&self, name: &str, mut device: Device) -> Result<usize, OpnsenseError> {
        mecmcp_inventory::validate_device_name(name)
            .map_err(|error| OpnsenseError::Config(error.to_string()))?;
        device.validate()?;
        self.require_credentials_confined(&mut device)?;
        crate::client::OpnsenseClient::new(device.clone())?;

        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| OpnsenseError::Malformed("inventory write lock poisoned".to_owned()))?;

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
        if devices.contains_key(name) {
            return Err(OpnsenseError::Config(format!(
                "device {name} already exists"
            )));
        }
        Self::require_credentials_unused(devices, &device)?;

        let entry = serde_json::to_value(&device)
            .map_err(|error| OpnsenseError::Malformed(error.to_string()))?;
        devices.insert(name.to_owned(), entry);

        write_owner_only(&path, &document)?;
        Ok(self.inner.reload()?)
    }

    /// The directory every `add_device` credential file and CA PEM must
    /// resolve under: a dedicated `credentials` directory beside the
    /// inventory file.
    ///
    /// Confining a model-callable add to an operator-provisioned directory
    /// limits what path it can ever name.
    ///
    /// # Errors
    ///
    /// Returns [`OpnsenseError::Config`] if the inventory path has no parent
    /// or the `credentials` directory does not exist.
    fn credentials_dir(&self) -> Result<PathBuf, OpnsenseError> {
        let parent = self
            .inner
            .source()
            .parent()
            .map(Path::to_owned)
            .ok_or_else(|| {
                OpnsenseError::Config("inventory path has no parent directory".to_owned())
            })?;
        let dir = parent.join("credentials");
        dir.canonicalize().map_err(|error| {
            OpnsenseError::Config(format!(
                "credentials directory {} must exist (create it, mode 0700, owned by the \
                 service user) before add_device can be used: {error}",
                dir.display()
            ))
        })
    }

    /// Canonicalize `device`'s credential and CA paths in place, requiring
    /// each to resolve under [`Self::credentials_dir`].
    ///
    /// The directory is only resolved (and therefore only required to
    /// exist) when `device` actually names a file-based credential or CA;
    /// an env-only device never touches it. Writing the canonical form back
    /// means the value persisted and later compared is the value that was
    /// checked.
    fn require_credentials_confined(&self, device: &mut Device) -> Result<(), OpnsenseError> {
        let fields: [(&str, &mut Option<PathBuf>); 3] = [
            ("api_key_file", &mut device.api_key_file),
            ("api_secret_file", &mut device.api_secret_file),
            ("ca_pem_path", &mut device.ca_pem_path),
        ];
        if fields.iter().all(|(_, path)| path.is_none()) {
            return Ok(());
        }
        let creds_dir = self.credentials_dir()?;
        for (label, path) in fields {
            let Some(original) = path.as_ref() else {
                continue;
            };
            let canonical = original.canonicalize().map_err(|error| {
                OpnsenseError::Config(format!("{label} {}: {error}", original.display()))
            })?;
            if !canonical.starts_with(&creds_dir) {
                return Err(OpnsenseError::Config(format!(
                    "{label} {} does not resolve under the credentials directory {}",
                    original.display(),
                    creds_dir.display()
                )));
            }
            *path = Some(canonical);
        }
        Ok(())
    }

    /// Refuse a credential or CA path already bound to another device in
    /// the freshly read document.
    ///
    /// Two devices sharing nothing is the only safe default; forbid any
    /// overlap rather than guessing which reuse was intended. Compares
    /// resolved file identity, not path text.
    fn require_credentials_unused(
        devices: &serde_json::Map<String, serde_json::Value>,
        device: &Device,
    ) -> Result<(), OpnsenseError> {
        let new_paths: Vec<(&PathBuf, Option<(u64, u64)>)> = [
            device.api_key_file.as_ref(),
            device.api_secret_file.as_ref(),
            device.ca_pem_path.as_ref(),
        ]
        .into_iter()
        .flatten()
        .map(|path| (path, dev_ino(path)))
        .collect();
        if new_paths.is_empty() {
            return Ok(());
        }
        for (other_name, other_value) in devices {
            for field in ["api_key_file", "api_secret_file", "ca_pem_path"] {
                let Some(other_path) = other_value.get(field).and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let other_canonical = Path::new(other_path).canonicalize().map_err(|error| {
                    OpnsenseError::Config(format!(
                        "device {other_name}'s {field} {other_path}: {error}"
                    ))
                })?;
                let other_dev_ino = dev_ino(&other_canonical);
                let collides = new_paths.iter().any(|(new_path, new_dev_ino)| {
                    **new_path == other_canonical
                        || matches!((new_dev_ino, other_dev_ino), (Some(a), Some(b)) if *a == b)
                });
                if collides {
                    return Err(OpnsenseError::Config(format!(
                        "{field} is already used by device {other_name}; credential files must \
                         not be shared across devices"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// `path`'s `(st_dev, st_ino)`, or `None` if it cannot be read.
fn dev_ino(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
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
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&temporary);
        return Err(io("cannot write next to", error));
    }
    drop(file);
    std::fs::rename(&temporary, path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        io("cannot replace", error)
    })?;

    // Best-effort: fsync the parent directory so the rename survives a crash.
    // A failure here does not undo an already-visible rename; there is
    // nothing safe to roll back to, so it is not treated as fatal.
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
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

    /// Create `<dir>/credentials`, the directory `add_device` requires every
    /// credential and CA path to resolve under.
    ///
    /// Also installs the process-wide rustls `CryptoProvider`, since
    /// `add_device` now builds a TLS config (see
    /// `DeviceRegistry::add_device`) and the production binary normally
    /// does this once at startup.
    fn credentials_dir(dir: &tempfile::TempDir) -> std::path::PathBuf {
        static CRYPTO_PROVIDER: std::sync::Once = std::sync::Once::new();
        CRYPTO_PROVIDER.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });

        let path = dir.path().join("credentials");
        std::fs::create_dir(&path).unwrap();
        path
    }

    /// Write an owner-only credential file under `creds_dir`.
    fn credential_file(
        creds_dir: &std::path::Path,
        name: &str,
        content: &str,
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = creds_dir.join(name);
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    /// A device whose credentials are files under `creds_dir`, loadable by
    /// `add_device`.
    fn new_device(endpoint: &str, creds_dir: &std::path::Path) -> Device {
        let key = credential_file(creds_dir, "fw-2.key", "key-value");
        let secret = credential_file(creds_dir, "fw-2.secret", "secret-value");
        serde_json::from_value(serde_json::json!({
            "endpoint": endpoint,
            "api_key_file": key,
            "api_secret_file": secret,
        }))
        .unwrap()
    }

    #[test]
    fn add_device_persists_owner_only_and_reloads() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = canonical_inventory(&dir);
        let creds_dir = credentials_dir(&dir);
        let registry = super::DeviceRegistry::load(&path).unwrap();

        let count = registry
            .add_device("fw-2", new_device("https://fw-2.example.org", &creds_dir))
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
        let creds_dir = credentials_dir(&dir);
        let registry = super::DeviceRegistry::load(canonical_inventory(&dir)).unwrap();
        assert!(
            registry
                .add_device("fw-1", new_device("https://x.example.org", &creds_dir))
                .is_err()
        );
        assert!(
            registry
                .add_device("../fw", new_device("https://x.example.org", &creds_dir))
                .is_err()
        );
        assert!(
            registry
                .add_device("fw-3", new_device("http://x.example.org", &creds_dir))
                .is_err()
        );
        assert_eq!(registry.names(), vec!["fw-1".to_owned()]);
    }

    #[test]
    fn add_device_refuses_a_credential_file_outside_the_credentials_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = canonical_inventory(&dir);
        credentials_dir(&dir);
        let registry = super::DeviceRegistry::load(&path).unwrap();

        let outside_key = credential_file(dir.path(), "outside.key", "key-value");
        let outside_secret = credential_file(dir.path(), "outside.secret", "secret-value");
        let device: Device = serde_json::from_value(serde_json::json!({
            "endpoint": "https://fw-2.example.org",
            "api_key_file": outside_key,
            "api_secret_file": outside_secret,
        }))
        .unwrap();

        let error = registry.add_device("fw-2", device).unwrap_err();
        assert!(
            error.to_string().contains("credentials directory"),
            "unexpected error: {error}"
        );
        assert!(registry.get("fw-2").is_err());
    }

    #[test]
    fn add_device_refuses_a_credential_file_already_used_by_another_device() {
        let dir = tempfile::tempdir().unwrap();
        let path = canonical_inventory(&dir);
        let creds_dir = credentials_dir(&dir);
        let registry = super::DeviceRegistry::load(&path).unwrap();

        registry
            .add_device("fw-2", new_device("https://fw-2.example.org", &creds_dir))
            .unwrap();

        // fw-3 tries to reuse fw-2's api_key_file.
        let reused_key = creds_dir.join("fw-2.key");
        let secret = credential_file(&creds_dir, "fw-3.secret", "secret-value");
        let device: Device = serde_json::from_value(serde_json::json!({
            "endpoint": "https://fw-3.example.org",
            "api_key_file": reused_key,
            "api_secret_file": secret,
        }))
        .unwrap();

        let error = registry.add_device("fw-3", device).unwrap_err();
        assert!(
            error.to_string().contains("already used"),
            "unexpected error: {error}"
        );
        assert!(registry.get("fw-3").is_err());
    }

    /// The reuse check must compare canonicalized paths, not raw strings:
    /// a different spelling of fw-2's own `api_key_file` is still a reuse.
    #[test]
    fn add_device_refuses_a_credential_file_reused_via_a_different_path_spelling() {
        let dir = tempfile::tempdir().unwrap();
        let path = canonical_inventory(&dir);
        let creds_dir = credentials_dir(&dir);
        let registry = super::DeviceRegistry::load(&path).unwrap();

        registry
            .add_device("fw-2", new_device("https://fw-2.example.org", &creds_dir))
            .unwrap();

        // Same file as fw-2's api_key_file, spelled with an extra `.` segment.
        let reused_key = creds_dir.join(".").join("fw-2.key");
        let secret = credential_file(&creds_dir, "fw-3.secret", "secret-value");
        let device: Device = serde_json::from_value(serde_json::json!({
            "endpoint": "https://fw-3.example.org",
            "api_key_file": reused_key,
            "api_secret_file": secret,
        }))
        .unwrap();

        let error = registry.add_device("fw-3", device).unwrap_err();
        assert!(
            error.to_string().contains("already used"),
            "unexpected error: {error}"
        );
        assert!(registry.get("fw-3").is_err());
    }

    /// The reuse check must also catch a hard link: a different name inside
    /// `credentials/` that resolves to the same inode as fw-2's credential.
    #[test]
    fn add_device_refuses_a_credential_file_reused_via_a_hard_link() {
        let dir = tempfile::tempdir().unwrap();
        let path = canonical_inventory(&dir);
        let creds_dir = credentials_dir(&dir);
        let registry = super::DeviceRegistry::load(&path).unwrap();

        registry
            .add_device("fw-2", new_device("https://fw-2.example.org", &creds_dir))
            .unwrap();

        let linked_key = creds_dir.join("fw-3.key");
        std::fs::hard_link(creds_dir.join("fw-2.key"), &linked_key).unwrap();
        let secret = credential_file(&creds_dir, "fw-3.secret", "secret-value");
        let device: Device = serde_json::from_value(serde_json::json!({
            "endpoint": "https://fw-3.example.org",
            "api_key_file": linked_key,
            "api_secret_file": secret,
        }))
        .unwrap();

        let error = registry.add_device("fw-3", device).unwrap_err();
        assert!(
            error.to_string().contains("already used"),
            "unexpected error: {error}"
        );
        assert!(registry.get("fw-3").is_err());
    }

    /// A stale in-memory view (e.g. another process edited `devices.json`
    /// without this registry reloading) must not let `add_device` overwrite
    /// a name that already exists on disk.
    #[test]
    fn add_device_refuses_a_name_that_exists_only_on_disk() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = canonical_inventory(&dir);
        let creds_dir = credentials_dir(&dir);
        let registry = super::DeviceRegistry::load(&path).unwrap();

        std::fs::write(
            &path,
            r#"{"version":1,"devices":{
                "fw-1":{"endpoint":"https://fw-1.example.org","api_key_env":"K1","api_secret_env":"S1"},
                "fw-9":{"endpoint":"https://operator.example.org","api_key_env":"K9","api_secret_env":"S9"}
            }}"#,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            registry.get("fw-9").is_err(),
            "the stale in-memory view must not already know fw-9"
        );

        let error = registry
            .add_device(
                "fw-9",
                new_device("https://attacker.example.org", &creds_dir),
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("already exists"),
            "unexpected error: {error}"
        );

        let on_disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            on_disk["devices"]["fw-9"]["endpoint"], "https://operator.example.org",
            "the operator's entry must not be overwritten"
        );
    }

    /// A credential that fails to load must refuse the add before anything
    /// is written, so a dead entry never reaches `devices.json`.
    #[test]
    fn add_device_refuses_when_a_credential_fails_to_load_and_leaves_the_file_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = canonical_inventory(&dir);
        let creds_dir = credentials_dir(&dir);
        let registry = super::DeviceRegistry::load(&path).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        let bad_key = credential_file(&creds_dir, "fw-2.key", "key-value");
        // Too permissive for the hardened loader, so loading it fails.
        std::fs::set_permissions(&bad_key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let secret = credential_file(&creds_dir, "fw-2.secret", "secret-value");
        let device: Device = serde_json::from_value(serde_json::json!({
            "endpoint": "https://fw-2.example.org",
            "api_key_file": bad_key,
            "api_secret_file": secret,
        }))
        .unwrap();

        assert!(registry.add_device("fw-2", device).is_err());
        assert!(registry.get("fw-2").is_err());
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            before, after,
            "devices.json must be untouched when a credential fails to load"
        );
    }

    /// An unparseable `ca_pem_path` must refuse the add before anything is
    /// written. Reading the file as text (the old check) is not enough: it
    /// must be built into a TLS config the same way a live client would.
    #[test]
    fn add_device_refuses_an_unparseable_ca_pem_and_leaves_the_file_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = canonical_inventory(&dir);
        let creds_dir = credentials_dir(&dir);
        let registry = super::DeviceRegistry::load(&path).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        let key = credential_file(&creds_dir, "fw-2.key", "key-value");
        let secret = credential_file(&creds_dir, "fw-2.secret", "secret-value");
        let bad_ca = credential_file(&creds_dir, "ca.pem", "not a PEM file");
        let device: Device = serde_json::from_value(serde_json::json!({
            "endpoint": "https://fw-2.example.org",
            "api_key_file": key,
            "api_secret_file": secret,
            "ca_pem_path": bad_ca,
        }))
        .unwrap();

        let error = registry.add_device("fw-2", device).unwrap_err();
        assert!(!error.to_string().is_empty());
        assert!(registry.get("fw-2").is_err());
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            before, after,
            "devices.json must be untouched when ca_pem_path cannot be parsed"
        );
    }
}
