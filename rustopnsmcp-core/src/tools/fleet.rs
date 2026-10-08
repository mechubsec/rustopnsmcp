//! Fleet-meta tools: the names and shapes every mechub MCP server shares.

use crate::inventory::Device;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;

/// Arguments for a tool that takes none. Any field is refused.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmptyArgs {}

/// Arguments for `gather_device_facts`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GatherFactsArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
}

/// Arguments for `add_device`. The same fields as a `devices.json` entry,
/// minus the environment-variable credential form.
///
/// Only the file form of a credential is accepted here; env refs stay
/// operator-only, set by hand-editing `devices.json`. The API key and secret
/// are referenced, never passed inline, and `add_device` additionally
/// requires both files to resolve under the server's dedicated credentials
/// directory and to be unused by any other device (see
/// `DeviceRegistry::add_device`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddDeviceArgs {
    /// The new device's name.
    pub device: String,
    /// `https://` base URL.
    pub endpoint: String,
    /// Owner-only file holding the API key, under the credentials directory.
    pub api_key_file: PathBuf,
    /// Owner-only file holding the API secret, under the credentials directory.
    pub api_secret_file: PathBuf,
    /// PEM trust anchor for a device behind a private CA.
    #[serde(default)]
    pub ca_pem_path: Option<PathBuf>,
}

impl AddDeviceArgs {
    /// The name and the inventory entry.
    #[must_use]
    pub fn into_device(self) -> (String, Device) {
        (
            self.device,
            Device {
                endpoint: self.endpoint,
                api_key_env: None,
                api_key_file: Some(self.api_key_file),
                api_secret_env: None,
                api_secret_file: Some(self.api_secret_file),
                ca_pem_path: self.ca_pem_path,
            },
        )
    }
}

/// The fact sheet for one device, from its system and firmware status.
///
/// A fact the device did not report is `null`, never a guess.
#[must_use]
pub fn facts_from(device: &str, system: &Value, firmware: &Value) -> Value {
    let fact =
        |source: &Value, pointer: &str| source.pointer(pointer).cloned().unwrap_or(Value::Null);
    serde_json::json!({
        "device": device,
        "product_name": fact(system, "/product_name"),
        "product_version": fact(firmware, "/product/product_version"),
        "product_latest": fact(firmware, "/product/product_latest"),
        "product_series": fact(firmware, "/product/product_series"),
        "upgrade_needs_reboot": fact(firmware, "/upgrade_needs_reboot"),
        "uptime": fact(system, "/device_uptime"),
        "cpu_type": fact(system, "/cpu_type"),
        "load_average": fact(system, "/load_average"),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::testing::fixture;

    #[test]
    fn facts_combine_system_and_firmware_status() {
        let facts = facts_from(
            "fw-1",
            &fixture("system_status"),
            &fixture("firmware_status"),
        );
        assert_eq!(facts["device"], "fw-1");
        assert_eq!(facts["product_name"], "OPNsense");
        assert_eq!(facts["product_version"], "24.7");
        assert_eq!(facts["product_latest"], "24.7");
        assert_eq!(facts["uptime"], "3 days, 04:12");
    }

    #[test]
    fn a_missing_fact_is_null_not_invented() {
        let facts = facts_from("fw-1", &serde_json::json!({}), &serde_json::json!({}));
        assert!(facts["product_version"].is_null());
        assert!(facts["cpu_type"].is_null());
    }

    #[test]
    fn empty_args_refuse_any_field() {
        assert!(serde_json::from_value::<EmptyArgs>(serde_json::json!({})).is_ok());
        assert!(serde_json::from_value::<EmptyArgs>(serde_json::json!({ "device": "x" })).is_err());
    }

    #[test]
    fn add_device_refuses_an_inline_secret() {
        let inline = serde_json::json!({
            "device": "fw-2", "endpoint": "https://fw-2.example.org",
            "api_key_file": "/creds/fw-2.key", "api_secret_file": "/creds/fw-2.secret",
            "api_key": "inline-key-must-not-parse",
        });
        assert!(serde_json::from_value::<AddDeviceArgs>(inline).is_err());
    }

    #[test]
    fn add_device_refuses_an_env_credential() {
        let env_ref = serde_json::json!({
            "device": "fw-2", "endpoint": "https://fw-2.example.org",
            "api_key_file": "/creds/fw-2.key", "api_secret_env": "S2",
        });
        assert!(serde_json::from_value::<AddDeviceArgs>(env_ref).is_err());
    }

    #[test]
    fn add_device_into_device_never_names_an_env_var() {
        let args: AddDeviceArgs = serde_json::from_value(serde_json::json!({
            "device": "fw-2", "endpoint": "https://fw-2.example.org",
            "api_key_file": "/creds/fw-2.key", "api_secret_file": "/creds/fw-2.secret",
        }))
        .unwrap();
        let (name, device) = args.into_device();
        assert_eq!(name, "fw-2");
        assert!(device.api_key_env.is_none());
        assert!(device.api_secret_env.is_none());
    }
}
