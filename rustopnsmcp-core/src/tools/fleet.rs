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

/// Arguments for `add_device`. The same fields as a `devices.json` entry; the
/// API key and secret are referenced, never passed inline.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddDeviceArgs {
    /// The new device's name.
    pub device: String,
    /// `https://` base URL.
    pub endpoint: String,
    /// Environment variable holding the API key.
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// Owner-only file holding the API key.
    #[serde(default)]
    pub api_key_file: Option<PathBuf>,
    /// Environment variable holding the API secret.
    #[serde(default)]
    pub api_secret_env: Option<String>,
    /// Owner-only file holding the API secret.
    #[serde(default)]
    pub api_secret_file: Option<PathBuf>,
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
                api_key_env: self.api_key_env,
                api_key_file: self.api_key_file,
                api_secret_env: self.api_secret_env,
                api_secret_file: self.api_secret_file,
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
            "api_key": "inline-key-must-not-parse", "api_secret_env": "S2",
        });
        assert!(serde_json::from_value::<AddDeviceArgs>(inline).is_err());
    }
}
