//! Persistent CLI configuration stored at `~/.aptos/config/settings.json`.
//!
//! Provides default values for network, gas parameters, node URL, API key,
//! and the default account alias. Values can be overridden per-session in the
//! interactive shell and are automatically persisted when changed via the `config` command.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Persistent CLI configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CliConfig {
    /// Default network (mainnet, testnet, devnet, local).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// Custom fullnode URL (overrides network when set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_url: Option<String>,

    /// API key for authenticated access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,

    /// Default max gas amount for transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_gas: Option<u64>,

    /// Default gas unit price for transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_unit_price: Option<u64>,

    /// Default credential alias to activate on session start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_account: Option<String>,

    /// Default output format: true = JSON, false/absent = human-readable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_output: Option<bool>,
}

impl CliConfig {
    /// Path to the config file: `~/.aptos/config/settings.json`.
    pub fn default_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("cannot determine home directory")?;
        Ok(home.join(".aptos").join("config").join("settings.json"))
    }

    /// Load config from disk. Returns `Default` if the file does not exist.
    pub fn load() -> Result<Self> {
        let path = Self::default_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(&path).context("failed to read config file")?;
        let config: CliConfig =
            serde_json::from_str(&contents).context("failed to parse config file")?;
        Ok(config)
    }

    /// Save the current config to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::default_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("failed to create config directory")?;

            // Set restrictive permissions on the config directory (Unix)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        let contents = serde_json::to_string_pretty(self).context("failed to serialize config")?;
        std::fs::write(&path, &contents).context("failed to write config file")?;

        // Set restrictive permissions on the config file (Unix)
        // This file may contain an API key.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }

    /// Get a config value by key name. Returns `None` if unset.
    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            "network" => self.network.clone(),
            "node_url" | "node-url" => self.node_url.clone(),
            "api_key" | "api-key" => self.api_key.clone(),
            "max_gas" | "max-gas" => self.max_gas.map(|v| v.to_string()),
            "gas_unit_price" | "gas-unit-price" => self.gas_unit_price.map(|v| v.to_string()),
            "default_account" | "default-account" => self.default_account.clone(),
            "json_output" | "json-output" => self.json_output.map(|v| v.to_string()),
            _ => None,
        }
    }

    /// Set a config value by key name. Returns an error for unknown keys or
    /// invalid values.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "network" => {
                match value {
                    "mainnet" | "testnet" | "devnet" | "local" => {}
                    _ => anyhow::bail!(
                        "invalid network: {value}. Options: mainnet, testnet, devnet, local"
                    ),
                }
                self.network = Some(value.to_string());
            }
            "node_url" | "node-url" => {
                self.node_url = Some(value.to_string());
            }
            "api_key" | "api-key" => {
                self.api_key = Some(value.to_string());
            }
            "max_gas" | "max-gas" => {
                let v: u64 = value.parse().context("max_gas must be a number")?;
                self.max_gas = Some(v);
            }
            "gas_unit_price" | "gas-unit-price" => {
                let v: u64 = value.parse().context("gas_unit_price must be a number")?;
                self.gas_unit_price = Some(v);
            }
            "default_account" | "default-account" => {
                self.default_account = Some(value.to_string());
            }
            "json_output" | "json-output" => {
                let v: bool = value.parse().context("json_output must be true or false")?;
                self.json_output = Some(v);
            }
            _ => anyhow::bail!("unknown config key: {key}"),
        }
        Ok(())
    }

    /// Unset (remove) a config value by key name.
    pub fn unset(&mut self, key: &str) -> Result<()> {
        match key {
            "network" => self.network = None,
            "node_url" | "node-url" => self.node_url = None,
            "api_key" | "api-key" => self.api_key = None,
            "max_gas" | "max-gas" => self.max_gas = None,
            "gas_unit_price" | "gas-unit-price" => self.gas_unit_price = None,
            "default_account" | "default-account" => self.default_account = None,
            "json_output" | "json-output" => self.json_output = None,
            _ => anyhow::bail!("unknown config key: {key}"),
        }
        Ok(())
    }

    /// All known config keys with descriptions.
    pub fn known_keys() -> &'static [(&'static str, &'static str)] {
        &[
            (
                "network",
                "Default network (mainnet, testnet, devnet, local)",
            ),
            ("node_url", "Custom fullnode URL (overrides network)"),
            ("api_key", "API key for authenticated access"),
            ("max_gas", "Default max gas amount for transactions"),
            ("gas_unit_price", "Default gas unit price for transactions"),
            (
                "default_account",
                "Credential alias to auto-activate on start",
            ),
            ("json_output", "Default output format (true = JSON)"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Default / construction
    // -----------------------------------------------------------------------

    #[test]
    fn default_config_is_all_none() {
        let cfg = CliConfig::default();
        assert!(cfg.network.is_none());
        assert!(cfg.node_url.is_none());
        assert!(cfg.api_key.is_none());
        assert!(cfg.max_gas.is_none());
        assert!(cfg.gas_unit_price.is_none());
        assert!(cfg.default_account.is_none());
        assert!(cfg.json_output.is_none());
    }

    // -----------------------------------------------------------------------
    // get / set
    // -----------------------------------------------------------------------

    #[test]
    fn set_and_get_network() {
        let mut cfg = CliConfig::default();
        cfg.set("network", "testnet").unwrap();
        assert_eq!(cfg.get("network"), Some("testnet".to_string()));
    }

    #[test]
    fn set_invalid_network_fails() {
        let mut cfg = CliConfig::default();
        assert!(cfg.set("network", "foonet").is_err());
    }

    #[test]
    fn set_and_get_node_url() {
        let mut cfg = CliConfig::default();
        cfg.set("node_url", "https://example.com").unwrap();
        assert_eq!(cfg.get("node_url"), Some("https://example.com".to_string()));
        // Also via dash alias
        assert_eq!(cfg.get("node-url"), Some("https://example.com".to_string()));
    }

    #[test]
    fn set_and_get_api_key() {
        let mut cfg = CliConfig::default();
        cfg.set("api-key", "my-secret-key").unwrap();
        assert_eq!(cfg.get("api_key"), Some("my-secret-key".to_string()));
    }

    #[test]
    fn set_and_get_max_gas() {
        let mut cfg = CliConfig::default();
        cfg.set("max_gas", "200000").unwrap();
        assert_eq!(cfg.get("max-gas"), Some("200000".to_string()));
        assert_eq!(cfg.max_gas, Some(200_000));
    }

    #[test]
    fn set_max_gas_invalid_value_fails() {
        let mut cfg = CliConfig::default();
        assert!(cfg.set("max_gas", "not_a_number").is_err());
    }

    #[test]
    fn set_and_get_gas_unit_price() {
        let mut cfg = CliConfig::default();
        cfg.set("gas-unit-price", "100").unwrap();
        assert_eq!(cfg.get("gas_unit_price"), Some("100".to_string()));
        assert_eq!(cfg.gas_unit_price, Some(100));
    }

    #[test]
    fn set_and_get_default_account() {
        let mut cfg = CliConfig::default();
        cfg.set("default-account", "alice").unwrap();
        assert_eq!(cfg.get("default_account"), Some("alice".to_string()));
    }

    #[test]
    fn set_and_get_json_output() {
        let mut cfg = CliConfig::default();
        cfg.set("json_output", "true").unwrap();
        assert_eq!(cfg.get("json-output"), Some("true".to_string()));
        assert_eq!(cfg.json_output, Some(true));
    }

    #[test]
    fn set_json_output_invalid_fails() {
        let mut cfg = CliConfig::default();
        assert!(cfg.set("json_output", "yes").is_err());
    }

    #[test]
    fn get_unknown_key_returns_none() {
        let cfg = CliConfig::default();
        assert!(cfg.get("nonexistent").is_none());
    }

    #[test]
    fn set_unknown_key_fails() {
        let mut cfg = CliConfig::default();
        assert!(cfg.set("nonexistent", "value").is_err());
    }

    // -----------------------------------------------------------------------
    // unset
    // -----------------------------------------------------------------------

    #[test]
    fn unset_clears_value() {
        let mut cfg = CliConfig::default();
        cfg.set("network", "testnet").unwrap();
        assert!(cfg.get("network").is_some());

        cfg.unset("network").unwrap();
        assert!(cfg.get("network").is_none());
    }

    #[test]
    fn unset_works_with_dash_alias() {
        let mut cfg = CliConfig::default();
        cfg.set("gas_unit_price", "100").unwrap();
        cfg.unset("gas-unit-price").unwrap();
        assert!(cfg.get("gas_unit_price").is_none());
    }

    #[test]
    fn unset_unknown_key_fails() {
        let mut cfg = CliConfig::default();
        assert!(cfg.unset("nonexistent").is_err());
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn json_round_trip() {
        let mut cfg = CliConfig::default();
        cfg.set("network", "devnet").unwrap();
        cfg.set("max_gas", "50000").unwrap();
        cfg.set("default_account", "bob").unwrap();

        let json = serde_json::to_string(&cfg).unwrap();
        let deserialized: CliConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.network, Some("devnet".to_string()));
        assert_eq!(deserialized.max_gas, Some(50_000));
        assert_eq!(deserialized.default_account, Some("bob".to_string()));
        // Unset fields should remain None
        assert!(deserialized.node_url.is_none());
        assert!(deserialized.api_key.is_none());
    }

    #[test]
    fn json_skips_none_fields() {
        let cfg = CliConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn deserialize_empty_object() {
        let cfg: CliConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.network.is_none());
        assert!(cfg.max_gas.is_none());
    }

    #[test]
    fn deserialize_partial_object() {
        let cfg: CliConfig =
            serde_json::from_str(r#"{"network":"mainnet","gas_unit_price":200}"#).unwrap();
        assert_eq!(cfg.network, Some("mainnet".to_string()));
        assert_eq!(cfg.gas_unit_price, Some(200));
        assert!(cfg.node_url.is_none());
    }

    // -----------------------------------------------------------------------
    // File I/O
    // -----------------------------------------------------------------------

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        let mut cfg = CliConfig::default();
        cfg.set("network", "testnet").unwrap();
        cfg.set("max_gas", "99999").unwrap();

        // Save manually to custom path
        let json = serde_json::to_string_pretty(&cfg).unwrap();
        std::fs::write(&path, &json).unwrap();

        // Load back
        let loaded: CliConfig =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.network, Some("testnet".to_string()));
        assert_eq!(loaded.max_gas, Some(99_999));
    }

    // -----------------------------------------------------------------------
    // known_keys
    // -----------------------------------------------------------------------

    #[test]
    fn known_keys_covers_all_fields() {
        let keys = CliConfig::known_keys();
        assert!(keys.len() >= 7, "expected at least 7 known keys");

        // Every key should be gettable/settable
        let key_names: Vec<&str> = keys.iter().map(|(k, _)| *k).collect();
        assert!(key_names.contains(&"network"));
        assert!(key_names.contains(&"node_url"));
        assert!(key_names.contains(&"api_key"));
        assert!(key_names.contains(&"max_gas"));
        assert!(key_names.contains(&"gas_unit_price"));
        assert!(key_names.contains(&"default_account"));
        assert!(key_names.contains(&"json_output"));
    }

    #[test]
    fn all_known_keys_are_gettable() {
        let cfg = CliConfig::default();
        for (key, _desc) in CliConfig::known_keys() {
            // Should not panic, just return None for unset defaults
            let _ = cfg.get(key);
        }
    }

    #[test]
    fn default_path_ends_with_settings_json() {
        let path = CliConfig::default_path().unwrap();
        assert!(path.ends_with("settings.json"));
        assert!(path.to_string_lossy().contains(".aptos"));
        assert!(path.to_string_lossy().contains("config"));
    }
}
