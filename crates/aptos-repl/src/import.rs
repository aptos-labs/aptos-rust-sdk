//! Import profiles from the legacy Aptos CLI config (`~/.aptos/config.yaml`).
//!
//! The legacy config format stores profiles with plaintext private keys:
//!
//! ```yaml
//! profiles:
//!   default:
//!     network: Testnet
//!     private_key: "ed25519-priv-0x..."
//!     public_key: "ed25519-pub-0x..."
//!     account: "0x..."
//!     rest_url: "https://..."
//! ```
//!
//! This module parses that format and imports the profiles into the
//! encrypted vault.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::common::KeyType;

// ---------------------------------------------------------------------------
// Legacy config types
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
pub struct LegacyConfig {
    #[serde(default)]
    pub profiles: BTreeMap<String, LegacyProfile>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct LegacyProfile {
    pub network: Option<String>,
    pub private_key: Option<String>,
    #[allow(dead_code)]
    pub public_key: Option<String>,
    pub account: Option<String>,
    pub rest_url: Option<String>,
    #[allow(dead_code)]
    pub faucet_url: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub derivation_path: Option<String>,
}

/// A parsed profile ready for import.
pub struct ImportableProfile {
    pub alias: String,
    pub private_key_hex: String,
    pub key_type: KeyType,
    pub network: Option<String>,
    #[allow(dead_code)]
    pub address: Option<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// The default path to the legacy Aptos CLI config.
pub fn legacy_config_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".aptos").join("config.yaml"))
}

/// Check if a legacy config exists.
pub fn legacy_config_exists() -> bool {
    legacy_config_path().map(|p| p.exists()).unwrap_or(false)
}

/// Load and parse the legacy config.
pub fn load_legacy_config() -> Result<LegacyConfig> {
    let path = legacy_config_path()?;
    let contents =
        std::fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
    let config: LegacyConfig =
        serde_yaml::from_str(&contents).context("failed to parse legacy config")?;
    Ok(config)
}

/// Extract importable profiles from the legacy config.
/// Only returns profiles that have a private key.
pub fn extract_importable_profiles(config: &LegacyConfig) -> Vec<ImportableProfile> {
    let mut profiles = Vec::new();

    for (name, profile) in &config.profiles {
        let Some(ref private_key_str) = profile.private_key else {
            continue; // skip profiles without private keys (e.g. ledger)
        };

        // Parse the private key format: "ed25519-priv-0x..." or just "0x..."
        let (key_type, hex) = parse_legacy_private_key(private_key_str);

        profiles.push(ImportableProfile {
            alias: name.clone(),
            private_key_hex: hex,
            key_type,
            network: profile.network.clone(),
            address: profile.account.clone(),
        });
    }

    // Sort by alias for deterministic ordering
    profiles.sort_by(|a, b| a.alias.cmp(&b.alias));
    profiles
}

/// Parse a legacy private key string.
///
/// Formats:
/// - `ed25519-priv-0x<hex>` -> (Ed25519, hex)
/// - `secp256k1-priv-0x<hex>` -> (Secp256k1, hex)
/// - `0x<hex>` -> (Ed25519, hex) -- assumed default
/// - `<hex>` -> (Ed25519, hex)
fn parse_legacy_private_key(s: &str) -> (KeyType, String) {
    if let Some(rest) = s.strip_prefix("ed25519-priv-") {
        let hex = rest.strip_prefix("0x").unwrap_or(rest);
        (KeyType::Ed25519, hex.to_string())
    } else if let Some(rest) = s.strip_prefix("secp256k1-priv-") {
        let hex = rest.strip_prefix("0x").unwrap_or(rest);
        (KeyType::Secp256k1, hex.to_string())
    } else if let Some(rest) = s.strip_prefix("secp256r1-priv-") {
        let hex = rest.strip_prefix("0x").unwrap_or(rest);
        (KeyType::Secp256r1, hex.to_string())
    } else {
        let hex = s.strip_prefix("0x").unwrap_or(s);
        (KeyType::Ed25519, hex.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ed25519_prefixed_key() {
        let (kt, hex) = parse_legacy_private_key(
            "ed25519-priv-0x64fd5d397964fae02392109e0cff976b76ddccc7454450ccb1bcdbe73860d426",
        );
        assert!(matches!(kt, KeyType::Ed25519));
        assert_eq!(
            hex,
            "64fd5d397964fae02392109e0cff976b76ddccc7454450ccb1bcdbe73860d426"
        );
    }

    #[test]
    fn parse_secp256k1_prefixed_key() {
        let (kt, hex) = parse_legacy_private_key("secp256k1-priv-0xabcd");
        assert!(matches!(kt, KeyType::Secp256k1));
        assert_eq!(hex, "abcd");
    }

    #[test]
    fn parse_bare_hex_key() {
        let (kt, hex) = parse_legacy_private_key("0xdeadbeef");
        assert!(matches!(kt, KeyType::Ed25519));
        assert_eq!(hex, "deadbeef");
    }

    #[test]
    fn parse_bare_hex_no_prefix() {
        let (kt, hex) = parse_legacy_private_key("deadbeef");
        assert!(matches!(kt, KeyType::Ed25519));
        assert_eq!(hex, "deadbeef");
    }

    #[test]
    fn parse_legacy_yaml() {
        let yaml = r#"
profiles:
  default:
    network: Testnet
    private_key: "ed25519-priv-0xaabbccdd"
    public_key: "ed25519-pub-0x1234"
    account: "0x5678"
    rest_url: "https://fullnode.testnet.aptoslabs.com"
  ledger:
    network: Mainnet
    account: "0xabcd"
    rest_url: "https://fullnode.mainnet.aptoslabs.com"
"#;
        let config: LegacyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.profiles.len(), 2);

        let importable = extract_importable_profiles(&config);
        // Only "default" has a private key, "ledger" should be skipped
        assert_eq!(importable.len(), 1);
        assert_eq!(importable[0].alias, "default");
        assert_eq!(importable[0].private_key_hex, "aabbccdd");
        assert!(matches!(importable[0].key_type, KeyType::Ed25519));
        assert_eq!(importable[0].network.as_deref(), Some("Testnet"));
    }

    #[test]
    fn extract_skips_profiles_without_keys() {
        let yaml = r#"
profiles:
  no-key:
    network: Mainnet
    account: "0x1"
"#;
        let config: LegacyConfig = serde_yaml::from_str(yaml).unwrap();
        let importable = extract_importable_profiles(&config);
        assert!(importable.is_empty());
    }

    #[test]
    fn legacy_config_path_ends_with_config_yaml() {
        let path = legacy_config_path().unwrap();
        assert!(path.ends_with("config.yaml"));
        assert!(path.to_string_lossy().contains(".aptos"));
    }
}
