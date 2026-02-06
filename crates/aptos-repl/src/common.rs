//! Shared types and helpers for the CLI.

use anyhow::{Context, Result, bail};
use aptos_sdk::{
    Aptos, AptosConfig,
    account::{Ed25519Account, Secp256k1Account, Secp256r1Account},
    types::AccountAddress,
};
use clap::ValueEnum;

/// Global options available on every command.
#[derive(clap::Args, Debug)]
pub struct GlobalOpts {
    /// Network to connect to
    #[arg(long, global = true, default_value = "mainnet")]
    pub network: NetworkArg,

    /// Custom fullnode URL (overrides --network)
    #[arg(long, global = true)]
    pub node_url: Option<String>,

    /// API key for authenticated access
    #[arg(long, global = true)]
    pub api_key: Option<String>,

    /// Output as JSON instead of human-readable text
    #[arg(long, global = true, default_value_t = false)]
    pub json: bool,
}

/// Supported network names.
#[derive(Debug, Clone, ValueEnum)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
    Devnet,
    Local,
}

/// Supported key types for account/key operations.
#[derive(Debug, Clone, ValueEnum)]
pub enum KeyType {
    Ed25519,
    Secp256k1,
    Secp256r1,
}

/// A CLI account that wraps the concrete SDK account types.
///
/// This avoids the `dyn Account` + `Sized` issue with generic SDK methods.
pub enum CliAccount {
    Ed25519(Ed25519Account),
    Secp256k1(Secp256k1Account),
    Secp256r1(Secp256r1Account),
}

impl CliAccount {
    pub fn address(&self) -> AccountAddress {
        match self {
            CliAccount::Ed25519(a) => a.address(),
            CliAccount::Secp256k1(a) => a.address(),
            CliAccount::Secp256r1(a) => a.address(),
        }
    }

    #[allow(dead_code)]
    pub fn public_key_hex(&self) -> String {
        match self {
            CliAccount::Ed25519(a) => a.public_key().to_string(),
            CliAccount::Secp256k1(a) => a.public_key().to_string(),
            CliAccount::Secp256r1(a) => a.public_key().to_string(),
        }
    }

    /// Call `sign_submit_and_wait` using the concrete account type.
    pub async fn sign_submit_and_wait(
        &self,
        aptos: &Aptos,
        payload: aptos_sdk::transaction::TransactionPayload,
    ) -> Result<aptos_sdk::api::response::AptosResponse<serde_json::Value>> {
        match self {
            CliAccount::Ed25519(a) => aptos
                .sign_submit_and_wait(a, payload, None)
                .await
                .map_err(Into::into),
            CliAccount::Secp256k1(a) => aptos
                .sign_submit_and_wait(a, payload, None)
                .await
                .map_err(Into::into),
            CliAccount::Secp256r1(a) => aptos
                .sign_submit_and_wait(a, payload, None)
                .await
                .map_err(Into::into),
        }
    }

    /// Call `transfer_apt` using the concrete account type.
    pub async fn transfer_apt(
        &self,
        aptos: &Aptos,
        recipient: AccountAddress,
        amount: u64,
    ) -> Result<aptos_sdk::api::response::AptosResponse<serde_json::Value>> {
        match self {
            CliAccount::Ed25519(a) => aptos
                .transfer_apt(a, recipient, amount)
                .await
                .map_err(Into::into),
            CliAccount::Secp256k1(a) => aptos
                .transfer_apt(a, recipient, amount)
                .await
                .map_err(Into::into),
            CliAccount::Secp256r1(a) => aptos
                .transfer_apt(a, recipient, amount)
                .await
                .map_err(Into::into),
        }
    }

    /// Call `transfer_coin` using the concrete account type.
    pub async fn transfer_coin(
        &self,
        aptos: &Aptos,
        recipient: AccountAddress,
        coin_type: aptos_sdk::types::TypeTag,
        amount: u64,
    ) -> Result<aptos_sdk::api::response::AptosResponse<serde_json::Value>> {
        match self {
            CliAccount::Ed25519(a) => aptos
                .transfer_coin(a, recipient, coin_type, amount)
                .await
                .map_err(Into::into),
            CliAccount::Secp256k1(a) => aptos
                .transfer_coin(a, recipient, coin_type, amount)
                .await
                .map_err(Into::into),
            CliAccount::Secp256r1(a) => aptos
                .transfer_coin(a, recipient, coin_type, amount)
                .await
                .map_err(Into::into),
        }
    }
}

impl GlobalOpts {
    /// Build an `AptosConfig` from the global options.
    pub fn build_config(&self) -> Result<AptosConfig> {
        let config = if let Some(url) = &self.node_url {
            AptosConfig::custom(url).context("invalid custom node URL")?
        } else {
            match self.network {
                NetworkArg::Mainnet => AptosConfig::mainnet(),
                NetworkArg::Testnet => AptosConfig::testnet(),
                NetworkArg::Devnet => AptosConfig::devnet(),
                NetworkArg::Local => AptosConfig::local(),
            }
        };

        let config = if let Some(key) = &self.api_key {
            config.with_api_key(key)
        } else {
            config
        };

        Ok(config)
    }

    /// Build an `Aptos` client from the global options.
    pub fn build_client(&self) -> Result<Aptos> {
        let config = self.build_config()?;
        Aptos::new(config).context("failed to create Aptos client")
    }
}

/// Parse an account address from a hex string.
pub fn parse_address(s: &str) -> Result<AccountAddress> {
    AccountAddress::from_hex(s).context("invalid account address")
}

/// Load an account from a private key hex string and key type.
pub fn load_account(private_key_hex: &str, key_type: &KeyType) -> Result<CliAccount> {
    let hex_str = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(private_key_hex);
    match key_type {
        KeyType::Ed25519 => {
            let account = Ed25519Account::from_private_key_hex(hex_str)
                .context("invalid Ed25519 private key")?;
            Ok(CliAccount::Ed25519(account))
        }
        KeyType::Secp256k1 => {
            let account = Secp256k1Account::from_private_key_hex(hex_str)
                .context("invalid Secp256k1 private key")?;
            Ok(CliAccount::Secp256k1(account))
        }
        KeyType::Secp256r1 => {
            let account = Secp256r1Account::from_private_key_hex(hex_str)
                .context("invalid Secp256r1 private key")?;
            Ok(CliAccount::Secp256r1(account))
        }
    }
}

/// Parse a BCS argument from a CLI string.
///
/// Supports:
/// - `address:<hex>` - AccountAddress
/// - `u8:<n>`, `u16:<n>`, `u32:<n>`, `u64:<n>`, `u128:<n>` - unsigned integers
/// - `bool:<true|false>` - boolean
/// - `string:<text>` - Move string (BCS-encoded)
/// - `hex:<bytes>` - raw hex bytes (vector<u8>)
pub fn parse_bcs_arg(s: &str) -> Result<Vec<u8>> {
    if let Some(rest) = s.strip_prefix("address:") {
        let addr = parse_address(rest)?;
        aptos_bcs::to_bytes(&addr).context("BCS encode address")
    } else if let Some(rest) = s.strip_prefix("u8:") {
        let v: u8 = rest.parse().context("invalid u8")?;
        aptos_bcs::to_bytes(&v).context("BCS encode u8")
    } else if let Some(rest) = s.strip_prefix("u16:") {
        let v: u16 = rest.parse().context("invalid u16")?;
        aptos_bcs::to_bytes(&v).context("BCS encode u16")
    } else if let Some(rest) = s.strip_prefix("u32:") {
        let v: u32 = rest.parse().context("invalid u32")?;
        aptos_bcs::to_bytes(&v).context("BCS encode u32")
    } else if let Some(rest) = s.strip_prefix("u64:") {
        let v: u64 = rest.parse().context("invalid u64")?;
        aptos_bcs::to_bytes(&v).context("BCS encode u64")
    } else if let Some(rest) = s.strip_prefix("u128:") {
        let v: u128 = rest.parse().context("invalid u128")?;
        aptos_bcs::to_bytes(&v).context("BCS encode u128")
    } else if let Some(rest) = s.strip_prefix("bool:") {
        let v: bool = rest.parse().context("invalid bool")?;
        aptos_bcs::to_bytes(&v).context("BCS encode bool")
    } else if let Some(rest) = s.strip_prefix("string:") {
        aptos_bcs::to_bytes(&rest).context("BCS encode string")
    } else if let Some(rest) = s.strip_prefix("hex:") {
        let bytes =
            hex::decode(rest.strip_prefix("0x").unwrap_or(rest)).context("invalid hex bytes")?;
        aptos_bcs::to_bytes(&bytes).context("BCS encode bytes")
    } else {
        bail!(
            "unknown argument format: {s}\n\
             Expected one of: address:<hex>, u8:<n>, u16:<n>, u32:<n>, u64:<n>, \
             u128:<n>, bool:<true|false>, string:<text>, hex:<bytes>"
        )
    }
}

/// Parse a JSON argument for view functions.
pub fn parse_json_arg(s: &str) -> Result<serde_json::Value> {
    // Try to parse as JSON first
    if let Ok(v) = serde_json::from_str(s) {
        return Ok(v);
    }
    // Otherwise, treat as a plain string
    Ok(serde_json::Value::String(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_address
    // -----------------------------------------------------------------------

    #[test]
    fn parse_address_valid_hex() {
        let addr = parse_address("0x1").unwrap();
        assert_eq!(addr, AccountAddress::from_hex("0x1").unwrap());
    }

    #[test]
    fn parse_address_full_hex() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let addr = parse_address(hex).unwrap();
        assert_eq!(addr, AccountAddress::ONE);
    }

    #[test]
    fn parse_address_invalid_fails() {
        assert!(parse_address("not_hex").is_err());
    }

    #[test]
    fn parse_address_empty_fails() {
        assert!(parse_address("").is_err());
    }

    // -----------------------------------------------------------------------
    // load_account
    // -----------------------------------------------------------------------

    #[test]
    fn load_ed25519_account() {
        // Generate a key, get its hex, then load it back
        let account = Ed25519Account::generate();
        let hex = hex::encode(account.private_key().to_bytes());
        let loaded = load_account(&hex, &KeyType::Ed25519).unwrap();
        assert_eq!(loaded.address(), account.address());
    }

    #[test]
    fn load_ed25519_account_with_0x_prefix() {
        let account = Ed25519Account::generate();
        let hex = format!("0x{}", hex::encode(account.private_key().to_bytes()));
        let loaded = load_account(&hex, &KeyType::Ed25519).unwrap();
        assert_eq!(loaded.address(), account.address());
    }

    #[test]
    fn load_secp256k1_account() {
        let account = Secp256k1Account::generate();
        let hex = hex::encode(account.private_key().to_bytes());
        let loaded = load_account(&hex, &KeyType::Secp256k1).unwrap();
        assert_eq!(loaded.address(), account.address());
    }

    #[test]
    fn load_secp256r1_account() {
        let account = Secp256r1Account::generate();
        let hex = hex::encode(account.private_key().to_bytes());
        let loaded = load_account(&hex, &KeyType::Secp256r1).unwrap();
        assert_eq!(loaded.address(), account.address());
    }

    #[test]
    fn load_account_invalid_hex_fails() {
        assert!(load_account("zzzz", &KeyType::Ed25519).is_err());
    }

    #[test]
    fn load_account_wrong_length_fails() {
        assert!(load_account("abcd", &KeyType::Ed25519).is_err());
    }

    // -----------------------------------------------------------------------
    // CliAccount
    // -----------------------------------------------------------------------

    #[test]
    fn cli_account_address_consistency() {
        let ed = Ed25519Account::generate();
        let addr = ed.address();
        let cli = CliAccount::Ed25519(ed);
        assert_eq!(cli.address(), addr);
    }

    #[test]
    fn cli_account_public_key_hex_not_empty() {
        let ed = Ed25519Account::generate();
        let cli = CliAccount::Ed25519(ed);
        assert!(!cli.public_key_hex().is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_bcs_arg
    // -----------------------------------------------------------------------

    #[test]
    fn parse_bcs_arg_u8() {
        let bytes = parse_bcs_arg("u8:42").unwrap();
        let val: u8 = aptos_bcs::from_bytes(&bytes).unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn parse_bcs_arg_u16() {
        let bytes = parse_bcs_arg("u16:1000").unwrap();
        let val: u16 = aptos_bcs::from_bytes(&bytes).unwrap();
        assert_eq!(val, 1000);
    }

    #[test]
    fn parse_bcs_arg_u32() {
        let bytes = parse_bcs_arg("u32:100000").unwrap();
        let val: u32 = aptos_bcs::from_bytes(&bytes).unwrap();
        assert_eq!(val, 100_000);
    }

    #[test]
    fn parse_bcs_arg_u64() {
        let bytes = parse_bcs_arg("u64:999999999").unwrap();
        let val: u64 = aptos_bcs::from_bytes(&bytes).unwrap();
        assert_eq!(val, 999_999_999);
    }

    #[test]
    fn parse_bcs_arg_u128() {
        let bytes = parse_bcs_arg("u128:340282366920938463463374607431768211455").unwrap();
        let val: u128 = aptos_bcs::from_bytes(&bytes).unwrap();
        assert_eq!(val, u128::MAX);
    }

    #[test]
    fn parse_bcs_arg_bool_true() {
        let bytes = parse_bcs_arg("bool:true").unwrap();
        let val: bool = aptos_bcs::from_bytes(&bytes).unwrap();
        assert!(val);
    }

    #[test]
    fn parse_bcs_arg_bool_false() {
        let bytes = parse_bcs_arg("bool:false").unwrap();
        let val: bool = aptos_bcs::from_bytes(&bytes).unwrap();
        assert!(!val);
    }

    #[test]
    fn parse_bcs_arg_string() {
        let bytes = parse_bcs_arg("string:hello world").unwrap();
        let val: String = aptos_bcs::from_bytes(&bytes).unwrap();
        assert_eq!(val, "hello world");
    }

    #[test]
    fn parse_bcs_arg_address() {
        let bytes = parse_bcs_arg("address:0x1").unwrap();
        let val: AccountAddress = aptos_bcs::from_bytes(&bytes).unwrap();
        assert_eq!(val, AccountAddress::ONE);
    }

    #[test]
    fn parse_bcs_arg_hex_bytes() {
        let bytes = parse_bcs_arg("hex:deadbeef").unwrap();
        let val: Vec<u8> = aptos_bcs::from_bytes(&bytes).unwrap();
        assert_eq!(val, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_bcs_arg_hex_with_0x_prefix() {
        let bytes = parse_bcs_arg("hex:0xdeadbeef").unwrap();
        let val: Vec<u8> = aptos_bcs::from_bytes(&bytes).unwrap();
        assert_eq!(val, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_bcs_arg_u8_overflow_fails() {
        assert!(parse_bcs_arg("u8:256").is_err());
    }

    #[test]
    fn parse_bcs_arg_bool_invalid_fails() {
        assert!(parse_bcs_arg("bool:maybe").is_err());
    }

    #[test]
    fn parse_bcs_arg_unknown_prefix_fails() {
        let result = parse_bcs_arg("foo:bar");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("unknown argument format"));
    }

    // -----------------------------------------------------------------------
    // parse_json_arg
    // -----------------------------------------------------------------------

    #[test]
    fn parse_json_arg_number() {
        let v = parse_json_arg("42").unwrap();
        assert_eq!(v, serde_json::json!(42));
    }

    #[test]
    fn parse_json_arg_string() {
        let v = parse_json_arg("\"hello\"").unwrap();
        assert_eq!(v, serde_json::json!("hello"));
    }

    #[test]
    fn parse_json_arg_object() {
        let v = parse_json_arg(r#"{"key":"val"}"#).unwrap();
        assert_eq!(v, serde_json::json!({"key": "val"}));
    }

    #[test]
    fn parse_json_arg_array() {
        let v = parse_json_arg("[1,2,3]").unwrap();
        assert_eq!(v, serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn parse_json_arg_boolean() {
        let v = parse_json_arg("true").unwrap();
        assert_eq!(v, serde_json::json!(true));
    }

    #[test]
    fn parse_json_arg_plain_string_fallback() {
        // Not valid JSON, so treated as plain string
        let v = parse_json_arg("hello world").unwrap();
        assert_eq!(v, serde_json::Value::String("hello world".to_string()));
    }

    #[test]
    fn parse_json_arg_address_string() {
        // An address like 0x1 is not valid JSON, falls back to string
        let v = parse_json_arg("0x1").unwrap();
        assert_eq!(v, serde_json::Value::String("0x1".to_string()));
    }

    // -----------------------------------------------------------------------
    // GlobalOpts / build_config
    // -----------------------------------------------------------------------

    #[test]
    fn build_config_mainnet() {
        let opts = GlobalOpts {
            network: NetworkArg::Mainnet,
            node_url: None,
            api_key: None,
            json: false,
        };
        let config = opts.build_config().unwrap();
        // Should succeed without error
        drop(config);
    }

    #[test]
    fn build_config_testnet() {
        let opts = GlobalOpts {
            network: NetworkArg::Testnet,
            node_url: None,
            api_key: None,
            json: false,
        };
        assert!(opts.build_config().is_ok());
    }

    #[test]
    fn build_config_custom_url() {
        let opts = GlobalOpts {
            network: NetworkArg::Mainnet,
            node_url: Some("https://fullnode.example.com/v1".to_string()),
            api_key: None,
            json: false,
        };
        assert!(opts.build_config().is_ok());
    }

    #[test]
    fn build_client_succeeds() {
        let opts = GlobalOpts {
            network: NetworkArg::Testnet,
            node_url: None,
            api_key: None,
            json: false,
        };
        assert!(opts.build_client().is_ok());
    }
}
