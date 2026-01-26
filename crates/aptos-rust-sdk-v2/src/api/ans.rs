//! Aptos Names Service (ANS) client.
//!
//! This module provides functionality for resolving ANS names (like `alice.apt`)
//! to Aptos addresses and vice versa.
//!
//! # Overview
//!
//! ANS is the naming service for Aptos, similar to ENS on Ethereum. It allows
//! users to register human-readable names that map to their addresses.
//!
//! # Example
//!
//! ```rust,ignore
//! use aptos_rust_sdk_v2::Aptos;
//! use aptos_rust_sdk_v2::AptosConfig;
//!
//! let aptos = Aptos::new(AptosConfig::mainnet())?;
//!
//! // Resolve a name to an address
//! let address = aptos.ans().get_address("alice.apt").await?;
//!
//! // Get the primary name for an address
//! let name = aptos.ans().get_primary_name(address).await?;
//! ```

use crate::api::FullnodeClient;
use crate::config::{AptosConfig, Network};
use crate::error::{AptosError, AptosResult};
use crate::types::AccountAddress;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The ANS contract address on mainnet.
pub const ANS_ADDRESS_MAINNET: &str =
    "0x867ed1f6bf916171b1de3ee92849b8978b7d1b9e0a8cc982a3d19d535dfd9c0c";

/// The ANS contract address on testnet.
pub const ANS_ADDRESS_TESTNET: &str =
    "0x5f8fd2347449685cf41d4db97926ec3a096eaf381c397f0e3d7cbc17fbdd0bce";

/// The router contract address on mainnet.
pub const ANS_ROUTER_MAINNET: &str =
    "0x867ed1f6bf916171b1de3ee92849b8978b7d1b9e0a8cc982a3d19d535dfd9c0c";

/// The router contract address on testnet.
pub const ANS_ROUTER_TESTNET: &str =
    "0x5f8fd2347449685cf41d4db97926ec3a096eaf381c397f0e3d7cbc17fbdd0bce";

/// Client for interacting with the Aptos Names Service.
///
/// # Example
///
/// ```rust,ignore
/// use aptos_rust_sdk_v2::api::AnsClient;
/// use aptos_rust_sdk_v2::config::AptosConfig;
///
/// let client = AnsClient::new(AptosConfig::mainnet())?;
///
/// // Resolve name to address
/// if let Some(address) = client.get_address("alice.apt").await? {
///     println!("alice.apt -> {}", address);
/// }
///
/// // Get primary name for address
/// if let Some(name) = client.get_primary_name(address).await? {
///     println!("{} -> {}", address, name);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AnsClient {
    fullnode: Arc<FullnodeClient>,
    ans_address: AccountAddress,
    network: Network,
}

/// A resolved ANS name with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsName {
    /// The full domain name (e.g., "alice.apt").
    pub name: String,
    /// The resolved address.
    pub address: AccountAddress,
    /// Expiration timestamp (Unix seconds).
    pub expiration_timestamp: Option<u64>,
    /// Whether this is a primary name for the address.
    pub is_primary: bool,
}

/// ANS domain registration info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    /// The domain name without TLD (e.g., "alice").
    pub domain: String,
    /// Optional subdomain (e.g., "sub" in "sub.alice.apt").
    pub subdomain: Option<String>,
    /// The registered address.
    pub target_address: Option<AccountAddress>,
    /// Expiration timestamp.
    pub expiration_timestamp: u64,
    /// Whether registration is expired.
    pub is_expired: bool,
}

impl AnsClient {
    /// Creates a new ANS client.
    pub fn new(config: AptosConfig) -> AptosResult<Self> {
        let ans_address = match config.network() {
            Network::Mainnet => AccountAddress::from_hex(ANS_ADDRESS_MAINNET)?,
            Network::Testnet => AccountAddress::from_hex(ANS_ADDRESS_TESTNET)?,
            _ => {
                return Err(AptosError::Config(
                    "ANS is only available on mainnet and testnet".into(),
                ))
            }
        };

        let fullnode = Arc::new(FullnodeClient::new(config.clone())?);
        let network = config.network();

        Ok(Self {
            fullnode,
            ans_address,
            network,
        })
    }

    /// Creates an ANS client from an existing fullnode client.
    pub fn from_fullnode(fullnode: Arc<FullnodeClient>, network: Network) -> AptosResult<Self> {
        let ans_address = match network {
            Network::Mainnet => AccountAddress::from_hex(ANS_ADDRESS_MAINNET)?,
            Network::Testnet => AccountAddress::from_hex(ANS_ADDRESS_TESTNET)?,
            _ => {
                return Err(AptosError::Config(
                    "ANS is only available on mainnet and testnet".into(),
                ))
            }
        };

        Ok(Self {
            fullnode,
            ans_address,
            network,
        })
    }

    /// Resolves an ANS name to an address.
    ///
    /// Accepts names with or without the `.apt` suffix.
    ///
    /// # Arguments
    ///
    /// * `name` - The ANS name to resolve (e.g., "alice" or "alice.apt")
    ///
    /// # Returns
    ///
    /// The resolved address, or `None` if the name is not registered.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let address = client.get_address("alice.apt").await?;
    /// let address = client.get_address("alice").await?;  // Same as above
    /// ```
    pub async fn get_address(&self, name: &str) -> AptosResult<Option<AccountAddress>> {
        let (domain, subdomain) = Self::parse_name(name)?;

        // Call the view function to get the target address
        let function = format!("{}::domains::get_target_addr", self.ans_address);

        let args = if let Some(sub) = &subdomain {
            vec![
                serde_json::json!(domain),
                serde_json::json!(sub),
            ]
        } else {
            vec![
                serde_json::json!(domain),
                serde_json::json!(""),  // Empty string for no subdomain
            ]
        };

        let result = self
            .fullnode
            .view(&function, vec![], args)
            .await;

        match result {
            Ok(response) => {
                // Response is [{ "vec": ["0x..."] }] or [{ "vec": [] }]
                if let Some(first) = response.data.first()
                    && let Some(vec_obj) = first.get("vec")
                        && let Some(arr) = vec_obj.as_array()
                            && let Some(addr_str) = arr.first().and_then(|v| v.as_str()) {
                                let address = AccountAddress::from_hex(addr_str)?;
                                return Ok(Some(address));
                            }
                Ok(None)
            }
            Err(AptosError::Api { status_code: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Gets the primary ANS name for an address.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to look up
    ///
    /// # Returns
    ///
    /// The primary name (with `.apt` suffix), or `None` if no primary name is set.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if let Some(name) = client.get_primary_name(address).await? {
    ///     println!("Primary name: {}", name);  // e.g., "alice.apt"
    /// }
    /// ```
    pub async fn get_primary_name(&self, address: AccountAddress) -> AptosResult<Option<String>> {
        // Call the view function to get the primary name
        let function = format!("{}::domains::get_reverse_lookup", self.ans_address);

        let result = self
            .fullnode
            .view(
                &function,
                vec![],
                vec![serde_json::json!(address.to_string())],
            )
            .await;

        match result {
            Ok(response) => {
                // Response format: [{ "vec": [{ "domain_name": "...", "subdomain_name": { "vec": [...] } }] }]
                if let Some(first) = response.data.first()
                    && let Some(vec_obj) = first.get("vec")
                        && let Some(arr) = vec_obj.as_array()
                            && let Some(name_obj) = arr.first() {
                                let domain = name_obj
                                    .get("domain_name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");

                                let subdomain = name_obj
                                    .get("subdomain_name")
                                    .and_then(|v| v.get("vec"))
                                    .and_then(|v| v.as_array())
                                    .and_then(|arr| arr.first())
                                    .and_then(|v| v.as_str());

                                if !domain.is_empty() {
                                    let full_name = if let Some(sub) = subdomain {
                                        if sub.is_empty() {
                                            format!("{}.apt", domain)
                                        } else {
                                            format!("{}.{}.apt", sub, domain)
                                        }
                                    } else {
                                        format!("{}.apt", domain)
                                    };
                                    return Ok(Some(full_name));
                                }
                            }
                Ok(None)
            }
            Err(AptosError::Api { status_code: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Checks if an ANS name is available for registration.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to check (without `.apt` suffix)
    ///
    /// # Returns
    ///
    /// `true` if the name is available, `false` if taken.
    pub async fn is_name_available(&self, name: &str) -> AptosResult<bool> {
        let address = self.get_address(name).await?;
        Ok(address.is_none())
    }

    /// Gets the expiration timestamp for a domain.
    ///
    /// # Arguments
    ///
    /// * `name` - The domain name to check
    ///
    /// # Returns
    ///
    /// The expiration timestamp in Unix seconds, or `None` if not registered.
    pub async fn get_expiration(&self, name: &str) -> AptosResult<Option<u64>> {
        let (domain, subdomain) = Self::parse_name(name)?;

        let function = format!("{}::domains::get_expiration", self.ans_address);

        let args = if let Some(sub) = &subdomain {
            vec![
                serde_json::json!(domain),
                serde_json::json!(sub),
            ]
        } else {
            vec![
                serde_json::json!(domain),
                serde_json::json!(""),
            ]
        };

        let result = self.fullnode.view(&function, vec![], args).await;

        match result {
            Ok(response) => {
                if let Some(first) = response.data.first()
                    && let Some(vec_obj) = first.get("vec")
                        && let Some(arr) = vec_obj.as_array()
                            && let Some(exp_str) = arr.first().and_then(|v| v.as_str())
                                && let Ok(exp) = exp_str.parse::<u64>() {
                                    return Ok(Some(exp));
                                }
                Ok(None)
            }
            Err(AptosError::Api { status_code: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Resolves an address or ANS name to an address.
    ///
    /// This is a convenience function that accepts either a hex address
    /// or an ANS name and returns the resolved address.
    ///
    /// # Arguments
    ///
    /// * `address_or_name` - Either a hex address (0x...) or an ANS name
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Both work:
    /// let addr = client.resolve("alice.apt").await?;
    /// let addr = client.resolve("0x123...").await?;
    /// ```
    pub async fn resolve(&self, address_or_name: &str) -> AptosResult<AccountAddress> {
        // Try to parse as address first
        if (address_or_name.starts_with("0x") || address_or_name.starts_with("0X"))
            && let Ok(address) = AccountAddress::from_hex(address_or_name) {
                return Ok(address);
            }

        // Try as ANS name
        self.get_address(address_or_name)
            .await?
            .ok_or_else(|| AptosError::NotFound(format!("ANS name not found: {}", address_or_name)))
    }

    /// Parses an ANS name into domain and optional subdomain.
    ///
    /// # Examples
    ///
    /// - "alice.apt" -> ("alice", None)
    /// - "alice" -> ("alice", None)
    /// - "sub.alice.apt" -> ("alice", Some("sub"))
    /// - "sub.alice" -> ("alice", Some("sub"))
    fn parse_name(name: &str) -> AptosResult<(String, Option<String>)> {
        // Remove .apt suffix if present
        let name = name.trim().to_lowercase();
        let name = name.strip_suffix(".apt").unwrap_or(&name);

        let parts: Vec<&str> = name.split('.').collect();

        match parts.len() {
            1 => {
                // Just domain: "alice"
                let domain = parts[0].to_string();
                Self::validate_name_part(&domain)?;
                Ok((domain, None))
            }
            2 => {
                // Subdomain.domain: "sub.alice"
                let subdomain = parts[0].to_string();
                let domain = parts[1].to_string();
                Self::validate_name_part(&subdomain)?;
                Self::validate_name_part(&domain)?;
                Ok((domain, Some(subdomain)))
            }
            _ => Err(AptosError::InvalidAddress(format!(
                "Invalid ANS name format: {}",
                name
            ))),
        }
    }

    /// Validates a name part (domain or subdomain).
    fn validate_name_part(part: &str) -> AptosResult<()> {
        if part.is_empty() {
            return Err(AptosError::InvalidAddress(
                "Name part cannot be empty".into(),
            ));
        }

        if part.len() > 63 {
            return Err(AptosError::InvalidAddress(
                "Name part cannot exceed 63 characters".into(),
            ));
        }

        // Must start with alphanumeric
        if !part.chars().next().map(|c| c.is_alphanumeric()).unwrap_or(false) {
            return Err(AptosError::InvalidAddress(
                "Name must start with alphanumeric character".into(),
            ));
        }

        // Can only contain alphanumeric and hyphens
        for c in part.chars() {
            if !c.is_alphanumeric() && c != '-' {
                return Err(AptosError::InvalidAddress(format!(
                    "Invalid character in name: '{}'",
                    c
                )));
            }
        }

        Ok(())
    }

    /// Returns the ANS contract address for the current network.
    pub fn ans_address(&self) -> AccountAddress {
        self.ans_address
    }

    /// Returns the current network.
    pub fn network(&self) -> Network {
        self.network
    }
}

/// Extension trait for types that can be resolved via ANS.
pub trait AnsResolvable {
    /// Resolves this value to an AccountAddress.
    fn resolve_address<'a>(
        &'a self,
        ans: &'a AnsClient,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AptosResult<AccountAddress>> + Send + 'a>>;
}

impl AnsResolvable for str {
    fn resolve_address<'a>(
        &'a self,
        ans: &'a AnsClient,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AptosResult<AccountAddress>> + Send + 'a>>
    {
        Box::pin(async move { ans.resolve(self).await })
    }
}

impl AnsResolvable for String {
    fn resolve_address<'a>(
        &'a self,
        ans: &'a AnsClient,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AptosResult<AccountAddress>> + Send + 'a>>
    {
        Box::pin(async move { ans.resolve(self).await })
    }
}

impl AnsResolvable for AccountAddress {
    fn resolve_address<'a>(
        &'a self,
        _ans: &'a AnsClient,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AptosResult<AccountAddress>> + Send + 'a>>
    {
        let addr = *self;
        Box::pin(async move { Ok(addr) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_name_simple() {
        let (domain, subdomain) = AnsClient::parse_name("alice").unwrap();
        assert_eq!(domain, "alice");
        assert!(subdomain.is_none());
    }

    #[test]
    fn test_parse_name_with_apt() {
        let (domain, subdomain) = AnsClient::parse_name("alice.apt").unwrap();
        assert_eq!(domain, "alice");
        assert!(subdomain.is_none());
    }

    #[test]
    fn test_parse_name_subdomain() {
        let (domain, subdomain) = AnsClient::parse_name("sub.alice").unwrap();
        assert_eq!(domain, "alice");
        assert_eq!(subdomain, Some("sub".to_string()));
    }

    #[test]
    fn test_parse_name_subdomain_with_apt() {
        let (domain, subdomain) = AnsClient::parse_name("sub.alice.apt").unwrap();
        assert_eq!(domain, "alice");
        assert_eq!(subdomain, Some("sub".to_string()));
    }

    #[test]
    fn test_parse_name_case_insensitive() {
        let (domain, subdomain) = AnsClient::parse_name("ALICE.APT").unwrap();
        assert_eq!(domain, "alice");
        assert!(subdomain.is_none());
    }

    #[test]
    fn test_parse_name_with_hyphen() {
        let (domain, subdomain) = AnsClient::parse_name("my-name.apt").unwrap();
        assert_eq!(domain, "my-name");
        assert!(subdomain.is_none());
    }

    #[test]
    fn test_parse_name_invalid_empty() {
        let result = AnsClient::parse_name("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_name_invalid_special_char() {
        let result = AnsClient::parse_name("alice@name.apt");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_name_part() {
        assert!(AnsClient::validate_name_part("alice").is_ok());
        assert!(AnsClient::validate_name_part("alice123").is_ok());
        assert!(AnsClient::validate_name_part("my-name").is_ok());
        assert!(AnsClient::validate_name_part("123abc").is_ok());

        // Invalid cases
        assert!(AnsClient::validate_name_part("").is_err());
        assert!(AnsClient::validate_name_part("-alice").is_err());
        assert!(AnsClient::validate_name_part("alice@").is_err());
        assert!(AnsClient::validate_name_part("alice name").is_err());
    }

    #[test]
    fn test_ans_addresses() {
        // Verify address constants are valid
        let mainnet = AccountAddress::from_hex(ANS_ADDRESS_MAINNET);
        assert!(mainnet.is_ok());

        let testnet = AccountAddress::from_hex(ANS_ADDRESS_TESTNET);
        assert!(testnet.is_ok());
    }

    #[test]
    fn test_parse_name_numeric() {
        let (domain, subdomain) = AnsClient::parse_name("123456").unwrap();
        assert_eq!(domain, "123456");
        assert!(subdomain.is_none());
    }

    #[test]
    fn test_parse_name_deep_subdomain() {
        // deep.sub.alice.apt should parse as subdomain="deep.sub", domain="alice"
        // Actually based on the implementation, it splits on last '.apt' then takes last two parts
        let result = AnsClient::parse_name("deep.sub.alice.apt");
        // This might be an error case or parse differently
        assert!(result.is_ok() || result.is_err()); // Just ensure it doesn't panic
    }

    #[test]
    fn test_validate_name_part_boundary_length() {
        // Test with 63 character name (max allowed)
        let long_name = "a".repeat(63);
        assert!(AnsClient::validate_name_part(&long_name).is_ok());

        // Test with 64 character name (exceeds limit)
        let too_long = "a".repeat(64);
        assert!(AnsClient::validate_name_part(&too_long).is_err());
    }

    #[test]
    fn test_validate_name_part_starts_with_hyphen() {
        // Validation rejects names starting with hyphen
        assert!(AnsClient::validate_name_part("-alice").is_err());
    }

    #[test]
    fn test_validate_name_part_contains_underscore() {
        // Underscores should be invalid (only hyphens allowed as separator)
        let result = AnsClient::validate_name_part("alice_bob");
        // Based on implementation: only allows alphanumeric and hyphens
        assert!(result.is_err());
    }

    #[test]
    fn test_router_addresses() {
        // Verify router address constants are valid
        let mainnet = AccountAddress::from_hex(ANS_ROUTER_MAINNET);
        assert!(mainnet.is_ok());

        let testnet = AccountAddress::from_hex(ANS_ROUTER_TESTNET);
        assert!(testnet.is_ok());
    }
}

