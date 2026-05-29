//! Aptos Names Service (ANS) client.
//!
//! Resolves `.apt` names to addresses and back, and builds the entry-function
//! payloads needed to register names and manage their primary-name / target
//! address records. This mirrors the read/write surface of the TypeScript
//! SDK's `ans` namespace, talking to the on-chain `router` module via view
//! functions and entry functions.
//!
//! # Networks
//!
//! ANS is only deployed on mainnet, testnet, and (for development) localnet.
//! On those networks [`AnsClient::new`] picks the correct `router` contract
//! address automatically. For devnet, custom networks, or a privately deployed
//! ANS, construct the client with [`AnsClient::with_router_address`] and supply
//! the contract address yourself.
//!
//! # Name format
//!
//! Names follow the ANS validation rules (see [`AnsName`]): each segment must
//! be 3-63 characters of lowercase `a-z`, `0-9`, and hyphens, and may not start
//! or end with a hyphen. A name may have at most two segments,
//! `subdomain.domain`, and an optional trailing `.apt` which is stripped.
//!
//! # Example
//!
//! ```rust,no_run
//! use aptos_sdk::api::{AnsClient, FullnodeClient};
//! use aptos_sdk::config::AptosConfig;
//!
//! # async fn run() -> aptos_sdk::error::AptosResult<()> {
//! let fullnode = FullnodeClient::new(AptosConfig::mainnet())?;
//! let ans = AnsClient::new(fullnode);
//!
//! if let Some(address) = ans.get_target_address("greg.apt").await? {
//!     println!("greg.apt resolves to {address}");
//! }
//! # Ok(())
//! # }
//! ```

use crate::api::FullnodeClient;
use crate::config::Network;
use crate::error::{AptosError, AptosResult};
use crate::transaction::EntryFunction;
use crate::types::AccountAddress;

/// `router` contract address on mainnet.
const MAINNET_ROUTER: &str = "0x867ed1f6bf916171b1de3ee92849b8978b7d1b9e0a8cc982a3d19d535dfd9c0c";
/// `router` contract address on testnet.
const TESTNET_ROUTER: &str = "0x5f8fd2347449685cf41d4db97926ec3a096eaf381332be4f1318ad4d16a8497c";
/// Default `router` contract address used by the local ANS test deployment
/// (matches the TypeScript SDK's `LOCAL_ANS_ACCOUNT_ADDRESS`).
const LOCAL_ROUTER: &str = "0x585fc9f0f0c54183b039ffc770ca282ebd87307916c215a3e692f2f8e4305e82";

/// Minimum length of a single ANS name segment.
const MIN_SEGMENT_LEN: usize = 3;
/// Maximum length of a single ANS name segment.
const MAX_SEGMENT_LEN: usize = 63;

/// Human-readable description of the segment validation rules.
const SEGMENT_RULES: &str = "a segment must be 3-63 characters of lowercase a-z, 0-9, and hyphens, \
     and may not start or end with a hyphen";

/// A validated ANS name, split into its domain and optional subdomain.
///
/// Construct one with [`AnsName::parse`], which enforces the ANS validation
/// rules and strips a trailing `.apt`.
///
/// # Example
///
/// ```rust
/// use aptos_sdk::api::ans::AnsName;
///
/// let name = AnsName::parse("alice.apt")?;
/// assert_eq!(name.domain(), "alice");
/// assert_eq!(name.subdomain(), None);
///
/// let sub = AnsName::parse("wallet.alice.apt")?;
/// assert_eq!(sub.domain(), "alice");
/// assert_eq!(sub.subdomain(), Some("wallet"));
/// # Ok::<(), aptos_sdk::error::AptosError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnsName {
    domain: String,
    subdomain: Option<String>,
}

impl AnsName {
    /// Parses and validates an ANS name.
    ///
    /// Accepts names with or without a trailing `.apt`, and either a bare
    /// domain (`alice`) or a `subdomain.domain` (`wallet.alice`).
    ///
    /// # Errors
    ///
    /// Returns an error if the name has more than two segments or any segment
    /// violates the ANS rules (3-63 characters of lowercase `a-z`, `0-9`, and
    /// non-leading/trailing hyphens).
    pub fn parse(name: &str) -> AptosResult<Self> {
        let trimmed = name.strip_suffix(".apt").unwrap_or(name);
        let mut parts = trimmed.split('.');
        let first = parts.next().unwrap_or("");
        let second = parts.next();
        if parts.next().is_some() {
            return Err(invalid_name(name, "a name may have at most two segments"));
        }

        if !is_valid_segment(first) {
            return Err(invalid_name(first, SEGMENT_RULES));
        }
        if let Some(second) = second
            && !is_valid_segment(second)
        {
            return Err(invalid_name(second, SEGMENT_RULES));
        }

        match second {
            // "subdomain.domain": first is the subdomain, second the domain.
            Some(domain) => Ok(Self {
                domain: domain.to_string(),
                subdomain: Some(first.to_string()),
            }),
            // "domain": no subdomain.
            None => Ok(Self {
                domain: first.to_string(),
                subdomain: None,
            }),
        }
    }

    /// Returns the domain (top-level) segment, e.g. `alice` for `alice.apt`.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the subdomain segment, if any.
    #[must_use]
    pub fn subdomain(&self) -> Option<&str> {
        self.subdomain.as_deref()
    }

    /// Returns `true` if this name has a subdomain.
    #[must_use]
    pub fn is_subdomain(&self) -> bool {
        self.subdomain.is_some()
    }

    /// Returns the fully qualified name (without the `.apt` suffix), e.g.
    /// `wallet.alice` or `alice`.
    #[must_use]
    pub fn full_name(&self) -> String {
        match &self.subdomain {
            Some(sub) => format!("{sub}.{}", self.domain),
            None => self.domain.clone(),
        }
    }
}

impl std::fmt::Display for AnsName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.apt", self.full_name())
    }
}

fn invalid_name(value: &str, reason: &str) -> AptosError {
    AptosError::Other(anyhow::anyhow!("invalid ANS name '{value}': {reason}"))
}

/// Validates a single ANS segment against the ANS naming rules.
fn is_valid_segment(segment: &str) -> bool {
    let len = segment.len();
    if !(MIN_SEGMENT_LEN..=MAX_SEGMENT_LEN).contains(&len) {
        return false;
    }
    let bytes = segment.as_bytes();
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    // First and last characters must be alphanumeric (no leading/trailing hyphen).
    if !is_alnum(bytes[0]) || !is_alnum(bytes[len - 1]) {
        return false;
    }
    bytes.iter().all(|&b| is_alnum(b) || b == b'-')
}

/// Builds the standard `(domain: String, subdomain: Option<String>)` argument
/// pair used by most `router` functions.
fn domain_subdomain_args(name: &AnsName) -> AptosResult<Vec<Vec<u8>>> {
    Ok(vec![
        bcs_string(name.domain())?,
        bcs_option_string(name.subdomain())?,
    ])
}

/// Client for the Aptos Names Service.
///
/// Cheap to clone (wraps a [`FullnodeClient`]). See the [module docs](self) for
/// usage and network support.
#[derive(Debug, Clone)]
pub struct AnsClient {
    fullnode: FullnodeClient,
    /// Explicit router contract address. When `None`, the address is resolved
    /// from the fullnode's configured network.
    router_override: Option<AccountAddress>,
}

impl AnsClient {
    /// Constructs an ANS client that resolves the `router` contract address
    /// from the fullnode's configured network (mainnet / testnet / localnet).
    ///
    /// For networks without a built-in ANS deployment (devnet, custom), use
    /// [`with_router_address`](Self::with_router_address) instead; calls on a
    /// client built with [`new`](Self::new) for such a network return an error.
    #[must_use]
    pub fn new(fullnode: FullnodeClient) -> Self {
        Self {
            fullnode,
            router_override: None,
        }
    }

    /// Constructs an ANS client pinned to an explicit `router` contract
    /// address.
    ///
    /// Use this for devnet, custom networks, or a privately deployed ANS where
    /// the contract address is not built in.
    #[must_use]
    pub fn with_router_address(fullnode: FullnodeClient, router_address: AccountAddress) -> Self {
        Self {
            fullnode,
            router_override: Some(router_address),
        }
    }

    /// Returns the resolved `router` contract address for this client.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::Config`] if no override was supplied and the
    /// configured network has no known ANS deployment.
    pub fn router_address(&self) -> AptosResult<AccountAddress> {
        if let Some(addr) = self.router_override {
            return Ok(addr);
        }
        let hex = match self.fullnode.config().network() {
            Network::Mainnet => MAINNET_ROUTER,
            Network::Testnet => TESTNET_ROUTER,
            Network::Local => LOCAL_ROUTER,
            other => {
                return Err(AptosError::Config(format!(
                    "ANS is not deployed on {}; construct the client with \
                     AnsClient::with_router_address to supply the router contract address",
                    other.as_str()
                )));
            }
        };
        AccountAddress::from_hex(hex)
    }

    // === Reads ===

    /// Resolves the **target address** a name points to (where it resolves to),
    /// or `None` if the name is unregistered or has no target set.
    ///
    /// This is the address callers usually want when "looking up a name". It is
    /// distinct from the owner address (see
    /// [`get_owner_address`](Self::get_owner_address)).
    ///
    /// # Errors
    ///
    /// Returns an error if the network has no ANS deployment, the name is
    /// invalid, or the underlying view call fails.
    pub async fn get_target_address(&self, name: &str) -> AptosResult<Option<AccountAddress>> {
        let name = AnsName::parse(name)?;
        let values = self
            .view_router("get_target_addr", domain_subdomain_args(&name)?)
            .await?;
        Ok(option_address(values.first()))
    }

    /// Resolves the **owner address** of a name (the account that controls the
    /// registration), or `None` if the name is unregistered.
    ///
    /// # Errors
    ///
    /// Returns an error if the network has no ANS deployment, the name is
    /// invalid, or the underlying view call fails.
    pub async fn get_owner_address(&self, name: &str) -> AptosResult<Option<AccountAddress>> {
        let name = AnsName::parse(name)?;
        let values = self
            .view_router("get_owner_addr", domain_subdomain_args(&name)?)
            .await?;
        Ok(option_address(values.first()))
    }

    /// Returns the primary name registered to an address (as a fully qualified
    /// name without the `.apt` suffix, e.g. `wallet.alice` or `alice`), or
    /// `None` if the address has no primary name.
    ///
    /// # Errors
    ///
    /// Returns an error if the network has no ANS deployment or the underlying
    /// view call fails.
    pub async fn get_primary_name(&self, address: AccountAddress) -> AptosResult<Option<String>> {
        let args = vec![bcs_address(address)?];
        let values = self.view_router("get_primary_name", args).await?;

        // The router returns (Option<String> subdomain, Option<String> domain).
        let subdomain = option_string(values.first());
        let domain = option_string(values.get(1));

        Ok(domain.map(|domain| match subdomain {
            Some(sub) => format!("{sub}.{domain}"),
            None => domain,
        }))
    }

    /// Returns the expiration timestamp of a name in **seconds since the Unix
    /// epoch**, or `None` if the name is unregistered.
    ///
    /// Note: the TypeScript SDK returns milliseconds; this returns the raw
    /// on-chain value in seconds. Multiply by 1000 for millisecond parity.
    ///
    /// # Errors
    ///
    /// Returns an error if the network has no ANS deployment, the name is
    /// invalid, or a non-recoverable transport error occurs. A Move abort from
    /// the node (e.g. the name does not exist) is reported as `Ok(None)`.
    pub async fn get_expiration(&self, name: &str) -> AptosResult<Option<u64>> {
        let name = AnsName::parse(name)?;
        let args = domain_subdomain_args(&name)?;
        match self.view_router("get_expiration", args).await {
            Ok(values) => Ok(values.first().and_then(parse_u64)),
            // A missing name aborts in the Move view; the node surfaces that as
            // a 4xx API error. Treat it as "no expiration" rather than failing.
            Err(AptosError::Api { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Resolves a name to its target address, erroring if it does not resolve.
    ///
    /// This is a convenience wrapper over
    /// [`get_target_address`](Self::get_target_address) for callers that treat
    /// an unresolved name as an error.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::NotFound`] if the name does not resolve to an
    /// address, plus any error from
    /// [`get_target_address`](Self::get_target_address).
    pub async fn lookup(&self, name: &str) -> AptosResult<AccountAddress> {
        self.get_target_address(name).await?.ok_or_else(|| {
            AptosError::NotFound(format!("ANS name '{name}' does not resolve to an address"))
        })
    }

    /// Returns the primary name registered to an address, if any.
    ///
    /// Alias for [`get_primary_name`](Self::get_primary_name).
    ///
    /// # Errors
    ///
    /// Returns an error if the network has no ANS deployment or the underlying
    /// view call fails.
    pub async fn reverse_lookup(&self, address: AccountAddress) -> AptosResult<Option<String>> {
        self.get_primary_name(address).await
    }

    // === Writes (entry-function builders) ===

    /// Builds the payload to register a top-level domain for the given
    /// duration (in seconds).
    ///
    /// `target_address` is the address the name will resolve to (defaults to
    /// the sender on-chain when `None`); `to_address` is the account that will
    /// own the registration (defaults to the sender when `None`).
    ///
    /// # Errors
    ///
    /// Returns an error if the network has no ANS deployment, the name is
    /// invalid, the name has a subdomain (use a subdomain-specific flow), or
    /// argument encoding fails.
    pub async fn register_domain_payload(
        &self,
        name: &str,
        registration_duration_secs: u64,
        target_address: Option<AccountAddress>,
        to_address: Option<AccountAddress>,
    ) -> AptosResult<EntryFunction> {
        let name = AnsName::parse(name)?;
        if name.is_subdomain() {
            return Err(invalid_name(
                &name.full_name(),
                "register_domain_payload expects a top-level domain, not a subdomain",
            ));
        }
        let args = vec![
            bcs_string(name.domain())?,
            bcs_u64(registration_duration_secs)?,
            bcs_option_address(target_address)?,
            bcs_option_address(to_address)?,
        ];
        self.router_entry("register_domain", args)
    }

    /// Builds the payload to set the sender's primary name to `name`.
    ///
    /// # Errors
    ///
    /// Returns an error if the network has no ANS deployment, the name is
    /// invalid, or argument encoding fails.
    pub fn set_primary_name_payload(&self, name: &str) -> AptosResult<EntryFunction> {
        let name = AnsName::parse(name)?;
        self.router_entry("set_primary_name", domain_subdomain_args(&name)?)
    }

    /// Builds the payload to clear the sender's primary name.
    ///
    /// # Errors
    ///
    /// Returns an error if the network has no ANS deployment.
    pub fn clear_primary_name_payload(&self) -> AptosResult<EntryFunction> {
        self.router_entry("clear_primary_name", vec![])
    }

    /// Builds the payload to point `name` at `address` (set its target
    /// address).
    ///
    /// # Errors
    ///
    /// Returns an error if the network has no ANS deployment, the name is
    /// invalid, or argument encoding fails.
    pub fn set_target_address_payload(
        &self,
        name: &str,
        address: AccountAddress,
    ) -> AptosResult<EntryFunction> {
        let name = AnsName::parse(name)?;
        let mut args = domain_subdomain_args(&name)?;
        args.push(bcs_address(address)?);
        self.router_entry("set_target_addr", args)
    }

    /// Builds the payload to clear the target address of `name`.
    ///
    /// # Errors
    ///
    /// Returns an error if the network has no ANS deployment, the name is
    /// invalid, or argument encoding fails.
    pub fn clear_target_address_payload(&self, name: &str) -> AptosResult<EntryFunction> {
        let name = AnsName::parse(name)?;
        self.router_entry("clear_target_addr", domain_subdomain_args(&name)?)
    }

    // === Internal helpers ===

    /// Calls a `router::<function>` view function with BCS-encoded args.
    async fn view_router(
        &self,
        function: &str,
        args: Vec<Vec<u8>>,
    ) -> AptosResult<Vec<serde_json::Value>> {
        let router = self.router_address()?;
        let function_id = format!("{router}::router::{function}");
        let response = self
            .fullnode
            .view_bcs_args(&function_id, vec![], args)
            .await?;
        Ok(response.into_inner())
    }

    /// Builds an entry-function payload targeting `router::<function>`.
    fn router_entry(&self, function: &str, args: Vec<Vec<u8>>) -> AptosResult<EntryFunction> {
        let router = self.router_address()?;
        let function_id = format!("{router}::router::{function}");
        EntryFunction::from_function_id(&function_id, vec![], args)
    }
}

// === BCS argument encoders ===

fn bcs_string(value: &str) -> AptosResult<Vec<u8>> {
    aptos_bcs::to_bytes(&value.to_string()).map_err(AptosError::bcs)
}

fn bcs_option_string(value: Option<&str>) -> AptosResult<Vec<u8>> {
    aptos_bcs::to_bytes(&value.map(ToString::to_string)).map_err(AptosError::bcs)
}

fn bcs_address(value: AccountAddress) -> AptosResult<Vec<u8>> {
    aptos_bcs::to_bytes(&value).map_err(AptosError::bcs)
}

fn bcs_option_address(value: Option<AccountAddress>) -> AptosResult<Vec<u8>> {
    aptos_bcs::to_bytes(&value).map_err(AptosError::bcs)
}

fn bcs_u64(value: u64) -> AptosResult<Vec<u8>> {
    aptos_bcs::to_bytes(&value).map_err(AptosError::bcs)
}

// === JSON result decoders ===

/// Unwraps a Move `Option<T>` from its JSON form.
///
/// The node renders `0x1::option::Option<T>` as `{"vec": []}` (none) or
/// `{"vec": [value]}` (some). A bare array is also accepted defensively.
fn unwrap_option(value: &serde_json::Value) -> Option<&serde_json::Value> {
    if let Some(vec) = value.get("vec").and_then(serde_json::Value::as_array) {
        return vec.first();
    }
    if let Some(arr) = value.as_array() {
        return arr.first();
    }
    None
}

/// Decodes an `Option<address>` view result into an [`AccountAddress`].
fn option_address(value: Option<&serde_json::Value>) -> Option<AccountAddress> {
    let inner = unwrap_option(value?)?;
    let s = inner.as_str()?;
    AccountAddress::from_hex(s).ok()
}

/// Decodes a non-empty `Option<String>` view result.
fn option_string(value: Option<&serde_json::Value>) -> Option<String> {
    let inner = unwrap_option(value?)?;
    let s = inner.as_str()?;
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Parses a `u64` view result, which the node renders as a JSON string.
fn parse_u64(value: &serde_json::Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    value.as_str().and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AptosConfig;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn ans_for(server: &MockServer) -> AnsClient {
        let url = format!("{}/v1", server.uri());
        let config = AptosConfig::custom(&url).unwrap().without_retry();
        let fullnode = FullnodeClient::new(config).unwrap();
        // Custom network has no built-in ANS deployment; pin a router address.
        AnsClient::with_router_address(fullnode, AccountAddress::from_hex("0x1").unwrap())
    }

    #[test]
    fn parse_plain_domain() {
        let name = AnsName::parse("alice.apt").unwrap();
        assert_eq!(name.domain(), "alice");
        assert_eq!(name.subdomain(), None);
        assert!(!name.is_subdomain());
        assert_eq!(name.full_name(), "alice");
        assert_eq!(name.to_string(), "alice.apt");
    }

    #[test]
    fn parse_without_suffix() {
        let name = AnsName::parse("alice").unwrap();
        assert_eq!(name.domain(), "alice");
        assert_eq!(name.subdomain(), None);
    }

    #[test]
    fn parse_subdomain() {
        let name = AnsName::parse("wallet.alice.apt").unwrap();
        assert_eq!(name.domain(), "alice");
        assert_eq!(name.subdomain(), Some("wallet"));
        assert!(name.is_subdomain());
        assert_eq!(name.full_name(), "wallet.alice");
    }

    #[test]
    fn parse_rejects_invalid_names() {
        // Too short.
        assert!(AnsName::parse("ab").is_err());
        // Leading hyphen.
        assert!(AnsName::parse("-abc").is_err());
        // Trailing hyphen.
        assert!(AnsName::parse("abc-").is_err());
        // Uppercase.
        assert!(AnsName::parse("Alice").is_err());
        // Three segments.
        assert!(AnsName::parse("a.b.c").is_err());
        // Invalid characters.
        assert!(AnsName::parse("ali_ce").is_err());
    }

    #[test]
    fn segment_validation_boundaries() {
        assert!(is_valid_segment("abc"));
        assert!(is_valid_segment("a-c"));
        assert!(is_valid_segment("a1c"));
        assert!(is_valid_segment(&"a".repeat(63)));
        assert!(!is_valid_segment(&"a".repeat(64)));
        assert!(!is_valid_segment("ab"));
        assert!(!is_valid_segment("-bc"));
        assert!(!is_valid_segment("ab-"));
    }

    #[test]
    fn router_address_unsupported_network_errors() {
        // Devnet has no built-in ANS deployment.
        let fullnode = FullnodeClient::new(AptosConfig::devnet()).unwrap();
        let ans = AnsClient::new(fullnode);
        assert!(matches!(ans.router_address(), Err(AptosError::Config(_))));
    }

    #[test]
    fn router_address_known_networks() {
        let mainnet = AnsClient::new(FullnodeClient::new(AptosConfig::mainnet()).unwrap());
        assert_eq!(
            mainnet.router_address().unwrap(),
            AccountAddress::from_hex(MAINNET_ROUTER).unwrap()
        );
        let testnet = AnsClient::new(FullnodeClient::new(AptosConfig::testnet()).unwrap());
        assert_eq!(
            testnet.router_address().unwrap(),
            AccountAddress::from_hex(TESTNET_ROUTER).unwrap()
        );
    }

    #[tokio::test]
    async fn get_target_address_resolves() {
        let server = MockServer::start().await;
        let addr = "0x0000000000000000000000000000000000000000000000000000000000000abc";
        Mock::given(method("POST"))
            .and(path("/v1/view"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{"vec": [addr]}])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let ans = ans_for(&server);
        let resolved = ans.get_target_address("alice.apt").await.unwrap();
        assert_eq!(resolved, Some(AccountAddress::from_hex(addr).unwrap()));
    }

    #[tokio::test]
    async fn get_target_address_none_when_unregistered() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/view"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{"vec": []}])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let ans = ans_for(&server);
        let resolved = ans.get_target_address("alice.apt").await.unwrap();
        assert_eq!(resolved, None);
    }

    #[tokio::test]
    async fn get_primary_name_combines_subdomain_and_domain() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/view"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                // (subdomain, domain)
                serde_json::json!([{"vec": ["wallet"]}, {"vec": ["alice"]}]),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let ans = ans_for(&server);
        let name = ans.get_primary_name(AccountAddress::ONE).await.unwrap();
        assert_eq!(name, Some("wallet.alice".to_string()));
    }

    #[tokio::test]
    async fn get_primary_name_domain_only() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/view"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"vec": []}, {"vec": ["alice"]}])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let ans = ans_for(&server);
        let name = ans.get_primary_name(AccountAddress::ONE).await.unwrap();
        assert_eq!(name, Some("alice".to_string()));
    }

    #[tokio::test]
    async fn get_primary_name_none() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/view"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"vec": []}, {"vec": []}])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let ans = ans_for(&server);
        let name = ans.get_primary_name(AccountAddress::ONE).await.unwrap();
        assert_eq!(name, None);
    }

    #[tokio::test]
    async fn get_expiration_parses_seconds() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/view"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!(["1700000000"])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let ans = ans_for(&server);
        let expiration = ans.get_expiration("alice.apt").await.unwrap();
        assert_eq!(expiration, Some(1_700_000_000));
    }

    #[tokio::test]
    async fn get_expiration_none_on_move_abort() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/view"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "message": "Move abort",
                "error_code": "invalid_input"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let ans = ans_for(&server);
        let expiration = ans.get_expiration("alice.apt").await.unwrap();
        assert_eq!(expiration, None);
    }

    #[tokio::test]
    async fn lookup_errors_when_unresolved() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/view"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{"vec": []}])),
            )
            .mount(&server)
            .await;

        let ans = ans_for(&server);
        let err = ans.lookup("alice.apt").await.unwrap_err();
        assert!(matches!(err, AptosError::NotFound(_)));
    }

    #[test]
    fn set_primary_name_payload_encodes_arguments() {
        let router = AccountAddress::from_hex("0x1").unwrap();
        let fullnode = FullnodeClient::new(AptosConfig::mainnet()).unwrap();
        let ans = AnsClient::with_router_address(fullnode, router);

        let payload = ans.set_primary_name_payload("alice.apt").unwrap();
        assert_eq!(payload.module.address, router);
        assert_eq!(payload.module.name.as_str(), "router");
        assert_eq!(payload.function, "set_primary_name");
        // (domain: String "alice", subdomain: Option<String>::None)
        assert_eq!(payload.args.len(), 2);
        assert_eq!(
            payload.args[0],
            aptos_bcs::to_bytes(&"alice".to_string()).unwrap()
        );
        assert_eq!(
            payload.args[1],
            aptos_bcs::to_bytes(&Option::<String>::None).unwrap()
        );
    }

    #[test]
    fn set_target_address_payload_encodes_arguments() {
        let router = AccountAddress::from_hex("0x1").unwrap();
        let target = AccountAddress::from_hex("0xabc").unwrap();
        let fullnode = FullnodeClient::new(AptosConfig::mainnet()).unwrap();
        let ans = AnsClient::with_router_address(fullnode, router);

        let payload = ans
            .set_target_address_payload("wallet.alice.apt", target)
            .unwrap();
        assert_eq!(payload.function, "set_target_addr");
        // (domain "alice", subdomain Some("wallet"), address target)
        assert_eq!(payload.args.len(), 3);
        assert_eq!(
            payload.args[0],
            aptos_bcs::to_bytes(&"alice".to_string()).unwrap()
        );
        assert_eq!(
            payload.args[1],
            aptos_bcs::to_bytes(&Some("wallet".to_string())).unwrap()
        );
        assert_eq!(payload.args[2], aptos_bcs::to_bytes(&target).unwrap());
    }

    #[tokio::test]
    async fn register_domain_payload_rejects_subdomain() {
        let fullnode = FullnodeClient::new(AptosConfig::mainnet()).unwrap();
        let ans =
            AnsClient::with_router_address(fullnode, AccountAddress::from_hex("0x1").unwrap());
        let result = ans
            .register_domain_payload("wallet.alice.apt", 31_536_000, None, None)
            .await;
        assert!(matches!(result, Err(AptosError::Other(_))));
    }

    #[tokio::test]
    async fn register_domain_payload_encodes_arguments() {
        let router = AccountAddress::from_hex("0x1").unwrap();
        let target = AccountAddress::from_hex("0xabc").unwrap();
        let fullnode = FullnodeClient::new(AptosConfig::mainnet()).unwrap();
        let ans = AnsClient::with_router_address(fullnode, router);

        let payload = ans
            .register_domain_payload("alice.apt", 31_536_000, Some(target), None)
            .await
            .unwrap();
        assert_eq!(payload.function, "register_domain");
        // (domain "alice", duration u64, target Some(addr), to None)
        assert_eq!(payload.args.len(), 4);
        assert_eq!(
            payload.args[0],
            aptos_bcs::to_bytes(&"alice".to_string()).unwrap()
        );
        assert_eq!(
            payload.args[1],
            aptos_bcs::to_bytes(&31_536_000u64).unwrap()
        );
        assert_eq!(payload.args[2], aptos_bcs::to_bytes(&Some(target)).unwrap());
        assert_eq!(
            payload.args[3],
            aptos_bcs::to_bytes(&Option::<AccountAddress>::None).unwrap()
        );
    }

    #[test]
    fn clear_primary_name_payload_has_no_args() {
        let fullnode = FullnodeClient::new(AptosConfig::mainnet()).unwrap();
        let ans =
            AnsClient::with_router_address(fullnode, AccountAddress::from_hex("0x1").unwrap());
        let payload = ans.clear_primary_name_payload().unwrap();
        assert_eq!(payload.function, "clear_primary_name");
        assert!(payload.args.is_empty());
    }

    #[tokio::test]
    async fn get_owner_address_resolves() {
        let server = MockServer::start().await;
        let addr = "0x0000000000000000000000000000000000000000000000000000000000000abc";
        Mock::given(method("POST"))
            .and(path("/v1/view"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{"vec": [addr]}])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let ans = ans_for(&server);
        let owner = ans.get_owner_address("alice.apt").await.unwrap();
        assert_eq!(owner, Some(AccountAddress::from_hex(addr).unwrap()));
    }

    #[tokio::test]
    async fn lookup_resolves_to_target_address() {
        let server = MockServer::start().await;
        let addr = "0x0000000000000000000000000000000000000000000000000000000000000abc";
        Mock::given(method("POST"))
            .and(path("/v1/view"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{"vec": [addr]}])),
            )
            .mount(&server)
            .await;

        let ans = ans_for(&server);
        let resolved = ans.lookup("alice.apt").await.unwrap();
        assert_eq!(resolved, AccountAddress::from_hex(addr).unwrap());
    }

    #[tokio::test]
    async fn reverse_lookup_returns_primary_name() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/view"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"vec": []}, {"vec": ["alice"]}])),
            )
            .mount(&server)
            .await;

        let ans = ans_for(&server);
        let name = ans.reverse_lookup(AccountAddress::ONE).await.unwrap();
        assert_eq!(name, Some("alice".to_string()));
    }

    #[test]
    fn clear_target_address_payload_encodes_arguments() {
        let router = AccountAddress::from_hex("0x1").unwrap();
        let fullnode = FullnodeClient::new(AptosConfig::mainnet()).unwrap();
        let ans = AnsClient::with_router_address(fullnode, router);

        let payload = ans.clear_target_address_payload("alice.apt").unwrap();
        assert_eq!(payload.function, "clear_target_addr");
        // (domain "alice", subdomain Option<String>::None)
        assert_eq!(payload.args.len(), 2);
        assert_eq!(
            payload.args[0],
            aptos_bcs::to_bytes(&"alice".to_string()).unwrap()
        );
        assert_eq!(
            payload.args[1],
            aptos_bcs::to_bytes(&Option::<String>::None).unwrap()
        );
    }
}
