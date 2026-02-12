//! Network configuration for the Aptos SDK.
//!
//! This module provides configuration options for connecting to different
//! Aptos networks (mainnet, testnet, devnet) or custom endpoints.

use crate::error::{AptosError, AptosResult};
use crate::retry::RetryConfig;
use crate::types::ChainId;
use std::time::Duration;
use url::Url;

/// Validates that a URL uses a safe scheme (http or https).
///
/// # Security
///
/// This prevents SSRF attacks via dangerous URL schemes like `file://`, `gopher://`, etc.
/// For production use, HTTPS is strongly recommended. HTTP is permitted (e.g., for local
/// development) but no host restrictions are enforced by this function.
///
/// # Errors
///
/// Returns [`AptosError::Config`] if the URL scheme is not `http` or `https`.
pub fn validate_url_scheme(url: &Url) -> AptosResult<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            // HTTP is allowed for local development and testing
            Ok(())
        }
        scheme => Err(AptosError::Config(format!(
            "unsupported URL scheme '{scheme}': only 'http' and 'https' are allowed"
        ))),
    }
}

/// Reads a response body with an enforced size limit, aborting early if exceeded.
///
/// Unlike `response.bytes().await?` which buffers the entire response in memory
/// before any size check, this function:
/// 1. Pre-checks the `Content-Length` header (if present) to reject obviously
///    oversized responses before reading any body data.
/// 2. Reads the body incrementally via chunked streaming, aborting as soon as
///    the accumulated size exceeds `max_size`.
///
/// This prevents memory exhaustion from malicious servers that send huge
/// responses (including chunked transfer-encoding without `Content-Length`).
///
/// # Errors
///
/// Returns [`AptosError::Api`] with error code `RESPONSE_TOO_LARGE` if the
/// response body exceeds `max_size` bytes.
pub async fn read_response_bounded(
    mut response: reqwest::Response,
    max_size: usize,
) -> AptosResult<Vec<u8>> {
    // Pre-check Content-Length header for early rejection (avoids reading any body)
    if let Some(content_length) = response.content_length()
        && content_length > max_size as u64
    {
        return Err(AptosError::Api {
            status_code: response.status().as_u16(),
            message: format!(
                "response too large: Content-Length {content_length} bytes exceeds limit of {max_size} bytes"
            ),
            error_code: Some("RESPONSE_TOO_LARGE".into()),
            vm_error_code: None,
        });
    }

    // Read body incrementally, aborting if accumulated size exceeds the limit.
    // This protects against chunked transfer-encoding that bypasses Content-Length.
    let mut body = Vec::with_capacity(std::cmp::min(max_size, 1024 * 1024));
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > max_size {
            return Err(AptosError::Api {
                status_code: response.status().as_u16(),
                message: format!(
                    "response too large: exceeded limit of {max_size} bytes during streaming"
                ),
                error_code: Some("RESPONSE_TOO_LARGE".into()),
                vm_error_code: None,
            });
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

/// Configuration for HTTP connection pooling.
///
/// Controls how connections are reused across requests for better performance.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of idle connections per host.
    /// Default: unlimited (no limit)
    pub max_idle_per_host: Option<usize>,
    /// Maximum total idle connections in the pool.
    /// Default: 100
    pub max_idle_total: usize,
    /// How long to keep idle connections alive.
    /// Default: 90 seconds
    pub idle_timeout: Duration,
    /// Whether to enable TCP keepalive.
    /// Default: true
    pub tcp_keepalive: Option<Duration>,
    /// Whether to enable TCP nodelay (disable Nagle's algorithm).
    /// Default: true
    pub tcp_nodelay: bool,
    /// Maximum response body size in bytes.
    /// Default: 10 MB (`10_485_760` bytes)
    ///
    /// # Security
    ///
    /// This limit helps prevent memory exhaustion from extremely large responses.
    /// The Aptos API responses are typically much smaller than this limit.
    pub max_response_size: usize,
}

/// Default maximum response size: 10 MB
///
/// # Security
///
/// This limit helps prevent memory exhaustion from malicious or compromised
/// servers sending extremely large responses. The default of 10 MB is generous
/// for normal Aptos API responses (typically under 1 MB). If you need to
/// handle larger responses (e.g., bulk data exports), increase this via
/// [`PoolConfigBuilder::max_response_size`].
const DEFAULT_MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: None, // unlimited
            max_idle_total: 100,
            idle_timeout: Duration::from_secs(90),
            tcp_keepalive: Some(Duration::from_secs(60)),
            tcp_nodelay: true,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
        }
    }
}

impl PoolConfig {
    /// Creates a new pool configuration builder.
    pub fn builder() -> PoolConfigBuilder {
        PoolConfigBuilder::default()
    }

    /// Creates a configuration optimized for high-throughput scenarios.
    ///
    /// - More idle connections
    /// - Longer idle timeout
    /// - TCP keepalive enabled
    pub fn high_throughput() -> Self {
        Self {
            max_idle_per_host: Some(32),
            max_idle_total: 256,
            idle_timeout: Duration::from_secs(300),
            tcp_keepalive: Some(Duration::from_secs(30)),
            tcp_nodelay: true,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
        }
    }

    /// Creates a configuration optimized for low-latency scenarios.
    ///
    /// - Fewer idle connections (fresher connections)
    /// - Shorter idle timeout
    /// - TCP nodelay enabled
    pub fn low_latency() -> Self {
        Self {
            max_idle_per_host: Some(8),
            max_idle_total: 32,
            idle_timeout: Duration::from_secs(30),
            tcp_keepalive: Some(Duration::from_secs(15)),
            tcp_nodelay: true,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
        }
    }

    /// Creates a minimal configuration for constrained environments.
    ///
    /// - Minimal idle connections
    /// - Short idle timeout
    pub fn minimal() -> Self {
        Self {
            max_idle_per_host: Some(2),
            max_idle_total: 8,
            idle_timeout: Duration::from_secs(10),
            tcp_keepalive: None,
            tcp_nodelay: true,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
        }
    }
}

/// Builder for `PoolConfig`.
#[derive(Debug, Clone, Default)]
#[allow(clippy::option_option)] // Intentional: distinguishes "not set" from "explicitly set to None"
pub struct PoolConfigBuilder {
    max_idle_per_host: Option<usize>,
    max_idle_total: Option<usize>,
    idle_timeout: Option<Duration>,
    /// None = not set (use default), Some(None) = explicitly disabled, Some(Some(d)) = explicitly set
    tcp_keepalive: Option<Option<Duration>>,
    tcp_nodelay: Option<bool>,
    max_response_size: Option<usize>,
}

impl PoolConfigBuilder {
    /// Sets the maximum idle connections per host.
    #[must_use]
    pub fn max_idle_per_host(mut self, max: usize) -> Self {
        self.max_idle_per_host = Some(max);
        self
    }

    /// Removes the limit on idle connections per host.
    #[must_use]
    pub fn unlimited_idle_per_host(mut self) -> Self {
        self.max_idle_per_host = None;
        self
    }

    /// Sets the maximum total idle connections.
    #[must_use]
    pub fn max_idle_total(mut self, max: usize) -> Self {
        self.max_idle_total = Some(max);
        self
    }

    /// Sets the idle connection timeout.
    #[must_use]
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = Some(timeout);
        self
    }

    /// Sets the TCP keepalive interval.
    #[must_use]
    pub fn tcp_keepalive(mut self, interval: Duration) -> Self {
        self.tcp_keepalive = Some(Some(interval));
        self
    }

    /// Disables TCP keepalive.
    #[must_use]
    pub fn no_tcp_keepalive(mut self) -> Self {
        self.tcp_keepalive = Some(None);
        self
    }

    /// Sets whether to enable TCP nodelay.
    #[must_use]
    pub fn tcp_nodelay(mut self, enabled: bool) -> Self {
        self.tcp_nodelay = Some(enabled);
        self
    }

    /// Sets the maximum response body size in bytes.
    ///
    /// # Security
    ///
    /// This helps prevent memory exhaustion from extremely large responses.
    #[must_use]
    pub fn max_response_size(mut self, size: usize) -> Self {
        self.max_response_size = Some(size);
        self
    }

    /// Builds the pool configuration.
    pub fn build(self) -> PoolConfig {
        let default = PoolConfig::default();
        PoolConfig {
            max_idle_per_host: self.max_idle_per_host.or(default.max_idle_per_host),
            max_idle_total: self.max_idle_total.unwrap_or(default.max_idle_total),
            idle_timeout: self.idle_timeout.unwrap_or(default.idle_timeout),
            tcp_keepalive: self.tcp_keepalive.unwrap_or(default.tcp_keepalive),
            tcp_nodelay: self.tcp_nodelay.unwrap_or(default.tcp_nodelay),
            max_response_size: self.max_response_size.unwrap_or(default.max_response_size),
        }
    }
}

/// Configuration for the Aptos client.
///
/// Use the builder methods to customize the configuration, or use one of the
/// preset configurations like [`AptosConfig::mainnet()`], [`AptosConfig::testnet()`],
/// or [`AptosConfig::devnet()`].
///
/// # Example
///
/// ```rust
/// use aptos_sdk::AptosConfig;
/// use aptos_sdk::retry::RetryConfig;
/// use aptos_sdk::config::PoolConfig;
///
/// // Use testnet with default settings
/// let config = AptosConfig::testnet();
///
/// // Custom configuration with retry and connection pooling
/// let config = AptosConfig::testnet()
///     .with_timeout(std::time::Duration::from_secs(30))
///     .with_retry(RetryConfig::aggressive())
///     .with_pool(PoolConfig::high_throughput());
/// ```
#[derive(Debug, Clone)]
pub struct AptosConfig {
    /// The network to connect to
    pub(crate) network: Network,
    /// REST API URL (fullnode)
    pub(crate) fullnode_url: Url,
    /// Indexer GraphQL URL (optional)
    pub(crate) indexer_url: Option<Url>,
    /// Faucet URL (optional, for testnets)
    pub(crate) faucet_url: Option<Url>,
    /// Request timeout
    pub(crate) timeout: Duration,
    /// Retry configuration for transient failures
    pub(crate) retry_config: RetryConfig,
    /// Connection pool configuration
    pub(crate) pool_config: PoolConfig,
    /// Optional API key for authenticated access
    pub(crate) api_key: Option<String>,
}

/// Known Aptos networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// Aptos mainnet
    Mainnet,
    /// Aptos testnet
    Testnet,
    /// Aptos devnet
    Devnet,
    /// Local development network
    Local,
    /// Custom network
    Custom,
}

impl Network {
    /// Returns the chain ID for this network.
    pub fn chain_id(&self) -> ChainId {
        match self {
            Network::Mainnet => ChainId::mainnet(),
            Network::Testnet => ChainId::testnet(),
            Network::Devnet => ChainId::new(165), // Devnet chain ID
            Network::Local => ChainId::new(4),    // Local testing chain ID
            Network::Custom => ChainId::new(0),   // Must be set manually
        }
    }

    /// Returns the network name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Devnet => "devnet",
            Network::Local => "local",
            Network::Custom => "custom",
        }
    }
}

impl Default for AptosConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl AptosConfig {
    /// Creates a configuration for Aptos mainnet.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aptos_sdk::AptosConfig;
    ///
    /// let config = AptosConfig::mainnet();
    /// ```
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn mainnet() -> Self {
        Self {
            network: Network::Mainnet,
            fullnode_url: Url::parse("https://fullnode.mainnet.aptoslabs.com/v1")
                .expect("valid mainnet URL"),
            indexer_url: Some(
                Url::parse("https://indexer.mainnet.aptoslabs.com/v1/graphql")
                    .expect("valid indexer URL"),
            ),
            faucet_url: None, // No faucet on mainnet
            timeout: Duration::from_secs(30),
            retry_config: RetryConfig::conservative(), // More conservative for mainnet
            pool_config: PoolConfig::default(),
            api_key: None,
        }
    }

    /// Creates a configuration for Aptos testnet.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aptos_sdk::AptosConfig;
    ///
    /// let config = AptosConfig::testnet();
    /// ```
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn testnet() -> Self {
        Self {
            network: Network::Testnet,
            fullnode_url: Url::parse("https://fullnode.testnet.aptoslabs.com/v1")
                .expect("valid testnet URL"),
            indexer_url: Some(
                Url::parse("https://indexer.testnet.aptoslabs.com/v1/graphql")
                    .expect("valid indexer URL"),
            ),
            faucet_url: Some(
                Url::parse("https://faucet.testnet.aptoslabs.com").expect("valid faucet URL"),
            ),
            timeout: Duration::from_secs(30),
            retry_config: RetryConfig::default(),
            pool_config: PoolConfig::default(),
            api_key: None,
        }
    }

    /// Creates a configuration for Aptos devnet.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aptos_sdk::AptosConfig;
    ///
    /// let config = AptosConfig::devnet();
    /// ```
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn devnet() -> Self {
        Self {
            network: Network::Devnet,
            fullnode_url: Url::parse("https://fullnode.devnet.aptoslabs.com/v1")
                .expect("valid devnet URL"),
            indexer_url: Some(
                Url::parse("https://indexer.devnet.aptoslabs.com/v1/graphql")
                    .expect("valid indexer URL"),
            ),
            faucet_url: Some(
                Url::parse("https://faucet.devnet.aptoslabs.com").expect("valid faucet URL"),
            ),
            timeout: Duration::from_secs(30),
            retry_config: RetryConfig::default(),
            pool_config: PoolConfig::default(),
            api_key: None,
        }
    }

    /// Creates a configuration for a local development network.
    ///
    /// This assumes the local network is running on the default ports
    /// (REST API on 8080, faucet on 8081).
    ///
    /// # Example
    ///
    /// ```rust
    /// use aptos_sdk::AptosConfig;
    ///
    /// let config = AptosConfig::local();
    /// ```
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn local() -> Self {
        Self {
            network: Network::Local,
            fullnode_url: Url::parse("http://127.0.0.1:8080/v1").expect("valid local URL"),
            indexer_url: None,
            faucet_url: Some(Url::parse("http://127.0.0.1:8081").expect("valid local faucet URL")),
            timeout: Duration::from_secs(10),
            retry_config: RetryConfig::aggressive(), // Fast retries for local dev
            pool_config: PoolConfig::low_latency(),  // Low latency for local dev
            api_key: None,
        }
    }

    /// Creates a custom configuration with the specified fullnode URL.
    ///
    /// # Security
    ///
    /// Only `http://` and `https://` URL schemes are allowed. Using `https://` is
    /// strongly recommended for production. HTTP is acceptable only for localhost
    /// development environments.
    ///
    /// # Errors
    ///
    /// Returns an error if the `fullnode_url` cannot be parsed as a valid URL
    /// or uses an unsupported scheme (e.g., `file://`, `ftp://`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use aptos_sdk::AptosConfig;
    ///
    /// let config = AptosConfig::custom("https://my-node.example.com/v1").unwrap();
    /// ```
    pub fn custom(fullnode_url: &str) -> AptosResult<Self> {
        let url = Url::parse(fullnode_url)?;
        validate_url_scheme(&url)?;
        Ok(Self {
            network: Network::Custom,
            fullnode_url: url,
            indexer_url: None,
            faucet_url: None,
            timeout: Duration::from_secs(30),
            retry_config: RetryConfig::default(),
            pool_config: PoolConfig::default(),
            api_key: None,
        })
    }

    /// Sets the request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the retry configuration for transient failures.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aptos_sdk::AptosConfig;
    /// use aptos_sdk::retry::RetryConfig;
    ///
    /// let config = AptosConfig::testnet()
    ///     .with_retry(RetryConfig::aggressive());
    /// ```
    #[must_use]
    pub fn with_retry(mut self, retry_config: RetryConfig) -> Self {
        self.retry_config = retry_config;
        self
    }

    /// Disables automatic retry for API calls.
    ///
    /// This is equivalent to `with_retry(RetryConfig::no_retry())`.
    #[must_use]
    pub fn without_retry(mut self) -> Self {
        self.retry_config = RetryConfig::no_retry();
        self
    }

    /// Sets the maximum number of retries for transient failures.
    ///
    /// This is a convenience method that modifies the retry config.
    #[must_use]
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.retry_config = RetryConfig::builder()
            .max_retries(max_retries)
            .initial_delay_ms(self.retry_config.initial_delay_ms)
            .max_delay_ms(self.retry_config.max_delay_ms)
            .exponential_base(self.retry_config.exponential_base)
            .jitter(self.retry_config.jitter)
            .build();
        self
    }

    /// Sets the connection pool configuration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aptos_sdk::AptosConfig;
    /// use aptos_sdk::config::PoolConfig;
    ///
    /// let config = AptosConfig::testnet()
    ///     .with_pool(PoolConfig::high_throughput());
    /// ```
    #[must_use]
    pub fn with_pool(mut self, pool_config: PoolConfig) -> Self {
        self.pool_config = pool_config;
        self
    }

    /// Sets an API key for authenticated access.
    ///
    /// This is useful when using Aptos Build or other services that
    /// provide higher rate limits with API keys.
    #[must_use]
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Sets a custom indexer URL.
    ///
    /// # Security
    ///
    /// Only `http://` and `https://` URL schemes are allowed.
    ///
    /// # Errors
    ///
    /// Returns an error if the `url` cannot be parsed as a valid URL
    /// or uses an unsupported scheme.
    pub fn with_indexer_url(mut self, url: &str) -> AptosResult<Self> {
        let parsed = Url::parse(url)?;
        validate_url_scheme(&parsed)?;
        self.indexer_url = Some(parsed);
        Ok(self)
    }

    /// Sets a custom faucet URL.
    ///
    /// # Security
    ///
    /// Only `http://` and `https://` URL schemes are allowed.
    ///
    /// # Errors
    ///
    /// Returns an error if the `url` cannot be parsed as a valid URL
    /// or uses an unsupported scheme.
    pub fn with_faucet_url(mut self, url: &str) -> AptosResult<Self> {
        let parsed = Url::parse(url)?;
        validate_url_scheme(&parsed)?;
        self.faucet_url = Some(parsed);
        Ok(self)
    }

    /// Returns the network this config is for.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Returns the fullnode URL.
    pub fn fullnode_url(&self) -> &Url {
        &self.fullnode_url
    }

    /// Returns the indexer URL, if configured.
    pub fn indexer_url(&self) -> Option<&Url> {
        self.indexer_url.as_ref()
    }

    /// Returns the faucet URL, if configured.
    pub fn faucet_url(&self) -> Option<&Url> {
        self.faucet_url.as_ref()
    }

    /// Returns the chain ID for this configuration.
    pub fn chain_id(&self) -> ChainId {
        self.network.chain_id()
    }

    /// Returns the retry configuration.
    pub fn retry_config(&self) -> &RetryConfig {
        &self.retry_config
    }

    /// Returns the request timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns the connection pool configuration.
    pub fn pool_config(&self) -> &PoolConfig {
        &self.pool_config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_config() {
        let config = AptosConfig::mainnet();
        assert_eq!(config.network(), Network::Mainnet);
        assert!(config.fullnode_url().as_str().contains("mainnet"));
        assert!(config.faucet_url().is_none());
    }

    #[test]
    fn test_testnet_config() {
        let config = AptosConfig::testnet();
        assert_eq!(config.network(), Network::Testnet);
        assert!(config.fullnode_url().as_str().contains("testnet"));
        assert!(config.faucet_url().is_some());
    }

    #[test]
    fn test_devnet_config() {
        let config = AptosConfig::devnet();
        assert_eq!(config.network(), Network::Devnet);
        assert!(config.fullnode_url().as_str().contains("devnet"));
        assert!(config.faucet_url().is_some());
        assert!(config.indexer_url().is_some());
    }

    #[test]
    fn test_local_config() {
        let config = AptosConfig::local();
        assert_eq!(config.network(), Network::Local);
        assert!(config.fullnode_url().as_str().contains("127.0.0.1"));
        assert!(config.faucet_url().is_some());
        assert!(config.indexer_url().is_none());
    }

    #[test]
    fn test_custom_config() {
        let config = AptosConfig::custom("https://custom.example.com/v1").unwrap();
        assert_eq!(config.network(), Network::Custom);
        assert_eq!(
            config.fullnode_url().as_str(),
            "https://custom.example.com/v1"
        );
    }

    #[test]
    fn test_custom_config_invalid_url() {
        let result = AptosConfig::custom("not a valid url");
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_methods() {
        let config = AptosConfig::testnet()
            .with_timeout(Duration::from_secs(60))
            .with_max_retries(5)
            .with_api_key("test-key");

        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.retry_config.max_retries, 5);
        assert_eq!(config.api_key, Some("test-key".to_string()));
    }

    #[test]
    fn test_retry_config() {
        let config = AptosConfig::testnet().with_retry(RetryConfig::aggressive());

        assert_eq!(config.retry_config.max_retries, 5);
        assert_eq!(config.retry_config.initial_delay_ms, 50);

        let config = AptosConfig::testnet().without_retry();
        assert_eq!(config.retry_config.max_retries, 0);
    }

    #[test]
    fn test_network_retry_defaults() {
        // Mainnet should be conservative
        let mainnet = AptosConfig::mainnet();
        assert_eq!(mainnet.retry_config.max_retries, 3);

        // Local should be aggressive
        let local = AptosConfig::local();
        assert_eq!(local.retry_config.max_retries, 5);
    }

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.max_idle_total, 100);
        assert_eq!(config.idle_timeout, Duration::from_secs(90));
        assert!(config.tcp_nodelay);
    }

    #[test]
    fn test_pool_config_presets() {
        let high = PoolConfig::high_throughput();
        assert_eq!(high.max_idle_per_host, Some(32));
        assert_eq!(high.max_idle_total, 256);

        let low = PoolConfig::low_latency();
        assert_eq!(low.max_idle_per_host, Some(8));
        assert_eq!(low.idle_timeout, Duration::from_secs(30));

        let minimal = PoolConfig::minimal();
        assert_eq!(minimal.max_idle_per_host, Some(2));
        assert_eq!(minimal.max_idle_total, 8);
    }

    #[test]
    fn test_pool_config_builder() {
        let config = PoolConfig::builder()
            .max_idle_per_host(16)
            .max_idle_total(64)
            .idle_timeout(Duration::from_secs(60))
            .tcp_nodelay(false)
            .build();

        assert_eq!(config.max_idle_per_host, Some(16));
        assert_eq!(config.max_idle_total, 64);
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
        assert!(!config.tcp_nodelay);
    }

    #[test]
    fn test_pool_config_builder_tcp_keepalive() {
        let config = PoolConfig::builder()
            .tcp_keepalive(Duration::from_secs(30))
            .build();
        assert_eq!(config.tcp_keepalive, Some(Duration::from_secs(30)));

        let config = PoolConfig::builder().no_tcp_keepalive().build();
        assert_eq!(config.tcp_keepalive, None);
    }

    #[test]
    fn test_pool_config_builder_unlimited_idle() {
        let config = PoolConfig::builder().unlimited_idle_per_host().build();
        assert_eq!(config.max_idle_per_host, None);
    }

    #[test]
    fn test_aptos_config_with_pool() {
        let config = AptosConfig::testnet().with_pool(PoolConfig::high_throughput());

        assert_eq!(config.pool_config.max_idle_total, 256);
    }

    #[test]
    fn test_aptos_config_with_indexer_url() {
        let config = AptosConfig::testnet()
            .with_indexer_url("https://custom-indexer.example.com/graphql")
            .unwrap();
        assert_eq!(
            config.indexer_url().unwrap().as_str(),
            "https://custom-indexer.example.com/graphql"
        );
    }

    #[test]
    fn test_aptos_config_with_faucet_url() {
        let config = AptosConfig::mainnet()
            .with_faucet_url("https://custom-faucet.example.com")
            .unwrap();
        assert_eq!(
            config.faucet_url().unwrap().as_str(),
            "https://custom-faucet.example.com/"
        );
    }

    #[test]
    fn test_aptos_config_default() {
        let config = AptosConfig::default();
        assert_eq!(config.network(), Network::Devnet);
    }

    #[test]
    fn test_network_chain_id() {
        assert_eq!(Network::Mainnet.chain_id().id(), 1);
        assert_eq!(Network::Testnet.chain_id().id(), 2);
        assert_eq!(Network::Devnet.chain_id().id(), 165);
        assert_eq!(Network::Local.chain_id().id(), 4);
        assert_eq!(Network::Custom.chain_id().id(), 0);
    }

    #[test]
    fn test_network_as_str() {
        assert_eq!(Network::Mainnet.as_str(), "mainnet");
        assert_eq!(Network::Testnet.as_str(), "testnet");
        assert_eq!(Network::Devnet.as_str(), "devnet");
        assert_eq!(Network::Local.as_str(), "local");
        assert_eq!(Network::Custom.as_str(), "custom");
    }

    #[test]
    fn test_aptos_config_getters() {
        let config = AptosConfig::testnet();

        assert_eq!(config.timeout(), Duration::from_secs(30));
        assert!(config.retry_config().max_retries > 0);
        assert!(config.pool_config().max_idle_total > 0);
        assert_eq!(config.chain_id().id(), 2);
    }

    #[tokio::test]
    async fn test_read_response_bounded_normal() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello world"))
            .mount(&server)
            .await;

        let response = reqwest::get(server.uri()).await.unwrap();
        let body = read_response_bounded(response, 1024).await.unwrap();
        assert_eq!(body, b"hello world");
    }

    #[tokio::test]
    async fn test_read_response_bounded_rejects_oversized_content_length() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        // Send a body whose accurate Content-Length exceeds the limit.
        // The function should reject based on Content-Length pre-check
        // before streaming the full body.
        let body = "x".repeat(200);
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let response = reqwest::get(server.uri()).await.unwrap();
        // Limit is 100 but body is 200 -- should be rejected via Content-Length pre-check
        let result = read_response_bounded(response, 100).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("response too large"));
    }

    #[tokio::test]
    async fn test_read_response_bounded_rejects_oversized_body() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        let large_body = "x".repeat(500);
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(large_body))
            .mount(&server)
            .await;

        let response = reqwest::get(server.uri()).await.unwrap();
        let result = read_response_bounded(response, 100).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_response_bounded_exact_limit() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        let body = "x".repeat(100);
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body.clone()))
            .mount(&server)
            .await;

        let response = reqwest::get(server.uri()).await.unwrap();
        let result = read_response_bounded(response, 100).await.unwrap();
        assert_eq!(result.len(), 100);
    }

    #[tokio::test]
    async fn test_read_response_bounded_empty() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let response = reqwest::get(server.uri()).await.unwrap();
        let result = read_response_bounded(response, 1024).await.unwrap();
        assert!(result.is_empty());
    }
}
