//! Network configuration for the Aptos SDK.
//!
//! This module provides configuration options for connecting to different
//! Aptos networks (mainnet, testnet, devnet) or custom endpoints.

use crate::retry::RetryConfig;
use crate::types::ChainId;
use std::time::Duration;
use url::Url;

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
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: None, // unlimited
            max_idle_total: 100,
            idle_timeout: Duration::from_secs(90),
            tcp_keepalive: Some(Duration::from_secs(60)),
            tcp_nodelay: true,
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
        }
    }
}

/// Builder for PoolConfig.
#[derive(Debug, Clone, Default)]
pub struct PoolConfigBuilder {
    max_idle_per_host: Option<Option<usize>>,
    max_idle_total: Option<usize>,
    idle_timeout: Option<Duration>,
    tcp_keepalive: Option<Option<Duration>>,
    tcp_nodelay: Option<bool>,
}

impl PoolConfigBuilder {
    /// Sets the maximum idle connections per host.
    pub fn max_idle_per_host(mut self, max: usize) -> Self {
        self.max_idle_per_host = Some(Some(max));
        self
    }

    /// Removes the limit on idle connections per host.
    pub fn unlimited_idle_per_host(mut self) -> Self {
        self.max_idle_per_host = Some(None);
        self
    }

    /// Sets the maximum total idle connections.
    pub fn max_idle_total(mut self, max: usize) -> Self {
        self.max_idle_total = Some(max);
        self
    }

    /// Sets the idle connection timeout.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = Some(timeout);
        self
    }

    /// Sets the TCP keepalive interval.
    pub fn tcp_keepalive(mut self, interval: Duration) -> Self {
        self.tcp_keepalive = Some(Some(interval));
        self
    }

    /// Disables TCP keepalive.
    pub fn no_tcp_keepalive(mut self) -> Self {
        self.tcp_keepalive = Some(None);
        self
    }

    /// Sets whether to enable TCP nodelay.
    pub fn tcp_nodelay(mut self, enabled: bool) -> Self {
        self.tcp_nodelay = Some(enabled);
        self
    }

    /// Builds the pool configuration.
    pub fn build(self) -> PoolConfig {
        let default = PoolConfig::default();
        PoolConfig {
            max_idle_per_host: self.max_idle_per_host.unwrap_or(default.max_idle_per_host),
            max_idle_total: self.max_idle_total.unwrap_or(default.max_idle_total),
            idle_timeout: self.idle_timeout.unwrap_or(default.idle_timeout),
            tcp_keepalive: self.tcp_keepalive.unwrap_or(default.tcp_keepalive),
            tcp_nodelay: self.tcp_nodelay.unwrap_or(default.tcp_nodelay),
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
/// use aptos_rust_sdk_v2::AptosConfig;
/// use aptos_rust_sdk_v2::retry::RetryConfig;
/// use aptos_rust_sdk_v2::config::PoolConfig;
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
    /// use aptos_rust_sdk_v2::AptosConfig;
    ///
    /// let config = AptosConfig::mainnet();
    /// ```
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
    /// use aptos_rust_sdk_v2::AptosConfig;
    ///
    /// let config = AptosConfig::testnet();
    /// ```
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
    /// use aptos_rust_sdk_v2::AptosConfig;
    ///
    /// let config = AptosConfig::devnet();
    /// ```
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
    /// use aptos_rust_sdk_v2::AptosConfig;
    ///
    /// let config = AptosConfig::local();
    /// ```
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
    /// # Example
    ///
    /// ```rust
    /// use aptos_rust_sdk_v2::AptosConfig;
    ///
    /// let config = AptosConfig::custom("https://my-node.example.com/v1").unwrap();
    /// ```
    pub fn custom(fullnode_url: &str) -> Result<Self, url::ParseError> {
        Ok(Self {
            network: Network::Custom,
            fullnode_url: Url::parse(fullnode_url)?,
            indexer_url: None,
            faucet_url: None,
            timeout: Duration::from_secs(30),
            retry_config: RetryConfig::default(),
            pool_config: PoolConfig::default(),
            api_key: None,
        })
    }

    /// Sets the request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the retry configuration for transient failures.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aptos_rust_sdk_v2::AptosConfig;
    /// use aptos_rust_sdk_v2::retry::RetryConfig;
    ///
    /// let config = AptosConfig::testnet()
    ///     .with_retry(RetryConfig::aggressive());
    /// ```
    pub fn with_retry(mut self, retry_config: RetryConfig) -> Self {
        self.retry_config = retry_config;
        self
    }

    /// Disables automatic retry for API calls.
    ///
    /// This is equivalent to `with_retry(RetryConfig::no_retry())`.
    pub fn without_retry(mut self) -> Self {
        self.retry_config = RetryConfig::no_retry();
        self
    }

    /// Sets the maximum number of retries for transient failures.
    ///
    /// This is a convenience method that modifies the retry config.
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
    /// use aptos_rust_sdk_v2::AptosConfig;
    /// use aptos_rust_sdk_v2::config::PoolConfig;
    ///
    /// let config = AptosConfig::testnet()
    ///     .with_pool(PoolConfig::high_throughput());
    /// ```
    pub fn with_pool(mut self, pool_config: PoolConfig) -> Self {
        self.pool_config = pool_config;
        self
    }

    /// Sets an API key for authenticated access.
    ///
    /// This is useful when using Aptos Build or other services that
    /// provide higher rate limits with API keys.
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Sets a custom indexer URL.
    pub fn with_indexer_url(mut self, url: &str) -> Result<Self, url::ParseError> {
        self.indexer_url = Some(Url::parse(url)?);
        Ok(self)
    }

    /// Sets a custom faucet URL.
    pub fn with_faucet_url(mut self, url: &str) -> Result<Self, url::ParseError> {
        self.faucet_url = Some(Url::parse(url)?);
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
    fn test_custom_config() {
        let config = AptosConfig::custom("https://custom.example.com/v1").unwrap();
        assert_eq!(config.network(), Network::Custom);
        assert_eq!(
            config.fullnode_url().as_str(),
            "https://custom.example.com/v1"
        );
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
        let config = AptosConfig::testnet()
            .with_retry(RetryConfig::aggressive());

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
    fn test_aptos_config_with_pool() {
        let config = AptosConfig::testnet()
            .with_pool(PoolConfig::high_throughput());

        assert_eq!(config.pool_config.max_idle_total, 256);
    }
}

