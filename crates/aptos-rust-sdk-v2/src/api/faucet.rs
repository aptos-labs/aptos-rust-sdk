//! Faucet client for funding accounts on testnets.

use crate::config::AptosConfig;
use crate::error::{AptosError, AptosResult};
use crate::retry::{RetryConfig, RetryExecutor};
use crate::types::AccountAddress;
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use url::Url;

/// Client for the Aptos faucet service.
///
/// The faucet is only available on devnet and testnet. Requests are
/// automatically retried with exponential backoff for transient failures.
///
/// # Example
///
/// ```rust,no_run
/// use aptos_rust_sdk_v2::api::FaucetClient;
/// use aptos_rust_sdk_v2::config::AptosConfig;
/// use aptos_rust_sdk_v2::types::AccountAddress;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let config = AptosConfig::testnet();
///     let client = FaucetClient::new(&config)?;
///     let address = AccountAddress::from_hex("0x123")?;
///     client.fund(address, 100_000_000).await?;
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct FaucetClient {
    faucet_url: Url,
    client: Client,
    retry_config: Arc<RetryConfig>,
}

/// Response from the faucet.
///
/// The faucet API can return different formats depending on version:
/// - Direct array: `["hash1", "hash2"]`
/// - Object: `{"txn_hashes": ["hash1", "hash2"]}`
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum FaucetResponse {
    /// Direct array of transaction hashes (localnet format).
    Direct(Vec<String>),
    /// Object with `txn_hashes` field (some older/alternative formats).
    Object { txn_hashes: Vec<String> },
}

impl FaucetResponse {
    pub(super) fn into_hashes(self) -> Vec<String> {
        match self {
            FaucetResponse::Direct(hashes) => hashes,
            FaucetResponse::Object { txn_hashes } => txn_hashes,
        }
    }
}

impl FaucetClient {
    /// Creates a new faucet client.
    ///
    /// # Errors
    ///
    /// Returns an error if the faucet URL is not configured in the config, or if the HTTP client
    /// fails to build (e.g., invalid TLS configuration).
    pub fn new(config: &AptosConfig) -> AptosResult<Self> {
        let faucet_url = config
            .faucet_url()
            .cloned()
            .ok_or_else(|| AptosError::Config("faucet URL not configured".into()))?;

        let pool = config.pool_config();

        let mut builder = Client::builder()
            .timeout(config.timeout)
            .pool_max_idle_per_host(pool.max_idle_per_host.unwrap_or(usize::MAX))
            .pool_idle_timeout(pool.idle_timeout)
            .tcp_nodelay(pool.tcp_nodelay);

        if let Some(keepalive) = pool.tcp_keepalive {
            builder = builder.tcp_keepalive(keepalive);
        }

        let client = builder.build().map_err(AptosError::Http)?;

        let retry_config = Arc::new(config.retry_config().clone());

        Ok(Self {
            faucet_url,
            client,
            retry_config,
        })
    }

    /// Creates a faucet client with a custom URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL cannot be parsed.
    pub fn with_url(url: &str) -> AptosResult<Self> {
        let faucet_url = Url::parse(url)?;
        let client = Client::new();
        Ok(Self {
            faucet_url,
            client,
            retry_config: Arc::new(RetryConfig::default()),
        })
    }

    /// Funds an account with the specified amount of octas.
    ///
    /// # Arguments
    ///
    /// * `address` - The account address to fund
    /// * `amount` - Amount in octas (1 APT = 10^8 octas)
    ///
    /// # Returns
    ///
    /// The transaction hashes of the funding transactions.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL cannot be built, the HTTP request fails, the API returns
    /// an error status code (e.g., rate limiting 429, server error 500), or the response
    /// cannot be parsed as JSON.
    pub async fn fund(&self, address: AccountAddress, amount: u64) -> AptosResult<Vec<String>> {
        let url = self.build_url(&format!("mint?address={address}&amount={amount}"))?;
        let client = self.client.clone();
        let retry_config = self.retry_config.clone();

        let executor = RetryExecutor::new((*retry_config).clone());
        executor
            .execute(|| {
                let client = client.clone();
                let url = url.clone();
                async move {
                    let response = client.post(url).send().await?;

                    if response.status().is_success() {
                        let faucet_response: FaucetResponse = response.json().await?;
                        Ok(faucet_response.into_hashes())
                    } else {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        Err(AptosError::api(status.as_u16(), body))
                    }
                }
            })
            .await
    }

    /// Funds an account with a default amount (usually 1 APT).
    ///
    /// # Errors
    ///
    /// Returns an error if the funding request fails (see [`fund`](Self::fund) for details).
    pub async fn fund_default(&self, address: AccountAddress) -> AptosResult<Vec<String>> {
        self.fund(address, 100_000_000).await // 1 APT
    }

    /// Creates an account and funds it.
    ///
    /// This is useful for quickly creating test accounts.
    ///
    /// # Errors
    ///
    /// Returns an error if the funding request fails (see [`fund`](Self::fund) for details).
    #[cfg(feature = "ed25519")]
    pub async fn create_and_fund(
        &self,
        amount: u64,
    ) -> AptosResult<(crate::account::Ed25519Account, Vec<String>)> {
        let account = crate::account::Ed25519Account::generate();
        let txn_hashes = self.fund(account.address(), amount).await?;
        Ok((account, txn_hashes))
    }

    fn build_url(&self, path: &str) -> AptosResult<Url> {
        let base = self.faucet_url.as_str().trim_end_matches('/');
        Url::parse(&format!("{base}/{path}")).map_err(AptosError::Url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path_regex},
    };

    #[test]
    fn test_faucet_client_creation() {
        let client = FaucetClient::new(&AptosConfig::testnet());
        assert!(client.is_ok());

        // Mainnet has no faucet
        let client = FaucetClient::new(&AptosConfig::mainnet());
        assert!(client.is_err());
    }

    async fn create_mock_faucet_client(server: &MockServer) -> FaucetClient {
        let config = AptosConfig::custom(&server.uri())
            .unwrap()
            .with_faucet_url(&server.uri())
            .unwrap()
            .without_retry();
        FaucetClient::new(&config).unwrap()
    }

    #[tokio::test]
    async fn test_fund_success() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"^/mint$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "txn_hashes": ["0xabc123", "0xdef456"]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_faucet_client(&server).await;
        let result = client.fund(AccountAddress::ONE, 100_000_000).await.unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "0xabc123");
    }

    #[tokio::test]
    async fn test_fund_success_direct_array() {
        // Test the direct array format used by localnet
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"^/mint$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!(["0xhash123", "0xhash456"])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_faucet_client(&server).await;
        let result = client.fund(AccountAddress::ONE, 100_000_000).await.unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "0xhash123");
        assert_eq!(result[1], "0xhash456");
    }

    #[tokio::test]
    async fn test_fund_default() {
        let server = MockServer::start().await;

        // Note: path_regex only matches the path, not query parameters
        Mock::given(method("POST"))
            .and(path_regex(r"^/mint$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "txn_hashes": ["0xfund123"]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_faucet_client(&server).await;
        let result = client.fund_default(AccountAddress::ONE).await.unwrap();

        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_fund_error() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"^/mint$"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Faucet error"))
            .expect(1)
            .mount(&server)
            .await;

        // Create client without retry to test error handling
        let config = AptosConfig::custom(&server.uri())
            .unwrap()
            .with_faucet_url(&server.uri())
            .unwrap()
            .without_retry();
        let client = FaucetClient::new(&config).unwrap();
        let result = client.fund(AccountAddress::ONE, 100_000_000).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fund_rate_limited() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"^/mint$"))
            .respond_with(ResponseTemplate::new(429).set_body_string("Too many requests"))
            .expect(1)
            .mount(&server)
            .await;

        let config = AptosConfig::custom(&server.uri())
            .unwrap()
            .with_faucet_url(&server.uri())
            .unwrap()
            .without_retry();
        let client = FaucetClient::new(&config).unwrap();
        let result = client.fund(AccountAddress::ONE, 100_000_000).await;

        assert!(result.is_err());
    }

    #[cfg(feature = "ed25519")]
    #[tokio::test]
    async fn test_create_and_fund() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"^/mint$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "txn_hashes": ["0xnewaccount"]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_faucet_client(&server).await;
        let (account, txn_hashes) = client.create_and_fund(100_000_000).await.unwrap();

        assert!(!account.address().is_zero());
        assert_eq!(txn_hashes.len(), 1);
    }

    #[test]
    fn test_build_url() {
        let config = AptosConfig::testnet();
        let client = FaucetClient::new(&config).unwrap();
        let url = client.build_url("mint?address=0x1&amount=1000").unwrap();
        assert!(url.as_str().contains("mint"));
        assert!(url.as_str().contains("address=0x1"));
    }
}
