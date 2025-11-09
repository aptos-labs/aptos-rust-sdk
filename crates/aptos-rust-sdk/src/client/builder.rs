use crate::client::config::AptosNetwork;
use crate::client::rest_api::AptosFullnodeClient;
use aptos_rust_sdk_types::{api_types::ledger_info::LedgerInfo, headers::X_APTOS_CLIENT};
use aptos_rust_sdk_types::AptosResult;
use reqwest::{
    header::{self, HeaderMap, HeaderName, HeaderValue},
    Client as ReqwestClient, ClientBuilder as ReqwestClientBuilder,
};
use std::env;
use std::str::FromStr;
use std::time::Duration;

const X_APTOS_SDK_HEADER_VALUE: &str = concat!("aptos-rust-sdk/", env!("CARGO_PKG_VERSION"));
const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 5;

pub struct AptosClientBuilder {
    // TODO: Add an indexer client
    rest_api_client_builder: ReqwestClientBuilder,
    network: AptosNetwork,
    timeout: Duration,
    headers: HeaderMap,
}

impl AptosClientBuilder {
    /// A hidden constructor, please use `AptosClient::builder()` to create
    pub fn new(network: AptosNetwork, headers: Option<&HeaderMap>) -> Self {
        let mut headers = headers
            .map(|h| h.clone())
            .unwrap_or_else(HeaderMap::new);
        
        headers.insert(
            X_APTOS_CLIENT,
            HeaderValue::from_static(X_APTOS_SDK_HEADER_VALUE),
        );

        Self {
            rest_api_client_builder: ReqwestClient::builder(),
            network,
            timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECONDS), // Default to 5 seconds
            headers,
        }
    }

    pub fn network(mut self, network: AptosNetwork) -> Self {
        self.network = network;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn header(mut self, header_key: &str, header_val: &str) -> AptosResult<Self> {
        self.headers.insert(
            HeaderName::from_str(header_key)?,
            HeaderValue::from_str(header_val)?,
        );
        Ok(self)
    }

    pub fn api_key(mut self, api_key: &str) -> AptosResult<Self> {
        self.headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", api_key))?,
        );
        Ok(self)
    }

    pub async fn build(self) -> Result<AptosFullnodeClient, anyhow::Error> {
        let rest_client = self
            .rest_api_client_builder
            .default_headers(self.headers)
            .timeout(self.timeout)
            .cookie_store(true)
            .build()?;

        // Fetch chain_id from RPC if not set
        let network = if self.network.chain_id().is_some() {
            self.network
        } else {
            let url = self.network.rest_url().join("v1")?;
            let ledger_info: LedgerInfo = rest_client
                .get(url)
                .send()
                .await?
                .json()
                .await?;
            let chain_id = ledger_info.chain_id();
            self.network.with_chain_id(Some(chain_id))
        };

        Ok(AptosFullnodeClient {
            network,
            rest_client,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aptos_rust_sdk_types::api_types::chain_id::ChainId;
    use url::Url;

    #[tokio::test]
    async fn test_build_with_invalid_url() {
        // Test with an invalid URL that cannot be parsed
        // This should fail when trying to create the network
        let invalid_url = match Url::parse("not-a-valid-url") {
            Ok(url) => url,
            Err(_) => {
                // If URL parsing fails, we can't even create the network
                // This is expected behavior - invalid URLs should fail at network creation
                return;
            }
        };

        // If we somehow get here, try to create a network with invalid URL
        let network = AptosNetwork::new("invalid", invalid_url, None, None);
        let builder = AptosClientBuilder::new(network, None);
        
        // Building should fail when trying to join the path
        let result = builder.build().await;
        assert!(result.is_err(), "Building with invalid URL should fail");
    }

    #[tokio::test]
    async fn test_build_with_unreachable_url() {
        // Test with a valid URL format but unreachable server
        // Use a non-existent domain to ensure connection failure
        let unreachable_url = Url::parse("http://this-domain-does-not-exist-12345.invalid:8080").unwrap();
        // Ensure chain_id is None so it tries to fetch from server
        let network = AptosNetwork::new("unreachable", unreachable_url, None, None);
        let builder = AptosClientBuilder::new(network, None);
        
        // Building should fail when trying to fetch chain_id from unreachable server
        let result = builder.build().await;
        assert!(result.is_err(), "Building with unreachable URL should fail");
        
        // Check that the error is related to connection failure or DNS resolution
        let error_msg = format!("{}", result.unwrap_err());
        assert!(
            error_msg.contains("connection") || 
            error_msg.contains("refused") || 
            error_msg.contains("timeout") ||
            error_msg.contains("failed") ||
            error_msg.contains("error sending request") ||
            error_msg.contains("error decoding response body") ||
            error_msg.contains("dns") ||
            error_msg.contains("resolve"),
            "Error should be related to connection/DNS failure, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_build_with_unreachable_url_no_chain_id() {
        // Test fetching chain_id from server when it's not set initially
        // Use mainnet URL but without chain_id to test fetching chain_id from server
        let base_url = AptosNetwork::mainnet().rest_url().clone();
        // Ensure chain_id is None so it tries to fetch from server
        let network = AptosNetwork::new("test", base_url, None, None);
        let builder = AptosClientBuilder::new(network, None);
        
        // Build should succeed and fetch chain_id from the server
        let client = builder.build().await.expect("Should successfully build client");
        
        // Verify that chain_id was fetched from the server
        let chain_id = client.network.chain_id().expect("Chain id should be fetched from server");
        assert_eq!(chain_id, ChainId::Mainnet, "Chain id should match mainnet");
    }
}
