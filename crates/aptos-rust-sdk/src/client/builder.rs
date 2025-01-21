use crate::client::config::AptosNetwork;
use crate::client::rest_api::AptosFullnodeClient;
use reqwest::{
    header::{self, HeaderMap, HeaderName, HeaderValue},
    Client as ReqwestClient, ClientBuilder as ReqwestClientBuilder,
};
use std::env;
use std::str::FromStr;
use std::time::Duration;
use aptos_rust_sdk_types::AptosResult;
use aptos_rust_sdk_types::headers::X_APTOS_CLIENT;

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
    pub fn new(network: AptosNetwork) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            X_APTOS_CLIENT,
            HeaderValue::from_static(X_APTOS_SDK_HEADER_VALUE),
        );

        let mut client_builder = Self {
            rest_api_client_builder: ReqwestClient::builder(),
            network,
            timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECONDS), // Default to 5 seconds
            headers,
        };

        // TODO: This seems like a bit of a hack here and needs to be documented
        if let Ok(key) = env::var("X_API_KEY") {
            client_builder = client_builder.api_key(&key).unwrap();
        }
        client_builder
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

    pub fn build(self) -> AptosFullnodeClient {
        AptosFullnodeClient {
            network: self.network,
            rest_client: self
                .rest_api_client_builder
                .default_headers(self.headers)
                .timeout(self.timeout)
                .cookie_store(true)
                .build()
                .unwrap(),
        }
    }
}
