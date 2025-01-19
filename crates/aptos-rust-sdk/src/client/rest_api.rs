use crate::client::builder::AptosClientBuilder;
use crate::client::config::AptosNetwork;
use crate::client::response::{FullnodeResponse, ParsableResponse};
use reqwest::header::ACCEPT;
use reqwest::Client as ReqwestClient;
use serde::de::DeserializeOwned;
use url::Url;
use aptos_rust_sdk_types::AptosResult;
use aptos_rust_sdk_types::mime_types::{ACCEPT_BCS, JSON};
use aptos_rust_sdk_types::state::State;

/// The Aptos client used for interacting with the blockchain
#[derive(Debug, Clone)]
pub struct AptosFullnodeClient {
    /// The network associated with this client
    pub(crate) network: AptosNetwork,
    /// Underlying HTTP REST client
    pub(crate) rest_client: ReqwestClient,
}

impl AptosFullnodeClient {
    /// Create a builder for the `AptosClient`
    pub fn builder(network: AptosNetwork) -> AptosClientBuilder {
        AptosClientBuilder::new(network)
    }

    /// Retrieve the network information for the client
    pub fn network(&self) -> &AptosNetwork {
        &self.network
    }

    /// Retrieves the transaction by hash.  Note that pending transactions can only be retrieved by
    /// hash
    pub async fn get_transaction_by_hash(
        &self,
        hash: String,
    ) -> AptosResult<FullnodeResponse<String>> {
        let url = self.build_rest_path(&format!("v1/transactions/by_hash/{}", hash))?;
        self.rest_get(url).await
    }

    /// Retrieves the transaction by ledger version.  Note that transactions are always committed
    /// with a ledger version
    pub async fn get_transaction_by_version(
        &self,
        version: u64,
    ) -> AptosResult<FullnodeResponse<String>> {
        let url = self.build_rest_path(&format!("v1/transactions/by_version/{}", version))?;
        self.rest_get(url).await
    }

    /// Retrieve the blockchain state
    pub async fn get_state(&self) -> AptosResult<State> {
        let url = self.build_rest_path("v1")?;
        let response = self
            .rest_client
            .get(url)
            .header(ACCEPT, ACCEPT_BCS)
            .send()
            .await?;

        let parsable_response = ParsableResponse(response);
        Ok(parsable_response.state()?)
    }

    /// Private function that handles BCS underneath
    async fn rest_get<T: DeserializeOwned>(&self, url: Url) -> AptosResult<FullnodeResponse<T>> {
        let response = self
            .rest_client
            .get(url)
            .header(ACCEPT, JSON)
            .send()
            .await?;

        println!("{:?}", response);

        let parsable_response = ParsableResponse(response);
        parsable_response.parse_response().await
    }

    /// Helper function to build the REST path on the current URL
    fn build_rest_path(&self, path: &str) -> AptosResult<Url> {
        let out = self.network.rest_url().join(path)?;
        Ok(out)
    }
}
