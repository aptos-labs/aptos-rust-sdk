use crate::client::builder::AptosClientBuilder;
use crate::client::config::AptosNetwork;
use crate::client::response::{FullnodeResponse, ParsableResponse};
use aptos_rust_sdk_types::api_types::account::AccountResource;
use aptos_rust_sdk_types::api_types::transaction::SignedTransaction;
use aptos_rust_sdk_types::api_types::view::ViewRequest;
use aptos_rust_sdk_types::mime_types::{
    ACCEPT_BCS, BCS_SIGNED_TRANSACTION, BCS_VIEW_FUNCTION, JSON,
};
use aptos_rust_sdk_types::state::State;
use aptos_rust_sdk_types::AptosResult;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Client as ReqwestClient;
use serde::de::DeserializeOwned;
use url::Url;

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

    /// Estimate the gas price for a transaction
    pub async fn get_estimate_gas_price(&self) -> AptosResult<FullnodeResponse<serde_json::Value>> {
        let url = self.build_rest_path("v1/estimate_gas_price")?;
        self.rest_get(url).await
    }

    /// Account Resources
    pub async fn get_account_resources(
        &self,
        address: String,
    ) -> AptosResult<FullnodeResponse<Vec<AccountResource>>> {
        let url = self.build_rest_path(&format!("v1/accounts/{}/resources", address))?;
        self.rest_get(url).await
    }

    pub async fn get_account_balance(
        &self,
        address: String,
        asset_type: String,
    ) -> AptosResult<FullnodeResponse<serde_json::Value>> {
        let url =
            self.build_rest_path(&format!("v1/accounts/{}/balance/{}", address, asset_type))?;
        self.rest_get(url).await
    }

    /// submit a transaction to the network.  This is a blocking call and will wait for the
    pub async fn submit_transaction(
        &self,
        signed_transaction: SignedTransaction,
    ) -> AptosResult<FullnodeResponse<serde_json::Value>> {
        let url = self.build_rest_path("v1/transactions")?;
        let response = self
            .rest_client
            .post(url)
            .header(CONTENT_TYPE, BCS_SIGNED_TRANSACTION)
            .header(ACCEPT, JSON)
            .body(signed_transaction.to_vec())
            .send()
            .await?;

        let parsable_response = ParsableResponse(response);
        parsable_response.parse_response().await
    }

    /// simulate a transaction to the network.  This is a blocking call and will wait for the
    pub async fn simulate_transaction(
        &self,
        signed_transaction: SignedTransaction,
    ) -> AptosResult<FullnodeResponse<serde_json::Value>> {
        let url = self.build_rest_path("v1/transactions/simulate")?;
        let response = self
            .rest_client
            .post(url)
            .header(CONTENT_TYPE, BCS_SIGNED_TRANSACTION)
            .header(ACCEPT, JSON)
            .body(signed_transaction.to_vec())
            .send()
            .await?;

        let parsable_response = ParsableResponse(response);
        parsable_response.parse_response().await
    }

    pub async fn view_function(
        &self,
        view_request: ViewRequest,
    ) -> AptosResult<FullnodeResponse<serde_json::Value>> {
        let url = self.build_rest_path("v1/view")?;
        let response = self
            .rest_client
            .post(url)
            .header(CONTENT_TYPE, JSON)
            .header(ACCEPT, JSON)
            .body(serde_json::to_string(&view_request)?)
            .send()
            .await?;

        let parsable_response = ParsableResponse(response);
        parsable_response.parse_response().await
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

#[cfg(test)]
mod view_function_tests {
    use super::*;
    use aptos_rust_sdk_types::api_types::move_types::{MoveStructTag, MoveType};
    use serde_json::Value;

    #[tokio::test]
    async fn test_view_function_with_struct_type_argument() {
        let builder = AptosClientBuilder::new(AptosNetwork::testnet());
        let client = builder.build();

        // Test view function with struct type argument (this is supported)
        let view_request = ViewRequest {
            function: "0x1::coin::balance".to_string(),
            type_arguments: vec![MoveType::Struct(MoveStructTag {
                address: "0x1".to_string(),
                module: "aptos_coin".to_string(),
                name: "AptosCoin".to_string(),
                generic_type_params: vec![],
            })],
            arguments: vec![
                Value::String(
                    "0xcbed0130acb69de816dfe70e637116aeecde8f171441445d236f6b25665d62fa"
                        .to_string(),
                ), // Account address
            ],
        };

        let result = client.view_function(view_request).await;
        assert!(
            result.is_ok(),
            "View function call with struct type argument should succeed"
        );

        let response = result.unwrap();
        let balance = response.into_inner();
        let balance_value = serde_json::from_value::<Vec<String>>(balance).unwrap();
        assert!(
            balance_value.len() == 1,
            "Balance should be a vector with one element"
        );
    }

    #[tokio::test]
    async fn test_view_function_with_no_type_arguments() {
        let builder = AptosClientBuilder::new(AptosNetwork::testnet());
        let client = builder.build();

        // Test view function with no type arguments
        let view_request = ViewRequest {
            function: "0x1::timestamp::now_seconds".to_string(),
            type_arguments: vec![],
            arguments: vec![],
        };

        let result = client.view_function(view_request).await;
        assert!(
            result.is_ok(),
            "View function call with no type arguments should succeed"
        );

        let response = result.unwrap();
        let timestamp = response.into_inner();
        let timestamp_value = serde_json::from_value::<Vec<String>>(timestamp).unwrap();
        let timestamp_value_str = timestamp_value[0].clone();
        let timestamp_value_u64 = timestamp_value_str.parse::<u64>().unwrap();
        assert!(
            timestamp_value_u64 > 0,
            "Timestamp should be a positive number"
        );
    }

    #[tokio::test]
    async fn test_view_function_with_address_argument() {
        let builder = AptosClientBuilder::new(AptosNetwork::testnet());
        let client = builder.build();

        // Test view function with address argument
        let view_request = ViewRequest {
            function: "0x1::account::get_sequence_number".to_string(),
            type_arguments: vec![],
            arguments: vec![
                Value::String("0x1".to_string()), // Account address
            ],
        };

        let result = client.view_function(view_request).await;
        assert!(
            result.is_ok(),
            "View function call with address argument should succeed"
        );

        let response = result.unwrap();
        let sequence_number = response.into_inner();
        let sequence_number_value = serde_json::from_value::<Vec<String>>(sequence_number).unwrap();
        let sequence_number_value_str = sequence_number_value[0].clone();
        let sequence_number_value_u64 = sequence_number_value_str.parse::<u64>().unwrap();
        assert!(
            sequence_number_value_u64 == 0,
            "Sequence number should be 0"
        );
    }

    #[tokio::test]
    async fn test_view_function_with_account_exists_check() {
        let builder = AptosClientBuilder::new(AptosNetwork::testnet());
        let client = builder.build();

        // Test view function to check if account exists
        let view_request = ViewRequest {
            function: "0x1::account::exists_at".to_string(),
            type_arguments: vec![],
            arguments: vec![
                Value::String("0x1".to_string()), // Address as string
            ],
        };

        let result = client.view_function(view_request).await;
        assert!(
            result.is_ok(),
            "View function call to check account existence should succeed"
        );

        let response = result.unwrap();
        let exists = response.into_inner();
        assert!(exists.is_array(), "Exists should be an array");
    }

    #[tokio::test]
    async fn test_view_function_error_handling() {
        let builder = AptosClientBuilder::new(AptosNetwork::testnet());
        let client = builder.build();

        // Test with invalid function name
        let view_request = ViewRequest {
            function: "0x1::nonexistent::function".to_string(),
            type_arguments: vec![],
            arguments: vec![],
        };

        let result = client.view_function(view_request).await;
        assert!(result.is_err(), "Invalid function should return error");
    }

    // Note: The following types are NOT supported in view functions due to API limitations:
    // - MoveType::Vector (fails with Reference/GenericTypeParam conversion errors)
    // - MoveType::Bool, MoveType::U64, MoveType::Address as type arguments (not expected by functions)
    // - Functions with generic type parameters that resolve to references
    //
    // Only struct type arguments (like for coin::balance) and functions with no type arguments
    // are reliably supported in the current API implementation.
}
