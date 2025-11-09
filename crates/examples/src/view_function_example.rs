use aptos_rust_sdk::client::builder::AptosClientBuilder;
use aptos_rust_sdk::client::config::AptosNetwork;
use aptos_rust_sdk_types::api_types::move_types::{MoveStructTag, MoveType};
use aptos_rust_sdk_types::api_types::view::ViewRequest;
use serde_json::Value;

/// Helper struct for view function operations
pub struct ViewFunctionHelper {
    client: aptos_rust_sdk::client::rest_api::AptosFullnodeClient,
}

impl ViewFunctionHelper {
    pub async fn new(network: AptosNetwork) -> Result<Self, anyhow::Error> {
        let builder = AptosClientBuilder::new(network, None);
        let client = builder.build().await?;
        Ok(Self { client: client })
    }

    /// Helper method to get account balance
    ///
    /// # Arguments
    /// * `address` - Account address
    /// * `coin_type` - Coin module name (e.g., "aptos_coin")
    /// * `coin_name` - Coin struct name (e.g., "AptosCoin")
    pub async fn get_balance(
        &self,
        address: &str,
        coin_type: &str,
        coin_name: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let request = ViewRequest {
            function: "0x1::coin::balance".to_string(),
            type_arguments: vec![MoveType::Struct(MoveStructTag {
                address: "0x1".to_string(),
                module: coin_type.to_string(),
                name: coin_name.to_string(),
                generic_type_params: vec![],
            })],
            arguments: vec![Value::String(address.to_string())],
        };

        let response = self.client.view_function(request).await?;
        Ok(response.into_inner())
    }

    /// Helper method to get account sequence number
    pub async fn get_sequence_number(
        &self,
        address: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let request = ViewRequest {
            function: "0x1::account::get_sequence_number".to_string(),
            type_arguments: vec![],
            arguments: vec![Value::String(address.to_string())],
        };

        let response = self.client.view_function(request).await?;
        Ok(response.into_inner())
    }

    /// Helper method to check if account exists
    pub async fn account_exists(&self, address: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let request = ViewRequest {
            function: "0x1::account::exists_at".to_string(),
            type_arguments: vec![],
            arguments: vec![Value::String(address.to_string())],
        };

        let response = self.client.view_function(request).await?;
        Ok(response.into_inner())
    }

    /// Helper method to get current timestamp
    pub async fn get_timestamp(&self) -> Result<Value, Box<dyn std::error::Error>> {
        let request = ViewRequest {
            function: "0x1::timestamp::now_seconds".to_string(),
            type_arguments: vec![],
            arguments: vec![],
        };

        let response = self.client.view_function(request).await?;
        Ok(response.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Setup test client
    async fn setup_client() -> aptos_rust_sdk::client::rest_api::AptosFullnodeClient {
        let builder = AptosClientBuilder::new(AptosNetwork::testnet(), None);
        builder.build().await.expect("Failed to create client")
    }

    #[tokio::test]
    async fn test_get_account_balance_success() {
        // This test should succeed - getting balance for a valid account
        let client = setup_client().await;
        let request = ViewRequest {
            function: "0x1::coin::balance".to_string(),
            type_arguments: vec![MoveType::Struct(MoveStructTag {
                address: "0x1".to_string(),
                module: "aptos_coin".to_string(),
                name: "AptosCoin".to_string(),
                generic_type_params: vec![],
            })],
            arguments: vec![Value::String("0x1".to_string())],
        };

        let result = client.view_function(request).await;
        assert!(result.is_ok(), "Getting account balance should succeed");

        let response = result.unwrap();
        let balance = response.into_inner();
        assert!(balance.is_array(), "Balance should be returned as an array");
    }

    #[tokio::test]
    async fn test_get_timestamp_success() {
        // This test should succeed - getting current timestamp
        let client = setup_client().await;
        let request = ViewRequest {
            function: "0x1::timestamp::now_seconds".to_string(),
            type_arguments: vec![],
            arguments: vec![],
        };

        let result = client.view_function(request).await;
        assert!(result.is_ok(), "Getting timestamp should succeed");

        let response = result.unwrap();
        let timestamp = response.into_inner();
        assert!(
            timestamp.is_array(),
            "Timestamp should be returned as an array"
        );
    }

    #[tokio::test]
    async fn test_get_sequence_number_success() {
        // This test should succeed - getting sequence number for a valid account
        let client = setup_client().await;
        let request = ViewRequest {
            function: "0x1::account::get_sequence_number".to_string(),
            type_arguments: vec![],
            arguments: vec![Value::String("0x1".to_string())],
        };

        let result = client.view_function(request).await;
        assert!(result.is_ok(), "Getting sequence number should succeed");

        let response = result.unwrap();
        let sequence = response.into_inner();
        assert!(
            sequence.is_array(),
            "Sequence number should be returned as an array"
        );
    }

    #[tokio::test]
    async fn test_account_exists_success() {
        // This test should succeed - checking if account exists
        let client = setup_client().await;
        let request = ViewRequest {
            function: "0x1::account::exists_at".to_string(),
            type_arguments: vec![],
            arguments: vec![Value::String("0x1".to_string())],
        };

        let result = client.view_function(request).await;
        assert!(result.is_ok(), "Checking account existence should succeed");

        let response = result.unwrap();
        let exists = response.into_inner();
        assert!(
            exists.is_array(),
            "Account existence should be returned as an array"
        );
    }

    #[tokio::test]
    async fn test_invalid_function_should_fail() {
        // This test should fail - calling a non-existent function
        let client = setup_client().await;
        let request = ViewRequest {
            function: "0x1::nonexistent::function".to_string(),
            type_arguments: vec![],
            arguments: vec![],
        };

        let result = client.view_function(request).await;
        assert!(result.is_err(), "Calling invalid function should fail");
    }

    #[tokio::test]
    async fn test_invalid_module_should_fail() {
        // This test should fail - calling function from non-existent module
        let client = setup_client().await;
        let request = ViewRequest {
            function: "0x1::invalid_module::some_function".to_string(),
            type_arguments: vec![],
            arguments: vec![],
        };

        let result = client.view_function(request).await;
        assert!(
            result.is_err(),
            "Calling function from invalid module should fail"
        );
    }

    #[tokio::test]
    async fn test_helper_get_balance_success() {
        // Test helper method - should succeed
        let helper = ViewFunctionHelper::new(AptosNetwork::testnet())
            .await
            .expect("Failed to create helper");

        let result = helper.get_balance("0x1", "aptos_coin", "AptosCoin").await;
        assert!(result.is_ok(), "Helper get_balance should succeed");
    }

    #[tokio::test]
    async fn test_helper_get_sequence_number_success() {
        // Test helper method - should succeed
        let helper = ViewFunctionHelper::new(AptosNetwork::testnet())
            .await
            .expect("Failed to create helper");

        let result = helper.get_sequence_number("0x1").await;
        assert!(result.is_ok(), "Helper get_sequence_number should succeed");
    }

    #[tokio::test]
    async fn test_helper_account_exists_success() {
        // Test helper method - should succeed
        let helper = ViewFunctionHelper::new(AptosNetwork::testnet())
            .await
            .expect("Failed to create helper");

        let result = helper.account_exists("0x1").await;
        assert!(result.is_ok(), "Helper account_exists should succeed");
    }

    #[tokio::test]
    async fn test_helper_get_timestamp_success() {
        // Test helper method - should succeed
        let helper = ViewFunctionHelper::new(AptosNetwork::testnet())
            .await
            .expect("Failed to create helper");

        let result = helper.get_timestamp().await;
        assert!(result.is_ok(), "Helper get_timestamp should succeed");
    }
}
