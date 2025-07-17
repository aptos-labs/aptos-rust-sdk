use aptos_rust_sdk::client::builder::AptosClientBuilder;
use aptos_rust_sdk::client::config::AptosNetwork;
use aptos_rust_sdk_types::api_types::move_types::{MoveStructTag, MoveType};
use aptos_rust_sdk_types::api_types::view::ViewRequest;
use serde_json::Value;

/// Example demonstrating how to use the view_function method
/// to call read-only functions on the Aptos blockchain
pub async fn view_function_examples() {
    println!("=== View Function Examples ===\n");

    // Create a client for testnet
    let builder = AptosClientBuilder::new(AptosNetwork::testnet());
    let client = builder.build();

    // Example 1: Get account balance (with struct type argument)
    println!("1. Getting account balance...");
    let balance_request = ViewRequest {
        function: "0x1::coin::balance".to_string(),
        type_arguments: vec![MoveType::Struct(MoveStructTag {
            address: "0x1".to_string(),
            module: "aptos_coin".to_string(),
            name: "AptosCoin".to_string(),
            generic_type_params: vec![],
        })],
        arguments: vec![
            Value::String("0x1".to_string()), // Account address
        ],
    };

    match client.view_function(balance_request).await {
        Ok(response) => {
            let balance = response.into_inner();
            println!("   Balance: {:?}", balance);
        }
        Err(e) => {
            println!("   Error getting balance: {:?}", e);
        }
    }

    // Example 2: Get current timestamp (no type arguments)
    println!("\n2. Getting current timestamp...");
    let timestamp_request = ViewRequest {
        function: "0x1::timestamp::now_seconds".to_string(),
        type_arguments: vec![],
        arguments: vec![],
    };

    match client.view_function(timestamp_request).await {
        Ok(response) => {
            let timestamp = response.into_inner();
            println!("   Current timestamp: {:?}", timestamp);
        }
        Err(e) => {
            println!("   Error getting timestamp: {:?}", e);
        }
    }

    // Example 3: Get account sequence number (no type arguments)
    println!("\n3. Getting account sequence number...");
    let sequence_request = ViewRequest {
        function: "0x1::account::get_sequence_number".to_string(),
        type_arguments: vec![],
        arguments: vec![
            Value::String("0x1".to_string()), // Account address
        ],
    };

    match client.view_function(sequence_request).await {
        Ok(response) => {
            let sequence_number = response.into_inner();
            println!("   Sequence number: {:?}", sequence_number);
        }
        Err(e) => {
            println!("   Error getting sequence number: {:?}", e);
        }
    }

    // Example 4: Check if account exists (no type arguments)
    println!("\n4. Checking if account exists...");
    let exists_request = ViewRequest {
        function: "0x1::account::exists_at".to_string(),
        type_arguments: vec![],
        arguments: vec![
            Value::String("0x1".to_string()), // Account address
        ],
    };

    match client.view_function(exists_request).await {
        Ok(response) => {
            let exists = response.into_inner();
            println!("   Account exists: {:?}", exists);
        }
        Err(e) => {
            println!("   Error checking account existence: {:?}", e);
        }
    }

    // Example 5: Error handling - invalid function
    println!("\n5. Testing error handling with invalid function...");
    let invalid_request = ViewRequest {
        function: "0x1::nonexistent::function".to_string(),
        type_arguments: vec![],
        arguments: vec![],
    };

    match client.view_function(invalid_request).await {
        Ok(response) => {
            println!("   Unexpected success: {:?}", response);
        }
        Err(e) => {
            println!("   Expected error: {:?}", e);
        }
    }

    println!("\n=== View Function Examples Complete ===");
    println!(
        "\nNote: The following types are NOT supported in view functions due to API limitations:"
    );
    println!("- MoveType::Vector (fails with Reference/GenericTypeParam conversion errors)");
    println!("- MoveType::Bool, MoveType::U64, MoveType::Address as type arguments");
    println!("- Functions with generic type parameters that resolve to references");
    println!("\nOnly struct type arguments (like for coin::balance) and functions with no type arguments");
    println!("are reliably supported in the current API implementation.");
}

/// Example showing how to create a reusable view function helper
pub struct ViewFunctionHelper {
    client: aptos_rust_sdk::client::rest_api::AptosFullnodeClient,
}

impl ViewFunctionHelper {
    pub fn new(network: AptosNetwork) -> Self {
        let builder = AptosClientBuilder::new(network);
        let client = builder.build();
        Self { client }
    }

    /// Helper method to get account balance
    pub async fn get_balance(
        &self,
        address: &str,
        coin_type: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let request = ViewRequest {
            function: "0x1::coin::balance".to_string(),
            type_arguments: vec![MoveType::Struct(MoveStructTag {
                address: "0x1".to_string(),
                module: coin_type.to_string(),
                name: "Coin".to_string(),
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

/// Example demonstrating the helper usage
pub async fn view_function_helper_example() {
    println!("=== View Function Helper Example ===\n");

    let helper = ViewFunctionHelper::new(AptosNetwork::testnet());

    // Get balance
    match helper.get_balance("0x1", "aptos_coin").await {
        Ok(balance) => println!("Balance: {:?}", balance),
        Err(e) => println!("Error getting balance: {:?}", e),
    }

    // Get sequence number
    match helper.get_sequence_number("0x1").await {
        Ok(seq) => println!("Sequence number: {:?}", seq),
        Err(e) => println!("Error getting sequence number: {:?}", e),
    }

    // Check if account exists
    match helper.account_exists("0x1").await {
        Ok(exists) => println!("Account exists: {:?}", exists),
        Err(e) => println!("Error checking account existence: {:?}", e),
    }

    // Get current timestamp
    match helper.get_timestamp().await {
        Ok(timestamp) => println!("Current timestamp: {:?}", timestamp),
        Err(e) => println!("Error getting timestamp: {:?}", e),
    }

    println!("\n=== View Function Helper Example Complete ===");
}
