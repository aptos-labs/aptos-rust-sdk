# View Function Examples and Tests

This directory contains comprehensive examples and tests for the `view_function` method in the Aptos Rust SDK.

## Overview

The `view_function` method allows you to call read-only functions on the Aptos blockchain without requiring a transaction. This is useful for querying account balances, checking account existence, getting timestamps, and other read-only operations.

## Files

### Examples
- `src/view_function_example.rs` - Comprehensive examples demonstrating various use cases
- `src/main.rs` - Binary to run the examples

### Tests
- `src/client/rest_api.rs` - Unit tests for the view_function method (in the `view_function_tests` module)

## Running Examples

To run the view function examples:

```bash
cargo run --bin view_function_example -p examples
```

This will execute various examples including:
1. Getting account balance (with struct type arguments)
2. Getting current timestamp (no type arguments)
3. Getting account sequence number (no type arguments)
4. Checking if account exists (no type arguments)
5. Error handling with invalid functions

## Running Tests

To run the view function tests:

```bash
cargo test view_function_tests --lib -p aptos-rust-sdk
```

## Example Usage

### Basic View Function Call

```rust
use aptos_rust_sdk::client::builder::AptosClientBuilder;
use aptos_rust_sdk::client::config::AptosNetwork;
use aptos_rust_sdk_types::api_types::view::ViewRequest;
use aptos_rust_sdk_types::api_types::move_types::{MoveStructTag, MoveType};
use serde_json::Value;

let builder = AptosClientBuilder::new(AptosNetwork::testnet());
let client = builder.build();

let view_request = ViewRequest {
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

let result = client.view_function(view_request).await;
match result {
    Ok(response) => {
        let balance = response.into_inner();
        println!("Balance: {:?}", balance);
    }
    Err(e) => {
        println!("Error: {:?}", e);
    }
}
```

### Helper Class

The examples also include a `ViewFunctionHelper` class that provides convenient methods for common operations:

```rust
let helper = ViewFunctionHelper::new(AptosNetwork::testnet());

// Get balance
let balance = helper.get_balance("0x1", "aptos_coin").await?;

// Get sequence number
let seq = helper.get_sequence_number("0x1").await?;

// Check if account exists
let exists = helper.account_exists("0x1").await?;

// Get current timestamp
let timestamp = helper.get_timestamp().await?;
```

## Supported View Functions

Here are the view functions that are currently supported:

| Function | Description | Type Arguments | Arguments |
|----------|-------------|----------------|-----------|
| `0x1::coin::balance` | Get account balance | `MoveType::Struct` | Account address, Coin type |
| `0x1::timestamp::now_seconds` | Get current timestamp | None | None |
| `0x1::account::get_sequence_number` | Get account sequence number | None | Account address |
| `0x1::account::exists_at` | Check if account exists | None | Account address |

## API Limitations

**Important**: The following types are NOT supported in view functions due to API limitations:

- `MoveType::Vector` (fails with Reference/GenericTypeParam conversion errors)
- `MoveType::Bool`, `MoveType::U64`, `MoveType::Address` as type arguments (not expected by functions)
- Functions with generic type parameters that resolve to references

**Only the following are reliably supported:**
- Struct type arguments (like for `coin::balance`)
- Functions with no type arguments

## Error Handling

The view function method returns a `Result` type, so always handle potential errors:

```rust
match client.view_function(request).await {
    Ok(response) => {
        // Handle successful response
        let data = response.into_inner();
        println!("Success: {:?}", data);
    }
    Err(e) => {
        // Handle error
        println!("Error: {:?}", e);
    }
}
```

## Testing

The tests cover the following working scenarios:
- View function calls with struct type arguments
- View function calls with no type arguments
- Address arguments
- Account existence checks
- Error handling with invalid functions

Run the tests to ensure the view function functionality works correctly with your setup.

## Notes

- View functions are read-only and don't require gas fees
- They don't modify blockchain state
- They're useful for querying data before making transactions
- Always use the correct type arguments for the function you're calling
- Handle errors appropriately in production code
- Be aware of API limitations when designing your view function calls 