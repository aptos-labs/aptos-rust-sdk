//! Example: Type-safe contract bindings using proc macros
//!
//! This example demonstrates how to use the `aptos_contract!` macro to generate
//! type-safe bindings for Move contracts at compile time.
//!
//! # Run with:
//! ```bash
//! cargo run --example contract_bindings --features "ed25519,macros"
//! ```

use aptos_sdk::{aptos_contract, types::AccountAddress};

// ANCHOR: define_contract
// Generate type-safe bindings from inline ABI
aptos_contract! {
    name: CoinModule,
    abi: r#"{
        "address": "0x1",
        "name": "coin",
        "exposed_functions": [
            {
                "name": "transfer",
                "visibility": "public",
                "is_entry": true,
                "is_view": false,
                "generic_type_params": [{"constraints": []}],
                "params": ["&signer", "address", "u64"],
                "return": []
            },
            {
                "name": "balance",
                "visibility": "public",
                "is_entry": false,
                "is_view": true,
                "generic_type_params": [{"constraints": []}],
                "params": ["address"],
                "return": ["u64"]
            }
        ],
        "structs": []
    }"#,
    // Optional: Include Move source for better parameter names
    source: r#"
        module 0x1::coin {
            /// Transfer coins from sender to recipient.
            public entry fun transfer<CoinType>(
                sender: &signer,
                to: address,
                amount: u64,
            ) { }

            /// Get the balance of an account.
            #[view]
            public fun balance<CoinType>(owner: address): u64 { 0 }
        }
    "#
}
// ANCHOR_END: define_contract

// ANCHOR: define_custom_contract
// A more complex example with custom token
aptos_contract! {
    name: MyToken,
    abi: r#"{
        "address": "0xcafe",
        "name": "my_token",
        "exposed_functions": [
            {
                "name": "mint",
                "visibility": "public",
                "is_entry": true,
                "is_view": false,
                "generic_type_params": [],
                "params": ["&signer", "address", "u64"],
                "return": []
            },
            {
                "name": "burn",
                "visibility": "public",
                "is_entry": true,
                "is_view": false,
                "generic_type_params": [],
                "params": ["&signer", "u64"],
                "return": []
            },
            {
                "name": "total_supply",
                "visibility": "public",
                "is_entry": false,
                "is_view": true,
                "generic_type_params": [],
                "params": [],
                "return": ["u64"]
            },
            {
                "name": "balance_of",
                "visibility": "public",
                "is_entry": false,
                "is_view": true,
                "generic_type_params": [],
                "params": ["address"],
                "return": ["u64"]
            }
        ],
        "structs": [
            {
                "name": "TokenInfo",
                "is_native": false,
                "abilities": ["key"],
                "generic_type_params": [],
                "fields": [
                    {"name": "name", "type": "0x1::string::String"},
                    {"name": "symbol", "type": "0x1::string::String"},
                    {"name": "decimals", "type": "u8"},
                    {"name": "total_supply", "type": "u64"}
                ]
            }
        ]
    }"#,
    source: r#"
        module 0xcafe::my_token {
            /// Mint new tokens to a recipient.
            public entry fun mint(
                admin: &signer,
                recipient: address,
                amount: u64,
            ) { }

            /// Burn tokens from sender's account.
            public entry fun burn(
                account: &signer,
                amount: u64,
            ) { }

            /// Get the total supply of tokens.
            #[view]
            public fun total_supply(): u64 { 0 }

            /// Get the balance of an address.
            #[view]
            public fun balance_of(owner: address): u64 { 0 }
        }
    "#
}
// ANCHOR_END: define_custom_contract

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Type-Safe Contract Bindings Example ===\n");

    // ANCHOR: use_contract
    // The macro generates a struct with instance methods and address override support
    // Create instances using the default address or a custom address
    let coin_module = CoinModule::new(); // Uses default address from ABI
    let my_token = MyToken::new();

    // You can also override the address for different deployments
    let _custom_deployment = MyToken::with_address("0xabcd1234");

    println!("CoinModule constants:");
    println!("  Default Address: {}", CoinModule::DEFAULT_ADDRESS);
    println!("  Effective Address: {}", coin_module.address());
    println!("  Module: {}", CoinModule::MODULE);

    println!("\nMyToken constants:");
    println!("  Default Address: {}", MyToken::DEFAULT_ADDRESS);
    println!("  Effective Address: {}", my_token.address());
    println!("  Module: {}", MyToken::MODULE);
    // ANCHOR_END: use_contract

    // ANCHOR: build_transaction
    // Build a transfer transaction payload
    let recipient = AccountAddress::from_hex("0x1234")?;
    let amount = 1_000_000u64;

    // With Move source, we get meaningful parameter names: `to`, `amount`
    // Methods are called on the instance, which uses the configured address
    let transfer_payload = coin_module.transfer(
        recipient, // to: address
        amount,    // amount: u64
        vec![],    // type_args (e.g., AptosCoin type)
    )?;

    println!("\nGenerated transfer payload: {:?}", transfer_payload);
    // ANCHOR_END: build_transaction

    // ANCHOR: custom_token_operations
    // Build custom token operations
    let mint_payload = my_token.mint(
        recipient, // recipient
        500_000,   // amount
    )?;
    println!("Generated mint payload: {:?}", mint_payload);

    let burn_payload = my_token.burn(
        100_000, // amount
    )?;
    println!("Generated burn payload: {:?}", burn_payload);
    // ANCHOR_END: custom_token_operations

    // ANCHOR: view_functions
    // View functions require an Aptos client (async)
    println!("\n--- View Function Demo (requires network) ---");
    println!("To call view functions, you need an Aptos client:");
    println!();
    println!("  let aptos = Aptos::new(AptosConfig::testnet())?;");
    println!("  let coin = CoinModule::new();");
    println!("  let balance = coin.view_balance(&aptos, owner, type_args).await?;");
    println!("  let supply = my_token.view_total_supply(&aptos).await?;");
    // ANCHOR_END: view_functions

    // ANCHOR: generated_structs
    // The macro also generates struct definitions
    println!("\n--- Generated Struct: TokenInfo ---");
    let token_info = TokenInfo {
        name: "My Token".to_string(),
        symbol: "MTK".to_string(),
        decimals: 8,
        total_supply: 1_000_000_000,
    };
    println!("TokenInfo: {:?}", token_info);
    // ANCHOR_END: generated_structs

    println!("\n=== Benefits of Type-Safe Bindings ===");
    println!("1. Compile-time type checking for arguments");
    println!("2. IDE autocomplete and documentation");
    println!("3. Meaningful parameter names from Move source");
    println!("4. No runtime ABI parsing overhead");
    println!("5. Generated structs for Move types");

    Ok(())
}
