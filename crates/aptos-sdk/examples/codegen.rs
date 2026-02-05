//! Example: Generate Rust bindings from Move module ABI
//!
//! This example demonstrates how to use the code generation feature to create
//! type-safe Rust bindings from Move module ABIs.
//!
//! # Run with:
//! ```bash
//! cargo run --example codegen --features ed25519
//! ```

use aptos_sdk::{
    api::response::{MoveFunction, MoveModuleABI, MoveStructDef, MoveStructField},
    codegen::{GeneratorConfig, ModuleGenerator, MoveSourceParser},
};

fn main() -> anyhow::Result<()> {
    // ANCHOR: create_abi
    // In practice, you would load this from a JSON file or fetch from chain
    let abi = MoveModuleABI {
        address: "0xcafe".to_string(),
        name: "my_token".to_string(),
        exposed_functions: vec![
            // An entry function for minting tokens
            MoveFunction {
                name: "mint".to_string(),
                visibility: "public".to_string(),
                is_entry: true,
                is_view: false,
                generic_type_params: vec![],
                params: vec![
                    "&signer".to_string(),
                    "address".to_string(),
                    "u64".to_string(),
                ],
                returns: vec![],
            },
            // An entry function for transferring tokens
            MoveFunction {
                name: "transfer".to_string(),
                visibility: "public".to_string(),
                is_entry: true,
                is_view: false,
                generic_type_params: vec![],
                params: vec![
                    "&signer".to_string(),
                    "address".to_string(),
                    "u64".to_string(),
                ],
                returns: vec![],
            },
            // A view function for getting balance
            MoveFunction {
                name: "balance".to_string(),
                visibility: "public".to_string(),
                is_entry: false,
                is_view: true,
                generic_type_params: vec![],
                params: vec!["address".to_string()],
                returns: vec!["u64".to_string()],
            },
            // A view function for getting total supply
            MoveFunction {
                name: "total_supply".to_string(),
                visibility: "public".to_string(),
                is_entry: false,
                is_view: true,
                generic_type_params: vec![],
                params: vec![],
                returns: vec!["u64".to_string()],
            },
        ],
        structs: vec![
            MoveStructDef {
                name: "TokenStore".to_string(),
                is_native: false,
                abilities: vec!["key".to_string()],
                generic_type_params: vec![],
                fields: vec![
                    MoveStructField {
                        name: "balance".to_string(),
                        typ: "u64".to_string(),
                    },
                    MoveStructField {
                        name: "owner".to_string(),
                        typ: "address".to_string(),
                    },
                ],
            },
            MoveStructDef {
                name: "TokenInfo".to_string(),
                is_native: false,
                abilities: vec!["key".to_string()],
                generic_type_params: vec![],
                fields: vec![
                    MoveStructField {
                        name: "name".to_string(),
                        typ: "0x1::string::String".to_string(),
                    },
                    MoveStructField {
                        name: "symbol".to_string(),
                        typ: "0x1::string::String".to_string(),
                    },
                    MoveStructField {
                        name: "decimals".to_string(),
                        typ: "u8".to_string(),
                    },
                    MoveStructField {
                        name: "total_supply".to_string(),
                        typ: "u64".to_string(),
                    },
                ],
            },
        ],
    };
    // ANCHOR_END: create_abi

    // ANCHOR: move_source
    // Move source provides parameter names and documentation
    let move_source = r#"
/// A token management module.
///
/// This module provides functionality for minting, transferring, 
/// and querying token balances.
module 0xcafe::my_token {
    use std::string::String;

    /// Stores token balance for an account.
    struct TokenStore has key {
        /// The current balance.
        balance: u64,
        /// The account that owns this store.
        owner: address,
    }

    /// Metadata about the token.
    struct TokenInfo has key {
        /// The human-readable name.
        name: String,
        /// The ticker symbol.
        symbol: String,
        /// Number of decimal places.
        decimals: u8,
        /// Total tokens in circulation.
        total_supply: u64,
    }

    /// Mints new tokens to a recipient.
    ///
    /// Only the admin can call this function.
    ///
    /// # Arguments
    /// * `admin` - The admin account authorized to mint
    /// * `recipient` - The address to receive the minted tokens
    /// * `amount` - The number of tokens to mint
    public entry fun mint(
        admin: &signer,
        recipient: address,
        amount: u64,
    ) {
        // implementation
    }

    /// Transfers tokens from the sender to a recipient.
    ///
    /// # Arguments
    /// * `sender` - The account sending tokens
    /// * `to` - The address to receive tokens
    /// * `amount` - The number of tokens to transfer
    public entry fun transfer(
        sender: &signer,
        to: address,
        amount: u64,
    ) {
        // implementation
    }

    /// Gets the token balance for an account.
    ///
    /// Returns 0 if the account has no TokenStore.
    #[view]
    public fun balance(owner: address): u64 {
        0
    }

    /// Gets the total supply of tokens.
    #[view]
    public fun total_supply(): u64 {
        0
    }
}
"#;

    // Parse the Move source
    let source_info = MoveSourceParser::parse(move_source);
    println!("Parsed Move source:");
    println!(
        "  - Functions: {:?}",
        source_info.functions.keys().collect::<Vec<_>>()
    );
    println!(
        "  - Structs: {:?}",
        source_info.structs.keys().collect::<Vec<_>>()
    );
    // ANCHOR_END: move_source

    // ANCHOR: generate_without_source
    // Generate without source info (uses generic names)
    println!("\n=== Generated WITHOUT Move Source ===\n");
    let config = GeneratorConfig::new()
        .with_entry_functions(true)
        .with_view_functions(true)
        .with_structs(false); // Skip structs for brevity

    let generator = ModuleGenerator::new(&abi, config.clone());
    let code_without_source = generator.generate()?;

    // Show just the transfer function
    for line in code_without_source.lines() {
        if line.contains("pub fn transfer")
            || line.contains("/// Entry function: `my_token::transfer`")
        {
            println!("{}", line);
        }
    }
    // ANCHOR_END: generate_without_source

    // ANCHOR: generate_with_source
    // Generate WITH source info (uses real parameter names and docs)
    println!("\n=== Generated WITH Move Source ===\n");
    let generator_with_source = ModuleGenerator::new(&abi, config).with_source_info(source_info);
    let code_with_source = generator_with_source.generate()?;

    // Show the transfer function with proper names
    let mut in_transfer = false;
    for line in code_with_source.lines() {
        if line.contains("/// Transfers tokens") {
            in_transfer = true;
        }
        if in_transfer {
            println!("{}", line);
            if line.starts_with("pub fn transfer") {
                break;
            }
        }
    }
    // ANCHOR_END: generate_with_source

    println!("\n=== Full Generated Code (with source) ===\n");

    // Generate full code with structs
    let full_config = GeneratorConfig::new()
        .with_entry_functions(true)
        .with_view_functions(true)
        .with_structs(true);

    let full_source_info = MoveSourceParser::parse(move_source);
    let full_generator = ModuleGenerator::new(&abi, full_config).with_source_info(full_source_info);
    let full_code = full_generator.generate()?;

    println!("{}", full_code);

    // ANCHOR: usage_example
    // The generated code can be used like this:
    //
    // ```rust
    // // Import the generated module
    // mod my_token;
    //
    // use aptos_sdk::{Aptos, AptosConfig};
    // use my_token::*;
    //
    // async fn example() -> anyhow::Result<()> {
    //     let aptos = Aptos::new(AptosConfig::testnet())?;
    //     let account = aptos.account().create_ed25519()?;
    //
    //     // Use generated entry function with meaningful parameter names
    //     let payload = mint(recipient_address, 1000)?;
    //     aptos.sign_submit_and_wait(&account, payload, None).await?;
    //
    //     // Use generated view function with proper parameter name
    //     let balance = view_balance(&aptos, owner_address).await?;
    //     println!("Balance: {:?}", balance);
    //
    //     Ok(())
    // }
    // ```
    // ANCHOR_END: usage_example

    println!("\n=== CLI Usage ===\n");
    println!("# Generate from ABI file only:");
    println!("aptos-codegen --input abi.json --output src/generated/");
    println!();
    println!("# Generate with Move source for better names:");
    println!("aptos-codegen --input abi.json --source my_token.move --output src/generated/");
    println!();
    println!("# Fetch from chain and generate:");
    println!("aptos-codegen --module 0x1::coin --network testnet --output src/generated/");

    Ok(())
}
