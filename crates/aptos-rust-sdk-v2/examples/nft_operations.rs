//! Example: NFT and Digital Asset operations
//!
//! This example demonstrates how to:
//! 1. Read NFT/token data from accounts
//! 2. Query collections and tokens via view functions
//! 3. Work with the Digital Assets (Token V2) standard
//!
//! Run with: `cargo run --example nft_operations --features "ed25519,indexer"`

use aptos_rust_sdk_v2::{Aptos, AptosConfig, types::AccountAddress};
use serde::Deserialize;

/// Token data from Token V2 standard
#[allow(dead_code)] // Shown for documentation purposes
#[derive(Debug, Deserialize)]
struct TokenData {
    name: String,
    description: String,
    uri: String,
}

/// Collection data
#[allow(dead_code)] // Shown for documentation purposes
#[derive(Debug, Deserialize)]
struct CollectionData {
    name: String,
    description: String,
    uri: String,
    #[serde(default)]
    current_supply: Option<String>,
    #[serde(default)]
    maximum_supply: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create client for mainnet
    let aptos = Aptos::new(AptosConfig::mainnet())?;
    println!("Connected to mainnet");

    // ==== Part 1: Query Token Objects ====
    println!("\n=== Part 1: Understanding Token V2 Structure ===");
    println!(
        "Token V2 (Digital Assets) uses object addresses. Each token is an object with resources."
    );
    println!("Key resource types:");
    println!("  - 0x4::token::Token (token metadata)");
    println!("  - 0x4::collection::Collection (collection metadata)");
    println!("  - 0x1::object::ObjectCore (object ownership)");

    // ==== Part 2: Read Token Using View Functions ====
    println!("\n=== Part 2: Query Token Info via View Functions ===");

    // Check if the token standard module exists
    let module_result = aptos
        .fullnode()
        .get_account_module(AccountAddress::FOUR, "token")
        .await;

    match module_result {
        Ok(module) => {
            if let Some(abi) = &module.data.abi {
                println!("Token module (0x4::token) functions:");

                let view_functions: Vec<_> = abi
                    .exposed_functions
                    .iter()
                    .filter(|f| f.is_view)
                    .take(10)
                    .collect();

                for func in view_functions {
                    println!("  - {} (params: {:?})", func.name, func.params);
                }
            }
        }
        Err(e) => {
            println!("Note: Token module query: {}", e);
        }
    }

    // ==== Part 3: Query Collection Info ====
    println!("\n=== Part 3: Collection Module Functions ===");

    let collection_module = aptos
        .fullnode()
        .get_account_module(AccountAddress::FOUR, "collection")
        .await;

    match collection_module {
        Ok(module) => {
            if let Some(abi) = &module.data.abi {
                println!("Collection module (0x4::collection) view functions:");

                let view_functions: Vec<_> = abi
                    .exposed_functions
                    .iter()
                    .filter(|f| f.is_view)
                    .take(10)
                    .collect();

                for func in view_functions {
                    println!("  - {}", func.name);
                }
            }
        }
        Err(e) => {
            println!("Note: Collection module query: {}", e);
        }
    }

    // ==== Part 4: Using the Indexer for NFT Queries ====
    #[cfg(feature = "indexer")]
    {
        println!("\n=== Part 4: Query NFTs via Indexer ===");

        if let Some(indexer) = aptos.indexer() {
            // Query a sample address for tokens (use a known NFT holder)
            // Note: This is a placeholder - replace with a real address that holds NFTs
            let sample_addr = AccountAddress::from_hex(
                "0x0000000000000000000000000000000000000000000000000000000000000001",
            )?;

            match indexer.get_account_tokens(sample_addr).await {
                Ok(tokens) => {
                    println!("Found {} tokens for address", tokens.len());
                    for token in tokens.iter().take(5) {
                        println!("  Token: {}", token.token_data_id);
                        if let Some(data) = &token.current_token_data {
                            println!("    Name: {}", data.token_name);
                            println!("    Description: {}", data.description);
                            if let Some(collection) = &data.current_collection {
                                println!("    Collection: {}", collection.collection_name);
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("Indexer query error: {}", e);
                }
            }

            // Query fungible asset balances
            match indexer.get_fungible_asset_balances(sample_addr).await {
                Ok(balances) => {
                    println!("\nFungible asset balances:");
                    for balance in balances.iter().take(5) {
                        let amount: u128 = balance.amount.parse().unwrap_or(0);
                        if let Some(metadata) = &balance.metadata {
                            println!(
                                "  {}: {} {}",
                                metadata.symbol,
                                amount as f64 / 10f64.powi(metadata.decimals as i32),
                                metadata.name
                            );
                        } else {
                            println!("  {}: {}", balance.asset_type, amount);
                        }
                    }
                }
                Err(e) => {
                    println!("Fungible asset query error: {}", e);
                }
            }
        } else {
            println!("Indexer not available");
        }
    }

    #[cfg(not(feature = "indexer"))]
    {
        println!("\n=== Part 4: Indexer Features ===");
        println!("Note: Enable 'indexer' feature for advanced NFT queries:");
        println!("  cargo run --example nft_operations --features \"ed25519,indexer\"");
    }

    // ==== Part 5: Query Object Ownership ====
    println!("\n=== Part 5: Object Model Overview ===");

    // Show object module functions
    let object_module = aptos
        .fullnode()
        .get_account_module(AccountAddress::ONE, "object")
        .await;

    match object_module {
        Ok(module) => {
            if let Some(abi) = &module.data.abi {
                println!("Object module (0x1::object) key functions:");

                let key_functions: Vec<_> = abi
                    .exposed_functions
                    .iter()
                    .filter(|f| {
                        f.name == "owner"
                            || f.name == "is_owner"
                            || f.name == "owns"
                            || f.name == "object_address"
                    })
                    .collect();

                for func in key_functions {
                    let func_type = if func.is_view {
                        "view"
                    } else if func.is_entry {
                        "entry"
                    } else {
                        "public"
                    };
                    println!("  - {} [{}]", func.name, func_type);
                }
            }
        }
        Err(e) => {
            println!("Object module query: {}", e);
        }
    }

    // ==== Part 6: Reading Primary Fungible Store ====
    println!("\n=== Part 6: Fungible Asset Standard ===");

    let fa_module = aptos
        .fullnode()
        .get_account_module(AccountAddress::ONE, "fungible_asset")
        .await;

    match fa_module {
        Ok(module) => {
            if let Some(abi) = &module.data.abi {
                println!("Fungible Asset module key view functions:");

                let view_functions: Vec<_> = abi
                    .exposed_functions
                    .iter()
                    .filter(|f| f.is_view)
                    .filter(|f| {
                        f.name.contains("balance")
                            || f.name.contains("supply")
                            || f.name.contains("name")
                            || f.name.contains("symbol")
                    })
                    .take(10)
                    .collect();

                for func in view_functions {
                    println!("  - {} -> {:?}", func.name, func.returns);
                }
            }
        }
        Err(e) => {
            println!("FA module query: {}", e);
        }
    }

    println!("\n✓ NFT operations examples completed!");
    println!("\nFor production NFT apps, consider:");
    println!("  1. Use the Indexer API for efficient queries");
    println!("  2. Cache collection/token metadata");
    println!("  3. Handle pagination for large collections");
    println!("  4. Subscribe to events for real-time updates");

    Ok(())
}
