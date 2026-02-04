//! Example: Indexer Queries
//!
//! This example demonstrates how to:
//! 1. Query fungible asset balances
//! 2. Get account tokens (NFTs)
//! 3. Fetch transaction history
//!
//! Run with: `cargo run --example indexer_queries --features "ed25519,indexer"`

use aptos_rust_sdk_v2::{Aptos, AptosConfig, api::PaginationParams, types::AccountAddress};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Indexer Queries Example ===\n");

    // Setup
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet");

    // Get the indexer client (requires "indexer" feature)
    let indexer = aptos.indexer().ok_or_else(|| {
        anyhow::anyhow!("Indexer not available. Make sure the 'indexer' feature is enabled.")
    })?;

    // Use a known address with activity (Aptos Framework)
    let known_address = AccountAddress::ONE; // 0x1
    println!("Querying data for address: {}", known_address);

    // 1. Get fungible asset balances
    println!("\n--- 1. Fungible Asset Balances ---");
    {
        match indexer.get_fungible_asset_balances(known_address).await {
            Ok(balances) => {
                println!("Found {} fungible asset balance(s):", balances.len());
                for (i, balance) in balances.iter().take(5).enumerate() {
                    println!("  {}. Asset: {}", i + 1, balance.asset_type);
                    println!("     Amount: {}", balance.amount);
                    if let Some(meta) = &balance.metadata {
                        println!("     Name: {} ({})", meta.name, meta.symbol);
                    }
                }
                if balances.len() > 5 {
                    println!("  ... and {} more", balances.len() - 5);
                }
            }
            Err(e) => println!("  Could not fetch balances: {}", e),
        }
    }

    // 2. Get account tokens (NFTs) with pagination
    println!("\n--- 2. Account Tokens (NFTs) ---");
    {
        let pagination = Some(PaginationParams {
            limit: 5,
            offset: 0,
        });

        match indexer
            .get_account_tokens_paginated(known_address, pagination)
            .await
        {
            Ok(page) => {
                let tokens = page.items;
                if tokens.is_empty() {
                    println!("  No tokens found for this address");
                } else {
                    println!("Found {} token(s):", tokens.len());
                    for (i, token) in tokens.iter().enumerate() {
                        println!("  {}. Token ID: {}", i + 1, token.token_data_id);
                        println!("     Amount: {}", token.amount);
                        if let Some(data) = &token.current_token_data {
                            println!("     Name: {}", data.token_name);
                            if let Some(collection) = &data.current_collection {
                                println!("     Collection: {}", collection.collection_name);
                            }
                        }
                    }
                }
            }
            Err(e) => println!("  Could not fetch tokens: {}", e),
        }
    }

    // 3. Get recent transactions
    println!("\n--- 3. Recent Transactions ---");
    {
        match indexer
            .get_account_transactions(known_address, Some(5))
            .await
        {
            Ok(transactions) => {
                println!("Recent {} transaction(s):", transactions.len());
                for (i, txn) in transactions.iter().enumerate() {
                    println!("  {}. Version: {}", i + 1, txn.transaction_version);
                    if !txn.coin_activities.is_empty() {
                        println!("     Coin activities: {}", txn.coin_activities.len());
                        for activity in txn.coin_activities.iter().take(2) {
                            let amount = activity.amount.as_deref().unwrap_or("N/A");
                            println!(
                                "       - {}: {} ({})",
                                activity.activity_type, amount, activity.coin_type
                            );
                        }
                    }
                }
            }
            Err(e) => println!("  Could not fetch transactions: {}", e),
        }
    }

    // 4. Custom GraphQL query
    println!("\n--- 4. Custom GraphQL Query ---");
    {
        // Custom query to get processor status
        let query = r#"
            query GetProcessorStatus {
                processor_status(limit: 3) {
                    processor
                    last_success_version
                }
            }
        "#;

        #[derive(Debug, serde::Deserialize)]
        struct ProcessorStatus {
            processor: String,
            last_success_version: i64,
        }

        #[derive(Debug, serde::Deserialize)]
        struct ProcessorStatusResponse {
            processor_status: Vec<ProcessorStatus>,
        }

        match indexer.query::<ProcessorStatusResponse>(query, None).await {
            Ok(response) => {
                println!("Processor status:");
                for status in response.processor_status.iter().take(3) {
                    println!(
                        "  {}: version {}",
                        status.processor, status.last_success_version
                    );
                }
            }
            Err(e) => println!("  Query failed: {}", e),
        }
    }

    println!("\n--- Summary ---");
    println!("The indexer provides fast access to:");
    println!("  • Fungible asset (FA) balances");
    println!("  • NFT/token ownership");
    println!("  • Transaction history with coin activities");
    println!("  • Custom GraphQL queries");

    println!("\n=== Indexer Queries Example Complete ===");

    Ok(())
}
