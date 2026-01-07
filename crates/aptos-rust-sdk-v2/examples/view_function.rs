//! Example: Calling view functions
//!
//! This example demonstrates how to call view functions (read-only)
//! on the Aptos blockchain.
//!
//! Run with: `cargo run --example view_function --features ed25519`

use aptos_rust_sdk_v2::{Aptos, AptosConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create client for testnet
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet");

    // Get ledger info
    let ledger_info = aptos.ledger_info().await?;
    println!("Ledger version: {}", ledger_info.version());
    println!("Block height: {}", ledger_info.height());
    println!("Epoch: {}", ledger_info.epoch_num());
    println!();

    // Call timestamp view function
    println!("Calling 0x1::timestamp::now_seconds...");
    let result = aptos
        .view("0x1::timestamp::now_seconds", vec![], vec![])
        .await?;
    println!("Current timestamp: {:?}", result);
    println!();

    // Check if an account exists
    let framework_address = "0x1";
    println!("Checking if account 0x1 exists...");
    let result = aptos
        .view(
            "0x1::account::exists_at",
            vec![],
            vec![serde_json::json!(framework_address)],
        )
        .await?;
    println!("Account exists: {:?}", result);
    println!();

    // Get account sequence number
    println!("Getting sequence number for 0x1...");
    let result = aptos
        .view(
            "0x1::account::get_sequence_number",
            vec![],
            vec![serde_json::json!(framework_address)],
        )
        .await?;
    println!("Sequence number: {:?}", result);
    println!();

    // Get coin balance for an address
    let test_address = "0x1"; // Framework address
    println!("Getting APT balance for {}...", test_address);
    let result = aptos
        .view(
            "0x1::coin::balance",
            vec!["0x1::aptos_coin::AptosCoin".to_string()],
            vec![serde_json::json!(test_address)],
        )
        .await?;
    println!("Balance: {:?} octas", result);

    Ok(())
}

