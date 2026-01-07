//! Example: Basic APT transfer
//!
//! This example demonstrates how to:
//! 1. Create an Aptos client
//! 2. Generate or load an account
//! 3. Fund the account using the faucet
//! 4. Transfer APT to another account
//!
//! Run with: `cargo run --example transfer --features "ed25519,faucet"`

use aptos_rust_sdk_v2::{
    account::Ed25519Account,
    Aptos, AptosConfig,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create client for testnet
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet");

    // Generate sender account
    let sender = Ed25519Account::generate();
    println!("Sender address: {}", sender.address());

    // Fund sender using faucet
    println!("Funding sender account...");
    aptos.fund_account(sender.address(), 100_000_000).await?;
    
    // Wait for funding to complete
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Check sender balance
    let balance = aptos.get_balance(sender.address()).await?;
    println!("Sender balance: {} APT", balance as f64 / 100_000_000.0);

    // Generate recipient account
    let recipient = Ed25519Account::generate();
    println!("Recipient address: {}", recipient.address());

    // Transfer 0.1 APT (10_000_000 octas)
    println!("Transferring 0.1 APT...");
    let result = aptos
        .transfer_apt(&sender, recipient.address(), 10_000_000)
        .await?;

    let success = result.data.get("success").and_then(|v| v.as_bool());
    if success == Some(true) {
        println!("Transfer successful!");
        
        // Check balances
        let sender_balance = aptos.get_balance(sender.address()).await?;
        let recipient_balance = aptos.get_balance(recipient.address()).await?;
        
        println!("Sender balance: {} APT", sender_balance as f64 / 100_000_000.0);
        println!("Recipient balance: {} APT", recipient_balance as f64 / 100_000_000.0);
    } else {
        let vm_status = result
            .data
            .get("vm_status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        println!("Transfer failed: {}", vm_status);
    }

    Ok(())
}

