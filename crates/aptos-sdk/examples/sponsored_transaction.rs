//! Example: Sponsored (fee payer) transaction
//!
//! This example demonstrates how to create a sponsored transaction
//! where a third party pays for the gas fees.
//!
//! Run with: `cargo run --example sponsored_transaction --features "ed25519,faucet"`

use aptos_sdk::{
    Aptos, AptosConfig,
    account::Ed25519Account,
    transaction::{
        EntryFunction, TransactionBuilder, builder::sign_fee_payer_transaction,
        types::FeePayerRawTransaction,
    },
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create client for testnet
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet");

    // Generate accounts
    let sender = Ed25519Account::generate();
    let recipient = Ed25519Account::generate();
    let fee_payer = Ed25519Account::generate();

    println!("Sender: {}", sender.address());
    println!("Recipient: {}", recipient.address());
    println!("Fee payer: {}", fee_payer.address());

    // Fund only the fee payer (sender doesn't need APT for gas!)
    println!("\nFunding fee payer account...");
    aptos.fund_account(fee_payer.address(), 100_000_000).await?;

    // Also fund sender with a small amount so they have something to transfer
    println!("Funding sender account...");
    aptos.fund_account(sender.address(), 10_000_000).await?;

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Check balances
    let sender_balance = aptos.get_balance(sender.address()).await?;
    let fee_payer_balance = aptos.get_balance(fee_payer.address()).await?;
    println!("\nInitial balances:");
    println!("  Sender: {} APT", sender_balance as f64 / 100_000_000.0);
    println!(
        "  Fee payer: {} APT",
        fee_payer_balance as f64 / 100_000_000.0
    );

    // Build the transaction payload
    let payload = EntryFunction::apt_transfer(recipient.address(), 5_000_000)?;

    // Get sequence number for sender
    let sequence_number = aptos.get_sequence_number(sender.address()).await?;

    // Build the raw transaction
    let raw_txn = TransactionBuilder::new()
        .sender(sender.address())
        .sequence_number(sequence_number)
        .payload(payload.into())
        .chain_id(aptos.chain_id())
        .expiration_from_now(600)
        .build()?;

    // Create a fee payer transaction
    let fee_payer_txn = FeePayerRawTransaction::new_simple(raw_txn, fee_payer.address());

    // Sign with both sender and fee payer
    let signed_txn = sign_fee_payer_transaction(
        &fee_payer_txn,
        &sender,
        &[], // No secondary signers
        &fee_payer,
    )?;

    // Submit the transaction
    println!("\nSubmitting sponsored transaction...");
    let result = aptos.submit_and_wait(&signed_txn, None).await?;

    let success = result.data.get("success").and_then(|v| v.as_bool());
    if success == Some(true) {
        println!("Transaction successful!");

        // Check final balances
        let sender_balance = aptos.get_balance(sender.address()).await?;
        let recipient_balance = aptos.get_balance(recipient.address()).await?;
        let fee_payer_balance = aptos.get_balance(fee_payer.address()).await?;

        println!("\nFinal balances:");
        println!("  Sender: {} APT", sender_balance as f64 / 100_000_000.0);
        println!(
            "  Recipient: {} APT",
            recipient_balance as f64 / 100_000_000.0
        );
        println!(
            "  Fee payer: {} APT (paid gas fees)",
            fee_payer_balance as f64 / 100_000_000.0
        );
    } else {
        let vm_status = result
            .data
            .get("vm_status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        println!("Transaction failed: {}", vm_status);
    }

    Ok(())
}
