//! Example: Orderless transaction (nonce-based replay protection)
//!
//! This example demonstrates how to:
//! 1. Create an Aptos client and fund a sender account
//! 2. Submit an **orderless** transaction with
//!    `Aptos::sign_submit_and_wait_orderless`
//!
//! Orderless transactions use a random replay-protection *nonce* instead of the
//! account's sequence number, so they can be submitted in any order (or
//! concurrently) within a short expiration window. On the wire this is an
//! ordinary transaction with `sequence_number = u64::MAX` carrying a
//! `TransactionPayload::Payload` whose extra config holds the nonce.
//!
//! Run with:
//! `cargo run --example orderless_transaction --features "ed25519,faucet"`

use aptos_sdk::{Aptos, AptosConfig, account::Ed25519Account, transaction::EntryFunction};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create client for devnet
    let aptos = Aptos::new(AptosConfig::devnet())?;
    println!("Connected to devnet");

    // Create and fund the sender
    let sender = aptos.create_funded_account(100_000_000).await?;
    println!("Sender: {}", sender.address());

    // Create a recipient
    let recipient = Ed25519Account::generate();
    println!("Recipient: {}", recipient.address());

    // Build an ordinary entry-function payload; the orderless helper wraps it in
    // the chain's `Payload` format and attaches a fresh random nonce (pass
    // `Some(nonce)` to reuse a specific one).
    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000_000)?;

    println!("Submitting orderless transfer...");
    let result = aptos
        .sign_submit_and_wait_orderless(&sender, payload.into(), None, None)
        .await?;

    let success = result
        .data
        .get("success")
        .and_then(serde_json::Value::as_bool);
    if success == Some(true) {
        println!("Orderless transaction successful!");
        let balance = aptos.get_balance(recipient.address()).await?;
        println!("Recipient balance: {balance} octas");
    } else {
        println!("Transaction failed: {:?}", result.data.get("vm_status"));
    }

    Ok(())
}
