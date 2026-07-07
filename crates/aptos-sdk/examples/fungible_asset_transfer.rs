//! Example: Fungible Asset (FA standard) transfer
//!
//! This example demonstrates how to:
//! 1. Create an Aptos client and fund a sender account
//! 2. Transfer a fungible asset with `Aptos::transfer_fungible_asset`
//!    (`0x1::primary_fungible_store::transfer`)
//!
//! It moves APT *as a fungible asset* (metadata object `0xa`), which every
//! funded account holds, so the example is self-contained. For a custom FA,
//! pass that asset's `Metadata` object address instead.
//!
//! Run with:
//! `cargo run --example fungible_asset_transfer --features "ed25519,faucet"`

use aptos_sdk::{Aptos, AptosConfig, account::Ed25519Account, types::AccountAddress};

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

    // The APT fungible-asset `Metadata` object lives at 0xa. Replace this with
    // your own asset's metadata address to transfer a different fungible asset.
    let apt_metadata = AccountAddress::from_hex("0xa")?;

    // Transfer 0.05 APT (5_000_000 octas) as a fungible asset.
    println!("Transferring 0.05 APT as a fungible asset...");
    let result = aptos
        .transfer_fungible_asset(&sender, apt_metadata, recipient.address(), 5_000_000)
        .await?;

    let success = result
        .data
        .get("success")
        .and_then(serde_json::Value::as_bool);
    if success == Some(true) {
        println!("Fungible asset transfer successful!");
        let balance = aptos.get_balance(recipient.address()).await?;
        println!("Recipient balance: {balance} octas");
    } else {
        println!("Transfer failed: {:?}", result.data.get("vm_status"));
    }

    Ok(())
}
