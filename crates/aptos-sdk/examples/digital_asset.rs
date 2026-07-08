//! Example: Digital Assets (NFTs) — create, mint, transfer
//!
//! This example demonstrates how to:
//! 1. Create a token collection (`0x4::aptos_token::create_collection`)
//! 2. Mint a digital asset into it (`0x4::aptos_token::mint`)
//! 3. Transfer the digital asset to another account
//!    (`Aptos::transfer_digital_asset`)
//!
//! The minted token's object address is read from the transaction's events.
//!
//! Run with: `cargo run --example digital_asset --features "ed25519,faucet"`

use aptos_sdk::transaction::{CollectionConfig, InputEntryFunctionData};
use aptos_sdk::types::AccountAddress;
use aptos_sdk::{Aptos, AptosConfig, account::Ed25519Account};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let aptos = Aptos::new(AptosConfig::devnet())?;
    println!("Connected to devnet");

    let creator = aptos.create_funded_account(100_000_000).await?;
    println!("Creator: {}", creator.address());

    let collection_name = "My Collection";

    // 1. Create the collection.
    println!("Creating collection...");
    let create = InputEntryFunctionData::create_collection(
        "An example collection",
        1000, // max supply
        collection_name,
        "https://example.com/collection",
        CollectionConfig::default(),
        0, // royalty numerator
        100,
    )?;
    aptos.sign_submit_and_wait(&creator, create, None).await?;

    // 2. Mint a token into the collection.
    println!("Minting a digital asset...");
    let mint = InputEntryFunctionData::mint_digital_asset(
        collection_name,
        "A one-of-a-kind token",
        "Token #1",
        "https://example.com/token/1",
        vec![],
        vec![],
        vec![],
    )?;
    let mint_result = aptos.sign_submit_and_wait(&creator, mint, None).await?;

    // The minted object address shows up as the `token` field of the mint event.
    let token_address = extract_minted_token_address(&mint_result.data)
        .ok_or_else(|| anyhow::anyhow!("could not find minted token address in events"))?;
    println!("Minted token object: {token_address}");

    // 3. Transfer the digital asset to a new owner.
    let recipient = Ed25519Account::generate();
    println!("Transferring token to {}...", recipient.address());
    aptos
        .transfer_digital_asset(&creator, token_address, recipient.address())
        .await?;
    println!("Digital asset transferred!");

    Ok(())
}

/// Scans a committed transaction's events for a minted token object address.
fn extract_minted_token_address(txn: &serde_json::Value) -> Option<AccountAddress> {
    let events = txn.get("events")?.as_array()?;
    for event in events {
        // The 0x4 mint event carries the new token object address under `token`.
        if let Some(token) = event
            .get("data")
            .and_then(|d| d.get("token"))
            .and_then(|t| t.as_str())
            && let Ok(addr) = AccountAddress::from_hex(token)
        {
            return Some(addr);
        }
    }
    None
}
