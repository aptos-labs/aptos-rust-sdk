//! Example: Rotating an account's authentication key
//!
//! This example demonstrates how to:
//! 1. Fund an account
//! 2. Rotate its authentication key to a brand-new key pair
//!    (`Aptos::rotate_auth_key`)
//! 3. Confirm the address is unchanged and the new key now controls it
//!
//! Rotation requires proving ownership of both the old and new keys (see
//! `RotationProofChallenge`); `rotate_auth_key` builds and signs that proof for
//! you.
//!
//! Run with: `cargo run --example rotate_auth_key --features "ed25519,faucet"`

use aptos_sdk::account::Ed25519Account;
use aptos_sdk::{Aptos, AptosConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let aptos = Aptos::new(AptosConfig::devnet())?;
    println!("Connected to devnet");

    // Fund an account under its original key.
    let account = aptos.create_funded_account(100_000_000).await?;
    let address = account.address();
    println!("Account: {address}");

    // Generate the key we want to rotate to. It must control `address` after the
    // rotation, so we rebuild it against the existing address below.
    let new_key = Ed25519Account::generate();
    println!("Rotating to a new key...");

    aptos.rotate_auth_key(&account, &new_key, None).await?;
    println!("Rotation committed. Address is unchanged: {address}");

    // After rotation, the *new* private key controls the *same* address. Build a
    // signer that pairs the new private key with the original address.
    let rotated =
        Ed25519Account::from_private_key(new_key.private_key().clone()).with_address(address);

    // Prove the new key works by sending a transaction from the account.
    let recipient = Ed25519Account::generate();
    println!("Sending a transfer signed by the new key...");
    let result = aptos
        .transfer_apt(&rotated, recipient.address(), 1_000_000)
        .await?;
    let success = result
        .data
        .get("success")
        .and_then(serde_json::Value::as_bool);
    println!(
        "Transfer with rotated key succeeded: {}",
        success == Some(true)
    );

    Ok(())
}
