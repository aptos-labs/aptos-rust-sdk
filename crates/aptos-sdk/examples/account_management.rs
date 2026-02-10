//! Example: Account Management and Key Derivation
//!
//! This example demonstrates how to:
//! 1. Generate random accounts
//! 2. Create accounts from mnemonic phrases (BIP-39)
//! 3. Derive multiple accounts from a single mnemonic
//! 4. Load accounts from private keys
//!
//! Run with: `cargo run --example account_management --features "ed25519,secp256k1,mnemonic,faucet"`

use aptos_sdk::{
    Aptos, AptosConfig,
    account::{Ed25519Account, Secp256k1Account},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Account Management Example ===\n");

    // 1. Generate a random Ed25519 account
    println!("--- 1. Random Account Generation ---");
    let random_account = Ed25519Account::generate();
    println!("Random Ed25519 Account:");
    println!("  Address:     {}", random_account.address());
    println!("  Public Key:  {}", random_account.public_key());

    // 2. Generate different key types
    println!("\n--- 2. Different Key Types ---");

    let secp_account = Secp256k1Account::generate();
    println!("Random Secp256k1 Account:");
    println!("  Address:     {}", secp_account.address());
    println!("  Public Key:  {}", secp_account.public_key());

    // 3. Create account with mnemonic
    println!("\n--- 3. Mnemonic-Based Account ---");

    // Generate account with a new mnemonic
    let (mnemonic_account, mnemonic_phrase) = Ed25519Account::generate_with_mnemonic()?;
    println!("Generated 24-word mnemonic:");
    println!("  {}", mnemonic_phrase);
    println!("\n  ⚠️  IMPORTANT: Store this phrase securely!");
    println!("\nDerived Account (index 0):");
    println!("  Address: {}", mnemonic_account.address());

    // 4. Derive multiple accounts from same mnemonic
    println!("\n--- 4. Multiple Account Derivation ---");
    println!("Deriving accounts at different indices from the same mnemonic:\n");

    for i in 0..5 {
        let account = Ed25519Account::from_mnemonic(&mnemonic_phrase, i)?;
        println!("  Account {}: {}", i, account.address());
    }

    // 5. Load account from existing mnemonic
    println!("\n--- 5. Loading from Known Mnemonic ---");

    // Standard test mnemonic (DO NOT use for real funds!)
    let test_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    println!("Test mnemonic: {}", test_phrase);

    let test_account = Ed25519Account::from_mnemonic(test_phrase, 0)?;
    println!("Derived address: {}", test_account.address());
    println!("\n⚠️  This is a well-known test mnemonic. Never use it for real funds!");

    // 6. Load account from private key hex
    println!("\n--- 6. Loading from Private Key ---");

    // Get the private key bytes and convert to hex
    // WARNING: This prints the private key for demonstration purposes ONLY.
    // NEVER print, log, or expose private keys in production code!
    let pk_bytes = random_account.private_key().to_bytes();
    let pk_hex = hex::encode(pk_bytes);
    println!(
        "[DEMO ONLY - NEVER DO THIS IN PRODUCTION] Private key (hex): {}",
        pk_hex
    );

    // Recreate account from private key hex
    let restored_account = Ed25519Account::from_private_key_hex(&pk_hex)?;
    println!("Restored account address: {}", restored_account.address());

    // Verify they match
    assert_eq!(random_account.address(), restored_account.address());
    println!("✓ Addresses match! Account successfully restored from private key.");

    // 7. Demonstrate using an account on testnet
    println!("\n--- 7. Using an Account on Testnet ---");

    let config = AptosConfig::testnet();
    let aptos = Aptos::new(config)?;

    // Generate fresh account for testnet
    let testnet_account = Ed25519Account::generate();
    println!("New testnet account: {}", testnet_account.address());

    // Fund it
    println!("Funding account...");
    aptos
        .fund_account(testnet_account.address(), 100_000_000)
        .await?;

    // Wait for funding
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Check balance
    let balance = aptos.get_balance(testnet_account.address()).await?;
    println!("Balance: {} APT", balance as f64 / 100_000_000.0);

    // 8. Summary of key concepts
    println!("\n--- Key Concepts Summary ---");
    println!("• Ed25519: Fast, widely-used signature scheme (default for Aptos)");
    println!("• Secp256k1: Bitcoin/Ethereum compatible signatures");
    println!("• Mnemonic: Human-readable backup of your keys (BIP-39)");
    println!("• Index: Allows multiple accounts from one mnemonic");
    println!("• Private Key: The secret that controls your account");
    println!("• Public Key: Safely shareable, used to derive address");
    println!("• Address: Your account identifier on the blockchain");

    println!("\n=== Account Management Example Complete ===");

    Ok(())
}
