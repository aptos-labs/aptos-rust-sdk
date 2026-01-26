//! Example: Multi-signature (M-of-N) accounts
//!
//! This example demonstrates how to:
//! 1. Create a multi-Ed25519 account (M-of-N threshold)
//! 2. Sign with multiple keys
//! 3. Aggregate signatures from multiple parties
//! 4. Submit multi-sig transactions
//!
//! Run with: `cargo run --example multi_sig_account --features "ed25519,faucet"`

use aptos_rust_sdk_v2::{
    Aptos, AptosConfig,
    account::MultiEd25519Account,
    crypto::Ed25519PrivateKey,
    transaction::{EntryFunction, TransactionBuilder, TransactionPayload},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Multi-Signature Account Example ===\n");

    // Connect to testnet
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet (chain_id: {})", aptos.chain_id().id());

    // ==== Part 1: Creating a 2-of-3 Multi-Sig Account ====
    println!("\n--- Part 1: Create 2-of-3 Multi-Sig Account ---");

    // Generate 3 keys for our multi-sig
    let key1 = Ed25519PrivateKey::generate();
    let key2 = Ed25519PrivateKey::generate();
    let key3 = Ed25519PrivateKey::generate();

    println!("Generated 3 Ed25519 keys:");
    println!("  Key 1: {}", key1.public_key());
    println!("  Key 2: {}", key2.public_key());
    println!("  Key 3: {}", key3.public_key());

    // Create a multi-sig account where we own all keys (2-of-3)
    let multi_account = MultiEd25519Account::new(
        vec![key1.clone(), key2.clone(), key3.clone()],
        2, // Threshold: 2 signatures required
    )?;

    println!("\nMulti-sig account created:");
    println!("  Address: {}", multi_account.address());
    println!(
        "  Threshold: {}-of-{}",
        multi_account.threshold(),
        multi_account.num_keys()
    );
    println!("  Can sign: {}", multi_account.can_sign());

    // ==== Part 2: Funding and Using the Multi-Sig ====
    println!("\n--- Part 2: Fund Multi-Sig Account ---");

    // Fund the multi-sig account
    aptos
        .fund_account(multi_account.address(), 100_000_000)
        .await?;
    println!("Funded multi-sig account with 1 APT");

    // Wait for funding
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Check balance
    let balance = aptos.get_balance(multi_account.address()).await?;
    println!("Balance: {} APT", balance as f64 / 100_000_000.0);

    // ==== Part 3: Signing with Multi-Sig ====
    println!("\n--- Part 3: Sign and Submit Transaction ---");

    // Create a simple transfer
    let recipient = Ed25519PrivateKey::generate().public_key().to_address();
    let payload = EntryFunction::apt_transfer(recipient, 1_000_000)?;

    // Get sequence number and build transaction
    let seq_num = aptos.get_sequence_number(multi_account.address()).await?;

    let raw_txn = TransactionBuilder::new()
        .sender(multi_account.address())
        .sequence_number(seq_num)
        .payload(TransactionPayload::EntryFunction(payload))
        .chain_id(aptos.chain_id())
        .build()?;

    // Create signed transaction (signs with the multi-sig account using threshold keys automatically)
    let signed =
        aptos_rust_sdk_v2::transaction::builder::sign_transaction(&raw_txn, &multi_account)?;

    println!(
        "Signed with threshold {}-of-{}",
        multi_account.threshold(),
        multi_account.num_keys()
    );

    // Submit and wait
    let result = aptos.submit_and_wait(&signed, None).await?;
    let success = result.data.get("success").and_then(|v| v.as_bool());
    println!("Transaction success: {:?}", success);

    // ==== Part 4: Distributed Signing (Multiple Parties) ====
    println!("\n--- Part 4: Distributed Signing Scenario ---");

    // In a real scenario, each party would have only their key.
    // Let's simulate this:

    let pub_keys = vec![key1.public_key(), key2.public_key(), key3.public_key()];

    // Party 1 only has key1
    let party1 = MultiEd25519Account::from_keys(pub_keys.clone(), vec![(0, key1.clone())], 2)?;
    println!("Party 1: owns key index 0, can_sign={}", party1.can_sign());

    // Party 2 only has key2
    let party2 = MultiEd25519Account::from_keys(pub_keys.clone(), vec![(1, key2.clone())], 2)?;
    println!("Party 2: owns key index 1, can_sign={}", party2.can_sign());

    // Party 3 only has key3
    let party3 = MultiEd25519Account::from_keys(pub_keys.clone(), vec![(2, key3.clone())], 2)?;
    println!("Party 3: owns key index 2, can_sign={}", party3.can_sign());

    // Create another transaction for distributed signing demo
    let payload2 = EntryFunction::apt_transfer(recipient, 500_000)?;
    let seq_num2 = aptos.get_sequence_number(multi_account.address()).await?;

    let raw_txn2 = TransactionBuilder::new()
        .sender(multi_account.address())
        .sequence_number(seq_num2)
        .payload(TransactionPayload::EntryFunction(payload2))
        .chain_id(aptos.chain_id())
        .build()?;

    let message = raw_txn2.signing_message()?;

    // Each party creates their signature contribution
    let contrib1 = party1.create_signature_contribution(&message, 0)?;
    println!("Party 1 signed at index {}", contrib1.0);

    let contrib3 = party3.create_signature_contribution(&message, 2)?;
    println!("Party 3 signed at index {}", contrib3.0);

    // Aggregate the signatures (anyone can do this)
    let aggregated = MultiEd25519Account::aggregate_signatures(vec![contrib1, contrib3])?;
    println!("Aggregated {} signatures", aggregated.num_signatures());

    // Verify the aggregated signature
    let multi_pk = multi_account.public_key();
    match multi_pk.verify(&message, &aggregated) {
        Ok(_) => println!("✓ Aggregated signature verified!"),
        Err(e) => println!("✗ Verification failed: {}", e),
    }

    // ==== Part 5: View-Only Account ====
    println!("\n--- Part 5: View-Only Multi-Sig ---");

    // Create a view-only account (for monitoring, not signing)
    let view_only = MultiEd25519Account::view_only(pub_keys, 2)?;
    println!("View-only account created:");
    println!("  Address: {}", view_only.address());
    println!("  Can sign: {}", view_only.can_sign());
    println!(
        "  Same address as full account: {}",
        view_only.address() == multi_account.address()
    );

    println!("\n✓ Multi-signature example completed!");
    Ok(())
}
