//! Example: Multi-Key Account with Mixed Signature Types
//!
//! This example demonstrates how to create and use a MultiKeyAccount,
//! which supports M-of-N threshold signatures with mixed key types
//! (e.g., Ed25519 + Secp256k1 in the same account).
//!
//! Run with: `cargo run --example multi_key_account --features "ed25519,secp256k1,faucet"`

use aptos_rust_sdk_v2::{
    account::{AnyPrivateKey, MultiKeyAccount},
    crypto::{AnyPublicKey, Ed25519PrivateKey, Secp256k1PrivateKey},
    transaction::{EntryFunction, TransactionBuilder},
    Aptos, AptosConfig,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Multi-Key Account Example ===\n");

    // 1. Setup Aptos client for testnet
    let config = AptosConfig::testnet();
    let aptos = Aptos::new(config)?;
    println!("Connected to testnet (chain_id: {})", aptos.chain_id());

    // 2. Generate individual private keys of different types
    println!("\n--- Creating Mixed Key Types ---");
    let ed25519_key_1 = Ed25519PrivateKey::generate();
    let secp256k1_key = Secp256k1PrivateKey::generate();
    let ed25519_key_2 = Ed25519PrivateKey::generate();

    println!("Key 0: Ed25519   - {}", ed25519_key_1.public_key());
    println!("Key 1: Secp256k1 - {}", secp256k1_key.public_key());
    println!("Key 2: Ed25519   - {}", ed25519_key_2.public_key());

    // 3. Create a 2-of-3 multi-key account with mixed types
    let threshold = 2;
    let private_keys = vec![
        AnyPrivateKey::ed25519(ed25519_key_1.clone()),
        AnyPrivateKey::secp256k1(secp256k1_key.clone()),
        AnyPrivateKey::ed25519(ed25519_key_2.clone()),
    ];

    let multi_key_account = MultiKeyAccount::new(private_keys, threshold)?;

    println!("\n--- Multi-Key Account Created ---");
    println!("Address:   {}", multi_key_account.address());
    println!("Threshold: {}-of-{}", multi_key_account.threshold(), multi_key_account.num_keys());
    println!("Key types: {:?}", multi_key_account.key_types());
    println!("Can sign:  {}", multi_key_account.can_sign());

    // 4. Fund the multi-key account
    println!("\n--- Funding Account ---");
    aptos.fund_account(multi_key_account.address(), 100_000_000).await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    
    let balance = aptos.get_balance(multi_key_account.address()).await.unwrap_or(0);
    println!("Balance: {} octas ({} APT)", balance, balance as f64 / 100_000_000.0);

    // 5. Create a recipient account
    let recipient = aptos.create_funded_account(0).await?;
    println!("\nRecipient: {}", recipient.address());

    // 6. Build and sign a transfer transaction
    println!("\n--- Building Transaction ---");
    let transfer_amount = 10_000_000; // 0.1 APT
    let payload = EntryFunction::apt_transfer(recipient.address(), transfer_amount)?;

    let sequence_number = aptos.get_sequence_number(multi_key_account.address()).await?;
    
    let raw_txn = TransactionBuilder::new()
        .sender(multi_key_account.address())
        .sequence_number(sequence_number)
        .payload(payload.into())
        .chain_id(aptos.chain_id())
        .max_gas_amount(100_000)
        .gas_unit_price(100)
        .build()?;

    // 7. Sign with the multi-key account (uses threshold number of keys)
    println!("Signing with {}-of-{} keys...", threshold, multi_key_account.num_keys());
    let signed_txn = aptos_rust_sdk_v2::transaction::builder::sign_transaction(
        &raw_txn,
        &multi_key_account,
    )?;

    // 8. Submit and wait for confirmation
    println!("Submitting transaction...");
    let result = aptos.submit_and_wait(&signed_txn, None).await?;
    println!("Transaction successful!");
    println!("Result: {:?}", result.data);

    // 9. Verify recipient received funds
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let recipient_balance = aptos.get_balance(recipient.address()).await.unwrap_or(0);
    println!("\nRecipient balance: {} octas", recipient_balance);

    // 10. Demonstrate distributed signing scenario
    println!("\n=== Distributed Signing Demo ===");
    demonstrate_distributed_signing().await?;

    println!("\n✅ Multi-key account example completed!");
    Ok(())
}

/// Demonstrates how different parties can sign independently
/// and combine signatures later.
async fn demonstrate_distributed_signing() -> anyhow::Result<()> {
    // Scenario: 3 parties each have one key, need 2-of-3 to sign

    // Generate keys (in real scenario, each party generates their own)
    let party1_key = Ed25519PrivateKey::generate();
    let party2_key = Secp256k1PrivateKey::generate();
    let party3_key = Ed25519PrivateKey::generate();

    // Create public key list (shared among all parties)
    let public_keys = vec![
        AnyPublicKey::ed25519(&party1_key.public_key()),
        AnyPublicKey::secp256k1(&party2_key.public_key()),
        AnyPublicKey::ed25519(&party3_key.public_key()),
    ];

    println!("\n--- Party 1: Creates view-only account ---");
    let party1_account = MultiKeyAccount::from_keys(
        public_keys.clone(),
        vec![(0, AnyPrivateKey::ed25519(party1_key))],
        2,
    )?;
    println!("Address: {}", party1_account.address());
    println!("Party 1 owns key at index 0");

    println!("\n--- Party 2: Creates their view of the account ---");
    let party2_account = MultiKeyAccount::from_keys(
        public_keys.clone(),
        vec![(1, AnyPrivateKey::secp256k1(party2_key))],
        2,
    )?;
    println!("Address: {} (same)", party2_account.address());
    println!("Party 2 owns key at index 1");

    // Both parties can create signature contributions
    let message = b"transaction_signing_message";

    println!("\n--- Creating Signature Contributions ---");
    
    // Party 1 creates their signature
    let (idx1, sig1) = party1_account.create_signature_contribution(message, 0)?;
    println!("Party 1 signed with key index {}", idx1);

    // Party 2 creates their signature
    let (idx2, sig2) = party2_account.create_signature_contribution(message, 1)?;
    println!("Party 2 signed with key index {}", idx2);

    // Combine signatures (can be done by any party or a relayer)
    println!("\n--- Aggregating Signatures ---");
    let multi_sig = MultiKeyAccount::aggregate_signatures(vec![
        (idx1, sig1),
        (idx2, sig2),
    ])?;
    println!("Combined {} signatures", multi_sig.num_signatures());

    // Verify the combined signature
    let pk = party1_account.public_key();
    pk.verify(message, &multi_sig)?;
    println!("✅ Combined signature verified!");

    // Demonstrate view-only account
    println!("\n--- View-Only Account ---");
    let view_only = MultiKeyAccount::view_only(public_keys, 2)?;
    println!("Address: {} (same)", view_only.address());
    println!("Can sign: {} (no private keys)", view_only.can_sign());

    Ok(())
}

