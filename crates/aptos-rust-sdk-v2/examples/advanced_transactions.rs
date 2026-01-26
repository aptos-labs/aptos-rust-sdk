//! Example: Advanced Transaction Combinations
//!
//! This example demonstrates how to combine different transaction features:
//! 1. Sponsored + Multi-agent transactions
//! 2. Sponsored + MultiKey account transactions
//! 3. Sponsored + MultiEd25519 (multisig) transactions
//! 4. Batch transactions with different account types
//!
//! Run with: `cargo run --example advanced_transactions --features "ed25519,secp256k1,faucet"`

use aptos_rust_sdk_v2::{
    account::{Account, AnyPrivateKey, Ed25519Account, MultiEd25519Account, MultiKeyAccount},
    crypto::{Ed25519PrivateKey, Secp256k1PrivateKey},
    transaction::{
        builder::{sign_fee_payer_transaction, sign_multi_agent_transaction},
        types::{FeePayerRawTransaction, MultiAgentRawTransaction},
        EntryFunction, SponsoredTransactionBuilder, TransactionBatchBuilder, TransactionBuilder,
        TransactionPayload,
    },
    Aptos, AptosConfig,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Advanced Transaction Combinations ===\n");

    // Connect to testnet
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet (chain_id: {})", aptos.chain_id());

    // ==== Part 1: Sponsored + Multi-agent Transaction ====
    println!("\n--- Part 1: Sponsored + Multi-agent Transaction ---");
    println!("Scenario: A swap transaction requiring two signers, with a third party paying gas");

    sponsored_multi_agent_example(&aptos).await?;

    // ==== Part 2: Sponsored + MultiKey Account ====
    println!("\n--- Part 2: Sponsored + MultiKey Account Transaction ---");
    println!("Scenario: A 2-of-3 multi-key account transaction with sponsored gas");

    sponsored_multikey_example(&aptos).await?;

    // ==== Part 3: Sponsored + MultiEd25519 (Multisig) ====
    println!("\n--- Part 3: Sponsored + MultiEd25519 Transaction ---");
    println!("Scenario: A 2-of-3 Ed25519 multisig transaction with sponsored gas");

    sponsored_multisig_example(&aptos).await?;

    // ==== Part 4: Batch with Different Account Types ====
    println!("\n--- Part 4: Batch Transactions with Multi-sig Account ---");
    println!("Scenario: Multiple transfers from a multi-sig account");

    batch_multisig_example(&aptos).await?;

    // ==== Part 5: Multi-agent with MultiKey Signers ====
    println!("\n--- Part 5: Multi-agent with MultiKey Secondary Signer ---");
    println!("Scenario: Primary signer is Ed25519, secondary is a MultiKey account");

    multi_agent_multikey_example(&aptos).await?;

    println!("\n=== All Advanced Transaction Examples Completed ===");
    Ok(())
}

/// Example: Sponsored + Multi-agent transaction
/// 
/// This combines:
/// - Fee payer (sponsor) paying for gas
/// - Multiple signers required for the transaction
async fn sponsored_multi_agent_example(aptos: &Aptos) -> anyhow::Result<()> {
    // Create accounts
    let primary_signer = Ed25519Account::generate();
    let secondary_signer = Ed25519Account::generate();
    let fee_payer = Ed25519Account::generate();
    let recipient = Ed25519Account::generate();

    println!("Primary signer: {}", primary_signer.address());
    println!("Secondary signer: {}", secondary_signer.address());
    println!("Fee payer: {}", fee_payer.address());
    println!("Recipient: {}", recipient.address());

    // Fund accounts (only fee payer needs gas, but both signers need some balance)
    println!("\nFunding accounts...");
    aptos.fund_account(primary_signer.address(), 50_000_000).await?;
    aptos.fund_account(secondary_signer.address(), 50_000_000).await?;
    aptos.fund_account(fee_payer.address(), 100_000_000).await?;

    // Build the transaction payload
    // In a real multi-agent scenario, this would be a function requiring multiple signers
    // (e.g., atomic swap, escrow release)
    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000_000)?;

    // Get sequence number for primary signer
    let sequence_number = aptos.get_sequence_number(primary_signer.address()).await?;

    // Build the raw transaction
    let raw_txn = TransactionBuilder::new()
        .sender(primary_signer.address())
        .sequence_number(sequence_number)
        .payload(TransactionPayload::EntryFunction(payload))
        .chain_id(aptos.chain_id())
        .max_gas_amount(100_000)
        .gas_unit_price(100)
        .expiration_from_now(600)
        .build()?;

    // Create a fee payer transaction with secondary signers
    // This combines multi-agent (secondary signers) with sponsorship (fee payer)
    let fee_payer_txn = FeePayerRawTransaction {
        raw_txn,
        secondary_signer_addresses: vec![secondary_signer.address()],
        fee_payer_address: fee_payer.address(),
    };

    // Sign with all parties
    let signed_txn = sign_fee_payer_transaction(
        &fee_payer_txn,
        &primary_signer,
        &[&secondary_signer as &dyn Account], // Secondary signers
        &fee_payer,
    )?;

    println!("\nTransaction signed by:");
    println!("  - Primary signer (sender)");
    println!("  - Secondary signer");
    println!("  - Fee payer (sponsor)");

    // Submit and wait
    println!("\nSubmitting sponsored multi-agent transaction...");
    let result = aptos.submit_and_wait(&signed_txn, None).await?;

    let success = result.data.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    println!("Transaction success: {}", success);

    // Verify fee payer paid the gas
    let fee_payer_balance = aptos.get_balance(fee_payer.address()).await?;
    println!("Fee payer balance after: {} APT (paid gas)", fee_payer_balance as f64 / 100_000_000.0);

    Ok(())
}

/// Example: Sponsored transaction with MultiKey account as sender
///
/// This combines:
/// - MultiKey account (mixed key types, threshold signing)
/// - Fee payer sponsoring gas
async fn sponsored_multikey_example(aptos: &Aptos) -> anyhow::Result<()> {
    // Create keys of different types
    let ed_key1 = Ed25519PrivateKey::generate();
    let secp_key = Secp256k1PrivateKey::generate();
    let ed_key2 = Ed25519PrivateKey::generate();

    println!("Key 0: Ed25519   - {}", ed_key1.public_key());
    println!("Key 1: Secp256k1 - {}", secp_key.public_key());
    println!("Key 2: Ed25519   - {}", ed_key2.public_key());

    // Create 2-of-3 MultiKey account
    let multi_key_account = MultiKeyAccount::new(
        vec![
            AnyPrivateKey::ed25519(ed_key1),
            AnyPrivateKey::secp256k1(secp_key),
            AnyPrivateKey::ed25519(ed_key2),
        ],
        2, // Threshold: 2-of-3
    )?;

    let fee_payer = Ed25519Account::generate();
    let recipient = Ed25519Account::generate();

    println!("\nMultiKey account: {} (2-of-3)", multi_key_account.address());
    println!("Fee payer: {}", fee_payer.address());
    println!("Recipient: {}", recipient.address());

    // Fund accounts
    println!("\nFunding accounts...");
    aptos.fund_account(multi_key_account.address(), 50_000_000).await?;
    aptos.fund_account(fee_payer.address(), 100_000_000).await?;

    // Build payload
    let payload = EntryFunction::apt_transfer(recipient.address(), 5_000_000)?;

    // Use SponsoredTransactionBuilder
    let signed_txn = SponsoredTransactionBuilder::new()
        .sender(multi_key_account.address())
        .sequence_number(aptos.get_sequence_number(multi_key_account.address()).await?)
        .fee_payer(fee_payer.address())
        .payload(TransactionPayload::EntryFunction(payload))
        .chain_id(aptos.chain_id())
        .max_gas_amount(100_000)
        .gas_unit_price(100)
        .expiration_from_now(600)
        .build_and_sign(
            &multi_key_account, // Sender signs with threshold keys
            &[],                // No secondary signers
            &fee_payer,         // Fee payer signs
        )?;

    println!("\nTransaction signed by:");
    println!("  - MultiKey account (2-of-3 threshold)");
    println!("  - Fee payer (sponsor)");

    // Submit
    println!("\nSubmitting sponsored MultiKey transaction...");
    let result = aptos.submit_and_wait(&signed_txn, None).await?;

    let success = result.data.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    println!("Transaction success: {}", success);

    // Check recipient balance
    let recipient_balance = aptos.get_balance(recipient.address()).await.unwrap_or(0);
    println!("Recipient received: {} APT", recipient_balance as f64 / 100_000_000.0);

    Ok(())
}

/// Example: Sponsored transaction with MultiEd25519 (classic multisig) account
///
/// This combines:
/// - MultiEd25519 account (M-of-N Ed25519 threshold)
/// - Fee payer sponsoring gas
async fn sponsored_multisig_example(aptos: &Aptos) -> anyhow::Result<()> {
    // Generate Ed25519 keys
    let key1 = Ed25519PrivateKey::generate();
    let key2 = Ed25519PrivateKey::generate();
    let key3 = Ed25519PrivateKey::generate();

    println!("Key 0: {}", key1.public_key());
    println!("Key 1: {}", key2.public_key());
    println!("Key 2: {}", key3.public_key());

    // Create 2-of-3 MultiEd25519 account
    let multi_ed_account = MultiEd25519Account::new(
        vec![key1, key2, key3],
        2, // Threshold
    )?;

    let fee_payer = Ed25519Account::generate();
    let recipient = Ed25519Account::generate();

    println!("\nMultiEd25519 account: {} (2-of-3)", multi_ed_account.address());
    println!("Fee payer: {}", fee_payer.address());

    // Fund accounts
    println!("\nFunding accounts...");
    aptos.fund_account(multi_ed_account.address(), 50_000_000).await?;
    aptos.fund_account(fee_payer.address(), 100_000_000).await?;

    // Build payload
    let payload = EntryFunction::apt_transfer(recipient.address(), 3_000_000)?;

    // Build sponsored transaction
    let signed_txn = SponsoredTransactionBuilder::new()
        .sender(multi_ed_account.address())
        .sequence_number(aptos.get_sequence_number(multi_ed_account.address()).await?)
        .fee_payer(fee_payer.address())
        .payload(TransactionPayload::EntryFunction(payload))
        .chain_id(aptos.chain_id())
        .max_gas_amount(100_000)
        .gas_unit_price(100)
        .expiration_from_now(600)
        .build_and_sign(
            &multi_ed_account, // Multi-sig account signs
            &[],
            &fee_payer,
        )?;

    println!("\nTransaction signed by:");
    println!("  - MultiEd25519 account (2-of-3 threshold)");
    println!("  - Fee payer (sponsor)");

    // Submit
    println!("\nSubmitting sponsored MultiEd25519 transaction...");
    let result = aptos.submit_and_wait(&signed_txn, None).await?;

    let success = result.data.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    println!("Transaction success: {}", success);

    Ok(())
}

/// Example: Batch transactions from a multi-sig account
///
/// This demonstrates sending multiple transactions efficiently
/// from a threshold signature account.
async fn batch_multisig_example(aptos: &Aptos) -> anyhow::Result<()> {
    // Create 2-of-3 MultiEd25519 account
    let key1 = Ed25519PrivateKey::generate();
    let key2 = Ed25519PrivateKey::generate();
    let key3 = Ed25519PrivateKey::generate();

    let multi_account = MultiEd25519Account::new(vec![key1, key2, key3], 2)?;
    
    // Create multiple recipients
    let recipient1 = Ed25519Account::generate();
    let recipient2 = Ed25519Account::generate();
    let recipient3 = Ed25519Account::generate();

    println!("Sender (2-of-3 multisig): {}", multi_account.address());
    println!("Recipient 1: {}", recipient1.address());
    println!("Recipient 2: {}", recipient2.address());
    println!("Recipient 3: {}", recipient3.address());

    // Fund the multi-sig account
    println!("\nFunding multisig account...");
    aptos.fund_account(multi_account.address(), 100_000_000).await?;

    // Create batch of transfers
    let payloads: Vec<TransactionPayload> = vec![
        TransactionPayload::EntryFunction(EntryFunction::apt_transfer(recipient1.address(), 1_000_000)?),
        TransactionPayload::EntryFunction(EntryFunction::apt_transfer(recipient2.address(), 2_000_000)?),
        TransactionPayload::EntryFunction(EntryFunction::apt_transfer(recipient3.address(), 3_000_000)?),
    ];

    // Get sequence number
    let starting_seq = aptos.get_sequence_number(multi_account.address()).await?;

    // Build batch
    let batch = TransactionBatchBuilder::new()
        .sender(multi_account.address())
        .starting_sequence_number(starting_seq)
        .chain_id(aptos.chain_id())
        .gas_unit_price(100)
        .max_gas_amount(100_000)
        .add_payloads(payloads)
        .build_and_sign(&multi_account)?;

    println!("\nBatch of {} transactions built and signed", batch.len());
    println!("Each signed with 2-of-3 threshold");

    // Submit all in parallel
    println!("\nSubmitting batch in parallel...");
    let results = batch.submit_and_wait_all(aptos.fullnode(), None).await;

    // Check results
    let mut succeeded = 0;
    let mut failed = 0;
    for result in &results {
        match &result.result {
            Ok(status) if status.is_success() => succeeded += 1,
            _ => failed += 1,
        }
    }

    println!("Batch results: {} succeeded, {} failed", succeeded, failed);

    // Verify balances
    let r1_balance = aptos.get_balance(recipient1.address()).await.unwrap_or(0);
    let r2_balance = aptos.get_balance(recipient2.address()).await.unwrap_or(0);
    let r3_balance = aptos.get_balance(recipient3.address()).await.unwrap_or(0);

    println!("Recipient balances:");
    println!("  Recipient 1: {} APT", r1_balance as f64 / 100_000_000.0);
    println!("  Recipient 2: {} APT", r2_balance as f64 / 100_000_000.0);
    println!("  Recipient 3: {} APT", r3_balance as f64 / 100_000_000.0);

    Ok(())
}

/// Example: Multi-agent transaction where secondary signer is a MultiKey account
///
/// This combines:
/// - Multi-agent (multiple required signers)
/// - MultiKey account as one of the signers
async fn multi_agent_multikey_example(aptos: &Aptos) -> anyhow::Result<()> {
    // Primary signer: regular Ed25519
    let primary = Ed25519Account::generate();

    // Secondary signer: 2-of-3 MultiKey account
    let ed_key = Ed25519PrivateKey::generate();
    let secp_key = Secp256k1PrivateKey::generate();
    let ed_key2 = Ed25519PrivateKey::generate();

    let secondary_multikey = MultiKeyAccount::new(
        vec![
            AnyPrivateKey::ed25519(ed_key),
            AnyPrivateKey::secp256k1(secp_key),
            AnyPrivateKey::ed25519(ed_key2),
        ],
        2,
    )?;

    let recipient = Ed25519Account::generate();

    println!("Primary signer (Ed25519): {}", primary.address());
    println!("Secondary signer (2-of-3 MultiKey): {}", secondary_multikey.address());
    println!("Recipient: {}", recipient.address());

    // Fund accounts
    println!("\nFunding accounts...");
    aptos.fund_account(primary.address(), 100_000_000).await?;
    aptos.fund_account(secondary_multikey.address(), 50_000_000).await?;

    // Build payload
    let payload = EntryFunction::apt_transfer(recipient.address(), 2_000_000)?;

    // Get sequence number
    let seq = aptos.get_sequence_number(primary.address()).await?;

    // Build raw transaction
    let raw_txn = TransactionBuilder::new()
        .sender(primary.address())
        .sequence_number(seq)
        .payload(TransactionPayload::EntryFunction(payload))
        .chain_id(aptos.chain_id())
        .max_gas_amount(100_000)
        .gas_unit_price(100)
        .expiration_from_now(600)
        .build()?;

    // Create multi-agent transaction
    let multi_agent_txn = MultiAgentRawTransaction::new(
        raw_txn,
        vec![secondary_multikey.address()],
    );

    // Sign with both: Ed25519 primary and MultiKey secondary
    let signed_txn = sign_multi_agent_transaction(
        &multi_agent_txn,
        &primary,
        &[&secondary_multikey as &dyn Account],
    )?;

    println!("\nTransaction signed by:");
    println!("  - Primary: Ed25519 single signature");
    println!("  - Secondary: MultiKey 2-of-3 threshold signature");

    // Submit
    println!("\nSubmitting multi-agent transaction...");
    let result = aptos.submit_and_wait(&signed_txn, None).await?;

    let success = result.data.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    println!("Transaction success: {}", success);

    Ok(())
}
