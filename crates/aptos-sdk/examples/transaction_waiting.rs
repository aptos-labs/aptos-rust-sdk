//! Example: Transaction Waiting Strategies
//!
//! This example demonstrates various ways to efficiently wait for transactions:
//! 1. Basic submit and wait
//! 2. Custom timeout handling
//! 3. Submit first, wait later (deferred waiting)
//! 4. Batch waiting strategies (parallel vs sequential)
//! 5. Polling and retry patterns
//! 6. Checking transaction success and parsing results
//!
//! Run with: `cargo run --example transaction_waiting --features "ed25519,faucet"`

use aptos_rust_sdk_v2::{
    Aptos, AptosConfig,
    account::Ed25519Account,
    transaction::{BatchSummary, BatchTransactionStatus, EntryFunction, TransactionBatchBuilder},
};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Transaction Waiting Strategies ===\n");

    // Connect to testnet
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet (chain_id: {})", aptos.chain_id());

    // Create and fund accounts
    let sender = aptos.create_funded_account(200_000_000).await?;
    let recipient = Ed25519Account::generate();
    println!("Sender: {}", sender.address());
    println!("Recipient: {}", recipient.address());

    // ==== Part 1: Basic Submit and Wait ====
    println!("\n--- Part 1: Basic Submit and Wait ---");
    basic_submit_and_wait(&aptos, &sender, recipient.address()).await?;

    // ==== Part 2: Custom Timeout ====
    println!("\n--- Part 2: Custom Timeout Handling ---");
    custom_timeout(&aptos, &sender, recipient.address()).await?;

    // ==== Part 3: Submit First, Wait Later ====
    println!("\n--- Part 3: Deferred Waiting ---");
    deferred_waiting(&aptos, &sender, recipient.address()).await?;

    // ==== Part 4: Batch Parallel Waiting ====
    println!("\n--- Part 4: Batch Parallel Waiting ---");
    batch_parallel_waiting(&aptos, &sender).await?;

    // ==== Part 5: Batch Sequential Waiting ====
    println!("\n--- Part 5: Batch Sequential Waiting ---");
    batch_sequential_waiting(&aptos, &sender).await?;

    // ==== Part 6: Parsing Transaction Results ====
    println!("\n--- Part 6: Parsing Transaction Results ---");
    parsing_results(&aptos, &sender, recipient.address()).await?;

    // ==== Part 7: Retry Patterns ====
    println!("\n--- Part 7: Retry Patterns ---");
    retry_patterns(&aptos, &sender, recipient.address()).await?;

    // ==== Part 8: Waiting for Multiple Independent Transactions ====
    println!("\n--- Part 8: Multiple Independent Transactions ---");
    multiple_independent(&aptos, &sender).await?;

    println!("\n=== Transaction Waiting Examples Completed ===");
    Ok(())
}

/// Part 1: Basic submit and wait - simplest approach
async fn basic_submit_and_wait(
    aptos: &Aptos,
    sender: &Ed25519Account,
    recipient: aptos_rust_sdk_v2::types::AccountAddress,
) -> anyhow::Result<()> {
    let payload = EntryFunction::apt_transfer(recipient, 100_000)?;

    // sign_submit_and_wait: builds, signs, submits, and waits in one call
    let result = aptos
        .sign_submit_and_wait(sender, payload.into(), None) // None = default timeout (30s)
        .await?;

    let success = result
        .data
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("sign_submit_and_wait() completed");
    println!("  Success: {}", success);
    println!("  Default timeout: 30 seconds");

    Ok(())
}

/// Part 2: Using custom timeouts
async fn custom_timeout(
    aptos: &Aptos,
    sender: &Ed25519Account,
    recipient: aptos_rust_sdk_v2::types::AccountAddress,
) -> anyhow::Result<()> {
    let payload = EntryFunction::apt_transfer(recipient, 100_000)?;

    // Custom timeout: 60 seconds
    let long_timeout = Some(Duration::from_secs(60));
    println!("Using custom timeout: 60 seconds");

    let _result = aptos
        .sign_submit_and_wait(sender, payload.into(), long_timeout)
        .await?;

    println!("Transaction completed within timeout");

    // Short timeout example (for demonstration)
    let payload2 = EntryFunction::apt_transfer(recipient, 50_000)?;
    let short_timeout = Some(Duration::from_secs(120)); // 2 minutes for safety

    let result2 = aptos
        .sign_submit_and_wait(sender, payload2.into(), short_timeout)
        .await?;

    let success = result2
        .data
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("Second transaction success: {}", success);

    // Note: If a transaction times out, you can still check its status later
    // using wait_for_transaction with the hash

    Ok(())
}

/// Part 3: Submit first, wait later (deferred waiting)
async fn deferred_waiting(
    aptos: &Aptos,
    sender: &Ed25519Account,
    recipient: aptos_rust_sdk_v2::types::AccountAddress,
) -> anyhow::Result<()> {
    let payload = EntryFunction::apt_transfer(recipient, 100_000)?;

    // Step 1: Submit the transaction (returns immediately with pending status)
    println!("Step 1: Submit transaction (non-blocking)");
    let pending = aptos.sign_and_submit(sender, payload.into()).await?;
    let txn_hash = pending.data.hash;
    println!("  Transaction submitted: {}", txn_hash);

    // Step 2: Do other work while transaction is pending
    println!("\nStep 2: Doing other work...");
    println!("  (In a real app, you could process other tasks here)");
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Step 3: Wait for the transaction when ready
    println!("\nStep 3: Wait for transaction confirmation");
    let result = aptos
        .fullnode()
        .wait_for_transaction(&txn_hash, Some(Duration::from_secs(60)))
        .await?;

    let success = result
        .data
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("  Transaction confirmed: {}", success);

    // You can also check status without blocking using get_transaction_by_hash
    println!("\nStep 4: Non-blocking status check");
    let status = aptos.fullnode().get_transaction_by_hash(&txn_hash).await?;
    let version = status.data.get("version").and_then(|v| v.as_str());
    println!("  Transaction version: {:?}", version);

    Ok(())
}

/// Part 4: Batch waiting - parallel strategy
async fn batch_parallel_waiting(aptos: &Aptos, sender: &Ed25519Account) -> anyhow::Result<()> {
    // Create multiple recipients
    let recipients: Vec<_> = (0..5).map(|_| Ed25519Account::generate()).collect();

    println!(
        "Submitting batch of {} transactions in parallel",
        recipients.len()
    );

    // Create payloads
    let payloads: Vec<_> = recipients
        .iter()
        .enumerate()
        .map(|(i, r)| {
            EntryFunction::apt_transfer(r.address(), (i as u64 + 1) * 100_000).map(|ef| ef.into())
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Get sequence number
    let seq = aptos.get_sequence_number(sender.address()).await?;

    // Build and sign batch
    let batch = TransactionBatchBuilder::new()
        .sender(sender.address())
        .starting_sequence_number(seq)
        .chain_id(aptos.chain_id())
        .gas_unit_price(100)
        .add_payloads(payloads)
        .build_and_sign(sender)?;

    println!("Built {} transactions", batch.len());

    // Submit all in PARALLEL and wait for all
    let start = std::time::Instant::now();
    let results = batch.submit_and_wait_all(aptos.fullnode(), None).await;
    let elapsed = start.elapsed();

    println!("\nParallel wait completed in {:?}", elapsed);

    // Summarize results
    let summary = BatchSummary::from_results(&results);
    println!("Summary:");
    println!("  Total: {}", summary.total);
    println!("  Succeeded: {}", summary.succeeded);
    println!("  Failed: {}", summary.failed);
    println!("  Total gas used: {}", summary.total_gas_used);

    if summary.all_succeeded() {
        println!("  All transactions succeeded!");
    }

    Ok(())
}

/// Part 5: Batch waiting - sequential strategy
async fn batch_sequential_waiting(aptos: &Aptos, sender: &Ed25519Account) -> anyhow::Result<()> {
    // Create recipients
    let recipients: Vec<_> = (0..3).map(|_| Ed25519Account::generate()).collect();

    println!(
        "Submitting batch of {} transactions SEQUENTIALLY",
        recipients.len()
    );
    println!("(Each waits for confirmation before sending next)");

    // Create payloads
    let payloads: Vec<_> = recipients
        .iter()
        .enumerate()
        .map(|(i, r)| {
            EntryFunction::apt_transfer(r.address(), (i as u64 + 1) * 50_000).map(|ef| ef.into())
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Get sequence number
    let seq = aptos.get_sequence_number(sender.address()).await?;

    // Build batch
    let batch = TransactionBatchBuilder::new()
        .sender(sender.address())
        .starting_sequence_number(seq)
        .chain_id(aptos.chain_id())
        .gas_unit_price(100)
        .add_payloads(payloads)
        .build_and_sign(sender)?;

    // Submit SEQUENTIALLY (wait for each before next)
    let start = std::time::Instant::now();
    let results = batch
        .submit_and_wait_sequential(aptos.fullnode(), None)
        .await;
    let elapsed = start.elapsed();

    println!("\nSequential wait completed in {:?}", elapsed);
    println!("(Slower than parallel, but ensures order)");

    // Check each result
    for result in &results {
        match &result.result {
            Ok(BatchTransactionStatus::Confirmed {
                success,
                version,
                gas_used,
                ..
            }) => {
                println!(
                    "  TX {}: success={}, version={}, gas={}",
                    result.index, success, version, gas_used
                );
            }
            Ok(BatchTransactionStatus::Pending { hash }) => {
                println!("  TX {}: pending ({})", result.index, hash);
            }
            Ok(BatchTransactionStatus::Failed { error }) => {
                println!("  TX {}: failed - {}", result.index, error);
            }
            Err(e) => {
                println!("  TX {}: error - {}", result.index, e);
            }
        }
    }

    Ok(())
}

/// Part 6: Parsing transaction results in detail
async fn parsing_results(
    aptos: &Aptos,
    sender: &Ed25519Account,
    recipient: aptos_rust_sdk_v2::types::AccountAddress,
) -> anyhow::Result<()> {
    let payload = EntryFunction::apt_transfer(recipient, 100_000)?;

    let result = aptos
        .sign_submit_and_wait(sender, payload.into(), None)
        .await?;

    println!("Parsing transaction result fields:");

    // Essential fields
    let hash = result
        .data
        .get("hash")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");
    let version = result
        .data
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");
    let success = result
        .data
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let vm_status = result
        .data
        .get("vm_status")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");

    println!("  hash: {}", hash);
    println!("  version: {}", version);
    println!("  success: {}", success);
    println!("  vm_status: {}", vm_status);

    // Gas information
    let gas_used = result
        .data
        .get("gas_used")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let gas_unit_price = result
        .data
        .get("gas_unit_price")
        .and_then(|v| v.as_str())
        .unwrap_or("0");

    let gas_used_u64: u64 = gas_used.parse().unwrap_or(0);
    let gas_price_u64: u64 = gas_unit_price.parse().unwrap_or(0);
    let total_gas_cost = gas_used_u64 * gas_price_u64;

    println!("\nGas information:");
    println!("  gas_used: {} units", gas_used);
    println!("  gas_unit_price: {} octas", gas_unit_price);
    println!(
        "  total_cost: {} octas ({} APT)",
        total_gas_cost,
        total_gas_cost as f64 / 100_000_000.0
    );

    // Timing information
    let timestamp = result
        .data
        .get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");
    let expiration = result
        .data
        .get("expiration_timestamp_secs")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");

    println!("\nTiming:");
    println!("  executed_at: {} (microseconds since epoch)", timestamp);
    println!("  expiration: {} (seconds since epoch)", expiration);

    // Events (if any)
    if let Some(events) = result.data.get("events").and_then(|v| v.as_array()) {
        println!("\nEvents: {} emitted", events.len());
        for (i, event) in events.iter().enumerate() {
            let event_type = event
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("  Event {}: {}", i, event_type);
        }
    }

    // State changes
    if let Some(changes) = result.data.get("changes").and_then(|v| v.as_array()) {
        println!("\nState changes: {}", changes.len());
    }

    Ok(())
}

/// Part 7: Retry patterns for failed submissions
async fn retry_patterns(
    aptos: &Aptos,
    sender: &Ed25519Account,
    recipient: aptos_rust_sdk_v2::types::AccountAddress,
) -> anyhow::Result<()> {
    println!("Demonstrating safe retry patterns:");

    // Build a transaction
    let payload = EntryFunction::apt_transfer(recipient, 50_000)?;
    let raw_txn = aptos.build_transaction(sender, payload.into()).await?;
    let signed_txn = aptos_rust_sdk_v2::transaction::builder::sign_transaction(&raw_txn, sender)?;

    // Pattern 1: Idempotent resubmission
    println!("\n1. Idempotent resubmission:");
    println!("   Submitting same signed transaction is safe");

    // Submit first time
    let pending = aptos.submit_transaction(&signed_txn).await?;
    println!("   First submit: {}", pending.data.hash);

    // Second submission of same transaction is idempotent
    // (will succeed but won't execute twice)
    match aptos.submit_transaction(&signed_txn).await {
        Ok(p) => println!("   Resubmit: {} (same hash, safe)", p.data.hash),
        Err(e) if e.to_string().contains("already") => {
            println!("   Resubmit: already submitted (safe)")
        }
        Err(e) => println!("   Resubmit error: {} (may be expected)", e),
    }

    // Wait for the transaction
    let result = aptos
        .fullnode()
        .wait_for_transaction(&pending.data.hash, None)
        .await?;
    let success = result
        .data
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("   Final result: success={}", success);

    // Pattern 2: Retry with exponential backoff (handled by SDK)
    println!("\n2. Automatic retry with backoff:");
    println!("   The SDK automatically retries transient failures");
    println!("   Configure via AptosConfig::with_retry()");

    // Pattern 3: Check before retry
    println!("\n3. Check status before retrying:");

    let payload2 = EntryFunction::apt_transfer(recipient, 25_000)?;
    let pending2 = aptos.sign_and_submit(sender, payload2.into()).await?;
    let hash = pending2.data.hash;

    // Check if already confirmed before retrying
    match aptos.fullnode().get_transaction_by_hash(&hash).await {
        Ok(txn) if txn.data.get("version").is_some() => {
            println!("   Transaction already confirmed, no retry needed");
        }
        Ok(_) => {
            println!("   Transaction pending, waiting...");
        }
        Err(_) => {
            println!("   Transaction not found, may need to resubmit");
        }
    }

    // Wait for final confirmation
    aptos.fullnode().wait_for_transaction(&hash, None).await?;
    println!("   Transaction confirmed");

    Ok(())
}

/// Part 8: Waiting for multiple independent transactions from different senders
async fn multiple_independent(aptos: &Aptos, _sender: &Ed25519Account) -> anyhow::Result<()> {
    // Create multiple independent senders
    let sender1 = aptos.create_funded_account(50_000_000).await?;
    let sender2 = aptos.create_funded_account(50_000_000).await?;
    let sender3 = aptos.create_funded_account(50_000_000).await?;

    let recipient = Ed25519Account::generate();

    println!("3 independent senders, each sending to same recipient");
    println!("All transactions processed in parallel");

    // Build payloads
    let payload1 = EntryFunction::apt_transfer(recipient.address(), 1_000_000)?;
    let payload2 = EntryFunction::apt_transfer(recipient.address(), 2_000_000)?;
    let payload3 = EntryFunction::apt_transfer(recipient.address(), 3_000_000)?;

    // Submit all in parallel using tokio::join!
    let start = std::time::Instant::now();

    let (result1, result2, result3) = tokio::join!(
        aptos.sign_submit_and_wait(&sender1, payload1.into(), None),
        aptos.sign_submit_and_wait(&sender2, payload2.into(), None),
        aptos.sign_submit_and_wait(&sender3, payload3.into(), None),
    );

    let elapsed = start.elapsed();
    println!("\nAll 3 transactions completed in {:?}", elapsed);

    // Check results
    let s1 = result1
        .map(|r| {
            r.data
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let s2 = result2
        .map(|r| {
            r.data
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let s3 = result3
        .map(|r| {
            r.data
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .unwrap_or(false);

    println!("Results:");
    println!("  Sender 1: success={}", s1);
    println!("  Sender 2: success={}", s2);
    println!("  Sender 3: success={}", s3);

    // Verify recipient got all the funds
    tokio::time::sleep(Duration::from_secs(1)).await;
    let balance = aptos.get_balance(recipient.address()).await.unwrap_or(0);
    println!(
        "\nRecipient total balance: {} APT",
        balance as f64 / 100_000_000.0
    );
    println!(
        "Expected: {} APT",
        (1_000_000 + 2_000_000 + 3_000_000) as f64 / 100_000_000.0
    );

    Ok(())
}
