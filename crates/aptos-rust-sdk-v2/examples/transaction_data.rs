//! Example: Getting and parsing transaction data
//!
//! This example demonstrates how to:
//! 1. Get transaction details by hash
//! 2. Parse transaction events
//! 3. Query transaction history
//! 4. Extract meaningful data from responses
//!
//! Run with: `cargo run --example transaction_data --features "ed25519,faucet"`

use aptos_rust_sdk_v2::{Aptos, AptosConfig, account::Ed25519Account, transaction::EntryFunction};
use serde::Deserialize;

/// Coin deposit event from 0x1::coin
#[derive(Debug, Deserialize)]
struct DepositEvent {
    amount: String,
}

/// Coin withdraw event from 0x1::coin
#[derive(Debug, Deserialize)]
struct WithdrawEvent {
    amount: String,
}

/// Account creation event
#[derive(Debug, Deserialize)]
struct CreateAccountEvent {
    created: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create client for testnet
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet");

    // Create and fund accounts for testing
    let sender = aptos.create_funded_account(100_000_000).await?;
    let recipient = Ed25519Account::generate();
    println!("Sender: {}", sender.address());
    println!("Recipient: {}", recipient.address());

    // ==== Part 1: Submit a transaction and get its details ====
    println!("\n=== Part 1: Submit Transaction and Get Details ===");

    let payload = EntryFunction::apt_transfer(recipient.address(), 10_000_000)?;
    let pending = aptos.sign_and_submit(&sender, payload.into()).await?;
    let txn_hash = pending.data.hash;
    println!("Submitted transaction: {}", txn_hash);

    // Wait for the transaction
    let result = aptos
        .fullnode()
        .wait_for_transaction(&txn_hash, None)
        .await?;

    // Parse transaction details
    println!("\nTransaction Details:");
    println!(
        "  Hash: {}",
        result
            .data
            .get("hash")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A")
    );
    println!(
        "  Version: {}",
        result
            .data
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A")
    );
    println!(
        "  Success: {}",
        result
            .data
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    );
    println!(
        "  Gas Used: {} gas units",
        result
            .data
            .get("gas_used")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A")
    );
    println!(
        "  Gas Unit Price: {} octas",
        result
            .data
            .get("gas_unit_price")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A")
    );
    println!(
        "  Sender: {}",
        result
            .data
            .get("sender")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A")
    );
    println!(
        "  Sequence Number: {}",
        result
            .data
            .get("sequence_number")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A")
    );

    // Calculate gas cost in APT
    if let (Some(gas_used), Some(gas_price)) = (
        result.data.get("gas_used").and_then(|v| v.as_str()),
        result.data.get("gas_unit_price").and_then(|v| v.as_str()),
    ) {
        let gas_used: u64 = gas_used.parse().unwrap_or(0);
        let gas_price: u64 = gas_price.parse().unwrap_or(0);
        let cost_octas = gas_used * gas_price;
        let cost_apt = cost_octas as f64 / 100_000_000.0;
        println!("  Total Gas Cost: {} APT ({} octas)", cost_apt, cost_octas);
    }

    // ==== Part 2: Parse Events from Transaction ====
    println!("\n=== Part 2: Parse Transaction Events ===");

    if let Some(events) = result.data.get("events").and_then(|v| v.as_array()) {
        println!("Found {} events:", events.len());

        for (i, event) in events.iter().enumerate() {
            let event_type = event
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("\n  Event {}: {}", i + 1, event_type);

            // Parse specific event types
            if event_type.contains("DepositEvent") {
                if let Some(data) = event.get("data")
                    && let Ok(deposit) = serde_json::from_value::<DepositEvent>(data.clone())
                {
                    let amount: u64 = deposit.amount.parse().unwrap_or(0);
                    println!(
                        "    Amount deposited: {} APT",
                        amount as f64 / 100_000_000.0
                    );
                }
            } else if event_type.contains("WithdrawEvent") {
                if let Some(data) = event.get("data")
                    && let Ok(withdraw) = serde_json::from_value::<WithdrawEvent>(data.clone())
                {
                    let amount: u64 = withdraw.amount.parse().unwrap_or(0);
                    println!(
                        "    Amount withdrawn: {} APT",
                        amount as f64 / 100_000_000.0
                    );
                }
            } else if event_type.contains("CreateAccountEvent")
                && let Some(data) = event.get("data")
                && let Ok(create) = serde_json::from_value::<CreateAccountEvent>(data.clone())
            {
                println!("    Created account: {}", create.created);
            }

            // Show raw data for debugging
            if let Some(data) = event.get("data") {
                println!("    Raw data: {}", serde_json::to_string(data)?);
            }
        }
    }

    // ==== Part 3: Query Events by Event Handle ====
    println!("\n=== Part 3: Query Deposit Events for Account ===");

    // Query deposit events for the recipient
    let events = aptos
        .fullnode()
        .get_events_by_event_handle(
            recipient.address(),
            "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
            "deposit_events",
            Some(0),  // Start from sequence 0
            Some(10), // Get up to 10 events
        )
        .await;

    match events {
        Ok(response) => {
            println!(
                "Found {} deposit events for recipient:",
                response.data.len()
            );
            for event in &response.data {
                if let Some(data) = event.get("data") {
                    let amount = data.get("amount").and_then(|v| v.as_str()).unwrap_or("0");
                    let amount: u64 = amount.parse().unwrap_or(0);
                    println!("  - Deposit: {} APT", amount as f64 / 100_000_000.0);
                }
            }
        }
        Err(e) => {
            println!(
                "Could not get events (account may not have CoinStore): {}",
                e
            );
        }
    }

    // ==== Part 4: Get Transaction by Version ====
    println!("\n=== Part 4: Query Transactions ===");

    // Get the ledger info to find recent transaction version
    let ledger_info = aptos.ledger_info().await?;
    println!("Current ledger version: {}", ledger_info.version());

    // Get a recent block
    let block = aptos
        .fullnode()
        .get_block_by_height(ledger_info.height(), true)
        .await?;

    if let Some(transactions) = block.data.get("transactions").and_then(|v| v.as_array()) {
        println!(
            "Block {} contains {} transactions",
            ledger_info.height(),
            transactions.len()
        );

        // Show first few transaction types
        for (i, txn) in transactions.iter().take(5).enumerate() {
            let txn_type = txn
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let success = txn
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            println!("  {}: {} (success: {})", i + 1, txn_type, success);
        }
    }

    // ==== Part 5: Get Account Resources ====
    println!("\n=== Part 5: Get Account Resources ===");

    let resources = aptos
        .fullnode()
        .get_account_resources(sender.address())
        .await?;

    println!("Account has {} resources:", resources.data.len());
    for resource in &resources.data {
        println!("  - {}", resource.typ);
    }

    // Get specific coin balance
    let apt_resource = aptos
        .fullnode()
        .get_account_resource(
            sender.address(),
            "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
        )
        .await?;

    if let Some(coin) = apt_resource.data.data.get("coin")
        && let Some(value) = coin.get("value").and_then(|v| v.as_str())
    {
        let balance: u64 = value.parse().unwrap_or(0);
        println!(
            "\nSender APT balance: {} APT ({} octas)",
            balance as f64 / 100_000_000.0,
            balance
        );
    }

    // ==== Part 6: Get Transaction by Hash (lookup previously submitted) ====
    println!("\n=== Part 6: Lookup Transaction by Hash ===");

    let lookup = aptos.fullnode().get_transaction_by_hash(&txn_hash).await?;
    println!("Re-fetched transaction:");
    println!(
        "  Timestamp: {}",
        lookup
            .data
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A")
    );
    println!(
        "  Expiration: {}",
        lookup
            .data
            .get("expiration_timestamp_secs")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A")
    );

    // Parse the payload to see what the transaction did
    if let Some(payload) = lookup.data.get("payload") {
        println!(
            "  Payload type: {}",
            payload
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A")
        );
        println!(
            "  Function: {}",
            payload
                .get("function")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A")
        );

        if let Some(args) = payload.get("arguments").and_then(|v| v.as_array()) {
            println!("  Arguments: {:?}", args);
        }
    }

    println!("\n✓ All transaction data examples completed!");
    Ok(())
}
