//! Example: Event Queries
//!
//! This example demonstrates how to:
//! 1. Get events emitted by transactions
//! 2. Query events by event handle
//!
//! Run with: `cargo run --example event_queries --features "ed25519,faucet"`

use aptos_rust_sdk_v2::{Aptos, AptosConfig, account::Ed25519Account, types::AccountAddress};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Event Queries Example ===\n");

    // Setup
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet");

    // Create and fund accounts
    let sender = Ed25519Account::generate();
    let recipient = Ed25519Account::generate();
    println!("Sender:    {}", sender.address());
    println!("Recipient: {}", recipient.address());

    // Fund both accounts
    println!("\nFunding accounts...");
    aptos.fund_account(sender.address(), 100_000_000).await?;
    aptos.fund_account(recipient.address(), 10_000_000).await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // 1. Execute a transfer and get events from the result
    println!("\n--- 1. Events from Transaction Result ---");
    {
        let transfer_amount = 5_000_000u64; // 0.05 APT

        println!(
            "Executing transfer of {} APT...",
            transfer_amount as f64 / 100_000_000.0
        );
        let result = aptos
            .transfer_apt(&sender, recipient.address(), transfer_amount)
            .await?;

        // Parse events from the transaction result
        if let Some(events) = result
            .data
            .get("events")
            .and_then(serde_json::Value::as_array)
        {
            println!("\nEvents emitted ({} total):", events.len());
            for (i, event) in events.iter().enumerate() {
                let event_type = event
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                println!("\n  Event {}:", i + 1);
                println!("    Type: {}", event_type);

                // Parse event data
                if let Some(data) = event.get("data")
                    && let Some(amount) = data.get("amount").and_then(serde_json::Value::as_str)
                {
                    println!("    Amount: {} octas", amount);
                }

                // Show sequence number
                if let Some(seq) = event
                    .get("sequence_number")
                    .and_then(serde_json::Value::as_str)
                {
                    println!("    Sequence: {}", seq);
                }
            }
        }
    }

    // 2. Query events by event handle
    println!("\n--- 2. Query Deposit Events by Handle ---");
    {
        println!("Querying deposit events for recipient...");
        match aptos
            .fullnode()
            .get_events_by_event_handle(
                recipient.address(),
                "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
                "deposit_events",
                None,     // start
                Some(10), // limit
            )
            .await
        {
            Ok(response) => {
                let events = response.data;
                println!("Found {} deposit event(s):", events.len());
                for (i, event) in events.iter().enumerate() {
                    if let Some(data) = event.get("data") {
                        let amount = data
                            .get("amount")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("?");
                        println!("  {}. Deposit: {} octas", i + 1, amount);
                    }
                }
            }
            Err(e) => println!("  Could not fetch events: {}", e),
        }
    }

    // 3. Query withdraw events
    println!("\n--- 3. Query Withdraw Events by Handle ---");
    {
        println!("Querying withdraw events for sender...");
        match aptos
            .fullnode()
            .get_events_by_event_handle(
                sender.address(),
                "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
                "withdraw_events",
                None,     // start
                Some(10), // limit
            )
            .await
        {
            Ok(response) => {
                let events = response.data;
                println!("Found {} withdraw event(s):", events.len());
                for (i, event) in events.iter().enumerate() {
                    if let Some(data) = event.get("data") {
                        let amount = data
                            .get("amount")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("?");
                        println!("  {}. Withdraw: {} octas", i + 1, amount);
                    }
                }
            }
            Err(e) => println!("  Could not fetch events: {}", e),
        }
    }

    // 4. Account activity summary
    println!("\n--- 4. Account Activity Summary ---");
    {
        println!("\nSender account:");
        print_account_event_summary(&aptos, sender.address()).await?;

        println!("\nRecipient account:");
        print_account_event_summary(&aptos, recipient.address()).await?;
    }

    println!("\n--- Summary ---");
    println!("Events are useful for:");
    println!("  • Tracking token transfers");
    println!("  • Monitoring account activity");
    println!("  • Building transaction history");
    println!("  • Auditing contract interactions");

    println!("\n=== Event Queries Example Complete ===");

    Ok(())
}

async fn print_account_event_summary(aptos: &Aptos, address: AccountAddress) -> anyhow::Result<()> {
    // Count deposits
    let deposits = aptos
        .fullnode()
        .get_events_by_event_handle(
            address,
            "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
            "deposit_events",
            None,
            Some(100),
        )
        .await
        .map(|r| r.data.len())
        .unwrap_or(0);

    // Count withdrawals
    let withdrawals = aptos
        .fullnode()
        .get_events_by_event_handle(
            address,
            "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
            "withdraw_events",
            None,
            Some(100),
        )
        .await
        .map(|r| r.data.len())
        .unwrap_or(0);

    println!("  Address: {}", address);
    println!("  Deposit events:  {}", deposits);
    println!("  Withdraw events: {}", withdrawals);

    Ok(())
}
