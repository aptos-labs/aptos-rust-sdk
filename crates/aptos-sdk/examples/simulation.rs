//! Example: Transaction Simulation
//!
//! This example demonstrates how to:
//! 1. Simulate transactions before sending
//! 2. Estimate gas costs accurately
//! 3. Detect failures before spending gas
//! 4. Analyze simulation results
//!
//! Run with: `cargo run --example simulation --features "ed25519,faucet"`

use aptos_sdk::{
    Aptos, AptosConfig,
    account::Ed25519Account,
    transaction::{EntryFunction, TransactionBuilder},
    types::TypeTag,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Transaction Simulation Example ===\n");

    // Setup
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet");

    // Create and fund accounts
    let sender = Ed25519Account::generate();
    let recipient = Ed25519Account::generate();
    println!("Sender:    {}", sender.address());
    println!("Recipient: {}", recipient.address());

    // Fund the sender
    println!("\nFunding sender account...");
    aptos.fund_account(sender.address(), 100_000_000).await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let balance = aptos.get_balance(sender.address()).await?;
    println!("Sender balance: {} APT", balance as f64 / 100_000_000.0);

    // 1. Simulate a valid transfer
    println!("\n--- 1. Simulating a Valid Transfer ---");
    {
        let transfer_amount = 10_000_000u64; // 0.1 APT
        let payload = EntryFunction::apt_transfer(recipient.address(), transfer_amount)?;

        println!(
            "Simulating transfer of {} APT...",
            transfer_amount as f64 / 100_000_000.0
        );
        let result = aptos.simulate(&sender, payload.into()).await?;

        println!("\nSimulation Result:");
        println!("  Success:      {}", result.success());
        println!("  Gas Used:     {} units", result.gas_used());
        println!("  Gas Price:    {} octas/unit", result.gas_unit_price());
        println!(
            "  Total Cost:   {} APT",
            (result.gas_used() * result.gas_unit_price()) as f64 / 100_000_000.0
        );

        if result.success() {
            println!("\n✓ Transaction will succeed!");
            println!("  Events emitted: {}", result.events().len());
            println!("  State changes:  {}", result.changes().len());
        }
    }

    // 2. Simulate with insufficient balance
    println!("\n--- 2. Simulating Transfer with Insufficient Balance ---");
    {
        // Try to send more than we have
        let huge_amount = 1_000_000_000_000u64; // 10,000 APT
        let payload = EntryFunction::apt_transfer(recipient.address(), huge_amount)?;

        println!(
            "Simulating transfer of {} APT (more than balance)...",
            huge_amount as f64 / 100_000_000.0
        );
        let result = aptos.simulate(&sender, payload.into()).await?;

        println!("\nSimulation Result:");
        println!("  Success:    {}", result.success());
        println!("  VM Status:  {}", result.vm_status());

        if !result.success() {
            println!("\n✗ Transaction would fail!");
            println!("  This saved you gas fees by detecting the failure before submission.");
        }
    }

    // 3. Simulate with custom gas settings
    println!("\n--- 3. Simulation with Custom Gas Settings ---");
    {
        let payload = EntryFunction::apt_transfer(recipient.address(), 1_000_000)?;
        let seq_num = aptos.get_sequence_number(sender.address()).await?;

        // Build transaction with custom gas
        let raw_txn = TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(seq_num)
            .payload(payload.into())
            .chain_id(aptos.chain_id())
            .max_gas_amount(500) // Intentionally low
            .gas_unit_price(100)
            .expiration_from_now(600)
            .build()?;

        // Sign it
        let signed = aptos_sdk::transaction::builder::sign_transaction(&raw_txn, &sender)?;

        println!("Simulating with very low max_gas_amount (500 units)...");
        let result = aptos.simulate_signed(&signed).await?;

        println!("\nSimulation Result:");
        println!("  Success:        {}", result.success());
        println!("  Max Gas Set:    {} units", result.max_gas_amount());
        println!("  Gas Used:       {} units", result.gas_used());

        if !result.success() && result.vm_status().contains("OUT_OF_GAS") {
            println!("\n✗ Transaction would run out of gas!");
            println!(
                "  Suggestion: Increase max_gas_amount to at least {}",
                result.gas_used() + 100
            );
        }
    }

    // 4. Use gas estimation
    println!("\n--- 4. Using Gas Estimation ---");
    {
        let payload = EntryFunction::apt_transfer(recipient.address(), 5_000_000)?;

        println!("Getting gas estimate for transfer...");
        let estimated_gas = aptos.estimate_gas(&sender, payload.clone().into()).await?;

        println!("\nGas Estimation:");
        println!("  Estimated gas (with 20% buffer): {} units", estimated_gas);

        // Now submit the transaction
        println!("\nSubmitting transaction...");
        let txn_result = aptos
            .sign_submit_and_wait(&sender, payload.into(), None)
            .await?;

        let actual_gas = txn_result
            .data
            .get("gas_used")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        println!("  Actual gas used:    {} units", actual_gas);
        println!("  Estimated was:      {} units", estimated_gas);
    }

    // 5. Simulate to check contract state
    println!("\n--- 5. Simulation for Pre-flight Checks ---");
    {
        // Simulate a coin registration to check if already registered
        let payload = EntryFunction::new(
            "0x1::managed_coin".parse()?,
            "register",
            vec![TypeTag::aptos_coin()],
            vec![],
        );

        println!("Checking if APT coin store needs registration...");
        let result = aptos.simulate(&sender, payload.into()).await?;

        if result.success() {
            println!("  Coin store registration would succeed (not yet registered)");
        } else if result.vm_status().contains("RESOURCE_ALREADY_EXISTS") {
            println!("  Coin store already registered (no action needed)");
        } else {
            println!("  Registration would fail: {}", result.vm_status());
        }
    }

    println!("\n--- Summary ---");
    println!("Transaction simulation is useful for:");
    println!("  • Validating transactions before submission");
    println!("  • Getting accurate gas estimates");
    println!("  • Detecting errors without spending gas");
    println!("  • Checking state conditions before execution");
    println!("  • Debugging failed transaction logic");

    println!("\n=== Transaction Simulation Example Complete ===");

    Ok(())
}
