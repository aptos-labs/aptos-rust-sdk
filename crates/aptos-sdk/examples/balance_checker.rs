//! Example: Balance Checker Utility
//!
//! This example demonstrates a practical utility for:
//! 1. Checking APT balance for any address
//! 2. Checking multiple accounts at once
//! 3. Watching for balance changes
//!
//! Run with: `cargo run --example balance_checker --features "ed25519,faucet"`

use aptos_sdk::{Aptos, AptosConfig, account::Ed25519Account, types::AccountAddress};
use std::time::Duration;

const OCTAS_PER_APT: f64 = 100_000_000.0;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Balance Checker Utility ===\n");

    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet\n");

    // 1. Check balance of a known address
    println!("--- 1. Check Single Address ---");
    {
        // Aptos Framework address
        let framework_addr = AccountAddress::ONE;
        check_balance(&aptos, framework_addr, "Aptos Framework").await?;
    }

    // 2. Check multiple addresses
    println!("\n--- 2. Check Multiple Addresses ---");
    {
        let addresses = vec![
            (AccountAddress::ONE, "Aptos Framework (0x1)"),
            (AccountAddress::THREE, "Aptos Token (0x3)"),
            (AccountAddress::FOUR, "Aptos Token Objects (0x4)"),
        ];

        println!("Checking {} addresses...\n", addresses.len());

        let mut total = 0u64;
        for (addr, name) in addresses {
            if let Ok(balance) = aptos.get_balance(addr).await {
                println!("  {}: {} APT", name, format_apt(balance));
                total += balance;
            } else {
                println!("  {}: Account not found or no balance", name);
            }
        }

        println!("\n  Total: {} APT", format_apt(total));
    }

    // 3. Watch balance changes
    println!("\n--- 3. Watch Balance Changes ---");
    {
        // Create a test account
        let account = Ed25519Account::generate();
        println!("Created test account: {}", account.address());

        // Fund it
        println!("Funding account with 1 APT...");
        aptos.fund_account(account.address(), 100_000_000).await?;
        tokio::time::sleep(Duration::from_secs(2)).await;

        let initial_balance = aptos.get_balance(account.address()).await.unwrap_or(0);
        println!("Initial balance: {} APT", format_apt(initial_balance));

        // Do a transfer to change balance
        let recipient = Ed25519Account::generate();
        println!("\nTransferring 0.1 APT...");
        aptos
            .transfer_apt(&account, recipient.address(), 10_000_000)
            .await?;

        // Check new balance
        let new_balance = aptos.get_balance(account.address()).await.unwrap_or(0);
        println!("New balance: {} APT", format_apt(new_balance));

        let change = initial_balance as i64 - new_balance as i64;
        println!(
            "Change: -{} APT (transfer + gas)",
            format_apt(change.unsigned_abs())
        );
    }

    // 4. Balance with account info
    println!("\n--- 4. Account Details ---");
    {
        let account = Ed25519Account::generate();
        aptos.fund_account(account.address(), 50_000_000).await?;
        tokio::time::sleep(Duration::from_secs(2)).await;

        print_account_details(&aptos, account.address()).await?;
    }

    // 5. Check if account exists
    println!("\n--- 5. Account Existence Check ---");
    {
        // Check a real account
        let real_addr = AccountAddress::ONE;
        let exists = check_account_exists(&aptos, real_addr).await;
        println!("  0x1 exists: {}", exists);

        // Check a random (likely non-existent) account
        let random_account = Ed25519Account::generate();
        let exists = check_account_exists(&aptos, random_account.address()).await;
        println!("  Random address exists: {}", exists);
    }

    println!("\n--- Summary ---");
    println!("This utility demonstrates:");
    println!("  • Checking APT balances for any address");
    println!("  • Batch checking multiple accounts");
    println!("  • Tracking balance changes");
    println!("  • Querying account details");

    println!("\n=== Balance Checker Complete ===");

    Ok(())
}

fn format_apt(octas: u64) -> String {
    let apt = octas as f64 / OCTAS_PER_APT;
    if apt >= 1.0 {
        format!("{:.4}", apt)
    } else if apt >= 0.0001 {
        format!("{:.6}", apt)
    } else {
        format!("{:.8}", apt)
    }
}

async fn check_balance(aptos: &Aptos, address: AccountAddress, name: &str) -> anyhow::Result<u64> {
    match aptos.get_balance(address).await {
        Ok(balance) => {
            println!("  {}", name);
            println!("    Address: {}", address);
            println!(
                "    Balance: {} APT ({} octas)",
                format_apt(balance),
                balance
            );
            Ok(balance)
        }
        Err(e) => {
            println!("  {}", name);
            println!("    Address: {}", address);
            println!("    Error: {}", e);
            Err(e.into())
        }
    }
}

async fn print_account_details(aptos: &Aptos, address: AccountAddress) -> anyhow::Result<()> {
    println!("Account: {}", address);

    // Get balance
    let balance = aptos.get_balance(address).await.unwrap_or(0);
    println!("  Balance: {} APT", format_apt(balance));

    // Get sequence number
    let seq_num = aptos.get_sequence_number(address).await.unwrap_or(0);
    println!("  Sequence Number: {}", seq_num);

    Ok(())
}

async fn check_account_exists(aptos: &Aptos, address: AccountAddress) -> bool {
    aptos.get_sequence_number(address).await.is_ok()
}
