//! Example: Reading smart contract state
//!
//! This example demonstrates how to:
//! 1. Read resources from an account
//! 2. Call view functions to read contract state
//! 3. Parse Move struct data
//! 4. Work with different resource types
//!
//! Run with: `cargo run --example read_contract_state --features ed25519`

use aptos_rust_sdk_v2::{types::AccountAddress, Aptos, AptosConfig};
use serde::Deserialize;

/// CoinStore resource structure
#[derive(Debug, Deserialize)]
struct CoinStore {
    coin: Coin,
    frozen: bool,
}

#[derive(Debug, Deserialize)]
struct Coin {
    value: String,
}

/// Account resource structure
#[derive(Debug, Deserialize)]
struct AccountResource {
    authentication_key: String,
    sequence_number: String,
}

/// Staking pool resource (partial)
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields required for deserialization
struct StakePool {
    active: CoinValue,
    inactive: CoinValue,
    pending_active: CoinValue,
    pending_inactive: CoinValue,
    operator_address: String,
}

#[derive(Debug, Deserialize)]
struct CoinValue {
    value: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create client for mainnet to read real data
    let aptos = Aptos::new(AptosConfig::mainnet())?;
    println!("Connected to mainnet");

    // ==== Part 1: Read Account Resource ====
    println!("\n=== Part 1: Read Account Resource ===");

    let framework_addr = AccountAddress::ONE;
    let account_resource = aptos
        .fullnode()
        .get_account_resource(framework_addr, "0x1::account::Account")
        .await?;

    let account: AccountResource = serde_json::from_value(account_resource.data.data.clone())?;
    println!("Framework account (0x1):");
    println!("  Auth key: {}...", &account.authentication_key[..20]);
    println!("  Sequence number: {}", account.sequence_number);

    // ==== Part 2: Read Coin Balance ====
    println!("\n=== Part 2: Read Coin Balance ===");

    // Read a well-known address with APT
    let rich_addr = AccountAddress::from_hex(
        "0x0000000000000000000000000000000000000000000000000000000000000001",
    )?;

    match aptos
        .fullnode()
        .get_account_resource(
            rich_addr,
            "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
        )
        .await
    {
        Ok(resource) => {
            let coin_store: CoinStore = serde_json::from_value(resource.data.data.clone())?;
            let balance: u64 = coin_store.coin.value.parse().unwrap_or(0);
            println!("Address {} APT balance:", rich_addr.to_short_string());
            println!("  {} APT ({} octas)", balance as f64 / 100_000_000.0, balance);
            println!("  Frozen: {}", coin_store.frozen);
        }
        Err(e) => {
            println!("Could not read coin store: {}", e);
        }
    }

    // ==== Part 3: Call View Functions ====
    println!("\n=== Part 3: Call View Functions ===");

    // Get current timestamp
    let timestamp = aptos
        .view("0x1::timestamp::now_seconds", vec![], vec![])
        .await?;
    println!("Current blockchain timestamp: {:?} seconds", timestamp);

    // Get total APT supply
    let supply = aptos
        .view(
            "0x1::coin::supply",
            vec!["0x1::aptos_coin::AptosCoin".to_string()],
            vec![],
        )
        .await?;
    println!("APT total supply: {:?}", supply);

    // Check if an address is an account
    let is_account = aptos
        .view(
            "0x1::account::exists_at",
            vec![],
            vec![serde_json::json!("0x1")],
        )
        .await?;
    println!("Is 0x1 an account: {:?}", is_account);

    // Get account sequence number via view
    let seq_num = aptos
        .view(
            "0x1::account::get_sequence_number",
            vec![],
            vec![serde_json::json!("0x1")],
        )
        .await?;
    println!("Framework sequence number: {:?}", seq_num);

    // ==== Part 4: Read Staking Info (if exists) ====
    println!("\n=== Part 4: Read Staking Resources ===");

    // Try to read stake pool from a known validator (this may or may not exist)
    // Using a placeholder address - in real usage you'd use an actual validator address
    let validator_addr = AccountAddress::from_hex(
        "0x0000000000000000000000000000000000000000000000000000000000000001",
    )?;

    match aptos
        .fullnode()
        .get_account_resource(validator_addr, "0x1::stake::StakePool")
        .await
    {
        Ok(resource) => {
            let stake_pool: StakePool = serde_json::from_value(resource.data.data.clone())?;
            let active: u64 = stake_pool.active.value.parse().unwrap_or(0);
            let inactive: u64 = stake_pool.inactive.value.parse().unwrap_or(0);
            println!("Stake pool for {}:", validator_addr.to_short_string());
            println!("  Active stake: {} APT", active as f64 / 100_000_000.0);
            println!("  Inactive stake: {} APT", inactive as f64 / 100_000_000.0);
            println!("  Operator: {}", stake_pool.operator_address);
        }
        Err(_) => {
            println!("No stake pool found at {}", validator_addr.to_short_string());
        }
    }

    // ==== Part 5: List All Resources ====
    println!("\n=== Part 5: List All Account Resources ===");

    let all_resources = aptos
        .fullnode()
        .get_account_resources(framework_addr)
        .await?;

    println!(
        "Framework account has {} resources:",
        all_resources.data.len()
    );
    for resource in all_resources.data.iter().take(10) {
        println!("  - {}", resource.typ);
    }
    if all_resources.data.len() > 10 {
        println!("  ... and {} more", all_resources.data.len() - 10);
    }

    // ==== Part 6: Read Module ABI ====
    println!("\n=== Part 6: Read Module Information ===");

    let coin_module = aptos
        .fullnode()
        .get_account_module(framework_addr, "coin")
        .await?;

    if let Some(abi) = &coin_module.data.abi {
        println!("Module 0x1::coin:");
        println!("  Structs: {}", abi.structs.len());
        for struct_def in abi.structs.iter().take(5) {
            println!("    - {}", struct_def.name);
        }

        let entry_functions: Vec<_> = abi
            .exposed_functions
            .iter()
            .filter(|f| f.is_entry)
            .collect();
        println!("  Entry functions: {}", entry_functions.len());
        for func in entry_functions.iter().take(5) {
            println!("    - {}", func.name);
        }

        let view_functions: Vec<_> = abi
            .exposed_functions
            .iter()
            .filter(|f| f.is_view)
            .collect();
        println!("  View functions: {}", view_functions.len());
        for func in view_functions.iter().take(5) {
            println!("    - {} -> {:?}", func.name, func.returns);
        }
    }

    // ==== Part 7: Complex View Function with Multiple Returns ====
    println!("\n=== Part 7: Complex View Function ===");

    // Get coin info
    let coin_info = aptos
        .view(
            "0x1::coin::name",
            vec!["0x1::aptos_coin::AptosCoin".to_string()],
            vec![],
        )
        .await?;
    println!("APT coin name: {:?}", coin_info);

    let coin_symbol = aptos
        .view(
            "0x1::coin::symbol",
            vec!["0x1::aptos_coin::AptosCoin".to_string()],
            vec![],
        )
        .await?;
    println!("APT coin symbol: {:?}", coin_symbol);

    let coin_decimals = aptos
        .view(
            "0x1::coin::decimals",
            vec!["0x1::aptos_coin::AptosCoin".to_string()],
            vec![],
        )
        .await?;
    println!("APT coin decimals: {:?}", coin_decimals);

    println!("\n✓ All contract state reading examples completed!");
    Ok(())
}

