//! Example: Calling smart contract entry functions
//!
//! This example demonstrates how to:
//! 1. Build a transaction that calls an entry function on a smart contract
//! 2. Pass typed arguments to the function
//! 3. Handle the response
//!
//! Run with: `cargo run --example call_contract --features "ed25519,faucet"`

use aptos_rust_sdk_v2::{
    Aptos, AptosConfig,
    account::Ed25519Account,
    transaction::{EntryFunction, TransactionBuilder, TransactionPayload},
    types::{AccountAddress, MoveModuleId, TypeTag},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create client for testnet
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet");

    // Generate and fund an account
    let account = aptos.create_funded_account(100_000_000).await?;
    println!("Account: {}", account.address());

    // Example 1: Call 0x1::aptos_account::transfer (simple APT transfer)
    println!("\n=== Example 1: Simple APT Transfer ===");
    {
        let recipient = Ed25519Account::generate();
        let amount: u64 = 1_000_000; // 0.01 APT

        let payload = EntryFunction::new(
            MoveModuleId::from_str_strict("0x1::aptos_account")?,
            "transfer",
            vec![], // No type arguments
            vec![
                aptos_bcs::to_bytes(&recipient.address())?,
                aptos_bcs::to_bytes(&amount)?,
            ],
        );

        let result = aptos
            .sign_submit_and_wait(&account, payload.into(), None)
            .await?;

        println!("Transfer successful!");
        println!(
            "  Version: {}",
            result
                .data
                .get("version")
                .unwrap_or(&serde_json::json!("N/A"))
        );
        println!(
            "  Gas used: {}",
            result
                .data
                .get("gas_used")
                .unwrap_or(&serde_json::json!("N/A"))
        );
    }

    // Example 2: Call 0x1::coin::transfer with type arguments
    println!("\n=== Example 2: Coin Transfer with Type Arguments ===");
    {
        let recipient = Ed25519Account::generate();
        let amount: u64 = 500_000; // 0.005 APT

        // This is equivalent to: 0x1::coin::transfer<0x1::aptos_coin::AptosCoin>(recipient, amount)
        let payload = EntryFunction::new(
            MoveModuleId::from_str_strict("0x1::coin")?,
            "transfer",
            vec![TypeTag::aptos_coin()], // Type argument: AptosCoin
            vec![
                aptos_bcs::to_bytes(&recipient.address())?,
                aptos_bcs::to_bytes(&amount)?,
            ],
        );

        let result = aptos
            .sign_submit_and_wait(&account, payload.into(), None)
            .await?;

        println!("Coin transfer successful!");
        println!(
            "  Version: {}",
            result
                .data
                .get("version")
                .unwrap_or(&serde_json::json!("N/A"))
        );
    }

    // Example 3: Call a contract with multiple arguments
    println!("\n=== Example 3: Register Coin (if not already registered) ===");
    {
        // Check if already registered
        let resource_result = aptos
            .fullnode()
            .get_account_resource(
                account.address(),
                "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
            )
            .await;

        match resource_result {
            Ok(_) => println!("  APT CoinStore already registered"),
            Err(e) if e.is_not_found() => {
                // Register the coin store since it doesn't exist
                let payload = EntryFunction::new(
                    MoveModuleId::from_str_strict("0x1::managed_coin")?,
                    "register",
                    vec![TypeTag::aptos_coin()],
                    vec![], // No arguments besides type arg
                );

                let result = aptos
                    .sign_submit_and_wait(&account, payload.into(), None)
                    .await?;

                println!("  Registered APT CoinStore");
                println!(
                    "  Version: {}",
                    result
                        .data
                        .get("version")
                        .unwrap_or(&serde_json::json!("N/A"))
                );
            }
            Err(e) => {
                // Propagate other errors (network issues, etc.)
                return Err(e.into());
            }
        }
    }

    // Example 4: Call with string argument (for a hypothetical contract)
    println!("\n=== Example 4: Demonstrating BCS Encoding of Various Types ===");
    {
        // This shows how to encode different argument types
        // (The actual call is commented out since we don't have a target contract)

        // String argument
        let name = "My Token".to_string();
        let _name_bytes = aptos_bcs::to_bytes(&name)?;
        println!("  String '{}' encoded to {} bytes", name, _name_bytes.len());

        // Boolean argument
        let flag = true;
        let _flag_bytes = aptos_bcs::to_bytes(&flag)?;
        println!("  Bool {} encoded to {} bytes", flag, _flag_bytes.len());

        // Vector<u8> (bytes)
        let data = vec![1u8, 2, 3, 4, 5];
        let _data_bytes = aptos_bcs::to_bytes(&data)?;
        println!(
            "  Vec<u8> {:?} encoded to {} bytes",
            data,
            _data_bytes.len()
        );

        // Vector<address>
        let addresses = vec![AccountAddress::ONE, AccountAddress::THREE];
        let _addresses_bytes = aptos_bcs::to_bytes(&addresses)?;
        println!(
            "  Vec<address> of {} items encoded to {} bytes",
            addresses.len(),
            _addresses_bytes.len()
        );

        // u128 (for large numbers)
        let large_amount: u128 = 1_000_000_000_000_000_000;
        let _large_bytes = aptos_bcs::to_bytes(&large_amount)?;
        println!(
            "  u128 {} encoded to {} bytes",
            large_amount,
            _large_bytes.len()
        );
    }

    // Example 5: Building a complex transaction with custom gas settings
    println!("\n=== Example 5: Custom Gas Settings ===");
    {
        let recipient = Ed25519Account::generate();

        // Get current gas price
        let gas_estimate = aptos.fullnode().estimate_gas_price().await?;
        println!(
            "  Current gas estimate: {} octas",
            gas_estimate.data.gas_estimate
        );

        // Build transaction with custom settings
        let payload = EntryFunction::apt_transfer(recipient.address(), 100_000)?;
        let sequence_number = aptos.get_sequence_number(account.address()).await?;

        let raw_txn = TransactionBuilder::new()
            .sender(account.address())
            .sequence_number(sequence_number)
            .payload(TransactionPayload::EntryFunction(payload))
            .max_gas_amount(50_000) // Lower than default
            .gas_unit_price(gas_estimate.data.high()) // Use high priority gas
            .chain_id(aptos.chain_id())
            .expiration_from_now(300) // 5 minutes
            .build()?;

        let signed = aptos_rust_sdk_v2::transaction::builder::sign_transaction(&raw_txn, &account)?;

        // Simulate first to check gas
        let simulation = aptos.simulate_transaction(&signed).await?;
        if let Some(sim_result) = simulation.data.first() {
            println!(
                "  Simulation gas used: {}",
                sim_result
                    .get("gas_used")
                    .unwrap_or(&serde_json::json!("N/A"))
            );
            println!(
                "  Simulation success: {}",
                sim_result
                    .get("success")
                    .unwrap_or(&serde_json::json!("N/A"))
            );
        }

        // Submit the real transaction
        let result = aptos.submit_and_wait(&signed, None).await?;
        println!(
            "  Actual gas used: {}",
            result
                .data
                .get("gas_used")
                .unwrap_or(&serde_json::json!("N/A"))
        );
    }

    println!("\n✓ All examples completed successfully!");
    Ok(())
}
