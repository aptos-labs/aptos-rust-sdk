//! Example: Deploy a Move module
//!
//! This example demonstrates the structure for deploying a Move module.
//! Note: You need to compile a Move module first to get the bytecode.
//!
//! Run with: `cargo run --example deploy_module --features "ed25519,faucet"`

use aptos_sdk::{Aptos, AptosConfig, account::Ed25519Account};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create client for testnet
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet");

    // Generate an account to deploy from
    let deployer = Ed25519Account::generate();
    println!("Deployer address: {}", deployer.address());

    // Fund the deployer account
    println!("\nFunding deployer account...");
    aptos.fund_account(deployer.address(), 100_000_000).await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // In a real deployment, you would:
    // 1. Compile your Move module using `aptos move compile`
    // 2. Read the compiled bytecode
    // 3. Create a publish transaction

    println!("\n=== Module Deployment Guide ===");
    println!("\nTo deploy a Move module:");
    println!("1. Create your Move module in a directory with Move.toml");
    println!("2. Compile with: aptos move compile --save-metadata");
    println!("3. Read the .mv bytecode file");
    println!("4. Use the code::publish_package_txn entry function");
    println!();

    // Show example code for deployment
    println!("Example code for deployment:");
    println!(
        r#"
    use std::fs;
    use aptos_sdk::transaction::{EntryFunction, TransactionBuilder};
    use aptos_sdk::types::MoveModuleId;
    
    // Read compiled module bytecode
    let module_bytecode = fs::read("build/MyModule/bytecode_modules/my_module.mv")?;
    let metadata = fs::read("build/MyModule/package-metadata.bcs")?;
    
    // Create publish payload using code::publish_package_txn
    // Note: metadata and module_bytecode are already byte vectors read from disk,
    // they are passed directly as entry function arguments (vector<u8>)
    let payload = EntryFunction::new(
        MoveModuleId::from_str_strict("0x1::code")?,
        "publish_package_txn",
        vec![],
        vec![
            metadata,
            vec![module_bytecode],
        ],
    );
    
    // Submit the transaction
    let result = aptos.sign_submit_and_wait(&deployer, payload.into(), None).await?;
    "#
    );
    println!();

    // For now, just demonstrate querying account modules
    println!("=== Checking Modules ===");
    println!("Checking modules at deployer address...");
    let response = aptos
        .fullnode()
        .get_account_modules(deployer.address())
        .await;

    match response {
        Ok(modules) => {
            println!("Found {} modules", modules.data.len());
            for module in &modules.data {
                if let Some(abi) = &module.abi {
                    println!("  - {}::{}", abi.address, abi.name);
                }
            }
        }
        Err(e) if e.is_not_found() => {
            println!("No modules found (account is new, which is expected)");
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    // Show modules on the framework address as an example
    println!("\nExample: Framework modules at 0x1:");
    let framework_modules = aptos.fullnode().get_account_modules("0x1".parse()?).await?;

    println!("Found {} framework modules", framework_modules.data.len());
    for module in framework_modules.data.iter().take(10) {
        if let Some(abi) = &module.abi {
            let entry_count = abi.exposed_functions.iter().filter(|f| f.is_entry).count();
            let view_count = abi.exposed_functions.iter().filter(|f| f.is_view).count();
            println!(
                "  - {} ({} entry, {} view functions)",
                abi.name, entry_count, view_count
            );
        }
    }
    println!(
        "  ... and {} more modules",
        framework_modules.data.len().saturating_sub(10)
    );

    Ok(())
}
