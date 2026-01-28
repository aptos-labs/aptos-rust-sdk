//! Example: Aptos Names Service (ANS)
//!
//! This example demonstrates how to:
//! 1. Resolve .apt names to addresses
//! 2. Look up primary name for an address
//! 3. Handle ANS in transactions
//!
//! Note: ANS is only available on mainnet and testnet.
//!
//! Run with: `cargo run --example ans_names --features "ed25519"`

use aptos_rust_sdk_v2::{Aptos, AptosConfig, types::AccountAddress};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Aptos Names Service (ANS) Example ===\n");

    // Connect to testnet (ANS available on testnet and mainnet)
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet");

    // 1. Resolve a .apt name to address
    println!("\n--- 1. Resolve Name to Address ---");
    {
        let names_to_resolve = vec![
            "aptos.apt",
            "test.apt",
            "alice.apt",
            "nonexistent-random-name-12345.apt",
        ];

        for name in names_to_resolve {
            print!("  {} -> ", name);
            match aptos.resolve_name(name).await? {
                Some(address) => println!("{}", address),
                None => println!("(not registered)"),
            }
        }
    }

    // 2. Look up primary name for an address
    println!("\n--- 2. Reverse Lookup (Address to Name) ---");
    {
        // Try to find names for some addresses
        let addresses_to_check = vec![AccountAddress::ONE, AccountAddress::THREE];

        for addr in addresses_to_check {
            print!("  {} -> ", addr);
            match aptos.get_primary_name(addr).await? {
                Some(name) => println!("{}", name),
                None => println!("(no primary name)"),
            }
        }
    }

    // 3. Demonstrate name resolution in context
    println!("\n--- 3. Using Names in Transactions ---");
    {
        // In a real app, you might want to support both names and addresses
        let user_input = "aptos.apt"; // This could come from user input

        println!("User entered: '{}'", user_input);

        let resolved_address = if user_input.ends_with(".apt") {
            // It's a name, resolve it
            match aptos.resolve_name(user_input).await? {
                Some(addr) => {
                    println!("  Resolved to: {}", addr);
                    Some(addr)
                }
                None => {
                    println!("  Name not found!");
                    None
                }
            }
        } else {
            // Try to parse as address
            match user_input.parse::<AccountAddress>() {
                Ok(addr) => {
                    println!("  Parsed as address: {}", addr);
                    Some(addr)
                }
                Err(_) => {
                    println!("  Invalid address format!");
                    None
                }
            }
        };

        if let Some(addr) = resolved_address {
            // Now you can use this address for transactions
            println!("  Ready to use address: {}", addr);
        }
    }

    // 4. Helper function demonstration
    println!("\n--- 4. Address Resolution Helper ---");
    {
        let test_inputs = vec![
            "0x1",
            "aptos.apt",
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            "alice.apt",
            "invalid",
        ];

        for input in test_inputs {
            let result = resolve_address_or_name(&aptos, input).await;
            println!("  '{}' -> {:?}", input, result);
        }
    }

    // 5. Check ANS availability
    println!("\n--- 5. ANS Service Status ---");
    {
        // Try a simple resolution to check if ANS is available
        let ans_available = aptos.resolve_name("test.apt").await.is_ok();
        println!("  ANS available: {}", ans_available);

        if !ans_available {
            println!("  Note: ANS is only available on mainnet and testnet");
        }
    }

    println!("\n--- Summary ---");
    println!("ANS (Aptos Names Service) allows:");
    println!("  • Human-readable names instead of hex addresses");
    println!("  • Forward resolution: name.apt -> 0x...");
    println!("  • Reverse resolution: 0x... -> name.apt");
    println!("  • Integration with wallets and dApps");

    println!("\n=== ANS Example Complete ===");

    Ok(())
}

/// Helper function to resolve either an address or an ANS name
async fn resolve_address_or_name(aptos: &Aptos, input: &str) -> Result<AccountAddress, String> {
    // Check if it's an ANS name
    if input.ends_with(".apt") {
        match aptos.resolve_name(input).await {
            Ok(Some(addr)) => Ok(addr),
            Ok(None) => Err(format!("Name '{}' not registered", input)),
            Err(e) => Err(format!("ANS lookup failed: {}", e)),
        }
    } else {
        // Try to parse as address
        input
            .parse::<AccountAddress>()
            .map_err(|e| format!("Invalid address: {}", e))
    }
}
