//! Example: Entry Function Transactions
//!
//! This example demonstrates multiple ways to build entry function transactions:
//! 1. Using the ergonomic InputEntryFunctionData builder
//! 2. Using EntryFunction directly with manual BCS encoding
//! 3. Using convenience helpers for common operations
//! 4. Working with type arguments and complex data types
//!
//! Run with: `cargo run --example entry_function --features "ed25519,faucet"`

use aptos_rust_sdk_v2::{
    Aptos, AptosConfig,
    account::Ed25519Account,
    transaction::{
        EntryFunction, InputEntryFunctionData, TransactionPayload, functions, move_none, move_some,
        move_string,
    },
    types::{MoveModuleId, TypeTag},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Entry Function Transaction Examples ===\n");

    // Connect to testnet
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet (chain_id: {})", aptos.chain_id());

    // Create and fund accounts
    let sender = aptos.create_funded_account(100_000_000).await?;
    let recipient = Ed25519Account::generate();
    println!("Sender: {}", sender.address());
    println!("Recipient: {}", recipient.address());

    // ==== Part 1: InputEntryFunctionData Builder (Recommended) ====
    println!("\n--- Part 1: InputEntryFunctionData Builder (Recommended) ---");

    // Simple APT transfer using the builder
    let payload1 = InputEntryFunctionData::new("0x1::aptos_account::transfer")
        .arg(recipient.address())
        .arg(1_000_000u64) // 0.01 APT
        .build()?;

    println!("Simple transfer payload built:");
    println!("  Function: 0x1::aptos_account::transfer");
    println!("  Arguments: [recipient, amount]");

    // Submit and wait for the transaction
    let result = aptos.sign_submit_and_wait(&sender, payload1, None).await?;
    let success = result
        .data
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("  Transaction success: {}", success);

    // ==== Part 2: Using Type Arguments ====
    println!("\n--- Part 2: Entry Functions with Type Arguments ---");

    // Generic coin transfer with type argument
    let payload2 = InputEntryFunctionData::new("0x1::coin::transfer")
        .type_arg("0x1::aptos_coin::AptosCoin") // Generic type argument
        .arg(recipient.address())
        .arg(500_000u64)
        .build()?;

    println!("Generic coin transfer:");
    println!("  Function: 0x1::coin::transfer<0x1::aptos_coin::AptosCoin>");
    println!("  Type arg parsed from string");

    let result = aptos.sign_submit_and_wait(&sender, payload2, None).await?;
    let success = result
        .data
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("  Transaction success: {}", success);

    // ==== Part 3: Convenience Helpers ====
    println!("\n--- Part 3: Convenience Helper Methods ---");

    // Using transfer_apt helper
    let payload3 = InputEntryFunctionData::transfer_apt(recipient.address(), 250_000)?;
    println!("InputEntryFunctionData::transfer_apt() - Quick APT transfer");

    let result = aptos.sign_submit_and_wait(&sender, payload3, None).await?;
    println!(
        "  Transaction success: {}",
        result
            .data
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    );

    // Using transfer_coin helper for any coin type
    let payload4 = InputEntryFunctionData::transfer_coin(
        "0x1::aptos_coin::AptosCoin",
        recipient.address(),
        100_000,
    )?;
    println!("InputEntryFunctionData::transfer_coin() - Generic coin transfer");

    let result = aptos.sign_submit_and_wait(&sender, payload4, None).await?;
    println!(
        "  Transaction success: {}",
        result
            .data
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    );

    // ==== Part 4: Using EntryFunction Directly ====
    println!("\n--- Part 4: Using EntryFunction Directly ---");

    // Sometimes you need more control - use EntryFunction directly
    let entry_fn = EntryFunction::new(
        MoveModuleId::from_str_strict("0x1::aptos_account")?,
        "transfer",
        vec![], // No type arguments
        vec![
            aptos_bcs::to_bytes(&recipient.address())?,
            aptos_bcs::to_bytes(&100_000u64)?,
        ],
    );
    let payload5 = TransactionPayload::EntryFunction(entry_fn);

    println!("EntryFunction::new() - Manual construction");
    println!("  Requires manual BCS encoding of arguments");

    let result = aptos.sign_submit_and_wait(&sender, payload5, None).await?;
    println!(
        "  Transaction success: {}",
        result
            .data
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    );

    // ==== Part 5: Function ID Constants ====
    println!("\n--- Part 5: Using Function ID Constants ---");

    // Use predefined function IDs for common operations
    println!("Available function constants:");
    println!(
        "  functions::APT_TRANSFER = \"{}\"",
        functions::APT_TRANSFER
    );
    println!(
        "  functions::COIN_TRANSFER = \"{}\"",
        functions::COIN_TRANSFER
    );
    println!(
        "  functions::CREATE_ACCOUNT = \"{}\"",
        functions::CREATE_ACCOUNT
    );
    println!(
        "  functions::REGISTER_COIN = \"{}\"",
        functions::REGISTER_COIN
    );
    println!(
        "  functions::PUBLISH_PACKAGE = \"{}\"",
        functions::PUBLISH_PACKAGE
    );

    println!("\nAvailable type constants:");
    println!("  aptos_rust_sdk_v2::transaction::types::APT_COIN = \"0x1::aptos_coin::AptosCoin\"");

    // Using constants
    let payload6 = InputEntryFunctionData::new(functions::APT_TRANSFER)
        .arg(recipient.address())
        .arg(50_000u64)
        .build()?;

    let result = aptos.sign_submit_and_wait(&sender, payload6, None).await?;
    println!("\nUsing functions::APT_TRANSFER constant:");
    println!(
        "  Transaction success: {}",
        result
            .data
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    );

    // ==== Part 6: Complex Argument Types ====
    println!("\n--- Part 6: Complex Argument Types ---");

    // Demonstrate various argument encoding helpers
    println!("Argument encoding helpers:");

    // move_string - for string arguments
    let name = move_string("MyToken");
    println!("  move_string(\"MyToken\") -> String arg for Move");

    // move_vec - for vector arguments
    let addresses = vec![recipient.address()];
    let amounts = vec![1000u64, 2000u64, 3000u64];
    println!("  move_vec(&[...]) -> Vector arg for Move");

    // move_some / move_none - for Option arguments
    let _some_value = move_some(42u64);
    let _none_value: Vec<u8> = move_none();
    println!("  move_some(42u64) -> Option::Some(42)");
    println!("  move_none() -> Option::None");

    // Example with complex types (hypothetical function)
    println!("\nExample complex payload (not submitted):");
    let _complex_payload = InputEntryFunctionData::new("0x1::example::complex_function")
        .arg(42u8) // u8
        .arg(1000u64) // u64
        .arg(true) // bool
        .arg(name) // String
        .arg(addresses) // vector<address>
        .arg(amounts) // vector<u64>
        .build();
    println!("  Built payload with: u8, u64, bool, String, vector<address>, vector<u64>");

    // ==== Part 7: TypeTag Construction ====
    println!("\n--- Part 7: TypeTag Construction Methods ---");

    // From string
    let type_tag1 = TypeTag::from_str_strict("0x1::aptos_coin::AptosCoin")?;
    println!("TypeTag::from_str_strict(\"0x1::aptos_coin::AptosCoin\")");

    // Convenience method
    let type_tag2 = TypeTag::aptos_coin();
    println!("TypeTag::aptos_coin() - convenience method");

    // They're equivalent
    assert_eq!(type_tag1, type_tag2);
    println!("Both produce the same TypeTag");

    // Using typed type args in builder
    let payload7 = InputEntryFunctionData::new("0x1::coin::transfer")
        .type_arg_typed(TypeTag::aptos_coin()) // Using TypeTag directly
        .arg(recipient.address())
        .arg(25_000u64)
        .build()?;

    let result = aptos.sign_submit_and_wait(&sender, payload7, None).await?;
    println!("\nUsing type_arg_typed():");
    println!(
        "  Transaction success: {}",
        result
            .data
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    );

    // ==== Part 8: From Parts Construction ====
    println!("\n--- Part 8: Building from Module Parts ---");

    // When you have module and function as separate values
    let module = MoveModuleId::from_str_strict("0x1::aptos_account")?;
    let payload8 = InputEntryFunctionData::from_parts(module, "transfer")
        .arg(recipient.address())
        .arg(10_000u64)
        .build()?;

    println!("InputEntryFunctionData::from_parts():");
    println!("  Useful when module ID is already parsed");

    let result = aptos.sign_submit_and_wait(&sender, payload8, None).await?;
    println!(
        "  Transaction success: {}",
        result
            .data
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    );

    // ==== Part 9: Build Entry Function Only ====
    println!("\n--- Part 9: Building Entry Function Only ---");

    // Sometimes you just need the EntryFunction, not the full payload
    let entry_fn = InputEntryFunctionData::new("0x1::aptos_account::transfer")
        .arg(recipient.address())
        .arg(5_000u64)
        .build_entry_function()?;

    println!("build_entry_function() returns EntryFunction directly:");
    println!(
        "  Module: {}::{}",
        entry_fn.module.address, entry_fn.module.name
    );
    println!("  Function: {}", entry_fn.function);
    println!("  Args count: {}", entry_fn.args.len());

    // Convert to payload manually
    let payload9 = TransactionPayload::EntryFunction(entry_fn);
    let result = aptos.sign_submit_and_wait(&sender, payload9, None).await?;
    println!(
        "  Transaction success: {}",
        result
            .data
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    );

    // ==== Part 10: Error Handling ====
    println!("\n--- Part 10: Error Handling ---");

    // Invalid function ID
    let result = InputEntryFunctionData::new("invalid_function")
        .arg(42u64)
        .build();
    println!("Invalid function ID: {}", result.is_err());
    if let Err(e) = result {
        println!("  Error: {}", e);
    }

    // Invalid type argument
    let result = InputEntryFunctionData::new("0x1::coin::transfer")
        .type_arg("not::a::valid::type")
        .arg(recipient.address())
        .arg(1000u64)
        .build();
    println!("Invalid type arg: {}", result.is_err());

    // ==== Summary ====
    println!("\n=== Summary ===");
    println!("Best practices for entry function transactions:");
    println!("  1. Use InputEntryFunctionData builder for most cases");
    println!("  2. Use helper methods (transfer_apt, transfer_coin) for common ops");
    println!("  3. Use function constants (functions::APT_TRANSFER) for clarity");
    println!("  4. Use type_arg() for string types, type_arg_typed() for TypeTag");
    println!("  5. Use move_vec(), move_some(), move_none() for complex types");

    // Final balance check
    let sender_balance = aptos.get_balance(sender.address()).await?;
    let recipient_balance = aptos.get_balance(recipient.address()).await?;
    println!("\nFinal balances:");
    println!("  Sender: {} APT", sender_balance as f64 / 100_000_000.0);
    println!(
        "  Recipient: {} APT",
        recipient_balance as f64 / 100_000_000.0
    );

    println!("\n=== Entry Function Examples Completed ===");
    Ok(())
}
