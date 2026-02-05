//! Example: Script transactions
//!
//! This example demonstrates how to create transactions using inline Move script
//! bytecode rather than calling existing entry functions on modules.
//!
//! Scripts are useful when you need to:
//! - Execute custom logic not available in existing modules
//! - Combine multiple operations atomically in a single transaction
//! - Perform operations that don't have a corresponding entry function
//!
//! Run with: `cargo run --example script_transaction --features "ed25519,faucet"`

use aptos_sdk::{
    Aptos, AptosConfig,
    account::Ed25519Account,
    transaction::{Script, ScriptArgument, TransactionBuilder, TransactionPayload},
    types::TypeTag,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Script Transaction Example ===\n");

    // Connect to testnet
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet (chain_id: {})", aptos.chain_id());

    // Create and fund accounts
    let sender = aptos.create_funded_account(100_000_000).await?;
    let recipient = Ed25519Account::generate();
    println!("Sender: {}", sender.address());
    println!("Recipient: {}", recipient.address());

    // ==== Part 1: Understanding Script Transactions ====
    println!("\n--- Part 1: Script Transaction Structure ---");

    println!("\nA Script transaction has three components:");
    println!("  1. code: Compiled Move bytecode (Vec<u8>)");
    println!("  2. type_args: Generic type arguments (Vec<TypeTag>)");
    println!("  3. args: Script arguments (Vec<ScriptArgument>)");

    // ==== Part 2: ScriptArgument Types ====
    println!("\n--- Part 2: Available ScriptArgument Types ---");

    // Demonstrate all ScriptArgument variants
    let demo_args = vec![
        ("U8", ScriptArgument::U8(255)),
        ("U16", ScriptArgument::U16(65535)),
        ("U32", ScriptArgument::U32(4_294_967_295)),
        ("U64", ScriptArgument::U64(18_446_744_073_709_551_615)),
        ("U128", ScriptArgument::U128(u128::MAX)),
        ("U256", ScriptArgument::U256([0xff; 32])), // 32-byte array
        ("Address", ScriptArgument::Address(recipient.address())),
        ("Bool", ScriptArgument::Bool(true)),
        ("U8Vector", ScriptArgument::U8Vector(vec![1, 2, 3, 4, 5])),
    ];

    println!("ScriptArgument variants:");
    for (name, arg) in &demo_args {
        println!("  - {}: {:?}", name, arg);
    }

    // ==== Part 3: Creating a Script Payload ====
    println!("\n--- Part 3: Creating a Script Payload ---");

    // In a real scenario, you would compile a Move script to get bytecode.
    // Here's an example Move script that transfers APT:
    //
    // script {
    //     use aptos_framework::aptos_account;
    //
    //     fun main(sender: &signer, recipient: address, amount: u64) {
    //         aptos_account::transfer(sender, recipient, amount);
    //     }
    // }
    //
    // To compile: `aptos move compile --named-addresses std=0x1`
    // The compiled bytecode would be in `build/<project>/bytecode_scripts/`

    // For demonstration, we'll use a minimal script bytecode
    // This is a placeholder - real scripts need actual compiled bytecode
    let example_bytecode: Vec<u8> = vec![
        // Move bytecode header and instructions would go here
        // In practice, read from a .mv file after compilation
    ];

    // Create a Script with the transfer parameters
    let script = Script::new(
        example_bytecode.clone(),
        vec![], // No type arguments for simple transfer
        vec![
            ScriptArgument::Address(recipient.address()),
            ScriptArgument::U64(1_000_000), // 0.01 APT
        ],
    );

    println!("Script created:");
    println!("  Bytecode length: {} bytes", script.code.len());
    println!("  Type arguments: {:?}", script.type_args);
    println!("  Arguments: {:?}", script.args);

    // Create the transaction payload
    let payload = TransactionPayload::Script(script);
    println!("\nPayload type: Script");

    // ==== Part 4: Building and Signing a Script Transaction ====
    println!("\n--- Part 4: Building Script Transaction ---");

    // Get sequence number
    let sequence_number = aptos.get_sequence_number(sender.address()).await?;

    // Build the transaction
    let raw_txn = TransactionBuilder::new()
        .sender(sender.address())
        .sequence_number(sequence_number)
        .payload(payload)
        .chain_id(aptos.chain_id())
        .max_gas_amount(100_000)
        .gas_unit_price(100)
        .expiration_from_now(600)
        .build()?;

    println!("Raw transaction built:");
    println!("  Sender: {}", raw_txn.sender);
    println!("  Sequence number: {}", raw_txn.sequence_number);
    println!("  Max gas: {}", raw_txn.max_gas_amount);

    // Sign the transaction
    let _signed_txn = aptos_sdk::transaction::builder::sign_transaction(&raw_txn, &sender)?;
    println!("Transaction signed successfully");

    // Note: We won't submit this transaction since we don't have valid bytecode
    // In a real scenario, you would:
    // let result = aptos.submit_and_wait(&signed_txn, None).await?;

    // ==== Part 5: Script with Type Arguments ====
    println!("\n--- Part 5: Script with Type Arguments ---");

    // Scripts can also have generic type arguments, like entry functions.
    // For example, a generic coin transfer script:
    //
    // script {
    //     use aptos_framework::coin;
    //
    //     fun main<CoinType>(sender: &signer, recipient: address, amount: u64) {
    //         coin::transfer<CoinType>(sender, recipient, amount);
    //     }
    // }

    let typed_script = Script::new(
        vec![],                      // Bytecode would go here
        vec![TypeTag::aptos_coin()], // Type argument: AptosCoin
        vec![
            ScriptArgument::Address(recipient.address()),
            ScriptArgument::U64(500_000),
        ],
    );

    println!("Script with type arguments:");
    println!("  Type args: {:?}", typed_script.type_args);
    println!("  This would call a generic function with <0x1::aptos_coin::AptosCoin>");

    // ==== Part 6: Script vs Entry Function Comparison ====
    println!("\n--- Part 6: Script vs Entry Function ---");

    println!("\nWhen to use Scripts:");
    println!("  - Custom logic not in existing modules");
    println!("  - Atomic multi-step operations");
    println!("  - One-off operations without deploying a module");
    println!("  - Complex conditional logic in a single transaction");

    println!("\nWhen to use Entry Functions:");
    println!("  - Calling existing module functions");
    println!("  - Standard operations (transfers, staking, etc.)");
    println!("  - Better gas efficiency for common patterns");
    println!("  - Easier to audit and verify");

    // ==== Part 7: Practical Example - Multi-recipient Transfer Script ====
    println!("\n--- Part 7: Multi-recipient Transfer Pattern ---");

    // A common use case for scripts: transferring to multiple recipients atomically
    // This would be the Move script:
    //
    // script {
    //     use aptos_framework::aptos_account;
    //
    //     fun multi_transfer(
    //         sender: &signer,
    //         recipient1: address,
    //         amount1: u64,
    //         recipient2: address,
    //         amount2: u64,
    //         recipient3: address,
    //         amount3: u64,
    //     ) {
    //         aptos_account::transfer(sender, recipient1, amount1);
    //         aptos_account::transfer(sender, recipient2, amount2);
    //         aptos_account::transfer(sender, recipient3, amount3);
    //     }
    // }

    let recipient2 = Ed25519Account::generate();
    let recipient3 = Ed25519Account::generate();

    let _multi_transfer_script = Script::new(
        vec![], // Compiled multi-transfer bytecode
        vec![], // No type arguments
        vec![
            ScriptArgument::Address(recipient.address()),
            ScriptArgument::U64(1_000_000),
            ScriptArgument::Address(recipient2.address()),
            ScriptArgument::U64(2_000_000),
            ScriptArgument::Address(recipient3.address()),
            ScriptArgument::U64(3_000_000),
        ],
    );

    println!("Multi-recipient transfer script:");
    println!("  Recipients: 3");
    println!(
        "  Total transfer: {} APT",
        (1_000_000 + 2_000_000 + 3_000_000) as f64 / 100_000_000.0
    );
    println!("  Benefit: Atomic - all succeed or all fail");

    // ==== Part 8: How to Compile Scripts ====
    println!("\n--- Part 8: How to Compile Move Scripts ---");

    println!("\nTo compile a Move script:");
    println!("  1. Create a script file (e.g., my_script.move):");
    println!("     script {{");
    println!("         use aptos_framework::aptos_account;");
    println!("         fun main(sender: &signer, recipient: address, amount: u64) {{");
    println!("             aptos_account::transfer(sender, recipient, amount);");
    println!("         }}");
    println!("     }}");
    println!();
    println!("  2. Compile with Aptos CLI:");
    println!("     aptos move compile --named-addresses std=0x1");
    println!();
    println!("  3. Read the compiled bytecode:");
    println!("     let bytecode = std::fs::read(\"build/project/bytecode_scripts/main.mv\")?;");
    println!();
    println!("  4. Use in your transaction:");
    println!("     let script = Script::new(bytecode, type_args, args);");

    println!("\n=== Script Transaction Example Completed ===");

    Ok(())
}
