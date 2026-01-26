//! Example: Multi-agent transaction
//!
//! This example demonstrates how to create a transaction that requires
//! signatures from multiple accounts.
//!
//! Run with: `cargo run --example multi_agent --features "ed25519,faucet"`

use aptos_rust_sdk_v2::{
    Aptos, AptosConfig,
    account::{Account, Ed25519Account},
    transaction::{
        EntryFunction, TransactionBuilder, TransactionPayload,
        builder::sign_multi_agent_transaction, types::MultiAgentRawTransaction,
    },
    types::MoveModuleId,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create client for testnet
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet");

    // Generate accounts
    let primary_signer = Ed25519Account::generate();
    let secondary_signer = Ed25519Account::generate();

    println!("Primary signer: {}", primary_signer.address());
    println!("Secondary signer: {}", secondary_signer.address());

    // Fund both accounts
    println!("\nFunding accounts...");
    aptos
        .fund_account(primary_signer.address(), 100_000_000)
        .await?;
    aptos
        .fund_account(secondary_signer.address(), 100_000_000)
        .await?;

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // For this example, we'll use a simple entry function
    // In practice, you would use a function that actually requires multiple signers
    // such as a multi-sig wallet or a swap that needs both parties to sign

    // Build a payload (using a simple transfer for demonstration)
    // Note: A real multi-agent use case would be something like:
    // - Atomic swaps between users
    // - Multi-sig operations
    // - Escrow releases
    let payload = TransactionPayload::EntryFunction(EntryFunction {
        module: MoveModuleId::from_str_strict("0x1::aptos_account")?,
        function: "transfer".to_string(),
        type_args: vec![],
        args: vec![
            aptos_bcs::to_bytes(&secondary_signer.address())?,
            aptos_bcs::to_bytes(&1000u64)?,
        ],
    });

    // Get sequence number
    let sequence_number = aptos.get_sequence_number(primary_signer.address()).await?;

    // Build the raw transaction
    let raw_txn = TransactionBuilder::new()
        .sender(primary_signer.address())
        .sequence_number(sequence_number)
        .payload(payload)
        .chain_id(aptos.chain_id())
        .expiration_from_now(600)
        .build()?;

    // Create a multi-agent transaction
    let multi_agent_txn = MultiAgentRawTransaction::new(raw_txn, vec![secondary_signer.address()]);

    // Sign with both signers
    let signed_txn = sign_multi_agent_transaction(
        &multi_agent_txn,
        &primary_signer,
        &[&secondary_signer as &dyn Account],
    )?;

    // Submit the transaction
    println!("\nSubmitting multi-agent transaction...");
    let result = aptos.submit_and_wait(&signed_txn, None).await?;

    let success = result.data.get("success").and_then(|v| v.as_bool());
    if success == Some(true) {
        println!("Multi-agent transaction successful!");

        let version = result.data.get("version").and_then(|v| v.as_str());
        println!("Transaction version: {:?}", version);
    } else {
        let vm_status = result
            .data
            .get("vm_status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        println!("Transaction failed: {}", vm_status);
    }

    Ok(())
}
