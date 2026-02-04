//! Example: On-chain Multisig Accounts (Multisig V2)
//!
//! This example demonstrates how to work with Aptos on-chain multisig accounts.
//! Unlike MultiEd25519Account (client-side threshold signing), on-chain multisig
//! uses the `0x1::multisig_account` module for governance-style proposals.
//!
//! On-chain multisig workflow:
//! 1. Create a multisig account with multiple owners
//! 2. Any owner can propose a transaction
//! 3. Other owners approve/reject the proposal
//! 4. Once threshold is met, anyone can execute the transaction
//!
//! Run with: `cargo run --example multisig_v2 --features "ed25519,faucet"`

use aptos_rust_sdk_v2::{
    Aptos, AptosConfig,
    account::Ed25519Account,
    transaction::{
        EntryFunction, InputEntryFunctionData, TransactionBuilder, TransactionPayload,
        payload::{Multisig, MultisigTransactionPayload},
    },
    types::AccountAddress,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== On-chain Multisig Account Example ===\n");

    // Connect to testnet
    let aptos = Aptos::new(AptosConfig::testnet())?;
    println!("Connected to testnet (chain_id: {})", aptos.chain_id());

    // ==== Part 1: Understanding On-chain Multisig ====
    println!("\n--- Part 1: Understanding On-chain Multisig ---");

    println!("\nOn-chain Multisig vs Client-side Multisig:");
    println!("  Client-side (MultiEd25519Account):");
    println!("    - Signatures collected off-chain");
    println!("    - Single transaction with multiple signatures");
    println!("    - Fast, but requires coordination");
    println!();
    println!("  On-chain (multisig_account module):");
    println!("    - Proposals stored on-chain");
    println!("    - Owners vote asynchronously");
    println!("    - Better for governance and DAOs");
    println!("    - Transaction history on-chain");

    // ==== Part 2: Create Owner Accounts ====
    println!("\n--- Part 2: Creating Owner Accounts ---");

    // Create 3 owner accounts
    let owner1 = aptos.create_funded_account(100_000_000).await?;
    let owner2 = aptos.create_funded_account(100_000_000).await?;
    let owner3 = aptos.create_funded_account(100_000_000).await?;

    println!("Owner 1: {}", owner1.address());
    println!("Owner 2: {}", owner2.address());
    println!("Owner 3: {}", owner3.address());

    // ==== Part 3: Create On-chain Multisig Account ====
    println!("\n--- Part 3: Creating On-chain Multisig Account ---");

    // Create multisig account with 2-of-3 threshold
    // The multisig address is deterministic based on creator's address and sequence number
    let owners = vec![owner1.address(), owner2.address(), owner3.address()];
    let threshold = 2u64;

    // Call 0x1::multisig_account::create_with_owners
    let create_payload = InputEntryFunctionData::new("0x1::multisig_account::create_with_owners")
        .arg(owners.clone()) // additional_owners: vector<address>
        .arg(threshold) // num_signatures_required: u64
        .arg(Vec::<String>::new()) // metadata_keys: vector<String>
        .arg(Vec::<Vec<u8>>::new()) // metadata_values: vector<vector<u8>>
        .build()?;

    println!("Creating 2-of-3 multisig account...");
    let result = aptos
        .sign_submit_and_wait(&owner1, create_payload, None)
        .await?;

    // Extract the multisig account address from the event
    let multisig_address = extract_multisig_address(&result.data)?;
    println!("Multisig account created: {}", multisig_address);

    // Fund the multisig account
    println!("\nFunding multisig account...");
    aptos.fund_account(multisig_address, 100_000_000).await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let balance = aptos.get_balance(multisig_address).await?;
    println!("Multisig balance: {} APT", balance as f64 / 100_000_000.0);

    // ==== Part 4: Create a Transaction Proposal ====
    println!("\n--- Part 4: Creating a Transaction Proposal ---");

    let recipient = Ed25519Account::generate();
    println!("Recipient for transfer: {}", recipient.address());

    // The inner transaction payload (what the multisig will execute)
    let transfer_entry_fn = EntryFunction::apt_transfer(recipient.address(), 10_000_000)?;

    // Create the proposal using create_transaction
    // This stores the transaction on-chain for voting
    let proposal_payload = InputEntryFunctionData::new("0x1::multisig_account::create_transaction")
        .arg(multisig_address) // multisig_account: address
        .arg(aptos_bcs::to_bytes(&transfer_entry_fn)?) // payload: vector<u8>
        .build()?;

    println!("Owner 1 creating transaction proposal...");
    let proposal_result = aptos
        .sign_submit_and_wait(&owner1, proposal_payload, None)
        .await?;

    let success = proposal_result
        .data
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("Proposal created: {}", success);

    // The sequence number of this proposal (starts at 1)
    let sequence_number = 1u64;
    println!("Proposal sequence number: {}", sequence_number);

    // ==== Part 5: Vote on the Proposal ====
    println!("\n--- Part 5: Voting on the Proposal ---");

    // Owner 2 approves the proposal
    let approve_payload = InputEntryFunctionData::new("0x1::multisig_account::approve_transaction")
        .arg(multisig_address) // multisig_account: address
        .arg(sequence_number) // sequence_number: u64
        .build()?;

    println!("Owner 2 approving proposal...");
    let approve_result = aptos
        .sign_submit_and_wait(&owner2, approve_payload, None)
        .await?;

    let success = approve_result
        .data
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("Owner 2 approved: {}", success);

    // Now we have 2 approvals (owner1 implicitly + owner2), meeting the threshold

    // ==== Part 6: Execute the Transaction ====
    println!("\n--- Part 6: Executing the Approved Transaction ---");

    // Using TransactionPayload::Multisig to execute
    // This is the special payload type for executing multisig transactions
    let multisig_payload = TransactionPayload::Multisig(Multisig {
        multisig_address,
        transaction_payload: Some(MultisigTransactionPayload::EntryFunction(
            transfer_entry_fn.clone(),
        )),
    });

    // Build and submit the execution transaction
    // Any owner (or even non-owner) can execute once threshold is met
    let seq = aptos.get_sequence_number(owner3.address()).await?;
    let raw_txn = TransactionBuilder::new()
        .sender(owner3.address())
        .sequence_number(seq)
        .payload(multisig_payload)
        .chain_id(aptos.chain_id())
        .max_gas_amount(200_000)
        .gas_unit_price(100)
        .expiration_from_now(600)
        .build()?;

    let signed = aptos_rust_sdk_v2::transaction::builder::sign_transaction(&raw_txn, &owner3)?;

    println!("Owner 3 executing approved transaction...");
    let exec_result = aptos.submit_and_wait(&signed, None).await?;

    let success = exec_result
        .data
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("Execution success: {}", success);

    // Verify the transfer
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let recipient_balance = aptos.get_balance(recipient.address()).await.unwrap_or(0);
    println!(
        "Recipient received: {} APT",
        recipient_balance as f64 / 100_000_000.0
    );

    // ==== Part 7: Query Multisig Account State ====
    println!("\n--- Part 7: Querying Multisig Account State ---");

    // Query the multisig account configuration
    query_multisig_state(&aptos, multisig_address).await?;

    // ==== Part 8: Reject a Proposal ====
    println!("\n--- Part 8: Rejecting a Proposal ---");

    // Create another proposal
    let reject_transfer = EntryFunction::apt_transfer(recipient.address(), 50_000_000)?;
    let proposal2_payload =
        InputEntryFunctionData::new("0x1::multisig_account::create_transaction")
            .arg(multisig_address)
            .arg(aptos_bcs::to_bytes(&reject_transfer)?)
            .build()?;

    println!("Owner 1 creating another proposal...");
    aptos
        .sign_submit_and_wait(&owner1, proposal2_payload, None)
        .await?;
    let sequence_number_2 = 2u64;

    // Owner 2 rejects this proposal
    let reject_payload = InputEntryFunctionData::new("0x1::multisig_account::reject_transaction")
        .arg(multisig_address)
        .arg(sequence_number_2)
        .build()?;

    println!("Owner 2 rejecting proposal #2...");
    let reject_result = aptos
        .sign_submit_and_wait(&owner2, reject_payload, None)
        .await?;

    let success = reject_result
        .data
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("Rejection recorded: {}", success);

    // Owner 3 also rejects
    let reject_payload_3 = InputEntryFunctionData::new("0x1::multisig_account::reject_transaction")
        .arg(multisig_address)
        .arg(sequence_number_2)
        .build()?;

    println!("Owner 3 also rejecting proposal #2...");
    aptos
        .sign_submit_and_wait(&owner3, reject_payload_3, None)
        .await?;

    // Now the proposal is fully rejected (2 rejections >= threshold)
    println!("Proposal #2 rejected by majority");

    // ==== Part 9: Add/Remove Owners ====
    println!("\n--- Part 9: Managing Owners ---");

    // Create a new potential owner
    let new_owner = aptos.create_funded_account(10_000_000).await?;
    println!("New potential owner: {}", new_owner.address());

    // To add a new owner, you need to create a proposal that calls add_owner
    // This itself requires multisig approval
    println!("\nNote: Adding/removing owners requires a multisig proposal");
    println!("Steps to add owner:");
    println!("  1. Create proposal calling 0x1::multisig_account::add_owner");
    println!("  2. Get threshold approvals");
    println!("  3. Execute the proposal");

    // Example payload (not executed to keep example simple):
    let _add_owner_payload = InputEntryFunctionData::new("0x1::multisig_account::add_owner")
        .arg(new_owner.address())
        .build()?;

    // ==== Summary ====
    println!("\n=== On-chain Multisig Summary ===");
    println!("Key functions in 0x1::multisig_account:");
    println!("  - create_with_owners: Create new multisig account");
    println!("  - create_transaction: Propose a new transaction");
    println!("  - approve_transaction: Vote yes on a proposal");
    println!("  - reject_transaction: Vote no on a proposal");
    println!("  - execute_rejected_transaction: Clean up rejected proposals");
    println!("  - add_owner/remove_owner: Modify owner set");
    println!("  - update_signature_required: Change threshold");

    println!("\nWhen to use on-chain multisig:");
    println!("  - DAO treasury management");
    println!("  - Protocol governance");
    println!("  - Asynchronous multi-party approvals");
    println!("  - Audit trail requirements");

    println!("\n=== On-chain Multisig Example Completed ===");
    Ok(())
}

/// Extract multisig account address from the creation event
fn extract_multisig_address(data: &serde_json::Value) -> anyhow::Result<AccountAddress> {
    // Look for CreateMultisigAccountEvent in events
    if let Some(events) = data.get("events").and_then(|v| v.as_array()) {
        for event in events {
            let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if event_type.contains("CreateMultisigAccountEvent")
                && let Some(addr_str) = event
                    .get("data")
                    .and_then(|d| d.get("multisig_account"))
                    .and_then(|v| v.as_str())
            {
                return AccountAddress::from_hex(addr_str)
                    .map_err(|e| anyhow::anyhow!("Invalid address: {}", e));
            }
        }
    }

    // Fallback: compute expected address from changes
    // The multisig account is created at a deterministic address
    if let Some(changes) = data.get("changes").and_then(|v| v.as_array()) {
        for change in changes {
            if let Some(addr) = change.get("address").and_then(|v| v.as_str()) {
                // Look for the multisig_account resource
                if let Some(data) = change.get("data")
                    && let Some(typ) = data.get("type").and_then(|v| v.as_str())
                    && typ.contains("multisig_account::MultisigAccount")
                {
                    return AccountAddress::from_hex(addr)
                        .map_err(|e| anyhow::anyhow!("Invalid address: {}", e));
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "Could not find multisig address in transaction result"
    ))
}

/// Query and display multisig account state
async fn query_multisig_state(
    aptos: &Aptos,
    multisig_address: AccountAddress,
) -> anyhow::Result<()> {
    // Get the MultisigAccount resource
    let resource = aptos
        .fullnode()
        .get_account_resource(multisig_address, "0x1::multisig_account::MultisigAccount")
        .await;

    match resource {
        Ok(res) => {
            println!("Multisig Account State:");

            // Parse owners
            if let Some(owners) = res.data.data.get("owners").and_then(|v| v.as_array()) {
                println!("  Owners: {}", owners.len());
                for (i, owner) in owners.iter().enumerate() {
                    println!("    {}: {}", i + 1, owner.as_str().unwrap_or("?"));
                }
            }

            // Parse threshold
            if let Some(threshold) = res
                .data
                .data
                .get("num_signatures_required")
                .and_then(|v| v.as_str())
            {
                println!("  Required signatures: {}", threshold);
            }

            // Parse last executed
            if let Some(last) = res
                .data
                .data
                .get("last_executed_sequence_number")
                .and_then(|v| v.as_str())
            {
                println!("  Last executed sequence: {}", last);
            }

            // Parse next sequence
            if let Some(next) = res
                .data
                .data
                .get("next_sequence_number")
                .and_then(|v| v.as_str())
            {
                println!("  Next sequence: {}", next);
            }
        }
        Err(e) => {
            println!("Could not query multisig state: {}", e);
        }
    }

    Ok(())
}
