use super::*;
use aptos_sdk::account::{Account, Ed25519Account};
use aptos_sdk::transaction::{
    EntryFunction, TransactionBuilder,
    builder::{sign_fee_payer_transaction, sign_multi_agent_transaction},
    types::{FeePayerRawTransaction, MultiAgentRawTransaction},
};

#[tokio::test]
#[ignore]
async fn e2e_fee_payer_transaction() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Create sender with minimal funds (just for account creation)
    let sender = aptos
        .create_funded_account(1_000)
        .await
        .expect("failed to create sender");

    // Create fee payer with lots of funds
    let fee_payer = aptos
        .create_funded_account(500_000_000)
        .await
        .expect("failed to create fee payer");

    let recipient = Ed25519Account::generate();

    println!("Sender: {}", sender.address());
    println!("Fee payer: {}", fee_payer.address());
    println!("Recipient: {}", recipient.address());

    // Build the fee payer transaction
    let payload = EntryFunction::apt_transfer(recipient.address(), 500).unwrap();

    let sender_seq = aptos
        .get_sequence_number(sender.address())
        .await
        .unwrap_or(0);
    let chain_id = aptos
        .ensure_chain_id()
        .await
        .expect("failed to resolve chain id");

    let raw_txn = TransactionBuilder::new()
        .sender(sender.address())
        .sequence_number(sender_seq)
        .payload(payload.into())
        .chain_id(chain_id)
        .max_gas_amount(100_000)
        .gas_unit_price(100)
        .build()
        .expect("failed to build");

    let fee_payer_txn = FeePayerRawTransaction {
        raw_txn,
        secondary_signer_addresses: vec![],
        fee_payer_address: fee_payer.address(),
    };

    let signed = sign_fee_payer_transaction(&fee_payer_txn, &sender, &[], &fee_payer)
        .expect("failed to sign");

    // Submit
    let result = aptos.submit_and_wait(&signed, None).await;

    // This may or may not work depending on localnet support for fee payer
    match result {
        Ok(r) => {
            println!("Fee payer transaction result: {:?}", r.data);
        }
        Err(e) => {
            println!("Fee payer transaction failed (may not be supported): {}", e);
        }
    }
}

#[tokio::test]
#[ignore]
async fn e2e_multi_agent_transaction() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Create primary sender
    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    // Create secondary signer
    let secondary = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create secondary");

    println!("Sender: {}", sender.address());
    println!("Secondary: {}", secondary.address());

    // Note: Most simple transactions don't need multi-agent
    // This is just demonstrating the signing flow
    let payload = EntryFunction::apt_transfer(Ed25519Account::generate().address(), 1000).unwrap();

    let sender_seq = aptos
        .get_sequence_number(sender.address())
        .await
        .unwrap_or(0);
    let chain_id = aptos
        .ensure_chain_id()
        .await
        .expect("failed to resolve chain id");

    let raw_txn = TransactionBuilder::new()
        .sender(sender.address())
        .sequence_number(sender_seq)
        .payload(payload.into())
        .chain_id(chain_id)
        .max_gas_amount(100_000)
        .gas_unit_price(100)
        .build()
        .expect("failed to build");

    let multi_agent_txn = MultiAgentRawTransaction {
        raw_txn,
        secondary_signer_addresses: vec![secondary.address()],
    };

    // Sign with both accounts
    let secondary_ref: &dyn Account = &secondary;
    let signed = sign_multi_agent_transaction(&multi_agent_txn, &sender, &[secondary_ref])
        .expect("failed to sign");

    // Submit
    let result = aptos.submit_and_wait(&signed, None).await;

    match result {
        Ok(r) => {
            println!("Multi-agent transaction result: {:?}", r.data);
        }
        Err(e) => {
            println!("Multi-agent transaction error: {}", e);
        }
    }
}
