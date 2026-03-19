use super::*;
use aptos_sdk::account::Ed25519Account;
use aptos_sdk::transaction::{InputEntryFunctionData, TransactionBatchBuilder};

#[tokio::test]
#[ignore]
async fn e2e_batch_build() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Create sender
    let sender = aptos
        .create_funded_account(500_000_000)
        .await
        .expect("failed to create sender");

    let recipient1 = Ed25519Account::generate();
    let recipient2 = Ed25519Account::generate();

    wait_for_finality().await;

    // Get sequence number and resolve chain ID
    let seq_num = aptos
        .fullnode()
        .get_sequence_number(sender.address())
        .await
        .expect("failed to get seq num");
    let chain_id = aptos
        .ensure_chain_id()
        .await
        .expect("failed to resolve chain id");

    // Build batch using TransactionBatchBuilder
    let payload1 = InputEntryFunctionData::transfer_apt(recipient1.address(), 10_000_000)
        .expect("failed to build payload 1");
    let payload2 = InputEntryFunctionData::transfer_apt(recipient2.address(), 10_000_000)
        .expect("failed to build payload 2");

    let batch = TransactionBatchBuilder::new()
        .sender(sender.address())
        .starting_sequence_number(seq_num)
        .chain_id(chain_id)
        .add_payload(payload1)
        .add_payload(payload2)
        .build_and_sign(&sender)
        .expect("failed to build batch");

    println!("Created batch of {} transactions", batch.len());
    assert_eq!(batch.len(), 2);
}
