use super::*;
use aptos_sdk::account::Ed25519Account;
use aptos_sdk::transaction::{EntryFunction, TransactionBuilder, builder::sign_transaction};

#[tokio::test]
#[ignore]
async fn e2e_error_insufficient_gas() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();
    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000).unwrap();

    let chain_id = aptos.ensure_chain_id().await.unwrap();
    let seq = aptos.get_sequence_number(sender.address()).await.unwrap();

    // Build with impossibly low gas limit
    let raw_txn = TransactionBuilder::new()
        .sender(sender.address())
        .sequence_number(seq)
        .payload(payload.into())
        .chain_id(chain_id)
        .max_gas_amount(1) // Far too low
        .gas_unit_price(100)
        .build()
        .expect("failed to build");

    let signed = sign_transaction(&raw_txn, &sender).expect("failed to sign");

    let result = aptos.submit_and_wait(&signed, None).await;
    assert!(result.is_err(), "insufficient gas should fail");
    println!("Insufficient gas error: {}", result.unwrap_err());
}

#[tokio::test]
#[ignore]
async fn e2e_error_invalid_payload() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    // Build a transaction calling a nonexistent entry function
    let module_id: aptos_sdk::types::MoveModuleId = "0x1::does_not_exist".parse().unwrap();
    let payload = aptos_sdk::transaction::TransactionPayload::EntryFunction(
        aptos_sdk::transaction::EntryFunction::new(module_id, "fake_function", vec![], vec![]),
    );

    let result = aptos.sign_submit_and_wait(&sender, payload, None).await;

    assert!(result.is_err(), "invalid payload should fail");
    println!("Invalid payload error: {}", result.unwrap_err());
}

#[tokio::test]
#[ignore]
async fn e2e_error_sequence_number_too_old() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    // First, execute a transaction to advance the sequence number
    let r1 = Ed25519Account::generate();
    aptos
        .transfer_apt(&sender, r1.address(), 1_000)
        .await
        .expect("failed to transfer");

    // Now build a transaction with the old (stale) sequence number 0
    let r2 = Ed25519Account::generate();
    let payload = EntryFunction::apt_transfer(r2.address(), 1_000).unwrap();
    let chain_id = aptos.ensure_chain_id().await.unwrap();

    let raw_txn = TransactionBuilder::new()
        .sender(sender.address())
        .sequence_number(0) // Already used
        .payload(payload.into())
        .chain_id(chain_id)
        .max_gas_amount(100_000)
        .gas_unit_price(100)
        .build()
        .expect("failed to build");

    let signed = sign_transaction(&raw_txn, &sender).expect("failed to sign");
    let result = aptos.submit_and_wait(&signed, None).await;

    assert!(result.is_err(), "stale sequence number should fail");
    println!("Stale seq num error: {}", result.unwrap_err());
}

#[tokio::test]
#[ignore]
async fn e2e_error_concurrent_same_seq() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(500_000_000)
        .await
        .expect("failed to create sender");

    let chain_id = aptos.ensure_chain_id().await.unwrap();
    let seq = aptos.get_sequence_number(sender.address()).await.unwrap();

    // Build 5 transactions all with the same sequence number
    let mut futures = Vec::new();
    for i in 0..5u64 {
        let recipient = Ed25519Account::generate();
        let payload = EntryFunction::apt_transfer(recipient.address(), 1_000 + i).unwrap();

        let raw_txn = TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(seq) // Same seq for all
            .payload(payload.into())
            .chain_id(chain_id)
            .max_gas_amount(100_000)
            .gas_unit_price(100)
            .build()
            .expect("failed to build");

        let signed = sign_transaction(&raw_txn, &sender).expect("failed to sign");
        let aptos_ref = &aptos;
        futures.push(async move { aptos_ref.submit_and_wait(&signed, None).await });
    }

    let results = futures::future::join_all(futures).await;

    // At most one should succeed; the rest should fail with seq number conflict
    let successes = results.iter().filter(|r| r.is_ok()).count();
    let failures = results.iter().filter(|r| r.is_err()).count();
    println!(
        "Concurrent same-seq: {} succeeded, {} failed",
        successes, failures
    );
    assert!(
        successes <= 1,
        "at most one concurrent txn with same seq should succeed"
    );
    assert!(failures >= 4, "most should fail");
}

#[tokio::test]
#[ignore]
async fn e2e_error_unfunded_sender() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Generate an account but do NOT fund it
    let sender = Ed25519Account::generate();
    let recipient = Ed25519Account::generate();

    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000).unwrap();

    // sign_submit_and_wait calls build_transaction which fetches seq number
    // An unfunded account may return seq=0 or error
    let result = aptos
        .sign_submit_and_wait(&sender, payload.into(), None)
        .await;

    // Should fail — unfunded account can't pay gas
    assert!(result.is_err(), "unfunded sender should fail");
    println!("Unfunded sender error: {}", result.unwrap_err());
}
