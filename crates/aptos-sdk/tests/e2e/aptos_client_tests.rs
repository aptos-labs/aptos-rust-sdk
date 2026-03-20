use super::*;
use aptos_sdk::account::Ed25519Account;
use aptos_sdk::transaction::EntryFunction;

#[tokio::test]
#[ignore]
async fn e2e_sign_and_submit() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();
    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000).unwrap();

    let pending = aptos
        .sign_and_submit(&sender, payload.into())
        .await
        .expect("failed to sign_and_submit");

    println!("Pending transaction hash: {}", pending.data.hash);
    assert!(!pending.data.hash.is_zero(), "hash should not be zero");
}

#[tokio::test]
#[ignore]
async fn e2e_sign_submit_and_wait() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();
    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000).unwrap();

    let result = aptos
        .sign_submit_and_wait(&sender, payload.into(), None)
        .await
        .expect("failed to sign_submit_and_wait");

    let success = result.data.get("success").and_then(|v| v.as_bool());
    assert_eq!(success, Some(true));
    println!("Transaction version: {:?}", result.data.get("version"));
}

#[tokio::test]
#[ignore]
async fn e2e_batch_transfer_apt() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(500_000_000)
        .await
        .expect("failed to create sender");

    let r1 = Ed25519Account::generate();
    let r2 = Ed25519Account::generate();
    let r3 = Ed25519Account::generate();

    let transfers = vec![
        (r1.address(), 1_000_000),
        (r2.address(), 2_000_000),
        (r3.address(), 3_000_000),
    ];

    let results = aptos
        .batch_transfer_apt(&sender, transfers)
        .await
        .expect("failed to batch_transfer_apt");

    assert_eq!(results.len(), 3);
    for (i, result) in results.iter().enumerate() {
        assert!(result.result.is_ok(), "batch txn {} should succeed", i);
        println!("Batch txn {}: {:?}", i, result.result);
    }
}

#[tokio::test]
#[ignore]
async fn e2e_submit_batch() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(300_000_000)
        .await
        .expect("failed to create sender");

    let r1 = Ed25519Account::generate();
    let r2 = Ed25519Account::generate();

    let payloads = vec![
        EntryFunction::apt_transfer(r1.address(), 1_000_000)
            .unwrap()
            .into(),
        EntryFunction::apt_transfer(r2.address(), 1_000_000)
            .unwrap()
            .into(),
    ];

    let results = aptos
        .submit_batch(&sender, payloads)
        .await
        .expect("failed to submit_batch");

    assert_eq!(results.len(), 2);
    for result in &results {
        assert!(result.result.is_ok(), "batch txn should succeed");
    }
}

#[tokio::test]
#[ignore]
async fn e2e_submit_batch_and_wait() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(300_000_000)
        .await
        .expect("failed to create sender");

    let r1 = Ed25519Account::generate();
    let r2 = Ed25519Account::generate();

    let payloads = vec![
        EntryFunction::apt_transfer(r1.address(), 1_000_000)
            .unwrap()
            .into(),
        EntryFunction::apt_transfer(r2.address(), 1_000_000)
            .unwrap()
            .into(),
    ];

    let results = aptos
        .submit_batch_and_wait(&sender, payloads, None)
        .await
        .expect("failed to submit_batch_and_wait");

    assert_eq!(results.len(), 2);
    for result in &results {
        assert!(result.result.is_ok(), "batch txn should succeed");
    }

    wait_for_finality().await;

    // Verify balances
    let b1 = aptos.get_balance(r1.address()).await.unwrap_or(0);
    let b2 = aptos.get_balance(r2.address()).await.unwrap_or(0);
    assert_eq!(b1, 1_000_000);
    assert_eq!(b2, 1_000_000);
}
