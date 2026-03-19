use super::*;
use aptos_sdk::account::Ed25519Account;
use aptos_sdk::transaction::EntryFunction;
use aptos_sdk::types::TypeTag;

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
async fn e2e_simulate() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();
    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000).unwrap();

    let result = aptos
        .simulate(&sender, payload.into())
        .await
        .expect("failed to simulate");

    assert!(result.success(), "simulation should succeed");
    assert!(result.gas_used() > 0, "gas_used should be > 0");
    println!("Simulated gas: {}", result.gas_used());
    println!("Events: {}", result.events().len());
    println!("VM status: {}", result.vm_status());
}

#[tokio::test]
#[ignore]
async fn e2e_estimate_gas() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();
    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000).unwrap();

    let gas = aptos
        .estimate_gas(&sender, payload.into())
        .await
        .expect("failed to estimate gas");

    assert!(gas > 0, "estimated gas should be > 0");
    println!("Estimated gas (with 20% margin): {}", gas);
}

#[tokio::test]
#[ignore]
async fn e2e_simulate_and_submit() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();
    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000).unwrap();

    let pending = aptos
        .simulate_and_submit(&sender, payload.into())
        .await
        .expect("failed to simulate_and_submit");

    println!("Submitted after simulation: {}", pending.data.hash);
    assert!(!pending.data.hash.is_zero());
}

#[tokio::test]
#[ignore]
async fn e2e_simulate_submit_and_wait() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();
    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000).unwrap();

    let result = aptos
        .simulate_submit_and_wait(&sender, payload.into(), None)
        .await
        .expect("failed to simulate_submit_and_wait");

    let success = result.data.get("success").and_then(|v| v.as_bool());
    assert_eq!(success, Some(true));
}

#[tokio::test]
#[ignore]
async fn e2e_transfer_coin() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();

    // Transfer APT using the generic transfer_coin method
    let result = aptos
        .transfer_coin(
            &sender,
            recipient.address(),
            TypeTag::aptos_coin(),
            5_000_000,
        )
        .await
        .expect("failed to transfer_coin");

    let success = result.data.get("success").and_then(|v| v.as_bool());
    assert_eq!(success, Some(true));

    wait_for_finality().await;

    let balance = aptos
        .get_balance(recipient.address())
        .await
        .expect("failed to get balance");
    assert_eq!(balance, 5_000_000);
}

#[tokio::test]
#[ignore]
async fn e2e_view_bcs_typed() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let account = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    wait_for_finality().await;

    // BCS-encode the owner address
    let owner_bytes = aptos_bcs::to_bytes(&account.address()).expect("failed to serialize");

    let balance: u64 = aptos
        .view_bcs(
            "0x1::coin::balance",
            vec!["0x1::aptos_coin::AptosCoin".to_string()],
            vec![owner_bytes],
        )
        .await
        .expect("failed to call view_bcs");

    assert!(balance > 0, "balance should be > 0");
    println!("Balance via BCS: {}", balance);
}

#[tokio::test]
#[ignore]
async fn e2e_view_bcs_raw() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Call now_seconds and get raw BCS bytes
    let raw_bytes = aptos
        .view_bcs_raw("0x1::timestamp::now_seconds", vec![], vec![])
        .await
        .expect("failed to call view_bcs_raw");

    assert!(!raw_bytes.is_empty(), "should return bytes");

    // Manually deserialize as u64
    let timestamp: u64 = aptos_bcs::from_bytes(&raw_bytes).expect("failed to deserialize");
    assert!(timestamp > 0);
    println!(
        "Raw BCS timestamp: {} ({} bytes)",
        timestamp,
        raw_bytes.len()
    );
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
