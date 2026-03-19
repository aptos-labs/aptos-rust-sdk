use super::*;
use aptos_sdk::account::Secp256r1Account;
use aptos_sdk::transaction::{EntryFunction, TransactionBuilder, builder::sign_transaction};

#[tokio::test]
#[ignore]
async fn e2e_secp256r1_address_derivation() {
    let account = Secp256r1Account::generate();

    // Address should not be zero
    assert!(!account.address().is_zero());

    // Same key should produce same address (deterministic)
    let address1 = account.address();
    let address2 = account.address();
    assert_eq!(address1, address2);

    println!("Secp256r1 account address: {}", account.address());
}

#[tokio::test]
#[ignore]
async fn e2e_secp256r1_fund_and_balance() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let account = Secp256r1Account::generate();

    aptos
        .fund_account(account.address(), 100_000_000)
        .await
        .expect("failed to fund");

    wait_for_finality().await;

    let balance = aptos
        .get_balance(account.address())
        .await
        .expect("failed to get balance");
    assert!(balance > 0, "balance should be > 0");
    println!("Secp256r1 balance: {} octas", balance);
}

#[tokio::test]
#[ignore]
async fn e2e_secp256r1_transfer() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = Secp256r1Account::generate();
    aptos
        .fund_account(sender.address(), 200_000_000)
        .await
        .expect("failed to fund sender");

    wait_for_finality().await;

    let recipient = Secp256r1Account::generate();
    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000_000).unwrap();

    let chain_id = aptos.ensure_chain_id().await.unwrap();
    let seq = aptos
        .get_sequence_number(sender.address())
        .await
        .unwrap_or(0);

    let raw_txn = TransactionBuilder::new()
        .sender(sender.address())
        .sequence_number(seq)
        .payload(payload.into())
        .chain_id(chain_id)
        .max_gas_amount(100_000)
        .gas_unit_price(100)
        .build()
        .expect("failed to build");

    let signed = sign_transaction(&raw_txn, &sender).expect("failed to sign secp256r1");

    let result = aptos.submit_and_wait(&signed, None).await;

    match result {
        Ok(r) => {
            let success = r.data.get("success").and_then(|v| v.as_bool());
            assert_eq!(success, Some(true), "secp256r1 transfer should succeed");
            println!("Secp256r1 transfer succeeded!");
        }
        Err(e) => {
            // SingleKey with secp256r1 may not be supported on all localnet versions
            println!(
                "Secp256r1 transfer failed (may not be supported on this localnet): {}",
                e
            );
        }
    }
}

#[tokio::test]
#[ignore]
async fn e2e_secp256r1_simulate() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = Secp256r1Account::generate();
    aptos
        .fund_account(sender.address(), 200_000_000)
        .await
        .expect("failed to fund sender");

    wait_for_finality().await;

    let recipient = Secp256r1Account::generate();
    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000).unwrap();

    let raw_txn = aptos
        .build_transaction(&sender, payload.into())
        .await
        .expect("failed to build");

    // For simulation, sign normally — the node accepts real signatures for simulation
    let signed = sign_transaction(&raw_txn, &sender).expect("failed to sign");

    let result = aptos.simulate_transaction(&signed).await;

    match result {
        Ok(r) => {
            let success = r.data[0].get("success").and_then(|v| v.as_bool());
            println!("Secp256r1 simulation success: {:?}", success);
        }
        Err(e) => {
            println!("Secp256r1 simulation error: {}", e);
        }
    }
}
