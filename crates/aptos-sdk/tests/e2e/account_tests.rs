use super::*;
use aptos_sdk::account::Ed25519Account;

#[tokio::test]
#[ignore]
async fn e2e_create_and_fund_account() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Create account
    let account = Ed25519Account::generate();
    println!("Created account: {}", account.address());

    // Fund account
    let txn_hashes = aptos
        .fund_account(account.address(), 100_000_000)
        .await
        .expect("failed to fund account");
    println!("Funded with txns: {:?}", txn_hashes);

    wait_for_finality().await;

    // Check balance
    let balance = aptos
        .get_balance(account.address())
        .await
        .expect("failed to get balance");
    assert!(balance > 0, "balance should be > 0");
    println!("Balance: {} octas", balance);
}

#[tokio::test]
#[ignore]
async fn e2e_create_funded_account_helper() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Use helper method
    let account = aptos
        .create_funded_account(50_000_000)
        .await
        .expect("failed to create funded account");

    println!("Created funded account: {}", account.address());

    wait_for_finality().await;

    let balance = aptos
        .get_balance(account.address())
        .await
        .expect("failed to get balance");
    assert!(balance > 0, "balance should be > 0");
}

#[tokio::test]
#[ignore]
async fn e2e_get_sequence_number() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let account = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    let seq_num = aptos
        .get_sequence_number(account.address())
        .await
        .expect("failed to get sequence number");

    println!("Sequence number: {}", seq_num);
    // New account should have sequence number 0
    assert_eq!(seq_num, 0);
}

#[tokio::test]
#[ignore]
async fn e2e_account_not_found() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Random unfunded account
    let account = Ed25519Account::generate();

    let result = aptos.get_sequence_number(account.address()).await;

    // Should get an error for non-existent account
    assert!(result.is_err() || result.unwrap() == 0);
}
