use super::*;
use aptos_sdk::account::Ed25519Account;

#[tokio::test]
#[ignore]
async fn e2e_view_timestamp() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let result = aptos
        .view("0x1::timestamp::now_seconds", vec![], vec![])
        .await
        .expect("failed to call view function");

    assert!(!result.is_empty(), "should return a value");
    println!("Current timestamp: {:?}", result);

    // Parse the timestamp
    if let Some(timestamp) = result[0].as_str() {
        let ts: u64 = timestamp.parse().expect("should be a number");
        assert!(ts > 0, "timestamp should be > 0");
    }
}

#[tokio::test]
#[ignore]
async fn e2e_view_coin_balance() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let account = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    wait_for_finality().await;

    // Use view function to check balance
    let result = aptos
        .view(
            "0x1::coin::balance",
            vec!["0x1::aptos_coin::AptosCoin".to_string()],
            vec![serde_json::json!(account.address().to_string())],
        )
        .await
        .expect("failed to call view function");

    assert!(!result.is_empty());
    println!("Balance via view: {:?}", result);
}

#[tokio::test]
#[ignore]
async fn e2e_view_account_exists() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let account = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    wait_for_finality().await;

    // Check if account exists
    let result = aptos
        .view(
            "0x1::account::exists_at",
            vec![],
            vec![serde_json::json!(account.address().to_string())],
        )
        .await
        .expect("failed to call view function");

    assert_eq!(result[0], serde_json::json!(true));
}

#[tokio::test]
#[ignore]
async fn e2e_view_nonexistent_account() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let random_address = Ed25519Account::generate().address();
    println!("Random address: {}", random_address);

    let result = aptos
        .view(
            "0x1::account::exists_at",
            vec![],
            vec![serde_json::json!(random_address.to_string())],
        )
        .await
        .expect("failed to call view function");

    println!("Result: {:?}", result);
    // Note: Modern Aptos chains use implicit accounts (AIP-42), so all addresses
    // are considered to "exist" with sequence_number=0 until a transaction is made.
    // The view function returns true for all addresses now.
    assert_eq!(result[0], serde_json::json!(true));
}
