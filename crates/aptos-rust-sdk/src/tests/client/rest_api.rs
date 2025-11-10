use crate::client::config::AptosNetwork;
use crate::client::rest_api::AptosFullnodeClient;

#[tokio::test]
async fn test_rest_client() {
    if std::env::var("SKIP_NETWORK_TESTS").is_ok() {
        return;
    }
    // TODO: Test against local testnet
    let aptos_client = AptosFullnodeClient::builder(AptosNetwork::localnet())
        .build()
        .await
        .unwrap();
    let state = aptos_client
        .get_state()
        .await
        .expect("Should successfully decode from headers");
    assert!(state.version > 0);
    assert_eq!(state.chain_id, 4);
}

#[tokio::test]
async fn test_get_by_version() {
    if std::env::var("SKIP_NETWORK_TESTS").is_ok() {
        return;
    }
    // TODO: Test against local testnet
    let aptos_client = AptosFullnodeClient::builder(AptosNetwork::localnet())
        .build()
        .await
        .unwrap();

    // Retrieve latest blockchain state
    let state = aptos_client
        .get_state()
        .await
        .expect("Expect blockchain state to be available");

    // Verify that latest transaction exists
    println!(
        "{:?}",
        aptos_client.get_transaction_by_version(state.version).await
    );
}
