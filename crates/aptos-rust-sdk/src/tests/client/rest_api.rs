use crate::client::config::AptosNetwork;
use crate::client::rest_api::AptosFullnodeClient;

#[tokio::test]
async fn test_rest_client() {
    // TODO: Test against local testnet
    let aptos_client = AptosFullnodeClient::builder(AptosNetwork::localnet()).build();
    let state = aptos_client
        .get_state()
        .await
        .expect("Should successfully decode from headers");
    assert!(state.version > 0);
    assert_eq!(state.chain_id, 4);
}

#[tokio::test]
async fn test_get_by_version() {
    // TODO: Test against local testnet
    let aptos_client = AptosFullnodeClient::builder(AptosNetwork::testnet()).build();

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

#[tokio::test]
async fn test_get_by_hash() {

    let aptos_client = AptosFullnodeClient::builder(AptosNetwork::testnet()).build();

    // Query transaction
    println!(
        "Full node response {:?}",
        aptos_client.get_transaction_by_hash("0xd051f517d81f50e7b69a484bf6cea880c1a1f4a3e96cd5afdfd7a2e2a0cfc3b3".to_string()).await
    );
}
