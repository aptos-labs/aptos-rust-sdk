use super::*;

#[tokio::test]
#[ignore]
async fn e2e_get_ledger_info() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let ledger_info = aptos
        .ledger_info()
        .await
        .expect("failed to get ledger info");

    println!(
        "Ledger version: {}",
        ledger_info.version().expect("failed to parse version")
    );
    println!(
        "Block height: {}",
        ledger_info.height().expect("failed to parse height")
    );
    println!(
        "Epoch: {}",
        ledger_info.epoch_num().expect("failed to parse epoch")
    );

    assert!(
        ledger_info.version().expect("failed to parse version") > 0,
        "ledger version should be > 0"
    );
}

#[tokio::test]
#[ignore]
async fn e2e_chain_id_from_ledger() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Just verify we can get ledger info
    let _ledger_info = aptos
        .ledger_info()
        .await
        .expect("failed to get ledger info");

    // Chain ID should be set
    assert!(aptos.chain_id().id() > 0);
    println!("Client chain ID: {}", aptos.chain_id().id());
}
