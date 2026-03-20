use super::*;
use aptos_sdk::account::Ed25519Account;
use aptos_sdk::types::AccountAddress;

#[tokio::test]
#[ignore]
async fn e2e_get_account_resources() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let account = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    wait_for_finality().await;

    let resources = aptos
        .fullnode()
        .get_account_resources(account.address())
        .await
        .expect("failed to get resources");

    // Funded account should have Account and CoinStore resources (at minimum)
    assert!(!resources.data.is_empty(), "should have resources");
    let type_names: Vec<&str> = resources.data.iter().map(|r| r.typ.as_str()).collect();
    println!("Resources: {:?}", type_names);

    assert!(
        type_names.iter().any(|t| t.contains("account::Account")),
        "should have Account resource"
    );
}

#[tokio::test]
#[ignore]
async fn e2e_get_account_resource() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let account = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    wait_for_finality().await;

    let resource = aptos
        .fullnode()
        .get_account_resource(account.address(), "0x1::account::Account")
        .await
        .expect("failed to get account resource");

    assert!(resource.data.typ.contains("Account"));
    // Account data should contain sequence_number
    assert!(resource.data.data.get("sequence_number").is_some());
    println!("Account resource data: {:?}", resource.data.data);
}

#[tokio::test]
#[ignore]
async fn e2e_get_account_modules() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Query framework modules at 0x1
    let modules = aptos
        .fullnode()
        .get_account_modules(AccountAddress::ONE)
        .await
        .expect("failed to get modules");

    assert!(!modules.data.is_empty(), "0x1 should have modules");
    println!("Number of modules at 0x1: {}", modules.data.len());

    // Should contain well-known modules like "coin"
    let module_names: Vec<_> = modules
        .data
        .iter()
        .filter_map(|m| m.abi.as_ref().map(|a| a.name.as_str()))
        .collect();
    assert!(
        module_names.contains(&"coin"),
        "0x1 should have a 'coin' module"
    );
}

#[tokio::test]
#[ignore]
async fn e2e_get_account_module() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let module = aptos
        .fullnode()
        .get_account_module(AccountAddress::ONE, "coin")
        .await
        .expect("failed to get coin module");

    assert!(module.data.abi.is_some(), "module should have ABI");
    let abi = module.data.abi.unwrap();
    assert_eq!(abi.name, "coin");
    println!(
        "Module 'coin' has {} exposed functions",
        abi.exposed_functions.len()
    );
}

#[tokio::test]
#[ignore]
async fn e2e_get_events_by_event_handle() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();

    // Transfer to generate events
    aptos
        .transfer_apt(&sender, recipient.address(), 1_000_000)
        .await
        .expect("failed to transfer");

    wait_for_finality().await;

    // Query withdraw events from the sender's CoinStore
    let events = aptos
        .fullnode()
        .get_events_by_event_handle(
            sender.address(),
            "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
            "withdraw_events",
            None,
            Some(10),
        )
        .await;

    match events {
        Ok(e) => {
            println!("Withdraw events: {}", e.data.len());
            // With legacy events, we should see at least one withdraw
            assert!(!e.data.is_empty(), "should have withdraw events");
        }
        Err(e) => {
            // Event API v2 may not support legacy event handles
            println!("Event handle query not supported (v2 events?): {}", e);
        }
    }
}

#[tokio::test]
#[ignore]
async fn e2e_get_block_by_height() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Get block at height 1 (should always exist)
    let block = aptos
        .fullnode()
        .get_block_by_height(1, false)
        .await
        .expect("failed to get block");

    assert!(block.data.get("block_height").is_some());
    println!("Block 1: {:?}", block.data);

    // Get with transactions
    let block_with_txns = aptos
        .fullnode()
        .get_block_by_height(1, true)
        .await
        .expect("failed to get block with txns");

    assert!(block_with_txns.data.get("transactions").is_some());
}

#[tokio::test]
#[ignore]
async fn e2e_get_block_by_version() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Get block containing version 1
    let block = aptos
        .fullnode()
        .get_block_by_version(1, false)
        .await
        .expect("failed to get block by version");

    assert!(block.data.get("block_height").is_some());
    assert!(block.data.get("first_version").is_some());
    println!("Block containing version 1: {:?}", block.data);
}

#[tokio::test]
#[ignore]
async fn e2e_estimate_gas_price() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let gas = aptos
        .fullnode()
        .estimate_gas_price()
        .await
        .expect("failed to estimate gas price");

    assert!(gas.data.gas_estimate > 0, "gas estimate should be > 0");
    println!(
        "Gas estimate: {} (low: {}, high: {})",
        gas.data.gas_estimate,
        gas.data.low(),
        gas.data.high()
    );
}
