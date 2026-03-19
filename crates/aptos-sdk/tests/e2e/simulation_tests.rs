use super::*;
use aptos_sdk::account::Ed25519Account;
use aptos_sdk::transaction::EntryFunction;

#[tokio::test]
#[ignore]
async fn e2e_simulate_successful_transfer() {
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
    assert!(result.gas_used() > 0, "should report gas");
    assert!(
        result.safe_gas_estimate() >= result.gas_used(),
        "safe estimate >= actual"
    );
    assert!(!result.events().is_empty(), "should have events");
    assert!(result.error_message().is_none(), "no error on success");
    println!(
        "Simulation: gas={}, safe_gas={}, events={}, vm_status={}",
        result.gas_used(),
        result.safe_gas_estimate(),
        result.events().len(),
        result.vm_status()
    );
}

#[tokio::test]
#[ignore]
async fn e2e_simulate_insufficient_balance() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Fund with very little
    let sender = aptos
        .create_funded_account(1_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();
    // Try to transfer way more than available
    let payload = EntryFunction::apt_transfer(recipient.address(), 999_999_999_999).unwrap();

    let result = aptos.simulate(&sender, payload.into()).await;

    match result {
        Ok(sim) => {
            // Simulation may succeed with failed status
            assert!(sim.failed(), "over-budget simulation should fail");
            assert!(sim.error_message().is_some(), "should have error message");
            println!("Simulation failure: {:?}", sim.error_message());
        }
        Err(e) => {
            // Or it may return an error directly
            println!("Simulation error (expected): {}", e);
        }
    }
}

#[tokio::test]
#[ignore]
async fn e2e_simulate_gas_accuracy() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();

    // First simulate
    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000).unwrap();
    let sim = aptos
        .simulate(&sender, payload.into())
        .await
        .expect("failed to simulate");
    let simulated_gas = sim.gas_used();

    // Then execute
    let payload2 = EntryFunction::apt_transfer(recipient.address(), 1_000).unwrap();
    let result = aptos
        .sign_submit_and_wait(&sender, payload2.into(), None)
        .await
        .expect("failed to execute");

    let actual_gas: u64 = result
        .data
        .get("gas_used")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    println!(
        "Simulated gas: {}, Actual gas: {}, Ratio: {:.2}",
        simulated_gas,
        actual_gas,
        simulated_gas as f64 / actual_gas as f64
    );

    // Simulated gas should be within 50% of actual gas
    let ratio = simulated_gas as f64 / actual_gas.max(1) as f64;
    assert!(
        (0.5..=2.0).contains(&ratio),
        "simulated/actual gas ratio {} should be between 0.5 and 2.0",
        ratio
    );
}

#[tokio::test]
#[ignore]
async fn e2e_simulate_invalid_module_call() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    // Build a raw transaction with a nonexistent module
    let module_id: aptos_sdk::types::MoveModuleId = "0x1::nonexistent_module".parse().unwrap();
    let payload = aptos_sdk::transaction::TransactionPayload::EntryFunction(
        aptos_sdk::transaction::EntryFunction::new(
            module_id,
            "nonexistent_function",
            vec![],
            vec![],
        ),
    );

    let result = aptos.simulate(&sender, payload).await;

    match result {
        Ok(sim) => {
            assert!(sim.failed(), "nonexistent module call should fail");
            println!("VM status: {}", sim.vm_status());
        }
        Err(e) => {
            // API may reject at the request level
            println!("Simulation error (expected): {}", e);
        }
    }
}

#[tokio::test]
#[ignore]
async fn e2e_simulate_state_changes() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();
    let payload = EntryFunction::apt_transfer(recipient.address(), 5_000_000).unwrap();

    let result = aptos
        .simulate(&sender, payload.into())
        .await
        .expect("failed to simulate");

    assert!(result.success());

    let changes = result.changes();
    println!("State changes: {}", changes.len());
    for change in changes {
        println!(
            "  - type: {}, address: {}",
            change.change_type, change.address
        );
    }
    // A transfer should produce state changes (at minimum, sender + receiver balances)
    assert!(!changes.is_empty(), "should have state changes");
}
