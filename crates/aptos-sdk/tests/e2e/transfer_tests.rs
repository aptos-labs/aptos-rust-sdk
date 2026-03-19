use super::*;
use aptos_sdk::account::Ed25519Account;

#[tokio::test]
#[ignore]
async fn e2e_transfer_apt() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Create and fund sender
    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");
    println!("Sender: {}", sender.address());

    // Create recipient
    let recipient = Ed25519Account::generate();
    println!("Recipient: {}", recipient.address());

    // Transfer
    let result = aptos
        .transfer_apt(&sender, recipient.address(), 10_000_000)
        .await
        .expect("failed to transfer");

    let success = result.data.get("success").and_then(|v| v.as_bool());
    assert_eq!(success, Some(true), "transfer should succeed");
    println!("Transfer successful!");

    wait_for_finality().await;

    // Check recipient balance
    let balance = aptos
        .get_balance(recipient.address())
        .await
        .expect("failed to get balance");
    assert_eq!(
        balance, 10_000_000,
        "recipient should have transferred amount"
    );
}

#[tokio::test]
#[ignore]
async fn e2e_multiple_transfers() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(500_000_000)
        .await
        .expect("failed to create sender");

    // Transfer to multiple recipients
    let recipients: Vec<_> = (0..3).map(|_| Ed25519Account::generate()).collect();

    for (i, recipient) in recipients.iter().enumerate() {
        let result = aptos
            .transfer_apt(&sender, recipient.address(), 1_000_000 * (i as u64 + 1))
            .await
            .expect("failed to transfer");

        let success = result.data.get("success").and_then(|v| v.as_bool());
        assert_eq!(success, Some(true));
        println!("Transfer {} to {} successful", i + 1, recipient.address());
    }

    wait_for_finality().await;

    // Verify balances
    for (i, recipient) in recipients.iter().enumerate() {
        let balance = aptos.get_balance(recipient.address()).await.unwrap_or(0);
        let expected = 1_000_000 * (i as u64 + 1);
        assert_eq!(balance, expected, "recipient {} balance mismatch", i);
    }
}

#[tokio::test]
#[ignore]
async fn e2e_transfer_insufficient_balance() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(1_000_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();

    // Try to transfer more than we have
    let result = aptos
        .transfer_apt(&sender, recipient.address(), 999_999_999_999)
        .await;

    // Should fail (either at simulation or execution)
    assert!(
        result.is_err() || {
            let r = result.unwrap();
            r.data.get("success").and_then(|v| v.as_bool()) == Some(false)
        }
    );
}
