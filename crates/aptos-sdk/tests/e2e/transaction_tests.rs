use super::*;
use aptos_sdk::account::Ed25519Account;
use aptos_sdk::transaction::{EntryFunction, builder::sign_transaction};

#[tokio::test]
#[ignore]
async fn e2e_build_sign_submit_transaction() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    let recipient = Ed25519Account::generate();

    // Build transaction manually
    let payload = EntryFunction::apt_transfer(recipient.address(), 1000).unwrap();
    let raw_txn = aptos
        .build_transaction(&sender, payload.into())
        .await
        .expect("failed to build transaction");

    // Sign
    let signed = sign_transaction(&raw_txn, &sender).expect("failed to sign");

    // Debug: Print BCS bytes
    let bcs_bytes = signed.to_bcs().expect("failed to serialize");
    println!("BCS bytes ({} total):", bcs_bytes.len());
    println!(
        "First 100 bytes: {}",
        const_hex::encode(&bcs_bytes[..100.min(bcs_bytes.len())])
    );
    println!(
        "Last 100 bytes: {}",
        const_hex::encode(&bcs_bytes[bcs_bytes.len().saturating_sub(100)..])
    );
    println!(
        "Authenticator variant (byte at offset {}): {}",
        bcs_bytes.len() - 97,
        bcs_bytes.get(bcs_bytes.len() - 97).unwrap_or(&0)
    );

    // Submit
    let result = aptos
        .submit_and_wait(&signed, None)
        .await
        .expect("failed to submit");

    println!("Transaction result: {:?}", result.data);
}

#[tokio::test]
#[ignore]
async fn e2e_simulate_transaction() {
    use aptos_sdk::account::Account;
    use aptos_sdk::transaction::authenticator::{Ed25519PublicKey, Ed25519Signature};
    use aptos_sdk::transaction::{SignedTransaction, TransactionAuthenticator};

    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let account = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    let payload = EntryFunction::apt_transfer(Ed25519Account::generate().address(), 1000).unwrap();

    let raw_txn = aptos
        .build_transaction(&account, payload.into())
        .await
        .expect("failed to build transaction");

    // For simulation, we need to create a transaction with a zeroed signature
    // (the API rejects transactions with valid signatures for simulation)
    let auth = TransactionAuthenticator::Ed25519 {
        public_key: Ed25519PublicKey(account.public_key_bytes().try_into().unwrap()),
        signature: Ed25519Signature([0u8; 64]),
    };
    let signed = SignedTransaction::new(raw_txn, auth);

    // Simulate
    let result = aptos
        .simulate_transaction(&signed)
        .await
        .expect("failed to simulate");

    assert!(!result.data.is_empty(), "simulation should return results");

    let success = result.data[0].get("success").and_then(|v| v.as_bool());
    assert_eq!(success, Some(true), "simulation should succeed");

    let gas_used = result.data[0].get("gas_used").and_then(|v| v.as_str());
    println!("Simulated gas used: {:?}", gas_used);
}

#[tokio::test]
#[ignore]
async fn e2e_get_transaction_by_hash() {
    use aptos_sdk::types::HashValue;

    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    // Do a transfer
    let result = aptos
        .transfer_apt(&sender, Ed25519Account::generate().address(), 1000)
        .await
        .expect("failed to transfer");

    let hash_str = result.data.get("hash").and_then(|v| v.as_str()).unwrap();
    println!("Transaction hash: {}", hash_str);

    wait_for_finality().await;

    // Parse the hash and get transaction by hash (via fullnode client)
    let hash = HashValue::from_hex(hash_str).expect("invalid hash");
    let txn = aptos.fullnode().get_transaction_by_hash(&hash).await;
    assert!(txn.is_ok(), "should be able to get transaction by hash");
}

#[tokio::test]
#[ignore]
async fn e2e_transaction_expiration() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let account = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    // Build transaction with very short expiration (already expired)
    let payload = EntryFunction::apt_transfer(Ed25519Account::generate().address(), 1000).unwrap();
    let chain_id = aptos
        .ensure_chain_id()
        .await
        .expect("failed to resolve chain id");

    let raw_txn = aptos_sdk::transaction::TransactionBuilder::new()
        .sender(account.address())
        .sequence_number(0)
        .payload(payload.into())
        .chain_id(chain_id)
        .expiration_timestamp_secs(1) // Already expired
        .build()
        .expect("failed to build");

    let signed = sign_transaction(&raw_txn, &account).expect("failed to sign");

    // Submission should fail due to expiration
    let result = aptos.submit_and_wait(&signed, None).await;
    assert!(result.is_err(), "expired transaction should fail");
}
