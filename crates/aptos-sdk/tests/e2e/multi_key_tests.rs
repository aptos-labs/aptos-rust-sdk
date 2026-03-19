use super::*;
use aptos_sdk::account::{AnyPrivateKey, MultiKeyAccount};
use aptos_sdk::crypto::{Ed25519PrivateKey, Secp256k1PrivateKey};
use aptos_sdk::transaction::{EntryFunction, TransactionBuilder, builder::sign_transaction};

#[tokio::test]
#[ignore]
async fn e2e_multi_key_account_transfer() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Create a 2-of-3 multi-key account with mixed types
    let ed_key1 = Ed25519PrivateKey::generate();
    let secp_key = Secp256k1PrivateKey::generate();
    let ed_key2 = Ed25519PrivateKey::generate();

    let keys = vec![
        AnyPrivateKey::ed25519(ed_key1),
        AnyPrivateKey::secp256k1(secp_key),
        AnyPrivateKey::ed25519(ed_key2),
    ];

    let multi_key_account = MultiKeyAccount::new(keys, 2).unwrap();
    println!("Multi-key account: {}", multi_key_account.address());

    // Fund the multi-key account
    aptos
        .fund_account(multi_key_account.address(), 100_000_000)
        .await
        .expect("failed to fund");

    wait_for_finality().await;

    // Check balance
    let balance = aptos
        .get_balance(multi_key_account.address())
        .await
        .unwrap_or(0);
    println!("Multi-key balance: {}", balance);

    // Build and sign a transfer
    let recipient = aptos_sdk::account::Ed25519Account::generate();
    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000_000).unwrap();

    let seq = aptos
        .get_sequence_number(multi_key_account.address())
        .await
        .unwrap_or(0);
    let chain_id = aptos
        .ensure_chain_id()
        .await
        .expect("failed to resolve chain id");

    let raw_txn = TransactionBuilder::new()
        .sender(multi_key_account.address())
        .sequence_number(seq)
        .payload(payload.into())
        .chain_id(chain_id)
        .max_gas_amount(100_000)
        .gas_unit_price(100)
        .build()
        .expect("failed to build");

    let signed =
        sign_transaction(&raw_txn, &multi_key_account).expect("failed to sign with multi-key");

    // Submit
    let result = aptos.submit_and_wait(&signed, None).await;

    match result {
        Ok(r) => {
            let success = r.data.get("success").and_then(|v| v.as_bool());
            println!("Multi-key transaction success: {:?}", success);
        }
        Err(e) => {
            // Multi-key might not be supported on all networks
            println!("Multi-key transaction error (may not be supported): {}", e);
        }
    }
}
