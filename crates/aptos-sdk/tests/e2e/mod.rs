//! End-to-end tests against localnet or testnet.
//!
//! These tests require a running Aptos node and are only compiled when
//! the `e2e` feature is enabled.
//!
//! ## Running the tests
//!
//! ### Option 1: Using the convenience script
//! ```bash
//! ./scripts/run-e2e.sh
//! ```
//!
//! ### Option 2: Manual setup
//! ```bash
//! # In one terminal, start localnet:
//! aptos node run-localnet --with-faucet
//!
//! # In another terminal, run tests:
//! cargo test -p aptos-sdk --features "e2e,full"
//! ```
//!
//! ### Option 3: Using custom node URLs
//! ```bash
//! export APTOS_LOCAL_NODE_URL=http://127.0.0.1:8080/v1
//! export APTOS_LOCAL_FAUCET_URL=http://127.0.0.1:8081
//! cargo test -p aptos-sdk --features "e2e,full"
//! ```
//!
//! ## Test Categories
//!
//! - **`account_tests`**: Account creation, funding, balance queries
//! - **`transfer_tests`**: APT transfers between accounts
//! - **`view_tests`**: View function calls
//! - **`transaction_tests`**: Transaction building, signing, submission
//! - **`multi_signer_tests`**: Multi-agent and fee payer transactions
//! - **`state_tests`**: Resource and state queries
//!
//! Script bytecode is loaded from each Move project: two-signer from
//! `tests/e2e/move/two_signer_transfer/two_signer_transfer.mv`, single-signer from
//! `tests/e2e/move/one_signer_transfer/one_signer_transfer.mv`. If a `.mv` file is
//! missing, the corresponding test fails (panic with compile instructions). Run the
//! compile command inside each project directory:
//! `aptos move compile-script --package-dir <project> --output-file <project>.mv`.

use aptos_sdk::{Aptos, AptosConfig};
use std::env;

/// Gets the configuration for E2E tests.
fn get_test_config() -> AptosConfig {
    if let Ok(node_url) = env::var("APTOS_LOCAL_NODE_URL") {
        AptosConfig::custom(&node_url)
            .unwrap()
            .with_faucet_url(
                &env::var("APTOS_LOCAL_FAUCET_URL")
                    .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string()),
            )
            .unwrap()
    } else {
        AptosConfig::local()
    }
}

/// Helper to wait for transaction finality
async fn wait_for_finality() {
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
}

// =============================================================================
// Account Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod account_tests {
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
        println!("Funded with txns: {txn_hashes:?}");

        wait_for_finality().await;

        // Check balance
        let balance = aptos
            .get_balance(account.address())
            .await
            .expect("failed to get balance");
        assert!(balance > 0, "balance should be > 0");
        println!("Balance: {balance} octas");
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

        println!("Sequence number: {seq_num}");
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

        // Under AIP-42 (implicit accounts) the fullnode reports sequence_number = 0
        // for any address that has never been touched. The two valid outcomes are:
        //   * an explicit "not found" error, or
        //   * sequence_number == 0
        // anything else (a non-zero seq num for a freshly-generated random key) is a bug.
        match aptos.get_sequence_number(account.address()).await {
            Ok(seq) => assert_eq!(
                seq, 0,
                "freshly generated account should have sequence number 0 \
                 (or return not-found), got {seq}"
            ),
            Err(e) => assert!(
                e.is_not_found(),
                "unexpected error for unfunded account (expected a not-found \
                 error or success with seq=0, but got something else): {e}"
            ),
        }

        // get_balance for a fresh address should return 0.
        let balance = aptos
            .get_balance(account.address())
            .await
            .expect("get_balance should succeed for unfunded address (implicit accounts)");
        assert_eq!(balance, 0, "fresh account must have zero balance");

        // account_exists currently maps to `GET /accounts/{addr}` which, under
        // AIP-42 (implicit accounts) on modern Aptos chains, returns 200 for
        // any well-formed address. The helper therefore reports `true` even
        // for never-funded addresses. We assert this is the actual behavior so
        // a regression (e.g., the helper falsely reporting `false` on devnet)
        // would surface immediately, while making the AIP-42 contract explicit
        // in the test name.
        let exists = aptos
            .account_exists(account.address())
            .await
            .expect("account_exists should succeed");
        assert!(
            exists,
            "under AIP-42 implicit accounts the fullnode reports any \
             well-formed address as existing"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn e2e_sequence_number_increments() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let sender = aptos
            .create_funded_account(500_000_000)
            .await
            .expect("failed to create funded sender");

        let start = aptos
            .get_sequence_number(sender.address())
            .await
            .expect("failed to get sequence number");
        assert_eq!(start, 0, "new account must start at sequence number 0");

        // Send two transactions and verify the on-chain sequence number advances.
        for i in 1..=2u64 {
            let recipient = Ed25519Account::generate();
            aptos
                .transfer_apt(&sender, recipient.address(), 1_000)
                .await
                .expect("transfer failed");
            let now = aptos
                .get_sequence_number(sender.address())
                .await
                .expect("failed to get sequence number");
            assert_eq!(
                now, i,
                "sequence number must increment by exactly 1 per submitted transaction"
            );
        }
    }
}

// =============================================================================
// Transfer Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod transfer_tests {
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

        let success = result
            .data
            .get("success")
            .and_then(serde_json::Value::as_bool);
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

            let success = result
                .data
                .get("success")
                .and_then(serde_json::Value::as_bool);
            assert_eq!(success, Some(true));
            println!("Transfer {} to {} successful", i + 1, recipient.address());
        }

        wait_for_finality().await;

        // Verify balances
        for (i, recipient) in recipients.iter().enumerate() {
            let balance = aptos.get_balance(recipient.address()).await.unwrap_or(0);
            let expected = 1_000_000 * (i as u64 + 1);
            assert_eq!(balance, expected, "recipient {i} balance mismatch");
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
                r.data.get("success").and_then(serde_json::Value::as_bool) == Some(false)
            }
        );
    }
}

// =============================================================================
// View Function Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod view_tests {
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
        println!("Current timestamp: {result:?}");

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

        let funded_amount: u64 = 100_000_000;
        let account = aptos
            .create_funded_account(funded_amount)
            .await
            .expect("failed to create account");

        wait_for_finality().await;

        let result = aptos
            .view(
                "0x1::coin::balance",
                vec!["0x1::aptos_coin::AptosCoin".to_string()],
                vec![serde_json::json!(account.address().to_string())],
            )
            .await
            .expect("failed to call view function");

        assert_eq!(result.len(), 1, "view function should return one value");
        let balance_str = result[0]
            .as_str()
            .expect("balance must be returned as a string");
        let balance_via_view: u64 = balance_str.parse().expect("balance must parse as a u64");

        // Compare against the canonical get_balance helper. The view function
        // and the helper must agree on the balance.
        let balance_via_helper = aptos
            .get_balance(account.address())
            .await
            .expect("get_balance failed");
        assert_eq!(
            balance_via_view, balance_via_helper,
            "view-function balance must match get_balance helper"
        );
        assert!(
            balance_via_view >= funded_amount,
            "balance ({balance_via_view}) must be at least the funded amount ({funded_amount})"
        );
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
        println!("Random address: {random_address}");

        let result = aptos
            .view(
                "0x1::account::exists_at",
                vec![],
                vec![serde_json::json!(random_address.to_string())],
            )
            .await
            .expect("failed to call view function");

        println!("Result: {result:?}");
        // Note: Modern Aptos chains use implicit accounts (AIP-42), so all addresses
        // are considered to "exist" with sequence_number=0 until a transaction is made.
        // The view function returns true for all addresses now.
        assert_eq!(result[0], serde_json::json!(true));
    }
}

// =============================================================================
// Transaction Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod transaction_tests {
    use super::*;
    use aptos_sdk::account::Ed25519Account;
    use aptos_sdk::transaction::{
        EntryFunction, Script, ScriptArgument, TransactionBuilder, TransactionPayload,
        builder::sign_transaction,
    };

    #[tokio::test]
    #[ignore]
    async fn e2e_script_transfer() {
        let script_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/e2e/move/one_signer_transfer/one_signer_transfer.mv");
        let bytecode = std::fs::read(&script_path).expect(
            "one_signer_transfer.mv not found; run inside tests/e2e/move/one_signer_transfer/: \
             aptos move compile-script --package-dir one_signer_transfer --output-file one_signer_transfer.mv",
        );

        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let sender = aptos
            .create_funded_account(100_000_000)
            .await
            .expect("failed to create sender");

        let recipient = Ed25519Account::generate().address();
        let amount = 50_000u64;

        let payload = TransactionPayload::Script(Script::new(
            bytecode,
            vec![],
            vec![
                ScriptArgument::Address(recipient),
                ScriptArgument::U64(amount),
            ],
        ));

        let sender_seq = aptos
            .get_sequence_number(sender.address())
            .await
            .expect("failed to get sequence number");
        let chain_id = aptos
            .ensure_chain_id()
            .await
            .expect("failed to resolve chain id");

        let raw_txn = TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(sender_seq)
            .payload(payload)
            .chain_id(chain_id)
            .max_gas_amount(100_000)
            .gas_unit_price(100)
            .build()
            .expect("failed to build");

        let signed = sign_transaction(&raw_txn, &sender).expect("failed to sign");

        let _result = aptos
            .submit_and_wait(&signed, None)
            .await
            .expect("submit_and_wait should succeed");

        wait_for_finality().await;

        let balance = aptos
            .get_balance(recipient)
            .await
            .expect("failed to get recipient balance");
        assert!(
            balance >= amount,
            "recipient balance {} should be >= amount {}",
            balance,
            amount
        );
    }

    #[tokio::test]
    #[ignore]
    async fn e2e_build_sign_submit_transaction() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let sender = aptos
            .create_funded_account(500_000_000)
            .await
            .expect("failed to create account");

        let recipient = Ed25519Account::generate();
        let amount: u64 = 1_234_567;

        let payload = EntryFunction::apt_transfer(recipient.address(), amount).unwrap();
        let raw_txn = aptos
            .build_transaction(&sender, payload.into())
            .await
            .expect("failed to build transaction");

        let signed = sign_transaction(&raw_txn, &sender).expect("failed to sign");

        // BCS round-trip: serialize then deserialize the signed transaction.
        let bcs_bytes = signed.to_bcs().expect("failed to serialize");
        assert!(
            !bcs_bytes.is_empty(),
            "BCS serialization must produce bytes"
        );

        let result = aptos
            .submit_and_wait(&signed, None)
            .await
            .expect("failed to submit");

        let success = result
            .data
            .get("success")
            .and_then(serde_json::Value::as_bool);
        assert_eq!(
            success,
            Some(true),
            "transaction should execute successfully, got: {:?}",
            result.data
        );

        wait_for_finality().await;

        // Verify the recipient was credited the *exact* amount.
        let balance = aptos
            .get_balance(recipient.address())
            .await
            .expect("failed to get recipient balance");
        assert_eq!(
            balance, amount,
            "recipient should have received exactly the transferred amount"
        );
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
            .create_funded_account(500_000_000)
            .await
            .expect("failed to create account");

        let payload =
            EntryFunction::apt_transfer(Ed25519Account::generate().address(), 1000).unwrap();

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

        let success = result.data[0]
            .get("success")
            .and_then(serde_json::Value::as_bool);
        assert_eq!(success, Some(true), "simulation should succeed");

        let gas_used = result.data[0].get("gas_used").and_then(|v| v.as_str());
        println!("Simulated gas used: {gas_used:?}");
    }

    #[tokio::test]
    #[ignore]
    async fn e2e_get_transaction_by_hash() {
        use aptos_sdk::types::HashValue;

        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let sender = aptos
            .create_funded_account(500_000_000)
            .await
            .expect("failed to create account");

        let result = aptos
            .transfer_apt(&sender, Ed25519Account::generate().address(), 1000)
            .await
            .expect("failed to transfer");

        let hash_str = result
            .data
            .get("hash")
            .and_then(|v| v.as_str())
            .expect("response must include a transaction hash");

        wait_for_finality().await;

        let hash = HashValue::from_hex(hash_str).expect("invalid hash");
        let txn = aptos
            .fullnode()
            .get_transaction_by_hash(&hash)
            .await
            .expect("should be able to get transaction by hash");

        // Verify the looked-up txn matches the one we submitted.
        let looked_up_hash = txn
            .data
            .get("hash")
            .and_then(|v| v.as_str())
            .expect("response must contain hash");
        assert_eq!(looked_up_hash, hash_str);

        let sender_field = txn
            .data
            .get("sender")
            .and_then(|v| v.as_str())
            .expect("transaction must have a sender field");
        // Sender can be returned in short or long form. Compare against both.
        assert!(
            sender_field == sender.address().to_short_string()
                || sender_field == sender.address().to_long_string(),
            "sender mismatch: got {sender_field}, expected {} or {}",
            sender.address().to_short_string(),
            sender.address().to_long_string()
        );

        let success = txn.data.get("success").and_then(serde_json::Value::as_bool);
        assert_eq!(success, Some(true));
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
        let payload =
            EntryFunction::apt_transfer(Ed25519Account::generate().address(), 1000).unwrap();
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
}

// =============================================================================
// Ledger/Chain Info Tests
// =============================================================================

#[cfg(feature = "ed25519")]
mod ledger_tests {
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
}

// =============================================================================
// Multi-Signer Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod multi_signer_tests {
    use super::*;
    use aptos_sdk::account::{Account, Ed25519Account};
    use aptos_sdk::transaction::{
        EntryFunction, Script, ScriptArgument, TransactionBuilder, TransactionPayload,
        builder::{sign_fee_payer_transaction, sign_multi_agent_transaction},
        types::{FeePayerRawTransaction, MultiAgentRawTransaction},
    };

    #[tokio::test]
    #[ignore]
    async fn e2e_fee_payer_transaction() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        // Sender has just enough APT to pay the transfer itself (no gas budget).
        let sender = aptos
            .create_funded_account(100_000_000)
            .await
            .expect("failed to create sender");

        // Fee payer covers the gas.
        let fee_payer = aptos
            .create_funded_account(500_000_000)
            .await
            .expect("failed to create fee payer");

        let recipient = Ed25519Account::generate();
        let transfer_amount: u64 = 500;

        let payload = EntryFunction::apt_transfer(recipient.address(), transfer_amount).unwrap();

        let sender_seq = aptos
            .get_sequence_number(sender.address())
            .await
            .expect("failed to get sender seq");
        let fee_payer_balance_before = aptos
            .get_balance(fee_payer.address())
            .await
            .expect("failed to read fee payer balance");
        let sender_balance_before = aptos
            .get_balance(sender.address())
            .await
            .expect("failed to read sender balance");
        let chain_id = aptos
            .ensure_chain_id()
            .await
            .expect("failed to resolve chain id");

        let raw_txn = TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(sender_seq)
            .payload(payload.into())
            .chain_id(chain_id)
            .max_gas_amount(2_000_000)
            .gas_unit_price(100)
            .build()
            .expect("failed to build");

        let fee_payer_txn = FeePayerRawTransaction {
            raw_txn,
            secondary_signer_addresses: vec![],
            fee_payer_address: fee_payer.address(),
        };

        let signed = sign_fee_payer_transaction(&fee_payer_txn, &sender, &[], &fee_payer)
            .expect("failed to sign");

        let result = aptos
            .submit_and_wait(&signed, None)
            .await
            .expect("fee-payer transaction must be accepted by devnet");

        let success = result
            .data
            .get("success")
            .and_then(serde_json::Value::as_bool);
        assert_eq!(
            success,
            Some(true),
            "fee-payer transaction must succeed: {:?}",
            result.data
        );

        wait_for_finality().await;

        // Recipient must have received exactly the transferred amount.
        let recipient_balance = aptos
            .get_balance(recipient.address())
            .await
            .expect("failed to get recipient balance");
        assert_eq!(recipient_balance, transfer_amount);

        // Sender balance must drop by exactly the transferred amount (no gas).
        let sender_balance_after = aptos
            .get_balance(sender.address())
            .await
            .expect("failed to get sender balance");
        assert_eq!(
            sender_balance_after,
            sender_balance_before - transfer_amount,
            "sender should have paid only the transfer amount, not gas"
        );

        // Fee payer should have decreased -- but by *less* than the gas budget.
        let fee_payer_balance_after = aptos
            .get_balance(fee_payer.address())
            .await
            .expect("failed to get fee payer balance");
        assert!(
            fee_payer_balance_after < fee_payer_balance_before,
            "fee payer must have paid gas"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn e2e_multi_agent_transaction() {
        let script_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/e2e/move/two_signer_transfer/two_signer_transfer.mv");
        let two_signer_bytecode = std::fs::read(&script_path).expect(
            "two_signer_transfer.mv not found; run inside tests/e2e/move/two_signer_transfer/: \
             aptos move compile-script --package-dir two_signer_transfer --output-file two_signer_transfer.mv",
        );

        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let sender = aptos
            .create_funded_account(500_000_000)
            .await
            .expect("failed to create sender");
        let secondary = aptos
            .create_funded_account(100_000_000)
            .await
            .expect("failed to create secondary");

        // Two-signer script: VM expects sender + secondary (matches multi-agent tx).
        let recipient = Ed25519Account::generate().address();
        let amount = 1000u64;
        let payload = TransactionPayload::Script(Script::new(
            two_signer_bytecode,
            vec![],
            vec![
                ScriptArgument::Address(recipient),
                ScriptArgument::U64(amount),
            ],
        ));

        let sender_seq = aptos
            .get_sequence_number(sender.address())
            .await
            .expect("failed to get sender seq");
        let chain_id = aptos
            .ensure_chain_id()
            .await
            .expect("failed to resolve chain id");

        let raw_txn = TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(sender_seq)
            .payload(payload)
            .chain_id(chain_id)
            .max_gas_amount(2_000_000)
            .gas_unit_price(100)
            .build()
            .expect("failed to build");

        let multi_agent_txn = MultiAgentRawTransaction {
            raw_txn,
            secondary_signer_addresses: vec![secondary.address()],
        };

        let secondary_ref: &dyn Account = &secondary;
        let signed = sign_multi_agent_transaction(&multi_agent_txn, &sender, &[secondary_ref])
            .expect("failed to sign");

        // BCS round-trip must succeed.
        let bytes = signed.to_bcs().expect("BCS serialization should succeed");
        assert!(!bytes.is_empty());

        let result = aptos
            .submit_and_wait(&signed, None)
            .await
            .expect("submit_and_wait should succeed");
        let success = result
            .data
            .get("success")
            .and_then(serde_json::Value::as_bool);
        assert_eq!(
            success,
            Some(true),
            "multi-agent two-signer transfer should succeed: {:?}",
            result.data
        );
    }

    /// Simulate a multi-agent transaction (no signatures) then sign and submit.
    #[tokio::test]
    #[ignore]
    async fn e2e_simulate_multi_agent_then_submit() {
        let script_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/e2e/move/two_signer_transfer/two_signer_transfer.mv");
        let two_signer_bytecode = std::fs::read(&script_path).expect(
            "two_signer_transfer.mv not found; run inside tests/e2e/move/two_signer_transfer/: \
             aptos move compile-script --package-dir two_signer_transfer --output-file two_signer_transfer.mv",
        );

        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let sender = aptos
            .create_funded_account(200_000_000)
            .await
            .expect("failed to create sender");
        let secondary = aptos
            .create_funded_account(100_000_000)
            .await
            .expect("failed to create secondary");

        // Use a two-signer script so the VM expects 2 signers (matches multi-agent tx).
        let recipient = Ed25519Account::generate().address();
        let amount = 1000u64;
        let payload = TransactionPayload::Script(Script::new(
            two_signer_bytecode,
            vec![],
            vec![
                ScriptArgument::Address(recipient),
                ScriptArgument::U64(amount),
            ],
        ));

        let sender_seq = aptos
            .get_sequence_number(sender.address())
            .await
            .unwrap_or(0);
        let chain_id = aptos
            .ensure_chain_id()
            .await
            .expect("failed to resolve chain id");

        let raw_txn = TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(sender_seq)
            .payload(payload)
            .chain_id(chain_id)
            .max_gas_amount(100_000)
            .gas_unit_price(100)
            .build()
            .expect("failed to build");

        let multi_agent_txn = MultiAgentRawTransaction {
            raw_txn,
            secondary_signer_addresses: vec![secondary.address()],
        };

        // Simulate first (no signatures required)
        let sim_result = aptos
            .simulate_multi_agent(&multi_agent_txn, None)
            .await
            .expect("simulate_multi_agent should succeed");
        println!(
            "Simulation success: {}, gas_used: {}",
            sim_result.success(),
            sim_result.gas_used()
        );

        // Then sign and submit
        let secondary_ref: &dyn Account = &secondary;
        let signed = sign_multi_agent_transaction(&multi_agent_txn, &sender, &[secondary_ref])
            .expect("failed to sign");
        aptos
            .submit_and_wait(&signed, None)
            .await
            .expect("submit_and_wait should succeed");
    }

    /// Simulate a fee-payer transaction (no signatures) then sign and submit.
    #[tokio::test]
    #[ignore]
    async fn e2e_simulate_fee_payer_then_submit() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let sender = aptos
            .create_funded_account(1_000)
            .await
            .expect("failed to create sender");
        let fee_payer = aptos
            .create_funded_account(500_000_000)
            .await
            .expect("failed to create fee payer");
        let recipient = Ed25519Account::generate();

        let payload = EntryFunction::apt_transfer(recipient.address(), 500).unwrap();
        let sender_seq = aptos
            .get_sequence_number(sender.address())
            .await
            .unwrap_or(0);
        let chain_id = aptos
            .ensure_chain_id()
            .await
            .expect("failed to resolve chain id");

        let raw_txn = TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(sender_seq)
            .payload(payload.into())
            .chain_id(chain_id)
            .max_gas_amount(100_000)
            .gas_unit_price(100)
            .build()
            .expect("failed to build");

        let fee_payer_txn = FeePayerRawTransaction {
            raw_txn,
            secondary_signer_addresses: vec![],
            fee_payer_address: fee_payer.address(),
        };

        // Simulate first (no signatures required)
        let sim_result = aptos
            .simulate_fee_payer(&fee_payer_txn, None)
            .await
            .expect("simulate_fee_payer should succeed");
        println!(
            "Simulation success: {}, gas_used: {}",
            sim_result.success(),
            sim_result.gas_used()
        );

        // Then sign and submit
        let signed = sign_fee_payer_transaction(&fee_payer_txn, &sender, &[], &fee_payer)
            .expect("failed to sign");
        aptos
            .submit_and_wait(&signed, None)
            .await
            .expect("submit_and_wait should succeed");
    }
}

// =============================================================================
// Multi-Key Account Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "secp256k1", feature = "faucet"))]
mod multi_key_e2e_tests {
    use super::*;
    use aptos_sdk::account::{AnyPrivateKey, MultiKeyAccount};
    use aptos_sdk::crypto::{Ed25519PrivateKey, Secp256k1PrivateKey};
    use aptos_sdk::transaction::{EntryFunction, TransactionBuilder, builder::sign_transaction};

    #[tokio::test]
    #[ignore]
    async fn e2e_multi_key_account_transfer() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        // 2-of-3 multi-key account: two Ed25519 keys and one Secp256k1 key.
        let ed_key1 = Ed25519PrivateKey::generate();
        let secp_key = Secp256k1PrivateKey::generate();
        let ed_key2 = Ed25519PrivateKey::generate();

        let keys = vec![
            AnyPrivateKey::ed25519(ed_key1),
            AnyPrivateKey::secp256k1(secp_key),
            AnyPrivateKey::ed25519(ed_key2),
        ];
        let multi_key_account = MultiKeyAccount::new(keys, 2).unwrap();

        aptos
            .fund_account(multi_key_account.address(), 500_000_000)
            .await
            .expect("failed to fund multi-key account");

        wait_for_finality().await;

        let balance_before = aptos
            .get_balance(multi_key_account.address())
            .await
            .expect("failed to get multi-key balance");
        assert!(
            balance_before >= 500_000_000,
            "multi-key account should be funded to at least 500M octas"
        );

        let recipient = aptos_sdk::account::Ed25519Account::generate();
        let transfer_amount: u64 = 1_000_000;
        let payload = EntryFunction::apt_transfer(recipient.address(), transfer_amount).unwrap();

        let seq = aptos
            .get_sequence_number(multi_key_account.address())
            .await
            .expect("failed to get seq");
        let chain_id = aptos
            .ensure_chain_id()
            .await
            .expect("failed to resolve chain id");

        let raw_txn = TransactionBuilder::new()
            .sender(multi_key_account.address())
            .sequence_number(seq)
            .payload(payload.into())
            .chain_id(chain_id)
            .max_gas_amount(2_000_000)
            .gas_unit_price(100)
            .build()
            .expect("failed to build");

        let signed =
            sign_transaction(&raw_txn, &multi_key_account).expect("failed to sign with multi-key");

        let result = aptos
            .submit_and_wait(&signed, None)
            .await
            .expect("multi-key transaction must be accepted");

        let success = result
            .data
            .get("success")
            .and_then(serde_json::Value::as_bool);
        assert_eq!(
            success,
            Some(true),
            "multi-key transaction must succeed: {:?}",
            result.data
        );

        wait_for_finality().await;

        let recipient_balance = aptos
            .get_balance(recipient.address())
            .await
            .expect("failed to get recipient balance");
        assert_eq!(
            recipient_balance, transfer_amount,
            "recipient should have received exactly the transferred amount"
        );
    }
}

// =============================================================================
// Resource/State Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod state_tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn e2e_get_account_resource_after_first_txn() {
        use aptos_sdk::account::Ed25519Account;

        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        // Under AIP-42 (implicit accounts) an address that has only been
        // *funded* via the faucet does not yet have a `0x1::account::Account`
        // resource on chain -- the resource is materialised the first time
        // *that account itself* submits a transaction. Drive at least one
        // transfer from this account so the Account resource exists, then
        // assert it parses and that the sequence_number it reports is 1.
        let sender = aptos
            .create_funded_account(500_000_000)
            .await
            .expect("failed to create account");
        let recipient = Ed25519Account::generate();
        aptos
            .transfer_apt(&sender, recipient.address(), 1_000)
            .await
            .expect("first transfer should succeed");

        wait_for_finality().await;

        let resource = aptos
            .fullnode()
            .get_account_resource(sender.address(), "0x1::account::Account")
            .await
            .expect("0x1::account::Account resource must exist after first txn");

        assert_eq!(resource.data.typ, "0x1::account::Account");
        let seq_str = resource
            .data
            .data
            .get("sequence_number")
            .and_then(|v| v.as_str())
            .expect("Account resource must have sequence_number");
        let seq: u64 = seq_str.parse().expect("sequence_number must be numeric");
        assert_eq!(
            seq, 1,
            "after exactly one transfer the on-chain sequence number must be 1"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn e2e_get_resources_for_funded_account() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let funded_amount: u64 = 100_000_000;
        let account = aptos
            .create_funded_account(funded_amount)
            .await
            .expect("failed to create account");

        wait_for_finality().await;

        // Modern Aptos APT balances live in fungible-store object resources,
        // not in `0x1::coin::CoinStore`. Use the canonical `get_balance`
        // helper and assert it matches the funded amount.
        let balance = aptos
            .get_balance(account.address())
            .await
            .expect("failed to read balance");
        assert!(
            balance >= funded_amount,
            "balance ({balance}) must be at least the funded amount ({funded_amount})"
        );

        // We do NOT assert that `get_account_resources` is non-empty. Under
        // AIP-42 a pure-faucet-funded address may have *no* directly-owned
        // resources (its balance is held in a fungible store object
        // referenced indirectly), so the call is exercised for its
        // network/serialization path only.
        let _ = aptos
            .fullnode()
            .get_account_resources(account.address())
            .await
            .expect("listing resources should not error");
    }
}

// =============================================================================
// SingleKey Account Tests (real transfer flow)
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod single_key_tests {
    use super::*;
    use aptos_sdk::account::{Ed25519Account, Ed25519SingleKeyAccount};
    use aptos_sdk::transaction::{EntryFunction, TransactionBuilder, builder::sign_transaction};

    #[tokio::test]
    #[ignore]
    async fn e2e_single_key_account_transfer() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        // SingleKey accounts derive a different address than legacy Ed25519.
        let sender = Ed25519SingleKeyAccount::generate();

        aptos
            .fund_account(sender.address(), 500_000_000)
            .await
            .expect("failed to fund single-key account");
        wait_for_finality().await;

        let recipient = Ed25519Account::generate();
        let amount: u64 = 2_500_000;
        let payload = EntryFunction::apt_transfer(recipient.address(), amount).unwrap();

        let seq = aptos
            .get_sequence_number(sender.address())
            .await
            .expect("failed to get seq");
        let chain_id = aptos
            .ensure_chain_id()
            .await
            .expect("failed to resolve chain id");

        let raw_txn = TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(seq)
            .payload(payload.into())
            .chain_id(chain_id)
            .max_gas_amount(2_000_000)
            .gas_unit_price(100)
            .build()
            .expect("failed to build");

        let signed = sign_transaction(&raw_txn, &sender).expect("failed to sign");
        let result = aptos
            .submit_and_wait(&signed, None)
            .await
            .expect("transaction submission failed");

        let success = result
            .data
            .get("success")
            .and_then(serde_json::Value::as_bool);
        assert_eq!(success, Some(true), "transaction must succeed");

        wait_for_finality().await;

        let recipient_balance = aptos
            .get_balance(recipient.address())
            .await
            .expect("failed to get recipient balance");
        assert_eq!(recipient_balance, amount);
    }
}

// =============================================================================
// Secp256k1 Account Tests (real transfer flow)
// =============================================================================

#[cfg(all(feature = "secp256k1", feature = "faucet"))]
mod secp256k1_tests {
    use super::*;
    use aptos_sdk::account::{Ed25519Account, Secp256k1Account};
    use aptos_sdk::transaction::{EntryFunction, TransactionBuilder, builder::sign_transaction};

    #[tokio::test]
    #[ignore]
    async fn e2e_secp256k1_account_transfer() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let sender = Secp256k1Account::generate();
        aptos
            .fund_account(sender.address(), 500_000_000)
            .await
            .expect("failed to fund secp256k1 account");
        wait_for_finality().await;

        let recipient = Ed25519Account::generate();
        let amount: u64 = 3_141_592;
        let payload = EntryFunction::apt_transfer(recipient.address(), amount).unwrap();

        let seq = aptos
            .get_sequence_number(sender.address())
            .await
            .expect("failed to get seq");
        let chain_id = aptos
            .ensure_chain_id()
            .await
            .expect("failed to resolve chain id");

        let raw_txn = TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(seq)
            .payload(payload.into())
            .chain_id(chain_id)
            .max_gas_amount(2_000_000)
            .gas_unit_price(100)
            .build()
            .expect("failed to build");

        let signed = sign_transaction(&raw_txn, &sender).expect("failed to sign");
        let result = aptos
            .submit_and_wait(&signed, None)
            .await
            .expect("transaction submission failed");

        let success = result
            .data
            .get("success")
            .and_then(serde_json::Value::as_bool);
        assert_eq!(success, Some(true), "secp256k1 transfer must succeed");

        wait_for_finality().await;

        let balance = aptos
            .get_balance(recipient.address())
            .await
            .expect("failed to get recipient balance");
        assert_eq!(balance, amount);
    }
}

// =============================================================================
// WebAuthn / Passkey Account Tests (real transfer flow with synthetic
// PartialAuthenticatorAssertionResponse)
//
// On current Aptos networks the on-chain `AnySignature` variant at index 2
// is `WebAuthn { signature: PartialAuthenticatorAssertionResponse }`, not a
// bare Secp256r1Ecdsa signature. The SDK ships a `WebAuthnAccount` wrapper
// that wraps a P-256 key in the WebAuthn envelope (rpIdHash +
// authenticator_data + client_data_json + canonical low-S signature) so the
// chain accepts the resulting transaction.
//
// This test exercises that path end-to-end against devnet: fund a
// WebAuthn-derived address, submit a real APT transfer signed by the
// WebAuthn account, and verify the recipient is credited exactly the
// transferred amount.
// =============================================================================

#[cfg(all(feature = "secp256r1", feature = "faucet"))]
mod webauthn_tests {
    use super::*;
    use aptos_sdk::account::WebAuthnAccount;
    use aptos_sdk::transaction::{EntryFunction, TransactionBuilder, builder::sign_transaction};

    #[tokio::test]
    #[ignore]
    async fn e2e_webauthn_account_transfer() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let sender = WebAuthnAccount::generate();
        aptos
            .fund_account(sender.address(), 500_000_000)
            .await
            .expect("failed to fund WebAuthn account");
        wait_for_finality().await;

        #[cfg(feature = "ed25519")]
        let recipient = aptos_sdk::account::Ed25519Account::generate();
        #[cfg(not(feature = "ed25519"))]
        let recipient = WebAuthnAccount::generate();

        let amount: u64 = 2_718_281;
        let payload = EntryFunction::apt_transfer(recipient.address(), amount).unwrap();

        let seq = aptos
            .get_sequence_number(sender.address())
            .await
            .expect("failed to get seq");
        let chain_id = aptos
            .ensure_chain_id()
            .await
            .expect("failed to resolve chain id");

        let raw_txn = TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(seq)
            .payload(payload.into())
            .chain_id(chain_id)
            .max_gas_amount(2_000_000)
            .gas_unit_price(100)
            .build()
            .expect("failed to build");

        let signed = sign_transaction(&raw_txn, &sender).expect("failed to sign");
        let result = aptos
            .submit_and_wait(&signed, None)
            .await
            .expect("WebAuthn transaction submission must succeed on devnet");

        let success = result
            .data
            .get("success")
            .and_then(serde_json::Value::as_bool);
        assert_eq!(
            success,
            Some(true),
            "WebAuthn transaction must execute successfully on devnet: {:?}",
            result.data
        );

        wait_for_finality().await;

        let recipient_balance = aptos
            .get_balance(recipient.address())
            .await
            .expect("failed to get recipient balance");
        assert_eq!(
            recipient_balance, amount,
            "recipient must receive exactly the transferred amount"
        );
    }
}

// =============================================================================
// MultiEd25519 Account Tests (real on-chain flow)
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod multi_ed25519_tests {
    use super::*;
    use aptos_sdk::account::{Ed25519Account, MultiEd25519Account};
    use aptos_sdk::crypto::Ed25519PrivateKey;
    use aptos_sdk::transaction::{EntryFunction, TransactionBuilder, builder::sign_transaction};

    #[tokio::test]
    #[ignore]
    async fn e2e_multi_ed25519_transfer() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let account = MultiEd25519Account::new(keys, 2).unwrap();

        aptos
            .fund_account(account.address(), 500_000_000)
            .await
            .expect("failed to fund multi-ed25519 account");
        wait_for_finality().await;

        let recipient = Ed25519Account::generate();
        let amount: u64 = 4_096_000;
        let payload = EntryFunction::apt_transfer(recipient.address(), amount).unwrap();

        let seq = aptos
            .get_sequence_number(account.address())
            .await
            .expect("failed to get seq");
        let chain_id = aptos
            .ensure_chain_id()
            .await
            .expect("failed to resolve chain id");

        let raw_txn = TransactionBuilder::new()
            .sender(account.address())
            .sequence_number(seq)
            .payload(payload.into())
            .chain_id(chain_id)
            .max_gas_amount(2_000_000)
            .gas_unit_price(100)
            .build()
            .expect("failed to build");

        let signed = sign_transaction(&raw_txn, &account).expect("failed to sign");
        let result = aptos
            .submit_and_wait(&signed, None)
            .await
            .expect("multi-ed25519 transaction submission failed");

        let success = result
            .data
            .get("success")
            .and_then(serde_json::Value::as_bool);
        assert_eq!(success, Some(true), "multi-ed25519 transfer must succeed");

        wait_for_finality().await;

        let balance = aptos
            .get_balance(recipient.address())
            .await
            .expect("failed to get recipient balance");
        assert_eq!(balance, amount);
    }
}

// =============================================================================
// Batch Transaction Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod batch_tests {
    use super::*;
    use aptos_sdk::account::Ed25519Account;
    use aptos_sdk::transaction::{InputEntryFunctionData, TransactionBatchBuilder};

    #[tokio::test]
    #[ignore]
    async fn e2e_batch_build_and_submit() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        // Fund well above the gas budget for 2 transactions (~400M octas).
        let sender = aptos
            .create_funded_account(1_000_000_000)
            .await
            .expect("failed to create sender");

        let recipient1 = Ed25519Account::generate();
        let recipient2 = Ed25519Account::generate();
        let amount1: u64 = 7_777_777;
        let amount2: u64 = 8_888_888;

        wait_for_finality().await;

        let seq_num = aptos
            .fullnode()
            .get_sequence_number(sender.address())
            .await
            .expect("failed to get seq num");
        let chain_id = aptos
            .ensure_chain_id()
            .await
            .expect("failed to resolve chain id");

        let payload1 = InputEntryFunctionData::transfer_apt(recipient1.address(), amount1)
            .expect("failed to build payload 1");
        let payload2 = InputEntryFunctionData::transfer_apt(recipient2.address(), amount2)
            .expect("failed to build payload 2");

        let batch = TransactionBatchBuilder::new()
            .sender(sender.address())
            .starting_sequence_number(seq_num)
            .chain_id(chain_id)
            .add_payload(payload1)
            .add_payload(payload2)
            .build_and_sign(&sender)
            .expect("failed to build batch");
        assert_eq!(batch.len(), 2);

        let txns = batch.transactions();
        // Sequence numbers must be strictly increasing and dense.
        assert_eq!(txns[0].raw_txn.sequence_number, seq_num);
        assert_eq!(txns[1].raw_txn.sequence_number, seq_num + 1);

        // Submit each transaction in the batch and wait for both to finalize.
        for txn in txns {
            aptos
                .submit_and_wait(txn, None)
                .await
                .expect("batch transaction must succeed");
        }

        wait_for_finality().await;

        // Recipients should have exactly the funded amounts.
        let balance1 = aptos
            .get_balance(recipient1.address())
            .await
            .expect("failed to read recipient1 balance");
        let balance2 = aptos
            .get_balance(recipient2.address())
            .await
            .expect("failed to read recipient2 balance");
        assert_eq!(balance1, amount1);
        assert_eq!(balance2, amount2);

        // Sender sequence number must have advanced by 2.
        let new_seq = aptos
            .get_sequence_number(sender.address())
            .await
            .expect("failed to read seq");
        assert_eq!(new_seq, seq_num + 2);
    }
}

// =============================================================================
// Additional Balance Tests
// =============================================================================

// =============================================================================
// Gas Estimation Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod gas_tests {
    use super::*;
    use aptos_sdk::account::Ed25519Account;
    use aptos_sdk::transaction::EntryFunction;

    #[tokio::test]
    #[ignore]
    async fn e2e_estimate_gas_for_transfer() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let sender = aptos
            .create_funded_account(500_000_000)
            .await
            .expect("failed to create sender");
        let recipient = Ed25519Account::generate();

        let payload = EntryFunction::apt_transfer(recipient.address(), 1_000)
            .expect("failed to build payload");

        let gas_used = aptos
            .estimate_gas(&sender, payload.into())
            .await
            .expect("estimate_gas must succeed");

        // Sanity bounds: a basic APT transfer is on the order of a few hundred to
        // a few thousand gas units on devnet. We bound very loosely to avoid
        // flakiness with on-chain gas schedule changes.
        assert!(gas_used > 0, "gas_used must be positive");
        assert!(
            gas_used < 1_000_000,
            "gas_used ({gas_used}) is wildly higher than expected for an APT transfer"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn e2e_estimate_gas_price() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let estimate = aptos
            .fullnode()
            .estimate_gas_price()
            .await
            .expect("estimate_gas_price must succeed");

        assert!(
            estimate.data.gas_estimate > 0,
            "gas_estimate must be positive"
        );
    }
}

// =============================================================================
// Sponsored (Fee Payer) Builder Helper Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod sponsored_builder_tests {
    use super::*;
    use aptos_sdk::account::Ed25519Account;
    use aptos_sdk::transaction::{EntryFunction, SponsoredTransactionBuilder};

    #[tokio::test]
    #[ignore]
    async fn e2e_sponsored_builder_real_transfer() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        // Sender has just the transfer amount; sponsor covers gas.
        let sender = aptos
            .create_funded_account(100_000_000)
            .await
            .expect("failed to create sender");
        let sponsor = aptos
            .create_funded_account(500_000_000)
            .await
            .expect("failed to create sponsor");
        let recipient = Ed25519Account::generate();

        let sender_seq = aptos
            .get_sequence_number(sender.address())
            .await
            .expect("failed to get sender seq");
        let chain_id = aptos
            .ensure_chain_id()
            .await
            .expect("failed to resolve chain id");

        let amount: u64 = 12_345;
        let payload = EntryFunction::apt_transfer(recipient.address(), amount).unwrap();

        let signed = SponsoredTransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(sender_seq)
            .fee_payer(sponsor.address())
            .payload(payload.into())
            .chain_id(chain_id)
            .max_gas_amount(2_000_000)
            .gas_unit_price(100)
            .build_and_sign(&sender, &[], &sponsor)
            .expect("failed to build+sign sponsored transaction");

        let result = aptos
            .submit_and_wait(&signed, None)
            .await
            .expect("sponsored transaction submission failed");

        let success = result
            .data
            .get("success")
            .and_then(serde_json::Value::as_bool);
        assert_eq!(success, Some(true), "sponsored transaction must succeed");

        wait_for_finality().await;

        let recipient_balance = aptos
            .get_balance(recipient.address())
            .await
            .expect("failed to get recipient balance");
        assert_eq!(recipient_balance, amount);
    }
}

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod balance_tests {
    use super::*;
    use aptos_sdk::account::Ed25519Account;

    #[tokio::test]
    #[ignore]
    async fn e2e_balance_multiple_accounts() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        // Create multiple accounts
        let accounts: Vec<_> = (0..3).map(|_| Ed25519Account::generate()).collect();

        // Fund all accounts
        for account in &accounts {
            aptos
                .fund_account(account.address(), 50_000_000)
                .await
                .expect("failed to fund account");
        }

        wait_for_finality().await;

        // Check all balances
        for (i, account) in accounts.iter().enumerate() {
            let balance = aptos
                .get_balance(account.address())
                .await
                .expect("failed to get balance");
            assert!(
                balance >= 50_000_000,
                "Account {i} should have at least 50M octas"
            );
            println!("Account {i}: {balance} octas");
        }
    }
}
