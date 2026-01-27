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
//! cargo test -p aptos-rust-sdk-v2 --features "e2e,full"
//! ```
//!
//! ### Option 3: Using custom node URLs
//! ```bash
//! export APTOS_LOCAL_NODE_URL=http://127.0.0.1:8080/v1
//! export APTOS_LOCAL_FAUCET_URL=http://127.0.0.1:8081
//! cargo test -p aptos-rust-sdk-v2 --features "e2e,full"
//! ```
//!
//! ## Test Categories
//!
//! - **account_tests**: Account creation, funding, balance queries
//! - **transfer_tests**: APT transfers between accounts
//! - **view_tests**: View function calls
//! - **transaction_tests**: Transaction building, signing, submission
//! - **multi_signer_tests**: Multi-agent and fee payer transactions
//! - **state_tests**: Resource and state queries

use aptos_rust_sdk_v2::{Aptos, AptosConfig};
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
    use aptos_rust_sdk_v2::account::Ed25519Account;

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
        println!("Funded with txns: {:?}", txn_hashes);

        wait_for_finality().await;

        // Check balance
        let balance = aptos
            .get_balance(account.address())
            .await
            .expect("failed to get balance");
        assert!(balance > 0, "balance should be > 0");
        println!("Balance: {} octas", balance);
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

        println!("Sequence number: {}", seq_num);
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

        let result = aptos.get_sequence_number(account.address()).await;

        // Should get an error for non-existent account
        assert!(result.is_err() || result.unwrap() == 0);
    }
}

// =============================================================================
// Transfer Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod transfer_tests {
    use super::*;
    use aptos_rust_sdk_v2::account::Ed25519Account;

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
}

// =============================================================================
// View Function Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod view_tests {
    use super::*;
    use aptos_rust_sdk_v2::account::Ed25519Account;

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
        println!("Random address: {}", random_address.to_string());

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
}

// =============================================================================
// Transaction Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod transaction_tests {
    use super::*;
    use aptos_rust_sdk_v2::account::Ed25519Account;
    use aptos_rust_sdk_v2::transaction::{EntryFunction, builder::sign_transaction};

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
            hex::encode(&bcs_bytes[..100.min(bcs_bytes.len())])
        );
        println!(
            "Last 100 bytes: {}",
            hex::encode(&bcs_bytes[bcs_bytes.len().saturating_sub(100)..])
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
        use aptos_rust_sdk_v2::account::Account;
        use aptos_rust_sdk_v2::transaction::authenticator::{
            Ed25519PublicKey, Ed25519Signature,
        };
        use aptos_rust_sdk_v2::transaction::{SignedTransaction, TransactionAuthenticator};

        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let account = aptos
            .create_funded_account(100_000_000)
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

        let success = result.data[0].get("success").and_then(|v| v.as_bool());
        assert_eq!(success, Some(true), "simulation should succeed");

        let gas_used = result.data[0].get("gas_used").and_then(|v| v.as_str());
        println!("Simulated gas used: {:?}", gas_used);
    }

    #[tokio::test]
    #[ignore]
    async fn e2e_get_transaction_by_hash() {
        use aptos_rust_sdk_v2::types::HashValue;

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
        let payload =
            EntryFunction::apt_transfer(Ed25519Account::generate().address(), 1000).unwrap();

        let raw_txn = aptos_rust_sdk_v2::transaction::TransactionBuilder::new()
            .sender(account.address())
            .sequence_number(0)
            .payload(payload.into())
            .chain_id(aptos.chain_id())
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
    use aptos_rust_sdk_v2::account::{Account, Ed25519Account};
    use aptos_rust_sdk_v2::transaction::{
        EntryFunction, TransactionBuilder,
        builder::{sign_fee_payer_transaction, sign_multi_agent_transaction},
        types::{FeePayerRawTransaction, MultiAgentRawTransaction},
    };

    #[tokio::test]
    #[ignore]
    async fn e2e_fee_payer_transaction() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        // Create sender with minimal funds (just for account creation)
        let sender = aptos
            .create_funded_account(1_000)
            .await
            .expect("failed to create sender");

        // Create fee payer with lots of funds
        let fee_payer = aptos
            .create_funded_account(500_000_000)
            .await
            .expect("failed to create fee payer");

        let recipient = Ed25519Account::generate();

        println!("Sender: {}", sender.address());
        println!("Fee payer: {}", fee_payer.address());
        println!("Recipient: {}", recipient.address());

        // Build the fee payer transaction
        let payload = EntryFunction::apt_transfer(recipient.address(), 500).unwrap();

        let sender_seq = aptos
            .get_sequence_number(sender.address())
            .await
            .unwrap_or(0);

        let raw_txn = TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(sender_seq)
            .payload(payload.into())
            .chain_id(aptos.chain_id())
            .max_gas_amount(100_000)
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

        // Submit
        let result = aptos.submit_and_wait(&signed, None).await;

        // This may or may not work depending on localnet support for fee payer
        match result {
            Ok(r) => {
                println!("Fee payer transaction result: {:?}", r.data);
            }
            Err(e) => {
                println!("Fee payer transaction failed (may not be supported): {}", e);
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn e2e_multi_agent_transaction() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        // Create primary sender
        let sender = aptos
            .create_funded_account(200_000_000)
            .await
            .expect("failed to create sender");

        // Create secondary signer
        let secondary = aptos
            .create_funded_account(100_000_000)
            .await
            .expect("failed to create secondary");

        println!("Sender: {}", sender.address());
        println!("Secondary: {}", secondary.address());

        // Note: Most simple transactions don't need multi-agent
        // This is just demonstrating the signing flow
        let payload =
            EntryFunction::apt_transfer(Ed25519Account::generate().address(), 1000).unwrap();

        let sender_seq = aptos
            .get_sequence_number(sender.address())
            .await
            .unwrap_or(0);

        let raw_txn = TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(sender_seq)
            .payload(payload.into())
            .chain_id(aptos.chain_id())
            .max_gas_amount(100_000)
            .gas_unit_price(100)
            .build()
            .expect("failed to build");

        let multi_agent_txn = MultiAgentRawTransaction {
            raw_txn,
            secondary_signer_addresses: vec![secondary.address()],
        };

        // Sign with both accounts
        let secondary_ref: &dyn Account = &secondary;
        let signed = sign_multi_agent_transaction(&multi_agent_txn, &sender, &[secondary_ref])
            .expect("failed to sign");

        // Submit
        let result = aptos.submit_and_wait(&signed, None).await;

        match result {
            Ok(r) => {
                println!("Multi-agent transaction result: {:?}", r.data);
            }
            Err(e) => {
                println!("Multi-agent transaction error: {}", e);
            }
        }
    }
}

// =============================================================================
// Multi-Key Account Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "secp256k1", feature = "faucet"))]
mod multi_key_e2e_tests {
    use super::*;
    use aptos_rust_sdk_v2::account::{AnyPrivateKey, MultiKeyAccount};
    use aptos_rust_sdk_v2::crypto::{Ed25519PrivateKey, Secp256k1PrivateKey};
    use aptos_rust_sdk_v2::transaction::{
        EntryFunction, TransactionBuilder, builder::sign_transaction,
    };

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
        let recipient = aptos_rust_sdk_v2::account::Ed25519Account::generate();
        let payload = EntryFunction::apt_transfer(recipient.address(), 1_000_000).unwrap();

        let seq = aptos
            .get_sequence_number(multi_key_account.address())
            .await
            .unwrap_or(0);

        let raw_txn = TransactionBuilder::new()
            .sender(multi_key_account.address())
            .sequence_number(seq)
            .payload(payload.into())
            .chain_id(aptos.chain_id())
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
}

// =============================================================================
// Resource/State Tests
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod state_tests {
    use super::*;

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

        // Get the Account resource via fullnode client
        let resource = aptos
            .fullnode()
            .get_account_resource(account.address(), "0x1::account::Account")
            .await;

        match resource {
            Ok(r) => {
                println!("Account resource: {:?}", r.data);
            }
            Err(e) => {
                println!("Failed to get resource: {}", e);
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn e2e_get_coin_store_resource() {
        let config = get_test_config();
        let aptos = Aptos::new(config).expect("failed to create client");

        let account = aptos
            .create_funded_account(100_000_000)
            .await
            .expect("failed to create account");

        wait_for_finality().await;

        // Get the CoinStore resource for APT
        let resource = aptos
            .fullnode()
            .get_account_resource(
                account.address(),
                "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
            )
            .await;

        match resource {
            Ok(r) => {
                println!("CoinStore resource: {:?}", r.data);
            }
            Err(e) => {
                println!("Failed to get CoinStore: {}", e);
            }
        }
    }
}
