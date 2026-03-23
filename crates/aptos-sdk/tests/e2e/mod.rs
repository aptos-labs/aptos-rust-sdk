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
//! # In one terminal, start localnet (use --with-indexer-api for indexer tests):
//! aptos node run-localnet --with-faucet --with-indexer-api
//!
//! # In another terminal, run tests:
//! cargo test -p aptos-sdk --features "e2e,full"
//! ```
//!
//! ### Option 3: Using custom node URLs
//! ```bash
//! export APTOS_LOCAL_NODE_URL=http://127.0.0.1:8080/v1
//! export APTOS_LOCAL_FAUCET_URL=http://127.0.0.1:8081
//! export APTOS_LOCAL_INDEXER_URL=http://127.0.0.1:8090/v1/graphql
//! cargo test -p aptos-sdk --features "e2e,full"
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
//! - **fullnode_tests**: FullnodeClient API coverage
//! - **aptos_client_tests**: Main Aptos client method coverage
//! - **error_tests**: Error and failure path coverage
//! - **indexer_tests**: IndexerClient queries (requires indexer API)

use aptos_sdk::{Aptos, AptosConfig};
use std::env;

/// Gets the configuration for E2E tests.
///
/// Supports the following environment variables:
/// - `APTOS_LOCAL_NODE_URL` — override the fullnode URL
/// - `APTOS_LOCAL_FAUCET_URL` — override the faucet URL
/// - `APTOS_LOCAL_INDEXER_URL` — enable indexer with the given URL
pub fn get_test_config() -> AptosConfig {
    let mut config = if let Ok(node_url) = env::var("APTOS_LOCAL_NODE_URL") {
        AptosConfig::custom(&node_url)
            .unwrap()
            .with_faucet_url(
                &env::var("APTOS_LOCAL_FAUCET_URL")
                    .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string()),
            )
            .unwrap()
    } else {
        AptosConfig::local()
    };

    if let Ok(indexer_url) = env::var("APTOS_LOCAL_INDEXER_URL")
        && !indexer_url.trim().is_empty()
    {
        config = config.with_indexer_url(&indexer_url).unwrap_or_else(|err| {
            panic!("Invalid APTOS_LOCAL_INDEXER_URL '{}': {}", indexer_url, err)
        });
    }

    config
}

/// Helper to wait for transaction finality.
pub async fn wait_for_finality() {
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
}

/// Helper to wait for the indexer to catch up to at least `min_version`.
///
/// Polls `indexer.get_indexer_version()` every 2 seconds, up to 60 seconds.
#[cfg(feature = "indexer")]
pub async fn wait_for_indexer(aptos: &Aptos, min_version: u64) {
    let indexer = aptos.indexer().expect("indexer client not configured");
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(60);

    loop {
        if let Ok(version) = indexer.get_indexer_version().await
            && version >= min_version
        {
            return;
        }
        if start.elapsed() >= timeout {
            panic!(
                "Indexer did not catch up to version {} within {}s",
                min_version,
                timeout.as_secs()
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

// =============================================================================
// Existing test modules (extracted to separate files)
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod account_tests;

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod transfer_tests;

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod view_tests;

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod transaction_tests;

#[cfg(feature = "ed25519")]
mod ledger_tests;

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod multi_signer_tests;

#[cfg(all(feature = "ed25519", feature = "secp256k1", feature = "faucet"))]
mod multi_key_tests;

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod state_tests;

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod single_key_tests;

#[cfg(all(feature = "secp256k1", feature = "faucet"))]
mod secp256k1_tests;

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod batch_tests;

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod balance_tests;

// =============================================================================
// New test modules
// =============================================================================

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod fullnode_tests;

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod aptos_client_tests;

#[cfg(all(feature = "ed25519", feature = "faucet"))]
mod error_tests;

#[cfg(all(feature = "secp256r1", feature = "faucet"))]
mod secp256r1_tests;

#[cfg(all(feature = "indexer", feature = "ed25519", feature = "faucet"))]
mod indexer_tests;
