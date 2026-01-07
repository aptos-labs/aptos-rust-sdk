//! API clients for the Aptos blockchain.
//!
//! This module provides clients for interacting with the Aptos network:
//!
//! - [`FullnodeClient`] - REST API client for fullnode operations
//! - [`FaucetClient`] - Client for funding accounts on testnets (feature-gated)
//! - [`IndexerClient`] - GraphQL client for indexed data (feature-gated)
//! - [`AnsClient`] - Aptos Names Service client for name resolution

pub mod ans;
pub mod fullnode;
pub mod response;

#[cfg(feature = "faucet")]
mod faucet;

#[cfg(feature = "indexer")]
mod indexer;

pub use ans::{AnsClient, AnsName, AnsResolvable};
pub use fullnode::FullnodeClient;
pub use response::{AptosResponse, GasEstimation, LedgerInfo, PendingTransaction};

#[cfg(feature = "faucet")]
pub use faucet::FaucetClient;

#[cfg(feature = "indexer")]
pub use indexer::IndexerClient;

