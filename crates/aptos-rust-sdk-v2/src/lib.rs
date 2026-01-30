//! # Aptos Rust SDK v2
//!
//! A user-friendly, idiomatic Rust SDK for the Aptos blockchain.
//!
//! This SDK provides a complete interface for interacting with the Aptos blockchain,
//! including account management, transaction building and signing, and API clients
//! for both the fullnode REST API and the indexer GraphQL API.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use aptos_rust_sdk_v2::{Aptos, AptosConfig};
//! use aptos_rust_sdk_v2::account::{Account, Ed25519Account};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Connect to testnet
//!     let aptos = Aptos::new(AptosConfig::testnet())?;
//!
//!     // Create a new account
//!     let account = Ed25519Account::generate();
//!     println!("Address: {}", account.address());
//!
//!     // Get balance (after funding)
//!     let balance = aptos.get_balance(account.address()).await?;
//!     println!("Balance: {} octas", balance);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Feature Flags
//!
//! The SDK uses feature flags to allow you to include only the functionality you need:
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `ed25519` | Yes | Ed25519 signature scheme |
//! | `secp256k1` | Yes | Secp256k1 ECDSA signatures |
//! | `secp256r1` | Yes | Secp256r1 (P-256) ECDSA signatures |
//! | `mnemonic` | Yes | BIP-39 mnemonic phrase support for key derivation |
//! | `indexer` | Yes | GraphQL indexer client |
//! | `faucet` | Yes | Faucet integration for testnets |
//! | `bls` | No | BLS12-381 signatures |
//! | `keyless` | No | OIDC-based keyless authentication |
//! | `macros` | No | Proc macros for type-safe contract bindings |
//!
//! ## Modules
//!
//! - [`account`] - Account management and key generation
//! - [`crypto`] - Cryptographic primitives and signature schemes
//! - [`transaction`] - Transaction building and signing
//! - [`api`] - REST and GraphQL API clients
//! - [`types`] - Core Aptos types
//! - [`codegen`] - Code generation from Move ABIs

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    clippy::pedantic
)]
// Pedantic lint exceptions - these are intentionally allowed
#![allow(
    clippy::must_use_candidate,       // Too noisy for SDK functions
    clippy::missing_errors_doc,       // Error documentation is at the error type level
    clippy::missing_panics_doc,       // We document panics where relevant
    clippy::match_same_arms,          // Sometimes intentionally explicit for clarity TODO: Remove, this showed a couple of issues
    clippy::unnecessary_wraps,        // Some wraps are for API consistency
)]

pub mod account;
pub mod api;
pub mod codegen;
pub mod config;
pub mod crypto;
pub mod error;
pub mod retry;
pub mod transaction;
pub mod types;

mod aptos;

// Re-export main entry points
pub use aptos::Aptos;
pub use config::AptosConfig;
pub use error::{AptosError, AptosResult};

// Re-export commonly used types
pub use types::{AccountAddress, ChainId, HashValue};

// Re-export proc macros when the feature is enabled
#[cfg(feature = "macros")]
#[cfg_attr(docsrs, doc(cfg(feature = "macros")))]
pub use aptos_rust_sdk_v2_macros::{MoveStruct, aptos_contract, aptos_contract_file};

#[cfg(test)]
mod tests;
