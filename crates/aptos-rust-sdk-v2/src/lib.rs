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
//! - [`api`] - REST and GraphQL API clients (including ANS)
//! - [`types`] - Core Aptos types
//! - [`codegen`] - Code generation from Move ABIs
//!
//! ## ANS (Aptos Names Service)
//!
//! The SDK includes built-in support for ANS name resolution:
//!
//! ```rust,ignore
//! let aptos = Aptos::mainnet()?;
//!
//! // Resolve a name to an address
//! let addr = aptos.resolve_name("alice.apt").await?;
//!
//! // Get the primary name for an address
//! let name = aptos.get_primary_name(addr).await?;
//!
//! // Resolve either address or name (convenience method)
//! let addr = aptos.resolve("alice.apt").await?;
//! let addr = aptos.resolve("0x1234...").await?;
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub
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
