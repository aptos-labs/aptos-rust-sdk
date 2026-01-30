//! Account management for the Aptos SDK.
#![allow(clippy::module_inception)] // account::account is intentional naming
//!
//! This module provides account types that wrap cryptographic keys
//! and provide a unified interface for signing transactions.
//!
//! # Account Types
//!
//! - [`Ed25519Account`] - Single-key Ed25519 account (legacy format, most common)
//! - [`Ed25519SingleKeyAccount`] - Ed25519 account using modern `SingleKey` format
//! - [`MultiEd25519Account`] - M-of-N multi-signature Ed25519 account
//! - [`Secp256k1Account`] - Single-key Secp256k1 account (Bitcoin/Ethereum curve)
//! - [`Secp256r1Account`] - Single-key Secp256r1/P-256 account (WebAuthn/Passkey)
//! - [`MultiKeyAccount`] - M-of-N multi-signature account with mixed key types
//! - [`KeylessAccount`] - OIDC-based keyless account
//!
//! # Example
//!
//! ```rust,ignore
//! use aptos_rust_sdk_v2::account::Ed25519Account;
//!
//! // Generate a new random account
//! let account = Ed25519Account::generate();
//! println!("Address: {}", account.address());
//!
//! // Create from a private key
//! let private_key_hex = "0x...";
//! let account = Ed25519Account::from_private_key_hex(private_key_hex).unwrap();
//! ```

mod account;
#[cfg(feature = "ed25519")]
mod ed25519;
#[cfg(feature = "keyless")]
mod keyless;
#[cfg(feature = "mnemonic")]
mod mnemonic;
#[cfg(feature = "ed25519")]
mod multi_ed25519;
mod multi_key;
#[cfg(feature = "secp256k1")]
mod secp256k1;
#[cfg(feature = "secp256r1")]
mod secp256r1;

pub use account::{Account, AnyAccount, AuthenticationKey};
#[cfg(feature = "ed25519")]
pub use ed25519::{Ed25519Account, Ed25519SingleKeyAccount};
#[cfg(feature = "keyless")]
pub use keyless::{
    EphemeralKeyPair, HttpPepperService, HttpProverService, KeylessAccount, KeylessSignature,
    OidcProvider, Pepper, PepperService, ProverService, ZkProof,
};
#[cfg(feature = "mnemonic")]
pub use mnemonic::Mnemonic;
#[cfg(feature = "ed25519")]
pub use multi_ed25519::MultiEd25519Account;
pub use multi_key::{AnyPrivateKey, MultiKeyAccount};
#[cfg(feature = "secp256k1")]
pub use secp256k1::Secp256k1Account;
#[cfg(feature = "secp256r1")]
pub use secp256r1::Secp256r1Account;
