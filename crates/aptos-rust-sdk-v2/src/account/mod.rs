//! Account management for the Aptos SDK.
//!
//! This module provides account types that wrap cryptographic keys
//! and provide a unified interface for signing transactions.
//!
//! # Account Types
//!
//! - [`Ed25519Account`] - Single-key Ed25519 account (most common)
//! - [`MultiEd25519Account`] - M-of-N multi-signature Ed25519 account
//! - [`Secp256k1Account`] - Single-key Secp256k1 account (Bitcoin/Ethereum curve)
//! - [`Secp256r1Account`] - Single-key Secp256r1/P-256 account (WebAuthn/Passkey)
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
#[cfg(feature = "ed25519")]
mod multi_ed25519;
mod multi_key;
#[cfg(feature = "keyless")]
mod keyless;
#[cfg(feature = "secp256k1")]
mod secp256k1;
#[cfg(feature = "secp256r1")]
mod secp256r1;
mod mnemonic;

pub use account::{Account, AnyAccount, AuthenticationKey};
#[cfg(feature = "ed25519")]
pub use ed25519::Ed25519Account;
#[cfg(feature = "ed25519")]
pub use multi_ed25519::MultiEd25519Account;
pub use multi_key::{AnyPrivateKey, MultiKeyAccount};
#[cfg(feature = "keyless")]
pub use keyless::{
    EphemeralKeyPair, HttpPepperService, HttpProverService, KeylessAccount, KeylessSignature,
    OidcProvider, Pepper, PepperService, ProverService, ZkProof,
};
#[cfg(feature = "secp256k1")]
pub use secp256k1::Secp256k1Account;
#[cfg(feature = "secp256r1")]
pub use secp256r1::Secp256r1Account;
pub use mnemonic::Mnemonic;
