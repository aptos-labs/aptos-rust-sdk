//! Account management for the Aptos SDK.
#![allow(clippy::module_inception)] // account::account is intentional naming
#![allow(rustdoc::broken_intra_doc_links)] // Docs don't use one of the features
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
//! - [`Secp256r1Account`] - Single-key Secp256r1/P-256 account. **Deprecated for
//!   transaction signing** (off-chain use only): bare `secp256r1` signatures are
//!   rejected by Aptos validators. Use [`WebAuthnAccount`] for on-chain P-256 signing.
//! - [`WebAuthnAccount`] - Secp256r1/P-256 account using the WebAuthn/Passkey
//!   envelope; the supported path for signing Aptos transactions with a P-256 key
//!   (requires `secp256r1` feature)
//! - [`MultiKeyAccount`] - M-of-N multi-signature account with mixed key types
//!
//! # Ed25519 example
//!
//! ```rust,ignore
//! use aptos_sdk::account::Ed25519Account;
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
#[cfg(feature = "mnemonic")]
mod mnemonic;
#[cfg(feature = "ed25519")]
mod multi_ed25519;
mod multi_key;
mod rotation;
#[cfg(feature = "secp256k1")]
mod secp256k1;
#[cfg(feature = "secp256r1")]
mod secp256r1;
#[cfg(feature = "secp256r1")]
mod webauthn;

pub use account::{Account, AnyAccount, AuthenticationKey};
#[cfg(feature = "ed25519")]
pub use ed25519::{Ed25519Account, Ed25519SingleKeyAccount};
#[cfg(feature = "mnemonic")]
pub use mnemonic::{DerivationPath, Mnemonic, PathComponent};
#[cfg(feature = "ed25519")]
pub use multi_ed25519::MultiEd25519Account;
pub use multi_key::{AnyPrivateKey, MultiKeyAccount};
pub use rotation::{RotationProofChallenge, build_rotate_auth_key_payload};
#[cfg(feature = "secp256k1")]
pub use secp256k1::Secp256k1Account;
#[cfg(feature = "secp256r1")]
#[allow(deprecated)] // Re-exported for back-compat; the type itself is deprecated.
pub use secp256r1::Secp256r1Account;
#[cfg(feature = "secp256r1")]
pub use webauthn::{DEFAULT_WEBAUTHN_ORIGIN, DEFAULT_WEBAUTHN_RP_ID, WebAuthnAccount};
