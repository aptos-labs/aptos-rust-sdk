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
//! - [`Secp256r1Account`] - Single-key Secp256r1/P-256 account (WebAuthn/Passkey)
//! - [`MultiKeyAccount`] - M-of-N multi-signature account with mixed key types
//! - [`KeylessAccount`] - OIDC-based keyless account (requires `keyless` feature)
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
//!
//! # Keyless (OIDC) example
//!
//! Keyless accounts are built from an OIDC JWT plus Aptos pepper / prover
//! services. Unlike the TypeScript SDK's `AccountClient`, the Rust SDK exposes
//! [`KeylessAccount`] directly. Enable `features = ["keyless"]` first.
//!
//! ```rust,ignore
//! # async fn keyless_example(jwt: &str) -> aptos_sdk::error::AptosResult<()> {
//! use aptos_sdk::account::{
//!     Account, EphemeralKeyPair, HttpPepperService, HttpProverService, KeylessAccount,
//! };
//! use aptos_sdk::config::Network;
//! use url::Url;
//!
//! // Generate before redirecting the user to your IdP; embed ephemeral.nonce() in the login URL.
//! let ephemeral = EphemeralKeyPair::generate(3600);
//!
//! let pepper = HttpPepperService::new(
//!     Url::parse(Network::Devnet.pepper_url().expect("devnet pepper URL")).unwrap(),
//! );
//! let prover = HttpProverService::new(
//!     Url::parse(Network::Devnet.prover_url().expect("devnet prover URL")).unwrap(),
//! );
//!
//! let account = KeylessAccount::from_jwt(jwt, ephemeral, &pepper, &prover).await?;
//! println!("Address: {}", account.address());
//! # Ok(())
//! # }
//! ```
//!
//! Full walkthrough: the [`keyless`] module docs and the
//! `keyless_account` binary example.

mod account;
#[cfg(feature = "ed25519")]
mod ed25519;
#[cfg(feature = "keyless")]
#[cfg_attr(docsrs, doc(cfg(feature = "keyless")))]
pub mod keyless;
#[cfg(feature = "mnemonic")]
mod mnemonic;
#[cfg(feature = "ed25519")]
mod multi_ed25519;
mod multi_key;
#[cfg(feature = "secp256k1")]
mod secp256k1;
#[cfg(feature = "secp256r1")]
mod secp256r1;
#[cfg(feature = "secp256r1")]
mod webauthn;

pub use account::{Account, AnyAccount, AuthenticationKey};
#[cfg(feature = "ed25519")]
pub use ed25519::{Ed25519Account, Ed25519SingleKeyAccount};
#[cfg(feature = "keyless")]
#[cfg_attr(docsrs, doc(cfg(feature = "keyless")))]
pub use keyless::{
    EphemeralKeyPair, HttpPepperService, HttpProverService, JwkSet, KeylessAccount,
    KeylessSignature, OidcProvider, Pepper, PepperService, ProverService, ZkProof,
};
#[cfg(feature = "mnemonic")]
pub use mnemonic::{DerivationPath, Mnemonic, PathComponent};
#[cfg(feature = "ed25519")]
pub use multi_ed25519::MultiEd25519Account;
pub use multi_key::{AnyPrivateKey, MultiKeyAccount};
#[cfg(feature = "secp256k1")]
pub use secp256k1::Secp256k1Account;
#[cfg(feature = "secp256r1")]
#[allow(deprecated)] // Re-exported for back-compat; the type itself is deprecated.
pub use secp256r1::Secp256r1Account;
#[cfg(feature = "secp256r1")]
pub use webauthn::{DEFAULT_WEBAUTHN_ORIGIN, DEFAULT_WEBAUTHN_RP_ID, WebAuthnAccount};
