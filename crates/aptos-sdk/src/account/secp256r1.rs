// Module docs prefer prose ("Aptos networks", "WebAuthn", etc.) over backticks
// in several places where clippy's pedantic `doc_markdown` lint would otherwise
// fire. We allow the lint locally to keep the deprecation note readable.
#![allow(clippy::doc_markdown)]

//! `Secp256r1` (P-256) account implementation.
//!
//! `Secp256r1`, also known as P-256 or `prime256v1`, is commonly used in
//! WebAuthn / Passkey implementations.
//!
//! # ⚠️ Deprecated for transaction signing
//!
//! [`Secp256r1Account`] cannot successfully submit transactions on current
//! Aptos networks. The on-chain `AnySignature` enum reserves variant index
//! `2` for **WebAuthn** (a `PartialAuthenticatorAssertionResponse` that
//! wraps a `secp256r1` signature in `authenticator_data` /
//! `client_data_json`) -- not for bare `secp256r1` ECDSA signatures. A
//! `Secp256r1Account`-signed transaction is therefore rejected by every
//! Aptos validator with a deserialization-level error.
//!
//! Use [`WebAuthnAccount`](super::WebAuthnAccount) for any new code that
//! needs to sign Aptos transactions with a P-256 key. `WebAuthnAccount`
//! reuses [`Secp256r1PrivateKey`] / [`Secp256r1PublicKey`] internally but
//! emits the correct on-chain wire format. See the on-chain definition in
//! [aptos-core][webauthn-rs].
//!
//! `Secp256r1Account` remains available for off-chain uses (raw P-256
//! `sign` / `verify`, key-management interop), but every API surface here
//! that touches on-chain semantics is marked `#[deprecated]`.
//!
//! [webauthn-rs]: https://github.com/aptos-labs/aptos-core/blob/main/types/src/transaction/webauthn.rs

use crate::account::account::{Account, AuthenticationKey};
use crate::crypto::{
    SINGLE_KEY_SCHEME, Secp256r1PrivateKey, Secp256r1PublicKey, derive_authentication_key,
};
use crate::error::AptosResult;
use crate::types::AccountAddress;
use std::fmt;

/// A `Secp256r1` (P-256) ECDSA account.
///
/// # ⚠️ Deprecated for on-chain transaction signing
///
/// On current Aptos networks the on-chain `AnySignature` variant at index
/// 2 is `WebAuthn`, **not** bare `secp256r1` ECDSA. Transactions signed by
/// this account type are rejected by every Aptos validator. Use
/// [`WebAuthnAccount`](super::WebAuthnAccount) instead -- it reuses the
/// same key material and produces the correct WebAuthn-envelope wire
/// format.
///
/// This type is still useful for off-chain P-256 use (sign / verify of
/// arbitrary bytes, key import/export, key-derivation testing) and for
/// constructing [`MultiKeyAccount`](super::MultiKeyAccount) public-key
/// material.
///
/// # Example
///
/// ```rust
/// # #![allow(deprecated)]
/// use aptos_sdk::account::Secp256r1Account;
///
/// // For off-chain signing only -- this account cannot submit
/// // transactions to a live Aptos network. Use `WebAuthnAccount` for that.
/// let account = Secp256r1Account::generate();
/// println!("Address: {}", account.address());
/// ```
#[deprecated(
    since = "0.5.0",
    note = "Use `WebAuthnAccount` for on-chain transaction signing. Bare \
            secp256r1 signatures are not accepted by Aptos validators (the \
            on-chain AnySignature variant 2 is WebAuthn, not Secp256r1Ecdsa). \
            This type is retained for off-chain use only."
)]
#[derive(Clone)]
pub struct Secp256r1Account {
    private_key: Secp256r1PrivateKey,
    public_key: Secp256r1PublicKey,
    address: AccountAddress,
}

#[allow(deprecated)]
impl Secp256r1Account {
    /// Generates a new random Secp256r1 account.
    pub fn generate() -> Self {
        let private_key = Secp256r1PrivateKey::generate();
        Self::from_private_key(private_key)
    }

    /// Creates an account from a private key.
    pub fn from_private_key(private_key: Secp256r1PrivateKey) -> Self {
        let public_key = private_key.public_key();
        let address = public_key.to_address();
        Self {
            private_key,
            public_key,
            address,
        }
    }

    /// Creates an account from private key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid Secp256r1 private key (must be exactly 32 bytes and a valid curve point).
    pub fn from_private_key_bytes(bytes: &[u8]) -> AptosResult<Self> {
        let private_key = Secp256r1PrivateKey::from_bytes(bytes)?;
        Ok(Self::from_private_key(private_key))
    }

    /// Creates an account from a private key hex string.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The hex string is invalid or cannot be decoded
    /// - The decoded bytes are not a valid Secp256r1 private key
    pub fn from_private_key_hex(hex_str: &str) -> AptosResult<Self> {
        let private_key = Secp256r1PrivateKey::from_hex(hex_str)?;
        Ok(Self::from_private_key(private_key))
    }

    /// Returns the account address.
    pub fn address(&self) -> AccountAddress {
        self.address
    }

    /// Returns the public key.
    pub fn public_key(&self) -> &Secp256r1PublicKey {
        &self.public_key
    }

    /// Returns a reference to the private key.
    pub fn private_key(&self) -> &Secp256r1PrivateKey {
        &self.private_key
    }

    /// Signs a message and returns the Secp256r1 signature.
    pub fn sign_message(&self, message: &[u8]) -> crate::crypto::Secp256r1Signature {
        self.private_key.sign(message)
    }
}

#[allow(deprecated)]
impl Account for Secp256r1Account {
    fn address(&self) -> AccountAddress {
        self.address
    }

    fn authentication_key(&self) -> AuthenticationKey {
        let uncompressed = self.public_key.to_uncompressed_bytes();
        let mut bcs_bytes = Vec::with_capacity(1 + 1 + uncompressed.len());
        bcs_bytes.push(0x02); // Secp256r1Ecdsa variant
        bcs_bytes.push(65); // ULEB128(65)
        bcs_bytes.extend_from_slice(&uncompressed);
        let key = derive_authentication_key(&bcs_bytes, SINGLE_KEY_SCHEME);
        AuthenticationKey::new(key)
    }

    fn sign(&self, message: &[u8]) -> crate::error::AptosResult<Vec<u8>> {
        // Return BCS-serialized `AnySignature::Secp256r1` (variant=2, len=64, bytes).
        //
        // NOTE: At the time of writing (devnet, ledger version ~49M, 2026-05),
        // raw `AnySignature::Secp256r1Ecdsa` may not be honored as a
        // single-key transaction authenticator -- the on-chain variant 2 in
        // `AnySignature` is the `WebAuthn` wrapper, which carries an
        // `AssertionSignature` plus a `client_data_json` and authenticator
        // data, not a bare ECDSA signature. This signing path produces a wire
        // format consistent with the SDK's address-derivation, but submitting
        // such transactions on-chain may fail at signature verification until
        // the SDK adds a `WebAuthnAccount` wrapper. Use `Ed25519SingleKeyAccount`
        // or `Secp256k1Account` for end-to-end transaction flows.
        let sig = self.private_key.sign(message).to_bytes().to_vec();
        debug_assert_eq!(
            sig.len(),
            64,
            "Secp256r1 signature must be exactly 64 bytes (R || S)"
        );
        let mut out = Vec::with_capacity(1 + 1 + sig.len());
        out.push(0x02); // AnySignature::Secp256r1 variant
        out.push(64); // ULEB128(64)
        out.extend_from_slice(&sig);
        Ok(out)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        // BCS-serialized `AnyPublicKey::Secp256r1Ecdsa`
        // (variant=2, ULEB128(65), 65 bytes SEC1 uncompressed).
        let uncompressed = self.public_key.to_uncompressed_bytes();
        let mut out = Vec::with_capacity(1 + 1 + uncompressed.len());
        out.push(0x02); // AnyPublicKey::Secp256r1Ecdsa variant
        out.push(65); // ULEB128(65)
        out.extend_from_slice(&uncompressed);
        out
    }

    fn signature_scheme(&self) -> u8 {
        SINGLE_KEY_SCHEME
    }
}

#[allow(deprecated)]
impl fmt::Debug for Secp256r1Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secp256r1Account")
            .field("address", &self.address)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(deprecated)] // we are deliberately testing the deprecated API
mod tests {
    use super::*;
    use crate::account::Account;

    #[test]
    fn test_generate() {
        let account = Secp256r1Account::generate();
        assert!(!account.address().is_zero());
    }

    #[test]
    fn test_from_private_key_roundtrip() {
        let account = Secp256r1Account::generate();
        let bytes = account.private_key().to_bytes();

        let restored = Secp256r1Account::from_private_key_bytes(&bytes).unwrap();
        assert_eq!(account.address(), restored.address());
    }

    #[test]
    fn test_sign_and_verify() {
        let account = Secp256r1Account::generate();
        let message = b"hello world";

        let signature = account.sign_message(message);
        assert!(account.public_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_account_trait() {
        let account = Secp256r1Account::generate();
        let message = b"test message";

        // sign() returns BCS(AnySignature::Secp256r1) = 1 + 1 + 64 = 66 bytes.
        let sig_bytes = account.sign(message).unwrap();
        assert_eq!(sig_bytes.len(), 66);
        assert_eq!(sig_bytes[0], 0x02, "AnySignature::Secp256r1 variant tag");
        assert_eq!(sig_bytes[1], 64, "ULEB128(64)");

        // public_key_bytes() returns BCS(AnyPublicKey::Secp256r1Ecdsa) =
        // variant(2) + ULEB128(65) + 65-byte SEC1 uncompressed. Total = 67 bytes.
        let pub_key_bytes = account.public_key_bytes();
        assert_eq!(pub_key_bytes.len(), 67);
        assert_eq!(
            pub_key_bytes[0], 0x02,
            "AnyPublicKey::Secp256r1Ecdsa variant tag"
        );
        assert_eq!(pub_key_bytes[1], 65, "ULEB128(65)");
        assert_eq!(pub_key_bytes[2], 0x04, "SEC1 uncompressed marker");

        assert!(!account.authentication_key().as_bytes().is_empty());
    }

    #[test]
    fn test_from_private_key() {
        let original = Secp256r1Account::generate();
        let private_key = original.private_key().clone();
        let restored = Secp256r1Account::from_private_key(private_key);
        assert_eq!(original.address(), restored.address());
    }

    #[test]
    fn test_from_private_key_hex() {
        let original = Secp256r1Account::generate();
        let hex = original.private_key().to_hex();
        let restored = Secp256r1Account::from_private_key_hex(&hex).unwrap();
        assert_eq!(original.address(), restored.address());
    }

    #[test]
    fn test_signature_scheme() {
        let account = Secp256r1Account::generate();
        assert_eq!(account.signature_scheme(), SINGLE_KEY_SCHEME);
    }

    #[test]
    fn test_debug_output() {
        let account = Secp256r1Account::generate();
        let debug = format!("{account:?}");
        assert!(debug.contains("Secp256r1Account"));
        assert!(debug.contains("address"));
    }

    #[test]
    fn test_invalid_private_key_bytes() {
        let result = Secp256r1Account::from_private_key_bytes(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_private_key_hex() {
        let result = Secp256r1Account::from_private_key_hex("invalid");
        assert!(result.is_err());
    }
}
