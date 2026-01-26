//! Ed25519 account implementation.

use crate::account::account::{Account, AuthenticationKey};
#[cfg(feature = "mnemonic")]
use crate::account::Mnemonic;
use crate::crypto::{Ed25519PrivateKey, Ed25519PublicKey, ED25519_SCHEME};
use crate::error::AptosResult;
use crate::types::AccountAddress;
use std::fmt;

/// An Ed25519 account for signing transactions.
///
/// This is the most common account type on Aptos.
///
/// # Example
///
/// ```rust
/// use aptos_rust_sdk_v2::account::Ed25519Account;
///
/// // Generate a new random account
/// let account = Ed25519Account::generate();
/// println!("Address: {}", account.address());
/// ```
#[derive(Clone)]
pub struct Ed25519Account {
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    address: AccountAddress,
}

impl Ed25519Account {
    /// Generates a new random Ed25519 account.
    pub fn generate() -> Self {
        let private_key = Ed25519PrivateKey::generate();
        Self::from_private_key(private_key)
    }

    /// Creates an account from a private key.
    pub fn from_private_key(private_key: Ed25519PrivateKey) -> Self {
        let public_key = private_key.public_key();
        let address = public_key.to_address();
        Self {
            private_key,
            public_key,
            address,
        }
    }

    /// Creates an account from private key bytes.
    pub fn from_private_key_bytes(bytes: &[u8]) -> AptosResult<Self> {
        let private_key = Ed25519PrivateKey::from_bytes(bytes)?;
        Ok(Self::from_private_key(private_key))
    }

    /// Creates an account from a private key hex string.
    pub fn from_private_key_hex(hex_str: &str) -> AptosResult<Self> {
        let private_key = Ed25519PrivateKey::from_hex(hex_str)?;
        Ok(Self::from_private_key(private_key))
    }

    /// Creates an account from a BIP-39 mnemonic phrase.
    ///
    /// Uses the standard Aptos derivation path: `m/44'/637'/0'/0'/index'`
    ///
    /// # Arguments
    ///
    /// * `mnemonic` - A BIP-39 mnemonic phrase (12, 15, 18, 21, or 24 words)
    /// * `index` - The account index in the derivation path
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use aptos_rust_sdk_v2::account::Ed25519Account;
    ///
    /// let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let account = Ed25519Account::from_mnemonic(mnemonic, 0).unwrap();
    /// ```
    #[cfg(feature = "mnemonic")]
    #[cfg_attr(docsrs, doc(cfg(feature = "mnemonic")))]
    pub fn from_mnemonic(mnemonic: &str, index: u32) -> AptosResult<Self> {
        let mnemonic = Mnemonic::from_phrase(mnemonic)?;
        let private_key = mnemonic.derive_ed25519_key(index)?;
        Ok(Self::from_private_key(private_key))
    }

    /// Generates a new account with a random mnemonic.
    ///
    /// Returns both the account and the mnemonic phrase (for backup).
    #[cfg(feature = "mnemonic")]
    #[cfg_attr(docsrs, doc(cfg(feature = "mnemonic")))]
    pub fn generate_with_mnemonic() -> AptosResult<(Self, String)> {
        let mnemonic = Mnemonic::generate(24)?;
        let phrase = mnemonic.phrase().to_string();
        let private_key = mnemonic.derive_ed25519_key(0)?;
        let account = Self::from_private_key(private_key);
        Ok((account, phrase))
    }

    /// Returns the account address.
    pub fn address(&self) -> AccountAddress {
        self.address
    }

    /// Returns the public key.
    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// Returns a reference to the private key.
    ///
    /// **Warning**: Handle with care to avoid leaking sensitive key material.
    pub fn private_key(&self) -> &Ed25519PrivateKey {
        &self.private_key
    }

    /// Signs a message and returns the Ed25519 signature.
    pub fn sign_message(&self, message: &[u8]) -> crate::crypto::Ed25519Signature {
        self.private_key.sign(message)
    }
}

impl Account for Ed25519Account {
    fn address(&self) -> AccountAddress {
        self.address
    }

    fn authentication_key(&self) -> AuthenticationKey {
        AuthenticationKey::new(self.public_key.to_authentication_key())
    }

    fn sign(&self, message: &[u8]) -> AptosResult<Vec<u8>> {
        Ok(self.private_key.sign(message).to_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    fn signature_scheme(&self) -> u8 {
        ED25519_SCHEME
    }
}

impl fmt::Debug for Ed25519Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Account")
            .field("address", &self.address)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let account = Ed25519Account::generate();
        assert!(!account.address().is_zero());
    }

    #[test]
    #[cfg(feature = "mnemonic")]
    fn test_from_mnemonic() {
        // Standard test mnemonic
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let account = Ed25519Account::from_mnemonic(mnemonic, 0).unwrap();

        // Same mnemonic should produce same account
        let account2 = Ed25519Account::from_mnemonic(mnemonic, 0).unwrap();
        assert_eq!(account.address(), account2.address());

        // Different index should produce different account
        let account3 = Ed25519Account::from_mnemonic(mnemonic, 1).unwrap();
        assert_ne!(account.address(), account3.address());
    }

    #[test]
    fn test_sign_and_verify() {
        let account = Ed25519Account::generate();
        let message = b"hello world";

        let signature = account.sign_message(message);
        assert!(account.public_key().verify(message, &signature).is_ok());
    }

    #[test]
    #[cfg(feature = "mnemonic")]
    fn test_generate_with_mnemonic() {
        let (account, mnemonic) = Ed25519Account::generate_with_mnemonic().unwrap();

        // Should be able to restore from the mnemonic
        let restored = Ed25519Account::from_mnemonic(&mnemonic, 0).unwrap();
        assert_eq!(account.address(), restored.address());
    }

    #[test]
    fn test_from_private_key() {
        let original = Ed25519Account::generate();
        let private_key = original.private_key().clone();
        let restored = Ed25519Account::from_private_key(private_key);
        assert_eq!(original.address(), restored.address());
    }

    #[test]
    fn test_from_private_key_bytes() {
        let original = Ed25519Account::generate();
        let bytes = original.private_key().to_bytes();
        let restored = Ed25519Account::from_private_key_bytes(&bytes).unwrap();
        assert_eq!(original.address(), restored.address());
    }

    #[test]
    fn test_from_private_key_hex() {
        let original = Ed25519Account::generate();
        let hex = original.private_key().to_hex();
        let restored = Ed25519Account::from_private_key_hex(&hex).unwrap();
        assert_eq!(original.address(), restored.address());
    }

    #[test]
    fn test_authentication_key() {
        let account = Ed25519Account::generate();
        let auth_key = account.authentication_key();
        assert_eq!(auth_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_public_key_bytes() {
        let account = Ed25519Account::generate();
        let bytes = account.public_key_bytes();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_signature_scheme() {
        let account = Ed25519Account::generate();
        assert_eq!(account.signature_scheme(), ED25519_SCHEME);
    }

    #[test]
    fn test_sign_trait() {
        let account = Ed25519Account::generate();
        let message = b"test message";
        let sig_bytes = account.sign(message).unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }

    #[test]
    fn test_debug_output() {
        let account = Ed25519Account::generate();
        let debug = format!("{:?}", account);
        assert!(debug.contains("Ed25519Account"));
        assert!(debug.contains("address"));
    }

    #[test]
    fn test_invalid_private_key_bytes() {
        let result = Ed25519Account::from_private_key_bytes(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_private_key_hex() {
        let result = Ed25519Account::from_private_key_hex("invalid");
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "mnemonic")]
    fn test_invalid_mnemonic() {
        let result = Ed25519Account::from_mnemonic("invalid mnemonic phrase", 0);
        assert!(result.is_err());
    }
}

