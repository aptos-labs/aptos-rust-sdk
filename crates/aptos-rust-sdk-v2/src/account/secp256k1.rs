//! Secp256k1 account implementation.

use crate::account::account::{Account, AuthenticationKey};
use crate::crypto::{
    SINGLE_KEY_SCHEME, Secp256k1PrivateKey, Secp256k1PublicKey, derive_authentication_key,
};
use crate::error::AptosResult;
use crate::types::AccountAddress;
use std::fmt;

/// A Secp256k1 ECDSA account for signing transactions.
///
/// This account type uses the same elliptic curve as Bitcoin and Ethereum.
///
/// # Example
///
/// ```rust
/// use aptos_rust_sdk_v2::account::Secp256k1Account;
///
/// let account = Secp256k1Account::generate();
/// println!("Address: {}", account.address());
/// ```
#[derive(Clone)]
pub struct Secp256k1Account {
    private_key: Secp256k1PrivateKey,
    public_key: Secp256k1PublicKey,
    address: AccountAddress,
}

impl Secp256k1Account {
    /// Generates a new random Secp256k1 account.
    pub fn generate() -> Self {
        let private_key = Secp256k1PrivateKey::generate();
        Self::from_private_key(private_key)
    }

    /// Creates an account from a private key.
    pub fn from_private_key(private_key: Secp256k1PrivateKey) -> Self {
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
    /// Returns an error if the bytes are not a valid Secp256k1 private key (must be exactly 32 bytes and a valid curve point).
    pub fn from_private_key_bytes(bytes: &[u8]) -> AptosResult<Self> {
        let private_key = Secp256k1PrivateKey::from_bytes(bytes)?;
        Ok(Self::from_private_key(private_key))
    }

    /// Creates an account from a private key hex string.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The hex string is invalid or cannot be decoded
    /// - The decoded bytes are not a valid Secp256k1 private key
    pub fn from_private_key_hex(hex_str: &str) -> AptosResult<Self> {
        let private_key = Secp256k1PrivateKey::from_hex(hex_str)?;
        Ok(Self::from_private_key(private_key))
    }

    /// Returns the account address.
    pub fn address(&self) -> AccountAddress {
        self.address
    }

    /// Returns the public key.
    pub fn public_key(&self) -> &Secp256k1PublicKey {
        &self.public_key
    }

    /// Returns a reference to the private key.
    pub fn private_key(&self) -> &Secp256k1PrivateKey {
        &self.private_key
    }

    /// Signs a message and returns the Secp256k1 signature.
    pub fn sign_message(&self, message: &[u8]) -> crate::crypto::Secp256k1Signature {
        self.private_key.sign(message)
    }
}

impl Account for Secp256k1Account {
    fn address(&self) -> AccountAddress {
        self.address
    }

    fn authentication_key(&self) -> AuthenticationKey {
        let key = derive_authentication_key(&self.public_key.to_bytes(), SINGLE_KEY_SCHEME);
        AuthenticationKey::new(key)
    }

    fn sign(&self, message: &[u8]) -> crate::error::AptosResult<Vec<u8>> {
        Ok(self.private_key.sign(message).to_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes()
    }

    fn signature_scheme(&self) -> u8 {
        SINGLE_KEY_SCHEME
    }
}

impl fmt::Debug for Secp256k1Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secp256k1Account")
            .field("address", &self.address)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;

    #[test]
    fn test_generate() {
        let account = Secp256k1Account::generate();
        assert!(!account.address().is_zero());
    }

    #[test]
    fn test_from_private_key_roundtrip() {
        let account = Secp256k1Account::generate();
        let bytes = account.private_key().to_bytes();

        let restored = Secp256k1Account::from_private_key_bytes(&bytes).unwrap();
        assert_eq!(account.address(), restored.address());
    }

    #[test]
    fn test_sign_and_verify() {
        let account = Secp256k1Account::generate();
        let message = b"hello world";

        let signature = account.sign_message(message);
        assert!(account.public_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_from_private_key() {
        let original = Secp256k1Account::generate();
        let private_key = original.private_key().clone();
        let restored = Secp256k1Account::from_private_key(private_key);
        assert_eq!(original.address(), restored.address());
    }

    #[test]
    fn test_from_private_key_hex() {
        let original = Secp256k1Account::generate();
        let hex = original.private_key().to_hex();
        let restored = Secp256k1Account::from_private_key_hex(&hex).unwrap();
        assert_eq!(original.address(), restored.address());
    }

    #[test]
    fn test_authentication_key() {
        let account = Secp256k1Account::generate();
        let auth_key = account.authentication_key();
        assert_eq!(auth_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_public_key_bytes() {
        let account = Secp256k1Account::generate();
        let bytes = account.public_key_bytes();
        assert_eq!(bytes.len(), 33); // Compressed public key
    }

    #[test]
    fn test_signature_scheme() {
        let account = Secp256k1Account::generate();
        assert_eq!(account.signature_scheme(), SINGLE_KEY_SCHEME);
    }

    #[test]
    fn test_sign_trait() {
        let account = Secp256k1Account::generate();
        let message = b"test message";
        let sig_bytes = account.sign(message).unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }

    #[test]
    fn test_debug_output() {
        let account = Secp256k1Account::generate();
        let debug = format!("{:?}", account);
        assert!(debug.contains("Secp256k1Account"));
        assert!(debug.contains("address"));
    }

    #[test]
    fn test_invalid_private_key_bytes() {
        let result = Secp256k1Account::from_private_key_bytes(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_private_key_hex() {
        let result = Secp256k1Account::from_private_key_hex("invalid");
        assert!(result.is_err());
    }
}
