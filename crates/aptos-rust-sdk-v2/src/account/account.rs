//! Account trait and common types.

use crate::error::AptosResult;
use crate::types::AccountAddress;
use serde::{Deserialize, Serialize};
use std::fmt;

/// An authentication key used to verify account ownership.
///
/// The authentication key is derived from the public key and can be
/// rotated to support key rotation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthenticationKey([u8; 32]);

impl AuthenticationKey {
    /// Creates an authentication key from bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates an authentication key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice length is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != 32 {
            return Err(crate::error::AptosError::InvalidAddress(format!(
                "authentication key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Creates an authentication key from a hex string.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The hex string is invalid or cannot be decoded
    /// - The decoded bytes are not exactly 32 bytes long
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the authentication key as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the authentication key as a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Returns the authentication key as a hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Derives the account address from this authentication key.
    ///
    /// For most accounts, the address equals the authentication key.
    pub fn to_address(&self) -> AccountAddress {
        AccountAddress::new(self.0)
    }
}

impl fmt::Debug for AuthenticationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthenticationKey({})", self.to_hex())
    }
}

impl fmt::Display for AuthenticationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<[u8; 32]> for AuthenticationKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<AuthenticationKey> for [u8; 32] {
    fn from(key: AuthenticationKey) -> Self {
        key.0
    }
}

impl From<AuthenticationKey> for AccountAddress {
    fn from(key: AuthenticationKey) -> Self {
        key.to_address()
    }
}

/// Trait for account types that can sign transactions.
///
/// This trait provides a common interface for different account types
/// (Ed25519, Secp256k1, multi-sig, keyless, etc.).
pub trait Account: Send + Sync {
    /// Returns the account address.
    fn address(&self) -> AccountAddress;

    /// Returns the authentication key.
    fn authentication_key(&self) -> AuthenticationKey;

    /// Signs a message and returns the signature bytes.
    ///
    /// # Errors
    ///
    /// May return an error if signing fails (e.g., insufficient signatures
    /// for multi-sig accounts).
    fn sign(&self, message: &[u8]) -> AptosResult<Vec<u8>>;

    /// Returns the public key bytes.
    fn public_key_bytes(&self) -> Vec<u8>;

    /// Returns the scheme identifier for this account type.
    fn signature_scheme(&self) -> u8;
}

/// An enum that can hold any account type.
///
/// This is useful when you need to store different account types
/// in the same collection or pass them around generically.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // Keyless account is intentionally large; boxing would complicate API
pub enum AnyAccount {
    /// An Ed25519 account.
    #[cfg(feature = "ed25519")]
    Ed25519(super::Ed25519Account),
    /// A multi-Ed25519 account.
    #[cfg(feature = "ed25519")]
    MultiEd25519(super::MultiEd25519Account),
    /// A multi-key account (mixed signature types).
    MultiKey(super::MultiKeyAccount),
    /// A Keyless account.
    #[cfg(feature = "keyless")]
    Keyless(super::KeylessAccount),
    /// A Secp256k1 account.
    #[cfg(feature = "secp256k1")]
    Secp256k1(super::Secp256k1Account),
}

impl Account for AnyAccount {
    fn address(&self) -> AccountAddress {
        match self {
            #[cfg(feature = "ed25519")]
            AnyAccount::Ed25519(account) => account.address(),
            #[cfg(feature = "ed25519")]
            AnyAccount::MultiEd25519(account) => account.address(),
            AnyAccount::MultiKey(account) => account.address(),
            #[cfg(feature = "keyless")]
            AnyAccount::Keyless(account) => account.address(),
            #[cfg(feature = "secp256k1")]
            AnyAccount::Secp256k1(account) => account.address(),
        }
    }

    fn authentication_key(&self) -> AuthenticationKey {
        match self {
            #[cfg(feature = "ed25519")]
            AnyAccount::Ed25519(account) => account.authentication_key(),
            #[cfg(feature = "ed25519")]
            AnyAccount::MultiEd25519(account) => account.authentication_key(),
            AnyAccount::MultiKey(account) => account.authentication_key(),
            #[cfg(feature = "keyless")]
            AnyAccount::Keyless(account) => account.authentication_key(),
            #[cfg(feature = "secp256k1")]
            AnyAccount::Secp256k1(account) => account.authentication_key(),
        }
    }

    fn sign(&self, message: &[u8]) -> AptosResult<Vec<u8>> {
        match self {
            #[cfg(feature = "ed25519")]
            AnyAccount::Ed25519(account) => Account::sign(account, message),
            #[cfg(feature = "ed25519")]
            AnyAccount::MultiEd25519(account) => Account::sign(account, message),
            AnyAccount::MultiKey(account) => Account::sign(account, message),
            #[cfg(feature = "keyless")]
            AnyAccount::Keyless(account) => Account::sign(account, message),
            #[cfg(feature = "secp256k1")]
            AnyAccount::Secp256k1(account) => Account::sign(account, message),
        }
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "ed25519")]
            AnyAccount::Ed25519(account) => account.public_key_bytes(),
            #[cfg(feature = "ed25519")]
            AnyAccount::MultiEd25519(account) => account.public_key_bytes(),
            AnyAccount::MultiKey(account) => account.public_key_bytes(),
            #[cfg(feature = "keyless")]
            AnyAccount::Keyless(account) => account.public_key_bytes(),
            #[cfg(feature = "secp256k1")]
            AnyAccount::Secp256k1(account) => account.public_key_bytes(),
        }
    }

    fn signature_scheme(&self) -> u8 {
        match self {
            #[cfg(feature = "ed25519")]
            AnyAccount::Ed25519(account) => account.signature_scheme(),
            #[cfg(feature = "ed25519")]
            AnyAccount::MultiEd25519(account) => account.signature_scheme(),
            AnyAccount::MultiKey(account) => account.signature_scheme(),
            #[cfg(feature = "keyless")]
            AnyAccount::Keyless(account) => account.signature_scheme(),
            #[cfg(feature = "secp256k1")]
            AnyAccount::Secp256k1(account) => account.signature_scheme(),
        }
    }
}

#[cfg(feature = "ed25519")]
impl From<super::Ed25519Account> for AnyAccount {
    fn from(account: super::Ed25519Account) -> Self {
        AnyAccount::Ed25519(account)
    }
}

#[cfg(feature = "ed25519")]
impl From<super::MultiEd25519Account> for AnyAccount {
    fn from(account: super::MultiEd25519Account) -> Self {
        AnyAccount::MultiEd25519(account)
    }
}

#[cfg(feature = "keyless")]
impl From<super::KeylessAccount> for AnyAccount {
    fn from(account: super::KeylessAccount) -> Self {
        AnyAccount::Keyless(account)
    }
}

#[cfg(feature = "secp256k1")]
impl From<super::Secp256k1Account> for AnyAccount {
    fn from(account: super::Secp256k1Account) -> Self {
        AnyAccount::Secp256k1(account)
    }
}

impl From<super::MultiKeyAccount> for AnyAccount {
    fn from(account: super::MultiKeyAccount) -> Self {
        AnyAccount::MultiKey(account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authentication_key() {
        let key = AuthenticationKey::new([1u8; 32]);
        assert_eq!(key.as_bytes(), &[1u8; 32]);

        let hex = key.to_hex();
        let restored = AuthenticationKey::from_hex(&hex).unwrap();
        assert_eq!(key, restored);
    }

    #[test]
    fn test_auth_key_to_address() {
        let key = AuthenticationKey::new([42u8; 32]);
        let address = key.to_address();
        assert_eq!(address.as_bytes(), &[42u8; 32]);
    }

    #[test]
    fn test_auth_key_from_bytes() {
        let bytes = [5u8; 32];
        let key = AuthenticationKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.to_bytes(), bytes);
    }

    #[test]
    fn test_auth_key_from_bytes_invalid_length() {
        let bytes = [5u8; 16];
        let result = AuthenticationKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_key_from_hex_with_prefix() {
        let key = AuthenticationKey::new([0xab; 32]);
        let hex = key.to_hex();
        assert!(hex.starts_with("0x"));
        let restored = AuthenticationKey::from_hex(&hex).unwrap();
        assert_eq!(key, restored);
    }

    #[test]
    fn test_auth_key_from_hex_without_prefix() {
        let key = AuthenticationKey::new([0xcd; 32]);
        let hex = key.to_hex();
        let hex_without_prefix = hex.trim_start_matches("0x");
        let restored = AuthenticationKey::from_hex(hex_without_prefix).unwrap();
        assert_eq!(key, restored);
    }

    #[test]
    fn test_auth_key_display() {
        let key = AuthenticationKey::new([0xff; 32]);
        let display = format!("{}", key);
        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn test_auth_key_debug() {
        let key = AuthenticationKey::new([0xaa; 32]);
        let debug = format!("{:?}", key);
        assert!(debug.contains("AuthenticationKey"));
    }

    #[test]
    fn test_auth_key_from_array() {
        let bytes = [7u8; 32];
        let key: AuthenticationKey = bytes.into();
        assert_eq!(key.to_bytes(), bytes);
    }

    #[test]
    fn test_auth_key_to_array() {
        let key = AuthenticationKey::new([8u8; 32]);
        let bytes: [u8; 32] = key.into();
        assert_eq!(bytes, [8u8; 32]);
    }

    #[test]
    fn test_auth_key_to_account_address() {
        let key = AuthenticationKey::new([9u8; 32]);
        let address: AccountAddress = key.into();
        assert_eq!(address.as_bytes(), &[9u8; 32]);
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_any_account_from_ed25519() {
        let ed25519 = super::super::Ed25519Account::generate();
        let any_account: AnyAccount = ed25519.into();
        if let AnyAccount::Ed25519(account) = any_account {
            assert!(!account.address().is_zero());
        } else {
            panic!("Expected Ed25519 account");
        }
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_any_account_ed25519_trait_methods() {
        let ed25519 = super::super::Ed25519Account::generate();
        let address = ed25519.address();
        let auth_key = ed25519.authentication_key();
        let any_account: AnyAccount = ed25519.into();

        assert_eq!(any_account.address(), address);
        assert_eq!(any_account.authentication_key(), auth_key);
        assert!(!any_account.public_key_bytes().is_empty());

        let sig = any_account.sign(b"test message").unwrap();
        assert!(!sig.is_empty());
    }

    #[cfg(feature = "secp256k1")]
    #[test]
    fn test_any_account_from_secp256k1() {
        let secp = super::super::Secp256k1Account::generate();
        let any_account: AnyAccount = secp.into();
        if let AnyAccount::Secp256k1(account) = any_account {
            assert!(!account.address().is_zero());
        } else {
            panic!("Expected Secp256k1 account");
        }
    }
}
