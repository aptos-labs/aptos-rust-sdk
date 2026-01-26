//! Ed25519 signature scheme implementation.
//!
//! Ed25519 is the default and most commonly used signature scheme on Aptos.

use crate::crypto::traits::{PublicKey, Signature, Signer, Verifier};
use crate::error::{AptosError, AptosResult};
use ed25519_dalek::{Signer as DalekSigner, Verifier as DalekVerifier};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// Ed25519 private key length in bytes.
pub const ED25519_PRIVATE_KEY_LENGTH: usize = 32;
/// Ed25519 public key length in bytes.
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
/// Ed25519 signature length in bytes.
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// An Ed25519 private key.
///
/// The private key is zeroized when dropped to prevent sensitive
/// data from remaining in memory.
///
/// # Example
///
/// ```rust
/// use aptos_rust_sdk_v2::crypto::{Ed25519PrivateKey, Signer};
///
/// // Generate a random key
/// let private_key = Ed25519PrivateKey::generate();
///
/// // Sign a message
/// let signature = private_key.sign(b"hello");
///
/// // Get the public key
/// let public_key = private_key.public_key();
/// ```
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Ed25519PrivateKey {
    #[zeroize(skip)]
    #[allow(unused)] // Field is used; lint false positive from Zeroize derive
    inner: ed25519_dalek::SigningKey,
}

impl Ed25519PrivateKey {
    /// Generates a new random Ed25519 private key.
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        Self { inner: signing_key }
    }

    /// Creates a private key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != ED25519_PRIVATE_KEY_LENGTH {
            return Err(AptosError::InvalidPrivateKey(format!(
                "expected {} bytes, got {}",
                ED25519_PRIVATE_KEY_LENGTH,
                bytes.len()
            )));
        }
        let mut key_bytes = [0u8; ED25519_PRIVATE_KEY_LENGTH];
        key_bytes.copy_from_slice(bytes);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
        Ok(Self { inner: signing_key })
    }

    /// Creates a private key from a hex string.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the private key as bytes.
    ///
    /// **Warning**: Handle the returned bytes carefully to avoid leaking
    /// sensitive key material.
    pub fn to_bytes(&self) -> [u8; ED25519_PRIVATE_KEY_LENGTH] {
        self.inner.to_bytes()
    }

    /// Returns the private key as a hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.inner.to_bytes()))
    }

    /// Returns the corresponding public key.
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Signs a message and returns the signature.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let signature = self.inner.sign(message);
        Ed25519Signature { inner: signature }
    }
}

impl Signer for Ed25519PrivateKey {
    type Signature = Ed25519Signature;

    fn sign(&self, message: &[u8]) -> Ed25519Signature {
        Ed25519PrivateKey::sign(self, message)
    }

    fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PrivateKey::public_key(self)
    }
}

impl fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519PrivateKey([REDACTED])")
    }
}

/// An Ed25519 public key.
///
/// # Example
///
/// ```rust
/// use aptos_rust_sdk_v2::crypto::{Ed25519PrivateKey, Ed25519PublicKey, Signer, Verifier};
///
/// let private_key = Ed25519PrivateKey::generate();
/// let public_key = private_key.public_key();
///
/// let message = b"hello";
/// let signature = private_key.sign(message);
///
/// assert!(public_key.verify(message, &signature).is_ok());
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ed25519PublicKey {
    inner: ed25519_dalek::VerifyingKey,
}

impl Ed25519PublicKey {
    /// Creates a public key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != ED25519_PUBLIC_KEY_LENGTH {
            return Err(AptosError::InvalidPublicKey(format!(
                "expected {} bytes, got {}",
                ED25519_PUBLIC_KEY_LENGTH,
                bytes.len()
            )));
        }
        let mut key_bytes = [0u8; ED25519_PUBLIC_KEY_LENGTH];
        key_bytes.copy_from_slice(bytes);
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| AptosError::InvalidPublicKey(e.to_string()))?;
        Ok(Self {
            inner: verifying_key,
        })
    }

    /// Creates a public key from a hex string.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the public key as bytes.
    pub fn to_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_LENGTH] {
        self.inner.to_bytes()
    }

    /// Returns the public key as a hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.inner.to_bytes()))
    }

    /// Verifies a signature against a message.
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> AptosResult<()> {
        self.inner
            .verify(message, &signature.inner)
            .map_err(|_| AptosError::SignatureVerificationFailed)
    }

    /// Derives the account address for this public key.
    ///
    /// Uses the Ed25519 single-key scheme (scheme byte 0).
    pub fn to_address(&self) -> crate::types::AccountAddress {
        crate::crypto::derive_address(&self.to_bytes(), crate::crypto::ED25519_SCHEME)
    }

    /// Derives the authentication key for this public key.
    pub fn to_authentication_key(&self) -> [u8; 32] {
        crate::crypto::derive_authentication_key(&self.to_bytes(), crate::crypto::ED25519_SCHEME)
    }
}

impl PublicKey for Ed25519PublicKey {
    const LENGTH: usize = ED25519_PUBLIC_KEY_LENGTH;

    fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        Ed25519PublicKey::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

impl Verifier for Ed25519PublicKey {
    type Signature = Ed25519Signature;

    fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> AptosResult<()> {
        Ed25519PublicKey::verify(self, message, signature)
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Ed25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(&self.inner.to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <[u8; ED25519_PUBLIC_KEY_LENGTH]>::deserialize(deserializer)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

/// An Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Signature {
    inner: ed25519_dalek::Signature,
}

impl Ed25519Signature {
    /// Creates a signature from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != ED25519_SIGNATURE_LENGTH {
            return Err(AptosError::InvalidSignature(format!(
                "expected {} bytes, got {}",
                ED25519_SIGNATURE_LENGTH,
                bytes.len()
            )));
        }
        let signature = ed25519_dalek::Signature::from_slice(bytes)
            .map_err(|e| AptosError::InvalidSignature(e.to_string()))?;
        Ok(Self { inner: signature })
    }

    /// Creates a signature from a hex string.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the signature as bytes.
    pub fn to_bytes(&self) -> [u8; ED25519_SIGNATURE_LENGTH] {
        self.inner.to_bytes()
    }

    /// Returns the signature as a hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.inner.to_bytes()))
    }
}

impl Signature for Ed25519Signature {
    type PublicKey = Ed25519PublicKey;
    const LENGTH: usize = ED25519_SIGNATURE_LENGTH;

    fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        Ed25519Signature::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

impl fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Signature({})", self.to_hex())
    }
}

impl fmt::Display for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Ed25519Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(&self.inner.to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for Ed25519Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign() {
        let private_key = Ed25519PrivateKey::generate();
        let message = b"hello world";
        let signature = private_key.sign(message);

        let public_key = private_key.public_key();
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        let private_key = Ed25519PrivateKey::generate();
        let message = b"hello world";
        let wrong_message = b"hello world!";
        let signature = private_key.sign(message);

        let public_key = private_key.public_key();
        assert!(public_key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let private_key = Ed25519PrivateKey::generate();
        let bytes = private_key.to_bytes();
        let restored = Ed25519PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(private_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_from_hex_roundtrip() {
        let private_key = Ed25519PrivateKey::generate();
        let hex = private_key.to_hex();
        let restored = Ed25519PrivateKey::from_hex(&hex).unwrap();
        assert_eq!(private_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_public_key_serialization() {
        let private_key = Ed25519PrivateKey::generate();
        let public_key = private_key.public_key();

        let json = serde_json::to_string(&public_key).unwrap();
        let restored: Ed25519PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(public_key, restored);
    }

    #[test]
    fn test_address_derivation() {
        let private_key = Ed25519PrivateKey::generate();
        let public_key = private_key.public_key();
        let address = public_key.to_address();

        // Address should not be zero
        assert!(!address.is_zero());

        // Same public key should always derive same address
        let address2 = public_key.to_address();
        assert_eq!(address, address2);
    }
}
