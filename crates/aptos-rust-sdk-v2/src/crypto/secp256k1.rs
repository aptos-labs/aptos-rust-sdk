//! Secp256k1 ECDSA signature scheme implementation.
//!
//! Secp256k1 is the same elliptic curve used by Bitcoin and Ethereum.

use crate::crypto::traits::{PublicKey, Signature, Signer, Verifier};
use crate::error::{AptosError, AptosResult};
use k256::ecdsa::{
    Signature as K256Signature, SigningKey, VerifyingKey, signature::Signer as K256Signer,
    signature::Verifier as K256Verifier,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// Secp256k1 private key length in bytes.
pub const SECP256K1_PRIVATE_KEY_LENGTH: usize = 32;
/// Secp256k1 public key length in bytes (compressed).
pub const SECP256K1_PUBLIC_KEY_LENGTH: usize = 33;
/// Secp256k1 uncompressed public key length in bytes.
#[allow(dead_code)] // Public API constant
pub const SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LENGTH: usize = 65;
/// Secp256k1 signature length in bytes (DER encoded max).
pub const SECP256K1_SIGNATURE_LENGTH: usize = 64;

/// A Secp256k1 ECDSA private key.
///
/// The private key is zeroized when dropped.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Secp256k1PrivateKey {
    #[zeroize(skip)]
    #[allow(unused)] // Field is used; lint false positive from Zeroize derive
    inner: SigningKey,
}

impl Secp256k1PrivateKey {
    /// Generates a new random Secp256k1 private key.
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
        Self { inner: signing_key }
    }

    /// Creates a private key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != SECP256K1_PRIVATE_KEY_LENGTH {
            return Err(AptosError::InvalidPrivateKey(format!(
                "expected {} bytes, got {}",
                SECP256K1_PRIVATE_KEY_LENGTH,
                bytes.len()
            )));
        }
        let signing_key = SigningKey::from_slice(bytes)
            .map_err(|e| AptosError::InvalidPrivateKey(e.to_string()))?;
        Ok(Self { inner: signing_key })
    }

    /// Creates a private key from a hex string.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the private key as bytes.
    pub fn to_bytes(&self) -> [u8; SECP256K1_PRIVATE_KEY_LENGTH] {
        self.inner.to_bytes().into()
    }

    /// Returns the private key as a hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.inner.to_bytes()))
    }

    /// Returns the corresponding public key.
    pub fn public_key(&self) -> Secp256k1PublicKey {
        Secp256k1PublicKey {
            inner: *self.inner.verifying_key(),
        }
    }

    /// Signs a message (pre-hashed with SHA256) and returns the signature.
    pub fn sign(&self, message: &[u8]) -> Secp256k1Signature {
        // Hash the message with SHA256 first (standard for ECDSA)
        let hash = crate::crypto::sha2_256(message);
        let signature: K256Signature = self.inner.sign(&hash);
        Secp256k1Signature { inner: signature }
    }

    /// Signs a pre-hashed message directly.
    pub fn sign_prehashed(&self, hash: &[u8; 32]) -> Secp256k1Signature {
        let signature: K256Signature = self.inner.sign(hash);
        Secp256k1Signature { inner: signature }
    }
}

impl Signer for Secp256k1PrivateKey {
    type Signature = Secp256k1Signature;

    fn sign(&self, message: &[u8]) -> Secp256k1Signature {
        Secp256k1PrivateKey::sign(self, message)
    }

    fn public_key(&self) -> Secp256k1PublicKey {
        Secp256k1PrivateKey::public_key(self)
    }
}

impl fmt::Debug for Secp256k1PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secp256k1PrivateKey([REDACTED])")
    }
}

/// A Secp256k1 ECDSA public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Secp256k1PublicKey {
    inner: VerifyingKey,
}

impl Secp256k1PublicKey {
    /// Creates a public key from compressed bytes (33 bytes).
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        let verifying_key = VerifyingKey::from_sec1_bytes(bytes)
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

    /// Returns the public key as compressed bytes (33 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_sec1_bytes().to_vec()
    }

    /// Returns the public key as uncompressed bytes (65 bytes).
    #[allow(dead_code)] // Public API
    pub fn to_uncompressed_bytes(&self) -> Vec<u8> {
        #[allow(unused_imports)]
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        self.inner.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Returns the public key as a hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }

    /// Verifies a signature against a message.
    pub fn verify(&self, message: &[u8], signature: &Secp256k1Signature) -> AptosResult<()> {
        // Hash the message with SHA256 first
        let hash = crate::crypto::sha2_256(message);
        self.inner
            .verify(&hash, &signature.inner)
            .map_err(|_| AptosError::SignatureVerificationFailed)
    }

    /// Verifies a signature against a pre-hashed message.
    pub fn verify_prehashed(
        &self,
        hash: &[u8; 32],
        signature: &Secp256k1Signature,
    ) -> AptosResult<()> {
        self.inner
            .verify(hash, &signature.inner)
            .map_err(|_| AptosError::SignatureVerificationFailed)
    }

    /// Derives the account address for this public key.
    pub fn to_address(&self) -> crate::types::AccountAddress {
        crate::crypto::derive_address(&self.to_bytes(), crate::crypto::SINGLE_KEY_SCHEME)
    }
}

impl PublicKey for Secp256k1PublicKey {
    const LENGTH: usize = SECP256K1_PUBLIC_KEY_LENGTH;

    fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        Secp256k1PublicKey::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Secp256k1PublicKey::to_bytes(self)
    }
}

impl Verifier for Secp256k1PublicKey {
    type Signature = Secp256k1Signature;

    fn verify(&self, message: &[u8], signature: &Secp256k1Signature) -> AptosResult<()> {
        Secp256k1PublicKey::verify(self, message, signature)
    }
}

impl fmt::Debug for Secp256k1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secp256k1PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for Secp256k1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Secp256k1PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(&self.to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for Secp256k1PublicKey {
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

/// A Secp256k1 ECDSA signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Secp256k1Signature {
    inner: K256Signature,
}

impl Secp256k1Signature {
    /// Creates a signature from raw bytes (64 bytes, r || s).
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != SECP256K1_SIGNATURE_LENGTH {
            return Err(AptosError::InvalidSignature(format!(
                "expected {} bytes, got {}",
                SECP256K1_SIGNATURE_LENGTH,
                bytes.len()
            )));
        }
        let signature = K256Signature::from_slice(bytes)
            .map_err(|e| AptosError::InvalidSignature(e.to_string()))?;
        Ok(Self { inner: signature })
    }

    /// Creates a signature from a hex string.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the signature as bytes (64 bytes, r || s).
    pub fn to_bytes(&self) -> [u8; SECP256K1_SIGNATURE_LENGTH] {
        self.inner.to_bytes().into()
    }

    /// Returns the signature as a hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }
}

impl Signature for Secp256k1Signature {
    type PublicKey = Secp256k1PublicKey;
    const LENGTH: usize = SECP256K1_SIGNATURE_LENGTH;

    fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        Secp256k1Signature::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

impl fmt::Debug for Secp256k1Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secp256k1Signature({})", self.to_hex())
    }
}

impl fmt::Display for Secp256k1Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Secp256k1Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(&self.to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for Secp256k1Signature {
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
        let private_key = Secp256k1PrivateKey::generate();
        let message = b"hello world";
        let signature = private_key.sign(message);

        let public_key = private_key.public_key();
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        let private_key = Secp256k1PrivateKey::generate();
        let message = b"hello world";
        let wrong_message = b"hello world!";
        let signature = private_key.sign(message);

        let public_key = private_key.public_key();
        assert!(public_key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let private_key = Secp256k1PrivateKey::generate();
        let bytes = private_key.to_bytes();
        let restored = Secp256k1PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(private_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_public_key_compressed() {
        let private_key = Secp256k1PrivateKey::generate();
        let public_key = private_key.public_key();

        // Compressed should be 33 bytes
        assert_eq!(public_key.to_bytes().len(), 33);

        // Uncompressed should be 65 bytes
        assert_eq!(public_key.to_uncompressed_bytes().len(), 65);
    }

    #[test]
    fn test_public_key_from_bytes_roundtrip() {
        let private_key = Secp256k1PrivateKey::generate();
        let public_key = private_key.public_key();
        let bytes = public_key.to_bytes();
        let restored = Secp256k1PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_signature_from_bytes_roundtrip() {
        let private_key = Secp256k1PrivateKey::generate();
        let signature = private_key.sign(b"test");
        let bytes = signature.to_bytes();
        let restored = Secp256k1Signature::from_bytes(&bytes).unwrap();
        assert_eq!(signature.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_hex_roundtrip() {
        let private_key = Secp256k1PrivateKey::generate();
        let hex = private_key.to_hex();
        let restored = Secp256k1PrivateKey::from_hex(&hex).unwrap();
        assert_eq!(private_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_public_key_hex_roundtrip() {
        let private_key = Secp256k1PrivateKey::generate();
        let public_key = private_key.public_key();
        let hex = public_key.to_hex();
        let restored = Secp256k1PublicKey::from_hex(&hex).unwrap();
        assert_eq!(public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_signature_hex_roundtrip() {
        let private_key = Secp256k1PrivateKey::generate();
        let signature = private_key.sign(b"test");
        let hex = signature.to_hex();
        let restored = Secp256k1Signature::from_hex(&hex).unwrap();
        assert_eq!(signature.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_invalid_private_key_bytes() {
        let bytes = vec![0u8; 16]; // Wrong length
        let result = Secp256k1PrivateKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_public_key_bytes() {
        let bytes = vec![0u8; 16]; // Wrong length
        let result = Secp256k1PublicKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_signature_bytes() {
        let bytes = vec![0u8; 16]; // Wrong length
        let result = Secp256k1Signature::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_json_serialization_public_key() {
        let private_key = Secp256k1PrivateKey::generate();
        let public_key = private_key.public_key();
        let json = serde_json::to_string(&public_key).unwrap();
        let restored: Secp256k1PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_json_serialization_signature() {
        let private_key = Secp256k1PrivateKey::generate();
        let signature = private_key.sign(b"test");
        let json = serde_json::to_string(&signature).unwrap();
        let restored: Secp256k1Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(signature.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_key_lengths() {
        assert_eq!(Secp256k1PublicKey::LENGTH, SECP256K1_PUBLIC_KEY_LENGTH);
        assert_eq!(Secp256k1Signature::LENGTH, SECP256K1_SIGNATURE_LENGTH);
    }

    #[test]
    fn test_display_debug() {
        let private_key = Secp256k1PrivateKey::generate();
        let public_key = private_key.public_key();
        let signature = private_key.sign(b"test");

        // Debug should contain type name
        assert!(format!("{:?}", public_key).contains("Secp256k1PublicKey"));
        assert!(format!("{:?}", signature).contains("Secp256k1Signature"));

        // Display should show hex
        assert!(format!("{}", public_key).starts_with("0x"));
        assert!(format!("{}", signature).starts_with("0x"));
    }
}
