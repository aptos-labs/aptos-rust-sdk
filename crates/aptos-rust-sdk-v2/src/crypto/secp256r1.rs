//! Secp256r1 (P-256) ECDSA signature scheme implementation.
//!
//! Secp256r1, also known as P-256 or prime256v1, is commonly used in
//! `WebAuthn` and passkey implementations.

use crate::crypto::traits::{PublicKey, Signature, Signer, Verifier};
use crate::error::{AptosError, AptosResult};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey, VerifyingKey, signature::Signer as P256Signer,
    signature::Verifier as P256Verifier,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// Secp256r1 private key length in bytes.
pub const SECP256R1_PRIVATE_KEY_LENGTH: usize = 32;
/// Secp256r1 public key length in bytes (compressed).
pub const SECP256R1_PUBLIC_KEY_LENGTH: usize = 33;
/// Secp256r1 signature length in bytes.
pub const SECP256R1_SIGNATURE_LENGTH: usize = 64;

/// A Secp256r1 (P-256) ECDSA private key.
///
/// The private key is zeroized when dropped.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Secp256r1PrivateKey {
    #[zeroize(skip)]
    #[allow(unused)] // Field is used; lint false positive from Zeroize derive
    inner: SigningKey,
}

impl Secp256r1PrivateKey {
    /// Generates a new random Secp256r1 private key.
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
        Self { inner: signing_key }
    }

    /// Creates a private key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::InvalidPrivateKey`] if:
    /// - The byte slice length is not exactly 32 bytes
    /// - The bytes do not represent a valid Secp256r1 private key
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != SECP256R1_PRIVATE_KEY_LENGTH {
            return Err(AptosError::InvalidPrivateKey(format!(
                "expected {} bytes, got {}",
                SECP256R1_PRIVATE_KEY_LENGTH,
                bytes.len()
            )));
        }
        let signing_key = SigningKey::from_slice(bytes)
            .map_err(|e| AptosError::InvalidPrivateKey(e.to_string()))?;
        Ok(Self { inner: signing_key })
    }

    /// Creates a private key from a hex string.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::Hex`] if the hex string is invalid.
    /// Returns [`AptosError::InvalidPrivateKey`] if the decoded bytes are not exactly 32 bytes or do not represent a valid Secp256r1 private key.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Creates a private key from AIP-80 format string.
    ///
    /// AIP-80 format: `secp256r1-priv-0x{hex_bytes}`
    ///
    /// # Errors
    ///
    /// Returns an error if the format is invalid or the key bytes are invalid.
    pub fn from_aip80(s: &str) -> AptosResult<Self> {
        const PREFIX: &str = "secp256r1-priv-";
        if let Some(hex_part) = s.strip_prefix(PREFIX) {
            Self::from_hex(hex_part)
        } else {
            Err(AptosError::InvalidPrivateKey(format!(
                "invalid AIP-80 format: expected prefix '{PREFIX}'"
            )))
        }
    }

    /// Returns the private key as bytes.
    pub fn to_bytes(&self) -> [u8; SECP256R1_PRIVATE_KEY_LENGTH] {
        self.inner.to_bytes().into()
    }

    /// Returns the private key as a hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.inner.to_bytes()))
    }

    /// Returns the private key in AIP-80 format.
    ///
    /// AIP-80 format: `secp256r1-priv-0x{hex_bytes}`
    pub fn to_aip80(&self) -> String {
        format!("secp256r1-priv-{}", self.to_hex())
    }

    /// Returns the corresponding public key.
    pub fn public_key(&self) -> Secp256r1PublicKey {
        Secp256r1PublicKey {
            inner: *self.inner.verifying_key(),
        }
    }

    /// Signs a message (pre-hashed with SHA256) and returns the signature.
    pub fn sign(&self, message: &[u8]) -> Secp256r1Signature {
        let hash = crate::crypto::sha2_256(message);
        let signature: P256Signature = self.inner.sign(&hash);
        Secp256r1Signature { inner: signature }
    }

    /// Signs a pre-hashed message directly.
    pub fn sign_prehashed(&self, hash: &[u8; 32]) -> Secp256r1Signature {
        let signature: P256Signature = self.inner.sign(hash);
        Secp256r1Signature { inner: signature }
    }
}

impl Signer for Secp256r1PrivateKey {
    type Signature = Secp256r1Signature;

    fn sign(&self, message: &[u8]) -> Secp256r1Signature {
        Secp256r1PrivateKey::sign(self, message)
    }

    fn public_key(&self) -> Secp256r1PublicKey {
        Secp256r1PrivateKey::public_key(self)
    }
}

impl fmt::Debug for Secp256r1PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secp256r1PrivateKey([REDACTED])")
    }
}

/// A Secp256r1 (P-256) ECDSA public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Secp256r1PublicKey {
    inner: VerifyingKey,
}

impl Secp256r1PublicKey {
    /// Creates a public key from compressed bytes (33 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::InvalidPublicKey`] if the bytes do not represent a valid Secp256r1 compressed public key.
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        let verifying_key = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| AptosError::InvalidPublicKey(e.to_string()))?;
        Ok(Self {
            inner: verifying_key,
        })
    }

    /// Creates a public key from a hex string.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::Hex`] if the hex string is invalid.
    /// Returns [`AptosError::InvalidPublicKey`] if the decoded bytes do not represent a valid Secp256r1 compressed public key.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Creates a public key from AIP-80 format string.
    ///
    /// AIP-80 format: `secp256r1-pub-0x{hex_bytes}`
    ///
    /// # Errors
    ///
    /// Returns an error if the format is invalid or the key bytes are invalid.
    pub fn from_aip80(s: &str) -> AptosResult<Self> {
        const PREFIX: &str = "secp256r1-pub-";
        if let Some(hex_part) = s.strip_prefix(PREFIX) {
            Self::from_hex(hex_part)
        } else {
            Err(AptosError::InvalidPublicKey(format!(
                "invalid AIP-80 format: expected prefix '{PREFIX}'"
            )))
        }
    }

    /// Returns the public key as compressed bytes (33 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        #[allow(unused_imports)]
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        self.inner.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Returns the public key as uncompressed bytes (65 bytes).
    pub fn to_uncompressed_bytes(&self) -> Vec<u8> {
        #[allow(unused_imports)]
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        self.inner.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Returns the public key as a hex string (compressed format).
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }

    /// Returns the public key in AIP-80 format (compressed).
    ///
    /// AIP-80 format: `secp256r1-pub-0x{hex_bytes}`
    pub fn to_aip80(&self) -> String {
        format!("secp256r1-pub-{}", self.to_hex())
    }

    /// Verifies a signature against a message.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::SignatureVerificationFailed`] if the signature is invalid or does not match the message.
    pub fn verify(&self, message: &[u8], signature: &Secp256r1Signature) -> AptosResult<()> {
        let hash = crate::crypto::sha2_256(message);
        self.inner
            .verify(&hash, &signature.inner)
            .map_err(|_| AptosError::SignatureVerificationFailed)
    }

    /// Verifies a signature against a pre-hashed message.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::SignatureVerificationFailed`] if the signature is invalid or does not match the hash.
    pub fn verify_prehashed(
        &self,
        hash: &[u8; 32],
        signature: &Secp256r1Signature,
    ) -> AptosResult<()> {
        self.inner
            .verify(hash, &signature.inner)
            .map_err(|_| AptosError::SignatureVerificationFailed)
    }

    /// Derives the account address for this public key.
    ///
    /// Uses the `SingleKey` authentication scheme (`scheme_id` = 2):
    /// `auth_key = SHA3-256(BCS(AnyPublicKey::Secp256r1) || 0x02)`
    ///
    /// Where `BCS(AnyPublicKey::Secp256r1)` = `0x02 || ULEB128(65) || uncompressed_public_key`
    pub fn to_address(&self) -> crate::types::AccountAddress {
        // BCS format: variant_byte || ULEB128(length) || uncompressed_public_key
        let uncompressed = self.to_uncompressed_bytes();
        let mut bcs_bytes = Vec::with_capacity(1 + 1 + uncompressed.len());
        bcs_bytes.push(0x02); // Secp256r1 variant
        bcs_bytes.push(65); // ULEB128(65) = 65 (since 65 < 128)
        bcs_bytes.extend_from_slice(&uncompressed);
        crate::crypto::derive_address(&bcs_bytes, crate::crypto::SINGLE_KEY_SCHEME)
    }
}

impl PublicKey for Secp256r1PublicKey {
    const LENGTH: usize = SECP256R1_PUBLIC_KEY_LENGTH;

    fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        Secp256r1PublicKey::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Secp256r1PublicKey::to_bytes(self)
    }
}

impl Verifier for Secp256r1PublicKey {
    type Signature = Secp256r1Signature;

    fn verify(&self, message: &[u8], signature: &Secp256r1Signature) -> AptosResult<()> {
        Secp256r1PublicKey::verify(self, message, signature)
    }
}

impl fmt::Debug for Secp256r1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secp256r1PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for Secp256r1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Secp256r1PublicKey {
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

impl<'de> Deserialize<'de> for Secp256r1PublicKey {
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

/// A Secp256r1 (P-256) ECDSA signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Secp256r1Signature {
    inner: P256Signature,
}

impl Secp256r1Signature {
    /// Creates a signature from raw bytes (64 bytes, r || s).
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::InvalidSignature`] if:
    /// - The byte slice length is not exactly 64 bytes
    /// - The bytes do not represent a valid Secp256r1 signature
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != SECP256R1_SIGNATURE_LENGTH {
            return Err(AptosError::InvalidSignature(format!(
                "expected {} bytes, got {}",
                SECP256R1_SIGNATURE_LENGTH,
                bytes.len()
            )));
        }
        let signature = P256Signature::from_slice(bytes)
            .map_err(|e| AptosError::InvalidSignature(e.to_string()))?;
        Ok(Self { inner: signature })
    }

    /// Creates a signature from a hex string.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::Hex`] if the hex string is invalid.
    /// Returns [`AptosError::InvalidSignature`] if the decoded bytes are not exactly 64 bytes or do not represent a valid Secp256r1 signature.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the signature as bytes (64 bytes, r || s).
    pub fn to_bytes(&self) -> [u8; SECP256R1_SIGNATURE_LENGTH] {
        self.inner.to_bytes().into()
    }

    /// Returns the signature as a hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }
}

impl Signature for Secp256r1Signature {
    type PublicKey = Secp256r1PublicKey;
    const LENGTH: usize = SECP256R1_SIGNATURE_LENGTH;

    fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        Secp256r1Signature::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

impl fmt::Debug for Secp256r1Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secp256r1Signature({})", self.to_hex())
    }
}

impl fmt::Display for Secp256r1Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Secp256r1Signature {
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

impl<'de> Deserialize<'de> for Secp256r1Signature {
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
        let private_key = Secp256r1PrivateKey::generate();
        let message = b"hello world";
        let signature = private_key.sign(message);

        let public_key = private_key.public_key();
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        let private_key = Secp256r1PrivateKey::generate();
        let message = b"hello world";
        let wrong_message = b"hello world!";
        let signature = private_key.sign(message);

        let public_key = private_key.public_key();
        assert!(public_key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let private_key = Secp256r1PrivateKey::generate();
        let bytes = private_key.to_bytes();
        let restored = Secp256r1PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(private_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_public_key_from_bytes_roundtrip() {
        let private_key = Secp256r1PrivateKey::generate();
        let public_key = private_key.public_key();
        let bytes = public_key.to_bytes();
        let restored = Secp256r1PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_signature_from_bytes_roundtrip() {
        let private_key = Secp256r1PrivateKey::generate();
        let signature = private_key.sign(b"test");
        let bytes = signature.to_bytes();
        let restored = Secp256r1Signature::from_bytes(&bytes).unwrap();
        assert_eq!(signature.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_hex_roundtrip() {
        let private_key = Secp256r1PrivateKey::generate();
        let hex = private_key.to_hex();
        let restored = Secp256r1PrivateKey::from_hex(&hex).unwrap();
        assert_eq!(private_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_public_key_hex_roundtrip() {
        let private_key = Secp256r1PrivateKey::generate();
        let public_key = private_key.public_key();
        let hex = public_key.to_hex();
        let restored = Secp256r1PublicKey::from_hex(&hex).unwrap();
        assert_eq!(public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_signature_hex_roundtrip() {
        let private_key = Secp256r1PrivateKey::generate();
        let signature = private_key.sign(b"test");
        let hex = signature.to_hex();
        let restored = Secp256r1Signature::from_hex(&hex).unwrap();
        assert_eq!(signature.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_invalid_private_key_bytes() {
        let bytes = vec![0u8; 16]; // Wrong length
        let result = Secp256r1PrivateKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_public_key_bytes() {
        let bytes = vec![0u8; 16]; // Wrong length
        let result = Secp256r1PublicKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_signature_bytes() {
        let bytes = vec![0u8; 16]; // Wrong length
        let result = Secp256r1Signature::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_json_serialization_public_key() {
        let private_key = Secp256r1PrivateKey::generate();
        let public_key = private_key.public_key();
        let json = serde_json::to_string(&public_key).unwrap();
        let restored: Secp256r1PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_json_serialization_signature() {
        let private_key = Secp256r1PrivateKey::generate();
        let signature = private_key.sign(b"test");
        let json = serde_json::to_string(&signature).unwrap();
        let restored: Secp256r1Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(signature.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_key_lengths() {
        assert_eq!(Secp256r1PublicKey::LENGTH, SECP256R1_PUBLIC_KEY_LENGTH);
        assert_eq!(Secp256r1Signature::LENGTH, SECP256R1_SIGNATURE_LENGTH);
    }

    #[test]
    fn test_display_debug() {
        let private_key = Secp256r1PrivateKey::generate();
        let public_key = private_key.public_key();
        let signature = private_key.sign(b"test");

        // Debug should contain type name
        assert!(format!("{:?}", public_key).contains("Secp256r1PublicKey"));
        assert!(format!("{:?}", signature).contains("Secp256r1Signature"));

        // Display should show hex
        assert!(format!("{}", public_key).starts_with("0x"));
        assert!(format!("{}", signature).starts_with("0x"));
    }

    #[test]
    fn test_compressed_public_key_length() {
        let private_key = Secp256r1PrivateKey::generate();
        let public_key = private_key.public_key();
        // Compressed public key should be 33 bytes
        assert_eq!(public_key.to_bytes().len(), 33);
    }

    #[test]
    fn test_private_key_aip80_roundtrip() {
        let private_key = Secp256r1PrivateKey::generate();
        let aip80 = private_key.to_aip80();

        // Should have correct prefix
        assert!(aip80.starts_with("secp256r1-priv-0x"));

        // Should roundtrip correctly
        let restored = Secp256r1PrivateKey::from_aip80(&aip80).unwrap();
        assert_eq!(private_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_private_key_aip80_format() {
        let bytes = [0x01; 32];
        let private_key = Secp256r1PrivateKey::from_bytes(&bytes).unwrap();
        let aip80 = private_key.to_aip80();

        // Expected format: secp256r1-priv-0x0101...01
        let expected = format!("secp256r1-priv-0x{}", "01".repeat(32));
        assert_eq!(aip80, expected);
    }

    #[test]
    fn test_private_key_aip80_invalid_prefix() {
        let result = Secp256r1PrivateKey::from_aip80("ed25519-priv-0x01");
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_aip80_roundtrip() {
        let private_key = Secp256r1PrivateKey::generate();
        let public_key = private_key.public_key();
        let aip80 = public_key.to_aip80();

        // Should have correct prefix
        assert!(aip80.starts_with("secp256r1-pub-0x"));

        // Should roundtrip correctly
        let restored = Secp256r1PublicKey::from_aip80(&aip80).unwrap();
        assert_eq!(public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_public_key_aip80_invalid_prefix() {
        let result = Secp256r1PublicKey::from_aip80("ed25519-pub-0x01");
        assert!(result.is_err());
    }

    #[test]
    fn test_signer_trait() {
        use crate::crypto::traits::Signer;

        let private_key = Secp256r1PrivateKey::generate();
        let message = b"trait test";

        let signature = Signer::sign(&private_key, message);
        let public_key = Signer::public_key(&private_key);

        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verifier_trait() {
        use crate::crypto::traits::Verifier;

        let private_key = Secp256r1PrivateKey::generate();
        let public_key = private_key.public_key();
        let message = b"verifier test";
        let signature = private_key.sign(message);

        assert!(Verifier::verify(&public_key, message, &signature).is_ok());
    }

    #[test]
    fn test_public_key_trait() {
        use crate::crypto::traits::PublicKey;

        let private_key = Secp256r1PrivateKey::generate();
        let public_key = private_key.public_key();
        let bytes = PublicKey::to_bytes(&public_key);
        let restored = Secp256r1PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_signature_trait() {
        use crate::crypto::traits::Signature;

        let private_key = Secp256r1PrivateKey::generate();
        let signature = private_key.sign(b"test");
        let bytes = Signature::to_bytes(&signature);
        let restored = Secp256r1Signature::from_bytes(&bytes).unwrap();
        assert_eq!(signature.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_private_key_debug() {
        let private_key = Secp256r1PrivateKey::generate();
        let debug = format!("{:?}", private_key);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(&private_key.to_hex()));
    }

    #[test]
    fn test_address_derivation() {
        let private_key = Secp256r1PrivateKey::generate();
        let public_key = private_key.public_key();
        let address = public_key.to_address();

        // Address should not be zero
        assert!(!address.is_zero());

        // Same public key should derive same address
        let address2 = public_key.to_address();
        assert_eq!(address, address2);
    }

    #[test]
    fn test_uncompressed_bytes() {
        let private_key = Secp256r1PrivateKey::generate();
        let public_key = private_key.public_key();

        // Uncompressed should be 65 bytes (0x04 prefix + 64 bytes)
        let uncompressed = public_key.to_uncompressed_bytes();
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04); // Uncompressed point prefix
    }

    #[test]
    fn test_private_key_clone() {
        let private_key = Secp256r1PrivateKey::generate();
        let cloned = private_key.clone();
        assert_eq!(private_key.to_bytes(), cloned.to_bytes());
    }

    #[test]
    fn test_public_key_equality() {
        let private_key = Secp256r1PrivateKey::generate();
        let pk1 = private_key.public_key();
        let pk2 = private_key.public_key();
        assert_eq!(pk1, pk2);

        let different = Secp256r1PrivateKey::generate().public_key();
        assert_ne!(pk1, different);
    }

    #[test]
    fn test_signature_verification() {
        let private_key = Secp256r1PrivateKey::generate();
        let sig1 = private_key.sign(b"test");
        let sig2 = private_key.sign(b"test");
        // Note: ECDSA signatures may have randomness, so they might not be equal
        // But they should both verify
        let public_key = private_key.public_key();
        assert!(public_key.verify(b"test", &sig1).is_ok());
        assert!(public_key.verify(b"test", &sig2).is_ok());
    }
}
