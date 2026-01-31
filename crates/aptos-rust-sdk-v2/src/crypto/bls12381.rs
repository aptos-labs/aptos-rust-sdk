//! BLS12-381 signature scheme implementation.
//!
//! BLS signatures support aggregation, which is used for validator
//! consensus signatures on Aptos.

use crate::crypto::traits::{PublicKey, Signature, Signer, Verifier};
use crate::error::{AptosError, AptosResult};
use blst::BLST_ERROR;
use blst::min_pk::{PublicKey as BlstPublicKey, SecretKey, Signature as BlstSignature};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// BLS12-381 private key length in bytes.
pub const BLS12381_PRIVATE_KEY_LENGTH: usize = 32;
/// BLS12-381 public key length in bytes (compressed).
pub const BLS12381_PUBLIC_KEY_LENGTH: usize = 48;
/// BLS12-381 signature length in bytes (compressed).
pub const BLS12381_SIGNATURE_LENGTH: usize = 96;
/// BLS12-381 proof of possession length in bytes.
pub const BLS12381_POP_LENGTH: usize = 96;

/// The domain separation tag for BLS signatures in Aptos.
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// The domain separation tag for BLS proof of possession.
const DST_POP: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// A BLS12-381 private key.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Bls12381PrivateKey {
    #[zeroize(skip)]
    #[allow(unused)] // Field is used; lint false positive from Zeroize derive
    inner: SecretKey,
}

impl Bls12381PrivateKey {
    /// Generates a new random BLS12-381 private key.
    ///
    /// # Panics
    ///
    /// This function will not panic in normal operation. The internal `expect`
    /// is a defensive check for the blst library's key generation, which only
    /// fails if the input keying material (IKM) is less than 32 bytes. Since
    /// we always provide exactly 32 bytes of random data, this cannot fail.
    pub fn generate() -> Self {
        let mut ikm = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ikm);
        // SAFETY: key_gen only fails if IKM is < 32 bytes. We provide exactly 32.
        let secret_key = SecretKey::key_gen(&ikm, &[])
            .expect("internal error: BLS key generation failed with 32-byte IKM");
        Self { inner: secret_key }
    }

    /// Creates a private key from a 32-byte seed.
    ///
    /// This uses the BLS key derivation function to derive a key from the seed.
    ///
    /// # Errors
    ///
    /// Returns an error if the seed is less than 32 bytes or if key derivation fails.
    pub fn from_seed(seed: &[u8]) -> AptosResult<Self> {
        if seed.len() < 32 {
            return Err(AptosError::InvalidPrivateKey(
                "seed must be at least 32 bytes".to_string(),
            ));
        }
        let secret_key = SecretKey::key_gen(seed, &[])
            .map_err(|e| AptosError::InvalidPrivateKey(format!("{e:?}")))?;
        Ok(Self { inner: secret_key })
    }

    /// Creates a private key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes length is not 32 bytes or if the key deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != BLS12381_PRIVATE_KEY_LENGTH {
            return Err(AptosError::InvalidPrivateKey(format!(
                "expected {} bytes, got {}",
                BLS12381_PRIVATE_KEY_LENGTH,
                bytes.len()
            )));
        }
        let secret_key = SecretKey::from_bytes(bytes)
            .map_err(|e| AptosError::InvalidPrivateKey(format!("{e:?}")))?;
        Ok(Self { inner: secret_key })
    }

    /// Creates a private key from a hex string.
    ///
    /// # Errors
    ///
    /// Returns an error if hex decoding fails or if the resulting bytes are invalid.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the private key as bytes.
    pub fn to_bytes(&self) -> [u8; BLS12381_PRIVATE_KEY_LENGTH] {
        self.inner.to_bytes()
    }

    /// Returns the private key as a hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.inner.to_bytes()))
    }

    /// Returns the corresponding public key.
    pub fn public_key(&self) -> Bls12381PublicKey {
        Bls12381PublicKey {
            inner: self.inner.sk_to_pk(),
        }
    }

    /// Signs a message and returns the signature.
    pub fn sign(&self, message: &[u8]) -> Bls12381Signature {
        let signature = self.inner.sign(message, DST, &[]);
        Bls12381Signature { inner: signature }
    }

    /// Creates a proof of possession for this key pair.
    ///
    /// A proof of possession (`PoP`) proves ownership of the private key
    /// and prevents rogue key attacks in aggregate signature schemes.
    pub fn create_proof_of_possession(&self) -> Bls12381ProofOfPossession {
        let pk = self.public_key();
        let pk_bytes = pk.to_bytes();
        let pop = self.inner.sign(&pk_bytes, DST_POP, &[]);
        Bls12381ProofOfPossession { inner: pop }
    }
}

impl Signer for Bls12381PrivateKey {
    type Signature = Bls12381Signature;

    fn sign(&self, message: &[u8]) -> Bls12381Signature {
        Bls12381PrivateKey::sign(self, message)
    }

    fn public_key(&self) -> Bls12381PublicKey {
        Bls12381PrivateKey::public_key(self)
    }
}

impl fmt::Debug for Bls12381PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bls12381PrivateKey([REDACTED])")
    }
}

/// A BLS12-381 public key.
#[derive(Clone, PartialEq, Eq)]
pub struct Bls12381PublicKey {
    inner: BlstPublicKey,
}

impl Bls12381PublicKey {
    /// Creates a public key from compressed bytes (48 bytes).
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes length is not 48 bytes or if the key deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != BLS12381_PUBLIC_KEY_LENGTH {
            return Err(AptosError::InvalidPublicKey(format!(
                "expected {} bytes, got {}",
                BLS12381_PUBLIC_KEY_LENGTH,
                bytes.len()
            )));
        }
        let public_key = BlstPublicKey::from_bytes(bytes)
            .map_err(|e| AptosError::InvalidPublicKey(format!("{e:?}")))?;
        Ok(Self { inner: public_key })
    }

    /// Creates a public key from a hex string.
    ///
    /// # Errors
    ///
    /// Returns an error if hex decoding fails or if the resulting bytes are invalid.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the public key as compressed bytes (48 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.compress().to_vec()
    }

    /// Returns the public key as a hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.inner.compress()))
    }

    /// Verifies a signature against a message.
    ///
    /// # Errors
    ///
    /// Returns an error if signature verification fails.
    pub fn verify(&self, message: &[u8], signature: &Bls12381Signature) -> AptosResult<()> {
        let result = signature
            .inner
            .verify(true, message, DST, &[], &self.inner, true);
        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(AptosError::SignatureVerificationFailed)
        }
    }
}

impl Bls12381PublicKey {
    /// Aggregates multiple public keys into a single aggregated public key.
    ///
    /// The aggregated public key can be used to verify an aggregated signature.
    ///
    /// WARNING: This assumes all public keys have had their proofs-of-possession verified.
    ///
    /// # Errors
    ///
    /// Returns an error if the list of public keys is empty or if aggregation fails.
    pub fn aggregate(public_keys: &[&Bls12381PublicKey]) -> AptosResult<Bls12381PublicKey> {
        if public_keys.is_empty() {
            return Err(AptosError::InvalidPublicKey(
                "cannot aggregate empty list of public keys".to_string(),
            ));
        }
        let blst_pks: Vec<&BlstPublicKey> = public_keys.iter().map(|pk| &pk.inner).collect();
        let agg_pk = blst::min_pk::AggregatePublicKey::aggregate(&blst_pks, false)
            .map_err(|e| AptosError::InvalidPublicKey(format!("{e:?}")))?;
        Ok(Bls12381PublicKey {
            inner: agg_pk.to_public_key(),
        })
    }
}

impl PublicKey for Bls12381PublicKey {
    const LENGTH: usize = BLS12381_PUBLIC_KEY_LENGTH;

    /// Creates a public key from compressed bytes (48 bytes).
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes length is not 48 bytes or if the key deserialization fails.
    fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        Bls12381PublicKey::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Bls12381PublicKey::to_bytes(self)
    }
}

impl Verifier for Bls12381PublicKey {
    type Signature = Bls12381Signature;

    /// Verifies a signature against a message.
    ///
    /// # Errors
    ///
    /// Returns an error if signature verification fails.
    fn verify(&self, message: &[u8], signature: &Bls12381Signature) -> AptosResult<()> {
        Bls12381PublicKey::verify(self, message, signature)
    }
}

impl fmt::Debug for Bls12381PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bls12381PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for Bls12381PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Bls12381PublicKey {
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

impl<'de> Deserialize<'de> for Bls12381PublicKey {
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

/// A BLS12-381 signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Bls12381Signature {
    inner: BlstSignature,
}

impl Bls12381Signature {
    /// Creates a signature from compressed bytes (96 bytes).
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes length is not 96 bytes or if the signature deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != BLS12381_SIGNATURE_LENGTH {
            return Err(AptosError::InvalidSignature(format!(
                "expected {} bytes, got {}",
                BLS12381_SIGNATURE_LENGTH,
                bytes.len()
            )));
        }
        let signature = BlstSignature::from_bytes(bytes)
            .map_err(|e| AptosError::InvalidSignature(format!("{e:?}")))?;
        Ok(Self { inner: signature })
    }

    /// Creates a signature from a hex string.
    ///
    /// # Errors
    ///
    /// Returns an error if hex decoding fails or if the resulting bytes are invalid.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the signature as compressed bytes (96 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.compress().to_vec()
    }

    /// Returns the signature as a hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.inner.compress()))
    }
}

impl Bls12381Signature {
    /// Aggregates multiple signatures into a single aggregated signature.
    ///
    /// The aggregated signature can be verified against an aggregated public key
    /// for the same message, or against individual public keys for different messages.
    ///
    /// # Errors
    ///
    /// Returns an error if the list of signatures is empty or if aggregation fails.
    pub fn aggregate(signatures: &[&Bls12381Signature]) -> AptosResult<Bls12381Signature> {
        if signatures.is_empty() {
            return Err(AptosError::InvalidSignature(
                "cannot aggregate empty list of signatures".to_string(),
            ));
        }
        let blst_sigs: Vec<&BlstSignature> = signatures.iter().map(|s| &s.inner).collect();
        let agg_sig = blst::min_pk::AggregateSignature::aggregate(&blst_sigs, false)
            .map_err(|e| AptosError::InvalidSignature(format!("{e:?}")))?;
        Ok(Bls12381Signature {
            inner: agg_sig.to_signature(),
        })
    }
}

impl Signature for Bls12381Signature {
    type PublicKey = Bls12381PublicKey;
    const LENGTH: usize = BLS12381_SIGNATURE_LENGTH;

    /// Creates a signature from compressed bytes (96 bytes).
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes length is not 96 bytes or if the signature deserialization fails.
    fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        Bls12381Signature::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Bls12381Signature::to_bytes(self)
    }
}

impl fmt::Debug for Bls12381Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bls12381Signature({})", self.to_hex())
    }
}

impl fmt::Display for Bls12381Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Bls12381Signature {
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

impl<'de> Deserialize<'de> for Bls12381Signature {
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

/// A BLS12-381 proof of possession.
///
/// A proof of possession (`PoP`) proves ownership of the private key corresponding
/// to a public key. This prevents rogue key attacks in aggregate signature schemes.
#[derive(Clone, PartialEq, Eq)]
pub struct Bls12381ProofOfPossession {
    inner: BlstSignature,
}

impl Bls12381ProofOfPossession {
    /// Creates a proof of possession from compressed bytes (96 bytes).
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes length is not 96 bytes or if the proof of possession deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != BLS12381_POP_LENGTH {
            return Err(AptosError::InvalidSignature(format!(
                "expected {} bytes, got {}",
                BLS12381_POP_LENGTH,
                bytes.len()
            )));
        }
        let pop = BlstSignature::from_bytes(bytes)
            .map_err(|e| AptosError::InvalidSignature(format!("{e:?}")))?;
        Ok(Self { inner: pop })
    }

    /// Creates a proof of possession from a hex string.
    ///
    /// # Errors
    ///
    /// Returns an error if hex decoding fails or if the resulting bytes are invalid.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the proof of possession as compressed bytes (96 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.compress().to_vec()
    }

    /// Returns the proof of possession as a hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.inner.compress()))
    }

    /// Verifies this proof of possession against a public key.
    ///
    /// Returns Ok(()) if the `PoP` is valid, or an error if invalid.
    ///
    /// # Errors
    ///
    /// Returns an error if proof of possession verification fails.
    pub fn verify(&self, public_key: &Bls12381PublicKey) -> AptosResult<()> {
        let pk_bytes = public_key.to_bytes();
        let result = self
            .inner
            .verify(true, &pk_bytes, DST_POP, &[], &public_key.inner, true);
        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(AptosError::SignatureVerificationFailed)
        }
    }
}

impl fmt::Debug for Bls12381ProofOfPossession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bls12381ProofOfPossession({})", self.to_hex())
    }
}

impl fmt::Display for Bls12381ProofOfPossession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign() {
        let private_key = Bls12381PrivateKey::generate();
        let message = b"hello world";
        let signature = private_key.sign(message);

        let public_key = private_key.public_key();
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        let private_key = Bls12381PrivateKey::generate();
        let message = b"hello world";
        let wrong_message = b"hello world!";
        let signature = private_key.sign(message);

        let public_key = private_key.public_key();
        assert!(public_key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let private_key = Bls12381PrivateKey::generate();
        let bytes = private_key.to_bytes();
        let restored = Bls12381PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(private_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_public_key_from_bytes_roundtrip() {
        let private_key = Bls12381PrivateKey::generate();
        let public_key = private_key.public_key();
        let bytes = public_key.to_bytes();
        let restored = Bls12381PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_signature_from_bytes_roundtrip() {
        let private_key = Bls12381PrivateKey::generate();
        let signature = private_key.sign(b"test");
        let bytes = signature.to_bytes();
        let restored = Bls12381Signature::from_bytes(&bytes).unwrap();
        assert_eq!(signature.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_hex_roundtrip() {
        let private_key = Bls12381PrivateKey::generate();
        let hex = private_key.to_hex();
        let restored = Bls12381PrivateKey::from_hex(&hex).unwrap();
        assert_eq!(private_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_public_key_hex_roundtrip() {
        let private_key = Bls12381PrivateKey::generate();
        let public_key = private_key.public_key();
        let hex = public_key.to_hex();
        let restored = Bls12381PublicKey::from_hex(&hex).unwrap();
        assert_eq!(public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_signature_hex_roundtrip() {
        let private_key = Bls12381PrivateKey::generate();
        let signature = private_key.sign(b"test");
        let hex = signature.to_hex();
        let restored = Bls12381Signature::from_hex(&hex).unwrap();
        assert_eq!(signature.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_public_key_length() {
        assert_eq!(Bls12381PublicKey::LENGTH, BLS12381_PUBLIC_KEY_LENGTH);
    }

    #[test]
    fn test_signature_length() {
        assert_eq!(Bls12381Signature::LENGTH, BLS12381_SIGNATURE_LENGTH);
    }

    #[test]
    fn test_invalid_private_key_bytes() {
        let bytes = vec![0u8; 16]; // Wrong length
        let result = Bls12381PrivateKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_public_key_bytes() {
        let bytes = vec![0u8; 16]; // Wrong length
        let result = Bls12381PublicKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_signature_bytes() {
        let bytes = vec![0u8; 16]; // Wrong length
        let result = Bls12381Signature::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_json_serialization_public_key() {
        let private_key = Bls12381PrivateKey::generate();
        let public_key = private_key.public_key();
        let json = serde_json::to_string(&public_key).unwrap();
        let restored: Bls12381PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_json_serialization_signature() {
        let private_key = Bls12381PrivateKey::generate();
        let signature = private_key.sign(b"test");
        let json = serde_json::to_string(&signature).unwrap();
        let restored: Bls12381Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(signature.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_proof_of_possession() {
        let private_key = Bls12381PrivateKey::generate();
        let public_key = private_key.public_key();
        let pop = private_key.create_proof_of_possession();

        // PoP should verify against the public key
        assert!(pop.verify(&public_key).is_ok());

        // PoP should fail against a different public key
        let other_key = Bls12381PrivateKey::generate().public_key();
        assert!(pop.verify(&other_key).is_err());
    }

    #[test]
    fn test_pop_bytes_roundtrip() {
        let private_key = Bls12381PrivateKey::generate();
        let pop = private_key.create_proof_of_possession();

        let bytes = pop.to_bytes();
        assert_eq!(bytes.len(), BLS12381_POP_LENGTH);

        let restored = Bls12381ProofOfPossession::from_bytes(&bytes).unwrap();
        assert_eq!(pop.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_pop_hex_roundtrip() {
        let private_key = Bls12381PrivateKey::generate();
        let pop = private_key.create_proof_of_possession();

        let hex = pop.to_hex();
        assert!(hex.starts_with("0x"));

        let restored = Bls12381ProofOfPossession::from_hex(&hex).unwrap();
        assert_eq!(pop.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_pop_invalid_bytes_length() {
        let bytes = vec![0u8; 32]; // Wrong length
        let result = Bls12381ProofOfPossession::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_public_keys() {
        let pk1 = Bls12381PrivateKey::generate().public_key();
        let pk2 = Bls12381PrivateKey::generate().public_key();
        let pk3 = Bls12381PrivateKey::generate().public_key();

        let agg = Bls12381PublicKey::aggregate(&[&pk1, &pk2, &pk3]).unwrap();
        assert!(!agg.to_bytes().is_empty());
    }

    #[test]
    fn test_aggregate_public_keys_empty() {
        let result = Bls12381PublicKey::aggregate(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_signatures() {
        let pk1 = Bls12381PrivateKey::generate();
        let pk2 = Bls12381PrivateKey::generate();

        let message = b"aggregate test";
        let sig1 = pk1.sign(message);
        let sig2 = pk2.sign(message);

        let agg_sig = Bls12381Signature::aggregate(&[&sig1, &sig2]).unwrap();
        assert!(!agg_sig.to_bytes().is_empty());
    }

    #[test]
    fn test_aggregate_signatures_empty() {
        let result = Bls12381Signature::aggregate(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_seed() {
        let seed = [42u8; 32];
        let pk1 = Bls12381PrivateKey::from_seed(&seed).unwrap();
        let pk2 = Bls12381PrivateKey::from_seed(&seed).unwrap();

        // Same seed should produce same key
        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn test_from_seed_too_short() {
        let seed = [42u8; 16]; // Too short
        let result = Bls12381PrivateKey::from_seed(&seed);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_debug() {
        let private_key = Bls12381PrivateKey::generate();
        let debug = format!("{:?}", private_key);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(&private_key.to_hex()));
    }

    #[test]
    fn test_public_key_debug() {
        let private_key = Bls12381PrivateKey::generate();
        let public_key = private_key.public_key();
        let debug = format!("{:?}", public_key);
        assert!(debug.contains("Bls12381PublicKey"));
    }

    #[test]
    fn test_public_key_display() {
        let private_key = Bls12381PrivateKey::generate();
        let public_key = private_key.public_key();
        let display = format!("{}", public_key);
        assert!(display.starts_with("0x"));
    }

    #[test]
    fn test_signature_debug() {
        let private_key = Bls12381PrivateKey::generate();
        let signature = private_key.sign(b"test");
        let debug = format!("{:?}", signature);
        assert!(debug.contains("Bls12381Signature"));
    }

    #[test]
    fn test_signature_display() {
        let private_key = Bls12381PrivateKey::generate();
        let signature = private_key.sign(b"test");
        let display = format!("{}", signature);
        assert!(display.starts_with("0x"));
    }

    #[test]
    fn test_pop_debug() {
        let private_key = Bls12381PrivateKey::generate();
        let pop = private_key.create_proof_of_possession();
        let debug = format!("{:?}", pop);
        assert!(debug.contains("Bls12381ProofOfPossession"));
    }

    #[test]
    fn test_pop_display() {
        let private_key = Bls12381PrivateKey::generate();
        let pop = private_key.create_proof_of_possession();
        let display = format!("{}", pop);
        assert!(display.starts_with("0x"));
    }

    #[test]
    fn test_signer_trait() {
        use crate::crypto::traits::Signer;

        let private_key = Bls12381PrivateKey::generate();
        let message = b"trait test";

        let signature = Signer::sign(&private_key, message);
        let public_key = Signer::public_key(&private_key);

        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verifier_trait() {
        use crate::crypto::traits::Verifier;

        let private_key = Bls12381PrivateKey::generate();
        let public_key = private_key.public_key();
        let message = b"verifier test";
        let signature = private_key.sign(message);

        assert!(Verifier::verify(&public_key, message, &signature).is_ok());
    }

    #[test]
    fn test_public_key_trait() {
        use crate::crypto::traits::PublicKey;

        let private_key = Bls12381PrivateKey::generate();
        let public_key = private_key.public_key();
        let bytes = PublicKey::to_bytes(&public_key);
        let restored = Bls12381PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(public_key, restored);
    }

    #[test]
    fn test_signature_trait() {
        use crate::crypto::traits::Signature;

        let private_key = Bls12381PrivateKey::generate();
        let signature = private_key.sign(b"test");
        let bytes = Signature::to_bytes(&signature);
        let restored = Bls12381Signature::from_bytes(&bytes).unwrap();
        assert_eq!(signature, restored);
    }
}
