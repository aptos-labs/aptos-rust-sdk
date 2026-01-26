//! Multi-Ed25519 signature scheme implementation.
//!
//! Multi-Ed25519 enables M-of-N threshold signatures where M signatures
//! out of N public keys are required to authorize a transaction.

use crate::crypto::ed25519::{
    ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH, Ed25519PublicKey, Ed25519Signature,
};
use crate::crypto::traits::{PublicKey, Verifier};
use crate::error::{AptosError, AptosResult};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum number of keys in a multi-Ed25519 account.
pub const MAX_NUM_OF_KEYS: usize = 32;

/// Minimum threshold (at least 1 signature required).
pub const MIN_THRESHOLD: u8 = 1;

/// A multi-Ed25519 public key.
///
/// This is a collection of Ed25519 public keys with a threshold value.
/// M-of-N signatures are required where M = threshold and N = number of keys.
///
/// # Example
///
/// ```rust,ignore
/// use aptos_rust_sdk_v2::crypto::{Ed25519PrivateKey, MultiEd25519PublicKey};
///
/// let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate().public_key()).collect();
/// let multi_pk = MultiEd25519PublicKey::new(keys, 2).unwrap(); // 2-of-3
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct MultiEd25519PublicKey {
    /// The individual public keys.
    public_keys: Vec<Ed25519PublicKey>,
    /// The required threshold (M in M-of-N).
    threshold: u8,
}

impl MultiEd25519PublicKey {
    /// Creates a new multi-Ed25519 public key.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - The individual Ed25519 public keys
    /// * `threshold` - The number of signatures required (M in M-of-N)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No public keys are provided
    /// - More than 32 public keys are provided
    /// - Threshold is 0
    /// - Threshold exceeds the number of keys
    pub fn new(public_keys: Vec<Ed25519PublicKey>, threshold: u8) -> AptosResult<Self> {
        if public_keys.is_empty() {
            return Err(AptosError::InvalidPublicKey(
                "multi-Ed25519 requires at least one public key".into(),
            ));
        }
        if public_keys.len() > MAX_NUM_OF_KEYS {
            return Err(AptosError::InvalidPublicKey(format!(
                "multi-Ed25519 supports at most {} keys, got {}",
                MAX_NUM_OF_KEYS,
                public_keys.len()
            )));
        }
        if threshold < MIN_THRESHOLD {
            return Err(AptosError::InvalidPublicKey(
                "threshold must be at least 1".into(),
            ));
        }
        if threshold as usize > public_keys.len() {
            return Err(AptosError::InvalidPublicKey(format!(
                "threshold {} exceeds number of keys {}",
                threshold,
                public_keys.len()
            )));
        }
        Ok(Self {
            public_keys,
            threshold,
        })
    }

    /// Returns the number of public keys.
    pub fn num_keys(&self) -> usize {
        self.public_keys.len()
    }

    /// Returns the threshold (M in M-of-N).
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Returns the individual public keys.
    pub fn public_keys(&self) -> &[Ed25519PublicKey] {
        &self.public_keys
    }

    /// Serializes the public key to bytes.
    ///
    /// Format: public_key_1 || public_key_2 || ... || public_key_n || threshold
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.public_keys.len() * ED25519_PUBLIC_KEY_LENGTH + 1);
        for pk in &self.public_keys {
            bytes.extend_from_slice(&pk.to_bytes());
        }
        bytes.push(self.threshold);
        bytes
    }

    /// Creates a public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.is_empty() {
            return Err(AptosError::InvalidPublicKey("empty bytes".into()));
        }
        if bytes.len() < ED25519_PUBLIC_KEY_LENGTH + 1 {
            return Err(AptosError::InvalidPublicKey(format!(
                "bytes too short: {} bytes",
                bytes.len()
            )));
        }

        let threshold = bytes[bytes.len() - 1];
        let key_bytes = &bytes[..bytes.len() - 1];

        if !key_bytes.len().is_multiple_of(ED25519_PUBLIC_KEY_LENGTH) {
            return Err(AptosError::InvalidPublicKey(format!(
                "key bytes length {} is not a multiple of {}",
                key_bytes.len(),
                ED25519_PUBLIC_KEY_LENGTH
            )));
        }

        let num_keys = key_bytes.len() / ED25519_PUBLIC_KEY_LENGTH;
        let mut public_keys = Vec::with_capacity(num_keys);

        for i in 0..num_keys {
            let start = i * ED25519_PUBLIC_KEY_LENGTH;
            let end = start + ED25519_PUBLIC_KEY_LENGTH;
            let pk = Ed25519PublicKey::from_bytes(&key_bytes[start..end])?;
            public_keys.push(pk);
        }

        Self::new(public_keys, threshold)
    }

    /// Derives the account address for this multi-Ed25519 public key.
    pub fn to_address(&self) -> crate::types::AccountAddress {
        crate::crypto::derive_address(&self.to_bytes(), crate::crypto::MULTI_ED25519_SCHEME)
    }

    /// Derives the authentication key for this public key.
    pub fn to_authentication_key(&self) -> [u8; 32] {
        crate::crypto::derive_authentication_key(
            &self.to_bytes(),
            crate::crypto::MULTI_ED25519_SCHEME,
        )
    }

    /// Verifies a multi-Ed25519 signature against a message.
    pub fn verify(&self, message: &[u8], signature: &MultiEd25519Signature) -> AptosResult<()> {
        // Check that we have enough signatures
        if signature.num_signatures() < self.threshold as usize {
            return Err(AptosError::SignatureVerificationFailed);
        }

        // Verify each signature
        for (index, sig) in signature.signatures() {
            if *index as usize >= self.public_keys.len() {
                return Err(AptosError::InvalidSignature(format!(
                    "signer index {} out of bounds (max {})",
                    index,
                    self.public_keys.len() - 1
                )));
            }
            let pk = &self.public_keys[*index as usize];
            pk.verify(message, sig)?;
        }

        Ok(())
    }
}

impl PublicKey for MultiEd25519PublicKey {
    const LENGTH: usize = 0; // Variable length

    fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        MultiEd25519PublicKey::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        MultiEd25519PublicKey::to_bytes(self)
    }
}

impl Verifier for MultiEd25519PublicKey {
    type Signature = MultiEd25519Signature;

    fn verify(&self, message: &[u8], signature: &MultiEd25519Signature) -> AptosResult<()> {
        MultiEd25519PublicKey::verify(self, message, signature)
    }
}

impl fmt::Debug for MultiEd25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MultiEd25519PublicKey({}-of-{} keys)",
            self.threshold,
            self.public_keys.len()
        )
    }
}

impl fmt::Display for MultiEd25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.to_bytes()))
    }
}

impl Serialize for MultiEd25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&format!("0x{}", hex::encode(self.to_bytes())))
        } else {
            serializer.serialize_bytes(&self.to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for MultiEd25519PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let s = s.strip_prefix("0x").unwrap_or(&s);
            let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

/// A multi-Ed25519 signature.
///
/// This contains individual Ed25519 signatures along with a bitmap indicating
/// which signers provided signatures.
#[derive(Clone, PartialEq, Eq)]
pub struct MultiEd25519Signature {
    /// Individual signatures with their signer index.
    signatures: Vec<(u8, Ed25519Signature)>,
    /// Bitmap indicating which keys signed (little-endian).
    bitmap: [u8; 4],
}

impl MultiEd25519Signature {
    /// Creates a new multi-Ed25519 signature from individual signatures.
    ///
    /// # Arguments
    ///
    /// * `signatures` - Vec of (signer_index, signature) pairs
    ///
    /// The signer indices must be in ascending order and within bounds.
    pub fn new(mut signatures: Vec<(u8, Ed25519Signature)>) -> AptosResult<Self> {
        if signatures.is_empty() {
            return Err(AptosError::InvalidSignature(
                "multi-Ed25519 signature requires at least one signature".into(),
            ));
        }
        if signatures.len() > MAX_NUM_OF_KEYS {
            return Err(AptosError::InvalidSignature(format!(
                "too many signatures: {} (max {})",
                signatures.len(),
                MAX_NUM_OF_KEYS
            )));
        }

        // Sort by index
        signatures.sort_by_key(|(idx, _)| *idx);

        // Check for duplicates and bounds
        let mut bitmap = [0u8; 4];
        let mut last_index: Option<u8> = None;

        for (index, _) in &signatures {
            if *index as usize >= MAX_NUM_OF_KEYS {
                return Err(AptosError::InvalidSignature(format!(
                    "signer index {} out of bounds (max {})",
                    index,
                    MAX_NUM_OF_KEYS - 1
                )));
            }
            if last_index == Some(*index) {
                return Err(AptosError::InvalidSignature(format!(
                    "duplicate signer index {}",
                    index
                )));
            }
            last_index = Some(*index);

            // Set bit in bitmap
            let byte_index = (index / 8) as usize;
            let bit_index = index % 8;
            bitmap[byte_index] |= 1 << bit_index;
        }

        Ok(Self { signatures, bitmap })
    }

    /// Creates a signature from bytes.
    ///
    /// Format: signature_1 || signature_2 || ... || signature_m || bitmap (4 bytes)
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() < 4 {
            return Err(AptosError::InvalidSignature("bytes too short".into()));
        }

        let bitmap_start = bytes.len() - 4;
        let mut bitmap = [0u8; 4];
        bitmap.copy_from_slice(&bytes[bitmap_start..]);

        let sig_bytes = &bytes[..bitmap_start];

        // Count signatures from bitmap
        let num_sigs = bitmap.iter().map(|b| b.count_ones()).sum::<u32>() as usize;

        if sig_bytes.len() != num_sigs * ED25519_SIGNATURE_LENGTH {
            return Err(AptosError::InvalidSignature(format!(
                "signature bytes length {} doesn't match expected {} signatures",
                sig_bytes.len(),
                num_sigs
            )));
        }

        // Parse signatures
        let mut signatures = Vec::with_capacity(num_sigs);
        let mut sig_idx = 0;

        for bit_pos in 0..(MAX_NUM_OF_KEYS as u8) {
            let byte_idx = (bit_pos / 8) as usize;
            let bit_idx = bit_pos % 8;

            if (bitmap[byte_idx] >> bit_idx) & 1 == 1 {
                let start = sig_idx * ED25519_SIGNATURE_LENGTH;
                let end = start + ED25519_SIGNATURE_LENGTH;
                let sig = Ed25519Signature::from_bytes(&sig_bytes[start..end])?;
                signatures.push((bit_pos, sig));
                sig_idx += 1;
            }
        }

        Ok(Self { signatures, bitmap })
    }

    /// Serializes the signature to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.signatures.len() * ED25519_SIGNATURE_LENGTH + 4);
        for (_, sig) in &self.signatures {
            bytes.extend_from_slice(&sig.to_bytes());
        }
        bytes.extend_from_slice(&self.bitmap);
        bytes
    }

    /// Returns the number of signatures.
    pub fn num_signatures(&self) -> usize {
        self.signatures.len()
    }

    /// Returns the individual signatures with their indices.
    pub fn signatures(&self) -> &[(u8, Ed25519Signature)] {
        &self.signatures
    }

    /// Returns the signer bitmap.
    pub fn bitmap(&self) -> &[u8; 4] {
        &self.bitmap
    }

    /// Checks if a particular index signed.
    pub fn has_signature(&self, index: u8) -> bool {
        if index as usize >= MAX_NUM_OF_KEYS {
            return false;
        }
        let byte_index = (index / 8) as usize;
        let bit_index = index % 8;
        (self.bitmap[byte_index] >> bit_index) & 1 == 1
    }
}

impl crate::crypto::traits::Signature for MultiEd25519Signature {
    type PublicKey = MultiEd25519PublicKey;
    const LENGTH: usize = 0; // Variable length

    fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        MultiEd25519Signature::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        MultiEd25519Signature::to_bytes(self)
    }
}

impl fmt::Debug for MultiEd25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MultiEd25519Signature({} signatures, bitmap={:?})",
            self.signatures.len(),
            self.bitmap
        )
    }
}

impl fmt::Display for MultiEd25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.to_bytes()))
    }
}

impl Serialize for MultiEd25519Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&format!("0x{}", hex::encode(self.to_bytes())))
        } else {
            serializer.serialize_bytes(&self.to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for MultiEd25519Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let s = s.strip_prefix("0x").unwrap_or(&s);
            let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Ed25519PrivateKey;

    #[test]
    fn test_multi_ed25519_public_key_creation() {
        let keys: Vec<_> = (0..3)
            .map(|_| Ed25519PrivateKey::generate().public_key())
            .collect();

        // Valid 2-of-3
        let multi_pk = MultiEd25519PublicKey::new(keys.clone(), 2).unwrap();
        assert_eq!(multi_pk.num_keys(), 3);
        assert_eq!(multi_pk.threshold(), 2);

        // Valid 3-of-3
        let multi_pk = MultiEd25519PublicKey::new(keys.clone(), 3).unwrap();
        assert_eq!(multi_pk.threshold(), 3);

        // Invalid: threshold > num_keys
        assert!(MultiEd25519PublicKey::new(keys.clone(), 4).is_err());

        // Invalid: threshold = 0
        assert!(MultiEd25519PublicKey::new(keys.clone(), 0).is_err());

        // Invalid: empty keys
        assert!(MultiEd25519PublicKey::new(vec![], 1).is_err());
    }

    #[test]
    fn test_multi_ed25519_sign_verify() {
        let private_keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = private_keys.iter().map(|k| k.public_key()).collect();

        let multi_pk = MultiEd25519PublicKey::new(public_keys, 2).unwrap();
        let message = b"test message";

        // Sign with keys 0 and 2 (2-of-3)
        let sig0 = private_keys[0].sign(message);
        let sig2 = private_keys[2].sign(message);

        let multi_sig = MultiEd25519Signature::new(vec![(0, sig0), (2, sig2)]).unwrap();

        // Verify should succeed
        assert!(multi_pk.verify(message, &multi_sig).is_ok());

        // Wrong message should fail
        assert!(multi_pk.verify(b"wrong message", &multi_sig).is_err());
    }

    #[test]
    fn test_multi_ed25519_insufficient_signatures() {
        let private_keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = private_keys.iter().map(|k| k.public_key()).collect();

        let multi_pk = MultiEd25519PublicKey::new(public_keys, 2).unwrap();
        let message = b"test message";

        // Only 1 signature (need 2)
        let sig0 = private_keys[0].sign(message);
        let multi_sig = MultiEd25519Signature::new(vec![(0, sig0)]).unwrap();

        // Should fail due to insufficient signatures
        assert!(multi_pk.verify(message, &multi_sig).is_err());
    }

    #[test]
    fn test_multi_ed25519_bytes_roundtrip() {
        let keys: Vec<_> = (0..3)
            .map(|_| Ed25519PrivateKey::generate().public_key())
            .collect();
        let multi_pk = MultiEd25519PublicKey::new(keys, 2).unwrap();

        let bytes = multi_pk.to_bytes();
        let restored = MultiEd25519PublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(multi_pk.threshold(), restored.threshold());
        assert_eq!(multi_pk.num_keys(), restored.num_keys());
        assert_eq!(multi_pk.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_multi_ed25519_signature_bytes_roundtrip() {
        let private_keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let message = b"test";

        let sig0 = private_keys[0].sign(message);
        let sig2 = private_keys[2].sign(message);

        let multi_sig = MultiEd25519Signature::new(vec![(0, sig0), (2, sig2)]).unwrap();

        let bytes = multi_sig.to_bytes();
        let restored = MultiEd25519Signature::from_bytes(&bytes).unwrap();

        assert_eq!(multi_sig.num_signatures(), restored.num_signatures());
        assert_eq!(multi_sig.bitmap(), restored.bitmap());
    }

    #[test]
    fn test_multi_ed25519_address_derivation() {
        let keys: Vec<_> = (0..3)
            .map(|_| Ed25519PrivateKey::generate().public_key())
            .collect();
        let multi_pk = MultiEd25519PublicKey::new(keys, 2).unwrap();

        let address = multi_pk.to_address();
        assert!(!address.is_zero());

        // Same keys should produce same address
        let address2 = multi_pk.to_address();
        assert_eq!(address, address2);
    }

    #[test]
    fn test_signature_bitmap() {
        let private_keys: Vec<_> = (0..5).map(|_| Ed25519PrivateKey::generate()).collect();
        let message = b"test";

        // Sign with indices 1, 3, 4
        let signatures: Vec<_> = [1, 3, 4]
            .iter()
            .map(|&i| (i, private_keys[i as usize].sign(message)))
            .collect();

        let multi_sig = MultiEd25519Signature::new(signatures).unwrap();

        assert!(!multi_sig.has_signature(0));
        assert!(multi_sig.has_signature(1));
        assert!(!multi_sig.has_signature(2));
        assert!(multi_sig.has_signature(3));
        assert!(multi_sig.has_signature(4));
        assert!(!multi_sig.has_signature(5));
    }
}
