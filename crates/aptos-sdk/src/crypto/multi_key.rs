//! `MultiKey` signature scheme implementation.
//!
//! `MultiKey` enables M-of-N threshold signatures with mixed key types.
//! Unlike `MultiEd25519`, each key can be a different signature scheme
//! (Ed25519, Secp256k1, Secp256r1, etc.).

use crate::error::{AptosError, AptosResult};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum number of keys in a multi-key account.
pub const MAX_NUM_OF_KEYS: usize = 32;

// Compile-time assertion: MAX_NUM_OF_KEYS must fit in u8 for bitmap operations
const _: () = assert!(MAX_NUM_OF_KEYS <= u8::MAX as usize);

/// Minimum threshold (at least 1 signature required).
pub const MIN_THRESHOLD: u8 = 1;

/// Supported signature schemes for multi-key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AnyPublicKeyVariant {
    /// Ed25519 public key.
    Ed25519 = 0,
    /// Secp256k1 ECDSA public key.
    Secp256k1 = 1,
    /// Secp256r1 (P-256) ECDSA public key.
    Secp256r1 = 2,
    /// Keyless public key.
    Keyless = 3,
}

impl AnyPublicKeyVariant {
    /// Get the variant from a byte.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::InvalidPublicKey`] if the byte value is not a valid variant (0-3).
    pub fn from_byte(byte: u8) -> AptosResult<Self> {
        match byte {
            0 => Ok(Self::Ed25519),
            1 => Ok(Self::Secp256k1),
            2 => Ok(Self::Secp256r1),
            3 => Ok(Self::Keyless),
            _ => Err(AptosError::InvalidPublicKey(format!(
                "unknown public key variant: {byte}"
            ))),
        }
    }

    /// Get the byte representation.
    pub fn as_byte(&self) -> u8 {
        *self as u8
    }
}

/// A public key that can be any supported signature scheme.
#[derive(Clone, PartialEq, Eq)]
pub struct AnyPublicKey {
    /// The signature scheme variant.
    pub variant: AnyPublicKeyVariant,
    /// The raw public key bytes.
    pub bytes: Vec<u8>,
}

impl AnyPublicKey {
    /// Creates a new `AnyPublicKey`.
    pub fn new(variant: AnyPublicKeyVariant, bytes: Vec<u8>) -> Self {
        Self { variant, bytes }
    }

    /// Creates an Ed25519 public key.
    #[cfg(feature = "ed25519")]
    pub fn ed25519(public_key: &crate::crypto::Ed25519PublicKey) -> Self {
        Self {
            variant: AnyPublicKeyVariant::Ed25519,
            bytes: public_key.to_bytes().to_vec(),
        }
    }

    /// Creates a Secp256k1 public key.
    /// Uses uncompressed format (65 bytes) as required by the Aptos protocol.
    #[cfg(feature = "secp256k1")]
    pub fn secp256k1(public_key: &crate::crypto::Secp256k1PublicKey) -> Self {
        Self {
            variant: AnyPublicKeyVariant::Secp256k1,
            bytes: public_key.to_uncompressed_bytes(),
        }
    }

    /// Creates a Secp256r1 public key.
    /// Uses uncompressed format (65 bytes) as required by the Aptos protocol.
    #[cfg(feature = "secp256r1")]
    pub fn secp256r1(public_key: &crate::crypto::Secp256r1PublicKey) -> Self {
        Self {
            variant: AnyPublicKeyVariant::Secp256r1,
            bytes: public_key.to_uncompressed_bytes(),
        }
    }

    /// Serializes to BCS format: `variant_byte` || ULEB128(length) || bytes
    ///
    /// This is the correct BCS serialization format for `AnyPublicKey` used
    /// in authentication key derivation: `SHA3-256(BCS(AnyPublicKey) || scheme_id)`
    pub fn to_bcs_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + 1 + self.bytes.len());
        result.push(self.variant.as_byte());
        // BCS uses ULEB128 for vector lengths
        result.extend(uleb128_encode(self.bytes.len()));
        result.extend_from_slice(&self.bytes);
        result
    }

    /// Verifies a signature against a message.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The signature variant doesn't match the public key variant
    /// - The public key bytes are invalid for the variant
    /// - The signature bytes are invalid for the variant
    /// - Signature verification fails
    /// - Verification is not supported for the variant
    #[allow(unused_variables)]
    pub fn verify(&self, message: &[u8], signature: &AnySignature) -> AptosResult<()> {
        if signature.variant != self.variant {
            return Err(AptosError::InvalidSignature(format!(
                "signature variant {:?} doesn't match public key variant {:?}",
                signature.variant, self.variant
            )));
        }

        match self.variant {
            #[cfg(feature = "ed25519")]
            AnyPublicKeyVariant::Ed25519 => {
                let pk = crate::crypto::Ed25519PublicKey::from_bytes(&self.bytes)?;
                let sig = crate::crypto::Ed25519Signature::from_bytes(&signature.bytes)?;
                pk.verify(message, &sig)
            }
            #[cfg(feature = "secp256k1")]
            AnyPublicKeyVariant::Secp256k1 => {
                // Public key can be either compressed (33 bytes) or uncompressed (65 bytes)
                let pk = crate::crypto::Secp256k1PublicKey::from_bytes(&self.bytes)?;
                let sig = crate::crypto::Secp256k1Signature::from_bytes(&signature.bytes)?;
                pk.verify(message, &sig)
            }
            #[cfg(feature = "secp256r1")]
            AnyPublicKeyVariant::Secp256r1 => {
                // Public key can be either compressed (33 bytes) or uncompressed (65 bytes)
                let pk = crate::crypto::Secp256r1PublicKey::from_bytes(&self.bytes)?;
                let sig = crate::crypto::Secp256r1Signature::from_bytes(&signature.bytes)?;
                pk.verify(message, &sig)
            }
            #[allow(unreachable_patterns)]
            _ => Err(AptosError::InvalidPublicKey(format!(
                "verification not supported for variant {:?}",
                self.variant
            ))),
        }
    }
}

impl fmt::Debug for AnyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AnyPublicKey({:?}, {})",
            self.variant,
            const_hex::encode_prefixed(&self.bytes)
        )
    }
}

impl fmt::Display for AnyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}:{}",
            self.variant,
            const_hex::encode_prefixed(&self.bytes)
        )
    }
}

/// A signature that can be any supported signature scheme.
#[derive(Clone, PartialEq, Eq)]
pub struct AnySignature {
    /// The signature scheme variant.
    pub variant: AnyPublicKeyVariant,
    /// The raw signature bytes.
    pub bytes: Vec<u8>,
}

impl AnySignature {
    /// Creates a new `AnySignature`.
    pub fn new(variant: AnyPublicKeyVariant, bytes: Vec<u8>) -> Self {
        Self { variant, bytes }
    }

    /// Creates an Ed25519 signature.
    #[cfg(feature = "ed25519")]
    pub fn ed25519(signature: &crate::crypto::Ed25519Signature) -> Self {
        Self {
            variant: AnyPublicKeyVariant::Ed25519,
            bytes: signature.to_bytes().to_vec(),
        }
    }

    /// Creates a Secp256k1 signature.
    #[cfg(feature = "secp256k1")]
    pub fn secp256k1(signature: &crate::crypto::Secp256k1Signature) -> Self {
        Self {
            variant: AnyPublicKeyVariant::Secp256k1,
            bytes: signature.to_bytes().to_vec(),
        }
    }

    /// Creates a Secp256r1 signature.
    #[cfg(feature = "secp256r1")]
    pub fn secp256r1(signature: &crate::crypto::Secp256r1Signature) -> Self {
        Self {
            variant: AnyPublicKeyVariant::Secp256r1,
            bytes: signature.to_bytes().to_vec(),
        }
    }

    /// Serializes to BCS format: `variant_byte` || ULEB128(length) || bytes
    pub fn to_bcs_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + 1 + self.bytes.len());
        result.push(self.variant.as_byte());
        // BCS uses ULEB128 for vector lengths
        result.extend(uleb128_encode(self.bytes.len()));
        result.extend_from_slice(&self.bytes);
        result
    }
}

/// Encodes a value as `ULEB128` (unsigned `LEB128`).
/// BCS uses `ULEB128` for encoding vector/sequence lengths.
/// For typical sizes (< 128), this returns a single byte.
#[allow(clippy::cast_possible_truncation)] // value & 0x7F is always <= 127
#[inline]
fn uleb128_encode(mut value: usize) -> Vec<u8> {
    // Pre-allocate for common case: values < 128 need 1 byte, < 16384 need 2 bytes
    let mut result = Vec::with_capacity(if value < 128 { 1 } else { 2 });
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            result.push(byte);
            break;
        }
        result.push(byte | 0x80);
    }
    result
}

/// Decodes a `ULEB128` value from bytes, returning `(value, bytes_consumed)`.
fn uleb128_decode(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut result: usize = 0;
    let mut shift = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None; // Overflow
        }
    }
    None
}

impl fmt::Debug for AnySignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AnySignature({:?}, {} bytes)",
            self.variant,
            self.bytes.len()
        )
    }
}

/// A multi-key public key supporting mixed signature schemes.
///
/// This allows M-of-N threshold signing where each key can be a different type.
#[derive(Clone, PartialEq, Eq)]
pub struct MultiKeyPublicKey {
    /// The individual public keys.
    public_keys: Vec<AnyPublicKey>,
    /// The required threshold (M in M-of-N).
    threshold: u8,
}

impl MultiKeyPublicKey {
    /// Creates a new multi-key public key.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - The individual public keys (can be mixed types)
    /// * `threshold` - The number of signatures required (M in M-of-N)
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::InvalidPublicKey`] if:
    /// - No public keys are provided
    /// - More than 32 public keys are provided
    /// - Threshold is 0
    /// - Threshold exceeds the number of keys
    pub fn new(public_keys: Vec<AnyPublicKey>, threshold: u8) -> AptosResult<Self> {
        if public_keys.is_empty() {
            return Err(AptosError::InvalidPublicKey(
                "multi-key requires at least one public key".into(),
            ));
        }
        if public_keys.len() > MAX_NUM_OF_KEYS {
            return Err(AptosError::InvalidPublicKey(format!(
                "multi-key supports at most {} keys, got {}",
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

    /// Returns the threshold.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Returns the individual public keys.
    pub fn public_keys(&self) -> &[AnyPublicKey] {
        &self.public_keys
    }

    /// Returns the key at the given index.
    pub fn get(&self, index: usize) -> Option<&AnyPublicKey> {
        self.public_keys.get(index)
    }

    /// Serializes to bytes for authentication key derivation.
    ///
    /// Format: `num_keys` || `pk1_bcs` || `pk2_bcs` || ... || threshold
    #[allow(clippy::cast_possible_truncation)] // public_keys.len() <= MAX_NUM_OF_KEYS (32)
    pub fn to_bytes(&self) -> Vec<u8> {
        // Pre-allocate: 1 byte num_keys + estimated key size (avg ~35 bytes per key) + 1 byte threshold
        let estimated_size = 2 + self.public_keys.len() * 36;
        let mut bytes = Vec::with_capacity(estimated_size);

        // Number of keys (1 byte, validated in new())
        bytes.push(self.public_keys.len() as u8);

        // Each public key in BCS format
        for pk in &self.public_keys {
            bytes.extend(pk.to_bcs_bytes());
        }

        // Threshold (1 byte)
        bytes.push(self.threshold);

        bytes
    }

    /// Creates from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::InvalidPublicKey`] if:
    /// - The bytes are empty
    /// - The number of keys is invalid (0 or > 32)
    /// - The bytes are too short for the expected structure
    /// - Any public key variant byte is invalid
    /// - Any public key length or data is invalid
    /// - The threshold is invalid
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        // SECURITY: Limit individual key size to prevent DoS via large allocations
        // Largest supported key is uncompressed secp256k1/secp256r1 at 65 bytes
        const MAX_KEY_SIZE: usize = 128;

        if bytes.is_empty() {
            return Err(AptosError::InvalidPublicKey("empty bytes".into()));
        }

        let num_keys = bytes[0] as usize;
        if num_keys == 0 || num_keys > MAX_NUM_OF_KEYS {
            return Err(AptosError::InvalidPublicKey(format!(
                "invalid number of keys: {num_keys}"
            )));
        }

        let mut offset = 1;
        let mut public_keys = Vec::with_capacity(num_keys);

        for _ in 0..num_keys {
            if offset >= bytes.len() {
                return Err(AptosError::InvalidPublicKey("bytes too short".into()));
            }

            let variant = AnyPublicKeyVariant::from_byte(bytes[offset])?;
            offset += 1;

            // Decode ULEB128 length
            let (len, len_bytes) = uleb128_decode(&bytes[offset..]).ok_or_else(|| {
                AptosError::InvalidPublicKey("invalid ULEB128 length encoding".into())
            })?;
            offset += len_bytes;

            if len > MAX_KEY_SIZE {
                return Err(AptosError::InvalidPublicKey(format!(
                    "key size {len} exceeds maximum {MAX_KEY_SIZE}"
                )));
            }

            if offset + len > bytes.len() {
                return Err(AptosError::InvalidPublicKey(
                    "bytes too short for key".into(),
                ));
            }

            let key_bytes = bytes[offset..offset + len].to_vec();
            offset += len;

            public_keys.push(AnyPublicKey::new(variant, key_bytes));
        }

        if offset >= bytes.len() {
            return Err(AptosError::InvalidPublicKey(
                "bytes too short for threshold".into(),
            ));
        }

        let threshold = bytes[offset];

        Self::new(public_keys, threshold)
    }

    /// Derives the account address for this multi-key public key.
    pub fn to_address(&self) -> crate::types::AccountAddress {
        crate::crypto::derive_address(&self.to_bytes(), crate::crypto::MULTI_KEY_SCHEME)
    }

    /// Derives the authentication key for this public key.
    pub fn to_authentication_key(&self) -> [u8; 32] {
        crate::crypto::derive_authentication_key(&self.to_bytes(), crate::crypto::MULTI_KEY_SCHEME)
    }

    /// Verifies a multi-key signature against a message.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The number of signatures is less than the threshold
    /// - Any individual signature verification fails
    /// - A signer index is out of bounds
    pub fn verify(&self, message: &[u8], signature: &MultiKeySignature) -> AptosResult<()> {
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

impl fmt::Debug for MultiKeyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MultiKeyPublicKey({}-of-{} keys)",
            self.threshold,
            self.public_keys.len()
        )
    }
}

impl fmt::Display for MultiKeyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&const_hex::encode_prefixed(self.to_bytes()))
    }
}

/// A multi-key signature containing signatures from multiple signers.
#[derive(Clone, PartialEq, Eq)]
pub struct MultiKeySignature {
    /// Individual signatures with their signer index.
    signatures: Vec<(u8, AnySignature)>,
    /// Bitmap indicating which keys signed (little-endian, up to 4 bytes for 32 keys).
    bitmap: [u8; 4],
}

impl MultiKeySignature {
    /// Creates a new multi-key signature from individual signatures.
    ///
    /// # Arguments
    ///
    /// * `signatures` - Vec of (`signer_index`, signature) pairs
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::InvalidSignature`] if:
    /// - No signatures are provided
    /// - More than 32 signatures are provided
    /// - A signer index is out of bounds (>= 32)
    /// - Duplicate signer indices are present
    pub fn new(mut signatures: Vec<(u8, AnySignature)>) -> AptosResult<Self> {
        if signatures.is_empty() {
            return Err(AptosError::InvalidSignature(
                "multi-key signature requires at least one signature".into(),
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

        // Check for duplicates and bounds, build bitmap
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
                    "duplicate signer index {index}"
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

    /// Returns the number of signatures.
    pub fn num_signatures(&self) -> usize {
        self.signatures.len()
    }

    /// Returns the individual signatures with their indices.
    pub fn signatures(&self) -> &[(u8, AnySignature)] {
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

    /// Serializes to bytes.
    ///
    /// Format: `num_signatures` || `sig1_bcs` || `sig2_bcs` || ... || bitmap (4 bytes)
    #[allow(clippy::cast_possible_truncation)] // signatures.len() <= MAX_NUM_OF_KEYS (32)
    pub fn to_bytes(&self) -> Vec<u8> {
        // Pre-allocate: 1 byte num_sigs + estimated sig size (avg ~66 bytes per sig) + 4 bytes bitmap
        let estimated_size = 5 + self.signatures.len() * 68;
        let mut bytes = Vec::with_capacity(estimated_size);

        // Number of signatures (validated in new())
        bytes.push(self.signatures.len() as u8);

        // Each signature in BCS format (ordered by index)
        for (_, sig) in &self.signatures {
            bytes.extend(sig.to_bcs_bytes());
        }

        // Bitmap (4 bytes)
        bytes.extend_from_slice(&self.bitmap);

        bytes
    }

    /// Creates from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::InvalidSignature`] if:
    /// - The bytes are too short (less than 5 bytes for `num_sigs` + bitmap)
    /// - The number of signatures is invalid (0 or > 32)
    /// - The bitmap doesn't match the number of signatures
    /// - The bytes are too short for the expected structure
    /// - Any signature variant byte is invalid
    /// - Any signature length or data is invalid
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        // SECURITY: Limit individual signature size to prevent DoS via large allocations
        // Largest supported signature is ~72 bytes for ECDSA DER format
        const MAX_SIGNATURE_SIZE: usize = 128;

        if bytes.len() < 5 {
            return Err(AptosError::InvalidSignature("bytes too short".into()));
        }

        let num_sigs = bytes[0] as usize;
        if num_sigs == 0 || num_sigs > MAX_NUM_OF_KEYS {
            return Err(AptosError::InvalidSignature(format!(
                "invalid number of signatures: {num_sigs}"
            )));
        }

        // Read bitmap from the end
        let bitmap_start = bytes.len() - 4;
        let mut bitmap = [0u8; 4];
        bitmap.copy_from_slice(&bytes[bitmap_start..]);

        // Parse signatures
        let mut offset = 1;
        let mut signatures = Vec::with_capacity(num_sigs);

        // Determine signer indices from bitmap (MAX_NUM_OF_KEYS is 32, fits in u8)
        let mut signer_indices = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        for bit_pos in 0..(MAX_NUM_OF_KEYS as u8) {
            let byte_idx = (bit_pos / 8) as usize;
            let bit_idx = bit_pos % 8;
            if (bitmap[byte_idx] >> bit_idx) & 1 == 1 {
                signer_indices.push(bit_pos);
            }
        }

        if signer_indices.len() != num_sigs {
            return Err(AptosError::InvalidSignature(
                "bitmap doesn't match number of signatures".into(),
            ));
        }

        for &index in &signer_indices {
            if offset >= bitmap_start {
                return Err(AptosError::InvalidSignature("bytes too short".into()));
            }

            let variant = AnyPublicKeyVariant::from_byte(bytes[offset])?;
            offset += 1;

            // Decode ULEB128 length
            let (len, len_bytes) =
                uleb128_decode(&bytes[offset..bitmap_start]).ok_or_else(|| {
                    AptosError::InvalidSignature("invalid ULEB128 length encoding".into())
                })?;
            offset += len_bytes;

            if len > MAX_SIGNATURE_SIZE {
                return Err(AptosError::InvalidSignature(format!(
                    "signature size {len} exceeds maximum {MAX_SIGNATURE_SIZE}"
                )));
            }

            if offset + len > bitmap_start {
                return Err(AptosError::InvalidSignature(
                    "bytes too short for signature".into(),
                ));
            }

            let sig_bytes = bytes[offset..offset + len].to_vec();
            offset += len;

            signatures.push((index, AnySignature::new(variant, sig_bytes)));
        }

        Ok(Self { signatures, bitmap })
    }
}

impl fmt::Debug for MultiKeySignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MultiKeySignature({} signatures, bitmap={:?})",
            self.signatures.len(),
            self.bitmap
        )
    }
}

impl fmt::Display for MultiKeySignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&const_hex::encode_prefixed(self.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_any_public_key_variant_from_byte() {
        assert_eq!(
            AnyPublicKeyVariant::from_byte(0).unwrap(),
            AnyPublicKeyVariant::Ed25519
        );
        assert_eq!(
            AnyPublicKeyVariant::from_byte(1).unwrap(),
            AnyPublicKeyVariant::Secp256k1
        );
        assert_eq!(
            AnyPublicKeyVariant::from_byte(2).unwrap(),
            AnyPublicKeyVariant::Secp256r1
        );
        assert_eq!(
            AnyPublicKeyVariant::from_byte(3).unwrap(),
            AnyPublicKeyVariant::Keyless
        );
        assert!(AnyPublicKeyVariant::from_byte(4).is_err());
        assert!(AnyPublicKeyVariant::from_byte(255).is_err());
    }

    #[test]
    fn test_any_public_key_variant_as_byte() {
        assert_eq!(AnyPublicKeyVariant::Ed25519.as_byte(), 0);
        assert_eq!(AnyPublicKeyVariant::Secp256k1.as_byte(), 1);
        assert_eq!(AnyPublicKeyVariant::Secp256r1.as_byte(), 2);
        assert_eq!(AnyPublicKeyVariant::Keyless.as_byte(), 3);
    }

    #[test]
    fn test_any_public_key_new() {
        let pk = AnyPublicKey::new(AnyPublicKeyVariant::Ed25519, vec![0x11; 32]);
        assert_eq!(pk.variant, AnyPublicKeyVariant::Ed25519);
        assert_eq!(pk.bytes.len(), 32);
        assert_eq!(pk.bytes[0], 0x11);
    }

    #[test]
    fn test_any_public_key_to_bcs_bytes() {
        let pk = AnyPublicKey::new(AnyPublicKeyVariant::Ed25519, vec![0xaa; 32]);
        let bcs = pk.to_bcs_bytes();

        // Format: variant_byte || ULEB128(length) || bytes
        assert_eq!(bcs[0], 0); // Ed25519 variant
        assert_eq!(bcs[1], 32); // ULEB128(32) = 0x20 (since 32 < 128)
        assert_eq!(bcs[2], 0xaa); // first byte of key
        assert_eq!(bcs.len(), 1 + 1 + 32); // variant + length + bytes
    }

    #[test]
    fn test_any_public_key_debug() {
        let pk = AnyPublicKey::new(AnyPublicKeyVariant::Secp256k1, vec![0xbb; 33]);
        let debug = format!("{pk:?}");
        assert!(debug.contains("Secp256k1"));
        assert!(debug.contains("0x"));
    }

    #[test]
    fn test_any_signature_new() {
        let sig = AnySignature::new(AnyPublicKeyVariant::Ed25519, vec![0xcc; 64]);
        assert_eq!(sig.variant, AnyPublicKeyVariant::Ed25519);
        assert_eq!(sig.bytes.len(), 64);
    }

    #[test]
    fn test_any_signature_to_bcs_bytes() {
        let sig = AnySignature::new(AnyPublicKeyVariant::Ed25519, vec![0xdd; 64]);
        let bcs = sig.to_bcs_bytes();

        // Format: variant_byte || ULEB128(length) || bytes
        assert_eq!(bcs[0], 0); // Ed25519 variant
        assert_eq!(bcs[1], 64); // ULEB128(64) = 0x40 (since 64 < 128)
        assert_eq!(bcs[2], 0xdd); // first byte of signature
        assert_eq!(bcs.len(), 1 + 1 + 64); // variant + length + bytes
    }

    #[test]
    fn test_any_signature_debug() {
        let sig = AnySignature::new(AnyPublicKeyVariant::Secp256r1, vec![0xee; 64]);
        let debug = format!("{sig:?}");
        assert!(debug.contains("Secp256r1"));
        assert!(debug.contains("64 bytes"));
    }

    #[test]
    fn test_any_public_key_verify_mismatched_variant() {
        let pk = AnyPublicKey::new(AnyPublicKeyVariant::Ed25519, vec![0; 32]);
        let sig = AnySignature::new(AnyPublicKeyVariant::Secp256k1, vec![0; 64]);

        let result = pk.verify(b"message", &sig);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("variant"));
    }

    #[test]
    fn test_multi_key_signature_insufficient_sigs() {
        // Empty signatures should fail
        let result = MultiKeySignature::new(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_key_signature_duplicate_indices() {
        let sig1 = AnySignature::new(AnyPublicKeyVariant::Ed25519, vec![0; 64]);
        let sig2 = AnySignature::new(AnyPublicKeyVariant::Ed25519, vec![1; 64]);

        // Duplicate index should fail
        let result = MultiKeySignature::new(vec![(0, sig1.clone()), (0, sig2)]);
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_key_signature_index_out_of_range() {
        let sig = AnySignature::new(AnyPublicKeyVariant::Ed25519, vec![0; 64]);

        // Index 32 is out of range (0-31)
        let result = MultiKeySignature::new(vec![(32, sig)]);
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_key_signature_basic() {
        let sig1 = AnySignature::new(AnyPublicKeyVariant::Ed25519, vec![0xaa; 64]);
        let sig2 = AnySignature::new(AnyPublicKeyVariant::Ed25519, vec![0xbb; 64]);

        let multi_sig = MultiKeySignature::new(vec![(0, sig1), (5, sig2)]).unwrap();

        assert_eq!(multi_sig.num_signatures(), 2);
        assert!(multi_sig.has_signature(0));
        assert!(!multi_sig.has_signature(1));
        assert!(multi_sig.has_signature(5));
    }

    #[test]
    fn test_multi_key_signature_debug_display() {
        let sig = AnySignature::new(AnyPublicKeyVariant::Ed25519, vec![0; 64]);
        let multi_sig = MultiKeySignature::new(vec![(0, sig)]).unwrap();

        let debug = format!("{multi_sig:?}");
        let display = format!("{multi_sig}");

        assert!(debug.contains("MultiKeySignature"));
        assert!(display.starts_with("0x"));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_public_key_creation() {
        use crate::crypto::Ed25519PrivateKey;

        let keys: Vec<_> = (0..3)
            .map(|_| AnyPublicKey::ed25519(&Ed25519PrivateKey::generate().public_key()))
            .collect();

        // Valid 2-of-3
        let multi_pk = MultiKeyPublicKey::new(keys.clone(), 2).unwrap();
        assert_eq!(multi_pk.num_keys(), 3);
        assert_eq!(multi_pk.threshold(), 2);

        // Invalid: threshold > num_keys
        assert!(MultiKeyPublicKey::new(keys.clone(), 4).is_err());

        // Invalid: threshold = 0
        assert!(MultiKeyPublicKey::new(keys.clone(), 0).is_err());

        // Invalid: empty keys
        assert!(MultiKeyPublicKey::new(vec![], 1).is_err());
    }

    #[test]
    #[cfg(all(feature = "ed25519", feature = "secp256k1"))]
    fn test_multi_key_mixed_types() {
        use crate::crypto::{Ed25519PrivateKey, Secp256k1PrivateKey};

        // Create mixed key types
        let ed_key = AnyPublicKey::ed25519(&Ed25519PrivateKey::generate().public_key());
        let secp_key = AnyPublicKey::secp256k1(&Secp256k1PrivateKey::generate().public_key());

        let multi_pk = MultiKeyPublicKey::new(vec![ed_key, secp_key], 2).unwrap();
        assert_eq!(multi_pk.num_keys(), 2);
        assert_eq!(
            multi_pk.get(0).unwrap().variant,
            AnyPublicKeyVariant::Ed25519
        );
        assert_eq!(
            multi_pk.get(1).unwrap().variant,
            AnyPublicKeyVariant::Secp256k1
        );
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_sign_verify() {
        use crate::crypto::Ed25519PrivateKey;

        let private_keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = private_keys
            .iter()
            .map(|k| AnyPublicKey::ed25519(&k.public_key()))
            .collect();

        let multi_pk = MultiKeyPublicKey::new(public_keys, 2).unwrap();
        let message = b"test message";

        // Sign with keys 0 and 2 (2-of-3)
        let sig0 = AnySignature::ed25519(&private_keys[0].sign(message));
        let sig2 = AnySignature::ed25519(&private_keys[2].sign(message));

        let multi_sig = MultiKeySignature::new(vec![(0, sig0), (2, sig2)]).unwrap();

        // Verify should succeed
        assert!(multi_pk.verify(message, &multi_sig).is_ok());

        // Wrong message should fail
        assert!(multi_pk.verify(b"wrong message", &multi_sig).is_err());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_bytes_roundtrip() {
        use crate::crypto::Ed25519PrivateKey;

        let keys: Vec<_> = (0..3)
            .map(|_| AnyPublicKey::ed25519(&Ed25519PrivateKey::generate().public_key()))
            .collect();
        let multi_pk = MultiKeyPublicKey::new(keys, 2).unwrap();

        let bytes = multi_pk.to_bytes();
        let restored = MultiKeyPublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(multi_pk.threshold(), restored.threshold());
        assert_eq!(multi_pk.num_keys(), restored.num_keys());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_signature_bytes_roundtrip() {
        use crate::crypto::Ed25519PrivateKey;

        let private_keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let message = b"test";

        let sig0 = AnySignature::ed25519(&private_keys[0].sign(message));
        let sig2 = AnySignature::ed25519(&private_keys[2].sign(message));

        let multi_sig = MultiKeySignature::new(vec![(0, sig0), (2, sig2)]).unwrap();

        let bytes = multi_sig.to_bytes();
        let restored = MultiKeySignature::from_bytes(&bytes).unwrap();

        assert_eq!(multi_sig.num_signatures(), restored.num_signatures());
        assert_eq!(multi_sig.bitmap(), restored.bitmap());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_signature_bitmap() {
        use crate::crypto::Ed25519PrivateKey;

        let private_keys: Vec<_> = (0..5).map(|_| Ed25519PrivateKey::generate()).collect();
        let message = b"test";

        // Sign with indices 1, 3, 4
        let signatures: Vec<_> = [1, 3, 4]
            .iter()
            .map(|&i| {
                (
                    i,
                    AnySignature::ed25519(&private_keys[i as usize].sign(message)),
                )
            })
            .collect();

        let multi_sig = MultiKeySignature::new(signatures).unwrap();

        assert!(!multi_sig.has_signature(0));
        assert!(multi_sig.has_signature(1));
        assert!(!multi_sig.has_signature(2));
        assert!(multi_sig.has_signature(3));
        assert!(multi_sig.has_signature(4));
        assert!(!multi_sig.has_signature(5));
    }

    #[test]
    fn test_multi_key_public_key_empty_keys() {
        let result = MultiKeyPublicKey::new(vec![], 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one"));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_public_key_threshold_zero() {
        use crate::crypto::Ed25519PrivateKey;

        let keys: Vec<_> = (0..2)
            .map(|_| AnyPublicKey::ed25519(&Ed25519PrivateKey::generate().public_key()))
            .collect();
        let result = MultiKeyPublicKey::new(keys, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least 1"));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_public_key_threshold_exceeds() {
        use crate::crypto::Ed25519PrivateKey;

        let keys: Vec<_> = (0..2)
            .map(|_| AnyPublicKey::ed25519(&Ed25519PrivateKey::generate().public_key()))
            .collect();
        let result = MultiKeyPublicKey::new(keys, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceed"));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_signature_empty() {
        let result = MultiKeySignature::new(vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one"));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_signature_duplicate_index() {
        use crate::crypto::Ed25519PrivateKey;

        let private_key = Ed25519PrivateKey::generate();
        let sig = AnySignature::ed25519(&private_key.sign(b"test"));

        let result = MultiKeySignature::new(vec![(0, sig.clone()), (0, sig)]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_public_key_accessors() {
        use crate::crypto::Ed25519PrivateKey;

        let keys: Vec<_> = (0..3)
            .map(|_| AnyPublicKey::ed25519(&Ed25519PrivateKey::generate().public_key()))
            .collect();
        let multi_pk = MultiKeyPublicKey::new(keys, 2).unwrap();

        assert_eq!(multi_pk.threshold(), 2);
        assert_eq!(multi_pk.num_keys(), 3);
        assert_eq!(multi_pk.public_keys().len(), 3);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_signature_accessors() {
        use crate::crypto::Ed25519PrivateKey;

        let private_key = Ed25519PrivateKey::generate();
        let sig0 = AnySignature::ed25519(&private_key.sign(b"test"));
        let sig2 = AnySignature::ed25519(&private_key.sign(b"test"));

        let multi_sig = MultiKeySignature::new(vec![(0, sig0), (2, sig2)]).unwrap();

        assert_eq!(multi_sig.num_signatures(), 2);
        assert_eq!(multi_sig.signatures().len(), 2);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_public_key_debug() {
        use crate::crypto::Ed25519PrivateKey;

        let keys: Vec<_> = (0..2)
            .map(|_| AnyPublicKey::ed25519(&Ed25519PrivateKey::generate().public_key()))
            .collect();
        let multi_pk = MultiKeyPublicKey::new(keys, 2).unwrap();

        let debug = format!("{multi_pk:?}");
        assert!(debug.contains("MultiKeyPublicKey"));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_signature_debug() {
        use crate::crypto::Ed25519PrivateKey;

        let private_key = Ed25519PrivateKey::generate();
        let sig = AnySignature::ed25519(&private_key.sign(b"test"));
        let multi_sig = MultiKeySignature::new(vec![(0, sig)]).unwrap();

        let debug = format!("{multi_sig:?}");
        assert!(debug.contains("MultiKeySignature"));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_public_key_display() {
        use crate::crypto::Ed25519PrivateKey;

        let keys: Vec<_> = (0..2)
            .map(|_| AnyPublicKey::ed25519(&Ed25519PrivateKey::generate().public_key()))
            .collect();
        let multi_pk = MultiKeyPublicKey::new(keys, 2).unwrap();

        let display = format!("{multi_pk}");
        assert!(display.starts_with("0x"));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_signature_display() {
        use crate::crypto::Ed25519PrivateKey;

        let private_key = Ed25519PrivateKey::generate();
        let sig = AnySignature::ed25519(&private_key.sign(b"test"));
        let multi_sig = MultiKeySignature::new(vec![(0, sig)]).unwrap();

        let display = format!("{multi_sig}");
        assert!(display.starts_with("0x"));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_public_key_to_address() {
        use crate::crypto::Ed25519PrivateKey;

        let keys: Vec<_> = (0..2)
            .map(|_| AnyPublicKey::ed25519(&Ed25519PrivateKey::generate().public_key()))
            .collect();
        let multi_pk = MultiKeyPublicKey::new(keys, 2).unwrap();

        let address = multi_pk.to_address();
        assert!(!address.is_zero());
    }

    #[test]
    fn test_any_public_key_variant_debug() {
        let variant = AnyPublicKeyVariant::Ed25519;
        let debug = format!("{variant:?}");
        assert!(debug.contains("Ed25519"));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_any_public_key_ed25519_debug() {
        use crate::crypto::Ed25519PrivateKey;

        let pk = AnyPublicKey::ed25519(&Ed25519PrivateKey::generate().public_key());
        let debug = format!("{pk:?}");
        assert!(debug.contains("Ed25519"));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_any_signature_ed25519_debug() {
        use crate::crypto::Ed25519PrivateKey;

        let private_key = Ed25519PrivateKey::generate();
        let sig = AnySignature::ed25519(&private_key.sign(b"test"));
        let debug = format!("{sig:?}");
        assert!(debug.contains("Ed25519"));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_multi_key_insufficient_signatures() {
        use crate::crypto::Ed25519PrivateKey;

        let private_keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = private_keys
            .iter()
            .map(|k| AnyPublicKey::ed25519(&k.public_key()))
            .collect();

        let multi_pk = MultiKeyPublicKey::new(public_keys, 2).unwrap();
        let message = b"test message";

        // Only provide 1 signature when threshold is 2
        let sig0 = AnySignature::ed25519(&private_keys[0].sign(message));
        let multi_sig = MultiKeySignature::new(vec![(0, sig0)]).unwrap();

        // Verify should fail
        let result = multi_pk.verify(message, &multi_sig);
        assert!(result.is_err());
    }
}
