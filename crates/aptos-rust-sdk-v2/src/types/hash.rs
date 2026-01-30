//! Hash value type.
//!
//! A 32-byte cryptographic hash value used throughout Aptos for
//! transaction hashes, state roots, and other cryptographic commitments.

use crate::error::{AptosError, AptosResult};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use std::fmt;
use std::str::FromStr;

/// The length of a hash value in bytes.
pub const HASH_LENGTH: usize = 32;

/// A 32-byte cryptographic hash value.
///
/// Hash values are used throughout Aptos for:
/// - Transaction hashes
/// - State roots
/// - Event keys
/// - Merkle tree nodes
///
/// # Example
///
/// ```rust
/// use aptos_rust_sdk_v2::HashValue;
///
/// // Compute a hash
/// let hash = HashValue::sha3_256(b"hello world");
/// assert_eq!(hash.to_hex().len(), 66); // "0x" + 64 hex chars
///
/// // Parse from hex (64 hex characters)
/// let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
/// let hash = HashValue::from_hex(hex).unwrap();
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HashValue([u8; HASH_LENGTH]);

impl HashValue {
    /// The "zero" hash (all zeros).
    pub const ZERO: Self = Self([0u8; HASH_LENGTH]);

    /// Creates a hash from a byte array.
    pub const fn new(bytes: [u8; HASH_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Computes the SHA3-256 hash of the given data.
    pub fn sha3_256<T: AsRef<[u8]>>(data: T) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(data.as_ref());
        let result = hasher.finalize();
        let mut bytes = [0u8; HASH_LENGTH];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Computes the SHA3-256 hash of multiple byte slices.
    pub fn sha3_256_of<I, T>(items: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut hasher = Sha3_256::new();
        for item in items {
            hasher.update(item.as_ref());
        }
        let result = hasher.finalize();
        let mut bytes = [0u8; HASH_LENGTH];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Creates a hash from a hex string (with or without `0x` prefix).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string contains invalid UTF-8, is not exactly 64 hex
    /// characters (excluding the optional `0x` prefix), or contains invalid hex characters.
    pub fn from_hex<T: AsRef<[u8]>>(hex_str: T) -> AptosResult<Self> {
        let hex_str = hex_str.as_ref();
        let hex_str = if hex_str.starts_with(b"0x") || hex_str.starts_with(b"0X") {
            &hex_str[2..]
        } else {
            hex_str
        };

        let hex_string = std::str::from_utf8(hex_str)
            .map_err(|e| AptosError::Internal(format!("Invalid UTF-8 in hex string: {e}")))?;

        if hex_string.len() != HASH_LENGTH * 2 {
            return Err(AptosError::Internal(format!(
                "Invalid hash length: expected {} hex characters, got {}",
                HASH_LENGTH * 2,
                hex_string.len()
            )));
        }

        let bytes = hex::decode(hex_string)?;
        let mut hash = [0u8; HASH_LENGTH];
        hash.copy_from_slice(&bytes);
        Ok(Self(hash))
    }

    /// Creates a hash from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice is not exactly 32 bytes long.
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> AptosResult<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() != HASH_LENGTH {
            return Err(AptosError::Internal(format!(
                "Invalid hash length: expected {} bytes, got {}",
                HASH_LENGTH,
                bytes.len()
            )));
        }
        let mut hash = [0u8; HASH_LENGTH];
        hash.copy_from_slice(bytes);
        Ok(Self(hash))
    }

    /// Returns the hash as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the hash as a byte array.
    pub fn to_bytes(&self) -> [u8; HASH_LENGTH] {
        self.0
    }

    /// Returns the hash as a hex string with `0x` prefix.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Returns true if this is the zero hash.
    pub fn is_zero(&self) -> bool {
        self == &Self::ZERO
    }
}

impl Default for HashValue {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Debug for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HashValue({})", self.to_hex())
    }
}

impl fmt::Display for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for HashValue {
    type Err = AptosError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl Serialize for HashValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for HashValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <[u8; HASH_LENGTH]>::deserialize(deserializer)?;
            Ok(Self(bytes))
        }
    }
}

impl From<[u8; HASH_LENGTH]> for HashValue {
    fn from(bytes: [u8; HASH_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl From<HashValue> for [u8; HASH_LENGTH] {
    fn from(hash: HashValue) -> Self {
        hash.0
    }
}

impl AsRef<[u8]> for HashValue {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256() {
        let hash = HashValue::sha3_256(b"hello world");
        assert!(!hash.is_zero());

        // Same input should produce same hash
        let hash2 = HashValue::sha3_256(b"hello world");
        assert_eq!(hash, hash2);

        // Different input should produce different hash
        let hash3 = HashValue::sha3_256(b"hello world!");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_sha3_256_of_multiple() {
        let hash1 = HashValue::sha3_256_of([b"hello" as &[u8], b" " as &[u8], b"world" as &[u8]]);
        let hash2 = HashValue::sha3_256(b"hello world");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_from_hex() {
        let hash = HashValue::sha3_256(b"test");
        let hex = hash.to_hex();
        let parsed = HashValue::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed);

        // Without prefix
        let parsed2 = HashValue::from_hex(&hex[2..]).unwrap();
        assert_eq!(hash, parsed2);

        // Uppercase 0X prefix
        let hex_upper = hex.replace("0x", "0X");
        let parsed3 = HashValue::from_hex(&hex_upper).unwrap();
        assert_eq!(hash, parsed3);
    }

    #[test]
    fn test_from_hex_invalid_length() {
        let result = HashValue::from_hex("0x1234");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_hex_invalid_chars() {
        let result = HashValue::from_hex("0xZZZZ");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes() {
        let bytes = [1u8; HASH_LENGTH];
        let hash = HashValue::new(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_json_serialization() {
        let hash = HashValue::sha3_256(b"test");
        let json = serde_json::to_string(&hash).unwrap();
        let parsed: HashValue = serde_json::from_str(&json).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn test_zero_hash() {
        assert!(HashValue::ZERO.is_zero());
        assert!(!HashValue::sha3_256(b"").is_zero());
    }

    #[test]
    fn test_new() {
        let bytes = [42u8; HASH_LENGTH];
        let hash = HashValue::new(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_display() {
        let hash = HashValue::ZERO;
        let display = format!("{}", hash);
        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn test_debug() {
        let hash = HashValue::ZERO;
        let debug = format!("{:?}", hash);
        assert!(debug.contains("HashValue"));
    }

    #[test]
    fn test_from_str() {
        let hash = HashValue::sha3_256(b"test");
        let hex = hash.to_hex();
        let parsed: HashValue = hex.parse().unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn test_ordering() {
        let hash1 = HashValue::new([0u8; HASH_LENGTH]);
        let hash2 = HashValue::new([1u8; HASH_LENGTH]);
        assert!(hash1 < hash2);
    }

    #[test]
    fn test_as_ref() {
        let hash = HashValue::sha3_256(b"test");
        let slice: &[u8] = hash.as_ref();
        assert_eq!(slice.len(), HASH_LENGTH);
    }
}
