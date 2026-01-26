//! Hash functions for the Aptos SDK.
//!
//! Provides SHA2-256 and SHA3-256 hash functions used throughout Aptos.

use sha2::Digest as Sha2Digest;

/// Available hash functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFunction {
    /// SHA2-256 (used for Secp256k1 ECDSA)
    Sha2_256,
    /// SHA3-256 (used for Ed25519 and authentication keys)
    Sha3_256,
}

/// Computes the SHA2-256 hash of the input.
///
/// This is used for Secp256k1 ECDSA message hashing.
///
/// # Example
///
/// ```rust
/// use aptos_rust_sdk_v2::crypto::sha2_256;
///
/// let hash = sha2_256(b"hello world");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn sha2_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Computes the SHA3-256 hash of the input.
///
/// This is used for Ed25519 signatures and authentication key derivation.
///
/// # Example
///
/// ```rust
/// use aptos_rust_sdk_v2::crypto::sha3_256;
///
/// let hash = sha3_256(b"hello world");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Computes the SHA3-256 hash of multiple byte slices.
#[allow(dead_code)] // Public API for users
pub fn sha3_256_of<I, T>(items: I) -> [u8; 32]
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    let mut hasher = sha3::Sha3_256::new();
    for item in items {
        hasher.update(item.as_ref());
    }
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Computes a domain-separated hash for transaction signing.
///
/// This is used to create the signing message for transactions:
/// SHA3-256(domain_separator || bcs_bytes)
#[allow(dead_code)] // Public API for users
pub fn signing_message(domain: &str, bcs_bytes: &[u8]) -> [u8; 32] {
    sha3_256_of([format!("APTOS::{}", domain).as_bytes(), bcs_bytes])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha2_256() {
        let hash = sha2_256(b"hello world");
        assert_eq!(hash.len(), 32);
        // Known hash value
        let expected =
            hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
                .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha3_256() {
        let hash = sha3_256(b"hello world");
        assert_eq!(hash.len(), 32);
        // Verify it's different from SHA2-256
        let sha2_hash = sha2_256(b"hello world");
        assert_ne!(hash, sha2_hash);
    }

    #[test]
    fn test_sha3_256_of_multiple() {
        let hash1 = sha3_256(b"helloworld");
        let hash2 = sha3_256_of([b"hello".as_slice(), b"world".as_slice()]);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_signing_message() {
        let msg = signing_message("RawTransaction", b"transaction_bytes");
        assert_eq!(msg.len(), 32);
    }
}
