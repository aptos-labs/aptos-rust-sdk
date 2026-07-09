//! Hash functions for the Aptos SDK.
//!
//! Provides SHA2-256 and SHA3-256 hash functions used throughout Aptos.

use sha2::Digest as Sha2Digest;

/// Available hash functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFunction {
    /// SHA2-256. General-purpose; **not** used for Aptos signature hashing.
    Sha2_256,
    /// SHA3-256 (used for Ed25519, Secp256k1 ECDSA, and authentication keys).
    Sha3_256,
}

/// Computes the SHA2-256 hash of the input.
///
/// This is a general-purpose SHA2-256 helper. Note that Aptos Secp256k1 ECDSA
/// signing hashes the message with **SHA3-256**, not SHA2-256, so this function
/// is not part of the signing path.
///
/// # Example
///
/// ```rust
/// use aptos_sdk::crypto::sha2_256;
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
/// use aptos_sdk::crypto::sha3_256;
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

/// Builds the signing message for an Aptos transaction preimage.
///
/// Aptos does **not** hash the whole `domain || bcs_bytes` blob into a single
/// digest. The signing message is the SHA3-256 hash of the domain separator
/// **concatenated with** the raw (unhashed) BCS bytes:
///
/// `SHA3-256(b"APTOS::{domain}") || bcs_bytes`
///
/// This matches the on-wire construction produced by
/// [`crate::transaction::types::RawTransaction::signing_message`]. Signing a
/// single hash taken over the concatenation (the previous behaviour of this
/// helper) yields a message the chain rejects with `INVALID_SIGNATURE`.
#[allow(dead_code)] // Public API for users
pub fn signing_message(domain: &str, bcs_bytes: &[u8]) -> Vec<u8> {
    let prefix = sha3_256(format!("APTOS::{domain}").as_bytes());
    let mut message = Vec::with_capacity(prefix.len() + bcs_bytes.len());
    message.extend_from_slice(&prefix);
    message.extend_from_slice(bcs_bytes);
    message
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
            const_hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
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
        let bcs_bytes = b"transaction_bytes";
        let msg = signing_message("RawTransaction", bcs_bytes);

        // Must be `SHA3-256(domain) || bcs_bytes` (hashed prefix CONCATENATED
        // with raw BCS bytes), NOT a single hash over the concatenation.
        let expected_prefix = sha3_256(b"APTOS::RawTransaction");
        assert_eq!(msg.len(), 32 + bcs_bytes.len());
        assert_eq!(&msg[..32], &expected_prefix[..]);
        assert_eq!(&msg[32..], bcs_bytes);

        // It must NOT equal the (incorrect) single hash of the whole blob.
        let single_hash = sha3_256_of([b"APTOS::RawTransaction".as_slice(), bcs_bytes]);
        assert_ne!(&msg[..32], &single_hash[..]);
    }

    #[test]
    fn test_signing_message_known_bytes() {
        // Hardcoded expected bytes for a small fixed input. The 32-byte prefix
        // is SHA3-256("APTOS::RawTransaction"); the two trailing bytes are the
        // raw BCS payload appended verbatim.
        let expected = const_hex::decode(
            "b5e97db07fa0bd0e5598aa3643a9bc6f6693bddc1a9fec9e674a461eaa00b193aabb",
        )
        .unwrap();
        let msg = signing_message("RawTransaction", &[0xaa, 0xbb]);
        assert_eq!(msg, expected);
    }
}
