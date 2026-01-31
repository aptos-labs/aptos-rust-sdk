//! Cryptographic primitives for the Aptos SDK.
//!
//! This module provides implementations of the signature schemes supported
//! by Aptos, including Ed25519, Secp256k1, and Secp256r1 (P-256).
//!
//! # Feature Flags
//!
//! - `ed25519` (default): Ed25519 signatures
//! - `secp256k1` (default): Secp256k1 ECDSA signatures
//! - `secp256r1`: Secp256r1 (P-256) ECDSA signatures
//! - `bls`: BLS12-381 signatures
//!
//! # Security Considerations
//!
//! ## Timing Attacks
//!
//! The `PartialEq` implementations for cryptographic types use standard byte
//! comparisons which may not be constant-time. This is generally acceptable
//! because:
//!
//! - Public keys and signatures are not secret material
//! - Signature verification in the underlying libraries uses constant-time
//!   operations for the actual cryptographic comparisons
//!
//! If you need constant-time comparisons for specific use cases (e.g., comparing
//! against expected signatures in tests), consider using the `subtle` crate's
//! `ConstantTimeEq` trait.
//!
//! ## Key Material Protection
//!
//! Private key types implement `Zeroize` and `ZeroizeOnDrop` to clear sensitive
//! key material from memory when dropped. The underlying cryptographic libraries
//! (ed25519-dalek, k256, p256) also implement secure key handling.
//!
//! # Example
//!
//! ```rust,ignore
//! use aptos_rust_sdk_v2::crypto::{Ed25519PrivateKey, Signer};
//!
//! let private_key = Ed25519PrivateKey::generate();
//! let message = b"hello world";
//! let signature = private_key.sign(message);
//!
//! let public_key = private_key.public_key();
//! assert!(public_key.verify(message, &signature).is_ok());
//! ```

mod hash;
mod traits;

#[cfg(feature = "bls")]
mod bls12381;
#[cfg(feature = "ed25519")]
mod ed25519;
#[cfg(feature = "ed25519")]
mod multi_ed25519;
mod multi_key;
#[cfg(feature = "secp256k1")]
mod secp256k1;
#[cfg(feature = "secp256r1")]
mod secp256r1;

// Re-export hash functions
pub use hash::{HashFunction, sha2_256, sha3_256, sha3_256_of, signing_message};

// Re-export traits
pub use traits::{PublicKey, Signature, Signer, Verifier};

// Re-export Ed25519 types
#[cfg(feature = "ed25519")]
pub use ed25519::{
    ED25519_PRIVATE_KEY_LENGTH, ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH,
    Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
};

// Re-export Multi-Ed25519 types
#[cfg(feature = "ed25519")]
pub use multi_ed25519::{
    MAX_NUM_OF_KEYS, MIN_THRESHOLD, MultiEd25519PublicKey, MultiEd25519Signature,
};

// Re-export Multi-Key types
pub use multi_key::{
    AnyPublicKey, AnyPublicKeyVariant, AnySignature, MAX_NUM_OF_KEYS as MULTI_KEY_MAX_NUM_OF_KEYS,
    MIN_THRESHOLD as MULTI_KEY_MIN_THRESHOLD, MultiKeyPublicKey, MultiKeySignature,
};

// Re-export Secp256k1 types
#[cfg(feature = "secp256k1")]
pub use secp256k1::{
    SECP256K1_PRIVATE_KEY_LENGTH, SECP256K1_PUBLIC_KEY_LENGTH,
    SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LENGTH, SECP256K1_SIGNATURE_LENGTH, Secp256k1PrivateKey,
    Secp256k1PublicKey, Secp256k1Signature,
};

// Re-export Secp256r1 types
#[cfg(feature = "secp256r1")]
pub use secp256r1::{
    SECP256R1_PRIVATE_KEY_LENGTH, SECP256R1_PUBLIC_KEY_LENGTH, SECP256R1_SIGNATURE_LENGTH,
    Secp256r1PrivateKey, Secp256r1PublicKey, Secp256r1Signature,
};

// Re-export BLS12-381 types
#[cfg(feature = "bls")]
pub use bls12381::{
    BLS12381_POP_LENGTH, BLS12381_PRIVATE_KEY_LENGTH, BLS12381_PUBLIC_KEY_LENGTH,
    BLS12381_SIGNATURE_LENGTH, Bls12381PrivateKey, Bls12381ProofOfPossession, Bls12381PublicKey,
    Bls12381Signature,
};

/// The authentication key scheme byte for Ed25519 single-key accounts.
pub const ED25519_SCHEME: u8 = 0;

/// The authentication key scheme byte for multi-Ed25519 accounts.
pub const MULTI_ED25519_SCHEME: u8 = 1;

/// The authentication key scheme byte for single-key accounts (unified).
pub const SINGLE_KEY_SCHEME: u8 = 2;

/// The authentication key scheme byte for multi-key accounts (unified).
pub const MULTI_KEY_SCHEME: u8 = 3;

/// The authentication key scheme byte for keyless accounts.
pub const KEYLESS_SCHEME: u8 = 5;

/// Derives an authentication key from a public key and scheme.
///
/// The authentication key is SHA3-256(public_key_bytes || `scheme_byte`).
pub fn derive_authentication_key(public_key: &[u8], scheme: u8) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(public_key);
    hasher.update([scheme]);
    let result = hasher.finalize();
    let mut auth_key = [0u8; 32];
    auth_key.copy_from_slice(&result);
    auth_key
}

/// Derives an account address from a public key and scheme.
///
/// For most accounts, the address equals the authentication key.
pub fn derive_address(public_key: &[u8], scheme: u8) -> crate::types::AccountAddress {
    let auth_key = derive_authentication_key(public_key, scheme);
    crate::types::AccountAddress::new(auth_key)
}
