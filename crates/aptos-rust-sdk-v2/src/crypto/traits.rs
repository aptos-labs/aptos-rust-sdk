//! Cryptographic traits for the Aptos SDK.
//!
//! These traits provide a unified interface for different signature schemes.

use crate::error::AptosResult;

/// A trait for types that can sign messages.
pub trait Signer {
    /// The signature type produced by this signer.
    type Signature: Signature;

    /// Signs the given message and returns a signature.
    fn sign(&self, message: &[u8]) -> Self::Signature;

    /// Returns the public key corresponding to this signer.
    fn public_key(&self) -> <Self::Signature as Signature>::PublicKey;
}

/// A trait for types that can verify signatures.
pub trait Verifier {
    /// The signature type this verifier can check.
    type Signature: Signature;

    /// Verifies that the signature is valid for the given message.
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> AptosResult<()>;
}

/// A trait for public key types.
pub trait PublicKey: Clone + Sized {
    /// The length of the public key in bytes.
    const LENGTH: usize;

    /// Creates a public key from bytes.
    fn from_bytes(bytes: &[u8]) -> AptosResult<Self>;

    /// Returns the public key as bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Returns the public key as a hex string with 0x prefix.
    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }
}

/// A trait for signature types.
pub trait Signature: Clone + Sized {
    /// The public key type for this signature scheme.
    type PublicKey: PublicKey;

    /// The length of the signature in bytes.
    const LENGTH: usize;

    /// Creates a signature from bytes.
    fn from_bytes(bytes: &[u8]) -> AptosResult<Self>;

    /// Returns the signature as bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Returns the signature as a hex string with 0x prefix.
    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }
}
