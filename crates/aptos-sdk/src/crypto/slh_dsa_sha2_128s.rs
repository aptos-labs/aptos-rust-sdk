//! SLH-DSA-SHA2-128s (post-quantum) signature scheme implementation.
//!
//! SLH-DSA (FIPS 205, formerly SPHINCS+) is a stateless hash-based signature
//! scheme. The SHA2-128s parameter set is the one Aptos supports on-chain
//! (AIP-137; `aptos-core` PR #18300, feature flag 107): 48-byte private keys
//! (three 16-byte seeds), 32-byte public keys, and 7,856-byte signatures.
//!
//! This mirrors the TypeScript SDK's `SlhDsaSha2128s*` types
//! (`aptos-ts-sdk` PR #802), which use `@noble/post-quantum`; here the
//! underlying implementation is the RustCrypto `slh-dsa` crate -- the same
//! crate (and pinned version) `aptos-crypto` uses on-chain -- so signatures
//! produced here verify on-chain and vice versa.
//!
//! On-chain variant indices (see `aptos-core`'s
//! `types/src/transaction/authenticator.rs`): `AnyPublicKey::SlhDsa_Sha2_128s`
//! is variant **5**, while `AnySignature::SlhDsa_Sha2_128s` is variant **4**.
//! The two enums diverge here, unlike for Ed25519/Secp256k1.

use crate::crypto::traits::{PublicKey, Signature, Signer, Verifier};
use crate::error::{AptosError, AptosResult};
use serde::{Deserialize, Serialize};
use slh_dsa::signature::{Keypair as _, Signer as SlhSigner, Verifier as SlhVerifier};
use std::fmt;
use zeroize::Zeroize;

/// SLH-DSA-SHA2-128s private key length in bytes (SK seed || PRF seed || PK seed).
pub const SLH_DSA_SHA2_128S_PRIVATE_KEY_LENGTH: usize = 48;
/// SLH-DSA-SHA2-128s public key length in bytes (PK seed || PK root).
pub const SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH: usize = 32;
/// SLH-DSA-SHA2-128s signature length in bytes.
pub const SLH_DSA_SHA2_128S_SIGNATURE_LENGTH: usize = 7856;

/// SLIP-0010-style master-key seed string for SLH-DSA-SHA2-128s.
///
/// Non-standard (there is no registered SLIP-0010 curve for SLH-DSA): this is
/// exactly the `"SLH-DSA-SHA2-128s seed"` string the TypeScript SDK uses, so
/// both SDKs derive the same keys from the same mnemonic and path.
pub const SLH_DSA_SHA2_128S_SLIP0010_SEED: &str = "SLH-DSA-SHA2-128s seed";

type SlhSigningKey = slh_dsa::SigningKey<slh_dsa::Sha2_128s>;
type SlhVerifyingKey = slh_dsa::VerifyingKey<slh_dsa::Sha2_128s>;
type SlhSignature = slh_dsa::Signature<slh_dsa::Sha2_128s>;

fn signing_key_from_seeds(seeds: &[u8; SLH_DSA_SHA2_128S_PRIVATE_KEY_LENGTH]) -> SlhSigningKey {
    SlhSigningKey::slh_keygen_internal(&seeds[0..16], &seeds[16..32], &seeds[32..48])
}

/// An SLH-DSA-SHA2-128s private key.
///
/// Serializes as only the 48-byte three seeds (SK seed || PRF seed ||
/// PK seed), the same representation the TypeScript SDK and `aptos-crypto`
/// use. The expanded signing key (which caches the derived PK root) is
/// computed once at construction and retained: recomputing it via
/// `slh_keygen` on every `sign` / `public_key` call is nearly as expensive
/// as signing itself, which made repeated use (and the test suite under
/// coverage instrumentation) needlessly slow. The seeds are zeroized when
/// dropped; the expanded key zeroizes its own seed material on drop (the
/// `slh-dsa` crate's `ZeroizeOnDrop` impl, pinned by a test below).
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SlhDsaSha2128sPrivateKey {
    seeds: [u8; SLH_DSA_SHA2_128S_PRIVATE_KEY_LENGTH],
    #[zeroize(skip)]
    #[allow(unused)] // Field is used; lint false positive from Zeroize derive
    inner: SlhSigningKey,
}

impl SlhDsaSha2128sPrivateKey {
    fn from_seeds(seeds: [u8; SLH_DSA_SHA2_128S_PRIVATE_KEY_LENGTH]) -> Self {
        Self {
            inner: signing_key_from_seeds(&seeds),
            seeds,
        }
    }

    /// Generates a new random SLH-DSA-SHA2-128s private key.
    pub fn generate() -> Self {
        let mut seeds = [0u8; SLH_DSA_SHA2_128S_PRIVATE_KEY_LENGTH];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seeds);
        Self::from_seeds(seeds)
    }

    /// Creates a private key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::InvalidPrivateKey`] if the slice is not exactly
    /// 48 bytes (the three 16-byte seeds).
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != SLH_DSA_SHA2_128S_PRIVATE_KEY_LENGTH {
            return Err(AptosError::InvalidPrivateKey(format!(
                "expected {} bytes, got {}",
                SLH_DSA_SHA2_128S_PRIVATE_KEY_LENGTH,
                bytes.len()
            )));
        }
        let mut seeds = [0u8; SLH_DSA_SHA2_128S_PRIVATE_KEY_LENGTH];
        seeds.copy_from_slice(bytes);
        Ok(Self::from_seeds(seeds))
    }

    /// Creates a private key from a hex string.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::Hex`] on invalid hex, or
    /// [`AptosError::InvalidPrivateKey`] if not exactly 48 bytes.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let bytes = const_hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Creates a private key from an AIP-80 format string.
    ///
    /// AIP-80 format: `slh-dsa-sha2-128s-priv-0x{hex_bytes}` (the prefix
    /// `aptos-crypto` defines for this scheme).
    ///
    /// # Errors
    ///
    /// Returns an error if the format is invalid or the key bytes are invalid.
    pub fn from_aip80(s: &str) -> AptosResult<Self> {
        const PREFIX: &str = "slh-dsa-sha2-128s-priv-";
        if let Some(hex_part) = s.strip_prefix(PREFIX) {
            Self::from_hex(hex_part)
        } else {
            Err(AptosError::InvalidPrivateKey(format!(
                "invalid AIP-80 format: expected prefix '{PREFIX}'"
            )))
        }
    }

    /// Derives the three seeds from a seed and hardened path components.
    ///
    /// SLIP-0010-style derivation exactly as the TypeScript SDK performs it:
    /// the master key is `HMAC-SHA512(key = "SLH-DSA-SHA2-128s seed", seed)`,
    /// each child is `HMAC-SHA512(chain_code, 0x00 || key || index_be)` with
    /// the hardened bit already applied to `index`, and the resulting 48-byte
    /// private key is `derived_key(32) || chain_code[..16]`.
    #[cfg(any(feature = "mnemonic", test))]
    pub(crate) fn derive_seeds(seed: &[u8], encoded_components: &[u32]) -> [u8; 48] {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        type HmacSha512 = Hmac<Sha512>;

        let mut mac = HmacSha512::new_from_slice(SLH_DSA_SHA2_128S_SLIP0010_SEED.as_bytes())
            .expect("HMAC accepts keys of any length");
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        for &encoded in encoded_components {
            let mut data = Vec::with_capacity(1 + 32 + 4);
            data.push(0u8);
            data.extend_from_slice(&key);
            data.extend_from_slice(&encoded.to_be_bytes());

            let mut mac =
                HmacSha512::new_from_slice(&chain_code).expect("HMAC accepts keys of any length");
            mac.update(&data);
            let result = mac.finalize().into_bytes();

            key.copy_from_slice(&result[..32]);
            chain_code.copy_from_slice(&result[32..]);
            zeroize::Zeroize::zeroize(&mut data);
        }

        let mut seeds = [0u8; SLH_DSA_SHA2_128S_PRIVATE_KEY_LENGTH];
        seeds[..32].copy_from_slice(&key);
        seeds[32..].copy_from_slice(&chain_code[..16]);
        zeroize::Zeroize::zeroize(&mut key);
        zeroize::Zeroize::zeroize(&mut chain_code);
        seeds
    }

    /// Derives a private key from `seed` at the given hardened path.
    #[cfg(any(feature = "mnemonic", test))]
    pub(crate) fn from_seed_and_path(seed: &[u8], encoded_components: &[u32]) -> Self {
        Self::from_seeds(Self::derive_seeds(seed, encoded_components))
    }

    /// Returns the private key as bytes (the 48-byte three seeds).
    pub fn to_bytes(&self) -> [u8; SLH_DSA_SHA2_128S_PRIVATE_KEY_LENGTH] {
        self.seeds
    }

    /// Returns the private key as a hex string.
    pub fn to_hex(&self) -> String {
        const_hex::encode_prefixed(self.seeds)
    }

    /// Returns the private key in AIP-80 format.
    ///
    /// AIP-80 format: `slh-dsa-sha2-128s-priv-0x{hex_bytes}`
    pub fn to_aip80(&self) -> String {
        format!("slh-dsa-sha2-128s-priv-{}", self.to_hex())
    }

    /// Returns the corresponding public key.
    pub fn public_key(&self) -> SlhDsaSha2128sPublicKey {
        let bytes: [u8; SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH] =
            self.inner.verifying_key().to_bytes().into();
        SlhDsaSha2128sPublicKey { bytes }
    }

    /// Signs a message and returns the signature.
    ///
    /// Deterministic (empty context string), matching `aptos-crypto`
    /// (`slh_dsa::signature::Signer`): the same key and message always
    /// produce the same signature. The TypeScript SDK's noble-based signing
    /// produces different bytes for the same input, but the two
    /// implementations cross-verify (checked against
    /// `@noble/post-quantum` 0.5.4 during development).
    pub fn sign(&self, message: &[u8]) -> SlhDsaSha2128sSignature {
        let signature: SlhSignature = SlhSigner::sign(&self.inner, message);
        SlhDsaSha2128sSignature {
            bytes: signature.to_vec(),
        }
    }
}

impl Signer for SlhDsaSha2128sPrivateKey {
    type Signature = SlhDsaSha2128sSignature;

    fn sign(&self, message: &[u8]) -> SlhDsaSha2128sSignature {
        SlhDsaSha2128sPrivateKey::sign(self, message)
    }

    fn public_key(&self) -> SlhDsaSha2128sPublicKey {
        SlhDsaSha2128sPrivateKey::public_key(self)
    }
}

impl fmt::Debug for SlhDsaSha2128sPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlhDsaSha2128sPrivateKey([REDACTED])")
    }
}

/// An SLH-DSA-SHA2-128s public key (32 bytes: PK seed || PK root).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SlhDsaSha2128sPublicKey {
    bytes: [u8; SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH],
}

impl SlhDsaSha2128sPublicKey {
    /// Creates a public key from raw bytes.
    ///
    /// Only the length is validated; any 32 bytes are a syntactically valid
    /// SLH-DSA public key (PK seed || PK root).
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::InvalidPublicKey`] if not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH {
            return Err(AptosError::InvalidPublicKey(format!(
                "expected {} bytes, got {}",
                SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH,
                bytes.len()
            )));
        }
        let mut out = [0u8; SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH];
        out.copy_from_slice(bytes);
        Ok(Self { bytes: out })
    }

    /// Creates a public key from a hex string.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::Hex`] on invalid hex, or
    /// [`AptosError::InvalidPublicKey`] if not exactly 32 bytes.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let bytes = const_hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Creates a public key from an AIP-80 format string.
    ///
    /// AIP-80 format: `slh-dsa-sha2-128s-pub-0x{hex_bytes}`
    ///
    /// # Errors
    ///
    /// Returns an error if the format is invalid or the key bytes are invalid.
    pub fn from_aip80(s: &str) -> AptosResult<Self> {
        const PREFIX: &str = "slh-dsa-sha2-128s-pub-";
        if let Some(hex_part) = s.strip_prefix(PREFIX) {
            Self::from_hex(hex_part)
        } else {
            Err(AptosError::InvalidPublicKey(format!(
                "invalid AIP-80 format: expected prefix '{PREFIX}'"
            )))
        }
    }

    /// Returns the public key as bytes.
    pub fn to_bytes(&self) -> [u8; SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH] {
        self.bytes
    }

    /// Returns the public key as a hex string.
    pub fn to_hex(&self) -> String {
        const_hex::encode_prefixed(self.bytes)
    }

    /// Returns the public key in AIP-80 format.
    ///
    /// AIP-80 format: `slh-dsa-sha2-128s-pub-0x{hex_bytes}`
    pub fn to_aip80(&self) -> String {
        format!("slh-dsa-sha2-128s-pub-{}", self.to_hex())
    }

    /// Verifies a signature against a message.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::SignatureVerificationFailed`] if the signature
    /// is malformed or does not verify for the message.
    pub fn verify(&self, message: &[u8], signature: &SlhDsaSha2128sSignature) -> AptosResult<()> {
        let verifying_key = SlhVerifyingKey::try_from(&self.bytes[..])
            .map_err(|_| AptosError::SignatureVerificationFailed)?;
        let slh_signature = SlhSignature::try_from(&signature.bytes[..])
            .map_err(|_| AptosError::SignatureVerificationFailed)?;
        SlhVerifier::verify(&verifying_key, message, &slh_signature)
            .map_err(|_| AptosError::SignatureVerificationFailed)
    }

    /// Derives the account address for this public key.
    ///
    /// Uses the `SingleKey` authentication scheme (`scheme_id` = 2):
    /// `auth_key = SHA3-256(BCS(AnyPublicKey::SlhDsa_Sha2_128s) || 0x02)`,
    /// where `BCS(AnyPublicKey::SlhDsa_Sha2_128s)` = `0x05 || ULEB128(32) || public_key`.
    pub fn to_address(&self) -> crate::types::AccountAddress {
        crate::crypto::derive_address(&self.to_bcs_bytes(), crate::crypto::SINGLE_KEY_SCHEME)
    }

    /// Derives the authentication key for this public key.
    pub fn to_authentication_key(&self) -> [u8; 32] {
        crate::crypto::derive_authentication_key(
            &self.to_bcs_bytes(),
            crate::crypto::SINGLE_KEY_SCHEME,
        )
    }

    /// BCS-serialized `AnyPublicKey::SlhDsa_Sha2_128s`: `0x05 || ULEB128(32) || public_key`.
    pub fn to_bcs_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 1 + self.bytes.len());
        out.push(5); // AnyPublicKey::SlhDsa_Sha2_128s variant
        out.push(32); // ULEB128(32)
        out.extend_from_slice(&self.bytes);
        out
    }
}

impl PublicKey for SlhDsaSha2128sPublicKey {
    const LENGTH: usize = SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH;

    fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        SlhDsaSha2128sPublicKey::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

impl Verifier for SlhDsaSha2128sPublicKey {
    type Signature = SlhDsaSha2128sSignature;

    fn verify(&self, message: &[u8], signature: &SlhDsaSha2128sSignature) -> AptosResult<()> {
        SlhDsaSha2128sPublicKey::verify(self, message, signature)
    }
}

impl fmt::Debug for SlhDsaSha2128sPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlhDsaSha2128sPublicKey({})", self.to_hex())
    }
}

impl fmt::Display for SlhDsaSha2128sPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for SlhDsaSha2128sPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(&self.bytes)
        }
    }
}

impl<'de> Deserialize<'de> for SlhDsaSha2128sPublicKey {
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

/// An SLH-DSA-SHA2-128s signature (7,856 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct SlhDsaSha2128sSignature {
    bytes: Vec<u8>,
}

impl SlhDsaSha2128sSignature {
    /// Creates a signature from raw bytes.
    ///
    /// Only the length is validated; cryptographic validity is determined at
    /// verification time.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::InvalidSignature`] if not exactly 7,856 bytes.
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        if bytes.len() != SLH_DSA_SHA2_128S_SIGNATURE_LENGTH {
            return Err(AptosError::InvalidSignature(format!(
                "expected {} bytes, got {}",
                SLH_DSA_SHA2_128S_SIGNATURE_LENGTH,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Creates a signature from a hex string.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::Hex`] on invalid hex, or
    /// [`AptosError::InvalidSignature`] if not exactly 7,856 bytes.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let bytes = const_hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the signature as bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Returns the signature as a hex string.
    pub fn to_hex(&self) -> String {
        const_hex::encode_prefixed(&self.bytes)
    }

    /// BCS-serialized `AnySignature::SlhDsa_Sha2_128s`:
    /// `0x04 || ULEB128(7856) || signature`.
    pub fn to_bcs_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 2 + self.bytes.len());
        out.push(4); // AnySignature::SlhDsa_Sha2_128s variant
        out.extend_from_slice(&crate::crypto::multi_key::uleb128_encode(self.bytes.len()));
        out.extend_from_slice(&self.bytes);
        out
    }
}

impl Signature for SlhDsaSha2128sSignature {
    type PublicKey = SlhDsaSha2128sPublicKey;
    const LENGTH: usize = SLH_DSA_SHA2_128S_SIGNATURE_LENGTH;

    fn from_bytes(bytes: &[u8]) -> AptosResult<Self> {
        SlhDsaSha2128sSignature::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl fmt::Debug for SlhDsaSha2128sSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlhDsaSha2128sSignature({} bytes)", self.bytes.len())
    }
}

impl fmt::Display for SlhDsaSha2128sSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for SlhDsaSha2128sSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(&self.bytes)
        }
    }
}

impl<'de> Deserialize<'de> for SlhDsaSha2128sSignature {
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

/// Shared SLH test fixture: one key and one signature, computed once for
/// the whole test binary.
///
/// SLH-DSA sign/verify each take seconds in a debug build (and far longer
/// under `cargo-tarpaulin` instrumentation, whose 60s test-response timeout
/// the un-shared suite tripped in CI). Tests that only need *a* valid
/// key/signature pair must use this fixture instead of signing again;
/// only the dedicated sign/verify tests pay for fresh operations.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{SlhDsaSha2128sPrivateKey, SlhDsaSha2128sPublicKey, SlhDsaSha2128sSignature};
    use std::sync::LazyLock;

    /// Message signed by the shared fixture signature.
    pub(crate) const MESSAGE: &[u8] = b"hello aptos";

    pub(crate) struct Fixture {
        pub(crate) private_key: SlhDsaSha2128sPrivateKey,
        pub(crate) public_key: SlhDsaSha2128sPublicKey,
        pub(crate) signature: SlhDsaSha2128sSignature,
    }

    static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
        let private_key = SlhDsaSha2128sPrivateKey::from_bytes(&[7u8; 48]).unwrap();
        let public_key = private_key.public_key();
        let signature = private_key.sign(MESSAGE);
        Fixture {
            private_key,
            public_key,
            signature,
        }
    });

    pub(crate) fn fixture() -> &'static Fixture {
        &FIXTURE
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{MESSAGE, fixture};
    use super::*;

    #[test]
    fn test_generate_and_sign() {
        let private_key = SlhDsaSha2128sPrivateKey::generate();
        let message = b"hello aptos";
        let signature = private_key.sign(message);
        assert_eq!(signature.bytes.len(), SLH_DSA_SHA2_128S_SIGNATURE_LENGTH);
        assert!(private_key.public_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        // Reuses the shared fixture signature; only the (failing) verify runs.
        let f = fixture();
        assert!(f.public_key.verify(b"wrong message", &f.signature).is_err());
    }

    #[test]
    fn test_signing_is_deterministic() {
        // aptos-crypto signs deterministically (empty context): re-signing
        // the fixture message with the fixture key must reproduce the
        // fixture signature byte-for-byte. One fresh sign, not two.
        let f = fixture();
        assert_eq!(f.private_key.sign(MESSAGE).bytes, f.signature.bytes);
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let private_key = &fixture().private_key;
        let restored = SlhDsaSha2128sPrivateKey::from_bytes(&private_key.to_bytes()).unwrap();
        assert_eq!(private_key.to_bytes(), restored.to_bytes());
        assert_eq!(private_key.public_key(), restored.public_key());
    }

    #[test]
    fn test_invalid_lengths() {
        assert!(SlhDsaSha2128sPrivateKey::from_bytes(&[0u8; 47]).is_err());
        assert!(SlhDsaSha2128sPrivateKey::from_bytes(&[0u8; 49]).is_err());
        assert!(SlhDsaSha2128sPublicKey::from_bytes(&[0u8; 31]).is_err());
        assert!(SlhDsaSha2128sSignature::from_bytes(&[0u8; 7855]).is_err());
    }

    #[test]
    fn test_aip80_roundtrip() {
        let private_key = &fixture().private_key;
        let aip80 = private_key.to_aip80();
        assert!(aip80.starts_with("slh-dsa-sha2-128s-priv-0x"));
        assert_eq!(
            SlhDsaSha2128sPrivateKey::from_aip80(&aip80)
                .unwrap()
                .to_bytes(),
            private_key.to_bytes()
        );
        assert!(SlhDsaSha2128sPrivateKey::from_aip80("ed25519-priv-0x01").is_err());

        let public_key = &fixture().public_key;
        let aip80 = public_key.to_aip80();
        assert!(aip80.starts_with("slh-dsa-sha2-128s-pub-0x"));
        assert_eq!(
            SlhDsaSha2128sPublicKey::from_aip80(&aip80).unwrap(),
            *public_key
        );
    }

    #[test]
    fn test_hex_roundtrip() {
        let f = fixture();
        assert_eq!(
            SlhDsaSha2128sPrivateKey::from_hex(&f.private_key.to_hex())
                .unwrap()
                .to_bytes(),
            f.private_key.to_bytes()
        );
        assert_eq!(
            SlhDsaSha2128sSignature::from_hex(&f.signature.to_hex())
                .unwrap()
                .bytes,
            f.signature.bytes
        );
    }

    #[test]
    fn test_bcs_framing() {
        // Framing only: reuses the fixture key/signature, no signing.
        let f = fixture();
        let bcs_pk = f.public_key.to_bcs_bytes();
        assert_eq!(bcs_pk.len(), 1 + 1 + 32);
        assert_eq!(bcs_pk[0], 5, "AnyPublicKey::SlhDsa_Sha2_128s variant");
        assert_eq!(bcs_pk[1], 32, "ULEB128(32)");

        let bcs_sig = f.signature.to_bcs_bytes();
        // ULEB128(7856) = [0xB0, 0x3D]
        assert_eq!(bcs_sig[0], 4, "AnySignature::SlhDsa_Sha2_128s variant");
        assert_eq!(&bcs_sig[1..3], &[0xB0, 0x3D], "ULEB128(7856)");
        assert_eq!(bcs_sig.len(), 1 + 2 + SLH_DSA_SHA2_128S_SIGNATURE_LENGTH);
    }

    #[test]
    fn test_address_derivation() {
        let public_key = &fixture().public_key;
        let address = public_key.to_address();
        assert!(!address.is_zero());
        assert_eq!(address, public_key.to_address());
        assert_eq!(address.as_bytes(), &public_key.to_authentication_key());
    }

    #[test]
    fn test_json_serialization() {
        let f = fixture();
        let json = serde_json::to_string(&f.public_key).unwrap();
        assert_eq!(
            serde_json::from_str::<SlhDsaSha2128sPublicKey>(&json).unwrap(),
            f.public_key
        );
        let json = serde_json::to_string(&f.signature).unwrap();
        assert_eq!(
            serde_json::from_str::<SlhDsaSha2128sSignature>(&json)
                .unwrap()
                .bytes,
            f.signature.bytes
        );
    }

    #[test]
    fn test_traits() {
        use crate::crypto::traits::{PublicKey as _, Signature as _};

        // Trait-object surface over the shared fixture: trait `sign` must
        // reproduce the (deterministic) fixture signature, and trait
        // `verify` must accept it. One sign + one verify total.
        let f = fixture();
        let signature = <SlhDsaSha2128sPrivateKey as Signer>::sign(&f.private_key, MESSAGE);
        assert_eq!(signature.bytes, f.signature.bytes);
        let public_key = <SlhDsaSha2128sPrivateKey as Signer>::public_key(&f.private_key);
        assert_eq!(public_key, f.public_key);
        assert!(
            <SlhDsaSha2128sPublicKey as Verifier>::verify(&public_key, MESSAGE, &signature).is_ok()
        );
        assert_eq!(SlhDsaSha2128sPublicKey::LENGTH, 32);
        assert_eq!(SlhDsaSha2128sSignature::LENGTH, 7856);
    }

    #[test]
    fn test_private_key_debug_redacted() {
        let private_key = &fixture().private_key;
        let debug = format!("{private_key:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(&private_key.to_hex()));
    }

    #[test]
    fn test_fixed_seed_public_key_cross_sdk_vector() {
        // Seeds 0x00..0x2f: keygen output confirmed identical between this
        // crate (RustCrypto `slh-dsa`) and `@noble/post-quantum` 0.5.4 (the
        // TypeScript SDK's implementation), and signatures cross-verify in
        // both directions.
        let seeds: Vec<u8> = (0u8..48).collect();
        let private_key = SlhDsaSha2128sPrivateKey::from_bytes(&seeds).unwrap();
        assert_eq!(
            private_key.public_key().to_hex(),
            "0x202122232425262728292a2b2c2d2e2f990ce6298792b128846a8e4a3a68954c"
        );
    }

    /// The cached expanded key must zeroize its seed material on drop (the
    /// reason the `Zeroize` derive above may skip it).
    #[test]
    fn test_inner_key_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SlhSigningKey>();
    }

    /// HD derivation vectors ported from `aptos-ts-sdk`'s `hdKey.test.ts`
    /// (PR #802): seed `000102...0f`, SLIP-0010 with the
    /// `"SLH-DSA-SHA2-128s seed"` master-key string, hardened-only.
    #[test]
    fn test_hd_derivation_ts_vectors() {
        const HARDENED: u32 = 0x8000_0000;
        let seed = const_hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let vectors: &[(&[u32], &str)] = &[
            (
                &[],
                "53c14b2681fcca8600d3ac7ce3459d6ceece7abc0a3b4c0376fc845c1b6503d66c5107d9484171c02f9eb0409849fceb",
            ),
            (
                &[HARDENED],
                "473049c70d5414379363b94f52de6b194c9f1651cb6a11b80cfee19f6ca67975201cdbec137ff57e2e9cd434fca0680d",
            ),
            (
                &[HARDENED, 1 | HARDENED],
                "b609bf21df9baae65045e2bb8c200e97fbf86201f58e4187197a60bfc827158e6ba452ffe50f57849c022b24d01ac123",
            ),
            (
                &[HARDENED, 1 | HARDENED, 2 | HARDENED],
                "60b55f07c62916f7f27a96be371a9e87adedb9acabd84d25c41e8aa5c8c326e2e64024132f8833181bc2ab008541ef2b",
            ),
            (
                &[HARDENED, 1 | HARDENED, 2 | HARDENED, 2 | HARDENED],
                "fb7242320fc3bc620587cfdfa54c2abed7d034f6c616ade3a9ad1780a099b268ed7a5bea0297711e997ff199b24bb82b",
            ),
            (
                &[
                    HARDENED,
                    1 | HARDENED,
                    2 | HARDENED,
                    2 | HARDENED,
                    0x3B9A_CA00 | HARDENED,
                ],
                "c72d4e3fb352a785aa375be20e0767ae20edbce1e18de90e0ea6e9d1677d17e84a410bb833bf091655dfabde17cc2011",
            ),
        ];
        for (path, expected_hex) in vectors {
            let key = SlhDsaSha2128sPrivateKey::from_seed_and_path(&seed, path);
            assert_eq!(
                const_hex::encode(key.to_bytes()),
                *expected_hex,
                "path {path:?}"
            );
        }
    }
}
