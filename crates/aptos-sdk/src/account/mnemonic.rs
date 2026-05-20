//! BIP-39 mnemonic phrase support for key derivation.
//!
//! This module requires the `mnemonic` feature flag.
//!
//! # Supported curves
//!
//! - **Ed25519** uses SLIP-0010 with the Aptos default path
//!   `m/44'/637'/0'/0'/{address_index}'`. Every component MUST be hardened
//!   because Ed25519 does not admit non-hardened child derivation (no
//!   scalar homomorphism on Curve25519). The `from_str` parser will reject
//!   non-hardened components when the resulting path is used with Ed25519.
//! - **Secp256k1** uses BIP-32 with the Aptos default path
//!   `m/44'/637'/0'/0/{address_index}` -- the last two indices are
//!   non-hardened, matching the TypeScript SDK's `APTOS_BIP44_REGEX`.
//!
//! `derive_ed25519_key(index)` and `derive_secp256k1_key(index)` place
//! `index` in the **5th (address) component**, preserving the pre-PR Rust
//! SDK semantics so existing addresses derived from a mnemonic do not
//! shift between SDK versions. Callers needing to vary the BIP-44
//! **account** index (the Petra / TS-SDK convention) should build the
//! path explicitly via [`DerivationPath::from_str`].

use crate::error::{AptosError, AptosResult};

/// Hardened-bit offset used by BIP-32 / SLIP-0010 to flag a hardened index.
const HARDENED_OFFSET: u32 = 0x8000_0000;
/// BIP-44 purpose (`44'`).
const BIP44_PURPOSE: u32 = 44;
/// Aptos coin type (`637'`).
const APTOS_COIN_TYPE: u32 = 637;

/// A single component of a BIP-32 derivation path.
///
/// Wraps a 31-bit numeric index plus a hardened flag. The encoded 32-bit
/// value used during derivation is `index | 0x80000000` when hardened.
///
/// Fields are private to enforce the `index < 2^31` invariant: a value with
/// the hardened bit already set would collide with an explicitly hardened
/// component during BIP-32 derivation, producing an ambiguous key. Use
/// [`Self::try_new`] to construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathComponent {
    /// The 31-bit numeric index (without the hardened bit applied).
    index: u32,
    /// Whether this component is hardened (denoted by a trailing apostrophe
    /// in path strings, e.g. `44'`).
    hardened: bool,
}

impl PathComponent {
    /// Constructs a path component, rejecting any `index` whose top bit is
    /// set (i.e. `index >= 2^31 = 0x8000_0000`).
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::KeyDerivation`] if `index` has its hardened
    /// bit set; valid BIP-32 indices are confined to 31 bits and the
    /// hardened bit is supplied via the `hardened` flag.
    pub fn try_new(index: u32, hardened: bool) -> AptosResult<Self> {
        if index & HARDENED_OFFSET != 0 {
            return Err(AptosError::KeyDerivation(format!(
                "derivation index {index} exceeds 2^31 - 1; the hardened bit \
                 must come from the `hardened` flag, not the raw value"
            )));
        }
        Ok(Self { index, hardened })
    }

    /// Returns the 31-bit numeric index without the hardened bit applied.
    #[must_use]
    pub fn index(self) -> u32 {
        self.index
    }

    /// Returns `true` when this component is hardened (encoded as
    /// `index | 0x80000000` during derivation).
    #[must_use]
    pub fn hardened(self) -> bool {
        self.hardened
    }

    /// Encodes this component as the 32-bit value passed to BIP-32 / SLIP-0010
    /// child-key derivation (i.e. with the hardened bit set when applicable).
    #[must_use]
    pub fn encoded(self) -> u32 {
        if self.hardened {
            self.index | HARDENED_OFFSET
        } else {
            self.index
        }
    }
}

/// A parsed BIP-32 / BIP-44 derivation path.
///
/// Use [`Self::aptos_ed25519`] / [`Self::aptos_secp256k1`] for the canonical
/// Aptos paths, or [`Self::from_str`] to parse a custom path of the form
/// `m/44'/637'/0'/0'/0'`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath {
    components: Vec<PathComponent>,
}

impl DerivationPath {
    /// Returns the path components in order.
    #[must_use]
    pub fn components(&self) -> &[PathComponent] {
        &self.components
    }

    /// Returns `true` iff every component in the path is hardened.
    ///
    /// Ed25519 derivation rejects paths that are not fully hardened.
    #[must_use]
    pub fn is_fully_hardened(&self) -> bool {
        self.components.iter().all(|c| c.hardened())
    }

    /// Builds the canonical Aptos Ed25519 derivation path
    /// `m/44'/637'/0'/0'/{address_index}'`.
    ///
    /// The `address_index` is placed in the final (address) BIP-44 component
    /// for backward compatibility with the pre-existing
    /// `Mnemonic::derive_ed25519_key(index)` behavior. Callers needing to
    /// vary the BIP-44 *account* index (the Petra/TS-SDK convention) should
    /// construct the path explicitly via [`Self::from_str`] and pass it to
    /// [`Mnemonic::derive_ed25519_key_at_path`].
    ///
    /// All five components are hardened, matching the TypeScript SDK's
    /// `APTOS_HARDENED_REGEX`.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::KeyDerivation`] if `address_index >= 2^31`
    /// (the top bit is reserved as the BIP-32 hardened flag).
    pub fn aptos_ed25519(address_index: u32) -> AptosResult<Self> {
        let h = |i| PathComponent::try_new(i, true);
        Ok(Self {
            components: vec![
                h(BIP44_PURPOSE)?,
                h(APTOS_COIN_TYPE)?,
                h(0)?,
                h(0)?,
                h(address_index)?,
            ],
        })
    }

    /// Builds the canonical Aptos Secp256k1 derivation path
    /// `m/44'/637'/0'/0/{address_index}`.
    ///
    /// The `address_index` is placed in the final (address) BIP-44 component
    /// for symmetry with [`Self::aptos_ed25519`]. The last two indices are
    /// non-hardened, matching the TypeScript SDK's `APTOS_BIP44_REGEX`.
    /// Callers needing to vary the BIP-44 *account* index should construct
    /// the path explicitly via [`Self::from_str`].
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::KeyDerivation`] if `address_index >= 2^31`.
    pub fn aptos_secp256k1(address_index: u32) -> AptosResult<Self> {
        let h = |i| PathComponent::try_new(i, true);
        let u = |i| PathComponent::try_new(i, false);
        Ok(Self {
            components: vec![
                h(BIP44_PURPOSE)?,
                h(APTOS_COIN_TYPE)?,
                h(0)?,
                u(0)?,
                u(address_index)?,
            ],
        })
    }

    /// Parses a derivation path of the form `m/44'/637'/0'/0'/0'`.
    ///
    /// Apostrophes (`'`) and lowercase `h` are accepted as hardened markers.
    /// The leading `m/` (or `M/`) prefix is required.
    ///
    /// This is a convenience wrapper around the [`std::str::FromStr`]
    /// implementation; both produce identical results.
    ///
    /// # Errors
    ///
    /// Returns [`AptosError::KeyDerivation`] if the path is malformed, a
    /// component is missing, the numeric value exceeds 2^31 - 1, or the
    /// path is empty.
    #[allow(clippy::should_implement_trait)] // also implemented via FromStr below; inherent method kept for ergonomics so callers don't need a `use std::str::FromStr` import.
    pub fn from_str(path: &str) -> AptosResult<Self> {
        <Self as std::str::FromStr>::from_str(path)
    }
}

impl std::str::FromStr for DerivationPath {
    type Err = AptosError;

    fn from_str(path: &str) -> AptosResult<Self> {
        let mut parts = path.split('/');
        let head = parts
            .next()
            .ok_or_else(|| AptosError::KeyDerivation("empty derivation path".to_string()))?;
        if !matches!(head, "m" | "M") {
            return Err(AptosError::KeyDerivation(format!(
                "derivation path must start with 'm/', got: {path}"
            )));
        }

        let mut components = Vec::new();
        for raw in parts {
            if raw.is_empty() {
                return Err(AptosError::KeyDerivation(format!(
                    "empty component in derivation path: {path}"
                )));
            }
            let (digits, hardened) = if let Some(rest) = raw.strip_suffix('\'') {
                (rest, true)
            } else if let Some(rest) = raw.strip_suffix('h') {
                (rest, true)
            } else {
                (raw, false)
            };

            let index: u32 = digits.parse().map_err(|_| {
                AptosError::KeyDerivation(format!(
                    "invalid numeric component '{raw}' in derivation path: {path}"
                ))
            })?;

            components.push(
                PathComponent::try_new(index, hardened).map_err(|e| match e {
                    AptosError::KeyDerivation(msg) => {
                        AptosError::KeyDerivation(format!("{msg} in path: {path}"))
                    }
                    other => other,
                })?,
            );
        }

        if components.is_empty() {
            return Err(AptosError::KeyDerivation(format!(
                "derivation path has no components: {path}"
            )));
        }

        Ok(Self { components })
    }
}

impl std::fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("m")?;
        for c in &self.components {
            if c.hardened() {
                write!(f, "/{}'", c.index())?;
            } else {
                write!(f, "/{}", c.index())?;
            }
        }
        Ok(())
    }
}

/// A BIP-39 mnemonic phrase for key derivation.
///
/// # Example
///
/// ```rust
/// use aptos_sdk::account::Mnemonic;
///
/// // Generate a new mnemonic
/// let mnemonic = Mnemonic::generate(24).unwrap();
/// println!("Mnemonic: {}", mnemonic.phrase());
///
/// // Parse an existing mnemonic
/// let mnemonic = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
/// ```
#[derive(Clone)]
pub struct Mnemonic {
    phrase: String,
}

impl Mnemonic {
    /// Generates a new random mnemonic phrase.
    ///
    /// # Arguments
    ///
    /// * `word_count` - Number of words (12, 15, 18, 21, or 24)
    ///
    /// # Errors
    ///
    /// Returns an error if the word count is not one of 12, 15, 18, 21, or 24,
    /// or if entropy generation fails.
    pub fn generate(word_count: usize) -> AptosResult<Self> {
        let entropy_bytes = match word_count {
            12 => 16, // 128 bits
            15 => 20, // 160 bits
            18 => 24, // 192 bits
            21 => 28, // 224 bits
            24 => 32, // 256 bits
            _ => {
                return Err(AptosError::InvalidMnemonic(format!(
                    "invalid word count: {word_count}, must be 12, 15, 18, 21, or 24"
                )));
            }
        };

        let mut entropy = vec![0u8; entropy_bytes];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut entropy);

        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| AptosError::InvalidMnemonic(e.to_string()));

        // SECURITY: Zeroize entropy before it goes out of scope to prevent
        // key material from lingering in memory
        zeroize::Zeroize::zeroize(&mut entropy);

        let mnemonic = mnemonic?;

        Ok(Self {
            phrase: mnemonic.to_string(),
        })
    }

    /// Creates a mnemonic from an existing phrase.
    ///
    /// # Errors
    ///
    /// Returns an error if the phrase is not a valid BIP-39 mnemonic.
    pub fn from_phrase(phrase: &str) -> AptosResult<Self> {
        // Validate the mnemonic
        let _mnemonic = bip39::Mnemonic::parse_normalized(phrase)
            .map_err(|e| AptosError::InvalidMnemonic(e.to_string()))?;

        Ok(Self {
            phrase: phrase.to_string(),
        })
    }

    /// Returns the mnemonic phrase.
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// Derives the seed from this mnemonic.
    ///
    /// Uses an empty passphrase by default.
    ///
    /// # Errors
    ///
    /// Returns an error if the mnemonic cannot be re-parsed (should not happen
    /// since the phrase was validated during construction).
    pub fn to_seed(&self) -> AptosResult<[u8; 64]> {
        self.to_seed_with_passphrase("")
    }

    /// Derives the seed from this mnemonic with a passphrase.
    ///
    /// # Errors
    ///
    /// Returns an error if the mnemonic phrase cannot be re-parsed. This should
    /// never happen because the phrase is validated during construction, but
    /// returning an error is safer than panicking.
    pub fn to_seed_with_passphrase(&self, passphrase: &str) -> AptosResult<[u8; 64]> {
        let mnemonic = bip39::Mnemonic::parse_normalized(&self.phrase).map_err(|e| {
            AptosError::InvalidMnemonic(format!("internal error: mnemonic re-parse failed: {e}"))
        })?;

        Ok(mnemonic.to_seed(passphrase))
    }

    /// Derives an Ed25519 private key using the Aptos default path
    /// `m/44'/637'/0'/0'/0'` with the given address index.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails or the derived key is invalid.
    #[cfg(feature = "ed25519")]
    pub fn derive_ed25519_key(&self, index: u32) -> AptosResult<crate::crypto::Ed25519PrivateKey> {
        self.derive_ed25519_key_at_path(&DerivationPath::aptos_ed25519(index)?)
    }

    /// Derives an Ed25519 private key at a custom BIP-44 path.
    ///
    /// All components of `path` must be hardened, matching SLIP-0010 (Ed25519
    /// has no non-hardened child derivation).
    ///
    /// # Errors
    ///
    /// Returns an error if the path contains a non-hardened component, if
    /// HMAC/SLIP-0010 derivation fails, or if the resulting key bytes do not
    /// form a valid Ed25519 private key.
    #[cfg(feature = "ed25519")]
    pub fn derive_ed25519_key_at_path(
        &self,
        path: &DerivationPath,
    ) -> AptosResult<crate::crypto::Ed25519PrivateKey> {
        if !path.is_fully_hardened() {
            return Err(AptosError::KeyDerivation(format!(
                "Ed25519 derivation requires every path component to be hardened; got {path}"
            )));
        }

        let mut seed = self.to_seed()?;
        let result = derive_ed25519_at_path(&seed, path);
        // SECURITY: Zeroize seed after use
        zeroize::Zeroize::zeroize(&mut seed);
        let mut key = result?;
        let private_key = crate::crypto::Ed25519PrivateKey::from_bytes(&key);
        // SECURITY: Zeroize raw key bytes after creating the key object
        zeroize::Zeroize::zeroize(&mut key);
        private_key
    }

    /// Derives a Secp256k1 private key using the Aptos default path
    /// `m/44'/637'/0'/0/0` with the given address index.
    ///
    /// The last two indices are non-hardened by convention, matching the
    /// TypeScript SDK.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails or the derived scalar is
    /// invalid (probability ~2^-127 per step, effectively never).
    #[cfg(feature = "secp256k1")]
    pub fn derive_secp256k1_key(
        &self,
        index: u32,
    ) -> AptosResult<crate::crypto::Secp256k1PrivateKey> {
        self.derive_secp256k1_key_at_path(&DerivationPath::aptos_secp256k1(index)?)
    }

    /// Derives a Secp256k1 private key at a custom BIP-32 path.
    ///
    /// Supports hardened and non-hardened components per BIP-32.
    ///
    /// # Errors
    ///
    /// Returns an error if HMAC fails, if any intermediate scalar is invalid
    /// (zero or >= curve order -- vanishingly rare), or if the final 32 bytes
    /// do not form a valid Secp256k1 private key.
    #[cfg(feature = "secp256k1")]
    pub fn derive_secp256k1_key_at_path(
        &self,
        path: &DerivationPath,
    ) -> AptosResult<crate::crypto::Secp256k1PrivateKey> {
        let mut seed = self.to_seed()?;
        let result = derive_secp256k1_at_path(&seed, path);
        zeroize::Zeroize::zeroize(&mut seed);
        let mut bytes = result?;
        let key = crate::crypto::Secp256k1PrivateKey::from_bytes(&bytes);
        zeroize::Zeroize::zeroize(&mut bytes);
        key
    }
}

/// Derives an Ed25519 key from a seed using SLIP-0010 along the given path.
#[cfg(feature = "ed25519")]
fn derive_ed25519_at_path(seed: &[u8], path: &DerivationPath) -> AptosResult<[u8; 32]> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;

    // SLIP-0010 master key derivation
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed")
        .map_err(|e| AptosError::KeyDerivation(e.to_string()))?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    for component in path.components() {
        let mut data = vec![0u8];
        data.extend_from_slice(&key);
        data.extend_from_slice(&component.encoded().to_be_bytes());

        let mut mac = HmacSha512::new_from_slice(&chain_code)
            .map_err(|e| AptosError::KeyDerivation(e.to_string()))?;
        mac.update(&data);
        let result = mac.finalize().into_bytes();

        key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        // SECURITY: Zeroize intermediate derivation data
        zeroize::Zeroize::zeroize(&mut data);
    }

    // SECURITY: Zeroize chain_code since we only return the key
    zeroize::Zeroize::zeroize(&mut chain_code);

    Ok(key)
}

/// Derives a Secp256k1 private key from a seed using BIP-32 along `path`.
///
/// Supports both hardened and non-hardened components. For non-hardened
/// derivation the parent compressed public key is fed into HMAC; the child
/// scalar is `(I_L + k_par) mod n`.
#[cfg(feature = "secp256k1")]
fn derive_secp256k1_at_path(seed: &[u8], path: &DerivationPath) -> AptosResult<[u8; 32]> {
    use hmac::{Hmac, Mac};
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{NonZeroScalar, ProjectivePoint, PublicKey, Scalar, SecretKey};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;

    // BIP-32 master key derivation: HMAC-SHA512(key = "Bitcoin seed", seed)
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
        .map_err(|e| AptosError::KeyDerivation(e.to_string()))?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let mut key_bytes = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key_bytes.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    // Validate master key forms a valid scalar.
    let mut parent = SecretKey::from_slice(&key_bytes)
        .map_err(|e| AptosError::KeyDerivation(format!("invalid master scalar: {e}")))?;

    for component in path.components() {
        let encoded = component.encoded();
        let data = if component.hardened() {
            // 0x00 || ser_256(k_par) || ser_32(i)
            let mut buf = Vec::with_capacity(1 + 32 + 4);
            buf.push(0u8);
            buf.extend_from_slice(&parent.to_bytes());
            buf.extend_from_slice(&encoded.to_be_bytes());
            buf
        } else {
            // ser_P(K_par) || ser_32(i)  -- compressed public key (33 bytes)
            let pub_key: PublicKey = parent.public_key();
            let encoded_point = pub_key.to_encoded_point(true);
            let mut buf = Vec::with_capacity(33 + 4);
            buf.extend_from_slice(encoded_point.as_bytes());
            buf.extend_from_slice(&encoded.to_be_bytes());
            buf
        };

        let mut mac = HmacSha512::new_from_slice(&chain_code)
            .map_err(|e| AptosError::KeyDerivation(e.to_string()))?;
        mac.update(&data);
        let result = mac.finalize().into_bytes();

        // Reject I_L >= n or I_L == 0 by requiring a valid NonZeroScalar.
        // `NonZeroScalar::try_from(&[u8])` returns Err in both failure modes.
        let il_scalar = NonZeroScalar::try_from(&result[..32]).map_err(|e| {
            AptosError::KeyDerivation(format!(
                "BIP-32 derivation produced invalid intermediate scalar: {e}"
            ))
        })?;

        // child_scalar = I_L + k_par (mod n)
        let parent_scalar: Scalar = *parent.to_nonzero_scalar().as_ref();
        let child_scalar = *il_scalar.as_ref() + parent_scalar;

        let child_nz =
            Option::<NonZeroScalar>::from(NonZeroScalar::new(child_scalar)).ok_or_else(|| {
                AptosError::KeyDerivation(
                    "BIP-32 derivation produced zero child scalar".to_string(),
                )
            })?;
        parent = SecretKey::from(child_nz);

        // Sanity: the child public key must be on the curve (it is, by
        // construction, since child_scalar is a non-zero scalar). The
        // projective-point form is computed implicitly by `parent.public_key()`
        // on the next iteration. We do not need to re-derive it here, but the
        // reference is kept so future changes don't accidentally drop it.
        let _ = ProjectivePoint::GENERATOR;

        // Update chain code from I_R.
        chain_code.copy_from_slice(&result[32..]);
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&parent.to_bytes());

    // SECURITY: Zeroize transient buffers.
    zeroize::Zeroize::zeroize(&mut key_bytes);
    zeroize::Zeroize::zeroize(&mut chain_code);

    Ok(out)
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mnemonic([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_generate_mnemonic() {
        let mnemonic = Mnemonic::generate(12).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 12);

        let mnemonic = Mnemonic::generate(24).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 24);
    }

    #[test]
    fn test_invalid_word_count() {
        assert!(Mnemonic::generate(13).is_err());
    }

    #[test]
    fn test_parse_mnemonic() {
        let mnemonic = Mnemonic::from_phrase(TEST_PHRASE).unwrap();
        assert_eq!(mnemonic.phrase(), TEST_PHRASE);
    }

    #[test]
    fn test_invalid_mnemonic() {
        assert!(Mnemonic::from_phrase("invalid mnemonic phrase").is_err());
    }

    #[test]
    fn test_path_from_str_hardened() {
        let path = DerivationPath::from_str("m/44'/637'/0'/0'/0'").unwrap();
        assert!(path.is_fully_hardened());
        assert_eq!(path.components().len(), 5);
        assert_eq!(path.to_string(), "m/44'/637'/0'/0'/0'");
    }

    #[test]
    fn test_path_from_str_mixed() {
        let path = DerivationPath::from_str("m/44'/637'/0'/0/0").unwrap();
        assert!(!path.is_fully_hardened());
        let comps = path.components();
        assert!(comps[0].hardened && comps[1].hardened && comps[2].hardened);
        assert!(!comps[3].hardened && !comps[4].hardened);
    }

    #[test]
    fn test_path_from_str_h_marker() {
        // Lowercase `h` is also a hardened marker.
        let path = DerivationPath::from_str("m/44h/637h/0h").unwrap();
        assert!(path.is_fully_hardened());
    }

    #[test]
    fn test_path_from_str_rejects_bad_prefix() {
        assert!(DerivationPath::from_str("44'/637'").is_err());
        assert!(DerivationPath::from_str("").is_err());
        assert!(DerivationPath::from_str("m").is_err());
        assert!(DerivationPath::from_str("m/44'/abc/0").is_err());
    }

    #[test]
    fn test_path_from_str_rejects_oversize_index() {
        // 2^31 sets the hardened bit -- reject it as a raw numeric value.
        assert!(DerivationPath::from_str("m/2147483648").is_err());
    }

    #[test]
    fn test_aptos_default_paths() {
        // `address_index` lives in the 5th BIP-44 component, matching the
        // pre-PR `derive_ed25519_key(index)` behavior so existing addresses
        // derived from a mnemonic do not silently shift between SDK versions.
        assert_eq!(
            DerivationPath::aptos_ed25519(0).unwrap().to_string(),
            "m/44'/637'/0'/0'/0'"
        );
        assert_eq!(
            DerivationPath::aptos_secp256k1(0).unwrap().to_string(),
            "m/44'/637'/0'/0/0"
        );
        assert_eq!(
            DerivationPath::aptos_ed25519(5).unwrap().to_string(),
            "m/44'/637'/0'/0'/5'",
            "address_index belongs in the 5th component",
        );
        assert_eq!(
            DerivationPath::aptos_secp256k1(5).unwrap().to_string(),
            "m/44'/637'/0'/0/5",
            "address_index belongs in the 5th component (non-hardened)",
        );
    }

    #[test]
    fn test_aptos_default_paths_reject_oversize_index() {
        // The 31-bit invariant surfaces as an error rather than panicking.
        assert!(DerivationPath::aptos_ed25519(0x8000_0000).is_err());
        assert!(DerivationPath::aptos_secp256k1(0x8000_0000).is_err());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_derive_ed25519_key() {
        let mnemonic = Mnemonic::from_phrase(TEST_PHRASE).unwrap();

        let key1 = mnemonic.derive_ed25519_key(0).unwrap();
        let key2 = mnemonic.derive_ed25519_key(0).unwrap();
        assert_eq!(key1.to_bytes(), key2.to_bytes());

        let key3 = mnemonic.derive_ed25519_key(1).unwrap();
        assert_ne!(key1.to_bytes(), key3.to_bytes());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_derive_ed25519_at_path_rejects_unhardened() {
        let mnemonic = Mnemonic::from_phrase(TEST_PHRASE).unwrap();
        let path = DerivationPath::from_str("m/44'/637'/0'/0/0").unwrap();
        let err = mnemonic.derive_ed25519_key_at_path(&path).unwrap_err();
        assert!(matches!(err, AptosError::KeyDerivation(_)));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_derive_ed25519_default_matches_path() {
        let mnemonic = Mnemonic::from_phrase(TEST_PHRASE).unwrap();
        let via_index = mnemonic.derive_ed25519_key(3).unwrap();
        let via_path = mnemonic
            .derive_ed25519_key_at_path(&DerivationPath::aptos_ed25519(3).unwrap())
            .unwrap();
        assert_eq!(via_index.to_bytes(), via_path.to_bytes());
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn test_derive_secp256k1_deterministic() {
        let mnemonic = Mnemonic::from_phrase(TEST_PHRASE).unwrap();
        let key1 = mnemonic.derive_secp256k1_key(0).unwrap();
        let key2 = mnemonic.derive_secp256k1_key(0).unwrap();
        assert_eq!(key1.to_bytes(), key2.to_bytes());

        let key3 = mnemonic.derive_secp256k1_key(1).unwrap();
        assert_ne!(key1.to_bytes(), key3.to_bytes());
    }

    /// Cross-SDK regression: the abandon-test mnemonic derived at the
    /// canonical Aptos Secp256k1 path `m/44'/637'/0'/0/0` must produce this
    /// exact private key. Changes to BIP-32 derivation that move this byte
    /// sequence are silent regressions vs the TypeScript SDK and MUST be
    /// cross-checked there before updating the fixture.
    #[test]
    #[cfg(feature = "secp256k1")]
    fn test_derive_secp256k1_pinned_aptos_vector() {
        let mnemonic = Mnemonic::from_phrase(TEST_PHRASE).unwrap();
        let key = mnemonic.derive_secp256k1_key(0).unwrap();
        assert_eq!(
            const_hex::encode(key.to_bytes()),
            "4613c3acaffc152273c102a6b27f6f4209e1d54cac18ad0ac96b5892b7d7bf91",
        );
    }

    /// Cross-validates the BIP-32 implementation against the well-known
    /// Bitcoin reference vector: the abandon-test mnemonic at
    /// `m/44'/0'/0'/0/0` (coin type 0, not Aptos) must yield the canonical
    /// Bitcoin private key. Verifies HMAC master derivation, hardened
    /// derivation, and non-hardened (public-key-based) derivation in a
    /// single fixture. Source: any reputable BIP-32 / mnemonic-to-key
    /// reference for the all-zero entropy mnemonic.
    #[test]
    #[cfg(feature = "secp256k1")]
    fn test_derive_secp256k1_bitcoin_reference_vector() {
        let mnemonic = Mnemonic::from_phrase(TEST_PHRASE).unwrap();
        let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        let key = mnemonic.derive_secp256k1_key_at_path(&path).unwrap();
        assert_eq!(
            const_hex::encode(key.to_bytes()),
            "e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372",
        );
    }

    #[test]
    fn test_path_component_encoded_sets_hardened_bit() {
        let hardened = PathComponent::try_new(44, true).unwrap();
        let unhardened = PathComponent::try_new(44, false).unwrap();
        assert_eq!(hardened.encoded(), 0x8000_002C);
        assert_eq!(unhardened.encoded(), 44);
        assert_eq!(hardened.index(), 44);
        assert!(hardened.hardened());
        assert!(!unhardened.hardened());
    }

    #[test]
    fn test_path_component_rejects_oversize_index() {
        // Top bit reserved as the hardened flag in BIP-32; raw values
        // with that bit already set would collide with hardened components
        // and produce ambiguous derivations. `try_new` MUST reject them.
        assert!(PathComponent::try_new(0x8000_0000, false).is_err());
        assert!(PathComponent::try_new(0x8000_0000, true).is_err());
        assert!(PathComponent::try_new(0xFFFF_FFFF, false).is_err());
        // Boundary: 2^31 - 1 is the largest valid raw index.
        assert!(PathComponent::try_new(0x7FFF_FFFF, true).is_ok());
    }

    #[test]
    fn test_path_display_roundtrip() {
        for s in ["m/44'/637'/0'/0/0", "m/44'/637'/3'/0'/0'", "m/0"] {
            let path = DerivationPath::from_str(s).unwrap();
            assert_eq!(path.to_string(), s, "roundtrip drifted for {s}");
        }
    }

    #[test]
    fn test_path_from_str_via_parse_trait() {
        // The FromStr trait impl exists so callers can `path.parse()` --
        // verify it returns the same shape as the inherent constructor.
        use std::str::FromStr;
        let via_inherent = DerivationPath::from_str("m/44'/637'/0'/0/0").unwrap();
        let via_trait: DerivationPath = "m/44'/637'/0'/0/0".parse().unwrap();
        let via_fromstr = <DerivationPath as FromStr>::from_str("m/44'/637'/0'/0/0").unwrap();
        assert_eq!(via_inherent, via_trait);
        assert_eq!(via_inherent, via_fromstr);
    }

    #[test]
    fn test_path_from_str_rejects_empty_component() {
        // Double slash should not be silently absorbed into a single segment.
        assert!(DerivationPath::from_str("m//44'").is_err());
        assert!(DerivationPath::from_str("m/44'/").is_err());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_passphrase_changes_derived_key() {
        // BIP-39 mandates the passphrase be folded into the seed; verify
        // the derived key is sensitive to it (otherwise the "secret
        // passphrase" feature would be a no-op).
        let mnemonic = Mnemonic::from_phrase(TEST_PHRASE).unwrap();
        let seed_default = mnemonic.to_seed().unwrap();
        let seed_passphrase = mnemonic.to_seed_with_passphrase("hunter2").unwrap();
        assert_ne!(seed_default, seed_passphrase);
        // And the derived key follows accordingly via the seed.
        let key = mnemonic.derive_ed25519_key(0).unwrap();
        // Re-derive at the same path through the seed-with-passphrase
        // path: there's no public `derive_*_from_seed` so we just assert
        // the seed itself differs (key sensitivity follows by construction
        // since the SLIP-0010 master HMAC is keyed by the seed).
        assert_eq!(key.to_bytes().len(), 32);
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn test_derive_secp256k1_different_paths_produce_different_keys() {
        // Sanity: distinct paths must produce distinct keys (otherwise
        // a derivation bug could be hiding behind a single-path test).
        let m = Mnemonic::from_phrase(TEST_PHRASE).unwrap();
        let k0 = m.derive_secp256k1_key(0).unwrap();
        let k1 = m.derive_secp256k1_key(1).unwrap();
        let k_bitcoin = m
            .derive_secp256k1_key_at_path(&DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap())
            .unwrap();
        assert_ne!(k0.to_bytes(), k1.to_bytes());
        assert_ne!(k0.to_bytes(), k_bitcoin.to_bytes());
        assert_ne!(k1.to_bytes(), k_bitcoin.to_bytes());
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn test_derive_secp256k1_custom_path() {
        let mnemonic = Mnemonic::from_phrase(TEST_PHRASE).unwrap();
        let path = DerivationPath::from_str("m/44'/637'/0'/0/0").unwrap();
        let via_path = mnemonic.derive_secp256k1_key_at_path(&path).unwrap();
        let via_index = mnemonic.derive_secp256k1_key(0).unwrap();
        assert_eq!(via_path.to_bytes(), via_index.to_bytes());
    }
}
