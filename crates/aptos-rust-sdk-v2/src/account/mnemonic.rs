//! BIP-39 mnemonic phrase support for key derivation.
//!
//! This module requires the `mnemonic` feature flag.

use crate::error::{AptosError, AptosResult};

/// A BIP-39 mnemonic phrase for key derivation.
///
/// # Example
///
/// ```rust
/// use aptos_rust_sdk_v2::account::Mnemonic;
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
    pub fn generate(word_count: usize) -> AptosResult<Self> {
        let entropy_bytes = match word_count {
            12 => 16, // 128 bits
            15 => 20, // 160 bits
            18 => 24, // 192 bits
            21 => 28, // 224 bits
            24 => 32, // 256 bits
            _ => {
                return Err(AptosError::InvalidMnemonic(format!(
                    "invalid word count: {}, must be 12, 15, 18, 21, or 24",
                    word_count
                )));
            }
        };

        let mut entropy = vec![0u8; entropy_bytes];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut entropy);

        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| AptosError::InvalidMnemonic(e.to_string()))?;

        Ok(Self {
            phrase: mnemonic.to_string(),
        })
    }

    /// Creates a mnemonic from an existing phrase.
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
    pub fn to_seed(&self) -> [u8; 64] {
        self.to_seed_with_passphrase("")
    }

    /// Derives the seed from this mnemonic with a passphrase.
    ///
    /// # Panics
    ///
    /// This function will never panic in normal operation because the mnemonic
    /// phrase is validated during construction (`from_phrase` or `generate`).
    /// The internal `expect` is a defensive check that should be unreachable.
    pub fn to_seed_with_passphrase(&self, passphrase: &str) -> [u8; 64] {
        // SAFETY: The mnemonic phrase was validated during construction.
        // This expect should never trigger in normal operation.
        let mnemonic = bip39::Mnemonic::parse_normalized(&self.phrase)
            .expect("internal error: mnemonic was validated during construction");

        mnemonic.to_seed(passphrase)
    }

    /// Derives an Ed25519 private key using the Aptos derivation path.
    ///
    /// Path: `m/44'/637'/0'/0'/index'`
    #[cfg(feature = "ed25519")]
    pub fn derive_ed25519_key(&self, index: u32) -> AptosResult<crate::crypto::Ed25519PrivateKey> {
        let seed = self.to_seed();
        let key = derive_ed25519_from_seed(&seed, index)?;
        crate::crypto::Ed25519PrivateKey::from_bytes(&key)
    }
}

/// Derives an Ed25519 key from a seed using the Aptos BIP-44 path.
///
/// This implements a simplified SLIP-0010 derivation for Ed25519.
#[cfg(feature = "ed25519")]
fn derive_ed25519_from_seed(seed: &[u8], index: u32) -> AptosResult<[u8; 32]> {
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

    // Aptos derivation path: m/44'/637'/0'/0'/index'
    // All indices are hardened (with 0x80000000 offset)
    let path = [
        44 | 0x80000000,    // 44' (purpose)
        637 | 0x80000000,   // 637' (Aptos coin type)
        0x80000000,         // 0' (account)
        0x80000000,         // 0' (change)
        index | 0x80000000, // index' (address index)
    ];

    for child_index in path {
        let mut data = vec![0u8];
        data.extend_from_slice(&key);
        data.extend_from_slice(&child_index.to_be_bytes());

        let mut mac = HmacSha512::new_from_slice(&chain_code)
            .map_err(|e| AptosError::KeyDerivation(e.to_string()))?;
        mac.update(&data);
        let result = mac.finalize().into_bytes();

        key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);
    }

    Ok(key)
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mnemonic([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        assert_eq!(mnemonic.phrase(), phrase);
    }

    #[test]
    fn test_invalid_mnemonic() {
        assert!(Mnemonic::from_phrase("invalid mnemonic phrase").is_err());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_derive_ed25519_key() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();

        let key1 = mnemonic.derive_ed25519_key(0).unwrap();
        let key2 = mnemonic.derive_ed25519_key(0).unwrap();
        assert_eq!(key1.to_bytes(), key2.to_bytes());

        let key3 = mnemonic.derive_ed25519_key(1).unwrap();
        assert_ne!(key1.to_bytes(), key3.to_bytes());
    }
}
