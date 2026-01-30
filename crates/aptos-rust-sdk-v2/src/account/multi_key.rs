//! MultiKey account implementation.
//!
//! This module provides the [`MultiKeyAccount`] type for M-of-N
//! threshold signature accounts with mixed key types.

use crate::account::account::{Account, AuthenticationKey};
use crate::crypto::{
    AnyPublicKey, AnyPublicKeyVariant, AnySignature, MULTI_KEY_SCHEME, MultiKeyPublicKey,
    MultiKeySignature,
};
use crate::error::{AptosError, AptosResult};
use crate::types::AccountAddress;
use std::fmt;

/// A private key that can be any supported signature scheme.
pub enum AnyPrivateKey {
    /// Ed25519 private key.
    #[cfg(feature = "ed25519")]
    Ed25519(crate::crypto::Ed25519PrivateKey),
    /// Secp256k1 private key.
    #[cfg(feature = "secp256k1")]
    Secp256k1(crate::crypto::Secp256k1PrivateKey),
    /// Secp256r1 private key.
    #[cfg(feature = "secp256r1")]
    Secp256r1(crate::crypto::Secp256r1PrivateKey),
}

impl AnyPrivateKey {
    /// Gets the signature scheme variant.
    #[allow(unreachable_code)]
    pub fn variant(&self) -> AnyPublicKeyVariant {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Ed25519(_) => AnyPublicKeyVariant::Ed25519,
            #[cfg(feature = "secp256k1")]
            Self::Secp256k1(_) => AnyPublicKeyVariant::Secp256k1,
            #[cfg(feature = "secp256r1")]
            Self::Secp256r1(_) => AnyPublicKeyVariant::Secp256r1,
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnyPrivateKey requires at least one crypto feature to be enabled"),
        }
    }

    /// Gets the public key.
    #[allow(unreachable_code)]
    pub fn public_key(&self) -> AnyPublicKey {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Ed25519(key) => AnyPublicKey::ed25519(&key.public_key()),
            #[cfg(feature = "secp256k1")]
            Self::Secp256k1(key) => AnyPublicKey::secp256k1(&key.public_key()),
            #[cfg(feature = "secp256r1")]
            Self::Secp256r1(key) => AnyPublicKey::secp256r1(&key.public_key()),
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnyPrivateKey requires at least one crypto feature to be enabled"),
        }
    }

    /// Signs a message.
    #[allow(unreachable_code, unused_variables)]
    pub fn sign(&self, message: &[u8]) -> AnySignature {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Ed25519(key) => AnySignature::ed25519(&key.sign(message)),
            #[cfg(feature = "secp256k1")]
            Self::Secp256k1(key) => AnySignature::secp256k1(&key.sign(message)),
            #[cfg(feature = "secp256r1")]
            Self::Secp256r1(key) => AnySignature::secp256r1(&key.sign(message)),
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnyPrivateKey requires at least one crypto feature to be enabled"),
        }
    }

    /// Creates an Ed25519 private key.
    #[cfg(feature = "ed25519")]
    pub fn ed25519(key: crate::crypto::Ed25519PrivateKey) -> Self {
        Self::Ed25519(key)
    }

    /// Creates a Secp256k1 private key.
    #[cfg(feature = "secp256k1")]
    pub fn secp256k1(key: crate::crypto::Secp256k1PrivateKey) -> Self {
        Self::Secp256k1(key)
    }

    /// Creates a Secp256r1 private key.
    #[cfg(feature = "secp256r1")]
    pub fn secp256r1(key: crate::crypto::Secp256r1PrivateKey) -> Self {
        Self::Secp256r1(key)
    }
}

impl Clone for AnyPrivateKey {
    #[allow(unreachable_code)]
    fn clone(&self) -> Self {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Ed25519(key) => Self::Ed25519(key.clone()),
            #[cfg(feature = "secp256k1")]
            Self::Secp256k1(key) => Self::Secp256k1(key.clone()),
            #[cfg(feature = "secp256r1")]
            Self::Secp256r1(key) => Self::Secp256r1(key.clone()),
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnyPrivateKey requires at least one crypto feature to be enabled"),
        }
    }
}

impl fmt::Debug for AnyPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AnyPrivateKey({:?})", self.variant())
    }
}

/// A multi-key account supporting M-of-N threshold signatures with mixed key types.
///
/// Unlike `MultiEd25519Account`, this account type supports mixed signature
/// schemes (e.g., 2-of-3 where one key is Ed25519 and two are Secp256k1).
///
/// # Example
///
/// ```rust,ignore
/// use aptos_rust_sdk_v2::account::{MultiKeyAccount, AnyPrivateKey};
/// use aptos_rust_sdk_v2::crypto::{Ed25519PrivateKey, Secp256k1PrivateKey};
///
/// // Create a 2-of-3 multisig with mixed key types
/// let keys = vec![
///     AnyPrivateKey::ed25519(Ed25519PrivateKey::generate()),
///     AnyPrivateKey::secp256k1(Secp256k1PrivateKey::generate()),
///     AnyPrivateKey::ed25519(Ed25519PrivateKey::generate()),
/// ];
/// let account = MultiKeyAccount::new(keys, 2).unwrap();
///
/// println!("Address: {}", account.address());
/// println!("Threshold: {}/{}", account.threshold(), account.num_keys());
/// ```
pub struct MultiKeyAccount {
    /// The private keys owned by this account (may be a subset).
    private_keys: Vec<(u8, AnyPrivateKey)>,
    /// The multi-key public key (contains all public keys).
    public_key: MultiKeyPublicKey,
    /// The derived account address.
    address: AccountAddress,
}

impl MultiKeyAccount {
    /// Creates a new multi-key account from private keys.
    ///
    /// All provided private keys will be used for signing. The threshold
    /// specifies how many signatures are required.
    ///
    /// # Arguments
    ///
    /// * `private_keys` - The private keys (can be mixed types)
    /// * `threshold` - The required number of signatures (M in M-of-N)
    pub fn new(private_keys: Vec<AnyPrivateKey>, threshold: u8) -> AptosResult<Self> {
        if private_keys.is_empty() {
            return Err(AptosError::InvalidPrivateKey(
                "at least one private key is required".into(),
            ));
        }
        if (threshold as usize) > private_keys.len() {
            return Err(AptosError::InvalidPrivateKey(format!(
                "threshold {} exceeds number of keys {}",
                threshold,
                private_keys.len()
            )));
        }

        let public_keys: Vec<_> = private_keys.iter().map(AnyPrivateKey::public_key).collect();
        let multi_public_key = MultiKeyPublicKey::new(public_keys, threshold)?;
        let address = multi_public_key.to_address();

        // Index the private keys (safe: validated by MultiKeyPublicKey::new above)
        #[allow(clippy::cast_possible_truncation)]
        let indexed_keys: Vec<_> = private_keys
            .into_iter()
            .enumerate()
            .map(|(i, k)| (i as u8, k))
            .collect();

        Ok(Self {
            private_keys: indexed_keys,
            public_key: multi_public_key,
            address,
        })
    }

    /// Creates a multi-key account from public keys with a subset of private keys.
    ///
    /// Use this when you don't have all the private keys.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - All the public keys in the account
    /// * `private_keys` - The private keys you own, with their indices
    /// * `threshold` - The required number of signatures
    pub fn from_keys(
        public_keys: Vec<AnyPublicKey>,
        private_keys: Vec<(u8, AnyPrivateKey)>,
        threshold: u8,
    ) -> AptosResult<Self> {
        let multi_public_key = MultiKeyPublicKey::new(public_keys, threshold)?;

        // Validate private key indices and types
        for (index, key) in &private_keys {
            if *index as usize >= multi_public_key.num_keys() {
                return Err(AptosError::InvalidPrivateKey(format!(
                    "private key index {index} out of bounds"
                )));
            }
            // Verify the private key matches the public key at that index
            let expected_pk = multi_public_key.get(*index as usize).unwrap();
            let actual_pk = key.public_key();
            if expected_pk.variant != actual_pk.variant || expected_pk.bytes != actual_pk.bytes {
                return Err(AptosError::InvalidPrivateKey(format!(
                    "private key at index {index} doesn't match public key"
                )));
            }
        }

        let address = multi_public_key.to_address();

        Ok(Self {
            private_keys,
            public_key: multi_public_key,
            address,
        })
    }

    /// Creates a view-only multi-key account (no signing capability).
    pub fn view_only(public_keys: Vec<AnyPublicKey>, threshold: u8) -> AptosResult<Self> {
        let multi_public_key = MultiKeyPublicKey::new(public_keys, threshold)?;
        let address = multi_public_key.to_address();

        Ok(Self {
            private_keys: vec![],
            public_key: multi_public_key,
            address,
        })
    }

    /// Returns the account address.
    pub fn address(&self) -> AccountAddress {
        self.address
    }

    /// Returns the multi-key public key.
    pub fn public_key(&self) -> &MultiKeyPublicKey {
        &self.public_key
    }

    /// Returns the number of keys in the account.
    pub fn num_keys(&self) -> usize {
        self.public_key.num_keys()
    }

    /// Returns the signature threshold.
    pub fn threshold(&self) -> u8 {
        self.public_key.threshold()
    }

    /// Returns the number of private keys we have.
    pub fn num_owned_keys(&self) -> usize {
        self.private_keys.len()
    }

    /// Checks if we can sign (have enough private keys to meet threshold).
    pub fn can_sign(&self) -> bool {
        self.private_keys.len() >= self.threshold() as usize
    }

    /// Returns the indices of the private keys we own.
    pub fn owned_key_indices(&self) -> Vec<u8> {
        self.private_keys.iter().map(|(i, _)| *i).collect()
    }

    /// Returns the key types for each index.
    pub fn key_types(&self) -> Vec<AnyPublicKeyVariant> {
        self.public_key
            .public_keys()
            .iter()
            .map(|pk| pk.variant)
            .collect()
    }

    /// Signs a message using the owned private keys.
    ///
    /// Will use up to `threshold` keys for signing.
    pub fn sign_message(&self, message: &[u8]) -> AptosResult<MultiKeySignature> {
        let threshold = self.threshold() as usize;
        if self.private_keys.len() < threshold {
            return Err(AptosError::InsufficientSignatures {
                required: threshold,
                provided: self.private_keys.len(),
            });
        }

        // Sign with the first `threshold` keys
        let signatures: Vec<_> = self.private_keys[..threshold]
            .iter()
            .map(|(index, key)| (*index, key.sign(message)))
            .collect();

        MultiKeySignature::new(signatures)
    }

    /// Signs a message using specific key indices.
    pub fn sign_with_indices(
        &self,
        message: &[u8],
        indices: &[u8],
    ) -> AptosResult<MultiKeySignature> {
        if indices.len() < self.threshold() as usize {
            return Err(AptosError::InsufficientSignatures {
                required: self.threshold() as usize,
                provided: indices.len(),
            });
        }

        let mut signatures = Vec::with_capacity(indices.len());

        for &index in indices {
            let key = self
                .private_keys
                .iter()
                .find(|(i, _)| *i == index)
                .ok_or_else(|| {
                    AptosError::InvalidPrivateKey(format!(
                        "don't have private key at index {index}"
                    ))
                })?;

            signatures.push((index, key.1.sign(message)));
        }

        MultiKeySignature::new(signatures)
    }

    /// Verifies a signature against a message.
    pub fn verify(&self, message: &[u8], signature: &MultiKeySignature) -> AptosResult<()> {
        self.public_key.verify(message, signature)
    }

    /// Returns the authentication key for this account.
    pub fn auth_key(&self) -> AuthenticationKey {
        AuthenticationKey::new(self.public_key.to_authentication_key())
    }

    /// Collects individual signatures into a multi-key signature.
    pub fn aggregate_signatures(
        signatures: Vec<(u8, AnySignature)>,
    ) -> AptosResult<MultiKeySignature> {
        MultiKeySignature::new(signatures)
    }

    /// Creates an individual signature contribution.
    pub fn create_signature_contribution(
        &self,
        message: &[u8],
        key_index: u8,
    ) -> AptosResult<(u8, AnySignature)> {
        let key = self
            .private_keys
            .iter()
            .find(|(i, _)| *i == key_index)
            .ok_or_else(|| {
                AptosError::InvalidPrivateKey(format!(
                    "don't have private key at index {key_index}"
                ))
            })?;

        Ok((key_index, key.1.sign(message)))
    }
}

impl Account for MultiKeyAccount {
    fn address(&self) -> AccountAddress {
        self.address
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes()
    }

    fn sign(&self, message: &[u8]) -> AptosResult<Vec<u8>> {
        let sig = self.sign_message(message)?;
        Ok(sig.to_bytes())
    }

    fn authentication_key(&self) -> AuthenticationKey {
        self.auth_key()
    }

    fn signature_scheme(&self) -> u8 {
        MULTI_KEY_SCHEME
    }
}

impl fmt::Debug for MultiKeyAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultiKeyAccount")
            .field("address", &self.address)
            .field(
                "keys",
                &format!(
                    "{}-of-{} (own {})",
                    self.threshold(),
                    self.num_keys(),
                    self.num_owned_keys()
                ),
            )
            .field("types", &self.key_types())
            .finish()
    }
}

impl fmt::Display for MultiKeyAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MultiKeyAccount({}, {}-of-{})",
            self.address.to_short_string(),
            self.threshold(),
            self.num_keys()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_create_ed25519_only() {
        use crate::crypto::Ed25519PrivateKey;

        let keys: Vec<_> = (0..3)
            .map(|_| AnyPrivateKey::ed25519(Ed25519PrivateKey::generate()))
            .collect();
        let account = MultiKeyAccount::new(keys, 2).unwrap();

        assert_eq!(account.num_keys(), 3);
        assert_eq!(account.threshold(), 2);
        assert_eq!(account.num_owned_keys(), 3);
        assert!(account.can_sign());

        // All keys should be Ed25519
        for variant in account.key_types() {
            assert_eq!(variant, AnyPublicKeyVariant::Ed25519);
        }
    }

    #[test]
    #[cfg(all(feature = "ed25519", feature = "secp256k1"))]
    fn test_create_mixed_types() {
        use crate::crypto::{Ed25519PrivateKey, Secp256k1PrivateKey};

        let keys = vec![
            AnyPrivateKey::ed25519(Ed25519PrivateKey::generate()),
            AnyPrivateKey::secp256k1(Secp256k1PrivateKey::generate()),
            AnyPrivateKey::ed25519(Ed25519PrivateKey::generate()),
        ];
        let account = MultiKeyAccount::new(keys, 2).unwrap();

        assert_eq!(account.num_keys(), 3);
        let types = account.key_types();
        assert_eq!(types[0], AnyPublicKeyVariant::Ed25519);
        assert_eq!(types[1], AnyPublicKeyVariant::Secp256k1);
        assert_eq!(types[2], AnyPublicKeyVariant::Ed25519);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_sign_and_verify() {
        use crate::crypto::Ed25519PrivateKey;

        let keys: Vec<_> = (0..3)
            .map(|_| AnyPrivateKey::ed25519(Ed25519PrivateKey::generate()))
            .collect();
        let account = MultiKeyAccount::new(keys, 2).unwrap();

        let message = b"test message";
        let signature = account.sign_message(message).unwrap();

        assert!(account.verify(message, &signature).is_ok());
        assert!(account.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    #[cfg(all(feature = "ed25519", feature = "secp256k1"))]
    fn test_sign_mixed_types() {
        use crate::crypto::{Ed25519PrivateKey, Secp256k1PrivateKey};

        let keys = vec![
            AnyPrivateKey::ed25519(Ed25519PrivateKey::generate()),
            AnyPrivateKey::secp256k1(Secp256k1PrivateKey::generate()),
            AnyPrivateKey::ed25519(Ed25519PrivateKey::generate()),
        ];
        let account = MultiKeyAccount::new(keys, 2).unwrap();

        let message = b"test message";
        let signature = account.sign_message(message).unwrap();

        assert!(account.verify(message, &signature).is_ok());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_partial_keys() {
        use crate::crypto::Ed25519PrivateKey;

        let all_keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = all_keys
            .iter()
            .map(|k| AnyPublicKey::ed25519(&k.public_key()))
            .collect();

        // Only own keys 0 and 2
        let my_keys = vec![
            (0u8, AnyPrivateKey::ed25519(all_keys[0].clone())),
            (2u8, AnyPrivateKey::ed25519(all_keys[2].clone())),
        ];

        let account = MultiKeyAccount::from_keys(public_keys, my_keys, 2).unwrap();

        assert_eq!(account.num_keys(), 3);
        assert_eq!(account.num_owned_keys(), 2);
        assert!(account.can_sign());

        // Should be able to sign
        let message = b"test";
        let signature = account.sign_message(message).unwrap();
        assert!(account.verify(message, &signature).is_ok());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_insufficient_keys() {
        use crate::crypto::Ed25519PrivateKey;

        let all_keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = all_keys
            .iter()
            .map(|k| AnyPublicKey::ed25519(&k.public_key()))
            .collect();

        // Only own 1 key but need 2
        let my_keys = vec![(0u8, AnyPrivateKey::ed25519(all_keys[0].clone()))];

        let account = MultiKeyAccount::from_keys(public_keys, my_keys, 2).unwrap();

        assert!(!account.can_sign());
        assert!(account.sign_message(b"test").is_err());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_view_only() {
        use crate::crypto::Ed25519PrivateKey;

        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = keys
            .iter()
            .map(|k| AnyPublicKey::ed25519(&k.public_key()))
            .collect();

        let view_only = MultiKeyAccount::view_only(public_keys, 2).unwrap();

        assert_eq!(view_only.num_keys(), 3);
        assert_eq!(view_only.num_owned_keys(), 0);
        assert!(!view_only.can_sign());
        assert!(view_only.sign_message(b"test").is_err());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_deterministic_address() {
        use crate::crypto::Ed25519PrivateKey;

        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = keys
            .iter()
            .map(|k| AnyPublicKey::ed25519(&k.public_key()))
            .collect();

        let account1 = MultiKeyAccount::new(
            keys.iter()
                .map(|k| AnyPrivateKey::ed25519(k.clone()))
                .collect(),
            2,
        )
        .unwrap();
        let account2 = MultiKeyAccount::view_only(public_keys, 2).unwrap();

        // Same public keys should produce same address
        assert_eq!(account1.address(), account2.address());
    }
}
