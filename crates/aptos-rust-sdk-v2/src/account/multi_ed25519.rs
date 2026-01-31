//! Multi-Ed25519 account implementation.
//!
//! This module provides the [`MultiEd25519Account`] type for M-of-N
//! threshold signature accounts using Ed25519 keys.

use crate::account::account::{Account, AuthenticationKey};
use crate::crypto::{
    Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, MULTI_ED25519_SCHEME,
    MultiEd25519PublicKey, MultiEd25519Signature,
};
use crate::error::{AptosError, AptosResult};
use crate::types::AccountAddress;
use std::fmt;

/// A multi-Ed25519 account supporting M-of-N threshold signatures.
///
/// This account type holds multiple Ed25519 keys and requires a threshold
/// number of signatures to authorize transactions.
///
/// # Example
///
/// ```rust,ignore
/// use aptos_rust_sdk_v2::account::MultiEd25519Account;
/// use aptos_rust_sdk_v2::crypto::Ed25519PrivateKey;
///
/// // Create a 2-of-3 multisig account
/// let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
/// let account = MultiEd25519Account::new(keys, 2).unwrap();
///
/// println!("Address: {}", account.address());
/// println!("Threshold: {}/{}", account.threshold(), account.num_keys());
///
/// // Sign a message
/// let message = b"hello";
/// let signature = account.sign(message);
/// ```
pub struct MultiEd25519Account {
    /// The private keys owned by this account (may be a subset).
    private_keys: Vec<(u8, Ed25519PrivateKey)>,
    /// The multi-Ed25519 public key (contains all public keys).
    public_key: MultiEd25519PublicKey,
    /// The derived account address.
    address: AccountAddress,
}

impl MultiEd25519Account {
    /// Creates a new multi-Ed25519 account from private keys.
    ///
    /// All provided private keys will be used for signing. The threshold
    /// specifies how many signatures are required.
    ///
    /// # Arguments
    ///
    /// * `private_keys` - The Ed25519 private keys
    /// * `threshold` - The required number of signatures (M in M-of-N)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // 2-of-3 multisig where we own all 3 keys
    /// let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
    /// let account = MultiEd25519Account::new(keys, 2).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - No private keys are provided
    /// - The threshold exceeds the number of keys
    /// - The multi-Ed25519 public key creation fails (e.g., too many keys, invalid threshold)
    pub fn new(private_keys: Vec<Ed25519PrivateKey>, threshold: u8) -> AptosResult<Self> {
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

        let public_keys: Vec<_> = private_keys
            .iter()
            .map(Ed25519PrivateKey::public_key)
            .collect();
        let multi_public_key = MultiEd25519PublicKey::new(public_keys, threshold)?;
        let address = multi_public_key.to_address();

        // Index the private keys (safe: validated by MultiEd25519PublicKey::new above)
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

    /// Creates a multi-Ed25519 account from public keys with a subset of private keys.
    ///
    /// Use this when you don't have all the private keys (e.g., a 2-of-3 where
    /// you only own 2 keys).
    ///
    /// # Arguments
    ///
    /// * `public_keys` - All the Ed25519 public keys in the account
    /// * `private_keys` - The private keys you own, with their indices
    /// * `threshold` - The required number of signatures
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // 2-of-3 multisig where we own keys 0 and 2
    /// let all_public_keys = vec![pk0, pk1, pk2];
    /// let my_keys = vec![(0, sk0), (2, sk2)];
    /// let account = MultiEd25519Account::from_keys(all_public_keys, my_keys, 2).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The multi-Ed25519 public key creation fails
    /// - A private key index is out of bounds
    /// - A private key doesn't match the public key at its index
    pub fn from_keys(
        public_keys: Vec<Ed25519PublicKey>,
        private_keys: Vec<(u8, Ed25519PrivateKey)>,
        threshold: u8,
    ) -> AptosResult<Self> {
        let multi_public_key = MultiEd25519PublicKey::new(public_keys, threshold)?;

        // Validate private key indices
        for (index, key) in &private_keys {
            if *index as usize >= multi_public_key.num_keys() {
                return Err(AptosError::InvalidPrivateKey(format!(
                    "private key index {index} out of bounds"
                )));
            }
            // Verify the private key matches the public key at that index
            let expected_pk = &multi_public_key.public_keys()[*index as usize];
            if key.public_key() != *expected_pk {
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

    /// Creates a view-only multi-Ed25519 account (no signing capability).
    ///
    /// This is useful for verifying signatures or looking up account information
    /// when you don't have any private keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the multi-Ed25519 public key creation fails (e.g., no keys provided, too many keys, invalid threshold).
    pub fn view_only(public_keys: Vec<Ed25519PublicKey>, threshold: u8) -> AptosResult<Self> {
        let multi_public_key = MultiEd25519PublicKey::new(public_keys, threshold)?;
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

    /// Returns the multi-Ed25519 public key.
    pub fn public_key(&self) -> &MultiEd25519PublicKey {
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

    /// Signs a message using the owned private keys.
    ///
    /// Will use up to `threshold` keys for signing.
    ///
    /// # Errors
    ///
    /// Returns an error if we don't have enough keys to meet the threshold.
    fn sign_internal(&self, message: &[u8]) -> AptosResult<MultiEd25519Signature> {
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

        MultiEd25519Signature::new(signatures)
    }

    /// Signs a message using specific key indices.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `indices` - The indices of keys to use for signing
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - We don't own a key at the specified index
    /// - Not enough indices are provided to meet threshold
    pub fn sign_with_indices(
        &self,
        message: &[u8],
        indices: &[u8],
    ) -> AptosResult<MultiEd25519Signature> {
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

        MultiEd25519Signature::new(signatures)
    }

    /// Verifies a signature against a message.
    ///
    /// # Errors
    ///
    /// Returns an error if signature verification fails (e.g., invalid signature, insufficient signatures, signature mismatch).
    pub fn verify(&self, message: &[u8], signature: &MultiEd25519Signature) -> AptosResult<()> {
        self.public_key.verify(message, signature)
    }

    /// Signs a message using the owned private keys.
    ///
    /// Will use up to `threshold` keys for signing.
    ///
    /// # Errors
    ///
    /// Returns an error if we don't have enough keys to meet the threshold.
    pub fn sign(&self, message: &[u8]) -> AptosResult<MultiEd25519Signature> {
        self.sign_internal(message)
    }

    /// Returns the authentication key for this account.
    pub fn auth_key(&self) -> AuthenticationKey {
        AuthenticationKey::new(self.public_key.to_authentication_key())
    }

    /// Collects individual signatures into a multi-signature.
    ///
    /// Use this when collecting signatures from multiple parties.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - No signatures are provided
    /// - Too many signatures are provided (more than 32)
    /// - Signer indices are out of bounds or duplicated
    pub fn aggregate_signatures(
        signatures: Vec<(u8, Ed25519Signature)>,
    ) -> AptosResult<MultiEd25519Signature> {
        MultiEd25519Signature::new(signatures)
    }

    /// Creates an individual signature contribution for this account.
    ///
    /// Returns the signature with the signer index. Use this when contributing
    /// your signature to a multi-party signing flow.
    ///
    /// # Errors
    ///
    /// Returns an error if we don't have a private key at the specified index.
    pub fn create_signature_contribution(
        &self,
        message: &[u8],
        key_index: u8,
    ) -> AptosResult<(u8, Ed25519Signature)> {
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

impl Account for MultiEd25519Account {
    fn address(&self) -> AccountAddress {
        self.address
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes()
    }

    fn sign(&self, message: &[u8]) -> AptosResult<Vec<u8>> {
        let sig = self.sign_internal(message)?;
        Ok(sig.to_bytes())
    }

    fn authentication_key(&self) -> AuthenticationKey {
        AuthenticationKey::new(self.public_key.to_authentication_key())
    }

    fn signature_scheme(&self) -> u8 {
        MULTI_ED25519_SCHEME
    }
}

impl fmt::Debug for MultiEd25519Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultiEd25519Account")
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
            .field("public_key", &self.public_key)
            .field("private_keys", &self.private_keys)
            .finish()
    }
}

impl fmt::Display for MultiEd25519Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MultiEd25519Account({}, {}-of-{})",
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
    fn test_create_2_of_3() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let account = MultiEd25519Account::new(keys, 2).unwrap();

        assert_eq!(account.num_keys(), 3);
        assert_eq!(account.threshold(), 2);
        assert_eq!(account.num_owned_keys(), 3);
        assert!(account.can_sign());
    }

    #[test]
    fn test_sign_and_verify() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let account = MultiEd25519Account::new(keys, 2).unwrap();

        let message = b"test message";
        let signature = account.sign(message).unwrap();

        assert!(account.verify(message, &signature).is_ok());
        assert!(account.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_partial_keys() {
        let all_keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = all_keys.iter().map(|k| k.public_key()).collect();

        // Only own keys 0 and 2
        let my_keys = vec![(0u8, all_keys[0].clone()), (2u8, all_keys[2].clone())];

        let account = MultiEd25519Account::from_keys(public_keys.clone(), my_keys, 2).unwrap();

        assert_eq!(account.num_keys(), 3);
        assert_eq!(account.num_owned_keys(), 2);
        assert!(account.can_sign());

        // Should be able to sign
        let message = b"test";
        let signature = account.sign(message).unwrap();
        assert!(account.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_insufficient_keys() {
        let all_keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = all_keys.iter().map(|k| k.public_key()).collect();

        // Only own 1 key but need 2
        let my_keys = vec![(0u8, all_keys[0].clone())];

        let account = MultiEd25519Account::from_keys(public_keys.clone(), my_keys, 2).unwrap();

        assert!(!account.can_sign());
        assert!(account.sign(b"test").is_err());
    }

    #[test]
    fn test_sign_with_specific_indices() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let account = MultiEd25519Account::new(keys, 2).unwrap();

        let message = b"test";

        // Sign with keys 1 and 2
        let signature = account.sign_with_indices(message, &[1, 2]).unwrap();
        assert!(account.verify(message, &signature).is_ok());

        // Check that signatures are from correct indices
        assert!(signature.has_signature(1));
        assert!(signature.has_signature(2));
        assert!(!signature.has_signature(0));
    }

    #[test]
    fn test_view_only_account() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();

        let view_only = MultiEd25519Account::view_only(public_keys, 2).unwrap();

        assert_eq!(view_only.num_keys(), 3);
        assert_eq!(view_only.num_owned_keys(), 0);
        assert!(!view_only.can_sign());
        assert!(view_only.sign(b"test").is_err());
    }

    #[test]
    fn test_signature_aggregation() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();

        // Simulate 3 parties each with their own key
        let party0 =
            MultiEd25519Account::from_keys(public_keys.clone(), vec![(0, keys[0].clone())], 2)
                .unwrap();
        let party2 =
            MultiEd25519Account::from_keys(public_keys.clone(), vec![(2, keys[2].clone())], 2)
                .unwrap();

        let message = b"transaction data";

        // Each party creates their contribution
        let contrib0 = party0.create_signature_contribution(message, 0).unwrap();
        let contrib2 = party2.create_signature_contribution(message, 2).unwrap();

        // Aggregate the signatures
        let aggregated =
            MultiEd25519Account::aggregate_signatures(vec![contrib0, contrib2]).unwrap();

        // Any party can verify
        assert!(party0.verify(message, &aggregated).is_ok());
        assert!(party2.verify(message, &aggregated).is_ok());
    }

    #[test]
    fn test_deterministic_address() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();

        let account1 = MultiEd25519Account::new(keys.clone(), 2).unwrap();
        let account2 = MultiEd25519Account::view_only(public_keys, 2).unwrap();

        // Same public keys should produce same address
        assert_eq!(account1.address(), account2.address());
    }

    #[test]
    fn test_empty_keys_error() {
        let result = MultiEd25519Account::new(vec![], 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_threshold_exceeds_keys_error() {
        let keys: Vec<_> = (0..2).map(|_| Ed25519PrivateKey::generate()).collect();
        let result = MultiEd25519Account::new(keys, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_keys_index_out_of_bounds() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();

        // Index 10 is out of bounds
        let my_keys = vec![(10u8, keys[0].clone())];
        let result = MultiEd25519Account::from_keys(public_keys, my_keys, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_keys_mismatched_key() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();

        // Provide wrong private key for index 0
        let different_key = Ed25519PrivateKey::generate();
        let my_keys = vec![(0u8, different_key)];
        let result = MultiEd25519Account::from_keys(public_keys, my_keys, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_owned_key_indices() {
        let all_keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = all_keys.iter().map(|k| k.public_key()).collect();

        let my_keys = vec![(0u8, all_keys[0].clone()), (2u8, all_keys[2].clone())];

        let account = MultiEd25519Account::from_keys(public_keys, my_keys, 2).unwrap();
        let indices = account.owned_key_indices();
        assert_eq!(indices, vec![0, 2]);
    }

    #[test]
    fn test_sign_with_indices_insufficient() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let account = MultiEd25519Account::new(keys, 2).unwrap();

        // Only 1 index but threshold is 2
        let result = account.sign_with_indices(b"test", &[0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_with_indices_missing_key() {
        let all_keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = all_keys.iter().map(|k| k.public_key()).collect();

        // Only own key 0
        let my_keys = vec![(0u8, all_keys[0].clone())];
        let account = MultiEd25519Account::from_keys(public_keys, my_keys, 1).unwrap();

        // Try to sign with key 1 which we don't have
        let result = account.sign_with_indices(b"test", &[1]);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_signature_contribution_missing_key() {
        let all_keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = all_keys.iter().map(|k| k.public_key()).collect();

        // Only own key 0
        let my_keys = vec![(0u8, all_keys[0].clone())];
        let account = MultiEd25519Account::from_keys(public_keys, my_keys, 1).unwrap();

        // Try to contribute with key 1 which we don't have
        let result = account.create_signature_contribution(b"test", 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_account_trait_implementation() {
        use crate::account::Account;

        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let account = MultiEd25519Account::new(keys, 2).unwrap();

        // Test Account trait methods
        assert!(!account.address().is_zero());
        assert!(!account.public_key_bytes().is_empty());
        assert_eq!(
            account.signature_scheme(),
            crate::crypto::MULTI_ED25519_SCHEME
        );

        // Test signing via trait (returns Vec<u8>)
        let sig_bytes: Vec<u8> = Account::sign(&account, b"test").unwrap();
        assert!(!sig_bytes.is_empty());
    }

    #[test]
    fn test_auth_key() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let account = MultiEd25519Account::new(keys, 2).unwrap();
        let auth_key = account.auth_key();
        assert_eq!(auth_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_display_format() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let account = MultiEd25519Account::new(keys, 2).unwrap();
        let display = format!("{}", account);
        assert!(display.contains("MultiEd25519Account"));
        assert!(display.contains("2-of-3"));
    }

    #[test]
    fn test_debug_format() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let account = MultiEd25519Account::new(keys, 2).unwrap();
        let debug = format!("{:?}", account);
        assert!(debug.contains("MultiEd25519Account"));
        assert!(debug.contains("address"));
    }

    #[test]
    fn test_public_key_accessor() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let account = MultiEd25519Account::new(keys, 2).unwrap();
        let pk = account.public_key();
        assert_eq!(pk.num_keys(), 3);
        assert_eq!(pk.threshold(), 2);
    }
}
