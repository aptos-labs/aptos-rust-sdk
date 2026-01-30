//! Transaction authenticators.

use crate::types::AccountAddress;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Ed25519 public key (32 bytes).
/// Serializes WITH a length prefix as required by Aptos BCS format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519PublicKey(pub [u8; 32]);

impl Serialize for Ed25519PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Aptos BCS format requires a length prefix for public keys
        // Use serde_bytes to serialize with ULEB128 length prefix
        serde_bytes::Bytes::new(&self.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize with length prefix
        let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::invalid_length(bytes.len(), &"32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Ed25519PublicKey(arr))
    }
}

impl From<Vec<u8>> for Ed25519PublicKey {
    /// Converts a `Vec<u8>` to `Ed25519PublicKey`.
    ///
    /// # Panics
    ///
    /// Panics if the input is not exactly 32 bytes. Use `Ed25519PublicKey::try_from_bytes`
    /// for fallible conversion.
    fn from(bytes: Vec<u8>) -> Self {
        assert!(
            bytes.len() == 32,
            "Ed25519PublicKey requires exactly 32 bytes, got {}",
            bytes.len()
        );
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ed25519PublicKey(arr)
    }
}

impl Ed25519PublicKey {
    /// Attempts to create an `Ed25519PublicKey` from a byte slice.
    ///
    /// Returns an error if the input is not exactly 32 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input slice is not exactly 32 bytes.
    pub fn try_from_bytes(bytes: &[u8]) -> crate::error::AptosResult<Self> {
        if bytes.len() != 32 {
            return Err(crate::error::AptosError::InvalidPublicKey(format!(
                "Ed25519PublicKey requires exactly 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Ed25519PublicKey(arr))
    }
}

/// Ed25519 signature (64 bytes).
/// Serializes WITH a length prefix as required by Aptos BCS format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519Signature(pub [u8; 64]);

impl Serialize for Ed25519Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Aptos BCS format requires a length prefix for signatures
        // Use serde_bytes to serialize with ULEB128 length prefix
        serde_bytes::Bytes::new(&self.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Ed25519Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize with length prefix
        let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::invalid_length(bytes.len(), &"64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Ed25519Signature(arr))
    }
}

impl From<Vec<u8>> for Ed25519Signature {
    /// Converts a `Vec<u8>` to `Ed25519Signature`.
    ///
    /// # Panics
    ///
    /// Panics if the input is not exactly 64 bytes. Use `Ed25519Signature::try_from_bytes`
    /// for fallible conversion.
    fn from(bytes: Vec<u8>) -> Self {
        assert!(
            bytes.len() == 64,
            "Ed25519Signature requires exactly 64 bytes, got {}",
            bytes.len()
        );
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ed25519Signature(arr)
    }
}

impl Ed25519Signature {
    /// Attempts to create an `Ed25519Signature` from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not exactly 64 bytes.
    pub fn try_from_bytes(bytes: &[u8]) -> crate::error::AptosResult<Self> {
        if bytes.len() != 64 {
            return Err(crate::error::AptosError::InvalidSignature(format!(
                "Ed25519Signature requires exactly 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        Ok(Ed25519Signature(arr))
    }
}

/// An authenticator for a transaction.
///
/// This contains the signature(s) and public key(s) that prove
/// the transaction was authorized by the sender.
///
/// Note: Variant indices must match Aptos core for BCS compatibility:
/// - 0: Ed25519
/// - 1: `MultiEd25519`
/// - 2: `MultiAgent`
/// - 3: `FeePayer`
/// - 4: `SingleSender` (for unified key support)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionAuthenticator {
    /// Ed25519 single-key authentication (variant 0).
    Ed25519 {
        /// The Ed25519 public key (32 bytes).
        public_key: Ed25519PublicKey,
        /// The Ed25519 signature (64 bytes).
        signature: Ed25519Signature,
    },
    /// Multi-Ed25519 authentication (variant 1).
    MultiEd25519 {
        /// The multi-Ed25519 public key.
        public_key: Vec<u8>,
        /// The multi-Ed25519 signature.
        signature: Vec<u8>,
    },
    /// Multi-agent transaction authentication (variant 2).
    MultiAgent {
        /// The sender's authenticator.
        sender: AccountAuthenticator,
        /// Secondary signer addresses.
        secondary_signer_addresses: Vec<AccountAddress>,
        /// Secondary signers' authenticators.
        secondary_signers: Vec<AccountAuthenticator>,
    },
    /// Fee payer transaction authentication (variant 3).
    FeePayer {
        /// The sender's authenticator.
        sender: AccountAuthenticator,
        /// Secondary signer addresses.
        secondary_signer_addresses: Vec<AccountAddress>,
        /// Secondary signers' authenticators.
        secondary_signers: Vec<AccountAuthenticator>,
        /// The fee payer's address.
        fee_payer_address: AccountAddress,
        /// The fee payer's authenticator.
        fee_payer_signer: AccountAuthenticator,
    },
    /// Single sender authentication with account authenticator (variant 4).
    /// Used for newer single-key and multi-key accounts.
    SingleSender {
        /// The account authenticator.
        sender: AccountAuthenticator,
    },
}

/// An authenticator for a single account (not the full transaction).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountAuthenticator {
    /// Ed25519 authentication (variant 0).
    Ed25519 {
        /// The public key (32 bytes).
        public_key: Ed25519PublicKey,
        /// The signature (64 bytes).
        signature: Ed25519Signature,
    },
    /// Multi-Ed25519 authentication (variant 1).
    MultiEd25519 {
        /// The public key.
        public_key: Vec<u8>,
        /// The signature.
        signature: Vec<u8>,
    },
    /// Single-key authentication (ed25519, secp256k1 and secp256r1) (variant 2).
    SingleKey {
        /// The public key (BCS-serialized `AnyPublicKey`).
        public_key: Vec<u8>,
        /// The signature (BCS-serialized `AnySignature`).
        signature: Vec<u8>,
    },
    /// Multi-key authentication (mixed signature types) (variant 3).
    MultiKey {
        /// The public key.
        public_key: Vec<u8>,
        /// The signature.
        signature: Vec<u8>,
    },
    /// No account authenticator used for simulation only (variant 4).
    NoAccountAuthenticator,
    /// Keyless (OIDC-based) authentication (variant 5).
    /// Uses ephemeral keys and ZK proofs for authentication.
    #[cfg(feature = "keyless")]
    #[cfg_attr(docsrs, doc(cfg(feature = "keyless")))]
    Keyless {
        /// The ephemeral public key bytes.
        public_key: Vec<u8>,
        /// The BCS-serialized `KeylessSignature` containing ephemeral signature and ZK proof.
        signature: Vec<u8>,
    },
}

/// Ed25519 authenticator helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519Authenticator {
    /// The public key.
    pub public_key: Vec<u8>,
    /// The signature.
    pub signature: Vec<u8>,
}

impl Ed25519Authenticator {
    /// Creates a new Ed25519 authenticator.
    pub fn new(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            public_key,
            signature,
        }
    }
}

impl From<Ed25519Authenticator> for TransactionAuthenticator {
    fn from(auth: Ed25519Authenticator) -> Self {
        TransactionAuthenticator::Ed25519 {
            public_key: auth.public_key.into(),
            signature: auth.signature.into(),
        }
    }
}

impl From<Ed25519Authenticator> for AccountAuthenticator {
    fn from(auth: Ed25519Authenticator) -> Self {
        AccountAuthenticator::Ed25519 {
            public_key: auth.public_key.into(),
            signature: auth.signature.into(),
        }
    }
}

impl TransactionAuthenticator {
    /// Creates an Ed25519 authenticator.
    pub fn ed25519(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self::Ed25519 {
            public_key: public_key.into(),
            signature: signature.into(),
        }
    }

    /// Creates a multi-Ed25519 authenticator.
    pub fn multi_ed25519(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self::MultiEd25519 {
            public_key,
            signature,
        }
    }

    /// Creates a multi-agent authenticator.
    pub fn multi_agent(
        sender: AccountAuthenticator,
        secondary_signer_addresses: Vec<AccountAddress>,
        secondary_signers: Vec<AccountAuthenticator>,
    ) -> Self {
        Self::MultiAgent {
            sender,
            secondary_signer_addresses,
            secondary_signers,
        }
    }

    /// Creates a fee payer authenticator.
    pub fn fee_payer(
        sender: AccountAuthenticator,
        secondary_signer_addresses: Vec<AccountAddress>,
        secondary_signers: Vec<AccountAuthenticator>,
        fee_payer_address: AccountAddress,
        fee_payer_signer: AccountAuthenticator,
    ) -> Self {
        Self::FeePayer {
            sender,
            secondary_signer_addresses,
            secondary_signers,
            fee_payer_address,
            fee_payer_signer,
        }
    }

    /// Creates a single sender authenticator.
    /// This is used for accounts with the unified key model (including multi-key accounts).
    pub fn single_sender(sender: AccountAuthenticator) -> Self {
        Self::SingleSender { sender }
    }
}

impl AccountAuthenticator {
    /// Creates an Ed25519 account authenticator.
    pub fn ed25519(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self::Ed25519 {
            public_key: public_key.into(),
            signature: signature.into(),
        }
    }
    /// Creates a single-key account authenticator.
    pub fn single_key(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self::SingleKey {
            public_key,
            signature,
        }
    }

    /// Creates a multi-key account authenticator.
    pub fn multi_key(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self::MultiKey {
            public_key,
            signature,
        }
    }

    /// Creates a no account authenticator.
    pub fn no_account_authenticator() -> Self {
        Self::NoAccountAuthenticator
    }

    /// Creates a keyless account authenticator.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The ephemeral public key bytes
    /// * `signature` - The BCS-serialized `KeylessSignature`
    #[cfg(feature = "keyless")]
    #[cfg_attr(docsrs, doc(cfg(feature = "keyless")))]
    pub fn keyless(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self::Keyless {
            public_key,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_authenticator() {
        let mut pk = [0u8; 32];
        pk[0..3].copy_from_slice(&[1, 2, 3]);
        let mut sig = [0u8; 64];
        sig[0..3].copy_from_slice(&[4, 5, 6]);

        let auth = Ed25519Authenticator::new(pk.to_vec(), sig.to_vec());
        let txn_auth: TransactionAuthenticator = auth.into();

        match txn_auth {
            TransactionAuthenticator::Ed25519 {
                public_key,
                signature,
            } => {
                assert_eq!(public_key.0[0..3], [1, 2, 3]);
                assert_eq!(signature.0[0..3], [4, 5, 6]);
            }
            _ => panic!("wrong authenticator type"),
        }
    }

    #[test]
    fn test_multi_agent_authenticator() {
        let sender = AccountAuthenticator::ed25519(vec![0; 32], vec![0; 64]);
        let auth = TransactionAuthenticator::multi_agent(sender, vec![], vec![]);

        match auth {
            TransactionAuthenticator::MultiAgent { .. } => {}
            _ => panic!("wrong authenticator type"),
        }
    }

    #[test]
    fn test_ed25519_bcs_format() {
        // Test that Ed25519 serializes WITH length prefixes (Aptos BCS format)
        let auth = TransactionAuthenticator::Ed25519 {
            public_key: Ed25519PublicKey([0xab; 32]),
            signature: Ed25519Signature([0xcd; 64]),
        };
        let bcs = aptos_bcs::to_bytes(&auth).unwrap();

        // Ed25519 variant should be index 0
        assert_eq!(bcs[0], 0, "Ed25519 variant index should be 0");
        // Next byte is length prefix for pubkey (32 = 0x20)
        assert_eq!(bcs[1], 32, "Pubkey length prefix should be 32");
        // Next 32 bytes should be the pubkey
        assert_eq!(bcs[2], 0xab, "First pubkey byte should be 0xab");
        // After pubkey (1 + 1 + 32 = 34), length prefix for signature (64 = 0x40)
        assert_eq!(bcs[34], 64, "Signature length prefix should be 64");
        // Signature starts at offset 35
        assert_eq!(bcs[35], 0xcd, "First signature byte should be 0xcd");
        // Total: 1 (variant) + 1 (pubkey len) + 32 (pubkey) + 1 (sig len) + 64 (sig) = 99
        assert_eq!(bcs.len(), 99, "BCS length should be 99");
    }

    #[test]
    fn test_ed25519_authenticator_into_account_authenticator() {
        let auth = Ed25519Authenticator::new(vec![0xaa; 32], vec![0xbb; 64]);
        let account_auth: AccountAuthenticator = auth.into();

        match account_auth {
            AccountAuthenticator::Ed25519 {
                public_key,
                signature,
            } => {
                assert_eq!(public_key.0[0], 0xaa);
                assert_eq!(signature.0[0], 0xbb);
            }
            _ => panic!("Expected Ed25519 variant"),
        }
    }

    #[test]
    fn test_transaction_authenticator_ed25519() {
        let auth = TransactionAuthenticator::ed25519(vec![0x11; 32], vec![0x22; 64]);
        match auth {
            TransactionAuthenticator::Ed25519 {
                public_key,
                signature,
            } => {
                assert_eq!(public_key.0[0], 0x11);
                assert_eq!(signature.0[0], 0x22);
            }
            _ => panic!("Expected Ed25519 variant"),
        }
    }

    #[test]
    fn test_transaction_authenticator_multi_ed25519() {
        let auth = TransactionAuthenticator::multi_ed25519(vec![0x33; 64], vec![0x44; 128]);
        match auth {
            TransactionAuthenticator::MultiEd25519 {
                public_key,
                signature,
            } => {
                assert_eq!(public_key.len(), 64);
                assert_eq!(signature.len(), 128);
            }
            _ => panic!("Expected MultiEd25519 variant"),
        }
    }

    #[test]
    fn test_fee_payer_authenticator() {
        let sender = AccountAuthenticator::ed25519(vec![0; 32], vec![0; 64]);
        let fee_payer = AccountAuthenticator::ed25519(vec![1; 32], vec![1; 64]);
        let fee_payer_address = AccountAddress::from_hex("0x123").unwrap();

        let auth = TransactionAuthenticator::fee_payer(
            sender,
            vec![],
            vec![],
            fee_payer_address,
            fee_payer,
        );

        match auth {
            TransactionAuthenticator::FeePayer {
                fee_payer_address: addr,
                ..
            } => {
                assert_eq!(addr, fee_payer_address);
            }
            _ => panic!("Expected FeePayer variant"),
        }
    }

    #[test]
    fn test_single_sender_authenticator() {
        let sender = AccountAuthenticator::ed25519(vec![0x55; 32], vec![0x66; 64]);
        let auth = TransactionAuthenticator::single_sender(sender);

        match auth {
            TransactionAuthenticator::SingleSender { sender } => match sender {
                AccountAuthenticator::Ed25519 { public_key, .. } => {
                    assert_eq!(public_key.0[0], 0x55);
                }
                _ => panic!("Expected Ed25519 sender"),
            },
            _ => panic!("Expected SingleSender variant"),
        }
    }

    #[test]
    fn test_account_authenticator_multi_key() {
        let auth = AccountAuthenticator::multi_key(vec![0x77; 100], vec![0x88; 200]);
        match auth {
            AccountAuthenticator::MultiKey {
                public_key,
                signature,
            } => {
                assert_eq!(public_key.len(), 100);
                assert_eq!(signature.len(), 200);
            }
            _ => panic!("Expected MultiKey variant"),
        }
    }

    #[test]
    fn test_ed25519_public_key_from_vec() {
        let pk: Ed25519PublicKey = vec![0x12; 32].into();
        assert_eq!(pk.0[0], 0x12);
        assert_eq!(pk.0.len(), 32);
    }

    #[test]
    fn test_ed25519_signature_from_vec() {
        let sig: Ed25519Signature = vec![0x34; 64].into();
        assert_eq!(sig.0[0], 0x34);
        assert_eq!(sig.0.len(), 64);
    }

    #[test]
    fn test_ed25519_public_key_bcs_roundtrip() {
        let pk = Ed25519PublicKey([0xef; 32]);
        let serialized = aptos_bcs::to_bytes(&pk).unwrap();
        // Aptos BCS format: 1 byte length prefix (32) + 32 bytes = 33 bytes
        assert_eq!(serialized.len(), 33);
        assert_eq!(serialized[0], 32); // Length prefix
        let deserialized: Ed25519PublicKey = aptos_bcs::from_bytes(&serialized).unwrap();
        assert_eq!(pk, deserialized);
    }

    #[test]
    fn test_ed25519_signature_bcs_roundtrip() {
        let sig = Ed25519Signature([0x99; 64]);
        let serialized = aptos_bcs::to_bytes(&sig).unwrap();
        let deserialized: Ed25519Signature = aptos_bcs::from_bytes(&serialized).unwrap();
        assert_eq!(sig, deserialized);
    }

    #[test]
    fn test_multi_agent_with_secondary_signers() {
        let sender = AccountAuthenticator::ed25519(vec![0; 32], vec![0; 64]);
        let secondary_signer1 = AccountAuthenticator::ed25519(vec![1; 32], vec![1; 64]);
        let secondary_signer2 = AccountAuthenticator::ed25519(vec![2; 32], vec![2; 64]);
        let addr1 = AccountAddress::from_hex("0x111").unwrap();
        let addr2 = AccountAddress::from_hex("0x222").unwrap();

        let auth = TransactionAuthenticator::multi_agent(
            sender,
            vec![addr1, addr2],
            vec![secondary_signer1, secondary_signer2],
        );

        match auth {
            TransactionAuthenticator::MultiAgent {
                secondary_signer_addresses,
                secondary_signers,
                ..
            } => {
                assert_eq!(secondary_signer_addresses.len(), 2);
                assert_eq!(secondary_signers.len(), 2);
            }
            _ => panic!("Expected MultiAgent variant"),
        }
    }

    #[test]
    fn test_transaction_authenticator_bcs_roundtrip() {
        let auth = TransactionAuthenticator::Ed25519 {
            public_key: Ed25519PublicKey([0x11; 32]),
            signature: Ed25519Signature([0x22; 64]),
        };

        let serialized = aptos_bcs::to_bytes(&auth).unwrap();
        let deserialized: TransactionAuthenticator = aptos_bcs::from_bytes(&serialized).unwrap();

        assert_eq!(auth, deserialized);
    }

    #[test]
    fn test_account_authenticator_bcs_roundtrip() {
        let auth = AccountAuthenticator::Ed25519 {
            public_key: Ed25519PublicKey([0x33; 32]),
            signature: Ed25519Signature([0x44; 64]),
        };

        let serialized = aptos_bcs::to_bytes(&auth).unwrap();
        let deserialized: AccountAuthenticator = aptos_bcs::from_bytes(&serialized).unwrap();

        assert_eq!(auth, deserialized);
    }

    #[test]
    fn test_account_authenticator_single_key() {
        let auth = AccountAuthenticator::single_key(vec![0x55; 33], vec![0x66; 65]);
        match auth {
            AccountAuthenticator::SingleKey {
                public_key,
                signature,
            } => {
                assert_eq!(public_key.len(), 33);
                assert_eq!(signature.len(), 65);
            }
            _ => panic!("Expected SingleKey variant"),
        }
    }

    #[test]
    fn test_account_authenticator_single_key_bcs_roundtrip() {
        let auth = AccountAuthenticator::SingleKey {
            public_key: vec![0x77; 33],
            signature: vec![0x88; 65],
        };

        let serialized = aptos_bcs::to_bytes(&auth).unwrap();
        // SingleKey should be variant index 2
        assert_eq!(serialized[0], 2, "SingleKey variant index should be 2");
        let deserialized: AccountAuthenticator = aptos_bcs::from_bytes(&serialized).unwrap();
        assert_eq!(auth, deserialized);
    }

    #[test]
    fn test_no_account_authenticator() {
        let auth = AccountAuthenticator::no_account_authenticator();
        match auth {
            AccountAuthenticator::NoAccountAuthenticator => {}
            _ => panic!("Expected NoAccountAuthenticator variant"),
        }
    }

    #[test]
    fn test_no_account_authenticator_bcs_roundtrip() {
        let auth = AccountAuthenticator::NoAccountAuthenticator;

        let serialized = aptos_bcs::to_bytes(&auth).unwrap();
        // NoAccountAuthenticator should be variant index 4
        assert_eq!(
            serialized[0], 4,
            "NoAccountAuthenticator variant index should be 4"
        );
        // It should be just the variant index, no payload
        assert_eq!(
            serialized.len(),
            1,
            "NoAccountAuthenticator should be 1 byte"
        );
        let deserialized: AccountAuthenticator = aptos_bcs::from_bytes(&serialized).unwrap();
        assert_eq!(auth, deserialized);
    }

    #[test]
    fn test_single_sender_with_single_key() {
        let sender = AccountAuthenticator::single_key(vec![0x99; 33], vec![0xaa; 65]);
        let auth = TransactionAuthenticator::single_sender(sender);

        match auth {
            TransactionAuthenticator::SingleSender { sender } => match sender {
                AccountAuthenticator::SingleKey { public_key, .. } => {
                    assert_eq!(public_key.len(), 33);
                }
                _ => panic!("Expected SingleKey sender"),
            },
            _ => panic!("Expected SingleSender variant"),
        }
    }

    #[test]
    fn test_account_authenticator_variant_indices() {
        // Verify all variant indices match Aptos core
        let ed25519 = AccountAuthenticator::ed25519(vec![0; 32], vec![0; 64]);
        let multi_ed25519 = AccountAuthenticator::MultiEd25519 {
            public_key: vec![0; 64],
            signature: vec![0; 128],
        };
        let single_key = AccountAuthenticator::single_key(vec![0; 33], vec![0; 65]);
        let multi_key = AccountAuthenticator::multi_key(vec![0; 100], vec![0; 200]);
        let no_account = AccountAuthenticator::no_account_authenticator();

        assert_eq!(aptos_bcs::to_bytes(&ed25519).unwrap()[0], 0, "Ed25519 = 0");
        assert_eq!(
            aptos_bcs::to_bytes(&multi_ed25519).unwrap()[0],
            1,
            "MultiEd25519 = 1"
        );
        assert_eq!(
            aptos_bcs::to_bytes(&single_key).unwrap()[0],
            2,
            "SingleKey = 2"
        );
        assert_eq!(
            aptos_bcs::to_bytes(&multi_key).unwrap()[0],
            3,
            "MultiKey = 3"
        );
        assert_eq!(
            aptos_bcs::to_bytes(&no_account).unwrap()[0],
            4,
            "NoAccountAuthenticator = 4"
        );
    }
}
