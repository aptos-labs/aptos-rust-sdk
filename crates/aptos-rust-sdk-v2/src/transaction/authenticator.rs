//! Transaction authenticators.

use crate::types::AccountAddress;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Ed25519 public key (32 bytes, fixed size).
/// Serializes without length prefix (as a fixed-size tuple).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519PublicKey(pub [u8; 32]);

impl Serialize for Ed25519PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // BCS serializes tuples/arrays without length prefix
        // Use serialize_tuple to achieve this
        use serde::ser::SerializeTuple;
        let mut seq = serializer.serialize_tuple(32)?;
        for byte in &self.0 {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Ed25519PublicKey;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "32 bytes")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut arr = [0u8; 32];
                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(Ed25519PublicKey(arr))
            }
        }
        deserializer.deserialize_tuple(32, Visitor)
    }
}

impl From<Vec<u8>> for Ed25519PublicKey {
    fn from(bytes: Vec<u8>) -> Self {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32.min(bytes.len())]);
        Ed25519PublicKey(arr)
    }
}

/// Ed25519 signature (64 bytes, fixed size).
/// Serializes without length prefix (as a fixed-size tuple).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519Signature(pub [u8; 64]);

impl Serialize for Ed25519Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // BCS serializes tuples/arrays without length prefix
        use serde::ser::SerializeTuple;
        let mut seq = serializer.serialize_tuple(64)?;
        for byte in &self.0 {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Ed25519Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Ed25519Signature;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "64 bytes")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut arr = [0u8; 64];
                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(Ed25519Signature(arr))
            }
        }
        deserializer.deserialize_tuple(64, Visitor)
    }
}

impl From<Vec<u8>> for Ed25519Signature {
    fn from(bytes: Vec<u8>) -> Self {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes[..64.min(bytes.len())]);
        Ed25519Signature(arr)
    }
}

/// An authenticator for a transaction.
///
/// This contains the signature(s) and public key(s) that prove
/// the transaction was authorized by the sender.
///
/// Note: Variant indices must match Aptos core for BCS compatibility:
/// - 0: Ed25519
/// - 1: MultiEd25519
/// - 2: MultiAgent
/// - 3: FeePayer
/// - 4: SingleSender (for unified key support)
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
    /// Ed25519 authentication.
    Ed25519 {
        /// The public key (32 bytes).
        public_key: Ed25519PublicKey,
        /// The signature (64 bytes).
        signature: Ed25519Signature,
    },
    /// Multi-Ed25519 authentication.
    MultiEd25519 {
        /// The public key.
        public_key: Vec<u8>,
        /// The signature.
        signature: Vec<u8>,
    },
    /// Multi-key authentication (mixed signature types).
    MultiKey {
        /// The public key.
        public_key: Vec<u8>,
        /// The signature.
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

    /// Creates a multi-key account authenticator.
    pub fn multi_key(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self::MultiKey {
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
        // Test that Ed25519 serializes without length prefix
        let auth = TransactionAuthenticator::Ed25519 {
            public_key: Ed25519PublicKey([0xab; 32]),
            signature: Ed25519Signature([0xcd; 64]),
        };
        let bcs = aptos_bcs::to_bytes(&auth).unwrap();

        // Ed25519 variant should be index 0
        assert_eq!(bcs[0], 0, "Ed25519 variant index should be 0");
        // Next 32 bytes should be the pubkey (no length prefix)
        assert_eq!(bcs[1], 0xab, "First pubkey byte should be 0xab");
        // Signature starts at offset 33
        assert_eq!(bcs[33], 0xcd, "First signature byte should be 0xcd");
        // Total: 1 (variant) + 32 (pubkey) + 64 (sig) = 97
        assert_eq!(bcs.len(), 97, "BCS length should be 97");
    }
}
