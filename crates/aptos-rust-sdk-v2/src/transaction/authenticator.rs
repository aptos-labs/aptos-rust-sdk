//! Transaction authenticators.

use crate::types::AccountAddress;
use serde::{Deserialize, Serialize};

/// An authenticator for a transaction.
///
/// This contains the signature(s) and public key(s) that prove
/// the transaction was authorized by the sender.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionAuthenticator {
    /// Ed25519 single-key authentication.
    Ed25519 {
        /// The Ed25519 public key.
        public_key: Vec<u8>,
        /// The Ed25519 signature.
        signature: Vec<u8>,
    },
    /// Multi-Ed25519 authentication.
    MultiEd25519 {
        /// The multi-Ed25519 public key.
        public_key: Vec<u8>,
        /// The multi-Ed25519 signature.
        signature: Vec<u8>,
    },
    /// Multi-key authentication (mixed signature types).
    MultiKey {
        /// The multi-key public key.
        public_key: Vec<u8>,
        /// The multi-key signature.
        signature: Vec<u8>,
    },
    /// Multi-agent transaction authentication.
    MultiAgent {
        /// The sender's authenticator.
        sender: AccountAuthenticator,
        /// Secondary signer addresses.
        secondary_signer_addresses: Vec<AccountAddress>,
        /// Secondary signers' authenticators.
        secondary_signers: Vec<AccountAuthenticator>,
    },
    /// Fee payer transaction authentication.
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
    /// Single key authentication (unified format).
    SingleKey {
        /// The authenticator.
        authenticator: SingleKeyAuthenticator,
    },
}

/// An authenticator for a single account (not the full transaction).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountAuthenticator {
    /// Ed25519 authentication.
    Ed25519 {
        /// The public key.
        public_key: Vec<u8>,
        /// The signature.
        signature: Vec<u8>,
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
    /// Single key authentication.
    SingleKey {
        /// The authenticator.
        authenticator: SingleKeyAuthenticator,
    },
}

/// Single key authenticator supporting multiple signature schemes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleKeyAuthenticator {
    /// The public key with scheme.
    pub public_key: AnyPublicKey,
    /// The signature with scheme.
    pub signature: AnySignature,
}

/// A public key with its scheme identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnyPublicKey {
    /// The signature scheme.
    pub scheme: SignatureScheme,
    /// The public key bytes.
    pub public_key: Vec<u8>,
}

/// A signature with its scheme identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnySignature {
    /// The signature scheme.
    pub scheme: SignatureScheme,
    /// The signature bytes.
    pub signature: Vec<u8>,
}

/// Supported signature schemes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SignatureScheme {
    /// Ed25519 signatures.
    Ed25519 = 0,
    /// Secp256k1 ECDSA signatures.
    Secp256k1 = 1,
    /// Secp256r1 (P-256) ECDSA signatures.
    Secp256r1 = 2,
    /// Keyless signatures.
    Keyless = 5,
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
            public_key: auth.public_key,
            signature: auth.signature,
        }
    }
}

impl From<Ed25519Authenticator> for AccountAuthenticator {
    fn from(auth: Ed25519Authenticator) -> Self {
        AccountAuthenticator::Ed25519 {
            public_key: auth.public_key,
            signature: auth.signature,
        }
    }
}

impl TransactionAuthenticator {
    /// Creates an Ed25519 authenticator.
    pub fn ed25519(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self::Ed25519 {
            public_key,
            signature,
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

    /// Creates a multi-key authenticator.
    pub fn multi_key(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self::MultiKey {
            public_key,
            signature,
        }
    }
}

impl AccountAuthenticator {
    /// Creates an Ed25519 account authenticator.
    pub fn ed25519(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self::Ed25519 {
            public_key,
            signature,
        }
    }

    /// Creates a single key account authenticator.
    pub fn single_key(scheme: SignatureScheme, public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self::SingleKey {
            authenticator: SingleKeyAuthenticator {
                public_key: AnyPublicKey { scheme, public_key },
                signature: AnySignature { scheme, signature },
            },
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
        let auth = Ed25519Authenticator::new(vec![1, 2, 3], vec![4, 5, 6]);
        let txn_auth: TransactionAuthenticator = auth.into();

        match txn_auth {
            TransactionAuthenticator::Ed25519 {
                public_key,
                signature,
            } => {
                assert_eq!(public_key, vec![1, 2, 3]);
                assert_eq!(signature, vec![4, 5, 6]);
            }
            _ => panic!("wrong authenticator type"),
        }
    }

    #[test]
    fn test_multi_agent_authenticator() {
        let sender = AccountAuthenticator::ed25519(vec![1], vec![2]);
        let auth = TransactionAuthenticator::multi_agent(sender, vec![], vec![]);

        match auth {
            TransactionAuthenticator::MultiAgent { .. } => {}
            _ => panic!("wrong authenticator type"),
        }
    }
}
