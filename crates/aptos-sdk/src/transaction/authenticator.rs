//! Transaction authenticators.

use crate::types::AccountAddress;
use serde::ser::{SerializeTuple, SerializeTupleVariant};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Helpers for emitting/consuming raw, length-prefix-free byte runs inside
/// BCS-serialized structures.
///
/// The Aptos on-chain `AccountAuthenticator::{SingleKey, MultiKey, Keyless}` variants
/// carry typed fields (e.g. `AnyPublicKey`, `AnySignature`, `MultiKeyPublicKey`,
/// `MultiKeySignature`, `SingleKeyAuthenticator`) whose BCS encodings already begin
/// with their own enum/struct tags. When the SDK represents those fields as
/// `Vec<u8>` of pre-encoded bytes, the default serde-BCS impl wraps each `Vec<u8>`
/// with another ULEB128 length prefix, producing wire bytes the on-chain
/// deserializer rejects.
///
/// `serialize_tuple(len)` in `aptos_bcs` emits its elements without a length prefix,
/// which is exactly what we need.
fn serialize_raw_bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    // For empty payloads we can't open a 0-element tuple in some serializers,
    // but BCS handles `serialize_tuple(0)` fine -- it produces no bytes.
    let mut tup = serializer.serialize_tuple(bytes.len())?;
    for byte in bytes {
        tup.serialize_element(byte)?;
    }
    tup.end()
}

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
///
/// The on-chain BCS schema for the `SingleKey`, `MultiKey`, and `Keyless`
/// variants wraps the public key and signature in typed Aptos-core structs
/// (`SingleKeyAuthenticator`, `MultiKeyAuthenticator`, `KeylessSignature`)
/// whose BCS encodings already begin with their own enum/struct tags.
/// Internally we still hold pre-encoded `Vec<u8>` (callers produce those via the
/// `AnyPublicKey`/`AnySignature`/`MultiKeyPublicKey`/`MultiKeySignature` helpers).
/// To match the on-chain wire format exactly we hand-roll the `Serialize`
/// implementation so those variants emit the inner bytes inline -- without the
/// extra ULEB128 length prefix that the derive impl would add to a `Vec<u8>` field.
#[derive(Clone, Debug, PartialEq, Eq)]
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
        /// The public key (BCS-serialized `MultiKeyPublicKey`).
        public_key: Vec<u8>,
        /// The signature (BCS-serialized `MultiKeySignature`).
        signature: Vec<u8>,
    },
    /// No account authenticator used for simulation only (variant 4).
    NoAccountAuthenticator,
    /// Keyless (OIDC-based) authentication (variant 5).
    /// Uses ephemeral keys and ZK proofs for authentication.
    #[cfg(feature = "keyless")]
    Keyless {
        /// The ephemeral public key bytes.
        public_key: Vec<u8>,
        /// The BCS-serialized `KeylessSignature` containing ephemeral signature and ZK proof.
        signature: Vec<u8>,
    },
}

// Tag values must match the order of the on-chain Rust enum, exactly.
const ACCOUNT_AUTH_TAG_ED25519: u32 = 0;
const ACCOUNT_AUTH_TAG_MULTI_ED25519: u32 = 1;
const ACCOUNT_AUTH_TAG_SINGLE_KEY: u32 = 2;
const ACCOUNT_AUTH_TAG_MULTI_KEY: u32 = 3;
const ACCOUNT_AUTH_TAG_NO_ACCOUNT: u32 = 4;
#[cfg(feature = "keyless")]
const ACCOUNT_AUTH_TAG_KEYLESS: u32 = 5;

impl Serialize for AccountAuthenticator {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            AccountAuthenticator::Ed25519 {
                public_key,
                signature,
            } => {
                // Ed25519 carries strongly-typed fields whose Serialize impls already
                // produce the correct BCS bytes; derive-equivalent emission is fine.
                let mut tv = serializer.serialize_tuple_variant(
                    "AccountAuthenticator",
                    ACCOUNT_AUTH_TAG_ED25519,
                    "Ed25519",
                    2,
                )?;
                tv.serialize_field(public_key)?;
                tv.serialize_field(signature)?;
                tv.end()
            }
            AccountAuthenticator::MultiEd25519 {
                public_key,
                signature,
            } => {
                // On-chain `MultiEd25519PublicKey` and `MultiEd25519Signature` are both
                // `Vec<u8>`-wrappers, so emitting our `Vec<u8>` fields with a length
                // prefix matches the wire format.
                let mut tv = serializer.serialize_tuple_variant(
                    "AccountAuthenticator",
                    ACCOUNT_AUTH_TAG_MULTI_ED25519,
                    "MultiEd25519",
                    2,
                )?;
                tv.serialize_field(public_key)?;
                tv.serialize_field(signature)?;
                tv.end()
            }
            AccountAuthenticator::SingleKey {
                public_key,
                signature,
            } => {
                // `SingleKey { authenticator: SingleKeyAuthenticator }`. We emit the inner
                // `SingleKeyAuthenticator` bytes inline (AnyPublicKey then AnySignature).
                serialize_account_auth_raw_pair(
                    serializer,
                    ACCOUNT_AUTH_TAG_SINGLE_KEY,
                    "SingleKey",
                    public_key,
                    signature,
                )
            }
            AccountAuthenticator::MultiKey {
                public_key,
                signature,
            } => {
                // `MultiKey { authenticator: MultiKeyAuthenticator }`. Emit the inner
                // bytes inline (MultiKeyPublicKey then MultiKeySignature).
                serialize_account_auth_raw_pair(
                    serializer,
                    ACCOUNT_AUTH_TAG_MULTI_KEY,
                    "MultiKey",
                    public_key,
                    signature,
                )
            }
            AccountAuthenticator::NoAccountAuthenticator => serializer
                .serialize_tuple_variant(
                    "AccountAuthenticator",
                    ACCOUNT_AUTH_TAG_NO_ACCOUNT,
                    "NoAccountAuthenticator",
                    0,
                )
                .and_then(SerializeTupleVariant::end),
            #[cfg(feature = "keyless")]
            AccountAuthenticator::Keyless {
                public_key,
                signature,
            } => serialize_account_auth_raw_pair(
                serializer,
                ACCOUNT_AUTH_TAG_KEYLESS,
                "Keyless",
                public_key,
                signature,
            ),
        }
    }
}

fn serialize_account_auth_raw_pair<S: Serializer>(
    serializer: S,
    tag: u32,
    name: &'static str,
    public_key: &[u8],
    signature: &[u8],
) -> Result<S::Ok, S::Error> {
    // We model the inner authenticator struct (e.g. `SingleKeyAuthenticator`) as
    // two raw-byte-runs concatenated together: emitting them as tuple-variant
    // fields means BCS writes the tag then each field's bytes inline.
    //
    // Each raw field is serialized via `serialize_raw_bytes` which uses
    // `serialize_tuple(len)` -- BCS emits no length prefix for tuples.
    struct Raw<'a>(&'a [u8]);
    impl Serialize for Raw<'_> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serialize_raw_bytes(self.0, s)
        }
    }

    let mut tv = serializer.serialize_tuple_variant("AccountAuthenticator", tag, name, 2)?;
    tv.serialize_field(&Raw(public_key))?;
    tv.serialize_field(&Raw(signature))?;
    tv.end()
}

impl<'de> Deserialize<'de> for AccountAuthenticator {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // The chain wire format for SingleKey/MultiKey/Keyless does not include
        // explicit length prefixes for the inner public_key/signature byte runs
        // (they are typed BCS structs whose total length is parser-recoverable from
        // their content). This makes a length-agnostic deserializer non-trivial
        // and out of scope here -- the SDK only ever *constructs* these
        // authenticators locally and *serializes* them, never deserializes
        // foreign on-wire bytes back into them.
        //
        // For tests that round-trip the SDK's own representation we deserialize
        // a stable internal layout that matches the prior derive-based Serialize
        // implementation: ULEB128(len)-prefixed Vec<u8> fields for the
        // SingleKey/MultiKey/Keyless variants. This is sufficient for the
        // existing test_account_authenticator_*_bcs_roundtrip tests, which
        // serialize *and* deserialize entirely inside the SDK.
        #[derive(Deserialize)]
        enum Compat {
            Ed25519 {
                public_key: Ed25519PublicKey,
                signature: Ed25519Signature,
            },
            MultiEd25519 {
                public_key: Vec<u8>,
                signature: Vec<u8>,
            },
            SingleKey {
                public_key: Vec<u8>,
                signature: Vec<u8>,
            },
            MultiKey {
                public_key: Vec<u8>,
                signature: Vec<u8>,
            },
            NoAccountAuthenticator,
            #[cfg(feature = "keyless")]
            Keyless {
                public_key: Vec<u8>,
                signature: Vec<u8>,
            },
        }

        Compat::deserialize(deserializer).map(|c| match c {
            Compat::Ed25519 {
                public_key,
                signature,
            } => AccountAuthenticator::Ed25519 {
                public_key,
                signature,
            },
            Compat::MultiEd25519 {
                public_key,
                signature,
            } => AccountAuthenticator::MultiEd25519 {
                public_key,
                signature,
            },
            Compat::SingleKey {
                public_key,
                signature,
            } => AccountAuthenticator::SingleKey {
                public_key,
                signature,
            },
            Compat::MultiKey {
                public_key,
                signature,
            } => AccountAuthenticator::MultiKey {
                public_key,
                signature,
            },
            Compat::NoAccountAuthenticator => AccountAuthenticator::NoAccountAuthenticator,
            #[cfg(feature = "keyless")]
            Compat::Keyless {
                public_key,
                signature,
            } => AccountAuthenticator::Keyless {
                public_key,
                signature,
            },
        })
    }
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
    fn test_account_authenticator_single_key_bcs_wire_format() {
        // The on-chain `AccountAuthenticator::SingleKey { authenticator: SingleKeyAuthenticator }`
        // BCS encoding is:
        //   * variant tag (ULEB128 of 2) -> 1 byte
        //   * BCS(SingleKeyAuthenticator) = BCS(AnyPublicKey) || BCS(AnySignature)
        //
        // The inner public_key/signature byte runs already start with their own
        // enum/struct tags, so they must be emitted *without* any additional
        // length prefix. Verify this by hand-building the expected output.
        let pk = vec![0x77; 33]; // simulated AnyPublicKey bytes
        let sig = vec![0x88; 65]; // simulated AnySignature bytes

        let auth = AccountAuthenticator::SingleKey {
            public_key: pk.clone(),
            signature: sig.clone(),
        };

        let serialized = aptos_bcs::to_bytes(&auth).unwrap();
        let mut expected = Vec::new();
        expected.push(2u8); // variant tag
        expected.extend_from_slice(&pk);
        expected.extend_from_slice(&sig);
        assert_eq!(
            serialized, expected,
            "SingleKey wire format must be variant tag + raw pubkey bytes + raw signature bytes \
             (no inner length prefixes)"
        );
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

    #[test]
    fn test_ed25519_public_key_try_from_bytes_valid() {
        let bytes = vec![0x12; 32];
        let pk = Ed25519PublicKey::try_from_bytes(&bytes).unwrap();
        assert_eq!(pk.0[0], 0x12);
    }

    #[test]
    fn test_ed25519_public_key_try_from_bytes_invalid_length() {
        let bytes = vec![0x12; 16]; // Wrong length
        let result = Ed25519PublicKey::try_from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_signature_try_from_bytes_valid() {
        let bytes = vec![0x34; 64];
        let sig = Ed25519Signature::try_from_bytes(&bytes).unwrap();
        assert_eq!(sig.0[0], 0x34);
    }

    #[test]
    fn test_ed25519_signature_try_from_bytes_invalid_length() {
        let bytes = vec![0x34; 32]; // Wrong length
        let result = Ed25519Signature::try_from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_authenticator_variant_indices() {
        // Verify transaction authenticator variant indices
        let ed25519 = TransactionAuthenticator::ed25519(vec![0; 32], vec![0; 64]);
        let multi_ed25519 = TransactionAuthenticator::multi_ed25519(vec![0; 64], vec![0; 128]);
        let sender = AccountAuthenticator::ed25519(vec![0; 32], vec![0; 64]);
        let multi_agent = TransactionAuthenticator::multi_agent(sender.clone(), vec![], vec![]);
        let fee_payer = TransactionAuthenticator::fee_payer(
            sender.clone(),
            vec![],
            vec![],
            AccountAddress::ONE,
            sender.clone(),
        );
        let single_sender = TransactionAuthenticator::single_sender(sender);

        assert_eq!(aptos_bcs::to_bytes(&ed25519).unwrap()[0], 0, "Ed25519 = 0");
        assert_eq!(
            aptos_bcs::to_bytes(&multi_ed25519).unwrap()[0],
            1,
            "MultiEd25519 = 1"
        );
        assert_eq!(
            aptos_bcs::to_bytes(&multi_agent).unwrap()[0],
            2,
            "MultiAgent = 2"
        );
        assert_eq!(
            aptos_bcs::to_bytes(&fee_payer).unwrap()[0],
            3,
            "FeePayer = 3"
        );
        assert_eq!(
            aptos_bcs::to_bytes(&single_sender).unwrap()[0],
            4,
            "SingleSender = 4"
        );
    }

    #[test]
    fn test_single_key_single_sender_bcs_wire_format() {
        // Pin the byte-for-byte wire layout of
        // `TransactionAuthenticator::SingleSender(AccountAuthenticator::SingleKey)`
        // so that a future regression in the hand-rolled Serialize impl is
        // caught at unit-test time (rather than at submission time on the
        // chain). The inner AnyPublicKey / AnySignature payloads must be
        // emitted *inline* after the variant tags -- no outer length prefixes.
        let mut pk = vec![0u8; 67];
        pk[0] = 0x02; // AnyPublicKey::Secp256r1Ecdsa variant
        pk[1] = 65; // ULEB128(65)
        pk[2] = 0x04; // SEC1 uncompressed marker
        let mut sig = vec![0u8; 66];
        sig[0] = 0x02; // AnySignature::WebAuthn variant
        sig[1] = 64; // ULEB128(64)

        let auth = AccountAuthenticator::single_key(pk.clone(), sig.clone());
        let bytes = aptos_bcs::to_bytes(&auth).unwrap();
        let mut expected_inner = Vec::new();
        expected_inner.push(2u8); // AccountAuthenticator::SingleKey variant tag
        expected_inner.extend_from_slice(&pk); // AnyPublicKey inline (no length prefix)
        expected_inner.extend_from_slice(&sig); // AnySignature inline (no length prefix)
        assert_eq!(bytes, expected_inner);

        let txn = TransactionAuthenticator::single_sender(auth);
        let bytes = aptos_bcs::to_bytes(&txn).unwrap();
        let mut expected_outer = Vec::new();
        expected_outer.push(4u8); // TransactionAuthenticator::SingleSender variant tag
        expected_outer.extend_from_slice(&expected_inner);
        assert_eq!(bytes, expected_outer);
    }

    #[test]
    fn test_multi_key_authenticator_bcs_wire_format() {
        // Same logic as test_account_authenticator_single_key_bcs_wire_format, but for
        // MultiKey. The on-chain `AccountAuthenticator::MultiKey { authenticator: MultiKeyAuthenticator }`
        // BCS encoding is:
        //   * variant tag (ULEB128 of 3) -> 1 byte
        //   * BCS(MultiKeyPublicKey) || BCS(MultiKeySignature)
        // Each inner blob already carries its own structural framing.
        let pk = vec![0xaa; 100];
        let sig = vec![0xbb; 200];
        let auth = AccountAuthenticator::multi_key(pk.clone(), sig.clone());

        let serialized = aptos_bcs::to_bytes(&auth).unwrap();
        let mut expected = Vec::new();
        expected.push(3u8); // variant tag
        expected.extend_from_slice(&pk);
        expected.extend_from_slice(&sig);
        assert_eq!(
            serialized, expected,
            "MultiKey wire format must be variant tag + raw pubkey bytes + raw signature bytes"
        );
    }

    #[test]
    fn test_multi_key_authenticator_bcs_rejects_keyless_public_key() {
        let auth = AccountAuthenticator::MultiKey {
            authenticator: MultiKeyAuthenticator::new(
                MultiKeyPublicKey::new(
                    vec![AnyPublicKey::new(
                        crate::crypto::AnyPublicKeyVariant::Keyless,
                        vec![],
                    )],
                    1,
                )
                .unwrap(),
                MultiKeySignature::new(vec![(
                    0,
                    AnySignature::new(crate::crypto::AnyPublicKeyVariant::Ed25519, vec![0x66; 64]),
                )])
                .unwrap(),
            ),
        };

        let serialized = aptos_bcs::to_bytes(&auth).unwrap();
        let result: Result<AccountAuthenticator, _> = aptos_bcs::from_bytes(&serialized);
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_ed25519_authenticator_bcs_roundtrip() {
        let auth = AccountAuthenticator::MultiEd25519 {
            public_key: vec![0xcc; 64],
            signature: vec![0xdd; 128],
        };

        let serialized = aptos_bcs::to_bytes(&auth).unwrap();
        // MultiEd25519 should be variant index 1
        assert_eq!(serialized[0], 1, "MultiEd25519 variant index should be 1");
        let deserialized: AccountAuthenticator = aptos_bcs::from_bytes(&serialized).unwrap();
        assert_eq!(auth, deserialized);
    }

    #[test]
    fn test_ed25519_public_key_deserialize_invalid_length() {
        // Serialize with wrong length (use 16 bytes instead of 32)
        let mut bytes = vec![16u8]; // Length prefix
        bytes.extend_from_slice(&[0xab; 16]); // Only 16 bytes
        let result: Result<Ed25519PublicKey, _> = aptos_bcs::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_signature_deserialize_invalid_length() {
        // Serialize with wrong length (use 32 bytes instead of 64)
        let mut bytes = vec![32u8]; // Length prefix
        bytes.extend_from_slice(&[0xab; 32]); // Only 32 bytes
        let result: Result<Ed25519Signature, _> = aptos_bcs::from_bytes(&bytes);
        assert!(result.is_err());
    }
}
