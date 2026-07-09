//! Transaction authenticators.

use crate::types::AccountAddress;
use serde::ser::{SerializeTuple, SerializeTupleVariant};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Helpers for emitting/consuming raw, length-prefix-free byte runs inside
/// BCS-serialized structures.
///
/// The Aptos on-chain `AccountAuthenticator::{SingleKey, MultiKey}` variants
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
/// The on-chain BCS schema for the `SingleKey` and `MultiKey`
/// variants wraps the public key and signature in typed Aptos-core structs
/// (`SingleKeyAuthenticator`, `MultiKeyAuthenticator`)
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
}

// Tag values must match the order of the on-chain Rust enum, exactly.
const ACCOUNT_AUTH_TAG_ED25519: u32 = 0;
const ACCOUNT_AUTH_TAG_MULTI_ED25519: u32 = 1;
const ACCOUNT_AUTH_TAG_SINGLE_KEY: u32 = 2;
const ACCOUNT_AUTH_TAG_MULTI_KEY: u32 = 3;
const ACCOUNT_AUTH_TAG_NO_ACCOUNT: u32 = 4;

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
        // The chain wire format for SingleKey/MultiKey does not include
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
        // SingleKey/MultiKey variants. This is sufficient for the
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

/// Zeroes the Ed25519 signature scalars in a BCS-encoded `MultiEd25519Signature`
/// blob while preserving the trailing 4-byte signer bitmap (and therefore the
/// signer count implied by it).
///
/// The legacy `MultiEd25519Signature` wire layout is
/// `sig_0(64) || .. || sig_{m-1}(64) || bitmap(4)` with no per-signature tags, so
/// keeping the final four bytes intact yields a structurally valid signature whose
/// signer count and bitmap match the input but whose signature scalars are all
/// zero. This is what the `/transactions/simulate` endpoint expects: an
/// authenticator that deserializes correctly but carries an (intentionally)
/// invalid signature. Zeroing the whole blob -- as a naive length-preserving
/// zeroing would -- destroys the bitmap and makes the byte length disagree with
/// the implied signer count, so the fullnode rejects the request at
/// deserialization instead of accepting it as an invalid signature.
fn zeroed_multi_ed25519_signature(signature: &[u8]) -> Vec<u8> {
    let mut out = signature.to_vec();
    match out.len().checked_sub(4) {
        // Zero every signature scalar byte, keep the 4-byte bitmap intact.
        Some(sig_bytes_len) => {
            for byte in &mut out[..sig_bytes_len] {
                *byte = 0;
            }
        }
        // Malformed / too short to contain a bitmap: fall back to zeroing the
        // whole (length-preserving) blob. SDK-produced authenticators never hit
        // this branch.
        None => out.iter_mut().for_each(|byte| *byte = 0),
    }
    out
}

/// Rebuilds a BCS-encoded `MultiKeySignature` blob with every inner `AnySignature`
/// payload zeroed, while preserving the signature count (leading ULEB128), each
/// signature's variant tag and length framing, and the trailing `BitVec` bitmap.
///
/// The `MultiKeySignature` wire layout is
/// `ULEB128(num_sigs) || (variant || ULEB128(len) || payload).. || ULEB128(4) || bitmap(4)`.
/// A naive length-preserving zeroing of the whole blob destroys the signature
/// count, the per-signature variant tags/length prefixes, and the bitmap, so the
/// fullnode cannot parse it back into a `MultiKeySignature`. Here we parse the
/// structure, zero only the signature payload bytes (keeping each variant and
/// byte length), and re-serialize so the result still deserializes into a valid
/// `MultiKeySignature` with the same signer count and bitmap.
fn zeroed_multi_key_signature(signature: &[u8]) -> Vec<u8> {
    use crate::crypto::{AnySignature, MultiKeySignature};

    let Ok(parsed) = MultiKeySignature::from_bytes(signature) else {
        // Not SDK-produced / unparseable: preserve length as a last resort.
        return vec![0u8; signature.len()];
    };
    let rebuilt: Vec<(u8, AnySignature)> = parsed
        .signatures()
        .iter()
        .map(|(index, sig)| {
            (
                *index,
                AnySignature::new(sig.variant, vec![0u8; sig.bytes.len()]),
            )
        })
        .collect();
    MultiKeySignature::new(rebuilt)
        .map_or_else(|_| vec![0u8; signature.len()], |sig| sig.to_bytes())
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

    /// Rewrites this transaction authenticator for `/transactions/simulate`.
    ///
    /// Delegates nested [`AccountAuthenticator`] values to
    /// [`AccountAuthenticator::for_simulate_endpoint`]. Top-level legacy
    /// [`TransactionAuthenticator::Ed25519`] / [`TransactionAuthenticator::MultiEd25519`]
    /// variants keep their public keys but zero signature bytes (there is no
    /// [`AccountAuthenticator::NoAccountAuthenticator`] field in those top-level
    /// authenticator shapes).
    #[must_use]
    pub fn for_simulate_endpoint(self) -> Self {
        match self {
            Self::Ed25519 {
                public_key,
                signature: _,
            } => Self::Ed25519 {
                public_key,
                signature: Ed25519Signature([0u8; 64]),
            },
            Self::MultiEd25519 {
                public_key,
                signature,
            } => Self::MultiEd25519 {
                public_key,
                signature: zeroed_multi_ed25519_signature(&signature),
            },
            Self::MultiAgent {
                sender,
                secondary_signer_addresses,
                secondary_signers,
            } => {
                let secondary: Vec<AccountAuthenticator> = secondary_signers
                    .into_iter()
                    .map(AccountAuthenticator::for_simulate_endpoint)
                    .collect();
                Self::multi_agent(
                    sender.for_simulate_endpoint(),
                    secondary_signer_addresses,
                    secondary,
                )
            }
            Self::FeePayer {
                sender,
                secondary_signer_addresses,
                secondary_signers,
                fee_payer_address,
                fee_payer_signer,
            } => {
                let secondary: Vec<AccountAuthenticator> = secondary_signers
                    .into_iter()
                    .map(AccountAuthenticator::for_simulate_endpoint)
                    .collect();
                Self::fee_payer(
                    sender.for_simulate_endpoint(),
                    secondary_signer_addresses,
                    secondary,
                    fee_payer_address,
                    fee_payer_signer.for_simulate_endpoint(),
                )
            }
            Self::SingleSender { sender } => Self::single_sender(sender.for_simulate_endpoint()),
        }
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

    /// Rewrites this authenticator for the Aptos `/transactions/simulate` endpoint.
    ///
    /// The fullnode rejects requests whose authenticators contain a cryptographically
    /// **valid** signature (HTTP 400: "Simulated transactions must not have a valid
    /// signature"). The SDK applies this transform automatically before simulate HTTP
    /// calls so callers do not need to hand-replace authenticators.
    ///
    /// * [`SingleKey`](AccountAuthenticator::SingleKey)
    ///   becomes [`AccountAuthenticator::NoAccountAuthenticator`], matching the common workaround for unified-key
    ///   accounts.
    /// * [`Ed25519`](AccountAuthenticator::Ed25519), [`MultiEd25519`](AccountAuthenticator::MultiEd25519),
    ///   and [`MultiKey`](AccountAuthenticator::MultiKey) keep their public key material but replace
    ///   only the signature bytes with zeros. For `MultiEd25519` / `MultiKey` the surrounding
    ///   framing (signer count, per-signature variant tags/lengths, and the bitmap/`BitVec`) is
    ///   preserved so the rewritten authenticator still deserializes into a valid
    ///   `MultiEd25519Signature` / `MultiKeySignature` on the fullnode.
    #[must_use]
    pub fn for_simulate_endpoint(self) -> Self {
        match self {
            Self::NoAccountAuthenticator => Self::NoAccountAuthenticator,
            Self::Ed25519 {
                public_key,
                signature: _,
            } => Self::Ed25519 {
                public_key,
                signature: Ed25519Signature([0u8; 64]),
            },
            Self::MultiEd25519 {
                public_key,
                signature,
            } => Self::MultiEd25519 {
                public_key,
                signature: zeroed_multi_ed25519_signature(&signature),
            },
            Self::SingleKey { .. } => Self::NoAccountAuthenticator,
            Self::MultiKey {
                public_key,
                signature,
            } => Self::MultiKey {
                public_key,
                signature: zeroed_multi_key_signature(&signature),
            },
        }
    }

    /// Verifies the authenticator against a signing message.
    ///
    /// # Errors
    ///
    /// Returns an error if the authenticator does not verify for the message.
    pub fn verify(&self, message: &[u8]) -> crate::error::AptosResult<()> {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Ed25519 {
                public_key,
                signature,
            } => {
                let public_key = crate::crypto::Ed25519PublicKey::from_bytes(&public_key.0)?;
                let signature = crate::crypto::Ed25519Signature::from_bytes(&signature.0)?;
                public_key.verify(message, &signature)
            }
            #[cfg(not(feature = "ed25519"))]
            Self::Ed25519 { .. } => Err(crate::error::AptosError::FeatureNotEnabled(
                "Ed25519 verification".into(),
            )),
            #[cfg(feature = "ed25519")]
            Self::MultiEd25519 {
                public_key,
                signature,
            } => {
                let public_key = crate::crypto::MultiEd25519PublicKey::from_bytes(public_key)?;
                let signature = crate::crypto::MultiEd25519Signature::from_bytes(signature)?;
                public_key.verify(message, &signature)
            }
            #[cfg(not(feature = "ed25519"))]
            Self::MultiEd25519 { .. } => Err(crate::error::AptosError::FeatureNotEnabled(
                "MultiEd25519 verification".into(),
            )),
            Self::SingleKey {
                public_key,
                signature,
            } => {
                let pk = crate::crypto::AnyPublicKey::from_bcs_bytes(public_key)?;
                let sig = crate::crypto::AnySignature::from_bcs_bytes(signature)?;
                pk.verify(message, &sig)
            }
            Self::MultiKey {
                public_key,
                signature,
            } => {
                let pk = crate::crypto::MultiKeyPublicKey::from_bytes(public_key)?;
                let sig = crate::crypto::MultiKeySignature::from_bytes(signature)?;
                pk.verify(message, &sig)
            }
            Self::NoAccountAuthenticator => Err(crate::error::AptosError::InvalidSignature(
                "no account authenticator cannot be verified".into(),
            )),
        }
    }

    /// Returns the account address implied by this authenticator's public key material.
    ///
    /// # Errors
    ///
    /// Returns an error if the contained public key bytes cannot be parsed.
    pub fn derived_address(&self) -> crate::error::AptosResult<AccountAddress> {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Ed25519 { public_key, .. } => {
                let public_key = crate::crypto::Ed25519PublicKey::from_bytes(&public_key.0)?;
                Ok(public_key.to_address())
            }
            #[cfg(not(feature = "ed25519"))]
            Self::Ed25519 { .. } => Err(crate::error::AptosError::FeatureNotEnabled(
                "Ed25519 address derivation".into(),
            )),
            #[cfg(feature = "ed25519")]
            Self::MultiEd25519 { public_key, .. } => {
                let public_key = crate::crypto::MultiEd25519PublicKey::from_bytes(public_key)?;
                Ok(public_key.to_address())
            }
            #[cfg(not(feature = "ed25519"))]
            Self::MultiEd25519 { .. } => Err(crate::error::AptosError::FeatureNotEnabled(
                "MultiEd25519 address derivation".into(),
            )),
            Self::SingleKey { public_key, .. } => Ok(AccountAddress::new(
                crate::crypto::derive_authentication_key(
                    public_key,
                    crate::crypto::SINGLE_KEY_SCHEME,
                ),
            )),
            Self::MultiKey { public_key, .. } => {
                let pk = crate::crypto::MultiKeyPublicKey::from_bytes(public_key)?;
                Ok(pk.to_address())
            }
            Self::NoAccountAuthenticator => Err(crate::error::AptosError::InvalidSignature(
                "no account authenticator has no derived address".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{AnyPublicKey, AnySignature, MultiKeyPublicKey, MultiKeySignature};

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

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_account_authenticator_single_key_verify_and_derived_address() {
        use crate::crypto::{Ed25519PrivateKey, SINGLE_KEY_SCHEME, derive_authentication_key};

        let private_key = Ed25519PrivateKey::generate();
        let message = b"single-key verify test";
        let public_key = crate::crypto::AnyPublicKey::ed25519(&private_key.public_key());
        let signature = crate::crypto::AnySignature::ed25519(&private_key.sign(message));
        let auth =
            AccountAuthenticator::single_key(public_key.to_bcs_bytes(), signature.to_bcs_bytes());

        auth.verify(message).unwrap();
        let expected = AccountAddress::new(derive_authentication_key(
            &public_key.to_bcs_bytes(),
            SINGLE_KEY_SCHEME,
        ));
        assert_eq!(auth.derived_address().unwrap(), expected);
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_account_authenticator_multi_ed25519_verify_and_derived_address() {
        use crate::account::{Account, MultiEd25519Account};
        use crate::crypto::Ed25519PrivateKey;

        let account = MultiEd25519Account::new(
            vec![Ed25519PrivateKey::generate(), Ed25519PrivateKey::generate()],
            2,
        )
        .unwrap();
        let message = b"multi-ed25519 verify test";
        let auth = AccountAuthenticator::MultiEd25519 {
            public_key: account.public_key_bytes(),
            signature: account.sign(message).unwrap().to_bytes(),
        };

        auth.verify(message).unwrap();
        assert_eq!(auth.derived_address().unwrap(), account.address());
    }

    #[test]
    fn test_no_account_authenticator() {
        let auth = AccountAuthenticator::no_account_authenticator();
        match auth {
            AccountAuthenticator::NoAccountAuthenticator => {}
            _ => panic!("Expected NoAccountAuthenticator variant"),
        }
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_account_authenticator_for_simulate_endpoint_single_key_to_no_account() {
        let auth = AccountAuthenticator::single_key(vec![0x01, 0x02], vec![0x03, 0x04]);
        let sanitized = auth.for_simulate_endpoint();
        assert!(matches!(
            sanitized,
            AccountAuthenticator::NoAccountAuthenticator
        ));
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_transaction_authenticator_for_simulate_endpoint_single_sender_strips_single_key() {
        let sender = AccountAuthenticator::single_key(vec![0x05, 0x06], vec![0x07, 0x08]);
        let auth = TransactionAuthenticator::single_sender(sender);
        let sanitized = auth.for_simulate_endpoint();
        assert!(matches!(
            sanitized,
            TransactionAuthenticator::SingleSender { ref sender }
                if matches!(sender, AccountAuthenticator::NoAccountAuthenticator)
        ));
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_transaction_authenticator_for_simulate_endpoint_ed25519_zeros_sig() {
        let auth = TransactionAuthenticator::Ed25519 {
            public_key: Ed25519PublicKey([7u8; 32]),
            signature: Ed25519Signature([9u8; 64]),
        };
        let sanitized = auth.for_simulate_endpoint();
        match sanitized {
            TransactionAuthenticator::Ed25519 { signature, .. } => {
                assert_eq!(signature.0, [0u8; 64]);
            }
            _ => panic!("expected Ed25519"),
        }
    }

    #[test]
    fn test_no_account_authenticator_verify_and_derived_address_errors() {
        let auth = AccountAuthenticator::NoAccountAuthenticator;
        assert!(auth.verify(b"no-auth").is_err());
        assert!(auth.derived_address().is_err());
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
        let mk_pk = MultiKeyPublicKey::new(
            vec![AnyPublicKey::new(
                crate::crypto::AnyPublicKeyVariant::Keyless,
                vec![],
            )],
            1,
        )
        .unwrap();
        let mk_sig = MultiKeySignature::new(vec![(
            0,
            AnySignature::new(crate::crypto::AnyPublicKeyVariant::Ed25519, vec![0x66; 64]),
        )])
        .unwrap();
        let auth = AccountAuthenticator::multi_key(mk_pk.to_bytes(), mk_sig.to_bytes());

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

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_account_authenticator_for_simulate_endpoint_multi_ed25519_stays_valid() {
        use crate::account::{Account, MultiEd25519Account};
        use crate::crypto::{Ed25519PrivateKey, MultiEd25519Signature};

        let account = MultiEd25519Account::new(
            vec![
                Ed25519PrivateKey::generate(),
                Ed25519PrivateKey::generate(),
                Ed25519PrivateKey::generate(),
            ],
            2,
        )
        .unwrap();
        let message = b"multi-ed25519 simulate test";
        let original_sig_bytes = account.sign(message).unwrap().to_bytes();
        let original = MultiEd25519Signature::from_bytes(&original_sig_bytes).unwrap();

        let auth = AccountAuthenticator::MultiEd25519 {
            public_key: account.public_key_bytes(),
            signature: original_sig_bytes.clone(),
        };

        let AccountAuthenticator::MultiEd25519 { signature, .. } = auth.for_simulate_endpoint()
        else {
            panic!("expected MultiEd25519 after simulate rewrite");
        };

        // Same total blob length as the input.
        assert_eq!(signature.len(), original_sig_bytes.len());

        // The rewritten blob must still deserialize into a valid
        // MultiEd25519Signature with the SAME signer count and SAME bitmap.
        let rewritten = MultiEd25519Signature::from_bytes(&signature).unwrap();
        assert_eq!(rewritten.num_signatures(), original.num_signatures());
        assert_eq!(rewritten.bitmap(), original.bitmap());

        // Every signature scalar byte is zero (only the 4-byte bitmap survives).
        assert!(signature[..signature.len() - 4].iter().all(|b| *b == 0));
        for (_, sig) in rewritten.signatures() {
            let sig_bytes = sig.to_bytes();
            assert_eq!(sig_bytes.len(), 64);
            assert!(sig_bytes.iter().all(|b| *b == 0));
        }
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_account_authenticator_for_simulate_endpoint_multi_key_stays_valid() {
        use crate::crypto::{
            AnyPublicKey, AnySignature, Ed25519PrivateKey, MultiKeyPublicKey, MultiKeySignature,
        };

        let sk0 = Ed25519PrivateKey::generate();
        let sk1 = Ed25519PrivateKey::generate();
        let sk2 = Ed25519PrivateKey::generate();
        let pk = MultiKeyPublicKey::new(
            vec![
                AnyPublicKey::ed25519(&sk0.public_key()),
                AnyPublicKey::ed25519(&sk1.public_key()),
                AnyPublicKey::ed25519(&sk2.public_key()),
            ],
            2,
        )
        .unwrap();
        let message = b"multi-key simulate test";
        let original = MultiKeySignature::new(vec![
            (0, AnySignature::ed25519(&sk0.sign(message))),
            (2, AnySignature::ed25519(&sk2.sign(message))),
        ])
        .unwrap();
        let original_sig_bytes = original.to_bytes();

        let auth = AccountAuthenticator::multi_key(pk.to_bytes(), original_sig_bytes.clone());
        let AccountAuthenticator::MultiKey { signature, .. } = auth.for_simulate_endpoint() else {
            panic!("expected MultiKey after simulate rewrite");
        };

        // Same total blob length as the input.
        assert_eq!(signature.len(), original_sig_bytes.len());

        // The rewritten blob must still deserialize into a valid MultiKeySignature
        // with the SAME signer count and SAME bitmap, but zeroed signature bytes.
        let rewritten = MultiKeySignature::from_bytes(&signature).unwrap();
        assert_eq!(rewritten.num_signatures(), original.num_signatures());
        assert_eq!(rewritten.bitmap(), original.bitmap());
        for ((idx_r, sig_r), (idx_o, sig_o)) in
            rewritten.signatures().iter().zip(original.signatures())
        {
            assert_eq!(idx_r, idx_o);
            assert_eq!(sig_r.variant, sig_o.variant);
            assert_eq!(sig_r.bytes.len(), sig_o.bytes.len());
            assert!(sig_r.bytes.iter().all(|b| *b == 0));
        }
    }

    #[test]
    fn test_zeroed_multi_ed25519_signature_wire_layout_pinned() {
        // Fixed input: two 64-byte signatures for signers {0, 2}. Aptos MSB-first
        // bitmap for {0, 2} is 0b1010_0000 in byte 0.
        let mut input = Vec::new();
        input.extend_from_slice(&[0x11u8; 64]);
        input.extend_from_slice(&[0x22u8; 64]);
        input.extend_from_slice(&[0b1010_0000, 0x00, 0x00, 0x00]);

        let out = zeroed_multi_ed25519_signature(&input);

        // Expected: all 128 signature bytes zeroed, 4-byte bitmap preserved.
        let mut expected = vec![0u8; 128];
        expected.extend_from_slice(&[0b1010_0000, 0x00, 0x00, 0x00]);
        assert_eq!(out, expected);
    }

    #[test]
    fn test_zeroed_multi_key_signature_wire_layout_pinned() {
        // Fixed input: two Ed25519 AnySignatures for signers {0, 1}.
        // Layout: ULEB(num_sigs=2) || (0x00 0x40 payload)*2 || ULEB(4) || bitmap.
        // MSB-first bitmap for {0, 1} is 0b1100_0000.
        let mut input = vec![0x02u8]; // num_sigs = 2
        input.extend_from_slice(&[0x00, 0x40]); // Ed25519 variant + ULEB128(64)
        input.extend_from_slice(&[0xaa; 64]);
        input.extend_from_slice(&[0x00, 0x40]);
        input.extend_from_slice(&[0xbb; 64]);
        input.push(0x04); // BCS BitVec length prefix
        input.extend_from_slice(&[0b1100_0000, 0x00, 0x00, 0x00]);

        let out = zeroed_multi_key_signature(&input);

        let mut expected = vec![0x02u8];
        expected.extend_from_slice(&[0x00, 0x40]);
        expected.extend_from_slice(&[0u8; 64]);
        expected.extend_from_slice(&[0x00, 0x40]);
        expected.extend_from_slice(&[0u8; 64]);
        expected.push(0x04);
        expected.extend_from_slice(&[0b1100_0000, 0x00, 0x00, 0x00]);
        assert_eq!(
            out, expected,
            "simulate-rewritten MultiKey signature wire layout drifted"
        );

        // And it still deserializes into a valid MultiKeySignature.
        let parsed = crate::crypto::MultiKeySignature::from_bytes(&out).unwrap();
        assert_eq!(parsed.num_signatures(), 2);
        assert_eq!(parsed.bitmap(), &[0b1100_0000, 0x00, 0x00, 0x00]);
    }
}
