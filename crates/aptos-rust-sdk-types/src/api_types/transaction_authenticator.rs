// Copyright © Aptos Foundation
// Parts of the project are originally copyright © Meta Platforms, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::api_types::address::AccountAddress;
use crate::api_types::transaction::{RawTransaction, RawTransactionWithData};
use crate::crypto::ed25519::public_key::Ed25519PublicKey;
use crate::crypto::ed25519::signature::Ed25519Signature;
use crate::crypto::hash::HashValue;
use anyhow::{bail, ensure};
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::hash::Hash;
use std::str::FromStr;
use thiserror::Error;

/// Maximum number of signatures supported in `TransactionAuthenticator`,
/// across all `AccountAuthenticator`s included.
pub const MAX_NUM_OF_SIGS: usize = 32;

/// An error enum for issues related to transaction or account authentication.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum AuthenticationError {
    /// The number of signatures exceeds the maximum supported.
    MaxSignaturesExceeded,
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Each transaction submitted to the Aptos blockchain contains a `TransactionAuthenticator`. During
/// transaction execution, the executor will check if every `AccountAuthenticator`'s signature on
/// the transaction hash is well-formed and whether the sha3 hash of the
/// `AccountAuthenticator`'s `AuthenticationKeyPreimage` matches the `AuthenticationKey` stored
/// under the participating signer's account address.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum TransactionAuthenticator {
    /// Single Ed25519 signature
    Ed25519 {
        public_key: Ed25519PublicKey,
        signature: Ed25519Signature,
    },
    /// Multi-agent transaction.
    MultiAgent {
        sender: AccountAuthenticator,
        secondary_signer_addresses: Vec<AccountAddress>,
        secondary_signers: Vec<AccountAuthenticator>,
    },
    /// Optional Multi-agent transaction with a fee payer.
    FeePayer {
        sender: AccountAuthenticator,
        secondary_signer_addresses: Vec<AccountAddress>,
        secondary_signers: Vec<AccountAuthenticator>,
        fee_payer_address: AccountAddress,
        fee_payer_signer: AccountAuthenticator,
    },
    SingleSender {
        sender: AccountAuthenticator,
    },
}

impl TransactionAuthenticator {
    /// Create a single-signature ed25519 authenticator
    pub fn ed25519(public_key: Ed25519PublicKey, signature: Ed25519Signature) -> Self {
        Self::Ed25519 {
            public_key,
            signature,
        }
    }

    /// Create a (optional) multi-agent fee payer authenticator
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

    /// Create a multi-agent authenticator
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

    /// Create a single-sender authenticator
    pub fn single_sender(sender: AccountAuthenticator) -> Self {
        Self::SingleSender { sender }
    }

    /// Return Ok if all AccountAuthenticator's public keys match their signatures, Err otherwise
    pub fn verify(&self, raw_txn: &RawTransaction) -> anyhow::Result<()> {
        let num_sigs: usize = self.sender().number_of_signatures()
            + self
                .secondary_signers()
                .iter()
                .map(|auth| auth.number_of_signatures())
                .sum::<usize>();
        if num_sigs > MAX_NUM_OF_SIGS {
            return Err(anyhow::Error::new(
                AuthenticationError::MaxSignaturesExceeded,
            ));
        }
        match self {
            Self::Ed25519 {
                public_key,
                signature,
            } => signature.verify(raw_txn, public_key),
            Self::FeePayer {
                sender,
                secondary_signer_addresses,
                secondary_signers,
                fee_payer_address,
                fee_payer_signer,
            } => {
                // In the fee payer model, the fee payer address can be optionally signed. We
                // realized when we designed the fee payer model, that we made it too restrictive
                // by requiring the signature over the fee payer address. So now we need to live in
                // a world where we support a multitude of different solutions. The modern approach
                // assumes that some may sign over the address and others will sign over the zero
                // address, so we verify both and only fail if the signature fails for either of
                // them. The legacy approach is to assume the address of the fee payer is signed
                // over.
                /*let mut to_verify = vec![sender];
                let _ = secondary_signers
                    .iter()
                    .map(|signer| to_verify.push(signer))
                    .collect::<Vec<_>>();

                let no_fee_payer_address_message = RawTransactionWithData::new_fee_payer(
                    raw_txn.clone(),
                    secondary_signer_addresses.clone(),
                    AccountAddress::ZERO,
                );

                let mut remaining = to_verify
                    .iter()
                    .filter(|verifier| verifier.verify(&no_fee_payer_address_message).is_err())
                    .collect::<Vec<_>>();

                remaining.push(&fee_payer_signer);

                let fee_payer_address_message = RawTransactionWithData::new_fee_payer(
                    raw_txn.clone(),
                    secondary_signer_addresses.clone(),
                    *fee_payer_address,
                );

                for verifier in remaining {
                    verifier.verify(&fee_payer_address_message)?;
                }

                Ok(())*/
                unimplemented!("TODO")
            }
            Self::MultiAgent {
                sender,
                secondary_signer_addresses,
                secondary_signers,
            } => {
                let message = RawTransactionWithData::new_multi_agent(
                    raw_txn.clone(),
                    secondary_signer_addresses.clone(),
                );
                sender.verify(&message)?;
                for signer in secondary_signers {
                    signer.verify(&message)?;
                }
                Ok(())
            }
            Self::SingleSender { sender } => sender.verify(raw_txn),
        }
    }

    pub fn sender(&self) -> AccountAuthenticator {
        match self {
            Self::Ed25519 {
                public_key,
                signature,
            } => AccountAuthenticator::ed25519(public_key.clone(), signature.clone()),
            Self::FeePayer { sender, .. } => sender.clone(),
            Self::MultiAgent { sender, .. } => sender.clone(),
            Self::SingleSender { sender } => sender.clone(),
        }
    }

    pub fn secondary_signer_addresses(&self) -> Vec<AccountAddress> {
        match self {
            Self::Ed25519 { .. } | Self::SingleSender { .. } => {
                vec![]
            }
            Self::FeePayer {
                sender: _,
                secondary_signer_addresses,
                ..
            } => secondary_signer_addresses.to_vec(),
            Self::MultiAgent {
                sender: _,
                secondary_signer_addresses,
                ..
            } => secondary_signer_addresses.to_vec(),
        }
    }

    pub fn secondary_signers(&self) -> Vec<AccountAuthenticator> {
        match self {
            Self::Ed25519 { .. } | Self::SingleSender { .. } => {
                vec![]
            }
            Self::FeePayer {
                sender: _,
                secondary_signer_addresses: _,
                secondary_signers,
                ..
            } => secondary_signers.to_vec(),
            Self::MultiAgent {
                sender: _,
                secondary_signer_addresses: _,
                secondary_signers,
            } => secondary_signers.to_vec(),
        }
    }

    pub fn fee_payer_address(&self) -> Option<AccountAddress> {
        match self {
            Self::Ed25519 { .. } | Self::MultiAgent { .. } | Self::SingleSender { .. } => None,
            Self::FeePayer {
                sender: _,
                secondary_signer_addresses: _,
                secondary_signers: _,
                fee_payer_address,
                ..
            } => Some(*fee_payer_address),
        }
    }

    pub fn fee_payer_signer(&self) -> Option<AccountAuthenticator> {
        match self {
            Self::Ed25519 { .. } | Self::MultiAgent { .. } | Self::SingleSender { .. } => None,
            Self::FeePayer {
                sender: _,
                secondary_signer_addresses: _,
                secondary_signers: _,
                fee_payer_address: _,
                fee_payer_signer,
            } => Some(fee_payer_signer.clone()),
        }
    }

    pub fn all_signers(&self) -> Vec<AccountAuthenticator> {
        match self {
            // This is to ensure that any new TransactionAuthenticator variant must update this function.
            Self::Ed25519 { .. }
            | Self::MultiAgent { .. }
            | Self::FeePayer { .. }
            | Self::SingleSender { .. } => {
                let mut account_authenticators: Vec<AccountAuthenticator> = vec![];
                account_authenticators.push(self.sender());
                account_authenticators.extend(self.secondary_signers());
                if let Some(fee_payer) = self.fee_payer_signer() {
                    account_authenticators.push(fee_payer);
                }
                account_authenticators
            }
        }
    }

    pub fn to_single_key_authenticators(&self) -> anyhow::Result<Vec<SingleKeyAuthenticator>> {
        let account_authenticators = self.all_signers();
        let mut single_key_authenticators: Vec<SingleKeyAuthenticator> =
            Vec::with_capacity(MAX_NUM_OF_SIGS);
        for account_authenticator in account_authenticators {
            match account_authenticator {
                AccountAuthenticator::Ed25519 {
                    public_key,
                    signature,
                } => {
                    let authenticator = SingleKeyAuthenticator {
                        public_key: AnyPublicKey::ed25519(public_key.clone()),
                        signature: AnySignature::ed25519(signature.clone()),
                    };
                    single_key_authenticators.push(authenticator);
                }
                AccountAuthenticator::SingleKey { authenticator } => {
                    single_key_authenticators.push(authenticator);
                }
                AccountAuthenticator::MultiKey { authenticator } => {
                    single_key_authenticators.extend(authenticator.to_single_key_authenticators()?);
                }
            };
        }
        Ok(single_key_authenticators)
    }
}

impl fmt::Display for TransactionAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519 { .. } => {
                write!(
                    f,
                    "TransactionAuthenticator[scheme: Ed25519, sender: {}]",
                    self.sender()
                )
            }
            Self::FeePayer {
                sender,
                secondary_signer_addresses,
                secondary_signers,
                fee_payer_address,
                fee_payer_signer,
            } => {
                let mut sec_addrs: String = "".to_string();
                for sec_addr in secondary_signer_addresses {
                    sec_addrs = format!("{}\n\t\t\t{:#?},", sec_addrs, sec_addr);
                }
                let mut sec_signers: String = "".to_string();
                for sec_signer in secondary_signers {
                    sec_signers = format!("{}\n\t\t\t{:#?},", sec_signers, sec_signer);
                }
                write!(
                    f,
                    "TransactionAuthenticator[\n\
                        \tscheme: MultiAgent, \n\
                        \tsender: {}\n\
                        \tsecondary signer addresses: {}\n\
                        \tsecondary signers: {}\n\n
                        \tfee payer address: {}\n\n
                        \tfee payer signer: {}]",
                    sender, sec_addrs, sec_signers, fee_payer_address, fee_payer_signer,
                )
            }
            Self::MultiAgent {
                sender,
                secondary_signer_addresses,
                secondary_signers,
            } => {
                let mut sec_addrs: String = "".to_string();
                for sec_addr in secondary_signer_addresses {
                    sec_addrs = format!("{}\n\t\t\t{:#?},", sec_addrs, sec_addr);
                }
                let mut sec_signers: String = "".to_string();
                for sec_signer in secondary_signers {
                    sec_signers = format!("{}\n\t\t\t{:#?},", sec_signers, sec_signer);
                }
                write!(
                    f,
                    "TransactionAuthenticator[\n\
                        \tscheme: MultiAgent, \n\
                        \tsender: {}\n\
                        \tsecondary signer addresses: {}\n\
                        \tsecondary signers: {}]",
                    sender, sec_addrs, sec_signers,
                )
            }
            Self::SingleSender { sender } => {
                write!(
                    f,
                    "TransactionAuthenticator[scheme: SingleSender, sender: {}]",
                    sender
                )
            }
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum Scheme {
    Ed25519 = 0,
    SingleKey = 2,
    MultiKey = 3,
    /// Add new derived schemes below.
    DeriveAuid = 251,
    DeriveObjectAddressFromObject = 252,
    DeriveObjectAddressFromGuid = 253,
    DeriveObjectAddressFromSeed = 254,
    DeriveResourceAccountAddress = 255,
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display = match self {
            Scheme::Ed25519 => "Ed25519",
            Scheme::SingleKey => "SingleKey",
            Scheme::MultiKey => "MultiKey",
            Scheme::DeriveAuid => "DeriveAuid",
            Scheme::DeriveObjectAddressFromObject => "DeriveObjectAddressFromObject",
            Scheme::DeriveObjectAddressFromGuid => "DeriveObjectAddressFromGuid",
            Scheme::DeriveObjectAddressFromSeed => "DeriveObjectAddressFromSeed",
            Scheme::DeriveResourceAccountAddress => "DeriveResourceAccountAddress",
        };
        write!(f, "Scheme::{}", display)
    }
}

/// An `AccountAuthenticator` is an an abstraction of a signature scheme. It must know:
/// (1) How to check its signature against a message and public key
/// (2) How to convert its public key into an `AuthenticationKeyPreimage` structured as
/// (public_key | signature_scheme_id).
/// Each on-chain `Account` must store an `AuthenticationKey` (computed via a sha3 hash of `(public
/// key bytes | scheme as u8)`).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum AccountAuthenticator {
    /// Ed25519 Single signature
    Ed25519 {
        public_key: Ed25519PublicKey,
        signature: Ed25519Signature,
    },
    /// Ed25519 K-of-N multisignature
    SingleKey {
        authenticator: SingleKeyAuthenticator,
    },
    MultiKey {
        authenticator: MultiKeyAuthenticator,
    },
    // ... add more schemes here
}

impl AccountAuthenticator {
    /// Unique identifier for the signature scheme
    pub fn scheme(&self) -> Scheme {
        match self {
            Self::Ed25519 { .. } => Scheme::Ed25519,
            Self::SingleKey { .. } => Scheme::SingleKey,
            Self::MultiKey { .. } => Scheme::MultiKey,
        }
    }

    /// Create a single-signature ed25519 authenticator
    pub fn ed25519(public_key: Ed25519PublicKey, signature: Ed25519Signature) -> Self {
        Self::Ed25519 {
            public_key,
            signature,
        }
    }

    /// Create a single-signature authenticator
    pub fn single_key(authenticator: SingleKeyAuthenticator) -> Self {
        Self::SingleKey { authenticator }
    }

    /// Create a multi-signature authenticator
    pub fn multi_key(authenticator: MultiKeyAuthenticator) -> Self {
        Self::MultiKey { authenticator }
    }

    /// Return Ok if the authenticator's public key matches its signature, Err otherwise
    pub fn verify<T: Serialize + Hash>(&self, message: &T) -> Result<(), anyhow::Error> {
        match self {
            Self::Ed25519 {
                public_key,
                signature,
            } => signature.verify(message, public_key),
            Self::SingleKey { authenticator } => authenticator.verify(message),
            Self::MultiKey { authenticator } => authenticator.verify(message),
        }
    }

    /// Return the raw bytes of `self.public_key`
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ed25519 { public_key, .. } => public_key.to_bytes().to_vec(),
            Self::SingleKey { authenticator } => authenticator.public_key_bytes(),
            Self::MultiKey { authenticator } => authenticator.public_key_bytes(),
        }
    }

    /// Return the raw bytes of `self.signature`
    pub fn signature_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ed25519 { signature, .. } => signature.to_bytes().to_vec(),
            Self::SingleKey { authenticator } => authenticator.signature_bytes(),
            Self::MultiKey { authenticator } => authenticator.signature_bytes(),
        }
    }

    /// Return an authentication key derived from `self`'s public key and scheme id
    pub fn authentication_key(&self) -> AuthenticationKey {
        AuthenticationKey::from_preimage(self.public_key_bytes(), self.scheme())
    }

    /// Return the number of signatures included in this account authenticator.
    pub fn number_of_signatures(&self) -> usize {
        match self {
            Self::Ed25519 { .. } => 1,
            Self::SingleKey { .. } => 1,
            Self::MultiKey { authenticator } => authenticator.signatures.len(),
        }
    }
}

/// A struct that represents an account authentication key. An account's address is the last 32
/// bytes of authentication key used to create it
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthenticationKey([u8; AuthenticationKey::LENGTH]);

impl AuthenticationKey {
    /// The number of bytes in an authentication key.
    pub const LENGTH: usize = AccountAddress::LENGTH;

    /// Create an authentication key from `bytes`
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Return an authentication key that is impossible (in expectation) to sign for--useful for
    /// intentionally relinquishing control of an account.
    pub const fn zero() -> Self {
        Self([0; 32])
    }

    /// Create an authentication key from a preimage by taking its sha3 hash
    pub fn from_preimage(mut public_key_bytes: Vec<u8>, scheme: Scheme) -> AuthenticationKey {
        public_key_bytes.push(scheme as u8);
        AuthenticationKey::new(*HashValue::sha3_256(&public_key_bytes).as_slice())
    }

    /// Construct a preimage from a transaction-derived AUID as (txn_hash || auid_scheme_id)
    pub fn auid(txn_hash: Vec<u8>, auid_counter: u64) -> Self {
        let mut hash_arg = Vec::new();
        hash_arg.extend(txn_hash);
        hash_arg.extend(auid_counter.to_le_bytes().to_vec());
        Self::from_preimage(hash_arg, Scheme::DeriveAuid)
    }

    /// Create an authentication key from an Ed25519 public key
    pub fn ed25519(public_key: &Ed25519PublicKey) -> AuthenticationKey {
        Self::from_preimage(public_key.to_bytes().to_vec(), Scheme::Ed25519)
    }

    /// Create an authentication key from an AnyPublicKey
    pub fn any_key(public_key: AnyPublicKey) -> AuthenticationKey {
        Self::from_preimage(public_key.to_bytes(), Scheme::SingleKey)
    }

    /// Create an authentication key from multiple AnyPublicKeys
    pub fn multi_key(public_keys: MultiKey) -> AuthenticationKey {
        Self::from_preimage(public_keys.to_bytes(), Scheme::MultiKey)
    }

    /// Return the authentication key as an account address
    pub fn account_address(&self) -> AccountAddress {
        AccountAddress::new(self.0)
    }

    /// Construct a vector from this authentication key
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Create a random authentication key. For testing only
    pub fn random() -> Self {
        let mut rng = OsRng;
        let buf: [u8; Self::LENGTH] = rng.gen();
        AuthenticationKey::new(buf)
    }
}

impl fmt::Display for AccountAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AccountAuthenticator[scheme id: {:?}, public key: {}, signature: {}]",
            self.scheme(),
            hex::encode(self.public_key_bytes()),
            hex::encode(self.signature_bytes())
        )
    }
}

impl TryFrom<&[u8]> for AuthenticationKey {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> std::result::Result<AuthenticationKey, anyhow::Error> {
        if bytes.len() != Self::LENGTH {
            return Err(anyhow::anyhow!("Wrong length for AuthenticationKey"));
        }
        let mut addr = [0u8; Self::LENGTH];
        addr.copy_from_slice(bytes);
        Ok(AuthenticationKey(addr))
    }
}

impl TryFrom<Vec<u8>> for AuthenticationKey {
    type Error = anyhow::Error;

    fn try_from(bytes: Vec<u8>) -> std::result::Result<AuthenticationKey, anyhow::Error> {
        AuthenticationKey::try_from(&bytes[..])
    }
}

impl FromStr for AuthenticationKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, anyhow::Error> {
        ensure!(
            !s.is_empty(),
            "authentication key string should not be empty.",
        );
        let bytes_out = ::hex::decode(s)?;
        let key = AuthenticationKey::try_from(bytes_out.as_slice())?;
        Ok(key)
    }
}

impl AsRef<[u8]> for AuthenticationKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::LowerHex for AuthenticationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Display for AuthenticationKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        // Forward to the LowerHex impl with a "0x" prepended (the # flag).
        write!(f, "{:#x}", self)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct MultiKeyAuthenticator {
    public_keys: MultiKey,
    signatures: Vec<AnySignature>,
    // TODO: signatures_bitmap: aptos_bitvec::BitVec,
}

impl MultiKeyAuthenticator {
    pub fn new(
        public_keys: MultiKey,
        _signatures: Vec<(u8, AnySignature)>,
    ) -> Result<Self, anyhow::Error> {
        ensure!(
            public_keys.len() < (u8::MAX as usize),
            "Too many public keys, {}, in MultiKeyAuthenticator.",
            public_keys.len(),
        );
        unimplemented!("Needs aptos bitvec");
        /*let mut signatures_bitmap = aptos_bitvec::BitVec::with_num_bits(public_keys.len() as u16);
        let mut any_signatures = vec![];

        for (idx, signature) in signatures {
            ensure!(
                (idx as usize) < public_keys.len(),
                "Signature index is out of public key range, {} < {}.",
                idx,
                public_keys.len(),
            );
            ensure!(
                !signatures_bitmap.is_set(idx as u16),
                "Duplicate signature index, {}.",
                idx
            );
            signatures_bitmap.set(idx as u16);
            any_signatures.push(signature);
        }

        Ok(MultiKeyAuthenticator {
            public_keys,
            signatures: any_signatures,
            signatures_bitmap,
        })*/
    }

    pub fn public_keys(&self) -> &MultiKey {
        &self.public_keys
    }

    pub fn signatures(&self) -> Vec<(u8, &AnySignature)> {
        let mut values = vec![];
        for (idx, signature) in
            std::iter::zip(self.signatures_bitmap.iter_ones(), self.signatures.iter())
        {
            values.push((idx as u8, signature));
        }
        values
    }

    pub fn to_single_key_authenticators(
        &self,
    ) -> Result<Vec<SingleKeyAuthenticator>, anyhow::Error> {
        ensure!(
            self.signatures_bitmap.last_set_bit().is_some(),
            "There were no signatures set in the bitmap."
        );

        ensure!(
            (self.signatures_bitmap.last_set_bit().unwrap() as usize) < self.public_keys.len(),
            "Mismatch in the position of the last signature and the number of PKs, {} >= {}.",
            self.signatures_bitmap.last_set_bit().unwrap(),
            self.public_keys.len(),
        );
        ensure!(
            self.signatures_bitmap.count_ones() as usize == self.signatures.len(),
            "Mismatch in number of signatures and the number of bits set in the signatures_bitmap, {} != {}.",
            self.signatures_bitmap.count_ones(),
            self.signatures.len(),
        );
        ensure!(
            self.signatures.len() >= self.public_keys.signatures_required() as usize,
            "Not enough signatures for verification, {} < {}.",
            self.signatures.len(),
            self.public_keys.signatures_required(),
        );
        let authenticators: Vec<SingleKeyAuthenticator> =
            std::iter::zip(self.signatures_bitmap.iter_ones(), self.signatures.iter())
                .map(|(idx, sig)| SingleKeyAuthenticator {
                    public_key: self.public_keys.public_keys[idx].clone(),
                    signature: sig.clone(),
                })
                .collect();
        Ok(authenticators)
    }

    pub fn verify<T: Serialize + Hash>(&self, message: &T) -> Result<(), anyhow::Error> {
        let authenticators = self.to_single_key_authenticators()?;
        authenticators
            .iter()
            .try_for_each(|authenticator| authenticator.verify(message))?;
        Ok(())
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_keys.to_bytes()
    }

    pub fn signature_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(&(&self.signatures, &self.signatures_bitmap))
            .expect("Only unhandleable errors happen here.")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MultiKey {
    public_keys: Vec<AnyPublicKey>,
    signatures_required: u8,
}

impl MultiKey {
    pub fn new(
        public_keys: Vec<AnyPublicKey>,
        signatures_required: u8,
    ) -> Result<Self, anyhow::Error> {
        ensure!(
            signatures_required > 0,
            "The number of required signatures is 0."
        );

        ensure!(
            public_keys.len() >= signatures_required as usize,
            "The number of public keys is smaller than the number of required signatures, {} < {}",
            public_keys.len(),
            signatures_required
        );

        Ok(Self {
            public_keys,
            signatures_required,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.public_keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.public_keys.len()
    }

    pub fn public_keys(&self) -> &[AnyPublicKey] {
        &self.public_keys
    }

    pub fn signatures_required(&self) -> u8 {
        self.signatures_required
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(&self).expect("Only unhandleable errors happen here.")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SingleKeyAuthenticator {
    public_key: AnyPublicKey,
    signature: AnySignature,
}

impl SingleKeyAuthenticator {
    pub fn new(public_key: AnyPublicKey, signature: AnySignature) -> Self {
        Self {
            public_key,
            signature,
        }
    }

    pub fn public_key(&self) -> &AnyPublicKey {
        &self.public_key
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes()
    }

    pub fn signature(&self) -> &AnySignature {
        &self.signature
    }

    pub fn signature_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(&self.signature).expect("Only unhandleable errors happen here.")
    }

    pub fn verify<T: Serialize + Hash>(&self, message: &T) -> Result<(), anyhow::Error> {
        self.signature.verify(&self.public_key, message)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum AnySignature {
    Ed25519 { signature: Ed25519Signature },
}

impl AnySignature {
    pub fn ed25519(signature: Ed25519Signature) -> Self {
        Self::Ed25519 { signature }
    }

    pub fn verify<T: Serialize + Hash>(
        &self,
        public_key: &AnyPublicKey,
        message: &T,
    ) -> Result<(), anyhow::Error> {
        match (self, public_key) {
            (Self::Ed25519 { signature }, AnyPublicKey::Ed25519 { public_key }) => {
                signature.verify(message, public_key)
            }
            _ => bail!("Invalid key, signature pairing"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum AnyPublicKey {
    Ed25519 { public_key: Ed25519PublicKey },
}

impl AnyPublicKey {
    pub fn ed25519(public_key: Ed25519PublicKey) -> Self {
        Self::Ed25519 { public_key }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("Only unhandleable errors happen here.")
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum EphemeralSignature {
    Ed25519 { signature: Ed25519Signature },
}

impl EphemeralSignature {
    pub fn ed25519(signature: Ed25519Signature) -> Self {
        Self::Ed25519 { signature }
    }

    pub fn verify<T: Serialize>(
        &self,
        message: &T,
        public_key: &EphemeralPublicKey,
    ) -> Result<(), anyhow::Error> {
        match (self, public_key) {
            (Self::Ed25519 { signature }, EphemeralPublicKey::Ed25519 { public_key }) => {
                signature.verify(message, public_key)
            }
            _ => {
                bail!("Unsupported ephemeral signature and public key combination");
            }
        }
    }
}

impl TryFrom<&[u8]> for EphemeralSignature {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        bcs::from_bytes::<EphemeralSignature>(bytes)
            .map_err(|_e| anyhow::anyhow!("Invalid signature"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum EphemeralPublicKey {
    Ed25519 { public_key: Ed25519PublicKey },
}

impl EphemeralPublicKey {
    pub fn ed25519(public_key: Ed25519PublicKey) -> Self {
        Self::Ed25519 { public_key }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("Only unhandleable errors happen here.")
    }
}

impl TryFrom<&[u8]> for EphemeralPublicKey {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        bcs::from_bytes::<EphemeralPublicKey>(bytes)
            .map_err(|_e| anyhow::Error::msg("Error deserializing ephemeral public key"))
    }
}

impl<'de> Deserialize<'de> for EphemeralPublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <String>::deserialize(deserializer)?;
            EphemeralPublicKey::try_from(
                hex::decode(s).map_err(serde::de::Error::custom)?.as_slice(),
            )
            .map_err(serde::de::Error::custom)
        } else {
            // In order to preserve the Serde data model and help analysis tools,
            // make sure to wrap our value in a container with the same name
            // as the original type.
            #[derive(::serde::Deserialize)]
            #[serde(rename = "EphemeralPublicKey")]
            enum Value {
                Ed25519 { public_key: Ed25519PublicKey },
            }

            let value = Value::deserialize(deserializer)?;
            Ok(match value {
                Value::Ed25519 { public_key } => EphemeralPublicKey::Ed25519 { public_key },
            })
        }
    }
}

impl Serialize for EphemeralPublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            hex::encode(self.to_bytes().as_slice()).serialize(serializer)
        } else {
            // See comment in deserialize.
            #[derive(::serde::Serialize)]
            #[serde(rename = "EphemeralPublicKey")]
            enum Value {
                Ed25519 { public_key: Ed25519PublicKey },
            }

            let value = match self {
                EphemeralPublicKey::Ed25519 { public_key } => Value::Ed25519 {
                    public_key: public_key.clone(),
                },
            };

            value.serialize(serializer)
        }
    }
}
