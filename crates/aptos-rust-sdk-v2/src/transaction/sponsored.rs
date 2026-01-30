//! Sponsored transaction helpers.
//!
//! This module provides high-level utilities for creating and managing
//! sponsored (fee payer) transactions, where one account pays the gas fees
//! on behalf of another account.
//!
//! # Overview
//!
//! Sponsored transactions allow a "fee payer" account to pay the gas fees
//! for a transaction initiated by a different "sender" account. This is useful for:
//!
//! - **Onboarding new users** - Users without APT can still execute transactions
//! - **dApp subsidization** - Applications can pay gas fees for their users
//! - **Gasless experiences** - Create seamless UX without exposing gas costs
//!
//! # Example
//!
//! ```rust,ignore
//! use aptos_rust_sdk_v2::transaction::{SponsoredTransactionBuilder, EntryFunction};
//!
//! // Build a sponsored transaction
//! let fee_payer_txn = SponsoredTransactionBuilder::new()
//!     .sender(user_account.address())
//!     .sequence_number(0)
//!     .fee_payer(sponsor_account.address())
//!     .payload(payload)
//!     .chain_id(ChainId::testnet())
//!     .build()?;
//!
//! // Sign with all parties
//! let signed = sign_sponsored_transaction(
//!     &fee_payer_txn,
//!     &user_account,
//!     &[],
//!     &sponsor_account,
//! )?;
//! ```

use crate::account::Account;
use crate::error::{AptosError, AptosResult};
use crate::transaction::authenticator::{AccountAuthenticator, TransactionAuthenticator};
use crate::transaction::builder::{
    DEFAULT_EXPIRATION_SECONDS, DEFAULT_GAS_UNIT_PRICE, DEFAULT_MAX_GAS_AMOUNT,
};
use crate::transaction::payload::TransactionPayload;
use crate::transaction::types::{FeePayerRawTransaction, RawTransaction, SignedTransaction};
use crate::types::{AccountAddress, ChainId};
use std::time::{SystemTime, UNIX_EPOCH};

/// A builder for constructing sponsored (fee payer) transactions.
///
/// This provides a fluent API for creating transactions where a fee payer
/// account pays the gas fees on behalf of the sender.
///
/// # Example
///
/// ```rust,ignore
/// use aptos_rust_sdk_v2::transaction::{SponsoredTransactionBuilder, EntryFunction};
///
/// // Build the fee payer transaction structure
/// let fee_payer_txn = SponsoredTransactionBuilder::new()
///     .sender(user_account.address())
///     .sequence_number(0)
///     .fee_payer(sponsor_account.address())
///     .payload(payload)
///     .chain_id(ChainId::testnet())
///     .build()?;
///
/// // Then sign it
/// let signed = sign_sponsored_transaction(
///     &fee_payer_txn,
///     &user_account,
///     &[],  // no secondary signers
///     &sponsor_account,
/// )?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct SponsoredTransactionBuilder {
    sender_address: Option<AccountAddress>,
    sequence_number: Option<u64>,
    secondary_addresses: Vec<AccountAddress>,
    fee_payer_address: Option<AccountAddress>,
    payload: Option<TransactionPayload>,
    max_gas_amount: u64,
    gas_unit_price: u64,
    expiration_timestamp_secs: Option<u64>,
    chain_id: Option<ChainId>,
}

impl SponsoredTransactionBuilder {
    /// Creates a new sponsored transaction builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sender_address: None,
            sequence_number: None,
            secondary_addresses: Vec::new(),
            fee_payer_address: None,
            payload: None,
            max_gas_amount: DEFAULT_MAX_GAS_AMOUNT,
            gas_unit_price: DEFAULT_GAS_UNIT_PRICE,
            expiration_timestamp_secs: None,
            chain_id: None,
        }
    }

    /// Sets the sender address.
    #[must_use]
    pub fn sender(mut self, address: AccountAddress) -> Self {
        self.sender_address = Some(address);
        self
    }

    /// Sets the sender's sequence number.
    #[must_use]
    pub fn sequence_number(mut self, sequence_number: u64) -> Self {
        self.sequence_number = Some(sequence_number);
        self
    }

    /// Adds a secondary signer address to the transaction.
    ///
    /// Secondary signers are additional accounts that must sign the transaction.
    /// This is useful for multi-party transactions.
    #[must_use]
    pub fn secondary_signer(mut self, address: AccountAddress) -> Self {
        self.secondary_addresses.push(address);
        self
    }

    /// Adds multiple secondary signer addresses to the transaction.
    #[must_use]
    pub fn secondary_signers(mut self, addresses: &[AccountAddress]) -> Self {
        self.secondary_addresses.extend(addresses);
        self
    }

    /// Sets the fee payer address.
    #[must_use]
    pub fn fee_payer(mut self, address: AccountAddress) -> Self {
        self.fee_payer_address = Some(address);
        self
    }

    /// Sets the transaction payload.
    #[must_use]
    pub fn payload(mut self, payload: TransactionPayload) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Sets the maximum gas amount.
    #[must_use]
    pub fn max_gas_amount(mut self, max_gas_amount: u64) -> Self {
        self.max_gas_amount = max_gas_amount;
        self
    }

    /// Sets the gas unit price in octas.
    #[must_use]
    pub fn gas_unit_price(mut self, gas_unit_price: u64) -> Self {
        self.gas_unit_price = gas_unit_price;
        self
    }

    /// Sets the expiration timestamp in seconds since Unix epoch.
    #[must_use]
    pub fn expiration_timestamp_secs(mut self, expiration_timestamp_secs: u64) -> Self {
        self.expiration_timestamp_secs = Some(expiration_timestamp_secs);
        self
    }

    /// Sets the expiration time relative to now.
    #[must_use]
    pub fn expiration_from_now(mut self, seconds: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.expiration_timestamp_secs = Some(now + seconds);
        self
    }

    /// Sets the chain ID.
    #[must_use]
    pub fn chain_id(mut self, chain_id: ChainId) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Builds the raw fee payer transaction (unsigned).
    ///
    /// This returns a `FeePayerRawTransaction` that can be signed later
    /// by the sender, secondary signers, and fee payer.
    ///
    /// # Errors
    ///
    /// Returns an error if `sender`, `sequence_number`, `payload`, `chain_id`, or `fee_payer` is not set.
    pub fn build(self) -> AptosResult<FeePayerRawTransaction> {
        let sender = self
            .sender_address
            .ok_or_else(|| AptosError::transaction("sender is required"))?;
        let sequence_number = self
            .sequence_number
            .ok_or_else(|| AptosError::transaction("sequence_number is required"))?;
        let payload = self
            .payload
            .ok_or_else(|| AptosError::transaction("payload is required"))?;
        let chain_id = self
            .chain_id
            .ok_or_else(|| AptosError::transaction("chain_id is required"))?;
        let fee_payer_address = self
            .fee_payer_address
            .ok_or_else(|| AptosError::transaction("fee_payer is required"))?;

        let expiration_timestamp_secs = self.expiration_timestamp_secs.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_add(DEFAULT_EXPIRATION_SECONDS)
                + DEFAULT_EXPIRATION_SECONDS
        });

        let raw_txn = RawTransaction::new(
            sender,
            sequence_number,
            payload,
            self.max_gas_amount,
            self.gas_unit_price,
            expiration_timestamp_secs,
            chain_id,
        );

        Ok(FeePayerRawTransaction {
            raw_txn,
            secondary_signer_addresses: self.secondary_addresses,
            fee_payer_address,
        })
    }

    /// Builds and signs the transaction with all provided accounts.
    ///
    /// This is a convenience method that builds the transaction and signs it
    /// in one step.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let signed = SponsoredTransactionBuilder::new()
    ///     .sender(user.address())
    ///     .sequence_number(0)
    ///     .fee_payer(sponsor.address())
    ///     .payload(payload)
    ///     .chain_id(ChainId::testnet())
    ///     .build_and_sign(&user, &[], &sponsor)?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if building the transaction fails or if any signer fails to sign.
    pub fn build_and_sign<S, F>(
        self,
        sender: &S,
        secondary_signers: &[&dyn Account],
        fee_payer: &F,
    ) -> AptosResult<SignedTransaction>
    where
        S: Account,
        F: Account,
    {
        let fee_payer_txn = self.build()?;
        sign_sponsored_transaction(&fee_payer_txn, sender, secondary_signers, fee_payer)
    }
}

/// Signs a sponsored (fee payer) transaction with all required signatures.
///
/// # Arguments
///
/// * `fee_payer_txn` - The unsigned fee payer transaction
/// * `sender` - The sender account
/// * `secondary_signers` - Additional signers (if any)
/// * `fee_payer` - The account paying gas fees
///
/// # Example
///
/// ```rust,ignore
/// use aptos_rust_sdk_v2::transaction::sign_sponsored_transaction;
///
/// let signed_txn = sign_sponsored_transaction(
///     &fee_payer_txn,
///     &sender_account,
///     &[],  // No secondary signers
///     &fee_payer_account,
/// )?;
/// ```
///
/// # Errors
///
/// Returns an error if generating the signing message fails or if any signer fails to sign.
pub fn sign_sponsored_transaction<S, F>(
    fee_payer_txn: &FeePayerRawTransaction,
    sender: &S,
    secondary_signers: &[&dyn Account],
    fee_payer: &F,
) -> AptosResult<SignedTransaction>
where
    S: Account,
    F: Account,
{
    let signing_message = fee_payer_txn.signing_message()?;

    // Sign with sender
    let sender_signature = sender.sign(&signing_message)?;
    let sender_public_key = sender.public_key_bytes();
    let sender_auth = make_account_authenticator(
        sender.signature_scheme(),
        sender_public_key,
        sender_signature,
    )?;

    // Sign with secondary signers
    let mut secondary_auths = Vec::with_capacity(secondary_signers.len());
    for signer in secondary_signers {
        let signature = signer.sign(&signing_message)?;
        let public_key = signer.public_key_bytes();
        secondary_auths.push(make_account_authenticator(
            signer.signature_scheme(),
            public_key,
            signature,
        )?);
    }

    // Sign with fee payer
    let fee_payer_signature = fee_payer.sign(&signing_message)?;
    let fee_payer_public_key = fee_payer.public_key_bytes();
    let fee_payer_auth = make_account_authenticator(
        fee_payer.signature_scheme(),
        fee_payer_public_key,
        fee_payer_signature,
    )?;

    let authenticator = TransactionAuthenticator::fee_payer(
        sender_auth,
        fee_payer_txn.secondary_signer_addresses.clone(),
        secondary_auths,
        fee_payer_txn.fee_payer_address,
        fee_payer_auth,
    );

    Ok(SignedTransaction::new(
        fee_payer_txn.raw_txn.clone(),
        authenticator,
    ))
}

/// Creates an account authenticator from signature components.
///
/// # Errors
///
/// Returns an error if the signature scheme is not recognized.
fn make_account_authenticator(
    scheme: u8,
    public_key: Vec<u8>,
    signature: Vec<u8>,
) -> AptosResult<AccountAuthenticator> {
    match scheme {
        crate::crypto::ED25519_SCHEME => Ok(AccountAuthenticator::ed25519(public_key, signature)),
        crate::crypto::MULTI_ED25519_SCHEME => Ok(AccountAuthenticator::MultiEd25519 {
            public_key,
            signature,
        }),
        crate::crypto::SINGLE_KEY_SCHEME => {
            Ok(AccountAuthenticator::single_key(public_key, signature))
        }
        crate::crypto::MULTI_KEY_SCHEME => {
            Ok(AccountAuthenticator::multi_key(public_key, signature))
        }
        _ => Err(AptosError::InvalidSignature(format!(
            "unknown signature scheme: {scheme}"
        ))),
    }
}

/// A partially signed sponsored transaction.
///
/// This represents a sponsored transaction that has been signed by some but
/// not all required signers. It can be passed between parties for signature
/// collection.
#[derive(Debug, Clone)]
pub struct PartiallySigned {
    /// The underlying fee payer transaction.
    pub fee_payer_txn: FeePayerRawTransaction,
    /// Sender's signature (if signed).
    pub sender_auth: Option<AccountAuthenticator>,
    /// Secondary signer signatures.
    pub secondary_auths: Vec<Option<AccountAuthenticator>>,
    /// Fee payer's signature (if signed).
    pub fee_payer_auth: Option<AccountAuthenticator>,
}

impl PartiallySigned {
    /// Creates a new partially signed transaction.
    pub fn new(fee_payer_txn: FeePayerRawTransaction) -> Self {
        let num_secondary = fee_payer_txn.secondary_signer_addresses.len();
        Self {
            fee_payer_txn,
            sender_auth: None,
            secondary_auths: vec![None; num_secondary],
            fee_payer_auth: None,
        }
    }

    /// Signs as the sender.
    ///
    /// # Errors
    ///
    /// Returns an error if generating the signing message fails, if signing fails,
    /// or if the signature scheme is not recognized.
    pub fn sign_as_sender<A: Account>(&mut self, sender: &A) -> AptosResult<()> {
        let signing_message = self.fee_payer_txn.signing_message()?;
        let signature = sender.sign(&signing_message)?;
        let public_key = sender.public_key_bytes();
        self.sender_auth = Some(make_account_authenticator(
            sender.signature_scheme(),
            public_key,
            signature,
        )?);
        Ok(())
    }

    /// Signs as a secondary signer at the given index.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is out of bounds, if generating the signing message fails,
    /// if signing fails, or if the signature scheme is not recognized.
    pub fn sign_as_secondary<A: Account>(&mut self, index: usize, signer: &A) -> AptosResult<()> {
        if index >= self.secondary_auths.len() {
            return Err(AptosError::transaction(format!(
                "secondary signer index {} out of bounds (max {})",
                index,
                self.secondary_auths.len()
            )));
        }

        let signing_message = self.fee_payer_txn.signing_message()?;
        let signature = signer.sign(&signing_message)?;
        let public_key = signer.public_key_bytes();
        self.secondary_auths[index] = Some(make_account_authenticator(
            signer.signature_scheme(),
            public_key,
            signature,
        )?);
        Ok(())
    }

    /// Signs as the fee payer.
    ///
    /// # Errors
    ///
    /// Returns an error if generating the signing message fails, if signing fails,
    /// or if the signature scheme is not recognized.
    pub fn sign_as_fee_payer<A: Account>(&mut self, fee_payer: &A) -> AptosResult<()> {
        let signing_message = self.fee_payer_txn.signing_message()?;
        let signature = fee_payer.sign(&signing_message)?;
        let public_key = fee_payer.public_key_bytes();
        self.fee_payer_auth = Some(make_account_authenticator(
            fee_payer.signature_scheme(),
            public_key,
            signature,
        )?);
        Ok(())
    }

    /// Checks if all required signatures have been collected.
    pub fn is_complete(&self) -> bool {
        self.sender_auth.is_some()
            && self.fee_payer_auth.is_some()
            && self.secondary_auths.iter().all(Option::is_some)
    }

    /// Finalizes the transaction if all signatures are present.
    ///
    /// Returns an error if any signatures are missing.
    ///
    /// # Errors
    ///
    /// Returns an error if the sender signature, fee payer signature, or any secondary signer signature is missing.
    pub fn finalize(self) -> AptosResult<SignedTransaction> {
        let sender_auth = self
            .sender_auth
            .ok_or_else(|| AptosError::transaction("missing sender signature"))?;
        let fee_payer_auth = self
            .fee_payer_auth
            .ok_or_else(|| AptosError::transaction("missing fee payer signature"))?;

        let secondary_auths: Result<Vec<_>, _> = self
            .secondary_auths
            .into_iter()
            .enumerate()
            .map(|(i, auth)| {
                auth.ok_or_else(|| {
                    AptosError::transaction(format!("missing secondary signer {i} signature"))
                })
            })
            .collect();
        let secondary_auths = secondary_auths?;

        let authenticator = TransactionAuthenticator::fee_payer(
            sender_auth,
            self.fee_payer_txn.secondary_signer_addresses.clone(),
            secondary_auths,
            self.fee_payer_txn.fee_payer_address,
            fee_payer_auth,
        );

        Ok(SignedTransaction::new(
            self.fee_payer_txn.raw_txn,
            authenticator,
        ))
    }
}

/// Extension trait that adds sponsorship capabilities to accounts.
///
/// This trait provides convenient methods for an account to sponsor
/// transactions for other users.
pub trait Sponsor: Account + Sized {
    /// Sponsors a transaction for another account.
    ///
    /// Creates and signs a sponsored transaction where `self` pays the gas fees.
    ///
    /// # Arguments
    ///
    /// * `sender` - The account initiating the transaction
    /// * `sender_sequence_number` - The sender's current sequence number
    /// * `payload` - The transaction payload
    /// * `chain_id` - The target chain ID
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use aptos_rust_sdk_v2::transaction::Sponsor;
    ///
    /// let signed_txn = sponsor_account.sponsor(
    ///     &user_account,
    ///     0,
    ///     payload,
    ///     ChainId::testnet(),
    /// )?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if building the transaction fails or if any signer fails to sign.
    fn sponsor<S: Account>(
        &self,
        sender: &S,
        sender_sequence_number: u64,
        payload: TransactionPayload,
        chain_id: ChainId,
    ) -> AptosResult<SignedTransaction> {
        SponsoredTransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(sender_sequence_number)
            .fee_payer(self.address())
            .payload(payload)
            .chain_id(chain_id)
            .build_and_sign(sender, &[], self)
    }

    /// Sponsors a transaction with custom gas settings.
    ///
    /// # Errors
    ///
    /// Returns an error if building the transaction fails or if any signer fails to sign.
    fn sponsor_with_gas<S: Account>(
        &self,
        sender: &S,
        sender_sequence_number: u64,
        payload: TransactionPayload,
        chain_id: ChainId,
        max_gas_amount: u64,
        gas_unit_price: u64,
    ) -> AptosResult<SignedTransaction> {
        SponsoredTransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(sender_sequence_number)
            .fee_payer(self.address())
            .payload(payload)
            .chain_id(chain_id)
            .max_gas_amount(max_gas_amount)
            .gas_unit_price(gas_unit_price)
            .build_and_sign(sender, &[], self)
    }
}

// Implement Sponsor for all Account types that are Sized
impl<A: Account + Sized> Sponsor for A {}

/// Creates a simple sponsored transaction with minimal configuration.
///
/// This is a convenience function for the common case of sponsoring a
/// simple transaction without secondary signers.
///
/// # Example
///
/// ```rust,ignore
/// use aptos_rust_sdk_v2::transaction::sponsor_transaction;
///
/// let signed = sponsor_transaction(
///     &sender_account,
///     sender_sequence_number,
///     &sponsor_account,
///     payload,
///     ChainId::testnet(),
/// )?;
/// ```
///
/// # Errors
///
/// Returns an error if building the transaction fails or if any signer fails to sign.
pub fn sponsor_transaction<S, F>(
    sender: &S,
    sender_sequence_number: u64,
    fee_payer: &F,
    payload: TransactionPayload,
    chain_id: ChainId,
) -> AptosResult<SignedTransaction>
where
    S: Account,
    F: Account,
{
    SponsoredTransactionBuilder::new()
        .sender(sender.address())
        .sequence_number(sender_sequence_number)
        .fee_payer(fee_payer.address())
        .payload(payload)
        .chain_id(chain_id)
        .build_and_sign(sender, &[], fee_payer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::payload::EntryFunction;

    #[test]
    fn test_builder_missing_sender() {
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let result = SponsoredTransactionBuilder::new()
            .sequence_number(0)
            .fee_payer(AccountAddress::ONE)
            .payload(TransactionPayload::EntryFunction(
                EntryFunction::apt_transfer(recipient, 1000).unwrap(),
            ))
            .chain_id(ChainId::testnet())
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("sender"));
    }

    #[test]
    fn test_builder_missing_fee_payer() {
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let result = SponsoredTransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(0)
            .payload(TransactionPayload::EntryFunction(
                EntryFunction::apt_transfer(recipient, 1000).unwrap(),
            ))
            .chain_id(ChainId::testnet())
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("fee_payer"));
    }

    #[test]
    fn test_builder_complete() {
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let fee_payer_txn = SponsoredTransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(5)
            .fee_payer(AccountAddress::from_hex("0x3").unwrap())
            .payload(payload.into())
            .chain_id(ChainId::testnet())
            .max_gas_amount(100_000)
            .gas_unit_price(150)
            .build()
            .unwrap();

        assert_eq!(fee_payer_txn.raw_txn.sender, AccountAddress::ONE);
        assert_eq!(fee_payer_txn.raw_txn.sequence_number, 5);
        assert_eq!(fee_payer_txn.raw_txn.max_gas_amount, 100_000);
        assert_eq!(fee_payer_txn.raw_txn.gas_unit_price, 150);
        assert_eq!(
            fee_payer_txn.fee_payer_address,
            AccountAddress::from_hex("0x3").unwrap()
        );
    }

    #[test]
    fn test_partially_signed_completion_check() {
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let fee_payer_txn = SponsoredTransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(0)
            .fee_payer(AccountAddress::from_hex("0x3").unwrap())
            .payload(payload.into())
            .chain_id(ChainId::testnet())
            .build()
            .unwrap();

        let partially_signed = PartiallySigned::new(fee_payer_txn);
        assert!(!partially_signed.is_complete());
    }

    #[test]
    fn test_partially_signed_finalize_incomplete() {
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let fee_payer_txn = SponsoredTransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(0)
            .fee_payer(AccountAddress::from_hex("0x3").unwrap())
            .payload(payload.into())
            .chain_id(ChainId::testnet())
            .build()
            .unwrap();

        let partially_signed = PartiallySigned::new(fee_payer_txn);
        let result = partially_signed.finalize();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing"));
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_full_sponsored_transaction() {
        use crate::account::Ed25519Account;

        let sender = Ed25519Account::generate();
        let fee_payer = Ed25519Account::generate();
        let recipient = AccountAddress::from_hex("0x123").unwrap();

        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let signed_txn = SponsoredTransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(0)
            .fee_payer(fee_payer.address())
            .payload(payload.into())
            .chain_id(ChainId::testnet())
            .build_and_sign(&sender, &[], &fee_payer)
            .unwrap();

        // Verify the transaction structure
        assert_eq!(signed_txn.raw_txn.sender, sender.address());
        assert!(matches!(
            signed_txn.authenticator,
            TransactionAuthenticator::FeePayer { .. }
        ));
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_sponsor_trait() {
        use crate::account::Ed25519Account;

        let sender = Ed25519Account::generate();
        let sponsor = Ed25519Account::generate();
        let recipient = AccountAddress::from_hex("0x123").unwrap();

        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        // Use the Sponsor trait
        let signed_txn = sponsor
            .sponsor(&sender, 0, payload.into(), ChainId::testnet())
            .unwrap();

        assert_eq!(signed_txn.raw_txn.sender, sender.address());
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_sponsor_transaction_fn() {
        use crate::account::Ed25519Account;

        let sender = Ed25519Account::generate();
        let fee_payer = Ed25519Account::generate();
        let recipient = AccountAddress::from_hex("0x123").unwrap();

        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        // Use the convenience function
        let signed_txn =
            sponsor_transaction(&sender, 0, &fee_payer, payload.into(), ChainId::testnet())
                .unwrap();

        assert_eq!(signed_txn.raw_txn.sender, sender.address());
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_partially_signed_flow() {
        use crate::account::Ed25519Account;

        let sender = Ed25519Account::generate();
        let fee_payer = Ed25519Account::generate();
        let recipient = AccountAddress::from_hex("0x123").unwrap();

        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        // Build the transaction
        let fee_payer_txn = SponsoredTransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(0)
            .fee_payer(fee_payer.address())
            .payload(payload.into())
            .chain_id(ChainId::testnet())
            .build()
            .unwrap();

        // Create partially signed and collect signatures
        let mut partially_signed = PartiallySigned::new(fee_payer_txn);

        // Not complete yet
        assert!(!partially_signed.is_complete());

        // Sign as sender
        partially_signed.sign_as_sender(&sender).unwrap();
        assert!(!partially_signed.is_complete());

        // Sign as fee payer
        partially_signed.sign_as_fee_payer(&fee_payer).unwrap();
        assert!(partially_signed.is_complete());

        // Finalize
        let signed_txn = partially_signed.finalize().unwrap();
        assert_eq!(signed_txn.raw_txn.sender, sender.address());
    }
}
