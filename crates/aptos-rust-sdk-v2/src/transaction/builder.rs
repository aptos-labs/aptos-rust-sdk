//! Transaction builder.

use crate::account::Account;
use crate::error::{AptosError, AptosResult};
use crate::transaction::authenticator::{AccountAuthenticator, TransactionAuthenticator};
use crate::transaction::payload::TransactionPayload;
use crate::transaction::types::{
    FeePayerRawTransaction, MultiAgentRawTransaction, RawTransaction, SignedTransaction,
};
use crate::types::{AccountAddress, ChainId};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default maximum gas amount.
pub const DEFAULT_MAX_GAS_AMOUNT: u64 = 200_000;
/// Default gas unit price in octas.
pub const DEFAULT_GAS_UNIT_PRICE: u64 = 100;
/// Default transaction expiration time in seconds.
pub const DEFAULT_EXPIRATION_SECONDS: u64 = 600; // 10 minutes

/// A builder for constructing transactions.
///
/// # Example
///
/// ```rust,no_run
/// use aptos_rust_sdk_v2::transaction::{TransactionBuilder, EntryFunction};
/// use aptos_rust_sdk_v2::types::{AccountAddress, ChainId};
///
/// let payload = EntryFunction::apt_transfer(
///     AccountAddress::from_hex("0x123").unwrap(),
///     1000,
/// ).unwrap();
///
/// let txn = TransactionBuilder::new()
///     .sender(AccountAddress::ONE)
///     .sequence_number(0)
///     .payload(payload.into())
///     .chain_id(ChainId::testnet())
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    sender: Option<AccountAddress>,
    sequence_number: Option<u64>,
    payload: Option<TransactionPayload>,
    max_gas_amount: u64,
    gas_unit_price: u64,
    expiration_timestamp_secs: Option<u64>,
    chain_id: Option<ChainId>,
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionBuilder {
    /// Creates a new transaction builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sender: None,
            sequence_number: None,
            payload: None,
            max_gas_amount: DEFAULT_MAX_GAS_AMOUNT,
            gas_unit_price: DEFAULT_GAS_UNIT_PRICE,
            expiration_timestamp_secs: None,
            chain_id: None,
        }
    }

    /// Sets the sender address.
    #[must_use]
    pub fn sender(mut self, sender: AccountAddress) -> Self {
        self.sender = Some(sender);
        self
    }

    /// Sets the sequence number.
    #[must_use]
    pub fn sequence_number(mut self, sequence_number: u64) -> Self {
        self.sequence_number = Some(sequence_number);
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
    ///
    /// Uses saturating arithmetic to handle edge cases like system time going backwards.
    #[must_use]
    pub fn expiration_from_now(mut self, seconds: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.expiration_timestamp_secs = Some(now.saturating_add(seconds));
        self
    }

    /// Sets the chain ID.
    #[must_use]
    pub fn chain_id(mut self, chain_id: ChainId) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Builds the raw transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if any required field is missing:
    /// - `sender` is required
    /// - `sequence_number` is required
    /// - `payload` is required
    /// - `chain_id` is required
    pub fn build(self) -> AptosResult<RawTransaction> {
        let sender = self
            .sender
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

        let expiration_timestamp_secs = self.expiration_timestamp_secs.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_add(DEFAULT_EXPIRATION_SECONDS)
        });

        Ok(RawTransaction::new(
            sender,
            sequence_number,
            payload,
            self.max_gas_amount,
            self.gas_unit_price,
            expiration_timestamp_secs,
            chain_id,
        ))
    }

    /// Builds and signs the transaction with the given account.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be built or signed.
    #[cfg(feature = "ed25519")]
    pub fn build_and_sign<A: Account>(self, account: &A) -> AptosResult<SignedTransaction> {
        let sender = self.sender.unwrap_or_else(|| account.address());
        let raw_txn = Self {
            sender: Some(sender),
            ..self
        }
        .build()?;

        sign_transaction(&raw_txn, account)
    }
}

/// Signs a raw transaction with the given account.
///
/// # Errors
///
/// Returns an error if generating the signing message fails or if the account fails to sign.
pub fn sign_transaction<A: Account>(
    raw_txn: &RawTransaction,
    account: &A,
) -> AptosResult<SignedTransaction> {
    let signing_message = raw_txn.signing_message()?;
    let signature = account.sign(&signing_message)?;
    let public_key = account.public_key_bytes();

    let authenticator =
        make_transaction_authenticator(account.signature_scheme(), public_key, signature)?;

    Ok(SignedTransaction::new(raw_txn.clone(), authenticator))
}

/// Creates a transaction authenticator based on the signature scheme.
///
/// # Errors
///
/// Returns an error if the signature scheme is not recognized.
fn make_transaction_authenticator(
    scheme: u8,
    public_key: Vec<u8>,
    signature: Vec<u8>,
) -> AptosResult<TransactionAuthenticator> {
    match scheme {
        crate::crypto::ED25519_SCHEME => {
            Ok(TransactionAuthenticator::ed25519(public_key, signature))
        }
        crate::crypto::MULTI_ED25519_SCHEME => Ok(TransactionAuthenticator::multi_ed25519(
            public_key, signature,
        )),
        crate::crypto::MULTI_KEY_SCHEME => {
            // Multi-key uses SingleSender variant with AccountAuthenticator::MultiKey
            Ok(TransactionAuthenticator::single_sender(
                AccountAuthenticator::multi_key(public_key, signature),
            ))
        }
        crate::crypto::SINGLE_KEY_SCHEME => {
            // Single-key scheme is used by Secp256k1, Secp256r1, and Ed25519SingleKey accounts
            // Uses SingleSender variant with AccountAuthenticator::SingleKey
            Ok(TransactionAuthenticator::single_sender(
                AccountAuthenticator::single_key(public_key, signature),
            ))
        }
        #[cfg(feature = "keyless")]
        crate::crypto::KEYLESS_SCHEME => {
            // Keyless accounts use SingleSender variant with AccountAuthenticator::SingleKey
            // The public key is the ephemeral Ed25519 key, and the signature is a BCS-serialized
            // KeylessSignature struct containing the ephemeral signature and ZK proof
            Ok(TransactionAuthenticator::single_sender(
                AccountAuthenticator::keyless(public_key, signature),
            ))
        }
        _ => Err(AptosError::InvalidSignature(format!(
            "unknown signature scheme: {scheme}"
        ))),
    }
}

/// Creates an account authenticator based on the signature scheme.
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
        #[cfg(feature = "keyless")]
        crate::crypto::KEYLESS_SCHEME => Ok(AccountAuthenticator::keyless(public_key, signature)),
        _ => Err(AptosError::InvalidSignature(format!(
            "unknown signature scheme: {scheme}"
        ))),
    }
}

/// Signs a multi-agent transaction.
///
/// # Errors
///
/// Returns an error if generating the signing message fails or if any signer fails to sign.
pub fn sign_multi_agent_transaction<A: Account>(
    multi_agent: &MultiAgentRawTransaction,
    sender: &A,
    secondary_signers: &[&dyn Account],
) -> AptosResult<SignedTransaction> {
    let signing_message = multi_agent.signing_message()?;

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

    let authenticator = TransactionAuthenticator::multi_agent(
        sender_auth,
        multi_agent.secondary_signer_addresses.clone(),
        secondary_auths,
    );

    Ok(SignedTransaction::new(
        multi_agent.raw_txn.clone(),
        authenticator,
    ))
}

/// Signs a fee payer transaction.
///
/// # Errors
///
/// Returns an error if generating the signing message fails or if any signer fails to sign.
pub fn sign_fee_payer_transaction<A: Account>(
    fee_payer_txn: &FeePayerRawTransaction,
    sender: &A,
    secondary_signers: &[&dyn Account],
    fee_payer: &dyn Account,
) -> AptosResult<SignedTransaction> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::payload::EntryFunction;

    #[test]
    fn test_builder_missing_fields() {
        let result = TransactionBuilder::new().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_complete() {
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let txn = TransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(0)
            .payload(payload.into())
            .chain_id(ChainId::testnet())
            .build()
            .unwrap();

        assert_eq!(txn.sender, AccountAddress::ONE);
        assert_eq!(txn.sequence_number, 0);
        assert_eq!(txn.max_gas_amount, DEFAULT_MAX_GAS_AMOUNT);
        assert_eq!(txn.gas_unit_price, DEFAULT_GAS_UNIT_PRICE);
    }

    #[test]
    fn test_builder_custom_gas() {
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let txn = TransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(0)
            .payload(payload.into())
            .max_gas_amount(500_000)
            .gas_unit_price(200)
            .chain_id(ChainId::testnet())
            .build()
            .unwrap();

        assert_eq!(txn.max_gas_amount, 500_000);
        assert_eq!(txn.gas_unit_price, 200);
    }

    #[test]
    fn test_builder_missing_sender() {
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let result = TransactionBuilder::new()
            .sequence_number(0)
            .payload(payload.into())
            .chain_id(ChainId::testnet())
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_missing_payload() {
        let result = TransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(0)
            .chain_id(ChainId::testnet())
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_missing_chain_id() {
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let result = TransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(0)
            .payload(payload.into())
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_custom_expiration() {
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();
        let custom_expiration = 9999999999;

        let txn = TransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(0)
            .payload(payload.into())
            .expiration_timestamp_secs(custom_expiration)
            .chain_id(ChainId::testnet())
            .build()
            .unwrap();

        assert_eq!(txn.expiration_timestamp_secs, custom_expiration);
    }

    #[test]
    fn test_default_expiration() {
        // Default expiration should be set to about DEFAULT_EXPIRATION_SECONDS from now
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let txn = TransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(0)
            .payload(payload.into())
            .chain_id(ChainId::testnet())
            .build()
            .unwrap();

        // Should be approximately now + DEFAULT_EXPIRATION_SECONDS (give or take a second)
        let expected_min = now + DEFAULT_EXPIRATION_SECONDS - 5;
        let expected_max = now + DEFAULT_EXPIRATION_SECONDS + 5;
        assert!(txn.expiration_timestamp_secs >= expected_min);
        assert!(txn.expiration_timestamp_secs <= expected_max);
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_sign_transaction() {
        use crate::account::Ed25519Account;

        let account = Ed25519Account::generate();
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let txn = TransactionBuilder::new()
            .sender(account.address())
            .sequence_number(0)
            .payload(payload.into())
            .chain_id(ChainId::testnet())
            .build()
            .unwrap();

        let signed = sign_transaction(&txn, &account).unwrap();
        assert_eq!(signed.sender(), account.address());
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_sign_multi_agent_transaction() {
        use crate::account::{Account, Ed25519Account};

        let sender = Ed25519Account::generate();
        let secondary = Ed25519Account::generate();
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let raw_txn = TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(0)
            .payload(payload.into())
            .chain_id(ChainId::testnet())
            .build()
            .unwrap();

        let multi_agent = MultiAgentRawTransaction {
            raw_txn,
            secondary_signer_addresses: vec![secondary.address()],
        };

        let secondary_signers: Vec<&dyn Account> = vec![&secondary];
        let signed =
            sign_multi_agent_transaction(&multi_agent, &sender, &secondary_signers).unwrap();
        assert_eq!(signed.sender(), sender.address());
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_sign_fee_payer_transaction() {
        use crate::account::Ed25519Account;

        let sender = Ed25519Account::generate();
        let fee_payer = Ed25519Account::generate();
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let raw_txn = TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(0)
            .payload(payload.into())
            .chain_id(ChainId::testnet())
            .build()
            .unwrap();

        let fee_payer_txn = FeePayerRawTransaction {
            raw_txn,
            secondary_signer_addresses: vec![],
            fee_payer_address: fee_payer.address(),
        };

        let signed = sign_fee_payer_transaction(&fee_payer_txn, &sender, &[], &fee_payer).unwrap();
        assert_eq!(signed.sender(), sender.address());
    }

    #[test]
    fn test_default_impl() {
        let builder = TransactionBuilder::default();
        // Verify defaults are set
        assert!(builder.sender.is_none());
        assert!(builder.sequence_number.is_none());
        assert!(builder.payload.is_none());
        assert_eq!(builder.max_gas_amount, DEFAULT_MAX_GAS_AMOUNT);
        assert_eq!(builder.gas_unit_price, DEFAULT_GAS_UNIT_PRICE);
    }
}
