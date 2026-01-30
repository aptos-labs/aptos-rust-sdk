//! Transaction types.

use crate::error::AptosResult;
use crate::transaction::authenticator::TransactionAuthenticator;
use crate::transaction::payload::TransactionPayload;
use crate::types::{AccountAddress, ChainId, HashValue};
use serde::{Deserialize, Serialize};

/// The raw transaction that a client signs.
///
/// A `RawTransaction` contains all the details of a transaction before
/// it is signed, including the sender, payload, gas parameters, and
/// expiration time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawTransaction {
    /// Sender's address.
    pub sender: AccountAddress,
    /// Sequence number of this transaction.
    pub sequence_number: u64,
    /// The transaction payload (entry function, script, etc.).
    pub payload: TransactionPayload,
    /// Maximum gas units the sender is willing to pay.
    pub max_gas_amount: u64,
    /// Price per gas unit in octas.
    pub gas_unit_price: u64,
    /// Expiration time in seconds since Unix epoch.
    pub expiration_timestamp_secs: u64,
    /// Chain ID to prevent cross-chain replay.
    pub chain_id: ChainId,
}

impl RawTransaction {
    /// Creates a new raw transaction.
    pub fn new(
        sender: AccountAddress,
        sequence_number: u64,
        payload: TransactionPayload,
        max_gas_amount: u64,
        gas_unit_price: u64,
        expiration_timestamp_secs: u64,
        chain_id: ChainId,
    ) -> Self {
        Self {
            sender,
            sequence_number,
            payload,
            max_gas_amount,
            gas_unit_price,
            expiration_timestamp_secs,
            chain_id,
        }
    }

    /// Generates the signing message for this transaction.
    ///
    /// This is the message that should be signed to create a valid
    /// transaction authenticator.
    ///
    /// # Errors
    ///
    /// Returns an error if BCS serialization of the transaction fails.
    pub fn signing_message(&self) -> AptosResult<Vec<u8>> {
        let prefix = crate::crypto::sha3_256(b"APTOS::RawTransaction");
        let bcs_bytes = aptos_bcs::to_bytes(self).map_err(crate::error::AptosError::bcs)?;

        let mut message = Vec::with_capacity(prefix.len() + bcs_bytes.len());
        message.extend_from_slice(&prefix);
        message.extend_from_slice(&bcs_bytes);
        Ok(message)
    }

    /// Serializes this transaction to BCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if BCS serialization fails.
    pub fn to_bcs(&self) -> AptosResult<Vec<u8>> {
        aptos_bcs::to_bytes(self).map_err(crate::error::AptosError::bcs)
    }
}

/// An orderless transaction using hash-based replay protection.
///
/// Unlike standard transactions that use sequence numbers, orderless transactions
/// use a random nonce and a short expiration window (typically 60 seconds) to
/// prevent replay attacks. This allows transactions to be submitted in any order.
///
/// # Note
///
/// Orderless transactions must be configured with a very short expiration time
/// (recommended: 60 seconds or less) since the replay protection relies on
/// the chain remembering recently seen transaction hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawTransactionOrderless {
    /// Sender's address.
    pub sender: AccountAddress,
    /// Random nonce for uniqueness (32 bytes recommended).
    pub nonce: Vec<u8>,
    /// The transaction payload (entry function, script, etc.).
    pub payload: TransactionPayload,
    /// Maximum gas units the sender is willing to pay.
    pub max_gas_amount: u64,
    /// Price per gas unit in octas.
    pub gas_unit_price: u64,
    /// Expiration time in seconds since Unix epoch.
    /// Should be short (e.g., current time + 60 seconds).
    pub expiration_timestamp_secs: u64,
    /// Chain ID to prevent cross-chain replay.
    pub chain_id: ChainId,
}

impl RawTransactionOrderless {
    /// Creates a new orderless transaction with a random nonce.
    pub fn new(
        sender: AccountAddress,
        payload: TransactionPayload,
        max_gas_amount: u64,
        gas_unit_price: u64,
        expiration_timestamp_secs: u64,
        chain_id: ChainId,
    ) -> Self {
        // Generate a random 32-byte nonce
        let mut nonce = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        Self {
            sender,
            nonce,
            payload,
            max_gas_amount,
            gas_unit_price,
            expiration_timestamp_secs,
            chain_id,
        }
    }

    /// Creates a new orderless transaction with a specific nonce.
    pub fn with_nonce(
        sender: AccountAddress,
        nonce: Vec<u8>,
        payload: TransactionPayload,
        max_gas_amount: u64,
        gas_unit_price: u64,
        expiration_timestamp_secs: u64,
        chain_id: ChainId,
    ) -> Self {
        Self {
            sender,
            nonce,
            payload,
            max_gas_amount,
            gas_unit_price,
            expiration_timestamp_secs,
            chain_id,
        }
    }

    /// Generates the signing message for this orderless transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if BCS serialization of the transaction fails.
    pub fn signing_message(&self) -> AptosResult<Vec<u8>> {
        let prefix = crate::crypto::sha3_256(b"APTOS::RawTransactionOrderless");
        let bcs_bytes = aptos_bcs::to_bytes(self).map_err(crate::error::AptosError::bcs)?;

        let mut message = Vec::with_capacity(prefix.len() + bcs_bytes.len());
        message.extend_from_slice(&prefix);
        message.extend_from_slice(&bcs_bytes);
        Ok(message)
    }

    /// Serializes this transaction to BCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if BCS serialization fails.
    pub fn to_bcs(&self) -> AptosResult<Vec<u8>> {
        aptos_bcs::to_bytes(self).map_err(crate::error::AptosError::bcs)
    }
}

/// A signed orderless transaction ready for submission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransactionOrderless {
    /// The orderless raw transaction.
    pub raw_txn: RawTransactionOrderless,
    /// The authenticator (signature(s) and public key(s)).
    pub authenticator: TransactionAuthenticator,
}

impl SignedTransactionOrderless {
    /// Creates a new signed orderless transaction.
    pub fn new(raw_txn: RawTransactionOrderless, authenticator: TransactionAuthenticator) -> Self {
        Self {
            raw_txn,
            authenticator,
        }
    }

    /// Serializes this signed transaction to BCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if BCS serialization fails.
    pub fn to_bcs(&self) -> AptosResult<Vec<u8>> {
        aptos_bcs::to_bytes(self).map_err(crate::error::AptosError::bcs)
    }

    /// Returns the sender address.
    pub fn sender(&self) -> AccountAddress {
        self.raw_txn.sender
    }

    /// Returns the nonce.
    pub fn nonce(&self) -> &[u8] {
        &self.raw_txn.nonce
    }

    /// Computes the transaction hash.
    ///
    /// # Errors
    ///
    /// Returns an error if BCS serialization of the transaction fails.
    pub fn hash(&self) -> AptosResult<HashValue> {
        let bcs_bytes = self.to_bcs()?;
        let prefix = crate::crypto::sha3_256(b"APTOS::Transaction");

        let mut data = Vec::with_capacity(prefix.len() + 1 + bcs_bytes.len());
        data.extend_from_slice(&prefix);
        // Use variant 2 for orderless user transactions (assuming standard is 0, script is 1)
        data.push(2);
        data.extend_from_slice(&bcs_bytes);

        Ok(HashValue::new(crate::crypto::sha3_256(&data)))
    }
}

/// A signed transaction ready for submission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The raw transaction.
    pub raw_txn: RawTransaction,
    /// The authenticator (signature(s) and public key(s)).
    pub authenticator: TransactionAuthenticator,
}

impl SignedTransaction {
    /// Creates a new signed transaction.
    pub fn new(raw_txn: RawTransaction, authenticator: TransactionAuthenticator) -> Self {
        Self {
            raw_txn,
            authenticator,
        }
    }

    /// Serializes this signed transaction to BCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if BCS serialization fails.
    pub fn to_bcs(&self) -> AptosResult<Vec<u8>> {
        aptos_bcs::to_bytes(self).map_err(crate::error::AptosError::bcs)
    }

    /// Returns the sender address.
    pub fn sender(&self) -> AccountAddress {
        self.raw_txn.sender
    }

    /// Returns the sequence number.
    pub fn sequence_number(&self) -> u64 {
        self.raw_txn.sequence_number
    }

    /// Computes the transaction hash.
    ///
    /// # Errors
    ///
    /// Returns an error if BCS serialization of the transaction fails.
    pub fn hash(&self) -> AptosResult<HashValue> {
        let bcs_bytes = self.to_bcs()?;
        let prefix = crate::crypto::sha3_256(b"APTOS::Transaction");

        let mut data = Vec::with_capacity(prefix.len() + 1 + bcs_bytes.len());
        data.extend_from_slice(&prefix);
        data.push(0); // User transaction variant
        data.extend_from_slice(&bcs_bytes);

        Ok(HashValue::new(crate::crypto::sha3_256(&data)))
    }
}

/// Information about a submitted/executed transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionInfo {
    /// The transaction hash.
    pub hash: HashValue,
    /// The ledger version this transaction was committed at.
    #[serde(default)]
    pub version: Option<u64>,
    /// Whether the transaction succeeded.
    #[serde(default)]
    pub success: Option<bool>,
    /// The VM status message.
    #[serde(default)]
    pub vm_status: Option<String>,
    /// Gas used by the transaction.
    #[serde(default)]
    pub gas_used: Option<u64>,
}

impl TransactionInfo {
    /// Returns true if the transaction succeeded.
    pub fn is_success(&self) -> bool {
        self.success.unwrap_or(false)
    }
}

/// Multi-agent transaction with additional signers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiAgentRawTransaction {
    /// The raw transaction.
    pub raw_txn: RawTransaction,
    /// Secondary signer addresses.
    pub secondary_signer_addresses: Vec<AccountAddress>,
}

impl MultiAgentRawTransaction {
    /// Creates a new multi-agent transaction.
    pub fn new(raw_txn: RawTransaction, secondary_signer_addresses: Vec<AccountAddress>) -> Self {
        Self {
            raw_txn,
            secondary_signer_addresses,
        }
    }

    /// Generates the signing message for multi-agent transactions.
    ///
    /// # Errors
    ///
    /// Returns an error if BCS serialization fails.
    pub fn signing_message(&self) -> AptosResult<Vec<u8>> {
        // Serialize as RawTransactionWithData::MultiAgent variant
        #[derive(Serialize)]
        enum RawTransactionWithData<'a> {
            MultiAgent {
                raw_txn: &'a RawTransaction,
                secondary_signer_addresses: &'a Vec<AccountAddress>,
            },
        }

        let prefix = crate::crypto::sha3_256(b"APTOS::RawTransactionWithData");

        let data = RawTransactionWithData::MultiAgent {
            raw_txn: &self.raw_txn,
            secondary_signer_addresses: &self.secondary_signer_addresses,
        };

        let bcs_bytes = aptos_bcs::to_bytes(&data).map_err(crate::error::AptosError::bcs)?;

        let mut message = Vec::with_capacity(prefix.len() + bcs_bytes.len());
        message.extend_from_slice(&prefix);
        message.extend_from_slice(&bcs_bytes);
        Ok(message)
    }
}

/// Fee payer transaction where a third party pays gas fees.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeePayerRawTransaction {
    /// The raw transaction.
    pub raw_txn: RawTransaction,
    /// Secondary signer addresses (for multi-agent).
    pub secondary_signer_addresses: Vec<AccountAddress>,
    /// The fee payer's address.
    pub fee_payer_address: AccountAddress,
}

impl FeePayerRawTransaction {
    /// Creates a new fee payer transaction.
    pub fn new(
        raw_txn: RawTransaction,
        secondary_signer_addresses: Vec<AccountAddress>,
        fee_payer_address: AccountAddress,
    ) -> Self {
        Self {
            raw_txn,
            secondary_signer_addresses,
            fee_payer_address,
        }
    }

    /// Creates a fee payer transaction without secondary signers.
    pub fn new_simple(raw_txn: RawTransaction, fee_payer_address: AccountAddress) -> Self {
        Self {
            raw_txn,
            secondary_signer_addresses: vec![],
            fee_payer_address,
        }
    }

    /// Generates the signing message for fee payer transactions.
    ///
    /// # Errors
    ///
    /// Returns an error if BCS serialization fails.
    pub fn signing_message(&self) -> AptosResult<Vec<u8>> {
        #[derive(Serialize)]
        enum RawTransactionWithData<'a> {
            #[allow(dead_code)]
            MultiAgent {
                raw_txn: &'a RawTransaction,
                secondary_signer_addresses: &'a Vec<AccountAddress>,
            },
            MultiAgentWithFeePayer {
                raw_txn: &'a RawTransaction,
                secondary_signer_addresses: &'a Vec<AccountAddress>,
                fee_payer_address: &'a AccountAddress,
            },
        }
        let prefix = crate::crypto::sha3_256(b"APTOS::RawTransactionWithData");

        let data = RawTransactionWithData::MultiAgentWithFeePayer {
            raw_txn: &self.raw_txn,
            secondary_signer_addresses: &self.secondary_signer_addresses,
            fee_payer_address: &self.fee_payer_address,
        };

        let bcs_bytes = aptos_bcs::to_bytes(&data).map_err(crate::error::AptosError::bcs)?;

        let mut message = Vec::with_capacity(prefix.len() + bcs_bytes.len());
        message.extend_from_slice(&prefix);
        message.extend_from_slice(&bcs_bytes);
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::payload::EntryFunction;
    use crate::types::MoveModuleId;

    fn create_test_raw_transaction() -> RawTransaction {
        RawTransaction::new(
            AccountAddress::ONE,
            0,
            TransactionPayload::EntryFunction(EntryFunction {
                module: MoveModuleId::from_str_strict("0x1::coin").unwrap(),
                function: "transfer".to_string(),
                type_args: vec![],
                args: vec![],
            }),
            100_000,
            100,
            1000000000,
            ChainId::testnet(),
        )
    }

    #[test]
    fn test_raw_transaction_signing_message() {
        let txn = create_test_raw_transaction();
        let message = txn.signing_message().unwrap();
        assert!(!message.is_empty());
        // First 32 bytes should be the hash prefix
        assert_eq!(message.len(), 32 + txn.to_bcs().unwrap().len());
    }

    #[test]
    fn test_raw_transaction_fields() {
        let txn = create_test_raw_transaction();
        assert_eq!(txn.sender, AccountAddress::ONE);
        assert_eq!(txn.sequence_number, 0);
        assert_eq!(txn.max_gas_amount, 100_000);
        assert_eq!(txn.gas_unit_price, 100);
        assert_eq!(txn.expiration_timestamp_secs, 1000000000);
        assert_eq!(txn.chain_id, ChainId::testnet());
    }

    #[test]
    fn test_raw_transaction_bcs_serialization() {
        let txn = create_test_raw_transaction();
        let bcs = txn.to_bcs().unwrap();
        assert!(!bcs.is_empty());
    }

    #[test]
    fn test_signed_transaction() {
        use crate::transaction::authenticator::{Ed25519PublicKey, Ed25519Signature};
        let txn = create_test_raw_transaction();
        // Create a dummy authenticator
        let auth = crate::transaction::TransactionAuthenticator::Ed25519 {
            public_key: Ed25519PublicKey([0u8; 32]),
            signature: Ed25519Signature([0u8; 64]),
        };
        let signed = SignedTransaction::new(txn, auth);
        assert_eq!(signed.sender(), AccountAddress::ONE);
    }

    #[test]
    fn test_signed_transaction_bcs() {
        use crate::transaction::authenticator::{Ed25519PublicKey, Ed25519Signature};
        let txn = create_test_raw_transaction();
        let auth = crate::transaction::TransactionAuthenticator::Ed25519 {
            public_key: Ed25519PublicKey([0u8; 32]),
            signature: Ed25519Signature([0u8; 64]),
        };
        let signed = SignedTransaction::new(txn, auth);
        let bcs = signed.to_bcs().unwrap();
        assert!(!bcs.is_empty());
    }

    #[test]
    fn test_authenticator_bcs_format() {
        // Test that Ed25519 authenticator serializes WITH length prefixes (Aptos BCS format)
        use crate::transaction::authenticator::{Ed25519PublicKey, Ed25519Signature};
        let auth = crate::transaction::TransactionAuthenticator::Ed25519 {
            public_key: Ed25519PublicKey([0xab; 32]),
            signature: Ed25519Signature([0xcd; 64]),
        };
        let bcs = aptos_bcs::to_bytes(&auth).unwrap();

        // Print for debugging
        println!("Authenticator BCS bytes: {}", hex::encode(&bcs));
        println!("First byte (variant index): {}", bcs[0]);
        println!("Second byte (length prefix): {}", bcs[1]);
        println!("Third byte (first pubkey byte): {}", bcs[2]);

        // Ed25519 variant should be index 0
        assert_eq!(bcs[0], 0, "Ed25519 variant index should be 0");
        // Next byte is length prefix for pubkey (32 = 0x20)
        assert_eq!(bcs[1], 32, "Pubkey length prefix should be 32");
        // Next 32 bytes should be pubkey
        assert_eq!(bcs[2], 0xab, "First pubkey byte should be 0xab");
        // After pubkey (1 + 1 + 32 = 34), length prefix for signature (64 = 0x40)
        assert_eq!(bcs[34], 64, "Signature length prefix should be 64");
        // Signature starts at offset 35
        assert_eq!(bcs[35], 0xcd, "First signature byte should be 0xcd");
        // Total: 1 (variant) + 1 (pubkey len) + 32 (pubkey) + 1 (sig len) + 64 (sig) = 99
        assert_eq!(bcs.len(), 99, "BCS length should be 99");
    }

    #[test]
    fn test_transaction_info_deserialization() {
        let json = r#"{
            "version": 12345,
            "hash": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "gas_used": 100,
            "success": true,
            "vm_status": "Executed successfully"
        }"#;
        let info: TransactionInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.version, Some(12345));
        assert_eq!(info.gas_used, Some(100));
        assert_eq!(info.success, Some(true));
        assert_eq!(info.vm_status, Some("Executed successfully".to_string()));
    }

    #[test]
    fn test_fee_payer_raw_transaction_new() {
        let raw_txn = create_test_raw_transaction();
        let secondary_addr = AccountAddress::from_hex("0x2").unwrap();
        let fee_payer_addr = AccountAddress::THREE;
        let fee_payer = FeePayerRawTransaction::new(raw_txn, vec![secondary_addr], fee_payer_addr);
        assert_eq!(fee_payer.fee_payer_address, AccountAddress::THREE);
        assert_eq!(fee_payer.secondary_signer_addresses.len(), 1);
    }

    #[test]
    fn test_fee_payer_raw_transaction_new_simple() {
        let raw_txn = create_test_raw_transaction();
        let fee_payer = FeePayerRawTransaction::new_simple(raw_txn, AccountAddress::THREE);
        assert_eq!(fee_payer.fee_payer_address, AccountAddress::THREE);
        assert!(fee_payer.secondary_signer_addresses.is_empty());
    }

    #[test]
    fn test_fee_payer_signing_message() {
        let raw_txn = create_test_raw_transaction();
        let fee_payer = FeePayerRawTransaction::new_simple(raw_txn, AccountAddress::THREE);
        let message = fee_payer.signing_message().unwrap();
        assert!(!message.is_empty());
    }
}
