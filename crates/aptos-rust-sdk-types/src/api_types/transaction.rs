use crate::api_types::address::AccountAddress;
use crate::api_types::chain_id::ChainId;
use crate::api_types::event::ContractEvent;
use crate::api_types::hash::HashValue;
use crate::api_types::module_id::ModuleId;
use crate::api_types::numbers::U64;
use crate::api_types::transaction_authenticator::TransactionAuthenticator;
use crate::api_types::type_tag::TypeTag;
use crate::api_types::write_set::WriteSet;
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TransactionData {
    /// A committed transaction
    OnChain(TransactionOnChainData),
    /// A transaction currently sitting in mempool
    Pending(SignedTransaction),
}

/// A committed transaction
///
/// This is a representation of the onchain payload, outputs, events, and proof of a transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionOnChainData {
    /// The ledger version of the transaction
    pub version: u64,
    /// The transaction submitted
    pub transaction: Transaction,
    /// Information about the transaction
    pub info: TransactionInfo,
    /// Events emitted by the transaction
    pub events: Vec<ContractEvent>,
    /// The accumulator root hash at this version
    pub accumulator_root_hash: HashValue,
    /// Final state of resources changed by the transaction
    pub changes: WriteSet,
}

/// A transaction that has been signed.
///
/// A `SignedTransaction` is a single transaction that can be atomically executed. Clients submit
/// these to validator nodes, and the validator and executor submits these to the VM.
///
/// **IMPORTANT:** The signature of a `SignedTransaction` is not guaranteed to be verified. For a
/// transaction whose signature is statically guaranteed to be verified, see
/// [`SignatureCheckedTransaction`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct SignedTransaction {
    /// The raw transaction
    raw_txn: RawTransaction,

    /// Public key and signature to authenticate
    authenticator: TransactionAuthenticator,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Transaction {
    UserTransaction(UserTransaction),
}

// TODO: Create other transaction types, handle serialization
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserTransaction {
    info: TransactionInfo,
    payload: TransactionPayload,
    authenticator: TransactionAuthenticator,
}

/// Information related to how a transaction affected the state of the blockchain
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub version: U64,
    pub hash: HashValue,
    pub state_change_hash: HashValue,
    pub event_root_hash: HashValue,
    pub state_checkpoint_hash: Option<HashValue>,
    pub gas_used: U64,
    /// Whether the transaction was successful
    pub success: bool,
    /// The VM status of the transaction, can tell useful information in a failure
    pub vm_status: String,
    pub accumulator_root_hash: HashValue,
    /// Final state of resources changed by the transaction
    pub changes: Vec<WriteSet>,
    /// Block height that the transaction belongs in, this field will not be present through the API
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<U64>,
    /// Epoch of the transaction belongs in, this field will not be present through the API
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<U64>,
}

/// RawTransaction is the portion of a transaction that a client signs.
#[derive(
    Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash,
)]
pub struct RawTransaction {
    /// Sender's address.
    sender: AccountAddress,

    /// Sequence number of this transaction. This must match the sequence number
    /// stored in the sender's account at the time the transaction executes.
    sequence_number: u64,

    /// The transaction payload, e.g., a script to execute.
    payload: TransactionPayload,

    /// Maximal total gas to spend for this transaction.
    max_gas_amount: u64,

    /// Price to be paid per gas unit.
    gas_unit_price: u64,

    /// Expiration timestamp for this transaction, represented
    /// as seconds from the Unix Epoch. If the current blockchain timestamp
    /// is greater than or equal to this time, then the transaction has
    /// expired and will be discarded. This can be set to a large value far
    /// in the future to indicate that a transaction does not expire.
    expiration_timestamp_secs: u64,

    /// Chain ID of the Aptos network this transaction is intended for.
    chain_id: ChainId,
}

/// Different kinds of transactions.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransactionPayload {
    /// A transaction that executes code.
    Script(Script),
    /// Deprecated.
    ModuleBundle,
    /// A transaction that executes an existing entry function published on-chain.
    EntryFunction(EntryFunction),
    /// A multisig transaction that allows an owner of a multisig account to execute a pre-approved
    /// transaction as the multisig account.
    Multisig(Multisig),
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Script {
    #[serde(with = "serde_bytes")]
    code: Vec<u8>,
    ty_args: Vec<TypeTag>,
    args: Vec<TransactionArgument>,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransactionArgument {
    U8(u8),
    U64(u64),
    U128(u128),
    Address(AccountAddress),
    U8Vector(#[serde(with = "serde_bytes")] Vec<u8>),
    Bool(bool),
    // NOTE: Added in bytecode version v6, do not reorder!
    U16(u16),
    U32(u32),
    // FIXME: import u256 library, or handle properly
    // U256(u256::U256),
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntryFunction {
    module: ModuleId,
    function: String,
    ty_args: Vec<TypeTag>,
    // TODO: #[serde(with = "vec_bytes")]
    args: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Multisig {
    pub multisig_address: AccountAddress,

    // Transaction payload is optional if already stored on chain.
    pub transaction_payload: Option<MultisigTransactionPayload>,
}

// We use an enum here for extensibility so we can add Script payload support
// in the future for example.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum MultisigTransactionPayload {
    EntryFunction(EntryFunction),
}

/// Two different kinds of WriteSet transactions.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum WriteSetPayload {
    /// Directly passing in the WriteSet.
    Direct(ChangeSet),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ChangeSet {
    write_set: WriteSet,
    events: Vec<ContractEvent>,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum RawTransactionWithData {
    MultiAgent {
        raw_txn: RawTransaction,
        secondary_signer_addresses: Vec<AccountAddress>,
    },
    MultiAgentWithFeePayer {
        raw_txn: RawTransaction,
        secondary_signer_addresses: Vec<AccountAddress>,
        fee_payer_address: AccountAddress,
    },
}

impl RawTransactionWithData {
    pub fn new_multi_agent(
        raw_txn: RawTransaction,
        secondary_signer_addresses: Vec<AccountAddress>,
    ) -> Self {
        Self::MultiAgent {
            raw_txn,
            secondary_signer_addresses,
        }
    }

    pub fn new_multi_agent_with_fee_payer(
        raw_txn: RawTransaction,
        secondary_signer_addresses: Vec<AccountAddress>,
        fee_payer_address: AccountAddress,
    ) -> Self {
        Self::MultiAgentWithFeePayer {
            raw_txn,
            secondary_signer_addresses,
            fee_payer_address,
        }
    }
}

impl SignedTransaction {
    pub fn new(raw_txn: RawTransaction, authenticator: TransactionAuthenticator) -> Self {
        Self {
            raw_txn,
            authenticator,
        }
    }

    pub fn raw_txn(&self) -> &RawTransaction {
        &self.raw_txn
    }

    pub fn authenticator(&self) -> &TransactionAuthenticator {
        &self.authenticator
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bcs::serialize_into(&mut bytes, self).unwrap();
        bytes
    }
}

impl RawTransaction {
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

    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bcs::serialize_into(&mut bytes, self).unwrap();
        bytes
    }
}

impl EntryFunction {
    pub fn new(
        module: ModuleId,
        function: String,
        ty_args: Vec<TypeTag>,
        args: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            module,
            function,
            ty_args,
            args,
        }
    }
}
