//! API response types.

use crate::types::HashValue;
use serde::{Deserialize, Serialize};

/// A response from the Aptos API with headers metadata.
#[derive(Debug, Clone)]
pub struct AptosResponse<T> {
    /// The response body.
    pub data: T,
    /// The ledger version at the time of the request.
    pub ledger_version: Option<u64>,
    /// The ledger timestamp in microseconds.
    pub ledger_timestamp: Option<u64>,
    /// The epoch number.
    pub epoch: Option<u64>,
    /// The block height.
    pub block_height: Option<u64>,
    /// The oldest ledger version available.
    pub oldest_ledger_version: Option<u64>,
    /// The cursor for pagination.
    pub cursor: Option<String>,
}

impl<T> AptosResponse<T> {
    /// Creates a new response with data only.
    pub fn new(data: T) -> Self {
        Self {
            data,
            ledger_version: None,
            ledger_timestamp: None,
            epoch: None,
            block_height: None,
            oldest_ledger_version: None,
            cursor: None,
        }
    }

    /// Returns the inner data.
    pub fn into_inner(self) -> T {
        self.data
    }

    /// Maps the inner data using a function.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> AptosResponse<U> {
        AptosResponse {
            data: f(self.data),
            ledger_version: self.ledger_version,
            ledger_timestamp: self.ledger_timestamp,
            epoch: self.epoch,
            block_height: self.block_height,
            oldest_ledger_version: self.oldest_ledger_version,
            cursor: self.cursor,
        }
    }
}

/// Response when submitting a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransaction {
    /// The transaction hash.
    pub hash: HashValue,
    /// The sender address.
    pub sender: String,
    /// The sequence number.
    pub sequence_number: String,
    /// Maximum gas amount.
    pub max_gas_amount: String,
    /// Gas unit price.
    pub gas_unit_price: String,
    /// Expiration timestamp.
    pub expiration_timestamp_secs: String,
}

impl PendingTransaction {
    /// Returns the transaction hash.
    pub fn hash(&self) -> &HashValue {
        &self.hash
    }

    /// Returns the sender address as a string.
    pub fn sender(&self) -> &str {
        &self.sender
    }

    /// Returns the sequence number.
    ///
    /// # Errors
    /// Returns an error if the sequence number string cannot be parsed as u64.
    pub fn sequence_number(&self) -> Result<u64, std::num::ParseIntError> {
        self.sequence_number.parse()
    }
}

/// Ledger information from the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerInfo {
    /// The chain ID.
    pub chain_id: u8,
    /// The epoch number.
    pub epoch: String,
    /// The ledger version.
    pub ledger_version: String,
    /// The oldest ledger version.
    pub oldest_ledger_version: String,
    /// The ledger timestamp in microseconds.
    pub ledger_timestamp: String,
    /// The node role.
    pub node_role: String,
    /// The oldest block height.
    pub oldest_block_height: String,
    /// The block height.
    pub block_height: String,
    /// Git hash of the node.
    pub git_hash: Option<String>,
}

impl LedgerInfo {
    /// Returns the ledger version as u64.
    ///
    /// # Errors
    /// Returns an error if the ledger version string cannot be parsed as u64.
    pub fn version(&self) -> Result<u64, std::num::ParseIntError> {
        self.ledger_version.parse()
    }

    /// Returns the block height as u64.
    ///
    /// # Errors
    /// Returns an error if the block height string cannot be parsed as u64.
    pub fn height(&self) -> Result<u64, std::num::ParseIntError> {
        self.block_height.parse()
    }

    /// Returns the epoch as u64.
    ///
    /// # Errors
    /// Returns an error if the epoch string cannot be parsed as u64.
    pub fn epoch_num(&self) -> Result<u64, std::num::ParseIntError> {
        self.epoch.parse()
    }
}

/// Gas estimation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasEstimation {
    /// Deprioritized gas estimate.
    pub deprioritized_gas_estimate: Option<u64>,
    /// Normal gas estimate.
    pub gas_estimate: u64,
    /// Prioritized gas estimate.
    pub prioritized_gas_estimate: Option<u64>,
}

impl GasEstimation {
    /// Returns the recommended gas price.
    pub fn recommended(&self) -> u64 {
        self.gas_estimate
    }

    /// Returns the low gas price for non-urgent transactions.
    pub fn low(&self) -> u64 {
        self.deprioritized_gas_estimate.unwrap_or(self.gas_estimate)
    }

    /// Returns the high gas price for urgent transactions.
    pub fn high(&self) -> u64 {
        self.prioritized_gas_estimate.unwrap_or(self.gas_estimate)
    }
}

/// Account data from the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountData {
    /// The sequence number.
    pub sequence_number: String,
    /// The authentication key.
    pub authentication_key: String,
}

impl AccountData {
    /// Returns the sequence number as u64.
    ///
    /// # Errors
    /// Returns an error if the sequence number string cannot be parsed as u64.
    pub fn sequence_number(&self) -> Result<u64, std::num::ParseIntError> {
        self.sequence_number.parse()
    }
}

/// A resource stored on chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    /// The resource type.
    #[serde(rename = "type")]
    pub typ: String,
    /// The resource data as JSON.
    pub data: serde_json::Value,
}

/// A Move module stored on chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveModule {
    /// The module bytecode as hex.
    pub bytecode: String,
    /// The module ABI.
    pub abi: Option<MoveModuleABI>,
}

/// Move module ABI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveModuleABI {
    /// The module address.
    pub address: String,
    /// The module name.
    pub name: String,
    /// Exposed functions.
    pub exposed_functions: Vec<MoveFunction>,
    /// Structs defined in the module.
    pub structs: Vec<MoveStructDef>,
}

/// A function defined in a Move module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveFunction {
    /// Function name.
    pub name: String,
    /// Visibility.
    pub visibility: String,
    /// Whether this is an entry function.
    pub is_entry: bool,
    /// Whether this is a view function.
    pub is_view: bool,
    /// Generic type parameters.
    pub generic_type_params: Vec<MoveFunctionGenericTypeParam>,
    /// Function parameters.
    pub params: Vec<String>,
    /// Return types.
    #[serde(rename = "return")]
    pub returns: Vec<String>,
}

/// Generic type parameter in a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveFunctionGenericTypeParam {
    /// Constraints on the type parameter.
    pub constraints: Vec<String>,
}

/// A struct defined in a Move module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveStructDef {
    /// Struct name.
    pub name: String,
    /// Whether this is a native struct.
    pub is_native: bool,
    /// Abilities of the struct.
    pub abilities: Vec<String>,
    /// Generic type parameters.
    pub generic_type_params: Vec<MoveStructGenericTypeParam>,
    /// Fields of the struct.
    pub fields: Vec<MoveStructField>,
}

/// Generic type parameter in a struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveStructGenericTypeParam {
    /// Constraints on the type parameter.
    pub constraints: Vec<String>,
}

/// A field in a Move struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveStructField {
    /// Field name.
    pub name: String,
    /// Field type.
    #[serde(rename = "type")]
    pub typ: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aptos_response() {
        let response = AptosResponse::new(42);
        assert_eq!(response.into_inner(), 42);
    }

    #[test]
    fn test_aptos_response_map() {
        let response = AptosResponse::new(42);
        let mapped = response.map(|x| x.to_string());
        assert_eq!(mapped.into_inner(), "42");
    }

    #[test]
    fn test_aptos_response_preserves_metadata() {
        let mut response = AptosResponse::new(42);
        response.ledger_version = Some(100);
        response.epoch = Some(5);
        response.block_height = Some(1000);
        response.cursor = Some("abc".to_string());

        let mapped = response.map(|x| x * 2);
        assert_eq!(mapped.data, 84);
        assert_eq!(mapped.ledger_version, Some(100));
        assert_eq!(mapped.epoch, Some(5));
        assert_eq!(mapped.block_height, Some(1000));
        assert_eq!(mapped.cursor, Some("abc".to_string()));
    }

    #[test]
    fn test_gas_estimation() {
        let gas = GasEstimation {
            deprioritized_gas_estimate: Some(50),
            gas_estimate: 100,
            prioritized_gas_estimate: Some(150),
        };
        assert_eq!(gas.low(), 50);
        assert_eq!(gas.recommended(), 100);
        assert_eq!(gas.high(), 150);
    }

    #[test]
    fn test_gas_estimation_defaults() {
        let gas = GasEstimation {
            deprioritized_gas_estimate: None,
            gas_estimate: 100,
            prioritized_gas_estimate: None,
        };
        assert_eq!(gas.low(), 100);
        assert_eq!(gas.recommended(), 100);
        assert_eq!(gas.high(), 100);
    }

    #[test]
    fn test_pending_transaction_deserialization() {
        let json = r#"{
            "hash": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "sender": "0x1",
            "sequence_number": "42",
            "max_gas_amount": "100000",
            "gas_unit_price": "100",
            "expiration_timestamp_secs": "1000000000"
        }"#;
        let pending: PendingTransaction = serde_json::from_str(json).unwrap();
        assert_eq!(pending.sender(), "0x1");
        assert_eq!(pending.sequence_number().unwrap(), 42);
    }

    #[test]
    fn test_ledger_info_deserialization() {
        let json = r#"{
            "chain_id": 2,
            "epoch": "100",
            "ledger_version": "12345",
            "oldest_ledger_version": "0",
            "ledger_timestamp": "1000000000",
            "node_role": "full_node",
            "oldest_block_height": "0",
            "block_height": "5000"
        }"#;
        let info: LedgerInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.chain_id, 2);
        assert_eq!(info.version().unwrap(), 12345);
        assert_eq!(info.height().unwrap(), 5000);
        assert_eq!(info.epoch_num().unwrap(), 100);
    }

    #[test]
    fn test_account_data_deserialization() {
        let json = r#"{
            "sequence_number": "10",
            "authentication_key": "0x1234"
        }"#;
        let account: AccountData = serde_json::from_str(json).unwrap();
        assert_eq!(account.sequence_number().unwrap(), 10);
    }

    #[test]
    fn test_resource_deserialization() {
        let json = r#"{
            "type": "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
            "data": {"coin": {"value": "1000"}}
        }"#;
        let resource: Resource = serde_json::from_str(json).unwrap();
        assert_eq!(
            resource.typ,
            "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"
        );
    }

    #[test]
    fn test_move_module_abi_deserialization() {
        let json = r#"{
            "address": "0x1",
            "name": "coin",
            "exposed_functions": [
                {
                    "name": "transfer",
                    "visibility": "public",
                    "is_entry": true,
                    "is_view": false,
                    "generic_type_params": [],
                    "params": ["&signer", "address", "u64"],
                    "return": []
                }
            ],
            "structs": []
        }"#;
        let abi: MoveModuleABI = serde_json::from_str(json).unwrap();
        assert_eq!(abi.name, "coin");
        assert_eq!(abi.exposed_functions.len(), 1);
        assert!(abi.exposed_functions[0].is_entry);
    }

    #[test]
    fn test_move_struct_def_deserialization() {
        let json = r#"{
            "name": "CoinStore",
            "is_native": false,
            "abilities": ["key"],
            "generic_type_params": [
                {"constraints": []}
            ],
            "fields": [
                {"name": "coin", "type": "0x1::coin::Coin<T0>"}
            ]
        }"#;
        let struct_def: MoveStructDef = serde_json::from_str(json).unwrap();
        assert_eq!(struct_def.name, "CoinStore");
        assert!(!struct_def.is_native);
        assert_eq!(struct_def.abilities, vec!["key"]);
        assert_eq!(struct_def.fields.len(), 1);
    }
}
