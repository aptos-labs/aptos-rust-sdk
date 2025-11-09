use crate::api_types::chain_id::ChainId;
use crate::api_types::numbers::U64;
use serde::{Deserialize, Serialize};

/// Ledger information returned from the RPC API
/// This represents the JSON response from the `/v1` endpoint
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct LedgerInfo {
    /// The chain ID of the network
    #[serde(rename = "chain_id")]
    pub chain_id: u8,

    /// The current epoch number
    #[serde(rename = "epoch")]
    pub epoch: U64,

    /// The current ledger version
    #[serde(rename = "ledger_version")]
    pub ledger_version: U64,

    /// The oldest ledger version available
    #[serde(rename = "oldest_ledger_version")]
    pub oldest_ledger_version: U64,

    /// The ledger timestamp in microseconds
    #[serde(rename = "ledger_timestamp")]
    pub ledger_timestamp: U64,

    /// The role of the node (e.g., "full_node")
    #[serde(rename = "node_role")]
    pub node_role: String,

    /// The oldest block height available
    #[serde(rename = "oldest_block_height")]
    pub oldest_block_height: U64,

    /// The current block height
    #[serde(rename = "block_height")]
    pub block_height: U64,

    /// The git hash of the node software
    #[serde(rename = "git_hash")]
    pub git_hash: String,
}

impl LedgerInfo {
    /// Get the chain ID as a ChainId enum
    pub fn chain_id(&self) -> ChainId {
        ChainId::from_u8(self.chain_id)
    }

    /// Get the epoch as u64
    pub fn epoch_u64(&self) -> u64 {
        self.epoch.as_u64()
    }

    /// Get the ledger version as u64
    pub fn ledger_version_u64(&self) -> u64 {
        self.ledger_version.as_u64()
    }

    /// Get the oldest ledger version as u64
    pub fn oldest_ledger_version_u64(&self) -> u64 {
        self.oldest_ledger_version.as_u64()
    }

    /// Get the ledger timestamp as u64
    pub fn ledger_timestamp_u64(&self) -> u64 {
        self.ledger_timestamp.as_u64()
    }

    /// Get the oldest block height as u64
    pub fn oldest_block_height_u64(&self) -> u64 {
        self.oldest_block_height.as_u64()
    }

    /// Get the block height as u64
    pub fn block_height_u64(&self) -> u64 {
        self.block_height.as_u64()
    }
}
