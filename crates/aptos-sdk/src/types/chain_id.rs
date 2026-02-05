//! Chain ID type.
//!
//! The chain ID identifies which Aptos network a transaction is intended for,
//! preventing replay attacks across networks.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A chain identifier for an Aptos network.
///
/// The chain ID is included in every transaction to ensure transactions
/// cannot be replayed across different networks.
///
/// # Known Chain IDs
///
/// - Mainnet: 1
/// - Testnet: 2  
/// - Devnet: varies (typically 165)
/// - Local: 4 (default for local testing)
///
/// # Example
///
/// ```rust
/// use aptos_sdk::ChainId;
///
/// let mainnet = ChainId::mainnet();
/// assert_eq!(mainnet.id(), 1);
///
/// let custom = ChainId::new(42);
/// assert_eq!(custom.id(), 42);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainId(u8);

impl ChainId {
    /// Creates a new chain ID.
    pub const fn new(id: u8) -> Self {
        Self(id)
    }

    /// Returns the chain ID for mainnet (1).
    pub const fn mainnet() -> Self {
        Self(1)
    }

    /// Returns the chain ID for testnet (2).
    pub const fn testnet() -> Self {
        Self(2)
    }

    /// Returns the numeric chain ID value.
    pub const fn id(&self) -> u8 {
        self.0
    }

    /// Returns true if this is the mainnet chain ID.
    pub const fn is_mainnet(&self) -> bool {
        self.0 == 1
    }

    /// Returns true if this is the testnet chain ID.
    pub const fn is_testnet(&self) -> bool {
        self.0 == 2
    }
}

impl Default for ChainId {
    fn default() -> Self {
        Self::testnet()
    }
}

impl fmt::Debug for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChainId({})", self.0)
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u8> for ChainId {
    fn from(id: u8) -> Self {
        Self(id)
    }
}

impl From<ChainId> for u8 {
    fn from(chain_id: ChainId) -> Self {
        chain_id.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_chain_ids() {
        assert_eq!(ChainId::mainnet().id(), 1);
        assert_eq!(ChainId::testnet().id(), 2);
    }

    #[test]
    fn test_is_mainnet_testnet() {
        assert!(ChainId::mainnet().is_mainnet());
        assert!(!ChainId::mainnet().is_testnet());
        assert!(ChainId::testnet().is_testnet());
        assert!(!ChainId::testnet().is_mainnet());
    }

    #[test]
    fn test_custom_chain_id() {
        let custom = ChainId::new(42);
        assert_eq!(custom.id(), 42);
        assert!(!custom.is_mainnet());
        assert!(!custom.is_testnet());
    }

    #[test]
    fn test_json_serialization() {
        let chain_id = ChainId::mainnet();
        let json = serde_json::to_string(&chain_id).unwrap();
        assert_eq!(json, "1");

        let parsed: ChainId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, chain_id);
    }

    #[test]
    fn test_default() {
        let default = ChainId::default();
        assert_eq!(default, ChainId::testnet());
    }

    #[test]
    fn test_debug() {
        let chain_id = ChainId::mainnet();
        let debug = format!("{chain_id:?}");
        assert_eq!(debug, "ChainId(1)");
    }

    #[test]
    fn test_display() {
        let chain_id = ChainId::testnet();
        let display = format!("{chain_id}");
        assert_eq!(display, "2");
    }

    #[test]
    fn test_from_u8() {
        let chain_id: ChainId = 3u8.into();
        assert_eq!(chain_id.id(), 3);
    }

    #[test]
    fn test_into_u8() {
        let chain_id = ChainId::new(5);
        let id: u8 = chain_id.into();
        assert_eq!(id, 5);
    }

    #[test]
    fn test_equality() {
        assert_eq!(ChainId::new(1), ChainId::mainnet());
        assert_ne!(ChainId::mainnet(), ChainId::testnet());
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ChainId::mainnet());
        set.insert(ChainId::testnet());
        assert_eq!(set.len(), 2);
        assert!(set.contains(&ChainId::new(1)));
    }
}
