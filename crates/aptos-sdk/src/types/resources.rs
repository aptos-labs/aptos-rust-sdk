//! Common resource types from the Aptos framework.
//!
//! These types represent the most commonly accessed on-chain resources and
//! deserialize the JSON shape returned by the Aptos REST (fullnode) API. In
//! particular, the API encodes every `u64` / `u128` value as a JSON string
//! (e.g. `"42"`); the numeric fields here parse that shape (and also accept a
//! plain JSON number for convenience) and serialize back to a string.
//!
//! Some structs are intentionally *partial* views of the underlying on-chain
//! resource: they declare only the fields callers commonly need. Because serde
//! ignores unknown fields by default, they still deserialize cleanly from the
//! full API object.

use crate::types::AccountAddress;
use crate::types::events::EventHandle;
use serde::{Deserialize, Serialize};

/// The account resource stored at every account address (`0x1::account::Account`).
///
/// This resource contains basic account information including
/// the sequence number used for replay protection.
///
/// This is a **partial view**: the full on-chain `Account` also carries the
/// `coin_register_events` / `key_rotation_events` handles and the rotation /
/// signer capability offers. Those fields are ignored during deserialization
/// (serde skips unknown fields), so this type still parses the full API object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountResource {
    /// The sequence number of the next transaction to be submitted.
    #[serde(with = "crate::types::string_num")]
    pub sequence_number: u64,
    /// The authentication key, as the hex string returned by the REST API
    /// (a `0x`-prefixed encoding of the on-chain `vector<u8>`).
    pub authentication_key: String,
    /// The next GUID creation number for this account.
    #[serde(default, with = "crate::types::string_num")]
    pub guid_creation_num: u64,
}

impl AccountResource {
    /// The type string for this resource.
    pub const TYPE: &'static str = "0x1::account::Account";
}

/// A coin store resource that holds a specific coin type.
///
/// This is the generic structure; use `CoinStore<AptosCoin>` for APT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinStoreResource {
    /// The current balance.
    pub coin: CoinInfo,
    /// Whether deposits are frozen.
    pub frozen: bool,
    /// Event handle for deposit events.
    pub deposit_events: EventHandle,
    /// Event handle for withdraw events.
    pub withdraw_events: EventHandle,
}

/// Coin information containing the balance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinInfo {
    /// The coin value/balance.
    #[serde(with = "crate::types::string_num")]
    pub value: u64,
}

impl CoinStoreResource {
    /// Returns the coin balance.
    pub fn balance(&self) -> u64 {
        self.coin.value
    }
}

/// The APT coin store type string.
#[allow(dead_code)]
pub const APT_COIN_STORE_TYPE: &str = "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>";

/// Fungible asset balance (for the new fungible asset standard).
#[allow(dead_code)] // Public API for users
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FungibleAssetBalance {
    /// The balance amount.
    #[serde(with = "crate::types::string_num")]
    pub balance: u64,
    /// Whether the balance is frozen.
    pub frozen: bool,
}

/// Fungible asset metadata.
#[allow(dead_code)] // Public API for users
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FungibleAssetMetadata {
    /// The name of the asset.
    pub name: String,
    /// The symbol of the asset.
    pub symbol: String,
    /// The number of decimals.
    pub decimals: u8,
}

/// Collection data for NFTs (v2).
#[allow(dead_code)] // Public API for users
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionData {
    /// The name of the collection.
    pub name: String,
    /// The description of the collection.
    pub description: String,
    /// The URI for collection metadata.
    pub uri: String,
    /// The current supply.
    #[serde(with = "crate::types::string_num")]
    pub current_supply: u64,
    /// The maximum supply (0 for unlimited).
    #[serde(with = "crate::types::string_num")]
    pub maximum_supply: u64,
}

/// Token data for NFTs (v2).
#[allow(dead_code)] // Public API for users
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenData {
    /// The name of the token.
    pub name: String,
    /// The description of the token.
    pub description: String,
    /// The URI for token metadata.
    pub uri: String,
    /// The collection this token belongs to.
    pub collection: AccountAddress,
}

/// Stake pool resource.
#[allow(dead_code)] // Public API for users
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StakePool {
    /// Active stake amount.
    #[serde(with = "crate::types::string_num")]
    pub active: u64,
    /// Inactive stake amount.
    #[serde(with = "crate::types::string_num")]
    pub inactive: u64,
    /// Pending active stake.
    #[serde(with = "crate::types::string_num")]
    pub pending_active: u64,
    /// Pending inactive stake.
    #[serde(with = "crate::types::string_num")]
    pub pending_inactive: u64,
    /// The operator address.
    pub operator_address: AccountAddress,
    /// The delegated voter address.
    pub delegated_voter: AccountAddress,
}

/// Staking config resource.
#[allow(dead_code)] // Public API for users
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StakingConfig {
    /// Minimum stake required.
    #[serde(with = "crate::types::string_num")]
    pub minimum_stake: u64,
    /// Maximum stake allowed.
    #[serde(with = "crate::types::string_num")]
    pub maximum_stake: u64,
    /// Recurring lockup duration in seconds.
    #[serde(with = "crate::types::string_num")]
    pub recurring_lockup_duration_secs: u64,
    /// Whether rewards are enabled.
    #[serde(with = "crate::types::string_num")]
    pub rewards_rate: u64,
    /// The rewards rate denominator.
    #[serde(with = "crate::types::string_num")]
    pub rewards_rate_denominator: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_resource_type() {
        assert_eq!(AccountResource::TYPE, "0x1::account::Account");
    }

    #[test]
    fn test_coin_store_balance() {
        use crate::types::events::{EventHandleGuid, EventHandleGuidId};
        let handle = |creation_num| EventHandle {
            counter: 0,
            guid: EventHandleGuid {
                id: EventHandleGuidId {
                    addr: AccountAddress::ONE,
                    creation_num,
                },
            },
        };
        let coin_store = CoinStoreResource {
            coin: CoinInfo { value: 1000 },
            frozen: false,
            deposit_events: handle(0),
            withdraw_events: handle(1),
        };
        assert_eq!(coin_store.balance(), 1000);
    }

    #[test]
    fn test_account_resource_api_json() {
        // Realistic fullnode `0x1::account::Account` data: all integers are
        // JSON strings, and there are extra fields this partial view ignores.
        let json = r#"{
            "authentication_key": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "coin_register_events": {
                "counter": "1",
                "guid": {"id": {"addr": "0x1", "creation_num": "0"}}
            },
            "guid_creation_num": "4",
            "key_rotation_events": {
                "counter": "0",
                "guid": {"id": {"addr": "0x1", "creation_num": "1"}}
            },
            "rotation_capability_offer": {"for": {"vec": []}},
            "sequence_number": "42",
            "signer_capability_offer": {"for": {"vec": []}}
        }"#;

        let account: AccountResource = serde_json::from_str(json).unwrap();
        assert_eq!(account.sequence_number, 42);
        assert_eq!(account.guid_creation_num, 4);
        assert_eq!(
            account.authentication_key,
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn test_coin_store_resource_api_json() {
        // Realistic fullnode `0x1::coin::CoinStore<...>` data.
        let json = r#"{
            "coin": {"value": "999999"},
            "deposit_events": {
                "counter": "3",
                "guid": {"id": {"addr": "0x1", "creation_num": "2"}}
            },
            "frozen": false,
            "withdraw_events": {
                "counter": "0",
                "guid": {"id": {"addr": "0x1", "creation_num": "3"}}
            }
        }"#;

        let store: CoinStoreResource = serde_json::from_str(json).unwrap();
        assert_eq!(store.balance(), 999_999);
        assert!(!store.frozen);
        assert_eq!(store.deposit_events.counter, 3);
        assert_eq!(store.deposit_events.guid.id.creation_num, 2);
        assert_eq!(store.deposit_events.guid.id.addr, AccountAddress::ONE);
    }
}
