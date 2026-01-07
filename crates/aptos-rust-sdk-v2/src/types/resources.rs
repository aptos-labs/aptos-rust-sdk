//! Common resource types from the Aptos framework.
//!
//! These types represent the most commonly accessed on-chain resources.

use crate::types::events::EventHandle;
use crate::types::AccountAddress;
use serde::{Deserialize, Serialize};

/// The account resource stored at every account address.
///
/// This resource contains basic account information including
/// the sequence number used for replay protection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountResource {
    /// The sequence number of the next transaction to be submitted.
    pub sequence_number: u64,
    /// The authentication key (derived from public key).
    pub authentication_key: String,
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
    pub current_supply: u64,
    /// The maximum supply (0 for unlimited).
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
    pub active: u64,
    /// Inactive stake amount.
    pub inactive: u64,
    /// Pending active stake.
    pub pending_active: u64,
    /// Pending inactive stake.
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
    pub minimum_stake: u64,
    /// Maximum stake allowed.
    pub maximum_stake: u64,
    /// Recurring lockup duration in seconds.
    pub recurring_lockup_duration_secs: u64,
    /// Whether rewards are enabled.
    pub rewards_rate: u64,
    /// The rewards rate denominator.
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
        let coin_store = CoinStoreResource {
            coin: CoinInfo { value: 1000 },
            frozen: false,
            deposit_events: EventHandle {
                counter: 0,
                guid: crate::types::events::EventGuid {
                    creation_number: 0,
                    account_address: AccountAddress::ONE,
                },
            },
            withdraw_events: EventHandle {
                counter: 0,
                guid: crate::types::events::EventGuid {
                    creation_number: 1,
                    account_address: AccountAddress::ONE,
                },
            },
        };
        assert_eq!(coin_store.balance(), 1000);
    }
}

