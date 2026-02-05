//! Test that MoveStruct derive works with basic attributes.

use aptos_sdk_macros::MoveStruct;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, MoveStruct)]
#[move_struct(address = "0x1", module = "coin", name = "CoinStore")]
pub struct CoinStore {
    pub coin: u64,
    pub frozen: bool,
}

fn main() {
    // Verify the generated methods exist and have correct signatures
    let _type_tag: &'static str = CoinStore::type_tag();
    assert_eq!(CoinStore::type_tag(), "0x1::coin::CoinStore");
}
