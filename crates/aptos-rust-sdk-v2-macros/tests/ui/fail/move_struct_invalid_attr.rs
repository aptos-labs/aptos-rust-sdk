//! Test that MoveStruct derive rejects unknown attributes.

use aptos_rust_sdk_v2_macros::MoveStruct;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, MoveStruct)]
#[move_struct(address = "0x1", invalid_attr = "value")]
pub struct BadStruct {
    pub value: u64,
}

fn main() {}
