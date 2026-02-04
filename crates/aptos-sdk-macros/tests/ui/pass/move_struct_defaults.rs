//! Test that MoveStruct derive works with default attribute values.

use aptos_sdk_macros::MoveStruct;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, MoveStruct)]
pub struct MyStruct {
    pub value: u64,
}

fn main() {
    // When no attributes are provided, uses defaults:
    // address = "0x1", module = "unknown", name = struct name
    let type_tag = MyStruct::type_tag();
    assert_eq!(type_tag, "0x1::unknown::MyStruct");
}
