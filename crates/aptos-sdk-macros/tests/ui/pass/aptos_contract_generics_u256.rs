//! Regression test: `aptos_contract!` output must COMPILE for
//! - generic Move structs (previously emitted `struct Foo<T0>` with an unused
//!   type parameter -> E0392),
//! - Move `u256` arguments/returns (previously mapped to the nonexistent
//!   `aptos_sdk::types::U256`; now the round-tripping `MoveU256` value type),
//! - entry-function bindings whose BCS/type paths must resolve in a crate that
//!   depends only on `aptos-sdk` (previously emitted bare `aptos_bcs::` paths).

use aptos_sdk_macros::aptos_contract;

aptos_contract! {
    name: TestModule,
    abi: r#"{
        "address": "0x1",
        "name": "test_mod",
        "exposed_functions": [
            {
                "name": "deposit",
                "visibility": "public",
                "is_entry": true,
                "is_view": false,
                "generic_type_params": [],
                "params": ["&signer", "address", "u256"],
                "return": []
            },
            {
                "name": "supply",
                "visibility": "public",
                "is_entry": false,
                "is_view": true,
                "generic_type_params": [],
                "params": [],
                "return": ["u256"]
            }
        ],
        "structs": [
            {
                "name": "Coin",
                "is_native": false,
                "abilities": ["store"],
                "generic_type_params": [{"constraints": []}],
                "fields": [{"name": "value", "type": "u256"}]
            },
            {
                "name": "Pair",
                "is_native": false,
                "abilities": ["store"],
                "generic_type_params": [{"constraints": []}, {"constraints": []}],
                "fields": [{"name": "amount", "type": "u64"}]
            }
        ]
    }"#
}

fn main() {
    let contract = TestModule::new();

    // Entry function: `u256` arg is a `MoveU256`, which BCS-encodes as 32
    // little-endian bytes (the correct on-wire form for a Move u256 argument).
    let addr = aptos_sdk::types::AccountAddress::new([0u8; 32]);
    let amount = aptos_sdk::transaction::MoveU256::parse("123456789012345678901234567890").unwrap();
    let _payload = contract.deposit(addr, amount).unwrap();

    // Generic structs compile and are constructible (PhantomData is skipped by
    // serde, so it does not appear in construction beyond the marker field).
    let coin: Coin<u64> = Coin {
        value: aptos_sdk::transaction::MoveU256::from_u128(42),
        _phantom: core::marker::PhantomData,
    };
    let _ = coin.clone();

    let pair: Pair<u64, bool> = Pair {
        amount: 7,
        _phantom: core::marker::PhantomData,
    };
    let _ = pair.clone();

    // The generic structs round-trip through serde/BCS despite the type params.
    let bytes = aptos_sdk::aptos_bcs::to_bytes(&coin).unwrap();
    let _decoded: Coin<u64> = aptos_sdk::aptos_bcs::from_bytes(&bytes).unwrap();
}
