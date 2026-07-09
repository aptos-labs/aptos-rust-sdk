//! Regression tests for the text (`ModuleGenerator`) code path.
//!
//! The pre-existing generator unit tests only asserted on substrings, which is
//! why several defects that produce *syntactically or semantically invalid*
//! Rust shipped. These tests generate a module that exercises the previously
//! broken paths and parse the result with `syn::parse_file`, so a syntax
//! regression fails the test instead of silently emitting uncompilable code.
//!
//! Covered defects:
//! - generic Move structs (E0392 — unused type parameter) now carry a
//!   `PhantomData` marker,
//! - Move `u256` maps to a real, existing Rust type (`MoveU256`),
//! - BCS argument encoding is fully qualified through `::aptos_sdk::aptos_bcs`,
//! - the `self` keyword field is escaped as `self_` (never the invalid
//!   `r#self`).

use aptos_sdk::api::response::{
    MoveFunction, MoveModuleABI, MoveStructDef, MoveStructField, MoveStructGenericTypeParam,
};
use aptos_sdk::codegen::{GeneratorConfig, ModuleGenerator};

fn abi() -> MoveModuleABI {
    MoveModuleABI {
        address: "0x1".to_string(),
        name: "regress".to_string(),
        exposed_functions: vec![
            // Entry function taking a u256 arg (BCS path).
            MoveFunction {
                name: "deposit".to_string(),
                visibility: "public".to_string(),
                is_entry: true,
                is_view: false,
                generic_type_params: vec![],
                params: vec![
                    "&signer".to_string(),
                    "address".to_string(),
                    "u256".to_string(),
                ],
                returns: vec![],
            },
            // View function returning a u256.
            MoveFunction {
                name: "supply".to_string(),
                visibility: "public".to_string(),
                is_entry: false,
                is_view: true,
                generic_type_params: vec![],
                params: vec![],
                returns: vec!["u256".to_string()],
            },
        ],
        structs: vec![
            // Single generic parameter -> PhantomData<T0> (no stray parens).
            MoveStructDef {
                name: "Coin".to_string(),
                is_native: false,
                abilities: vec!["store".to_string()],
                generic_type_params: vec![MoveStructGenericTypeParam {
                    constraints: vec![],
                }],
                fields: vec![MoveStructField {
                    name: "value".to_string(),
                    typ: "u256".to_string(),
                }],
            },
            // Two generic parameters -> PhantomData<(T0, T1)>.
            MoveStructDef {
                name: "Pair".to_string(),
                is_native: false,
                abilities: vec!["store".to_string()],
                generic_type_params: vec![
                    MoveStructGenericTypeParam {
                        constraints: vec![],
                    },
                    MoveStructGenericTypeParam {
                        constraints: vec![],
                    },
                ],
                fields: vec![MoveStructField {
                    name: "amount".to_string(),
                    typ: "u64".to_string(),
                }],
            },
            // A field named after a keyword that cannot be a raw identifier.
            MoveStructDef {
                name: "Reserved".to_string(),
                is_native: false,
                abilities: vec!["drop".to_string()],
                generic_type_params: vec![],
                fields: vec![MoveStructField {
                    name: "self".to_string(),
                    typ: "u64".to_string(),
                }],
            },
        ],
    }
}

#[test]
fn generated_module_is_valid_rust() {
    let abi = abi();
    let code = ModuleGenerator::new(&abi, GeneratorConfig::default())
        .generate()
        .expect("code generation failed");

    // The output must be syntactically valid Rust.
    syn::parse_file(&code)
        .unwrap_or_else(|e| panic!("generated code is not valid Rust: {e}\n---\n{code}"));

    // Generic structs carry a PhantomData marker (fixes E0392).
    assert!(
        code.contains("_phantom: ::core::marker::PhantomData<T0>,"),
        "single generic param should use PhantomData<T0>:\n{code}"
    );
    assert!(
        code.contains("_phantom: ::core::marker::PhantomData<(T0, T1)>,"),
        "two generic params should use PhantomData<(T0, T1)>:\n{code}"
    );

    // u256 maps to the real, existing `MoveU256` type, not the nonexistent
    // `types::U256` the generator used to emit.
    assert!(
        !code.contains("types::U256"),
        "u256 must not map to the nonexistent types::U256:\n{code}"
    );
    assert!(
        code.contains("MoveU256"),
        "u256 must map to MoveU256:\n{code}"
    );
    assert!(
        code.contains("pub value: MoveU256"),
        "u256 field -> MoveU256:\n{code}"
    );

    // BCS encoding is routed through the re-export.
    assert!(
        code.contains("::aptos_sdk::aptos_bcs::to_bytes"),
        "BCS calls must be fully qualified:\n{code}"
    );

    // `self` keyword field is suffixed, not written as the invalid `r#self`.
    assert!(
        code.contains("self_: u64") && !code.contains("r#self"),
        "keyword field `self` must be escaped as `self_`:\n{code}"
    );
}
