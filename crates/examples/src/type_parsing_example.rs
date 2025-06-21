use aptos_rust_sdk_types::api_types::type_tag::{StructTag, TypeTag};
use std::str::FromStr;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing TypeTag parsing:");

    // Test primitive types
    let primitive_types = vec![
        "bool", "u8", "u16", "u32", "u64", "u128", "u256", "address", "signer",
    ];

    for type_str in primitive_types {
        let parsed = TypeTag::from_str(type_str)?;
        println!("  {} -> {}", type_str, parsed.to_canonical_string());
    }

    // Test vector types
    let vector_types = vec!["vector<u8>", "vector<bool>", "vector<vector<u64>>"];

    for type_str in vector_types {
        let parsed = TypeTag::from_str(type_str)?;
        println!("  {} -> {}", type_str, parsed.to_canonical_string());
    }

    println!("\nTesting StructTag parsing:");

    // Test struct types
    let struct_types = vec![
        "0x1::string::String",
        "0x1::option::Option<u64>",
        "0x1::coin::Coin<0x1::aptos_coin::AptosCoin>",
        "0x123::module::Name<bool, vector<u8>>",
    ];

    for type_str in struct_types {
        let parsed = StructTag::from_str(type_str)?;
        println!("  {} -> {}", type_str, parsed.to_canonical_string());
    }

    println!("\nTesting TypeTag with complex struct types:");

    // Test complex types that include structs
    let complex_types = vec![
        "0x1::string::String",
        "vector<0x1::coin::Coin<0x1::aptos_coin::AptosCoin>>",
    ];

    for type_str in complex_types {
        let parsed = TypeTag::from_str(type_str)?;
        println!("  {} -> {}", type_str, parsed.to_canonical_string());
    }

    println!("\nAll parsing tests completed successfully!");
    Ok(())
}
