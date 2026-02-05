# Feature Plan: Type-Safe Contract Bindings (Proc Macros)

## Overview

Generate compile-time type-safe bindings for Move contracts using procedural macros. This eliminates runtime ABI parsing and provides IDE support, autocomplete, and compile-time error checking.

## Status: ✅ Implemented

## Goals

1. **Compile-Time Safety** - Type check contract interactions at compile time
2. **Developer Experience** - IDE autocomplete, documentation, and error messages
3. **Zero Runtime Overhead** - No ABI parsing at runtime
4. **Move Source Integration** - Extract parameter names and docs from Move source

## Macros

### `aptos_contract!`

Generates contract bindings from inline ABI:

```rust
use aptos_sdk::aptos_contract;

aptos_contract! {
    name: CoinModule,
    abi: r#"{
        "address": "0x1",
        "name": "coin",
        "exposed_functions": [
            {
                "name": "transfer",
                "is_entry": true,
                "params": ["&signer", "address", "u64"],
                ...
            }
        ],
        "structs": [...]
    }"#,
    // Optional: Move source for better param names
    source: r#"
        module 0x1::coin {
            public entry fun transfer(sender: &signer, to: address, amount: u64) { }
        }
    "#
}

// Generated:
// pub struct CoinModule;
// impl CoinModule {
//     pub fn transfer(to: AccountAddress, amount: u64, type_args: Vec<TypeTag>) 
//         -> AptosResult<TransactionPayload> { ... }
// }
```

### `aptos_contract_file!`

Generates bindings from an ABI file:

```rust
use aptos_sdk::aptos_contract_file;

// Reads ABI at compile time
aptos_contract_file!("abi/my_module.json", MyModule);

// With Move source
aptos_contract_file!("abi/my_module.json", MyModule, "sources/my_module.move");
```

### `#[derive(MoveStruct)]`

Derives BCS serialization for Move-compatible structs:

```rust
use aptos_sdk::MoveStruct;

#[derive(MoveStruct, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[move_struct(address = "0x1", module = "coin", name = "CoinStore")]
pub struct CoinStore {
    pub coin: u64,
    pub frozen: bool,
}

// Generated:
// impl CoinStore {
//     pub fn type_tag() -> &'static str { "0x1::coin::CoinStore" }
//     pub fn to_bcs(&self) -> AptosResult<Vec<u8>> { ... }
//     pub fn from_bcs(bytes: &[u8]) -> AptosResult<Self> { ... }
// }
```

## Generated Code

For each entry function:
- Excludes `&signer` parameters (sender is implicit)
- Generates BCS-encoded arguments
- Returns `AptosResult<TransactionPayload>`

For each view function:
- Generates async function taking `&Aptos` client
- JSON-encodes arguments for API call
- Returns `AptosResult<Vec<serde_json::Value>>`

For each struct:
- Generates Rust struct with serde derives
- Handles generic type parameters
- Maps Move types to Rust types

## Type Mapping

| Move Type | Rust Type |
|-----------|-----------|
| `bool` | `bool` |
| `u8`-`u128` | `u8`-`u128` |
| `u256` | `U256` |
| `address` | `AccountAddress` |
| `vector<u8>` | `Vec<u8>` |
| `vector<T>` | `Vec<T>` |
| `0x1::string::String` | `String` |
| `0x1::option::Option<T>` | `Option<T>` |
| `0x1::object::Object<T>` | `AccountAddress` |

## Usage Example

```rust
use aptos_sdk::{aptos_contract, Aptos, AptosConfig};

aptos_contract! {
    name: MyToken,
    abi: include_str!("../abi/my_token.json"),
    source: include_str!("../sources/my_token.move")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let aptos = Aptos::new(AptosConfig::testnet())?;
    let account = aptos.account().create_ed25519()?;
    
    // Type-safe entry function call
    let payload = MyToken::transfer(recipient, 1000)?;
    aptos.sign_submit_and_wait(&account, payload, None).await?;
    
    // Type-safe view function call
    let balance = MyToken::view_balance(&aptos, account.address()).await?;
    
    Ok(())
}
```

## Implementation

### Crate Structure

```
crates/aptos-sdk-macros/
├── Cargo.toml
├── src/
│   ├── lib.rs       # Macro definitions
│   ├── abi.rs       # ABI types
│   ├── parser.rs    # Input parsing & Move source parsing
│   └── codegen.rs   # Code generation
```

### Feature Flag

Enable with the `macros` feature:

```toml
[dependencies]
aptos-sdk = { version = "0.1", features = ["macros"] }
```

## Benefits

1. **Compile-time errors** - Catch type mismatches before runtime
2. **IDE support** - Autocomplete, go-to-definition, inline docs
3. **No runtime parsing** - ABI is processed at compile time
4. **Meaningful names** - Parameter names from Move source
5. **Documentation** - Doc comments preserved from Move source

## Future Enhancements

1. **Network fetch** - `aptos_contract_network!` to fetch ABI at compile time
2. **Watch mode** - Regenerate on ABI/source file changes
3. **Custom type mappings** - User-defined Move-to-Rust mappings
4. **Event types** - Generate event structs from ABI
5. **Builder pattern** - Fluent API for complex calls

