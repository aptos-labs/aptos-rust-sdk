# Feature Plan: InputEntryFunctionData

## Overview

`InputEntryFunctionData` provides a type-safe, ergonomic builder pattern for constructing entry function payloads. It eliminates the need for manual BCS encoding and provides better error handling during payload construction.

## Goals

1. **Ergonomic API** - Simple, fluent builder pattern
2. **Type-safe arguments** - Accept Rust types directly, auto-encode to BCS
3. **Type argument parsing** - Parse type tags from strings
4. **Error accumulation** - Collect all errors before failing
5. **Common helpers** - Pre-built methods for common operations

## API Design

### InputEntryFunctionData

```rust
/// A type-safe builder for entry function payloads.
#[derive(Debug, Clone)]
pub struct InputEntryFunctionData {
    module: MoveModuleId,
    function: String,
    type_args: Vec<TypeTag>,
    args: Vec<Vec<u8>>,
}

impl InputEntryFunctionData {
    /// Creates a new builder from a function ID string.
    pub fn new(function_id: &str) -> InputEntryFunctionDataBuilder;

    /// Creates a builder from module and function name.
    pub fn from_parts(module: MoveModuleId, function: impl Into<String>) -> InputEntryFunctionDataBuilder;

    // Common operation helpers
    pub fn transfer_apt(recipient: AccountAddress, amount: u64) -> AptosResult<TransactionPayload>;
    pub fn transfer_coin(coin_type: &str, recipient: AccountAddress, amount: u64) -> AptosResult<TransactionPayload>;
    pub fn create_account(auth_key: AccountAddress) -> AptosResult<TransactionPayload>;
    pub fn register_coin(coin_type: &str) -> AptosResult<TransactionPayload>;
    pub fn publish_package(metadata: Vec<u8>, code: Vec<Vec<u8>>) -> AptosResult<TransactionPayload>;
}
```

### InputEntryFunctionDataBuilder

```rust
/// Builder for InputEntryFunctionData.
pub struct InputEntryFunctionDataBuilder {
    module: Result<MoveModuleId, String>,
    function: String,
    type_args: Vec<TypeTag>,
    args: Vec<Vec<u8>>,
    errors: Vec<String>,
}

impl InputEntryFunctionDataBuilder {
    /// Adds a type argument from a string.
    pub fn type_arg(self, type_arg: &str) -> Self;

    /// Adds a type argument from a TypeTag.
    pub fn type_arg_typed(self, type_arg: TypeTag) -> Self;

    /// Adds multiple type arguments.
    pub fn type_args(self, type_args: impl IntoIterator<Item = &'static str>) -> Self;

    /// Adds a BCS-encodable argument.
    pub fn arg<T: Serialize>(self, value: T) -> Self;

    /// Adds a raw BCS-encoded argument.
    pub fn arg_raw(self, bytes: Vec<u8>) -> Self;

    /// Builds the transaction payload.
    pub fn build(self) -> AptosResult<TransactionPayload>;

    /// Builds just the entry function.
    pub fn build_entry_function(self) -> AptosResult<EntryFunction>;
}
```

### Helper Functions

```rust
/// Creates a Move vector from items.
pub fn move_vec<T: Serialize>(items: &[T]) -> Vec<u8>;

/// Creates a Move string.
pub fn move_string(s: &str) -> String;

/// Creates an Option::Some value.
pub fn move_some<T: Serialize>(value: T) -> Vec<u8>;

/// Creates an Option::None value.
pub fn move_none() -> Vec<u8>;
```

### MoveU256

```rust
/// A u256 value for Move arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveU256(pub [u8; 32]);

impl MoveU256 {
    pub fn from_str(s: &str) -> AptosResult<Self>;
    pub fn from_u128(val: u128) -> Self;
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self;
}
```

### Common Constants

```rust
pub mod functions {
    pub const APT_TRANSFER: &str = "0x1::aptos_account::transfer";
    pub const COIN_TRANSFER: &str = "0x1::coin::transfer";
    pub const CREATE_ACCOUNT: &str = "0x1::aptos_account::create_account";
    pub const REGISTER_COIN: &str = "0x1::managed_coin::register";
    pub const PUBLISH_PACKAGE: &str = "0x1::code::publish_package_txn";
}

pub mod types {
    pub const APT_COIN: &str = "0x1::aptos_coin::AptosCoin";
}
```

## TypeTag Parsing

Added `TypeTag::from_str_strict` to parse type tags from strings:

```rust
impl TypeTag {
    pub fn from_str_strict(s: &str) -> AptosResult<Self>;
}
```

Supports:
- Primitive types: `bool`, `u8`, `u16`, `u32`, `u64`, `u128`, `u256`, `address`, `signer`
- Struct types: `0x1::module::Struct`
- Vector types: `vector<element>`
- Generic types: `0x1::module::Struct<T1, T2>`

## Usage Examples

### Simple Transfer

```rust
let payload = InputEntryFunctionData::new("0x1::aptos_account::transfer")
    .arg(recipient_address)
    .arg(1_000_000u64)
    .build()?;
```

### Transfer with Type Args

```rust
let payload = InputEntryFunctionData::new("0x1::coin::transfer")
    .type_arg("0x1::aptos_coin::AptosCoin")
    .arg(recipient)
    .arg(amount)
    .build()?;
```

### Using Helper Methods

```rust
// APT transfer
let payload = InputEntryFunctionData::transfer_apt(recipient, 1_000_000)?;

// Coin transfer
let payload = InputEntryFunctionData::transfer_coin(
    "0x1::aptos_coin::AptosCoin",
    recipient,
    amount,
)?;

// Create account
let payload = InputEntryFunctionData::create_account(auth_key)?;
```

### Various Argument Types

```rust
let payload = InputEntryFunctionData::new("0x1::my_module::my_function")
    .arg(42u64)           // u64
    .arg(true)            // bool
    .arg("hello".to_string())  // String
    .arg(vec![1u8, 2, 3])     // Vec<u8>
    .arg(AccountAddress::ONE) // address
    .arg(MoveU256::from_u128(12345)) // u256
    .build()?;
```

### Move Option Values

```rust
let payload = InputEntryFunctionData::new("0x1::optional::set_value")
    .arg_raw(move_some(42u64))  // Option::Some
    .build()?;

let payload = InputEntryFunctionData::new("0x1::optional::clear_value")
    .arg_raw(move_none())  // Option::None
    .build()?;
```

## Implementation Details

### Error Handling

The builder accumulates errors during construction:
- Invalid function ID → stored as error
- Invalid type argument → added to errors list
- Serialization failure → added to errors list

All errors are reported when `build()` is called, providing better debugging.

### BCS Encoding

Arguments are automatically BCS-encoded using `aptos_bcs::to_bytes`. This handles:
- Primitive types
- Structs with `#[derive(Serialize)]`
- Vectors
- Options (via `move_some`/`move_none` helpers)

### Type Arguments

Type arguments are parsed using the new `TypeTag::from_str_strict` method which supports:
- All primitive types
- Struct tags with generics
- Nested vector types
- Complex generic types

## Testing

### Unit Tests

1. **Builder tests**
   - Simple transfer construction
   - Type argument parsing
   - Invalid function ID handling
   - Invalid type arg handling
   - Various argument types

2. **Helper function tests**
   - `transfer_apt`
   - `transfer_coin`
   - `move_some` / `move_none`
   - `MoveU256` serialization

3. **TypeTag parsing tests**
   - Primitive types
   - Struct types
   - Vector types
   - Generic types

## Dependencies

- Uses existing `aptos_bcs` for serialization
- Uses existing `TypeTag`, `MoveModuleId`, `EntryFunctionId`
- No new external dependencies

## Files Changed

1. `src/transaction/input.rs` - New input builder module
2. `src/transaction/mod.rs` - Export input types
3. `src/types/move_types.rs` - Add `TypeTag::from_str_strict`
4. `feature-plans/19-input-entry-function-data.md` - This document

## Comparison with TypeScript SDK

| TypeScript SDK | Rust SDK |
|----------------|----------|
| `InputEntryFunctionData` type | `InputEntryFunctionData::new()` builder |
| `generateRawTransaction` | `.build()` returns `TransactionPayload` |
| JSON type arguments | String parsing with `TypeTag::from_str_strict` |
| JSON arguments | Type-safe `.arg<T>()` with auto BCS encoding |

## Future Enhancements

1. **Validation** - Validate arguments against ABI at runtime
2. **Simulation** - Simulate payload before building
3. **ABI integration** - Load function signatures from on-chain ABI
4. **Macro support** - Compile-time checked payloads (already in `aptos_contract!`)

