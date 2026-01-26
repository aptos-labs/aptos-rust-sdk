# aptos-rust-sdk-v2-macros

Procedural macros for generating type-safe Aptos contract bindings at compile time.

## Features

- `aptos_contract!` - Generate contract bindings from inline ABI
- `aptos_contract_file!` - Generate contract bindings from ABI file
- `#[derive(MoveStruct)]` - Derive Move struct serialization
- Compile-time type checking for contract interactions

## Usage

### Contract Bindings from ABI

```rust
use aptos_rust_sdk_v2_macros::aptos_contract;

// From inline ABI JSON
aptos_contract! {
    name: MyCoin,
    abi: r#"{
        "address": "0xcafe",
        "name": "my_coin",
        "exposed_functions": [...],
        "structs": [...]
    }"#
}

// Use the generated bindings
let payload = MyCoin::transfer(recipient, amount)?;
let balance = MyCoin::view_balance(&aptos, owner).await?;
```

### From ABI File

```rust
use aptos_rust_sdk_v2_macros::aptos_contract_file;

// Load ABI from file at compile time
aptos_contract_file!("abi/my_module.json", MyModule);
```

### With Move Source (Better Parameter Names)

```rust
use aptos_rust_sdk_v2_macros::aptos_contract;

aptos_contract! {
    name: MyCoin,
    abi: include_str!("../abi/my_coin.json"),
    source: include_str!("../sources/my_coin.move")
}
```

## Generated Code

For a module with entry functions `transfer` and `mint`, and view function `balance`:

```rust
pub struct MyCoin;

impl MyCoin {
    /// Transfer tokens to a recipient
    pub fn transfer(
        recipient: AccountAddress,
        amount: u64,
    ) -> AptosResult<TransactionPayload> {
        // ...
    }

    /// Mint new tokens
    pub fn mint(
        to: AccountAddress,
        amount: u64,
    ) -> AptosResult<TransactionPayload> {
        // ...
    }

    /// Get balance for an account
    pub async fn view_balance(
        aptos: &Aptos,
        owner: AccountAddress,
    ) -> AptosResult<u64> {
        // ...
    }
}
```

## License

Apache-2.0

