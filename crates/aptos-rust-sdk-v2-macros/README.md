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
pub struct MyCoin {
    address: Option<String>,
}

impl MyCoin {
    /// Default address from ABI
    pub const DEFAULT_ADDRESS: &'static str = "0xcafe";
    pub const MODULE: &'static str = "my_coin";

    /// Create with default address
    pub fn new() -> Self { ... }

    /// Create with custom address (for different deployments)
    pub fn with_address(addr: impl Into<String>) -> Self { ... }

    /// Get effective address
    pub fn address(&self) -> &str { ... }

    /// Transfer tokens (entry function)
    pub fn transfer(
        &self,
        recipient: AccountAddress,
        amount: u64,
    ) -> AptosResult<TransactionPayload> {
        // ...
    }

    /// Mint new tokens (entry function)
    pub fn mint(
        &self,
        to: AccountAddress,
        amount: u64,
    ) -> AptosResult<TransactionPayload> {
        // ...
    }

    /// Get balance with typed return (BCS - recommended)
    pub async fn view_balance(
        &self,
        aptos: &Aptos,
        owner: AccountAddress,
    ) -> AptosResult<u64> {
        // Uses BCS for lossless serialization
    }

    /// Get balance with JSON response (for debugging)
    pub async fn view_balance_json(
        &self,
        aptos: &Aptos,
        owner: AccountAddress,
    ) -> AptosResult<Vec<serde_json::Value>> {
        // Uses JSON for human-readable output
    }
}
```

## Address Override

The generated bindings support address override for deploying to different addresses:

```rust
// Use default address from ABI
let coin = MyCoin::new();

// Override for testnet deployment
let coin = MyCoin::with_address("0xabcd1234...");

// All methods use the configured address
let payload = coin.transfer(recipient, amount)?;
```

## View Function Variants

Each view function generates two variants:

- `view_<name>()` - Returns typed values using BCS (recommended for type safety)
- `view_<name>_json()` - Returns raw JSON (useful for debugging/inspection)
```

## License

Apache-2.0

