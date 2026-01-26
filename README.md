# Aptos Rust SDK

A user-friendly, idiomatic Rust SDK for the Aptos blockchain with feature parity to the TypeScript SDK.

## Features

- **Full Blockchain Interaction**: Connect, explore, and interact with the Aptos blockchain
- **Multiple Signature Schemes**: Ed25519, Secp256k1, Secp256r1 (P-256), and BLS12-381
- **Transaction Building**: Fluent builder pattern for constructing transactions
- **Account Management**: Single-key, multi-sig, and keyless (OIDC) accounts
- **Type Safety**: Strong Rust type system for Move contract interactions
- **Modular Design**: Feature flags to include only what you need

## Workspace Layout

- `crates/aptos-rust-sdk-v2` – Main SDK crate with async clients, account management, transaction building, and crypto
- `crates/aptos-rust-sdk-v2-macros` – Procedural macros for type-safe contract bindings

## Prerequisites

- Rust toolchain 1.85+ (tracked in `rust-toolchain.toml`)
- Access to an Aptos fullnode REST endpoint (mainnet/testnet/devnet/localnet)

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
aptos-rust-sdk-v2 = { git = "https://github.com/aptos-labs/aptos-rust-sdk", package = "aptos-rust-sdk-v2" }
```

Basic usage:

```rust
use aptos_rust_sdk_v2::{Aptos, AptosConfig};
use aptos_rust_sdk_v2::account::{Account, Ed25519Account};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Connect to testnet
    let aptos = Aptos::new(AptosConfig::testnet())?;

    // Create a new account
    let account = Ed25519Account::generate();
    println!("Address: {}", account.address());

    // Check balance
    let balance = aptos.get_balance(account.address()).await?;
    println!("Balance: {} octas", balance);

    Ok(())
}
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `ed25519` | ✓ | Ed25519 signature scheme |
| `secp256k1` | ✓ | Secp256k1 ECDSA signatures |
| `mnemonic` | ✓ | BIP-39 mnemonic phrase support for key derivation |
| `secp256r1` | | Secp256r1 (P-256) ECDSA signatures |
| `bls` | | BLS12-381 signatures |
| `keyless` | | OIDC-based keyless authentication |
| `indexer` | | GraphQL indexer client |
| `faucet` | | Faucet integration for testnets |
| `full` | | Enable all features |

### Minimal Build

For the smallest possible binary:

```toml
[dependencies]
aptos-rust-sdk-v2 = { git = "https://github.com/aptos-labs/aptos-rust-sdk", package = "aptos-rust-sdk-v2", default-features = false, features = ["ed25519"] }
```

### Full Build

For all features:

```toml
[dependencies]
aptos-rust-sdk-v2 = { git = "https://github.com/aptos-labs/aptos-rust-sdk", package = "aptos-rust-sdk-v2", features = ["full"] }
```

## Examples

See the [`crates/aptos-rust-sdk-v2/examples/`](crates/aptos-rust-sdk-v2/examples/) directory for complete working examples:

- [`transfer.rs`](crates/aptos-rust-sdk-v2/examples/transfer.rs) - Basic APT transfer
- [`deploy_module.rs`](crates/aptos-rust-sdk-v2/examples/deploy_module.rs) - Deploy a Move module
- [`sponsored_transaction.rs`](crates/aptos-rust-sdk-v2/examples/sponsored_transaction.rs) - Fee payer flow
- [`multi_agent.rs`](crates/aptos-rust-sdk-v2/examples/multi_agent.rs) - Multi-signer transactions
- [`view_function.rs`](crates/aptos-rust-sdk-v2/examples/view_function.rs) - Read-only queries
- [`multi_key_account.rs`](crates/aptos-rust-sdk-v2/examples/multi_key_account.rs) - Multi-key account operations
- [`multi_sig_account.rs`](crates/aptos-rust-sdk-v2/examples/multi_sig_account.rs) - Multi-sig v2 accounts
- [`nft_operations.rs`](crates/aptos-rust-sdk-v2/examples/nft_operations.rs) - NFT interactions
- [`codegen.rs`](crates/aptos-rust-sdk-v2/examples/codegen.rs) - Contract binding generation
- [`contract_bindings.rs`](crates/aptos-rust-sdk-v2/examples/contract_bindings.rs) - Using generated bindings

## Development

### Building

```bash
# Build with default features (ed25519 + secp256k1)
cargo build -p aptos-rust-sdk-v2

# Build with all features
cargo build -p aptos-rust-sdk-v2 --all-features

# Release build
cargo build -p aptos-rust-sdk-v2 --release
```

### Testing

```bash
# Run unit tests
cargo test -p aptos-rust-sdk-v2

# Run tests with all features
cargo test -p aptos-rust-sdk-v2 --all-features

# Run E2E tests (requires localnet)
aptos node run-localnet --with-faucet
cargo test -p aptos-rust-sdk-v2 --features "e2e" -- --ignored
```

### Linting and Formatting

```bash
# Run clippy
cargo clippy -p aptos-rust-sdk-v2 --all-features -- -D warnings

# Format code (uses nightly rustfmt)
cargo +nightly fmt
```

## Resources

- [Aptos Developer Documentation](https://aptos.dev)
- [TypeScript SDK](https://github.com/aptos-labs/aptos-ts-sdk)

## License

Apache-2.0
