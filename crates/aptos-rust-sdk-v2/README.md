# Aptos Rust SDK v2

A user-friendly, idiomatic Rust SDK for the Aptos blockchain with feature parity to the TypeScript SDK.

## Features

- **Full Blockchain Interaction**: Connect, explore, and interact with the Aptos blockchain
- **Multiple Signature Schemes**: Ed25519, Secp256k1, Secp256r1 (P-256), and BLS12-381
- **Transaction Building**: Fluent builder pattern for constructing transactions
- **Account Management**: Single-key, multi-sig, and keyless (OIDC) accounts
- **Type Safety**: Strong Rust type system for Move contract interactions
- **Modular Design**: Feature flags to include only what you need

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
aptos-rust-sdk-v2 = "0.1"
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
aptos-rust-sdk-v2 = { version = "0.1", default-features = false, features = ["ed25519"] }
```

### Full Build

For all features:

```toml
[dependencies]
aptos-rust-sdk-v2 = { version = "0.1", features = ["full"] }
```

## Examples

See the [`examples/`](examples/) directory for complete working examples:

- [`transfer.rs`](examples/transfer.rs) - Basic APT transfer
- [`deploy_module.rs`](examples/deploy_module.rs) - Deploy a Move module
- [`sponsored_transaction.rs`](examples/sponsored_transaction.rs) - Fee payer flow
- [`multi_agent.rs`](examples/multi_agent.rs) - Multi-signer transactions
- [`view_function.rs`](examples/view_function.rs) - Read-only queries

## Testing

### Running Unit Tests

```bash
# Run unit tests with default features
cargo test -p aptos-rust-sdk-v2 --lib

# Run unit tests with all features
cargo test -p aptos-rust-sdk-v2 --lib --features "full"

# Run behavioral tests
cargo test -p aptos-rust-sdk-v2 --test lib --features "full"
```

### Running E2E Tests

E2E tests require a running Aptos localnet:

```bash
# Terminal 1: Start localnet
aptos node run-localnet

# Terminal 2: Run E2E tests
cargo test -p aptos-rust-sdk-v2 --features "e2e" -- --ignored
```

### Code Coverage

```bash
# Unit tests only (default)
cargo tarpaulin -p aptos-rust-sdk-v2 --features "full" --skip-clean

# Include E2E tests (requires localnet)
cargo tarpaulin -p aptos-rust-sdk-v2 --features "full,e2e" --ignored --skip-clean --timeout 300

# Or use the helper script
./scripts/coverage.sh        # Unit tests only
./scripts/coverage.sh e2e    # Include E2E tests
./scripts/coverage.sh ci     # CI mode with HTML/XML output
```

See `tarpaulin.toml` for coverage configuration profiles.

## Documentation

- [API Documentation](https://docs.rs/aptos-rust-sdk-v2)
- [Aptos Developer Documentation](https://aptos.dev)

## License

Apache-2.0

