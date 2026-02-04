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
aptos-sdk = "0.1"
```

Basic usage:

```rust
use aptos_sdk::{Aptos, AptosConfig};
use aptos_sdk::account::{Account, Ed25519Account};

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
| `secp256r1` | ✓ | Secp256r1 (P-256) ECDSA signatures |
| `mnemonic` | ✓ | BIP-39 mnemonic phrase support for key derivation |
| `indexer` | ✓ | GraphQL indexer client |
| `faucet` | ✓ | Faucet integration for testnets |
| `bls` | | BLS12-381 signatures |
| `keyless` | | OIDC-based keyless authentication |
| `macros` | | Procedural macros for type-safe contract bindings |
| `full` | | Enable all features |

### Minimal Build

For the smallest possible binary:

```toml
[dependencies]
aptos-sdk = { version = "0.1", default-features = false, features = ["ed25519"] }
```

### Full Build

For all features:

```toml
[dependencies]
aptos-sdk = { version = "0.1", features = ["full"] }
```

## Examples

See the [`examples/`](examples/) directory for complete working examples:

### Basic Operations
- [`transfer.rs`](examples/transfer.rs) - Basic APT transfer
- [`view_function.rs`](examples/view_function.rs) - Read-only view function calls
- [`transaction_data.rs`](examples/transaction_data.rs) - Working with transaction data

### Advanced Transactions
- [`entry_function.rs`](examples/entry_function.rs) - Entry function transaction building
- [`script_transaction.rs`](examples/script_transaction.rs) - Script-based transactions
- [`sponsored_transaction.rs`](examples/sponsored_transaction.rs) - Fee payer (sponsored) transactions
- [`multi_agent.rs`](examples/multi_agent.rs) - Multi-signer transactions
- [`transaction_waiting.rs`](examples/transaction_waiting.rs) - Transaction waiting strategies
- [`advanced_transactions.rs`](examples/advanced_transactions.rs) - Complex transaction combinations

### Account Types
- [`multi_key_account.rs`](examples/multi_key_account.rs) - Multi-key (mixed signature) accounts
- [`multi_sig_account.rs`](examples/multi_sig_account.rs) - MultiEd25519 threshold accounts
- [`multisig_v2.rs`](examples/multisig_v2.rs) - On-chain multisig (governance) accounts

### Smart Contracts
- [`deploy_module.rs`](examples/deploy_module.rs) - Deploy a Move module
- [`call_contract.rs`](examples/call_contract.rs) - Call contract entry functions
- [`read_contract_state.rs`](examples/read_contract_state.rs) - Read contract state
- [`nft_operations.rs`](examples/nft_operations.rs) - NFT/Digital Asset interactions
- [`codegen.rs`](examples/codegen.rs) - Contract binding generation
- [`contract_bindings.rs`](examples/contract_bindings.rs) - Using generated type-safe bindings

## Development

### Building

```bash
# Build with default features
cargo build -p aptos-sdk

# Build with all features
cargo build -p aptos-sdk --all-features

# Build with specific features only
cargo build -p aptos-sdk --features "ed25519,secp256r1,bls"

# Check compilation (faster than build)
cargo check -p aptos-sdk --all-features

# Release build (optimized)
cargo build -p aptos-sdk --release --all-features
```

### Linting

```bash
# Run clippy lints
cargo clippy -p aptos-sdk --all-features -- -D warnings

# Check formatting
cargo fmt -p aptos-sdk -- --check

# Format code
cargo fmt -p aptos-sdk
```

### Testing

#### Unit Tests

```bash
# Run unit tests with default features
cargo test -p aptos-sdk

# Run tests with all features
cargo test -p aptos-sdk --all-features

# Run tests with specific features
cargo test -p aptos-sdk --features "full"

# Run a specific test by name
cargo test -p aptos-sdk test_name

# Run tests with output visible
cargo test -p aptos-sdk -- --nocapture

# Run doc tests only
cargo test -p aptos-sdk --doc

# Run library tests only (no integration tests)
cargo test -p aptos-sdk --lib
```

#### E2E Tests

E2E tests require a running Aptos localnet:

```bash
# Terminal 1: Start localnet
aptos node run-localnet

# Terminal 2: Run E2E tests
cargo test -p aptos-sdk --features "e2e" -- --ignored
```

#### Behavioral Tests

The SDK includes Gherkin-based behavioral specification tests:

```bash
# Run behavioral tests (from workspace root)
cd specifications/tests/rust
cargo test

# Run with verbose output
cargo test -- --nocapture
```

### Code Coverage

```bash
# Unit tests only (default)
cargo tarpaulin -p aptos-sdk --features "full" --skip-clean

# Include E2E tests (requires localnet)
cargo tarpaulin -p aptos-sdk --features "full,e2e" --ignored --skip-clean --timeout 300

# Or use the helper script
./scripts/coverage.sh        # Unit tests only
./scripts/coverage.sh e2e    # Include E2E tests
./scripts/coverage.sh ci     # CI mode with HTML/XML output
```

See `tarpaulin.toml` for coverage configuration profiles.

### Generating Documentation

```bash
# Generate and open documentation
cargo doc -p aptos-sdk --all-features --open

# Generate docs without opening browser
cargo doc -p aptos-sdk --all-features

# Include private items in docs
cargo doc -p aptos-sdk --all-features --document-private-items
```

## Resources

- [API Documentation](https://docs.rs/aptos-sdk)
- [Aptos Developer Documentation](https://aptos.dev)

## License

Apache-2.0

