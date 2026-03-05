# Aptos Rust SDK

[![CI](https://github.com/aptos-labs/aptos-rust-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/aptos-labs/aptos-rust-sdk/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/aptos-labs/aptos-rust-sdk/graph/badge.svg)](https://codecov.io/gh/aptos-labs/aptos-rust-sdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](rust-toolchain.toml)
[![API Docs](https://img.shields.io/badge/docs-aptos--labs.github.io-blue)](https://aptos-labs.github.io/aptos-rust-sdk/aptos_sdk/index.html)

A user-friendly, idiomatic Rust SDK for the [Aptos](https://aptos.dev) blockchain with feature parity to the [TypeScript SDK](https://github.com/aptos-labs/aptos-ts-sdk).

## Features

- **Full Blockchain Interaction** &mdash; Connect, explore, and transact on the Aptos blockchain
- **Multiple Signature Schemes** &mdash; Ed25519, Secp256k1, Secp256r1 (P-256), and BLS12-381
- **Transaction Building** &mdash; Fluent builder pattern for entry functions, scripts, and multi-agent transactions
- **Account Management** &mdash; Single-key, multi-key, multi-sig, and keyless (OIDC) accounts
- **Type-Safe Contract Bindings** &mdash; Proc macros for generating Rust bindings from Move ABIs
- **Modular Design** &mdash; Feature flags to include only what you need for minimal binary size
- **Async / Await** &mdash; Built on `tokio` and `reqwest` for non-blocking I/O

## Workspace Layout

| Crate | Description |
|---|---|
| [`aptos-sdk`](crates/aptos-sdk/) | Main SDK &mdash; async clients, account management, transaction building, and crypto |
| [`aptos-sdk-macros`](crates/aptos-sdk-macros/) | Procedural macros for type-safe contract bindings |

## Prerequisites

- **Rust** 1.90+ (pinned in [`rust-toolchain.toml`](rust-toolchain.toml))
- An Aptos fullnode REST endpoint (mainnet / testnet / devnet / localnet)

## Quick Start

Add the SDK to your `Cargo.toml`:

```toml
[dependencies]
aptos-sdk = { git = "https://github.com/aptos-labs/aptos-rust-sdk", package = "aptos-sdk" }
```

Then use it:

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
| `ed25519` | Yes | Ed25519 signature scheme |
| `secp256k1` | Yes | Secp256k1 ECDSA signatures |
| `secp256r1` | Yes | Secp256r1 (P-256) ECDSA signatures |
| `mnemonic` | Yes | BIP-39 mnemonic phrase support for key derivation |
| `indexer` | Yes | GraphQL indexer client |
| `faucet` | Yes | Faucet integration for testnets |
| `bls` | &mdash; | BLS12-381 signatures |
| `keyless` | &mdash; | OIDC-based keyless authentication |
| `macros` | &mdash; | Procedural macros for type-safe contract bindings |
| `full` | &mdash; | Enable all features |

### Minimal Build

Include only the signature scheme you need:

```toml
[dependencies]
aptos-sdk = { git = "https://github.com/aptos-labs/aptos-rust-sdk", package = "aptos-sdk", default-features = false, features = ["ed25519"] }
```

### Full Build

Enable everything:

```toml
[dependencies]
aptos-sdk = { git = "https://github.com/aptos-labs/aptos-rust-sdk", package = "aptos-sdk", features = ["full"] }
```

## Examples

Complete, runnable examples live in [`crates/aptos-sdk/examples/`](crates/aptos-sdk/examples/).

### Basic Operations

| Example | Description |
|---|---|
| [`transfer.rs`](crates/aptos-sdk/examples/transfer.rs) | Basic APT transfer between accounts |
| [`view_function.rs`](crates/aptos-sdk/examples/view_function.rs) | Read-only view function calls |
| [`balance_checker.rs`](crates/aptos-sdk/examples/balance_checker.rs) | Check account balances |
| [`transaction_data.rs`](crates/aptos-sdk/examples/transaction_data.rs) | Working with transaction data |
| [`simulation.rs`](crates/aptos-sdk/examples/simulation.rs) | Simulate transactions before submission |

### Advanced Transactions

| Example | Description |
|---|---|
| [`entry_function.rs`](crates/aptos-sdk/examples/entry_function.rs) | Entry function transaction building |
| [`script_transaction.rs`](crates/aptos-sdk/examples/script_transaction.rs) | Script-based transactions |
| [`sponsored_transaction.rs`](crates/aptos-sdk/examples/sponsored_transaction.rs) | Fee payer (sponsored) transactions |
| [`multi_agent.rs`](crates/aptos-sdk/examples/multi_agent.rs) | Multi-signer transactions |
| [`transaction_waiting.rs`](crates/aptos-sdk/examples/transaction_waiting.rs) | Transaction waiting strategies |
| [`advanced_transactions.rs`](crates/aptos-sdk/examples/advanced_transactions.rs) | Complex transaction combinations |

### Account Types

| Example | Description |
|---|---|
| [`account_management.rs`](crates/aptos-sdk/examples/account_management.rs) | Account creation and management |
| [`multi_key_account.rs`](crates/aptos-sdk/examples/multi_key_account.rs) | Multi-key (mixed signature) accounts |
| [`multi_sig_account.rs`](crates/aptos-sdk/examples/multi_sig_account.rs) | MultiEd25519 threshold accounts |
| [`multisig_v2.rs`](crates/aptos-sdk/examples/multisig_v2.rs) | On-chain multisig (governance) accounts |

### Smart Contracts

| Example | Description |
|---|---|
| [`deploy_module.rs`](crates/aptos-sdk/examples/deploy_module.rs) | Deploy a Move module |
| [`call_contract.rs`](crates/aptos-sdk/examples/call_contract.rs) | Call contract entry functions |
| [`read_contract_state.rs`](crates/aptos-sdk/examples/read_contract_state.rs) | Read contract state |
| [`nft_operations.rs`](crates/aptos-sdk/examples/nft_operations.rs) | NFT / Digital Asset interactions |
| [`codegen.rs`](crates/aptos-sdk/examples/codegen.rs) | Contract binding generation |
| [`contract_bindings.rs`](crates/aptos-sdk/examples/contract_bindings.rs) | Using generated type-safe bindings |

### Indexer & Events

| Example | Description |
|---|---|
| [`indexer_queries.rs`](crates/aptos-sdk/examples/indexer_queries.rs) | Query the Aptos indexer via GraphQL |
| [`event_queries.rs`](crates/aptos-sdk/examples/event_queries.rs) | Query on-chain events |

Run any example with:

```bash
cargo run -p aptos-sdk --example transfer --features "ed25519,faucet"
```

## Development

### Building

```bash
cargo build -p aptos-sdk                    # Default features
cargo build -p aptos-sdk --all-features     # All features
cargo build -p aptos-sdk --release          # Release build
```

### Testing

```bash
cargo test -p aptos-sdk                     # Unit tests (default features)
cargo test -p aptos-sdk --all-features      # Unit tests (all features)

# E2E tests (requires a running localnet)
aptos node run-localnet --with-faucet
cargo test -p aptos-sdk --features "e2e" -- --ignored
```

### Linting & Formatting

```bash
cargo clippy -p aptos-sdk --all-features -- -D warnings
cargo fmt -- --check
```

## Architecture

```
crates/aptos-sdk/src/
├── aptos.rs            # Main entry point – combines all API capabilities
├── config.rs           # Network configuration (mainnet, testnet, devnet, localnet)
├── account/            # Account types: Ed25519, Secp256k1, Secp256r1, MultiKey, Keyless
├── api/                # REST fullnode, GraphQL indexer, faucet, and ANS clients
├── transaction/        # Builder, authenticator, sponsored & batched transactions
├── crypto/             # Signature schemes, hashing, and cryptographic traits
├── types/              # Addresses, Move types, hash values
└── codegen/            # Generate type-safe Rust bindings from Move ABIs
```

## Resources

- [Aptos Developer Documentation](https://aptos.dev)
- [API Reference (GitHub Pages)](https://aptos-labs.github.io/aptos-rust-sdk/aptos_sdk/index.html)
- [TypeScript SDK](https://github.com/aptos-labs/aptos-ts-sdk)

## License

Apache-2.0
