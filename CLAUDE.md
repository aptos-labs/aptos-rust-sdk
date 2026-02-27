# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The Aptos Rust SDK is a user-friendly, idiomatic Rust SDK for interacting with the Aptos blockchain. It has feature parity with the TypeScript SDK and supports full blockchain interaction including account management, transaction building, and multiple signature schemes.

The project consists of two workspace crates:

- **aptos-sdk**: Main SDK crate with API clients, account management, transaction building, and cryptography
- **aptos-sdk-macros**: Procedural macros for type-safe contract bindings

## Development Commands

### Building

```bash
cargo build                                    # Build with default features (ed25519 + secp256k1)
cargo build -p aptos-sdk --all-features  # Build with all features
cargo build --release                          # Release build
```

### Testing

```bash
cargo test -p aptos-sdk                # Run unit tests (lib)
cargo test -p aptos-sdk --lib          # Same: run lib unit tests only
cargo test -p aptos-sdk --all-features # Test with all features
cargo test -p aptos-sdk --features "e2e" -- --ignored  # E2E tests (requires localnet)
```

**Full test** means: (1) all lib unit tests pass (`cargo test -p aptos-sdk --lib`), and optionally (2) E2E tests when a localnet is available. E2E tests are marked `#[ignore]` and require a running Aptos node. To run them:

- Start localnet first: `aptos node run-localnet --with-faucet`, or
- Use the script: `./scripts/run-e2e.sh` (starts localnet and runs E2E), or
- With an already-running node: `cargo test -p aptos-sdk --features "e2e,full" -- --ignored`

### Linting and Formatting

```bash
cargo clippy -p aptos-sdk --all-features -- -D warnings  # Strict linting
cargo fmt                                      # Format code
cargo fmt -- --check                           # Check formatting
```

### Running Examples

```bash
cargo run -p aptos-sdk --example transfer --features "ed25519,faucet"
cargo run -p aptos-sdk --example view_function --features "ed25519"
```

Examples are in `crates/aptos-sdk/examples/`.

## Code Architecture

### Main Entry Point

The SDK follows a client-centric design with `Aptos` as the main entry point:
- `Aptos` in `crates/aptos-sdk/src/aptos.rs` - Primary client combining all API capabilities
- `AptosConfig` in `crates/aptos-sdk/src/config.rs` - Network configuration (mainnet, testnet, devnet, localnet)

### Module Structure

- **`account/`** - Account management and key generation
  - `Ed25519Account`, `Secp256k1Account`, `Secp256r1Account` - Single-key accounts
  - `MultiKeyAccount` - Multi-key authentication
  - `KeylessAccount` - OIDC-based keyless authentication

- **`api/`** - API clients
  - `fullnode.rs` - REST API client for fullnode interactions
  - `indexer.rs` - GraphQL indexer client
  - `faucet.rs` - Faucet client for testnets
  - `ans.rs` - Aptos Names Service integration

- **`transaction/`** - Transaction building and signing
  - `builder.rs` - Fluent builder pattern for transactions
  - `authenticator.rs` - Transaction authentication
  - `sponsored.rs` - Fee payer (sponsored) transactions
  - `batch.rs` - Transaction batching

- **`crypto/`** - Cryptographic primitives
  - Multiple signature schemes: Ed25519, Secp256k1, Secp256r1, BLS12-381
  - `hash.rs` - Hashing utilities
  - `traits.rs` - Core cryptographic traits

- **`types/`** - Core Aptos types
  - `address.rs` - Account addresses
  - `move_types.rs` - Move type representations
  - `hash.rs` - Hash values

- **`codegen/`** - Code generation from Move ABIs
  - Generates type-safe Rust bindings from Move contract ABIs

### Key Patterns

- **Feature Flags**: Cryptographic schemes and optional features are behind feature flags (ed25519, secp256k1, mnemonic, secp256r1, bls, keyless, indexer, faucet)
- **Builder Pattern**: Transactions and configurations use fluent builder patterns
- **Async/Await**: Heavy use of `tokio` for async operations
- **Result Types**: Uses `AptosResult<T>` with `AptosError` throughout
- **BCS Serialization**: Uses `aptos-bcs` crate for Binary Canonical Serialization

### Important Files to Understand

- `crates/aptos-sdk/src/aptos.rs` - Main SDK client combining all capabilities
- `crates/aptos-sdk/src/config.rs` - Network configuration
- `crates/aptos-sdk/src/transaction/builder.rs` - Transaction builder
- `crates/aptos-sdk/src/account/mod.rs` - Account trait and implementations
- `crates/aptos-sdk/src/crypto/traits.rs` - Core cryptographic traits
- `crates/aptos-sdk/examples/transfer.rs` - Working example of basic transfer

## Rust Toolchain

- **Version**: 1.90+ (specified in `rust-toolchain.toml`)
- **Edition**: 2024
- **Components**: cargo, clippy, rustc, rust-docs, rust-std
- **Note**: Uses stable rustfmt for formatting

## Testing Strategy

- Unit tests are co-located with source code or in `src/tests/` directories.
- **Full test pass**: Run `cargo test -p aptos-sdk --lib`; all tests (including simulation and fullnode query-param tests) should pass.
- E2E tests require a running Aptos localnet (`aptos node run-localnet --with-faucet`). They are ignored by default; run with `-- --ignored` and the `e2e` feature, or use `./scripts/run-e2e.sh`.
- Behavioral tests in `crates/aptos-sdk/tests/behavioral/`.
- Property-based testing with `proptest` for crypto components (via `fuzzing` feature).
