# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The Aptos Rust SDK is a work-in-progress SDK for interacting with the Aptos blockchain. It currently supports crypto functionality but does not yet support transaction submission. The project consists of four main workspace crates:

- **aptos-rust-sdk**: Main SDK crate with REST API client functionality
- **aptos-rust-sdk-types**: Core types and data structures for Aptos API interactions  
- **aptos-crypto**: Cryptographic primitives (ed25519, BLS12-381, secp256k1, etc.)
- **aptos-crypto-derive**: Procedural macros for crypto implementations

## Development Commands

### Building
```bash
cargo build                    # Build all workspace members
cargo build --release         # Release build
cargo build -p aptos-rust-sdk  # Build specific crate
```

### Testing
```bash
cargo test                     # Run all tests
cargo test -p aptos-rust-sdk   # Test specific crate
cargo test --lib              # Run library tests only
```

### Linting and Formatting
```bash
cargo clippy                   # Run linter
cargo clippy --all-targets --all-features -- -D warnings  # Strict linting
cargo fmt                     # Format code (uses nightly rustfmt in CI)
```

### Examples
```bash
cargo run --example rest_api   # Run REST API example
# Examples are in crates/aptos-rust-sdk/examples/ and crates/examples/src/
```

## Code Architecture

### Client Architecture
The SDK follows a builder pattern for client construction:
- `AptosClientBuilder` in `crates/aptos-rust-sdk/src/client/builder.rs` creates configured clients
- `AptosFullnodeClient` in `crates/aptos-rust-sdk/src/client/rest_api.rs` handles REST API interactions
- Network configurations in `crates/aptos-rust-sdk/src/client/config.rs` (mainnet, testnet, devnet)

### Type System
The type system is centralized in `aptos-rust-sdk-types`:
- `api_types/` contains all Aptos-specific types (addresses, transactions, Move types, etc.)
- `serializable.rs` handles BCS (Binary Canonical Serialization) 
- Custom error handling through `error.rs` with `AptosResult<T>` type alias

### Cryptographic Layer
Comprehensive crypto support in `aptos-crypto`:
- Multiple signature schemes: Ed25519, BLS12-381, secp256k1, secp256r1
- Multi-signature support (`multi_ed25519.rs`)
- Poseidon hashing for keyless accounts (`poseidon_bn254/`)
- Asymmetric encryption (`asymmetric_encryption/`)

### Key Patterns
- **Workspace Dependencies**: All external dependencies are centralized in the root `Cargo.toml` workspace section
- **BCS Serialization**: Uses `aptos-bcs` crate instead of standard `bcs` for serialization
- **Async/Await**: Heavy use of `tokio` for async operations, especially in client code
- **Builder Pattern**: Clients and complex types use builder patterns for construction
- **Result Types**: Uses `AptosResult<T>` consistently throughout the SDK

## Important Files to Understand
- `crates/aptos-rust-sdk/src/client/rest_api.rs`: Core REST client implementation
- `crates/aptos-rust-sdk-types/src/api_types/transaction.rs`: Transaction type definitions
- `crates/aptos-rust-sdk-types/src/api_types/view.rs`: View function request/response types
- `crates/aptos-crypto/src/traits.rs`: Core cryptographic traits
- `crates/aptos-rust-sdk/examples/rest_api.rs`: Working example of SDK usage

## Rust Toolchain
- **Version**: 1.85 (specified in `rust-toolchain.toml`)
- **Components**: cargo, clippy, rustc, rust-docs, rust-std
- **Note**: Uses nightly rustfmt for formatting (not specified in toolchain)

## Testing Strategy
- Unit tests are located in `src/tests/` directories within each crate
- Property-based testing with `proptest` for crypto components
- Integration tests in `crates/aptos-rust-sdk/src/tests/`
- Test vectors for crypto validation in `crates/aptos-crypto/test_vectors/`