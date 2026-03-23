# Changelog

All notable changes to `aptos-sdk` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

### Added
- `FullnodeClient::simulate_transaction_with_options` — simulate with optional query parameters (`estimate_max_gas_amount`, `estimate_gas_unit_price`, `estimate_prioritized_gas_unit_price`). Existing `simulate_transaction` is unchanged (single-arg) and delegates to the new method with `None` for backward compatibility.
- `Aptos::simulate_signed_with_options`, plus option-aware multi-signer simulation flows (`Aptos::simulate_multi_agent`, `Aptos::simulate_fee_payer`) for consistent high-level simulation APIs while preserving no-options usage.
- Simulation helper builders: `build_simulation_signed_multi_agent` and `build_simulation_signed_fee_payer` for constructing simulation-only signed transactions using `NoAccountAuthenticator` placeholders.

### Changed
- `FullnodeClient::simulate_transaction` — restored to a single-argument API `(signed_txn)`; use `simulate_transaction_with_options` when passing options.
- `TransactionAuthenticator` / `AccountAuthenticator` single-key and multi-key BCS handling aligned with `aptos-core` and TS SDK encoding expectations.
- Local ECDSA (`secp256k1` / `secp256r1`) signing and verification behavior aligned with MultiKey verification paths for cross-scheme consistency.
- Increased default max gas amount from 200,000 to 2,000,000 (10x)
- Packaging behavior: published crate now excludes precompiled Move bytecode files under `tests/e2e/move/**/*.mv`.

### Fixed
- **Script payload BCS** — Reordered `ScriptArgument` enum variants to match chain/TS SDK (`ScriptTransactionArgumentVariants`), and added `Serialized` plus signed-integer variants (`I8`–`I256`). Script transactions now serialize correctly and can be submitted successfully.
- `SignedTransaction::verify_signature` now rejects `MultiAgent` / `FeePayer` authenticators when `secondary_signer_addresses.len() != secondary_signers.len()` (previous `zip` truncation could hide missing or extra signers).
- no-default-features feature-combination compatibility: verification/parsing paths are now correctly gated so `ed25519`-disabled builds do not reference unavailable Ed25519 types.

### Security
- Hardened MultiKey decoding: `MultiKeyPublicKey`, `MultiKeySignature`, `AnyPublicKey`, and `AnySignature` now enforce bounded element counts and exact key/signature length checks during deserialization to reduce memory-amplification DoS risk.
- Hardened authenticator address checks: multi-agent and fee-payer verification now enforces sender, secondary signer, and fee payer derived-address consistency.
- Keyless variants continue to be rejected from MultiKey-only decoding paths (`AnyPublicKey` / `AnySignature`) where they are not valid inputs.

## [0.4.1] - 2026-03-04

### Changed
- Upgraded `aws-lc-sys` from 0.37.1 to 0.38.0 (pinned as direct dependency)
- Upgraded `aws-lc-rs` from 1.16.0 to 1.16.1

## [0.4.0] - 2026-02-25

### Security
- Comprehensive security audit remediating 21 findings across the SDK
- Second-pass audit fixes across crypto, keyless, and API client modules
- Enforced low-S normalization for ECDSA (secp256k1/secp256r1) signatures to match aptos-core
- Hardened keyless account JWT verification
- Improved input validation across API clients and codegen

### Changed
- Upgraded `reqwest` from v0.12 to v0.13
- Replaced `hex` crate with `const-hex` for improved performance
- Removed `async-trait` dependency in favor of native async trait support
- Audited and cleaned up dependency tree
- Bumped `keccak` from 0.1.5 to 0.1.6
- Improved dependency feature selection for reduced compile times
- Configured `docs.rs` metadata for release builds

### Fixed
- Resolved rustdoc warnings breaking CI documentation check
- Fixed clippy `needless_borrows_for_generic_args` warnings

### Performance
- Reduced allocations and lock overhead in hot paths

### Removed
- Unnecessary feature-flags

## [0.1.0] - 2026-01-06

### Added

#### Core Types
- `AccountAddress` - 32-byte account addresses with hex parsing/formatting
- `ChainId` - Network chain identifiers (mainnet, testnet, devnet, custom)
- `HashValue` - 32-byte hashes with SHA3-256 computation
- `TypeTag` - Move type representations for generics

#### Cryptography (Feature-Gated)
- **Ed25519** (`ed25519` feature, default): Standard Ed25519 signatures
- **Secp256k1** (`secp256k1` feature, default): Bitcoin-style ECDSA signatures
- **Secp256r1** (`secp256r1` feature): P-256/WebAuthn/Passkey support
- **BLS12-381** (`bls` feature): Aggregate signature support
- Multi-Ed25519 and Multi-Key support for M-of-N multisig

#### Account Management
- `Ed25519Account` - Single-key Ed25519 accounts
- `Secp256k1Account` - Single-key Secp256k1 accounts
- `Secp256r1Account` - Passkey/WebAuthn accounts
- `MultiEd25519Account` - M-of-N Ed25519 multisig
- `MultiKeyAccount` - M-of-N mixed key types
- `KeylessAccount` (`keyless` feature) - OIDC-based authentication
- BIP-39 mnemonic phrase support
- BIP-44 HD derivation paths

#### Transaction Building
- `TransactionBuilder` - Fluent API for constructing transactions
- `EntryFunction` payloads for Move entry function calls
- Multi-agent transaction support
- Fee payer (sponsored) transaction support
- `InputEntryFunctionData` - Type-safe entry function builders

#### API Clients
- `FullnodeClient` - REST API for blockchain interaction
- `FaucetClient` (`faucet` feature) - Testnet account funding
- `IndexerClient` (`indexer` feature) - GraphQL queries for indexed data
- `AnsClient` - Aptos Names Service integration

#### High-Level Client
- `Aptos` - Unified client combining all APIs
- `AptosConfig` - Network configuration with presets
- Automatic retry with exponential backoff
- Connection pooling for improved performance
- Local transaction simulation

#### Transaction Features
- Transaction batching for multiple transactions
- Sponsored transaction helpers
- Gas estimation with safety margins

#### Code Generation
- `ModuleGenerator` - Generate Rust code from Move ABIs
- `MoveSourceParser` - Extract parameter names from Move source
- Type-safe contract bindings via proc macros (`macros` feature)
- CLI tool for code generation (`cli` feature)

#### Developer Experience
- Comprehensive Rustdoc documentation
- Working examples for common use cases
- Unit, behavioral, and E2E test suites
- GitHub Actions CI/CD pipeline
- Code coverage with tarpaulin

### Security
- Private keys are zeroized on drop
- No unsafe code (`#![forbid(unsafe_code)]`)
- Feature-gated cryptographic implementations

### Notes
- This SDK is independent of `aptos-core` for faster compilation
- Minimum Supported Rust Version (MSRV): 1.90

[0.4.0]: https://github.com/aptos-labs/aptos-rust-sdk/releases/tag/sdk-v0.4.0
[0.1.0]: https://github.com/aptos-labs/aptos-rust-sdk/releases/tag/sdk-v0.1.0
