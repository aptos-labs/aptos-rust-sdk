# Aptos Rust SDK v2 - Development Plan

## Overview

This document outlines the comprehensive plan for building `aptos-sdk`, a user-friendly, idiomatic Rust SDK that provides feature parity with the `@aptos-labs/ts-sdk` TypeScript SDK.

### Goals

1. **Idiomatic Rust** - Follow Rust conventions and best practices
2. **Feature Parity** - Match TypeScript SDK functionality
3. **Modular Design** - Optional features via cargo feature flags
4. **Comprehensive Testing** - Unit, behavioral, and E2E tests
5. **Excellent Documentation** - Full rustdoc coverage with examples
6. **Broad Compatibility** - Support multiple platforms and Rust versions

---

## Phase 1: Project Foundation ✅

### 1.1 Project Structure
- [x] Create workspace member `crates/aptos-sdk`
- [x] Setup `Cargo.toml` with workspace dependencies
- [x] Define feature flags for optional functionality
- [x] Create module structure

### 1.2 Development Infrastructure
- [x] Setup formatting (`rustfmt.toml` with nightly features)
- [x] Setup linting (`clippy.toml` with strict rules)
- [x] Setup GitHub CI workflow for:
  - [x] Formatting checks
  - [x] Linting (multiple feature combinations)
  - [x] Testing (cross-platform: Ubuntu, macOS, Windows)
  - [x] Documentation generation
  - [x] GitHub Pages deployment
  - [x] MSRV (Minimum Supported Rust Version) check
  - [x] Security audit

---

## Phase 2: Core Types ✅

### 2.1 Primitive Types
- [x] `AccountAddress` - 32-byte account address
- [x] `HashValue` - 32-byte hash
- [x] `ChainId` - Network chain identifier
- [x] `U256` - 256-bit unsigned integer

### 2.2 Move Types
- [x] `TypeTag` - Move type representation
- [x] `MoveModuleId` - Module identifier (`address::name`)
- [x] `MoveStructTag` - Full struct type with generics
- [x] `MoveType` - Enum for all Move types

### 2.3 Serialization
- [x] BCS serialization support
- [x] JSON serialization for API responses
- [x] Hex encoding/decoding utilities

---

## Phase 3: Cryptography ✅

### 3.1 Hash Functions
- [x] SHA3-256 hashing
- [x] Domain-separated hashing (prefix system)
- [x] `CryptoHasher` derive macro support

### 3.2 Signature Schemes (Feature-Gated)

| Feature | Scheme | Status |
|---------|--------|--------|
| `ed25519` | Ed25519 | ✅ Complete |
| `secp256k1` | Secp256k1 (ECDSA) | ✅ Complete |
| `secp256r1` | Secp256r1/P-256 (WebAuthn) | ✅ Complete |
| `bls` | BLS12-381 | ✅ Complete |

### 3.3 Key Derivation
- [x] BIP-39 mnemonic support
- [x] BIP-44 HD derivation paths
- [x] Aptos derivation path (`m/44'/637'/0'/0'/0'`)

---

## Phase 4: Account Management ✅

### 4.1 Account Types
- [x] `Account` trait for signing
- [x] `Ed25519Account` - Single-key Ed25519
- [x] `Secp256k1Account` - Single-key Secp256k1
- [x] `AnyAccount` - Type-erased account wrapper
- [x] `AuthenticationKey` - Derived from public keys

### 4.2 Account Features
- [x] Generate random accounts
- [x] Import from private key (hex/bytes)
- [x] Import from mnemonic phrase
- [x] Address derivation (auth key → address)
- [x] Keyless accounts (OpenID Connect)

### 4.3 Multi-Signature Support ✅
- [x] `MultiEd25519Account` - M-of-N multisig (Ed25519 only)
- [x] `MultiKeyAccount` - M-of-N with mixed key types (Ed25519 + Secp256k1 + Secp256r1)

---

## Phase 5: Transaction Building ✅

### 5.1 Transaction Types
- [x] `RawTransaction` - Unsigned transaction
- [x] `SignedTransaction` - Signed with authenticator
- [x] `TransactionPayload` variants:
  - [x] `EntryFunction` - Call module functions
  - [x] `Script` - Execute bytecode
  - [x] `Multisig` - Multisig execution

### 5.2 Transaction Builder
- [x] `TransactionBuilder` - Fluent API
- [x] Automatic sequence number fetching
- [x] Gas estimation integration
- [x] Expiration time helpers

### 5.3 Authenticators
- [x] `TransactionAuthenticator` - Signature container
- [x] Single signer (Ed25519, Secp256k1, Secp256r1)
- [x] Multi-agent transactions
- [x] Fee payer (sponsored) transactions

---

## Phase 6: API Clients ✅

### 6.1 Fullnode REST Client
- [x] `AptosFullnodeClient` - REST API interactions
- [x] Account queries (resources, modules, balance)
- [x] Transaction queries (by hash, version)
- [x] Block queries (by height, version)
- [x] View function calls
- [x] Transaction submission
- [x] Transaction simulation
- [x] Gas estimation
- [x] Wait for transaction confirmation
- [x] Events queries

### 6.2 Faucet Client (Feature: `faucet`)
- [x] `AptosFaucetClient` - Testnet/devnet funding
- [x] Fund accounts with test tokens

### 6.3 Indexer Client (Feature: `indexer`)
- [x] `AptosIndexerClient` - GraphQL queries
- [x] Token/NFT queries
- [x] Fungible asset queries
- [x] Account activity queries

### 6.4 High-Level Client
- [x] `Aptos` - Unified client combining all APIs
- [x] `AptosConfig` - Network configuration
- [x] Convenience methods for common operations

---

## Phase 7: Network Configuration ✅

### 7.1 Built-in Networks
- [x] Mainnet configuration
- [x] Testnet configuration
- [x] Devnet configuration
- [x] Localnet configuration (localhost)
- [x] Custom network support

### 7.2 Configuration Options
- [x] Custom fullnode URL
- [x] Custom faucet URL
- [x] Custom indexer URL
- [x] Request timeout settings

---

## Phase 8: Error Handling ✅

### 8.1 Error Types
- [x] `AptosError` - Main SDK error type
- [x] Rich error context (source, location)
- [x] Conversion from external errors
- [x] HTTP status code handling

### 8.2 Result Types
- [x] `AptosResult<T>` - SDK result alias
- [x] Proper error propagation

---

## Phase 9: Testing Strategy ✅

### 9.1 Unit Tests ✅
- [x] Type serialization/deserialization
- [x] Cryptographic operations
- [x] Address computation
- [x] Transaction building

### 9.2 Behavioral Tests ✅
- [x] Account creation flows (Ed25519, MultiEd25519, MultiKey)
- [x] Transaction signing flows
- [x] Multi-agent scenarios
- [x] Fee payer scenarios
- [x] Cross-scheme crypto tests (Ed25519 + Secp256k1)
- [x] Multi-key distributed signing

### 9.3 E2E Tests Against Localnet ✅
- [x] Setup localnet using Aptos CLI (documented)
- [x] Account funding via faucet
- [x] Token transfers (single and multiple)
- [x] View function calls (timestamp, balance, account exists)
- [x] Transaction simulation
- [x] Transaction by hash lookup
- [x] Fee payer transactions
- [x] Multi-agent transactions
- [x] Multi-key account transactions

### 9.4 Integration Tests ✅
- [x] Ledger info queries
- [x] Resource queries
- [x] Error handling tests

---

## Phase 10: Examples ✅

### 10.1 Basic Examples
- [x] `transfer.rs` - Simple APT transfer
- [x] `view_function.rs` - Calling view functions

### 10.2 Advanced Examples
- [x] `call_contract.rs` - Entry function calls with arguments
- [x] `transaction_data.rs` - Parsing transaction responses
- [x] `read_contract_state.rs` - Reading on-chain state
- [x] `nft_operations.rs` - NFT/Digital Asset queries
- [x] `multi_agent.rs` - Multi-signer transactions
- [x] `sponsored_transaction.rs` - Fee payer transactions
- [x] `deploy_module.rs` - Module deployment guide
- [x] `multi_sig_account.rs` - Multi-Ed25519 account usage
- [x] `multi_key_account.rs` - Multi-Key account with mixed types

---

## Phase 11: Documentation ✅

### 11.1 Rustdoc
- [x] Module-level documentation
- [x] Function documentation with examples
- [x] Type documentation
- [x] Feature flag documentation

### 11.2 CI Integration
- [x] Doc build verification (with `-D warnings`)
- [x] GitHub Pages deployment
- [x] Examples documentation

---

## Phase 12: Feature Flags

### Current Feature Matrix

| Feature | Description | Default |
|---------|-------------|---------|
| `ed25519` | Ed25519 signatures | ✅ Yes |
| `secp256k1` | Secp256k1 ECDSA | ✅ Yes |
| `secp256r1` | P-256/WebAuthn support | ❌ No |
| `bls` | BLS12-381 signatures | ❌ No |
| `keyless` | OIDC-based keyless authentication | ❌ No |
| `faucet` | Faucet client | ❌ No |
| `indexer` | Indexer GraphQL client | ❌ No |
| `fuzzing` | Fuzzing utilities | ❌ No |
| `cli` | Code generation CLI tool | ❌ No |
| `macros` | Proc macros for type-safe bindings | ❌ No |
| `full` | Full SDK feature set | ❌ No |

### Feature Combinations
- Minimal: `--no-default-features --features ed25519`
- Standard: (default features)
- Full crypto: `--no-default-features --features "ed25519,secp256k1,secp256r1,bls"`
- Full stack: `--features full`

---

## Phase 13: Future Enhancements

### 13.1 TypeScript SDK Parity (Remaining)
- [ ] `InputGenerateTransactionPayloadData` builders
- [x] `InputEntryFunctionData` type-safe builders ✅
- [x] ANS (Aptos Names Service) integration ✅
- [x] Passkey/WebAuthn authentication (Secp256r1Account) ✅
- [x] Sponsored transaction helpers ✅

### 13.2 Advanced Features
- [x] Transaction batching ✅
- [x] Automatic retry with exponential backoff ✅
- [x] Connection pooling ✅
- [ ] Event subscription (WebSocket)
- [x] Local transaction simulation ✅

### 13.3 Developer Experience
- [ ] CLI tool for common operations
- [x] Code generation from ABI ✅
- [x] CLI tool for codegen (`aptos-codegen` binary) ✅
- [x] Type-safe contract bindings (proc macro) ✅
- [ ] Wallet adapter integration

---

## Architecture Decisions

### 1. No aptos-core Dependency
The SDK is independent of the `aptos-core` repository to:
- Reduce compile times
- Minimize dependency tree
- Allow faster iteration
- Support WASM targets (future)

### 2. Feature-Gated Cryptography
Cryptographic implementations are behind feature flags to:
- Reduce binary size when unused
- Allow platform-specific implementations
- Support no-std environments (future)

### 3. BCS as Primary Serialization
Using BCS (Binary Canonical Serialization) for:
- Efficient wire format
- Deterministic serialization
- Type-safe encoding/decoding

### 4. Builder Pattern for Transactions
Transaction building uses the builder pattern to:
- Provide fluent API
- Allow optional parameters
- Enable compile-time validation

### 5. Trait-Based Account Abstraction
The `Account` trait allows:
- Multiple signature scheme support
- Custom account implementations
- Easy testing with mock accounts

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-01-06 | Initial release |

---

## References

- [Aptos TypeScript SDK](https://github.com/aptos-labs/aptos-ts-sdk)
- [Aptos Developer Documentation](https://aptos.dev)
- [Move Language](https://move-language.github.io/move/)
- [BCS Specification](https://github.com/diem/bcs)
