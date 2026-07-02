# Changelog

All notable changes to `aptos-sdk` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

## [0.6.0] - 2026-07-08

### Security
- Bumped transitive dependencies to clear `cargo audit` advisories:
  `quinn-proto` (RUSTSEC-2026-0185, remote memory exhaustion),
  `anyhow` (RUSTSEC-2026-0190, unsound `Error::downcast_mut()`), and
  `rand` 0.9.x (RUSTSEC-2026-0097, unsound with custom loggers).

### Added
- Object & digital-asset (NFT) write helpers for TypeScript-SDK parity:
  `InputEntryFunctionData::transfer_object` (`0x1::object::transfer_call`),
  `transfer_digital_asset`, `create_collection` (with a `CollectionConfig`
  builder), `mint_digital_asset`, `mint_soul_bound_digital_asset`,
  `burn_digital_asset`, `freeze_digital_asset_transfer`,
  `unfreeze_digital_asset_transfer`, plus the high-level
  `Aptos::transfer_object` and `Aptos::transfer_digital_asset`.
- Staking (delegation pool) payload builders:
  `InputEntryFunctionData::{delegation_add_stake, delegation_unlock,
  delegation_reactivate_stake, delegation_withdraw}`
  (`0x1::delegation_pool::*`).
- Account Abstraction (AIP-113) payload builders:
  `InputEntryFunctionData::{add_authentication_function,
  remove_authentication_function, remove_authenticator}`
  (`0x1::account_abstraction::*`).
- Authentication-key rotation: `account::RotationProofChallenge` (BCS layout
  pinned to `0x1::account::RotationProofChallenge`),
  `account::build_rotate_auth_key_payload` (signs the challenge with both the
  current and new keys), and the high-level `Aptos::rotate_auth_key`. Also
  added `Ed25519Account::with_address` to build a signer for an account whose
  on-chain address no longer matches its key (e.g. after a rotation).
- Fullnode table-item reads: `FullnodeClient::get_table_item(handle, key_type,
  value_type, key)` and the convenience wrapper `Aptos::get_table_item(...)`
  call `POST /tables/{handle}/item`, matching the TypeScript SDK's
  `getTableItem`. This unblocks reading Move `Table` state, which is not exposed
  as a normal account resource.
- Additional fullnode read endpoints for TypeScript-SDK parity:
  `FullnodeClient::get_transaction_by_version(version)`,
  `get_transactions(start, limit)` (list committed transactions),
  `get_account_transactions(address, start, limit)`, and
  `get_events_by_creation_number(address, creation_number, start, limit)`
  (`getAccountEventsByCreationNumber`).
- Fungible Asset (FA standard) transfers:
  `InputEntryFunctionData::transfer_fungible_asset(metadata, recipient, amount)`
  (payload builder for `0x1::primary_fungible_store::transfer`) and the
  high-level `Aptos::transfer_fungible_asset(sender, metadata, recipient,
  amount)`, the current-standard counterpart to `transfer_coin` and match for
  the TypeScript SDK's `transferFungibleAsset`.
- Chain-compatible **orderless transactions** (replay protection via a nonce
  instead of a sequence number). New `TransactionPayload::Payload` variant
  (BCS index 4) with `TransactionPayloadInner`, `TransactionExecutable`, and
  `TransactionExtraConfig`, plus `TransactionPayload::into_orderless(nonce)` and
  the `Aptos` helpers `build_orderless_transaction`,
  `sign_and_submit_orderless`, and `sign_submit_and_wait_orderless`. These
  produce an ordinary `RawTransaction` with `sequence_number = u64::MAX` and a
  `TransactionExtraConfig::V1 { replay_protection_nonce: Some(nonce), .. }`,
  matching aptos-core's on-wire format (pinned by a BCS wire-format test).
- Keyless (OIDC) documentation: expanded module-level docs on
  [`account::keyless`](https://docs.rs/aptos-sdk/latest/aptos_sdk/account/keyless/index.html),
  a `keyless_account` example, and [`Network::pepper_url`] /
  [`Network::prover_url`] helpers that return the default Aptos-hosted service
  endpoints (matching the TypeScript SDK). Added
  [`EphemeralKeyPairSnapshot`] with [`EphemeralKeyPair::to_snapshot`],
  [`EphemeralKeyPair::from_snapshot`], [`EphemeralKeyPair::save_to_file`], and
  [`EphemeralKeyPair::load_from_file`] for persisting ephemeral keys across an
  OAuth redirect. Corrected the outdated `KeylessAccount::new` snippet in
  `MIGRATION.md`.
- `api::AnsClient` is now a working Aptos Names Service client instead of a
  scaffold. It talks to the on-chain `router` module on mainnet / testnet /
  localnet (router contract addresses are built in; use
  `AnsClient::with_router_address` for devnet, custom, or privately deployed
  ANS). New surface:
  - Reads: `get_target_address(name)`, `get_owner_address(name)`,
    `get_primary_name(address)`, `get_expiration(name)` (epoch **seconds**),
    plus the convenience wrappers `lookup(name)` (errors with
    `AptosError::NotFound` when a name does not resolve) and
    `reverse_lookup(address)`. Previously `lookup` / `reverse_lookup` always
    returned `AptosError::Internal("...not yet implemented...")`.
  - Entry-function payload builders: `register_domain_payload`,
    `set_primary_name_payload`, `clear_primary_name_payload`,
    `set_target_address_payload`, `clear_target_address_payload`.
  - `api::ans::AnsName` -- parses and validates `.apt` names (domain +
    optional subdomain) per the ANS naming rules.
  - `Aptos::ans()` returns an `AnsClient` bound to the client's fullnode and
    network.
- `FullnodeClient::view_bcs_args(function, type_args, args)` -- calls a view
  function whose arguments are supplied as real BCS bytes (serialized as an
  on-wire `ViewRequest`, like the TypeScript SDK's `view`) and returns the
  JSON-decoded result values. Unlike `view_bcs`, this round-trips non-trivial
  Move argument types such as `Option<String>` correctly, not just addresses.
- `FullnodeClient::config()` -- exposes the `AptosConfig` backing the client.

### Deprecated
- `transaction::RawTransactionOrderless` and
  `transaction::SignedTransactionOrderless` are deprecated. They are a
  non-standard, homegrown orderless representation (32-byte nonce plus an
  `APTOS::RawTransactionOrderless` signing-domain separator) that the Aptos
  fullnode does **not** accept, so any transaction built with them would be
  rejected. Use the chain-compatible orderless support added in this release:
  `TransactionPayload::into_orderless` or the `Aptos::*_orderless` helpers.

## [0.5.0] - 2026-05-21

### Added
- `api::AnsClient` scaffold (`api/ans.rs`) -- exposes `lookup(name)` and
  `reverse_lookup(address)` method signatures so future ANS work has an
  obvious landing spot. Both methods currently return
  `AptosError::Internal("...not yet implemented...")` so callers fail
  fast rather than silently treating placeholder addresses as real.
  Reconciles the previous `AGENTS.md` reference to `api/ans.rs` with
  reality (the file did not exist before this commit).
- New behavioral test module `tests/behavioral/wire_format.rs` -- pins the
  exact BCS / signing-message byte layout for `RawTransaction` (sequenced
  full-hex pin and orderless prefix), `AccountAuthenticator::Ed25519`,
  `AccountAuthenticator::SingleKey(AnyPublicKey::Ed25519)`,
  `AccountAuthenticator::MultiEd25519` (variant 1, with bitmap layout),
  `AccountAuthenticator::MultiKey` (variant 3, mixed Ed25519+Secp256k1
  with BitVec bitmap), and a nested generic `TypeTag`. Inputs are fully
  deterministic (fixed Ed25519 / Secp256k1 keys, fixed expiration, fixed
  nonce) so the resulting bytes can be cross-checked against the
  TypeScript SDK constructed with identical inputs.
- `FullnodeClient::get_account_resources_paginated(address, start, limit)`
  and `FullnodeClient::get_account_modules_paginated(address, start, limit)`
  -- forward `start` / `limit` query parameters to the REST API so callers
  can page through accounts that publish more resources / modules than the
  default page size. `start` is `Option<&str>` so opaque cursor tokens
  surfaced through the `x-aptos-cursor` header (`AptosResponse::cursor`)
  round-trip losslessly. The previous one-shot `get_account_resources` /
  `get_account_modules` methods are preserved and delegate to the new
  pagination methods with `None` for both arguments.
- `account::DerivationPath` and `account::PathComponent` -- parse BIP-32 /
  BIP-44 derivation path strings (`m/44'/637'/0'/0/0`, lowercase `h` also
  accepted as a hardened marker) and expose
  `aptos_ed25519(address_index) -> AptosResult<Self>` /
  `aptos_secp256k1(address_index) -> AptosResult<Self>` builders for the
  canonical Aptos paths. `address_index` lives in the BIP-44 5th
  component to match the pre-existing `Mnemonic::derive_ed25519_key`
  behavior; callers needing TS-SDK-style account-level indexing must
  build the path explicitly via `DerivationPath::from_str`.
  `PathComponent` fields are private; construct via
  `PathComponent::try_new(index, hardened)` which rejects `index >= 2^31`
  (the BIP-32 hardened bit).
- `Mnemonic::derive_secp256k1_key(index)` — derives an Aptos Secp256k1 private
  key via BIP-32 along the canonical Aptos path. Cross-validated against the
  Bitcoin reference vector for the `abandon × 11 about` mnemonic at
  `m/44'/0'/0'/0/0` so hardened + non-hardened child derivation are both
  exercised by tests.
- `Mnemonic::derive_ed25519_key_at_path(&path)` and
  `Mnemonic::derive_secp256k1_key_at_path(&path)` — derive at a caller-supplied
  derivation path. Ed25519 paths must be fully hardened (SLIP-0010) and a
  non-hardened component returns `AptosError::KeyDerivation` instead of
  producing an invalid key.
- `FullnodeClient::simulate_transaction_with_options` — simulate with optional query parameters (`estimate_max_gas_amount`, `estimate_gas_unit_price`, `estimate_prioritized_gas_unit_price`). Existing `simulate_transaction` is unchanged (single-arg) and delegates to the new method with `None` for backward compatibility.
- `Aptos::simulate_signed_with_options`, plus option-aware multi-signer simulation (`Aptos::simulate_multi_agent`, `Aptos::simulate_fee_payer`) for consistent high-level simulation APIs while preserving no-options usage.
- `build_simulation_signed_multi_agent` and `build_simulation_signed_fee_payer` for constructing simulation-only signed transactions using `NoAccountAuthenticator` placeholders.
- `SignedTransaction::for_simulate_endpoint`, `TransactionAuthenticator::for_simulate_endpoint`, and `AccountAuthenticator::for_simulate_endpoint` — strip signing material for `/transactions/simulate` when serializing manually; `FullnodeClient::simulate_transaction` / `simulate_transaction_with_options` apply the same transform automatically.
- `AnyPublicKey::from_bcs_bytes` and `AnySignature::from_bcs_bytes` — parse raw BCS `AnyPublicKey` / `AnySignature` bytes for `SingleKey` validation, `AccountAuthenticator::verify`, and related builder paths.
- `WebAuthnAccount` for on-chain `secp256r1` transaction signing. Wraps a
  `Secp256r1PrivateKey` and emits the on-chain `AnySignature::WebAuthn`
  envelope (synthetic `PartialAuthenticatorAssertionResponse` carrying
  `SHA3-256(signing_message)` as the base64url challenge, a configurable
  `rp_id` / `origin`, and a 37-byte `authenticatorData`). End-to-end
  verified against devnet via `e2e_webauthn_account_transfer`.
- `DEFAULT_WEBAUTHN_RP_ID` / `DEFAULT_WEBAUTHN_ORIGIN` constants and
  `WebAuthnAccount::from_parts(...)` for callers that need to pin the
  relying-party identity for off-chain auditing.
- `Secp256k1PublicKey::to_raw_bytes()` and
  `Secp256r1PublicKey::to_raw_bytes()` return the 64-byte raw `(X || Y)`
  encoding that `aptos-stdlib::secp256k1::ecdsa_raw_public_key_from_64_bytes`
  expects (in addition to the existing 65-byte SEC1 uncompressed form).
- New end-to-end tests in `tests/e2e/`: real transfer flows for
  `Ed25519SingleKeyAccount`, `Secp256k1Account`, `WebAuthnAccount`,
  `MultiEd25519Account`, and `MultiKeyAccount`; gas-estimation tests;
  sponsored-builder transfer; sequence-number progression; batch
  submission; and an `e2e_account_not_found` regression test that
  pins the AIP-42 implicit-account contract.
- New regression unit tests pin the on-chain BCS wire layout of
  `TransactionAuthenticator::SingleSender(AccountAuthenticator::SingleKey)`
  and `AccountAuthenticator::MultiKey`, plus the per-scheme behaviour of
  the zero-signed authenticator built by `Aptos::simulate`.

### Changed
- **MSRV bumped from 1.90 to 1.95**. Both `rust-toolchain.toml` and the
  workspace `rust-version = "1.95.0"` field in the root `Cargo.toml`
  now require Rust 1.95+; every CI job (Test, Lint, MSRV, Format,
  Documentation, Security Audit, Code Coverage) is pinned to 1.95.
  Downstream consumers building against the SDK need at least Rust
  1.95.0 -- released 2026-04-14, well under the typical "last six
  months" support window.
- **Cargo manifest modernised.** Switched from `resolver = "2"` to
  `resolver = "3"` (the recommended resolver for edition-2024 packages,
  with tighter `--no-default-features` unification). Lint configuration
  moved into `[workspace.lints]` in the root `Cargo.toml` (stabilised
  in Rust 1.74); both member crates now declare `[lints] workspace = true`.
  The previous per-crate `#![warn(...)]` / `#![allow(...)]` block in
  `crates/aptos-sdk/src/lib.rs` has been retired -- workspace lints
  cover the same surface and additionally apply to examples, tests,
  and the proc-macros crate.
- Increased default max gas amount from 200,000 to 2,000,000 (10x).
- `Aptos::fund_account` now keeps issuing faucet requests until the
  on-chain balance has grown by the requested amount (max 16 attempts),
  so devnet -- whose `/mint` endpoint caps each response at 1 APT --
  actually delivers the requested amount instead of silently
  short-funding the caller.
- `Aptos::simulate` and `Aptos::estimate_gas` now build a zero-signed
  `SignedTransaction` whose authenticator shape matches the account's
  signature scheme (Ed25519, MultiEd25519, SingleKey, MultiKey). The
  simulation endpoint rejects valid signatures since it is a
  gas-estimation tool, not an execution tool; previously the helper only
  worked for `Ed25519Account`.
- `Network::Devnet.chain_id()` now returns `0` ("unknown") instead of a
  hardcoded value. The `Aptos` client treats `0` as a signal to fetch
  the live chain ID from the configured fullnode via
  `Aptos::ensure_chain_id`, so devnet transactions automatically pick up
  the correct chain ID across devnet resets.
- All `examples/*.rs` programs switched from `AptosConfig::testnet()`
  to `AptosConfig::devnet()`. The Aptos testnet faucet now requires a
  JWT-authenticated API key (`x-is-jwt: true`) and rejects
  unauthenticated requests with HTTP 500.
- `Secp256k1PublicKey::from_bytes` and `Secp256r1PublicKey::from_bytes`
  now also accept the 64-byte raw `(X || Y)` encoding (in addition to
  the SEC1 compressed/uncompressed forms).
- Published crate excludes precompiled Move bytecode under `tests/e2e/move/**/*.mv`.

### Deprecated
- `Secp256r1Account` for on-chain transaction signing. The on-chain
  `AnySignature` variant 2 is `WebAuthn` (a
  `PartialAuthenticatorAssertionResponse`), not bare `Secp256r1Ecdsa`,
  so transactions signed by `Secp256r1Account` are rejected by every
  Aptos validator with a deserialization-level error. Use
  `WebAuthnAccount` instead. `Secp256r1Account` is retained for
  off-chain P-256 sign/verify and as a public-key source for
  `MultiKeyAccount`.

### Fixed
- **Simulate endpoint** — `FullnodeClient::simulate_transaction` / `simulate_transaction_with_options` now serialize `signed_txn.for_simulate_endpoint()` so authenticators are rewritten client-side (e.g. `SingleKey` → `NoAccountAuthenticator`, legacy `Ed25519` signatures zeroed) before calling `/transactions/simulate`, avoiding the fullnode 400 "Simulated transactions must not have a valid signature" when passing a normally signed transaction to `Aptos::simulate_signed` or the raw client.
- BCS wire format of `AccountAuthenticator::{SingleKey, MultiKey, Keyless}`.
  Previously the derived `Serialize` impl added a ULEB128 length prefix
  in front of each pre-BCS-encoded inner field, so the chain's
  `bcs::from_bytes::<MultiKeyAuthenticator>` rejected the bytes with
  `DeserializationError`. The hand-rolled `Serialize` now emits the
  `AnyPublicKey` / `AnySignature` payloads inline after the variant tag,
  matching the on-chain `SingleKeyAuthenticator` / `MultiKeyAuthenticator`
  struct layout.
- `Secp256k1PrivateKey::sign` no longer double-hashes. The previous
  implementation pre-hashed the message with SHA-256 and then called
  `k256::ecdsa::SigningKey::sign`, which *also* applies SHA-256
  internally, producing a signature over `SHA-256(SHA-256(msg))`. Sign
  and verify both double-hashed so unit tests passed, but the chain's
  `aptos-crypto::secp256k1_ecdsa::Signature::verify` hashes the
  signing message with **SHA-3-256** -- so every transaction was rejected
  with `INVALID_SIGNATURE`. `sign` and `verify` now compute the SHA-3-256
  digest themselves and route through `signature::hazmat::PrehashSigner` /
  `PrehashVerifier`.
- `Ed25519SingleKeyAccount` / `Secp256k1Account` / `Secp256r1Account` /
  `WebAuthnAccount` -- `Account::sign` now wraps the produced signature
  in the BCS-encoded `AnySignature::*` framing expected by the on-chain
  `SingleKeyAuthenticator.signature` field. Previously the bare 64-byte
  signature was emitted, which the chain rejected.
- `MultiEd25519Signature` and `MultiKeySignature` signer-bitmaps are now
  MSB-first within each byte (matches `aptos-crypto::multi_ed25519::bitmap_set_bit`
  -- `128u8 >> bucket_pos` -- and `aptos_bitvec::BitVec::set`). The SDK
  was LSB-first, so the chain looked up the wrong public key for each
  signature and rejected every multi-signature transaction with
  `INVALID_SIGNATURE`.
- `MultiKeySignature::to_bytes` now emits the BCS `BitVec` ULEB128 length
  prefix in front of the 4-byte bitmap, matching the on-chain
  `BCS((Vec<AnySignature>, BitVec))` layout. Previously the bitmap was
  appended raw and the chain's deserializer rejected the bytes.
- `Secp256k1PublicKey::to_address` and `Secp256r1PublicKey::to_address`
  now derive the auth key from 65-byte SEC1 uncompressed encoding
  (matching the chain's canonicalisation through
  `libsecp256k1::PublicKey::serialize()` / `p256::ecdsa::VerifyingKey::to_sec1_bytes()`).
  Previously the SDK and the chain disagreed on the address for the same
  key, so a SDK-derived address could not actually receive funds the
  chain would let the same key spend.
- Devnet end-to-end submission. The combination of the
  `fund_account` looping, the devnet chain-ID auto-resolve, the
  zero-signed simulator, the deprecation of `Secp256r1Account`, and the
  on-wire fixes above means every account type the SDK can sign for
  (Ed25519, Ed25519SingleKey, Secp256k1, MultiEd25519, MultiKey, WebAuthn)
  now successfully submits transactions on devnet.
- **Script payload BCS** — Reordered `ScriptArgument` enum variants to match chain/TS SDK (`ScriptTransactionArgumentVariants`), and added `Serialized` plus signed-integer variants (`I8`–`I256`). Script transactions now serialize correctly and can be submitted successfully.
- `SignedTransaction::verify_signature` now rejects `MultiAgent` / `FeePayer` authenticators when `secondary_signer_addresses.len() != secondary_signers.len()` (previous `zip` truncation could hide missing or extra signers).
- no-default-features feature-combination compatibility: verification/parsing paths are now correctly gated so `ed25519`-disabled builds do not reference unavailable Ed25519 types.

### Security
- New 2026-05 security review (`SECURITY_REVIEW_2026-05.md`) confirms
  every Feb-2026 finding remains remediated. Three new informational /
  low-severity items are tracked (S-23 example prints private key,
  S-24 fuzz targets still missing, S-25 `secp256r1` `S == ORDER_HALF`
  regression test). The audit's correctness fixes either preserve or
  improve the prior security posture (e.g. `secp256k1` SHA-3-256
  alignment improves domain separation from other ECDSA-over-SHA-256
  protocols; `Aptos::simulate` no longer routes private-key material
  through the gas-estimation path).
- BIP-32 secp256k1 derivation now zeroizes the per-step HMAC input buffer
  for hardened components, which transiently contains the parent private
  key (`0x00 || ser_256(k_par) || ser_32(i)`). Previously that buffer
  was dropped without scrubbing, leaving secret material on the heap
  until reused.
- Documented the deliberate deviation from BIP-32's "advance to index
  i+1" retry rule when an intermediate `I_L` is `>= n` or the derived
  child scalar is `0`. We return an error instead of silently producing
  a key at a different path; the failure probability per component is
  ~2^-127.
- Hardened MultiKey decoding: `MultiKeyPublicKey`, `MultiKeySignature`, `AnyPublicKey`, and `AnySignature` now enforce bounded element counts and exact key/signature length checks during deserialization to reduce memory-amplification DoS risk.
- Hardened authenticator address checks: multi-agent and fee-payer verification now enforces sender, secondary signer, and fee payer derived-address consistency.
- Keyless variants continue to be rejected from MultiKey-only decoding paths (`AnyPublicKey` / `AnySignature`) where they are not valid inputs.
- Patched five RUSTSEC advisories surfaced by `cargo audit`:
  - `aws-lc-sys < 0.39.0`: RUSTSEC-2026-0044 (X.509 name-constraints
    bypass via wildcard / Unicode CN) and RUSTSEC-2026-0048 (CRL
    distribution-point scope-check logic error). Bumped to 0.41.0.
  - `rustls-webpki < 0.103.13`: RUSTSEC-2026-0098 (URI-name name
    constraints incorrectly accepted), RUSTSEC-2026-0099 (name
    constraints accepted for wildcard certificates), and
    RUSTSEC-2026-0104 (reachable panic in CRL parsing). Bumped to
    0.103.13.

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

[0.6.0]: https://github.com/aptos-labs/aptos-rust-sdk/releases/tag/sdk-v0.6.0
[0.5.0]: https://github.com/aptos-labs/aptos-rust-sdk/releases/tag/sdk-v0.5.0
[0.4.1]: https://github.com/aptos-labs/aptos-rust-sdk/releases/tag/sdk-v0.4.1
[0.4.0]: https://github.com/aptos-labs/aptos-rust-sdk/releases/tag/sdk-v0.4.0
[0.1.0]: https://github.com/aptos-labs/aptos-rust-sdk/releases/tag/sdk-v0.1.0
