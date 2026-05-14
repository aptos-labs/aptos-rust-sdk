# AGENTS.md

Guidance for AI coding agents (Claude, Cursor, Copilot, OpenAI Codex,
etc.) working on this repository. This is the canonical agent-instruction
file; `CLAUDE.md` is kept as a thin pointer to this file for backward
compatibility.

## Project Overview

The Aptos Rust SDK is a user-friendly, idiomatic Rust SDK for interacting
with the Aptos blockchain. It has feature parity with the TypeScript SDK
and supports full blockchain interaction including account management,
transaction building, and multiple signature schemes.

The project consists of two workspace crates:

- **aptos-sdk**: Main SDK crate with API clients, account management,
  transaction building, and cryptography.
- **aptos-sdk-macros**: Procedural macros for type-safe contract
  bindings.

## Required workflow for every code change

When you complete a code change, run **all** of these before pushing or
opening a PR. If any of them fails, fix it before proceeding -- CI runs
every one and will reject the PR otherwise.

```bash
cargo fmt
cargo fmt -- --check                                                 # idempotency check
cargo clippy -p aptos-sdk --all-targets --all-features -- -D warnings
cargo clippy -p aptos-sdk --all-targets -- -D warnings               # default features
cargo clippy -p aptos-sdk --no-default-features -- -D warnings
cargo test -p aptos-sdk --all-features
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc \
    -p aptos-sdk --all-features --no-deps                            # docs.rs parity
```

The lint job in CI runs the three clippy variants above, not just
`--all-features`. A clippy error that only fires under `--all-targets`
or under `--no-default-features` (e.g. unused private functions reachable
only behind a feature flag) is a real failure -- always run all three
locally.

The documentation job uses **nightly** with `--cfg docsrs` and treats
warnings as errors, so broken intra-doc links and `clippy::doc_markdown`
patterns that pass under stable can still break CI on docs.

## ⚠️ Updating the changelog

**Any user-visible change** (public API addition / change / deprecation /
removal, behaviour change, security fix, bug fix that affects callers,
new feature) **MUST** add an entry to the relevant CHANGELOG before the
PR is opened. The repo has two changelogs:

- `crates/aptos-sdk/CHANGELOG.md` -- the main SDK crate.
- `crates/aptos-sdk-macros/CHANGELOG.md` -- the proc-macros crate.

Add entries under the `## [unreleased]` heading, grouped by
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) categories:

- **Added** -- new features or public API surface.
- **Changed** -- behaviour or surface that already existed but now acts
  differently (be explicit about why -- a one-line "now does X" is
  rarely enough for an SDK with this many subtle on-wire contracts).
- **Deprecated** -- API that still works but should not be used in new
  code. Include the replacement.
- **Removed** -- API that no longer compiles.
- **Fixed** -- regressions or correctness fixes. **Be specific about
  the symptom callers would have seen** (e.g. "transactions rejected
  with INVALID_SIGNATURE" rather than "fixed signature bug") so users
  can match their incident logs against the entry.
- **Security** -- anything that could change the security posture of
  the SDK or downstream applications. Link to
  `SECURITY_REVIEW_*.md` / `SECURITY_AUDIT.md` if the change is large.

Pure refactors with no observable effect (renaming a private helper,
reformatting, internal doc improvements) do **not** need a changelog
entry. Internal test-only changes do **not** need one either.

If your change touches the proc-macros crate, update *both* changelogs
when the SDK-side surface visible to callers also changes; otherwise
update only the macros changelog.

CI does not currently enforce a changelog entry, but a reviewer will
block the PR if a user-visible change lacks one. Treat the changelog as
part of the change itself.

## Development Commands

### Building

```bash
cargo build                              # default features (ed25519 + secp256k1 + ...)
cargo build -p aptos-sdk --all-features  # all features
cargo build --release                    # release build
```

### Testing

```bash
cargo test -p aptos-sdk                                                   # unit tests
cargo test -p aptos-sdk --all-features                                    # all features
APTOS_LOCAL_NODE_URL=https://fullnode.devnet.aptoslabs.com/v1 \
APTOS_LOCAL_FAUCET_URL=https://faucet.devnet.aptoslabs.com         \
    cargo test -p aptos-sdk --features "e2e,full" -- --ignored            # E2E on devnet
```

The end-to-end tests in `tests/e2e/` are gated behind the `e2e` feature
flag and `#[ignore]`d so a normal `cargo test` doesn't try to reach the
network. Devnet's faucet is rate-limited per IP and will return
`429 Request rejected by 1 checkers` if you run the full e2e suite in
quick succession -- run individual tests with cooldowns when iterating
against the live network. The SDK's faucet client already retries with
backoff for transient `429`s.

For deterministic offline tests, set `APTOS_LOCAL_NODE_URL` to a
localnet running on `127.0.0.1:8080` (the default in
`AptosConfig::local()`).

### Linting and Formatting

```bash
cargo fmt                                                  # format code
cargo fmt -- --check                                       # check formatting
cargo clippy -p aptos-sdk --all-features -- -D warnings    # strict linting (single variant)
```

But before pushing, run the three-variant clippy from the
"Required workflow" section above.

### Running Examples

All examples target devnet (the testnet faucet now requires a JWT API
key and rejects unauthenticated requests):

```bash
cargo run -p aptos-sdk --example transfer       --features "ed25519,faucet"
cargo run -p aptos-sdk --example view_function  --features "ed25519"
```

Examples are in `crates/aptos-sdk/examples/` and are individually feature-gated
in `crates/aptos-sdk/Cargo.toml`.

## Code Architecture

### Main Entry Point

The SDK follows a client-centric design with `Aptos` as the main entry
point:

- `Aptos` in `crates/aptos-sdk/src/aptos.rs` -- primary client combining
  all API capabilities.
- `AptosConfig` in `crates/aptos-sdk/src/config.rs` -- network
  configuration (mainnet, testnet, devnet, localnet, custom).

### Module Structure

- **`account/`** -- account management and key generation.
  - `Ed25519Account`, `Ed25519SingleKeyAccount`, `Secp256k1Account`,
    `Secp256r1Account` (deprecated for transactions; off-chain only),
    `WebAuthnAccount` (on-chain `secp256r1` via the WebAuthn envelope).
  - `MultiEd25519Account` for legacy M-of-N Ed25519.
  - `MultiKeyAccount` for M-of-N with mixed key types.
  - `KeylessAccount` for OIDC-based keyless authentication.
- **`api/`** -- API clients.
  - `fullnode.rs` -- REST API client for fullnode interactions.
  - `indexer.rs` -- GraphQL indexer client.
  - `faucet.rs` -- faucet client for testnets / devnet.
  - `ans.rs` -- Aptos Names Service integration.
- **`transaction/`** -- transaction building and signing.
  - `builder.rs` -- fluent builder pattern.
  - `authenticator.rs` -- `TransactionAuthenticator` and
    `AccountAuthenticator`. The SingleKey / MultiKey / Keyless variants
    have a hand-rolled `Serialize` impl that matches the on-chain BCS
    layout; do **not** revert to derive without re-pinning the
    wire-format tests.
  - `sponsored.rs` -- fee payer (sponsored) transactions.
  - `batch.rs` -- transaction batching.
- **`crypto/`** -- cryptographic primitives.
  - Multiple signature schemes: Ed25519, Secp256k1, Secp256r1, BLS12-381.
  - Signing always normalises to low-S for ECDSA.
  - `secp256k1` hashing uses SHA-3-256 to match `aptos-crypto::secp256k1_ecdsa`.
- **`types/`** -- core Aptos types (`AccountAddress`, `ChainId`,
  `HashValue`, `TypeTag`, …).
- **`codegen/`** -- code generation from Move ABIs (proc macro + library).

### Key Patterns

- **Feature flags**: cryptographic schemes and optional features sit
  behind feature flags (`ed25519`, `secp256k1`, `secp256r1`, `bls`,
  `keyless`, `mnemonic`, `indexer`, `faucet`, `macros`, `cli`, ...).
  Anything that is only reachable behind a feature flag must be gated
  on the same flag, or `--no-default-features` clippy will flag it as
  dead code.
- **Builder pattern**: transactions, configurations, and entry-function
  inputs use fluent builders.
- **Async / await**: heavy use of `tokio` for all network I/O.
- **Result types**: `AptosResult<T>` (aliased to `Result<T, AptosError>`)
  is used throughout. Prefer `?` propagation; only use `.unwrap()` /
  `.expect()` in tests or for invariants that genuinely cannot fail.
- **BCS serialization**: the `aptos-bcs` crate is the canonical
  serializer for on-wire transactions and signatures. **Wire-format
  changes touching `AccountAuthenticator`, `TransactionAuthenticator`,
  `MultiEd25519Signature`, or `MultiKeySignature` MUST add a unit test
  that pins the exact byte layout** so a derive-vs-hand-roll regression
  is caught without devnet access.

### Important files to understand

- `crates/aptos-sdk/src/aptos.rs` -- main SDK client combining all
  capabilities.
- `crates/aptos-sdk/src/config.rs` -- network configuration. Note that
  `Network::Devnet.chain_id()` returns `0` so the live chain ID is
  resolved on first use; don't hardcode devnet IDs.
- `crates/aptos-sdk/src/transaction/builder.rs` -- transaction builder.
- `crates/aptos-sdk/src/transaction/authenticator.rs` -- authenticator
  types with the carefully hand-rolled `Serialize` impl.
- `crates/aptos-sdk/src/account/mod.rs` -- `Account` trait and
  implementations.
- `crates/aptos-sdk/src/account/webauthn.rs` -- WebAuthn / Passkey
  account (the supported path for on-chain `secp256r1` signing).
- `crates/aptos-sdk/src/crypto/traits.rs` -- core cryptographic traits.
- `crates/aptos-sdk/examples/transfer.rs` -- working example of a basic
  transfer.

## Rust Toolchain

- **Version**: 1.90+ (specified in `rust-toolchain.toml`).
- **Edition**: 2024.
- **Components**: cargo, clippy, rustc, rust-docs, rust-std.
- **Note**: uses stable rustfmt for formatting. The Documentation CI
  job requires nightly for `--cfg docsrs` parity with docs.rs.

## Testing Strategy

- **Unit tests** are co-located with source code (`#[cfg(test)] mod tests`)
  or in `src/tests/` directories.
- **Behavioral tests** are in `crates/aptos-sdk/tests/behavioral/`; they
  pin documented invariants (e.g. authentication-key derivation rules)
  without requiring a network.
- **E2E tests** are in `crates/aptos-sdk/tests/e2e/`, gated behind the
  `e2e` feature flag and `#[ignore]`d so they only run when explicitly
  requested. They submit real transactions against a live Aptos network
  (devnet by default; localnet if `APTOS_LOCAL_NODE_URL` points to one).
- **Property-based testing** with `proptest` for crypto components (via
  the `fuzzing` feature). Note: the fuzzing feature pulls in
  proptest/arbitrary infrastructure but the SDK does not yet ship
  formal fuzz targets (tracked as F-21 in `SECURITY_AUDIT.md` and
  S-24 in `SECURITY_REVIEW_2026-05.md`).

When adding tests, prefer assertions over `println!`. A test that only
prints values without asserting them is a regression risk -- it passes
even when the production code starts producing wrong output. The audit
documented in `AUDIT_SUMMARY_2026-05.md` removed several such no-op
tests.

## Security review documents

- `SECURITY_AUDIT.md` -- Feb-2026 audit. 22 findings, all remediated or
  knowingly deferred.
- `SECURITY_REVIEW_2026-05.md` -- May-2026 follow-up review covering
  the audit branch's changes. Three new informational/low items.
- `AUDIT_SUMMARY_2026-05.md` -- May-2026 audit summary, file-by-file
  breakdown of the May-2026 changes.

When making a change that could affect the security posture (key
handling, signature verification, network input parsing, codegen,
deserialization), reread the relevant section of `SECURITY_AUDIT.md`
first and either preserve or explicitly improve the documented
mitigation.