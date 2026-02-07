# Aptos CLI — Design Plan & Progress Tracker

> Tracks what has been built, what remains, and the status of every feature
> described in [DESIGN.md](./DESIGN.md).

**Last updated:** 2026-02-06

Legend: Done / Partial / Not Started / Deferred

---

## Codebase Snapshot

| Metric | Value |
|--------|-------|
| Total lines of Rust | 6,765 |
| Source files | 13 |
| Public structs | 32 |
| Public functions | 37 |
| Test functions | 173 |
| Commands (top-level) | 5 (`account`, `key`, `move`, `transaction`, `info`) |
| Subcommands | 26 |
| REPL-only commands | 16 (`credential *`, `use`, `whoami`, `network`, `config *`, `help`, `quit`) |
| Auto-injected flags | 12 commands |
| Platforms shipped | 6 (Linux x86/ARM, macOS x86/ARM, Windows x86) |

---

## Phase 0 — Foundation (COMPLETE)

Everything in Phase 0 is shipped and tested.

### Account Commands

| Command | Status | Args | Auto-Inject | Tests |
|---------|--------|------|-------------|-------|
| `account create` | Done | `--key-type` (opt), `--mnemonic` (opt) | — | 3 |
| `account fund` | Done | `--address` (opt), `--amount` (req, APT or octas) | `--address` | 3 |
| `account balance` | Done | `--address` (opt) | `--address` | 2 |
| `account lookup` | Done | `--address` (opt) | `--address` | 1 |
| `account resources` | Done | `--address` (opt) | `--address` | 1 |
| `account resource` | Done | `--address` (opt), `--resource-type` (req) | `--address` | 2 |
| `account modules` | Done | `--address` (opt) | `--address` | 1 |
| `account transfer` | Done | `--private-key` (req), `--to` (req), `--amount` (req, APT or octas), `--key-type` (opt), `--coin-type` (opt) | `--private-key`, `--key-type` | 5 |

### Key Commands

| Command | Status | Args | Auto-Inject | Tests |
|---------|--------|------|-------------|-------|
| `key generate` | Done | `--key-type` (opt), `--mnemonic` (opt) | — | 5 |
| `key from-mnemonic` | Done | `--phrase` (req), `--index` (opt) | — | 3 |
| `key show` | Done | `--private-key` (req), `--key-type` (opt) | — | 3 |

### Move Commands

| Command | Status | Args | Auto-Inject | Tests |
|---------|--------|------|-------------|-------|
| `move init` | Done | `--name` (req), `--dir` (opt), `--named-address` (opt) | — | 4 |
| `move compile` | Done | `--package-dir` (opt), `--save-metadata` (opt), `--named-addresses` (opt) | — | 2 |
| `move test` | Done | `--package-dir` (opt), `--filter` (opt), `--named-addresses` (opt) | — | 2 |
| `move view` | Done | `--function` (req), `--type-args` (opt), `--args` (opt) | — | 3 |
| `move run` | Done | `--function` (req), `--private-key` (req), `--key-type` (opt), `--type-args` (opt), `--args` (opt), `--max-gas` (opt) | `--private-key`, `--key-type` | 3 |
| `move publish` | Done | `--private-key` (req), `--key-type` (opt), `--package-dir` (req) | `--private-key`, `--key-type` | 3 |
| `move build-publish` | Done | `--private-key` (req), `--key-type` (opt), `--package-dir` (opt), `--named-addresses` (opt) | `--private-key`, `--key-type` | 2 |
| `move inspect` | Done | `--address` (opt), `--module` (req) | `--address` | 3 |

### Transaction Commands

| Command | Status | Args | Auto-Inject | Tests |
|---------|--------|------|-------------|-------|
| `transaction lookup` | Done | `--hash` (req) | — | 2 |
| `transaction simulate` | Done | `--function` (req), `--sender` (opt), `--type-args` (opt), `--args` (opt) | `--sender` | 4 |

### Info Commands

| Command | Status | Args | Auto-Inject | Tests |
|---------|--------|------|-------------|-------|
| `info ledger` | Done | (none) | — | 1 |
| `info gas-price` | Done | (none) | — | 1 |
| `info block` | Done | `--height` (opt), `--version` (opt), `--with-transactions` (opt) | — | 5 |

### Interactive REPL

| Feature | Status | Tests |
|---------|--------|-------|
| REPL main loop (rustyline + prompt) | Done | — |
| Colorized prompt (`[network:alias] >>>`) | Done | — |
| Command history (secrets filtered) | Done | 7 |
| Shell argument parsing (shellwords) | Done | — |
| `help` / `?` | Done | — |
| `quit` / `exit` / `q` | Done | — |
| `tx` alias for `transaction` | Done | — |

### Credential Management (REPL)

| Feature | Status | Tests |
|---------|--------|-------|
| `credential init` — create vault | Done | — |
| `credential unlock` — decrypt vault | Done | — |
| `credential lock` — lock session | Done | — |
| `credential add` — add key to vault | Done | — |
| `credential generate` / `gen` — generate + add | Done | — |
| `credential remove` / `rm` — remove key | Done | — |
| `credential list` / `ls` — list keys | Done | — |
| `credential import` — import legacy profiles | Done | 6 |
| `credential change-password` — re-encrypt | Done | — |
| `use <alias>` — set active account | Done | — |
| `use none` — clear active account | Done | — |
| `whoami` — show active identity | Done | — |

### Session & Config (REPL)

| Feature | Status | Tests |
|---------|--------|-------|
| `network <name>` — switch network | Done | 4 |
| `config list` / `ls` | Done | — |
| `config get <key>` | Done | — |
| `config set <key> <value>` | Done | — |
| `config unset <key>` / `rm` / `remove` | Done | — |
| `config path` | Done | — |
| Persistent config (`~/.aptos/config/settings.json`) | Done | 23 |

### Auto-Injection Engine

| Injection | Status | Trigger Commands |
|-----------|--------|-----------------|
| `--private-key` + `--key-type` from active account | Done | `run`, `publish`, `build-publish`, `transfer`, `fund` |
| `--address` from active account | Done | `balance`, `lookup`, `resources`, `resource`, `modules`, `fund`, `inspect` |
| `--sender` from active account | Done | `simulate` |
| `--network` from session | Done | all |
| `--node-url` from session | Done | all |
| `--api-key` from session | Done | all |
| `--json` from session | Done | all |
| Zeroize argv after dispatch | Done | all signing commands |

### Encrypted Vault

| Feature | Status | Tests |
|---------|--------|-------|
| AES-256-GCM encryption | Done | 3 |
| Argon2id KDF (256 MiB, 4 iter) | Done | — |
| Per-entry random nonce (12 bytes) | Done | — |
| Random salt (32 bytes) | Done | — |
| Atomic file writes (temp + rename) | Done | 1 |
| File permissions 0o600 (Unix) | Done | — |
| Directory permissions 0o700 (Unix) | Done | — |
| Zeroize on drop (`Credential`, `ImportableProfile`) | Done | — |
| Password strength validation (12+ chars, mixed) | Done | 4 |
| Unlock rate limiting (5 tries, exp backoff) | Done | — |

### Legacy Import

| Feature | Status | Tests |
|---------|--------|-------|
| Detect `~/.aptos/config.yaml` | Done | 1 |
| Parse YAML profiles | Done | 1 |
| Extract `ed25519-priv-`, `secp256k1-priv-`, bare hex | Done | 3 |
| Import into vault (skip duplicates) | Done | 1 |
| Apply default network/node_url | Done | — |
| Offer import during onboarding | Done | — |

### Amount Parsing

| Feature | Status | Tests |
|---------|--------|-------|
| Integer octas (`150000000`) | Done | 2 |
| Decimal APT (`1.5` -> 150000000) | Done | 5 |
| Small fractions (`0.00000001` -> 1 octa) | Done | 1 |
| Rounding (`0.123456789`) | Done | 1 |
| Error: negative, non-numeric, empty | Done | 3 |

### Output Formatting

| Feature | Status | Tests |
|---------|--------|-------|
| `--json` mode (all commands) | Done | 3 |
| Human-readable mode (colorized) | Done | — |
| APT formatting (`format_apt()`) | Done | 5 |
| Key/value display (`print_kv()`) | Done | — |
| Headers, success, warning, error, info, dim | Done | — |

### Argument Parsing (BCS & JSON)

| Feature | Status | Tests |
|---------|--------|-------|
| `u8`, `u16`, `u32`, `u64`, `u128` | Done | 5 |
| `bool:true`, `bool:false` | Done | 2 |
| `string:...` | Done | 1 |
| `address:0x...` | Done | 1 |
| `hex:...` / `hex:0x...` | Done | 2 |
| JSON args (number, string, object, array, bool) | Done | 7 |
| Overflow / invalid type errors | Done | 2 |

### Security Measures

| Measure | Status | Reference |
|---------|--------|-----------|
| `aes-gcm` >= 0.10.3 (CVE fix) | Done | CRIT-001 |
| Config/vault file permissions 0o600 | Done | HIGH-001 |
| Argv zeroization after dispatch | Done | HIGH-002 |
| One-at-a-time key re-encryption | Done | HIGH-003 |
| Argon2id 256 MiB / 4 iterations | Done | MED-001 |
| History secret filtering (hex, keywords) | Done | MED-002 |
| Named address injection prevention | Done | MED-003 |
| Config directory 0o700 | Done | MED-004 |
| Sanitized error messages (no key material) | Done | MED-005 |
| Password strength (12+ chars, complexity) | Done | LOW-001 |
| Unlock rate limiting (exp backoff) | Done | LOW-002 |
| History file 0o600 | Done | LOW-003 |
| `ImportableProfile` zeroize on drop | Done | LOW-004 |

### CI/CD

| Pipeline | Status | File |
|----------|--------|------|
| Format check (`cargo fmt`) | Done | `ci.yml` |
| Clippy (`-D warnings`) | Done | `ci.yml` |
| Unit tests | Done | `ci.yml` |
| Cross-platform build matrix | Done | `ci.yml` |
| Release pipeline (6 targets) | Done | `cli-release.yml` |
| No-SIMD Linux variant | Done | `cli-release.yml` |
| SHA256 checksums | Done | `cli-release.yml` |
| GLIBC/SSL in release notes | Done | `cli-release.yml` |

### Documentation

| Document | Status |
|----------|--------|
| `BUILD.md` — build instructions, platform matrix | Done |
| `docs/DESIGN.md` — full architecture & phases | Done |
| `docs/DESIGN_PLAN.md` — this file | Done |
| `README.md` — user-facing docs | Not Started |

---

## Phase 1 — Full Indexer & Transaction Explorer (NOT STARTED)

| Feature | Status | Notes |
|---------|--------|-------|
| `indexer tokens --address` | Not Started | SDK `indexer` feature already enabled |
| `indexer balances --address` | Not Started | |
| `indexer history --address [--limit]` | Not Started | |
| `indexer events --address --type [--start] [--limit]` | Not Started | |
| `indexer query --graphql [--variables]` | Not Started | Raw GraphQL passthrough |
| Transaction explorer: decode payloads | Not Started | Upgrade `transaction lookup` |
| Transaction explorer: show events | Not Started | |
| Transaction explorer: show state changes | Not Started | |
| Event watching (`--follow` mode) | Not Started | |
| Tests | Not Started | ~400 lines estimated |

**Estimated effort:** ~1,700 lines

---

## Phase 2 — Scripting Engine & Automation (NOT STARTED)

| Feature | Status | Notes |
|---------|--------|-------|
| `.aptos` script file format | Not Started | |
| Lexer + parser | Not Started | ~600 lines estimated |
| Variable system (`let`, `$VAR`, `${VAR}`) | Not Started | |
| Built-in variables (`$ADDRESS`, `$NETWORK`, etc.) | Not Started | |
| Control flow (`if`/`end`, `for`/`end`) | Not Started | |
| Assertions (`assert`, `assert_eq`) | Not Started | |
| Error handling (`on_error`) | Not Started | |
| `--file <path>` CLI flag | Not Started | |
| Pipe mode (`echo cmd | aptos-cli`) | Not Started | |
| Heredoc support (`--file -`) | Not Started | |
| Tests | Not Started | ~600 lines estimated |

**Estimated effort:** ~2,350 lines

---

## Phase 3 — Advanced Account Workflows (NOT STARTED)

| Feature | Status | Notes |
|---------|--------|-------|
| `multisig create` | Not Started | SDK has `MultiEd25519Account`, `MultiKeyAccount` |
| `multisig propose` | Not Started | |
| `multisig approve` | Not Started | |
| `multisig reject` | Not Started | |
| `multisig execute` | Not Started | |
| `multisig pending` | Not Started | |
| `multisig info` | Not Started | |
| `transaction sponsor` | Not Started | SDK has `SponsoredTransactionBuilder` |
| Multi-agent transactions | Not Started | SDK has `MultiAgentRawTransaction` |
| `batch transfer --file <csv>` | Not Started | SDK has `submit_batch()` |
| `batch run --file <script>` | Not Started | Depends on Phase 2 |
| `batch submit --file <txns.json>` | Not Started | |
| Vault multi-key credential support | Not Started | |
| Tests | Not Started | ~600 lines estimated |

**Estimated effort:** ~3,000 lines

---

## Phase 4 — Watch Mode & Developer Experience (NOT STARTED)

| Feature | Status | Notes |
|---------|--------|-------|
| `move watch --package-dir` | Not Started | Needs `notify` crate |
| File change debouncing (200ms) | Not Started | |
| Auto-compile on save | Not Started | |
| Auto-test on compile success | Not Started | |
| `--auto-deploy` to localnet | Not Started | |
| `node start [--background]` | Not Started | Wraps `aptos node run-localnet` |
| `node stop` | Not Started | |
| `node status` | Not Started | |
| `node reset` | Not Started | |
| `node logs [--follow]` | Not Started | |
| Command aliases (`bal`, `tx`) | Partial | `tx` exists, no others |
| Rustyline auto-completion | Not Started | |
| `$_` last result reference | Not Started | |
| Smart address display (short form) | Not Started | |
| Tests | Not Started | ~400 lines estimated |

**Estimated effort:** ~1,850 lines

---

## Phase 5 — Rich Testing Framework (NOT STARTED)

| Feature | Status | Notes |
|---------|--------|-------|
| `test unit` (wrap `move test` + coverage) | Not Started | |
| `test gas-profile --function [--iterations]` | Not Started | Uses `simulate` under the hood |
| `test verify-deploy --package-dir --address` | Not Started | Compare local vs on-chain bytecode |
| `test integration --file` | Not Started | Depends on Phase 2 scripting |
| `test benchmark --function [--iterations]` | Not Started | |
| Tests | Not Started | ~400 lines estimated |

**Estimated effort:** ~2,150 lines

---

## Phase 6 — Embedded Move Compiler (NOT STARTED)

| Feature | Status | Notes |
|---------|--------|-------|
| `embedded-compiler` feature flag | Not Started | Behind `[features]` gate |
| In-process compilation | Not Started | Needs `move-compiler` crate |
| Error mapping (compiler errors -> CLI output) | Not Started | |
| Fallback to external `aptos` CLI | Not Started | |
| Tests | Not Started | ~500 lines estimated |

**Estimated effort:** ~2,500 lines

---

## Phase 7 — Plugin System (NOT STARTED)

| Feature | Status | Notes |
|---------|--------|-------|
| WASM runtime (wasmtime) | Not Started | |
| Plugin API surface | Not Started | |
| Plugin manifest format (`plugin.toml`) | Not Started | |
| `plugin install` | Not Started | |
| `plugin remove` | Not Started | |
| `plugin list` | Not Started | |
| `plugin update` | Not Started | |
| `plugin create` (scaffold) | Not Started | |
| Sandboxed execution | Not Started | |
| Tests | Not Started | ~500 lines estimated |

**Estimated effort:** ~2,700 lines

---

## Phase 8 — Keyless Auth & Gas Station (NOT STARTED)

| Feature | Status | Notes |
|---------|--------|-------|
| `credential keyless` (OIDC flow) | Not Started | SDK has `KeylessAccount` |
| Browser OAuth redirect handler | Not Started | Local HTTP server for callback |
| JWT storage in vault | Not Started | |
| Ephemeral key management | Not Started | |
| Gas Station API client | Not Started | Geomi integration |
| `--sponsored` flag on transaction commands | Not Started | |
| `config set gas_station_api_key` | Not Started | |
| Tests | Not Started | ~400 lines estimated |

**Estimated effort:** ~2,500 lines

---

## Phase 9 — Project Scaffolding & Templates (NOT STARTED)

| Feature | Status | Notes |
|---------|--------|-------|
| `init` interactive wizard | Not Started | |
| Built-in templates (minimal, token, NFT, DeFi, governance) | Not Started | |
| Template registry (Git-based) | Not Started | |
| Local custom templates (`~/.aptos/templates/`) | Not Started | |
| Deploy scripts generated per template | Not Started | Depends on Phase 2 |
| Tests | Not Started | ~300 lines estimated |

**Estimated effort:** ~2,200 lines

---

## Distribution

| Channel | Status | Notes |
|---------|--------|-------|
| GitHub Releases (pre-built binaries) | Done | 6 platform targets |
| `cargo install` (crates.io) | Not Started | Need to publish crate |
| Homebrew tap | Not Started | Formula spec in DESIGN.md |
| Auto-update check (`self update`) | Not Started | |

---

## Overall Progress

```
Phase 0  Foundation              ████████████████████  COMPLETE   6,765 lines
Phase 1  Indexer + Tx Explorer   ░░░░░░░░░░░░░░░░░░░░  0%        ~1,700 lines
Phase 2  Scripting Engine        ░░░░░░░░░░░░░░░░░░░░  0%        ~2,350 lines
Phase 3  Advanced Accounts       ░░░░░░░░░░░░░░░░░░░░  0%        ~3,000 lines
Phase 4  Watch Mode + DX         ░▒░░░░░░░░░░░░░░░░░░  ~3%       ~1,850 lines
Phase 5  Testing Framework       ░░░░░░░░░░░░░░░░░░░░  0%        ~2,150 lines
Phase 6  Embedded Compiler       ░░░░░░░░░░░░░░░░░░░░  0%        ~2,500 lines
Phase 7  Plugin System           ░░░░░░░░░░░░░░░░░░░░  0%        ~2,700 lines
Phase 8  Keyless + Gas Station   ░░░░░░░░░░░░░░░░░░░░  0%        ~2,500 lines
Phase 9  Scaffolding             ░░░░░░░░░░░░░░░░░░░░  0%        ~2,200 lines

Total implemented:  6,765 lines    (20% of full plan)
Total remaining:   ~26,950 lines   (across phases 1-9)
Total planned:     ~33,715 lines
```

---

## Test Coverage by Module

```
common.rs          ██████████████████████████████████████████  40 tests
main.rs            ██████████████████████████████████████████████████████████████  62 tests
config.rs          ███████████████████████  23 tests
interactive.rs     ███████████████  15 tests
credentials.rs     ███████████  11 tests
move_cmd.rs        ██████████  10 tests
output.rs          ██████  6 tests
import.rs          ██████  6 tests
account.rs         ░░  0 (covered by main.rs parsing tests)
key.rs             ░░  0 (covered by main.rs parsing tests)
transaction.rs     ░░  0 (covered by main.rs parsing tests)
info.rs            ░░  0 (covered by main.rs parsing tests)
                   ─────────────────────────────────────────
                   173 total tests
```

---

## SDK Feature Utilization

Shows which SDK features are used by the CLI today vs. available.

```
SDK Feature                    CLI Usage                         Status
───────────────────────        ─────────────────────────────     ──────
Ed25519 accounts               account create, key generate      Done
Secp256k1 accounts             account create, key generate      Done
Secp256r1 accounts             account create, key generate      Done
Mnemonic (BIP-39)              key from-mnemonic, key generate   Done
Fullnode REST API              All account/info/tx commands      Done
  - get_account                account lookup                    Done
  - get_balance                account balance                   Done
  - get_account_resources      account resources                 Done
  - get_account_resource       account resource                  Done
  - get_account_modules        account modules                   Done
  - get_account_module         move inspect                      Done
  - get_transaction_by_hash    transaction lookup                Done
  - estimate_gas_price         info gas-price                    Done
  - get_block_by_height        info block --height               Done
  - get_block_by_version       info block --version              Done
  - simulate_transaction       transaction simulate              Done
  - view                       move view                         Done
Faucet                         account fund                      Done
Transaction building           move run, account transfer        Done
  - EntryFunction              move run                          Done
  - sign_submit_and_wait       move run, publish, transfer       Done
  - TransactionBuilder         transaction simulate              Done
Indexer GraphQL                —                                 Phase 1
  - get_fungible_asset_bal     —                                 Phase 1
  - get_account_tokens         —                                 Phase 1
  - get_account_transactions   —                                 Phase 1
  - custom GraphQL queries     —                                 Phase 1
Batch operations               —                                 Phase 3
  - submit_batch               —                                 Phase 3
  - batch_transfer_apt         —                                 Phase 3
Multi-sig accounts             —                                 Phase 3
  - MultiEd25519Account        —                                 Phase 3
  - MultiKeyAccount            —                                 Phase 3
Sponsored transactions         —                                 Phase 3
  - SponsoredTransactionBuilder —                                Phase 3
  - FeePayerRawTransaction     —                                 Phase 3
Multi-agent transactions       —                                 Phase 3
  - MultiAgentRawTransaction   —                                 Phase 3
Keyless accounts               —                                 Phase 8
  - KeylessAccount             —                                 Phase 8
Simulation (rich)              —                                 Phase 1
  - SimulationResult.events()  —                                 Phase 1
  - SimulationResult.state_changes() —                           Phase 1
  - estimate_gas               —                                 Phase 5
Code generation                —                                 Not planned
  - codegen from ABI           —                                 Not planned (SDK feature)
```
