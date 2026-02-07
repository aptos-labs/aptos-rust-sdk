# Aptos CLI Design Document

> A comprehensive wrapper around the Aptos Rust SDK, delivering a modern
> interactive CLI for Move developers building dApps on Aptos.

**Status:** Living document
**Last updated:** 2026-02-06
**Binary name:** `aptos-cli`
**Crate:** `aptos-cli` (workspace member at `crates/aptos-cli/`)

---

## Table of Contents

1. [Vision & Goals](#1-vision--goals)
2. [Architecture Overview](#2-architecture-overview)
3. [Current State (Phase 0)](#3-current-state-phase-0)
4. [Phase 1 — Full Indexer & Transaction Explorer](#4-phase-1--full-indexer--transaction-explorer)
5. [Phase 2 — Scripting Engine & Automation](#5-phase-2--scripting-engine--automation)
6. [Phase 3 — Advanced Account Workflows](#6-phase-3--advanced-account-workflows)
7. [Phase 4 — Watch Mode & Developer Experience](#7-phase-4--watch-mode--developer-experience)
8. [Phase 5 — Rich Testing Framework](#8-phase-5--rich-testing-framework)
9. [Phase 6 — Embedded Move Compiler](#9-phase-6--embedded-move-compiler)
10. [Phase 7 — Plugin System](#10-phase-7--plugin-system)
11. [Phase 8 — Keyless Auth & Gas Station](#11-phase-8--keyless-auth--gas-station)
12. [Phase 9 — Project Scaffolding & Templates](#12-phase-9--project-scaffolding--templates)
13. [Distribution Plan](#13-distribution-plan)
14. [Security Model](#14-security-model)
15. [Data Flow Diagrams](#15-data-flow-diagrams)
16. [Decision Log](#16-decision-log)

---

## 1. Vision & Goals

### Mission

Build the **definitive CLI for Move developers** on Aptos — an interactive,
scriptable, secure tool that replaces the need for the official `aptos` CLI in
day-to-day dApp development workflows.

### Non-Goals

- **Not a node operator tool.** This CLI does not manage validators, fullnodes,
  or network infrastructure.
- **Not a wallet.** It manages developer credentials, not end-user wallets.
- **Not backwards-compatible with the official CLI.** Command names and flags
  are optimized for ergonomics, not for drop-in replacement.

### Design Principles

```
 1. Developer-first    — Optimize for the "edit → compile → test → deploy" loop
 2. Interactive-first   — REPL is the primary interface, batch mode is secondary
 3. Secure by default   — Encrypted credentials, zeroized memory, no plaintext keys
 4. Self-documenting    — Discoverable commands, rich help text, inline examples
 5. Scriptable          — Every interactive command also works in batch/pipe mode
 6. Minimal footprint   — Small binary, fast startup, low dependencies
```

### Target Audience

Move developers building dApps on Aptos, across all experience levels:

| Persona | Needs |
|---------|-------|
| **New developer** | Guided onboarding, scaffolding, clear errors |
| **Active builder** | Fast compile/test cycle, watch mode, deployment |
| **Protocol team** | Multi-sig, sponsored txns, batch operations |
| **Scripter/CI** | Non-interactive mode, JSON output, exit codes |

---

## 2. Architecture Overview

### System Context

```
┌──────────────────────────────────────────────────────────────────┐
│                         Developer Machine                        │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │                      aptos-cli                           │    │
│  │                                                          │    │
│  │  ┌──────────┐  ┌───────────┐  ┌──────────────────────┐  │    │
│  │  │  REPL    │  │ Scripting │  │   Non-Interactive    │  │    │
│  │  │  Engine  │  │  Engine   │  │      (batch)         │  │    │
│  │  └────┬─────┘  └─────┬─────┘  └──────────┬───────────┘  │    │
│  │       │               │                    │              │    │
│  │       └───────────┬───┴────────────────────┘              │    │
│  │                   ▼                                       │    │
│  │          ┌────────────────┐                               │    │
│  │          │ Command Router │                               │    │
│  │          └───────┬────────┘                               │    │
│  │       ┌──────────┼──────────────────────┐                 │    │
│  │       ▼          ▼          ▼           ▼                 │    │
│  │  ┌─────────┐ ┌────────┐ ┌──────┐ ┌──────────┐           │    │
│  │  │ Account │ │  Move  │ │  Tx  │ │  Info /  │           │    │
│  │  │   Mgmt  │ │  Cmds  │ │  Ops │ │ Indexer  │           │    │
│  │  └────┬────┘ └───┬────┘ └──┬───┘ └────┬─────┘           │    │
│  │       └──────────┼─────────┼───────────┘                 │    │
│  │                  ▼         ▼                              │    │
│  │          ┌───────────────────────┐                        │    │
│  │          │    Aptos Rust SDK     │                        │    │
│  │          │  (aptos-sdk crate)    │                        │    │
│  │          └───────────┬───────────┘                        │    │
│  │                      │                                    │    │
│  │  ┌───────────────────┼──────────────────────────────┐     │    │
│  │  │  Storage Layer    │                              │     │    │
│  │  │                   │                              │     │    │
│  │  │  ~/.aptos/        ▼                              │     │    │
│  │  │  ├── credentials/vault.json  (AES-256-GCM)      │     │    │
│  │  │  ├── config/settings.json                        │     │    │
│  │  │  ├── history                                     │     │    │
│  │  │  └── scripts/     (user scripts)                 │     │    │
│  │  └──────────────────────────────────────────────────┘     │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────┬────────────────────────────────────┘
                              │  HTTPS
          ┌───────────────────┼───────────────────────┐
          ▼                   ▼                       ▼
   ┌──────────────┐  ┌───────────────┐  ┌─────────────────┐
   │   Fullnode   │  │   Indexer     │  │    Faucet       │
   │   REST API   │  │   GraphQL    │  │  (testnet/dev)  │
   └──────────────┘  └───────────────┘  └─────────────────┘
```

### Module Architecture

```
aptos-cli/src/
├── main.rs                 # Entry point, CLI parsing, mode dispatch
├── common.rs               # Shared types (GlobalOpts, KeyType, CliAccount)
├── config.rs               # Persistent configuration (~/.aptos/config/)
├── credentials.rs          # Encrypted vault (AES-256-GCM + Argon2id)
├── import.rs               # Legacy aptos CLI profile importer
├── interactive.rs          # REPL engine, session state, prompt rendering
├── output.rs               # Colorized terminal output formatting
├── scripting.rs            # [Phase 2] Script parser & executor
├── watcher.rs              # [Phase 4] File watcher for hot-reload
├── plugins/                # [Phase 7] Plugin system
│   ├── mod.rs
│   ├── loader.rs
│   └── api.rs
└── commands/
    ├── mod.rs              # Command module registry
    ├── account.rs          # Account operations
    ├── key.rs              # Key management
    ├── move_cmd.rs         # Move compile/test/publish/view/run
    ├── transaction.rs      # Transaction lookup/simulate
    ├── info.rs             # Network info, gas, blocks
    ├── indexer.rs          # [Phase 1] Indexer queries
    ├── token.rs            # [Phase 1] Token/NFT operations
    └── multisig.rs         # [Phase 3] Multi-sig workflows
```

### Execution Modes

The CLI operates in three modes. All share the same command router:

```
          ┌─────────────────────────┐
          │    aptos-cli binary     │
          └────────────┬────────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
    ┌──────────┐ ┌──────────┐ ┌──────────┐
    │   REPL   │ │  Script  │ │  Single  │
    │  (default│ │  Engine  │ │  Command │
    │  no args)│ │  --file  │ │  (e.g.   │
    │          │ │  or pipe │ │  account │
    │  stdin → │ │          │ │  balance)│
    │  prompt  │ │  .aptos  │ │          │
    │  loop    │ │  files   │ │  stdout →│
    └──────────┘ └──────────┘ └──────────┘
        │              │             │
        └──────────────┴─────────────┘
                       │
              ┌────────▼────────┐
              │ Command Router  │
              │ (unified parse  │
              │  + dispatch)    │
              └─────────────────┘
```

---

## 3. Current State (Phase 0)

**Status:** Complete and functional.

### What Exists

| Category | Commands | Notes |
|----------|----------|-------|
| **Account** | `create`, `fund`, `balance`, `lookup`, `resources`, `resource`, `modules`, `transfer` | Address auto-injected from active account |
| **Key** | `generate`, `from-mnemonic`, `show` | Ed25519/Secp256k1/Secp256r1 |
| **Move** | `init`, `compile`, `test`, `view`, `run`, `publish`, `build-publish`, `inspect` | Wraps external `aptos` CLI for compilation |
| **Transaction** | `lookup`, `simulate` | Sender auto-injected |
| **Info** | `ledger`, `gas-price`, `block` | — |
| **REPL** | `credential *`, `use`, `whoami`, `network`, `config *`, `help` | Encrypted vault, session mgmt |

### What Works Well

- Encrypted credential vault (AES-256-GCM + Argon2id)
- Auto-injection of addresses and credentials from active account
- Legacy Aptos CLI profile import
- Human-friendly amounts (`--amount 1.5` = 1.5 APT)
- Colorized output with `--json` mode
- Cross-platform builds (Linux/macOS/Windows, x86/ARM)
- 237 passing tests, clippy-clean, security-audited

### Gaps to Fill

```
 ┌─────────────────────────────────────────────────────────────┐
 │                   CAPABILITY COVERAGE MAP                    │
 │                                                             │
 │  SDK Feature              CLI Coverage        Gap           │
 │  ─────────────────────    ───────────────     ─────────     │
 │  Fullnode REST API        ██████████░░        Events         │
 │  Account management       █████████████       (complete)     │
 │  Transaction building     ████████░░░░        Multi-agent    │
 │  Transaction simulation   ██████████░░        Rich output    │
 │  View functions           █████████████       (complete)     │
 │  Faucet                   █████████████       (complete)     │
 │  Indexer GraphQL          ░░░░░░░░░░░░        Not started    │
 │  Batch operations         ░░░░░░░░░░░░        Not started    │
 │  Multi-sig                ░░░░░░░░░░░░        Not started    │
 │  Sponsored transactions   ░░░░░░░░░░░░        Not started    │
 │  Multi-agent transactions ░░░░░░░░░░░░        Not started    │
 │  Keyless auth             ░░░░░░░░░░░░        Not started    │
 │  ANS (name service)       ░░░░░░░░░░░░        Not started    │
 │  Scripting                ░░░░░░░░░░░░        Not started    │
 │  Watch/hot-reload         ░░░░░░░░░░░░        Not started    │
 └─────────────────────────────────────────────────────────────┘
```

---

## 4. Phase 1 — Full Indexer & Transaction Explorer

**Goal:** Rich data queries that go beyond the fullnode REST API.

**Dependencies:** SDK `indexer` feature (already enabled).

### New Commands

```
indexer
├── tokens         --address <addr>                   # List tokens/NFTs
├── balances       --address <addr>                   # Fungible asset balances
├── history        --address <addr> [--limit N]       # Transaction history
├── events         --address <addr> --type <event>    # Event stream
│                  [--start N] [--limit N]
└── query          --graphql <query>                  # Raw GraphQL query
                   [--variables <json>]
```

### Transaction Explorer Enhancements

Upgrade `transaction lookup` to decode and display:

```
┌─ Transaction 0xabc123...def ─────────────────────────────────┐
│                                                               │
│  Status:    SUCCESS                    Version: 1234567       │
│  Gas Used:  42 units (4200 octas)      Epoch: 100            │
│  Timestamp: 2026-02-06 14:30:00 UTC                          │
│                                                               │
│  ┌─ Payload ────────────────────────────────────────────┐    │
│  │  Function: 0x1::aptos_account::transfer              │    │
│  │  Type Args: (none)                                   │    │
│  │  Args:                                               │    │
│  │    [0] address: 0xBOB                                │    │
│  │    [1] u64: 100000000 (1.0 APT)                      │    │
│  └──────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─ Events (2) ─────────────────────────────────────────┐    │
│  │  WithdrawEvent { amount: 100000000 }                  │    │
│  │  DepositEvent  { amount: 100000000 }                  │    │
│  └──────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─ State Changes (3) ──────────────────────────────────┐    │
│  │  0xALICE::CoinStore<APT>  balance: 900 → 800 APT     │    │
│  │  0xBOB::CoinStore<APT>    balance: 100 → 200 APT     │    │
│  │  0xALICE                  seq_num: 5 → 6              │    │
│  └──────────────────────────────────────────────────────┘    │
└───────────────────────────────────────────────────────────────┘
```

### Event Watching

```
aptos-cli> events --address 0x1 --type 0x1::coin::DepositEvent --follow
Watching for events... (Ctrl+C to stop)

  [Block 999] DepositEvent { amount: 50000000 }  → 0x1
  [Block 1002] DepositEvent { amount: 100000000 } → 0x1
  ...
```

### Data Model

```
               ┌──────────────────┐
               │  IndexerClient   │
               │  (SDK crate)     │
               └────────┬─────────┘
                        │ GraphQL
          ┌─────────────┼────────────────┐
          ▼             ▼                ▼
   ┌────────────┐ ┌──────────┐ ┌──────────────┐
   │  Token     │ │ Fungible │ │  Transaction │
   │  Queries   │ │  Asset   │ │   History    │
   │            │ │ Queries  │ │              │
   └────────────┘ └──────────┘ └──────────────┘
```

### Effort Estimate

| Task | Complexity | Lines (est.) |
|------|-----------|-------------|
| `indexer` command module | Medium | ~400 |
| Token/NFT display | Medium | ~300 |
| Transaction explorer upgrade | Medium | ~350 |
| Event streaming | Medium | ~250 |
| Tests | Medium | ~400 |
| **Total** | | **~1,700** |

---

## 5. Phase 2 — Scripting Engine & Automation

**Goal:** Full scripting with variables, loops, conditionals, and batch
file execution for CI/CD and repeatable workflows.

### Script Language

Aptos Script Files (`.aptos`) — a minimal domain-specific language:

```bash
# deploy.aptos — Deploy and verify a Move module

# Variables
let DEPLOYER = "my_account"
let PACKAGE_DIR = "./my_module"
let NETWORK = "testnet"

# Configuration
network $NETWORK
use $DEPLOYER

# Compile and deploy
move compile --package-dir $PACKAGE_DIR --named-addresses my_addr=$ADDRESS
move build-publish --package-dir $PACKAGE_DIR --named-addresses my_addr=$ADDRESS

# Verify deployment
let MODULES = account modules --json
assert $MODULES contains "my_module" "Module not found after deployment"

# Run a test transaction
move run --function ${ADDRESS}::my_module::set_message --args string:"Hello, Aptos!"

# Verify state
let RESULT = move view --function ${ADDRESS}::my_module::get_message --args "\"$ADDRESS\""
print "Deployed and verified: $RESULT"
```

### Script Features

```
┌───────────────────────────────────────────────────────────┐
│                  SCRIPTING ENGINE                          │
│                                                           │
│  Variables     │  let NAME = "value"                      │
│                │  let RESULT = <command> --json            │
│                │  $NAME, ${NAME}, $ADDRESS (built-in)      │
│                                                           │
│  Control Flow  │  if <condition>                          │
│                │    <commands>                             │
│                │  end                                     │
│                │                                          │
│                │  for ITEM in <list>                      │
│                │    <commands>                             │
│                │  end                                     │
│                                                           │
│  Assertions    │  assert <expr> <message>                 │
│                │  assert_eq <a> <b> <message>             │
│                                                           │
│  I/O           │  print <message>                         │
│                │  print_json <value>                       │
│                │  sleep <seconds>                          │
│                                                           │
│  Errors        │  on_error continue | abort | retry N     │
│                                                           │
│  Built-in Vars │  $ADDRESS — active account address       │
│                │  $NETWORK — current network              │
│                │  $TIMESTAMP — current unix timestamp      │
│                │  $EXIT_CODE — last command exit code      │
└───────────────────────────────────────────────────────────┘
```

### Execution Modes

```bash
# Run a script file
aptos-cli --file deploy.aptos

# Pipe commands (non-interactive)
echo "account balance" | aptos-cli --network testnet

# Heredoc for inline scripts
aptos-cli --file - <<'EOF'
use my_account
account balance
EOF

# Single command (existing behavior)
aptos-cli account balance --address 0x1
```

### Script Engine Architecture

```
 ┌──────────────┐
 │  .aptos file │
 └──────┬───────┘
        │ read
        ▼
 ┌──────────────┐     ┌──────────────┐
 │    Lexer     │────▶│    Parser    │
 └──────────────┘     └──────┬───────┘
                             │ AST
                             ▼
                      ┌──────────────┐
                      │  Evaluator   │
                      │              │
                      │  ┌────────┐  │
                      │  │ Scope  │  │  variables, env
                      │  └────────┘  │
                      │  ┌────────┐  │
                      │  │  Cmd   │  │  reuses existing
                      │  │Dispatch│  │  command router
                      │  └────────┘  │
                      └──────────────┘
```

### Effort Estimate

| Task | Complexity | Lines (est.) |
|------|-----------|-------------|
| Lexer + Parser | High | ~600 |
| Evaluator + scope | High | ~500 |
| Variable interpolation | Medium | ~200 |
| Control flow (if/for) | Medium | ~300 |
| Non-interactive pipe mode | Low | ~150 |
| Tests | High | ~600 |
| **Total** | | **~2,350** |

---

## 6. Phase 3 — Advanced Account Workflows

**Goal:** Multi-signature, sponsored transactions, multi-agent transactions,
and batch operations.

### New Commands

```
# Multi-sig operations
multisig
├── create           --owners <addr>... --threshold N    # Create multi-sig account
├── propose          --multisig <addr> --function <fn>   # Propose transaction
│                    [--args ...] [--type-args ...]
├── approve          --multisig <addr> --seq N           # Approve proposal
├── reject           --multisig <addr> --seq N           # Reject proposal
├── execute          --multisig <addr> --seq N           # Execute approved txn
├── pending          --multisig <addr>                   # List pending proposals
└── info             --multisig <addr>                   # Show multi-sig config

# Sponsored transactions
transaction
├── sponsor          --function <fn> --sender <addr>     # Create fee-payer txn
│                    [--fee-payer <alias>]
└── sign-as-sponsor  --txn <hex/file>                    # Sign as fee payer

# Batch operations
batch
├── transfer         --file <csv>                        # Batch transfers from CSV
│                    [--dry-run]
├── run              --file <script>                     # Run batch script
└── submit           --file <txns.json>                  # Submit pre-built txns
```

### Multi-Sig Transaction Flow

```
 Owner A              Multi-sig Account              Owner B
 ───────              ─────────────────              ───────
    │                        │                          │
    │  multisig propose      │                          │
    │───────────────────────▶│                          │
    │                        │ proposal #1 created      │
    │                        │                          │
    │                        │    multisig approve      │
    │                        │◀─────────────────────────│
    │                        │                          │
    │  multisig execute      │                          │
    │───────────────────────▶│                          │
    │                        │──── submit txn ────▶ Blockchain
    │                        │                          │
```

### Sponsored Transaction Flow

```
 Sender                   CLI Session                  Fee Payer
 ──────                   ───────────                  ─────────
    │                         │                            │
    │  tx sponsor --fn ...    │                            │
    │────────────────────────▶│                            │
    │                         │ build FeePayerRawTxn       │
    │                         │                            │
    │  sign (sender key)      │                            │
    │────────────────────────▶│                            │
    │                         │ sign (fee payer key)       │
    │                         │───────────────────────────▶│
    │                         │                            │
    │                         │◀───── signed ──────────────│
    │                         │                            │
    │                         │──── submit ────▶ Blockchain │
```

### Batch CSV Format

```csv
recipient,amount_apt
0xBOB,1.5
0xALICE,2.0
0xCHARLIE,0.5
```

### Effort Estimate

| Task | Complexity | Lines (est.) |
|------|-----------|-------------|
| Multi-sig commands | High | ~800 |
| Sponsored transaction support | High | ~500 |
| Multi-agent transaction support | Medium | ~400 |
| Batch operations (CSV, JSON) | Medium | ~400 |
| Credential vault: multi-key support | Medium | ~300 |
| Tests | High | ~600 |
| **Total** | | **~3,000** |

---

## 7. Phase 4 — Watch Mode & Developer Experience

**Goal:** `move watch` for hot-reload during development, localnet management,
and developer quality-of-life improvements.

### Watch Mode

```bash
aptos-cli> move watch --package-dir ./my_module --named-addresses my_addr=0xcafe

  Watching ./my_module/sources/ for changes...
  Press Ctrl+C to stop.

  [14:30:01] File changed: sources/my_module.move
  [14:30:01] Compiling...
  [14:30:03] ✓ Compilation succeeded (2 modules)
  [14:30:03] Running tests...
  [14:30:05] ✓ All 3 tests passed

  [14:30:12] File changed: sources/my_module.move
  [14:30:12] Compiling...
  [14:30:13] ✗ Compilation failed:
             error[E04001]: unresolved type
               ┌─ sources/my_module.move:15:20
               │
            15 │     let x: Strin = ...
               │            ^^^^^ unresolved type
```

### Watch Architecture

```
 ┌──────────────────┐
 │   File Watcher   │  notify/inotify/FSEvents
 │   (notify crate) │
 └────────┬─────────┘
          │ file change event
          ▼
 ┌──────────────────┐
 │   Debouncer      │  coalesce rapid saves (200ms)
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐     ┌──────────────────┐
 │  Compile Step    │────▶│   Test Step      │  (if compile passes)
 │  (move compile)  │     │  (move test)     │
 └──────────────────┘     └──────────────────┘
          │                        │
          └────────────┬───────────┘
                       ▼
              ┌────────────────┐
              │  Auto-Publish  │  (optional, --auto-deploy)
              │  to localnet   │
              └────────────────┘
```

### Localnet Management

Wrap the existing `aptos node run-localnet` command:

```
node
├── start        [--background]              # Start localnet
├── stop                                     # Stop running localnet
├── status                                   # Check if localnet is running
├── reset                                    # Reset localnet state
└── logs         [--follow]                  # View localnet logs
```

### Developer Quality-of-Life

```
# Smart address display (short by default, full with --verbose)
aptos-cli> account balance
  Balance: 10.5 APT (0x1a2b...3c4d)

# APT amount formatting everywhere
aptos-cli> account fund --amount 10     # 10 APT (not octas!)

# Command aliases
aptos-cli> bal                           # → account balance
aptos-cli> tx 0xhash                     # → transaction lookup --hash ...

# Auto-completion in REPL
aptos-cli> account ba<TAB>
  balance

# Previous result reference
aptos-cli> account create
  Address: 0xNEW_ADDR
aptos-cli> account fund --address $_ --amount 1
  Funded!
```

### Effort Estimate

| Task | Complexity | Lines (est.) |
|------|-----------|-------------|
| File watcher + debouncer | Medium | ~350 |
| Watch loop with compile + test | Medium | ~300 |
| Localnet wrapper commands | Low | ~250 |
| Command aliases | Low | ~150 |
| Auto-completion (rustyline) | Medium | ~300 |
| `$_` last result reference | Low | ~100 |
| Tests | Medium | ~400 |
| **Total** | | **~1,850** |

---

## 8. Phase 5 — Rich Testing Framework

**Goal:** Go beyond `move test` with gas profiling, coverage reports,
deployment verification, and integration testing against localnet.

### Testing Commands

```
test
├── unit             --package-dir .                    # Run Move unit tests
│                    [--filter <pattern>]               # (wraps move test)
│                    [--coverage]                       # Generate coverage
├── gas-profile      --function <fn>                    # Profile gas usage
│                    [--args ...] [--iterations N]
├── verify-deploy    --package-dir .                    # Verify deployed code
│                    --address <addr>                   # matches local source
├── integration      --file <test.aptos>               # Run integration test
│                    [--network local]                  # script against chain
└── benchmark        --function <fn>                   # Repeated execution
                     [--iterations 100]                 # with statistics
```

### Gas Profiling Output

```
┌─ Gas Profile: 0x1::my_module::complex_operation ─────────────┐
│                                                               │
│  Iteration  │  Gas Used  │  Execution  │  Storage  │ I/O     │
│  ─────────  │  ─────────  │  ─────────  │  ───────  │ ────    │
│  1          │     1,245   │       890   │     255   │  100    │
│  2          │     1,180   │       825   │     255   │  100    │
│  3          │     1,190   │       835   │     255   │  100    │
│  ─────────  │  ─────────  │  ─────────  │  ───────  │ ────    │
│  Avg        │     1,205   │       850   │     255   │  100    │
│  Min        │     1,180   │       825   │     255   │  100    │
│  Max        │     1,245   │       890   │     255   │  100    │
│                                                               │
│  Estimated cost at 100 gas/unit: 0.001205 APT                │
└───────────────────────────────────────────────────────────────┘
```

### Deployment Verification

```
aptos-cli> test verify-deploy --package-dir ./my_module --address 0xDEPLOYED

  Verifying deployed bytecode matches local source...

  Module my_module:
    Local hash:    0xabc123...
    On-chain hash: 0xabc123...
    ✓ Match

  Module my_module_utils:
    Local hash:    0xdef456...
    On-chain hash: 0xdef456...
    ✓ Match

  ✓ All 2 modules verified
```

### Effort Estimate

| Task | Complexity | Lines (est.) |
|------|-----------|-------------|
| `test unit` (wrap + coverage) | Low | ~200 |
| Gas profiling | High | ~500 |
| Deployment verification | Medium | ~350 |
| Integration test runner | High | ~400 |
| Benchmark mode | Medium | ~300 |
| Tests | Medium | ~400 |
| **Total** | | **~2,150** |

---

## 9. Phase 6 — Embedded Move Compiler

**Goal:** Remove dependency on external `aptos` CLI binary by embedding the
Move compiler directly.

### Current vs. Target

```
 CURRENT (Phase 0)                     TARGET (Phase 6)
 ─────────────────                     ──────────────────

 ┌─────────────┐                       ┌─────────────┐
 │  aptos-cli  │                       │  aptos-cli  │
 │  (our CLI)  │                       │  (our CLI)  │
 └──────┬──────┘                       └──────┬──────┘
        │ subprocess                          │ in-process
        ▼                                     ▼
 ┌──────────────┐                      ┌──────────────┐
 │ aptos binary │                      │ move-compiler │
 │ (external)   │                      │   (embedded)  │
 └──────────────┘                      └──────────────┘

 Pros:                                 Pros:
 - Always latest compiler              - Self-contained binary
 - Smaller binary                      - No PATH dependency
 - No compiler maintenance             - Faster (no subprocess)
                                       - Better error integration
 Cons:                                 Cons:
 - External dependency                 - Larger binary (~30MB+)
 - subprocess overhead                 - Must track compiler updates
 - Error format mismatch               - Complex build
```

### Implementation Strategy

1. Add `aptos-move-compiler` as an optional dependency behind a feature flag
2. Default to embedded compiler when available
3. Fall back to external CLI if embedded compilation fails
4. Keep external CLI support for users who prefer it

### Feature Flag

```toml
[features]
default = ["embedded-compiler"]
embedded-compiler = ["dep:move-compiler", "dep:move-package"]
external-compiler = []  # use external aptos CLI
```

### Effort Estimate

| Task | Complexity | Lines (est.) |
|------|-----------|-------------|
| Compiler integration | Very High | ~1,200 |
| Error mapping | High | ~400 |
| Feature flag wiring | Medium | ~200 |
| Fallback logic | Medium | ~200 |
| Tests | High | ~500 |
| **Total** | | **~2,500** |

---

## 10. Phase 7 — Plugin System

**Goal:** Allow community-contributed commands and workflows via a
safe, sandboxed plugin system.

### Plugin Architecture

```
 ┌──────────────────────────────────────────────────────────┐
 │                      aptos-cli                           │
 │                                                          │
 │  ┌──────────────────────────────────────────────────┐   │
 │  │              Plugin Manager                       │   │
 │  │                                                   │   │
 │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐          │   │
 │  │  │ Plugin  │  │ Plugin  │  │ Plugin  │  ...      │   │
 │  │  │   A     │  │   B     │  │   C     │          │   │
 │  │  │ (WASM)  │  │ (WASM)  │  │ (WASM)  │          │   │
 │  │  └────┬────┘  └────┬────┘  └────┬────┘          │   │
 │  │       │             │            │               │   │
 │  │       └─────────────┼────────────┘               │   │
 │  │                     ▼                             │   │
 │  │              ┌──────────────┐                     │   │
 │  │              │  Plugin API  │                     │   │
 │  │              │              │                     │   │
 │  │              │  - read()    │  Sandboxed:         │   │
 │  │              │  - write()   │  No FS access       │   │
 │  │              │  - query()   │  No network access  │   │
 │  │              │  - sign()    │  Only via CLI APIs   │   │
 │  │              └──────────────┘                     │   │
 │  └──────────────────────────────────────────────────┘   │
 └──────────────────────────────────────────────────────────┘
```

### Plugin Manifest

```toml
# ~/.aptos/plugins/defi-tools/plugin.toml
[plugin]
name = "defi-tools"
version = "1.0.0"
description = "DeFi interaction helpers"
author = "community"
wasm = "defi_tools.wasm"

[[commands]]
name = "swap"
description = "Token swap via DEX aggregator"
args = ["--from", "--to", "--amount"]

[[commands]]
name = "pool"
description = "Liquidity pool operations"
subcommands = ["add", "remove", "info"]
```

### Plugin Commands

```
plugin
├── install        --url <git-url>      # Install plugin from Git
│                  --name <registry>    # ... or from registry
├── remove         --name <plugin>      # Remove plugin
├── list                                # List installed plugins
├── update         [--name <plugin>]    # Update plugin(s)
└── create         --name <plugin>      # Scaffold new plugin
```

### Effort Estimate

| Task | Complexity | Lines (est.) |
|------|-----------|-------------|
| WASM runtime (wasmtime) | Very High | ~800 |
| Plugin API surface | High | ~600 |
| Plugin manager (install/remove) | Medium | ~400 |
| Plugin manifest parser | Low | ~200 |
| Scaffold/template | Low | ~200 |
| Tests | High | ~500 |
| **Total** | | **~2,700** |

---

## 11. Phase 8 — Keyless Auth & Gas Station

**Goal:** Support OIDC-based keyless authentication and Geomi Gas Station
integration for fee sponsorship.

### Keyless Authentication Flow

```
 User                    CLI                  OIDC Provider     Aptos
 ────                    ───                  ─────────────     ─────
  │                       │                        │              │
  │  credential keyless   │                        │              │
  │──────────────────────▶│                        │              │
  │                       │  open browser          │              │
  │                       │───────────────────────▶│              │
  │                       │                        │              │
  │  Google/Apple login   │                        │              │
  │──────────────────────────────────────────────▶│              │
  │                       │                        │              │
  │                       │◀── JWT token ──────────│              │
  │                       │                        │              │
  │                       │  derive keyless acct   │              │
  │                       │───────────────────────────────────────▶
  │                       │                        │              │
  │                       │  store in vault        │              │
  │                       │  (encrypted JWT +      │              │
  │                       │   ephemeral key)       │              │
  │                       │                        │              │
```

### Gas Station Integration

```
# Configure Gas Station
aptos-cli> config set gas_station_api_key <key>
aptos-cli> config set gas_station_url https://gas.geomi.io

# Use sponsored transactions automatically
aptos-cli> move run --function 0x1::my_module::action --sponsored
  Transaction sponsored by Gas Station
  Gas paid by: 0xSPONSOR
  User gas cost: 0 APT
```

### Effort Estimate

| Task | Complexity | Lines (est.) |
|------|-----------|-------------|
| Keyless auth flow (OAuth + JWT) | Very High | ~800 |
| Browser redirect handler | High | ~300 |
| Vault support for keyless credentials | Medium | ~300 |
| Gas Station API client | Medium | ~400 |
| Sponsored transaction integration | Medium | ~300 |
| Tests | High | ~400 |
| **Total** | | **~2,500** |

---

## 12. Phase 9 — Project Scaffolding & Templates

**Goal:** `aptos-cli init` with pre-built dApp templates.

### Template System

```
aptos-cli> init

  Select a template:

    1. Minimal       — Move module with tests
    2. Token         — Fungible asset with mint/burn/transfer
    3. NFT Collection — Digital asset collection with marketplace
    4. DeFi          — AMM pool with swap/liquidity functions
    5. Governance    — On-chain voting and proposal system
    6. Custom        — Blank project

  Template: 2

  Project name: my_token
  Named address: my_token_addr

  Creating project...
    ✓ Move.toml
    ✓ sources/token.move
    ✓ sources/token_events.move
    ✓ tests/token_tests.move
    ✓ scripts/deploy.aptos
    ✓ scripts/mint.aptos
    ✓ .gitignore

  Done! Next steps:
    cd my_token
    aptos-cli move test --named-addresses my_token_addr=0xcafe
```

### Template Registry

```
 ┌──────────────────────────────────────┐
 │          Template Registry           │
 │                                      │
 │  Built-in:                           │
 │    minimal, token, nft, defi, gov    │
 │                                      │
 │  Community (GitHub):                 │
 │    aptos-templates/marketplace       │
 │    aptos-templates/bridge            │
 │    user/custom-template              │
 │                                      │
 │  Local:                              │
 │    ~/.aptos/templates/my_template    │
 └──────────────────────────────────────┘
```

### Effort Estimate

| Task | Complexity | Lines (est.) |
|------|-----------|-------------|
| Template engine | Medium | ~400 |
| Built-in templates (5) | Medium | ~1,000 |
| Git-based template fetching | Medium | ~300 |
| Interactive template wizard | Low | ~200 |
| Tests | Low | ~300 |
| **Total** | | **~2,200** |

---

## 13. Distribution Plan

### Channels

| Channel | Phase | Priority |
|---------|-------|----------|
| **GitHub Releases** | 0 (now) | Pre-built binaries for all platforms |
| **`cargo install`** | 1 | `cargo install aptos-cli` from crates.io |
| **Homebrew** | 1 | `brew install aptos-cli` tap |

### Platform Matrix

```
 Platform              Arch      GLIBC    TLS Backend     Status
 ────────              ────      ─────    ───────────     ──────
 Linux (Ubuntu 22.04+) x86_64   2.35+    OpenSSL 3.x     ✓ shipping
 Linux (Ubuntu 22.04+) x86_64   2.35+    OpenSSL 3.x     ✓ no-SIMD variant
 Linux (Ubuntu 24.04+) ARM64    2.39+    OpenSSL 3.x     ✓ shipping
 macOS 15+             x86_64   N/A      Security.fmwk   ✓ shipping
 macOS 14+             ARM64    N/A      Security.fmwk   ✓ shipping
 Windows 10+           x86_64   N/A      Schannel        ✓ shipping
```

### Homebrew Tap

```ruby
# homebrew-aptos/Formula/aptos-cli.rb
class AptosCli < Formula
  desc "Modern CLI for Aptos blockchain development"
  homepage "https://github.com/aptos-labs/aptos-rust-sdk"
  version "0.2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/.../aptos-cli-v0.2.0-macos-arm64.zip"
      sha256 "..."
    else
      url "https://github.com/.../aptos-cli-v0.2.0-macos-x86_64.zip"
      sha256 "..."
    end
  end

  on_linux do
    url "https://github.com/.../aptos-cli-v0.2.0-linux-x86_64.zip"
    sha256 "..."
  end

  def install
    bin.install "aptos-cli"
  end

  test do
    system "#{bin}/aptos-cli", "--version"
  end
end
```

### Auto-Update

```
aptos-cli> version
  aptos-cli 0.2.0

  A new version is available: 0.3.0
  Run `aptos-cli self update` or `brew upgrade aptos-cli`
```

---

## 14. Security Model

### Threat Model

```
 ┌─────────────────────────────────────────────────────────────┐
 │                     THREAT MODEL                             │
 │                                                             │
 │  Asset               │  Threat                   │ Mitigation│
 │  ─────               │  ──────                   │ ──────────│
 │  Private keys         │  Disk theft              │ AES-256   │
 │  (vault.json)         │  Memory dump             │ Zeroize   │
 │                       │  Brute-force password    │ Argon2id  │
 │                       │  Weak password           │ Min 12chr │
 │                       │                          │ Complexity│
 │                                                             │
 │  Session state        │  Process memory           │ Zeroize   │
 │  (in-memory keys)     │  Core dump                │ No core   │
 │                       │  Swap file                │ mlock     │
 │                                                             │
 │  Command history      │  Credential leakage      │ Filter    │
 │  (~/.aptos/history)   │                          │ Detection │
 │                       │                          │ 0o600     │
 │                                                             │
 │  Config files         │  API key theft           │ 0o600     │
 │  (settings.json)      │  Directory traversal     │ 0o700 dir │
 │                                                             │
 │  External CLI         │  Command injection       │ Validate  │
 │  (aptos binary)       │  (named addresses)       │ Sanitize  │
 │                       │  PATH manipulation       │ Abs path  │
 └─────────────────────────────────────────────────────────────┘
```

### Encryption Details

```
 Password
    │
    ▼
 ┌──────────────────┐
 │    Argon2id       │  256 MiB memory
 │    KDF            │  4 iterations
 │                   │  1 parallelism
 │  salt (32 bytes)  │  32-byte output
 └────────┬─────────┘
          │ 256-bit key
          ▼
 ┌──────────────────┐
 │   AES-256-GCM     │
 │                   │  Per-entry nonce (12 bytes)
 │  plaintext key ──▶│──▶ ciphertext + tag
 └──────────────────┘

 Storage: vault.json
 ┌─────────────────────────────────┐
 │  {                               │
 │    "version": 1,                 │
 │    "salt": "<base64>",           │
 │    "entries": {                  │
 │      "alice": {                  │
 │        "key_type": "ed25519",    │
 │        "nonce": "<base64>",      │
 │        "ciphertext": "<base64>"  │
 │      }                           │
 │    }                             │
 │  }                               │
 └─────────────────────────────────┘
```

### Security Audit Status

All findings from the initial security audit have been remediated:

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| CRIT-001 | Critical | Vulnerable `aes-gcm` version | Fixed (>=0.10.3) |
| HIGH-001 | High | Config files world-readable | Fixed (0o600) |
| HIGH-002 | High | Private keys in argv not zeroized | Fixed |
| HIGH-003 | High | Bulk key exposure during pw change | Fixed |
| MED-001 | Medium | Weak Argon2id parameters | Fixed (256MiB/4iter) |
| MED-002 | Medium | Insufficient history filtering | Fixed |
| MED-003 | Medium | Command injection via named addrs | Fixed |
| MED-004 | Medium | Config dir permissions | Fixed (0o700) |
| MED-005 | Medium | Key material in error messages | Fixed |
| LOW-001 | Low | Weak password requirements | Fixed (12+ chars) |
| LOW-002 | Low | No rate limiting on unlock | Fixed (exp backoff) |
| LOW-003 | Low | History file permissions | Fixed (0o600) |
| LOW-004 | Low | Imported keys not zeroized | Fixed (Drop impl) |

---

## 15. Data Flow Diagrams

### REPL Session Lifecycle

```
 ┌──────────────┐
 │   Start CLI  │
 └──────┬───────┘
        │
        ▼
 ┌──────────────┐     ┌──────────────────────────────────┐
 │ Load Config  │────▶│  ~/.aptos/config/settings.json   │
 └──────┬───────┘     └──────────────────────────────────┘
        │
        ▼
 ┌──────────────┐  no   ┌──────────────┐
 │ Vault exists?│──────▶│  Onboarding  │
 └──────┬───────┘       │  Flow        │
        │ yes           │              │
        ▼               │  1. Detect   │
 ┌──────────────┐       │     legacy   │
 │ Unlock Vault │       │     config   │
 │  (password)  │       │  2. Import   │
 │              │       │     or       │
 │  max 5 tries │       │     generate │
 │  exp backoff │       │  3. Create   │
 └──────┬───────┘       │     vault    │
        │               └──────┬───────┘
        │◀─────────────────────┘
        ▼
 ┌──────────────┐
 │ Activate     │  from config.default_account
 │ Account      │
 └──────┬───────┘
        │
        ▼
 ┌──────────────────────────────────────────────────────────┐
 │                     REPL MAIN LOOP                       │
 │                                                          │
 │  ┌──────────────┐                                       │
 │  │ Render Prompt │  [testnet:alice] >>>                  │
 │  └──────┬───────┘                                       │
 │         │                                               │
 │         ▼                                               │
 │  ┌──────────────┐                                       │
 │  │ Read Line    │  rustyline + history                  │
 │  └──────┬───────┘                                       │
 │         │                                               │
 │         ▼                                               │
 │  ┌──────────────┐                                       │
 │  │ Parse Args   │  shellwords split                    │
 │  └──────┬───────┘                                       │
 │         │                                               │
 │         ▼                                               │
 │  ┌──────────────┐  ┌───────────────────────────────┐   │
 │  │ Auto-Inject  │──│ --private-key (if signing)    │   │
 │  │ from session │  │ --address (if read-only)      │   │
 │  │              │  │ --sender (if simulate)        │   │
 │  │              │  │ --network, --api-key, --json  │   │
 │  └──────┬───────┘  └───────────────────────────────┘   │
 │         │                                               │
 │         ▼                                               │
 │  ┌──────────────┐                                       │
 │  │ Dispatch Cmd │──▶ clap parse + execute              │
 │  └──────┬───────┘                                       │
 │         │                                               │
 │         ▼                                               │
 │  ┌──────────────┐                                       │
 │  │ Zeroize argv │  clear sensitive args from memory    │
 │  └──────┬───────┘                                       │
 │         │                                               │
 │         ▼                                               │
 │  ┌──────────────┐  ┌───────────────────────────────┐   │
 │  │ Save History │──│ filter secrets, save to disk  │   │
 │  └──────┬───────┘  └───────────────────────────────┘   │
 │         │                                               │
 │         └──────────────▶ (loop back to prompt)          │
 │                                                          │
 └──────────────────────────────────────────────────────────┘
```

### Transaction Signing Flow

```
 User types:  move run --function 0x1::module::func --args u64:100

        │
        ▼
 ┌──────────────────┐
 │  REPL detects:   │
 │  cmd = "run"     │
 │  needs signing   │
 │  no --private-key│
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐     ┌───────────────────┐
 │  Vault lookup    │────▶│  Decrypt key with │
 │  (active alias)  │     │  session cipher   │
 └────────┬─────────┘     └───────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  Inject args:    │
 │  --private-key X │
 │  --key-type Y    │
 │  --network Z     │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐
 │  clap parse      │
 │  → RunArgs       │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐     ┌───────────────────┐
 │  load_account()  │────▶│  SDK Account      │
 │  from private key│     │  (Ed25519/etc.)   │
 └────────┬─────────┘     └───────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  Build payload   │  EntryFunction::from_function_id()
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐
 │  sign_submit_    │  SDK handles:
 │  and_wait()      │  - sequence number
 │                  │  - gas estimation
 │                  │  - signing
 │                  │  - submission
 │                  │  - polling for result
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐
 │  Display result  │  success/fail, hash, gas used
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐
 │  Zeroize argv    │  wipe private key from memory
 └──────────────────┘
```

---

## 16. Decision Log

Key architectural decisions and their rationale:

| # | Decision | Options Considered | Choice | Rationale |
|---|----------|-------------------|--------|-----------|
| D1 | Command structure | Drop-in replacement for official CLI vs. own design | **Own design** | Optimize for REPL ergonomics, not compatibility |
| D2 | Move compiler | Embedded vs. external wrapper | **External now, embed later** (Phase 6) | Keeps binary small, always latest compiler |
| D3 | Plugin system | WASM vs. native vs. scripts | **WASM** (Phase 7) | Safe sandboxing, portable, community-friendly |
| D4 | Multi-account | Full from start vs. phased | **Phased** | Basic first (Phase 0), multi-sig/sponsored in Phase 3 |
| D5 | Indexer | Full vs. basic vs. none | **Full** (Phase 1) | Critical for dApp developers |
| D6 | Scripting | Full DSL vs. basic batch vs. pipe | **Full DSL** (Phase 2) | CI/CD, repeatable workflows, testing |
| D7 | Keyless auth | Now vs. later vs. never | **Later** (Phase 8) | Architecture planned, complex OAuth flow |
| D8 | Gas Station | Native vs. generic | **Later** (Phase 8) | Plan with keyless, Geomi integration |
| D9 | Watch mode | Built-in vs. external (`watchexec`) | **Built-in** (Phase 4) | Tight integration with compile+test loop |
| D10 | Distribution | GitHub only vs. multi-channel | **Homebrew + cargo + GH Releases** | Developer reach, easy install |
| D11 | Testing | Basic vs. full framework | **Phased** | Start with move test, add gas profiling later |
| D12 | Project templates | Now vs. later | **Later** (Phase 9) | Focus on core dev workflow first |
| D13 | Binary name | aptos-repl vs. aptos-cli vs. apt | **aptos-cli** | Recognizable, authoritative, discoverable |
| D14 | Credential storage | Plaintext vs. encrypted | **Encrypted** (AES-256-GCM + Argon2id) | Security by default |
| D15 | Localnet management | Built-in vs. wrap external | **Wrap external** `aptos node run-localnet` | Avoid duplicating complex node logic |

---

## Appendix A — Phase Roadmap Summary

```
 Phase  Description                      Effort    Dependencies
 ─────  ───────────                      ──────    ────────────
   0    Current state (complete)         ~6,000L   —
   1    Indexer + Transaction Explorer   ~1,700L   SDK indexer feature
   2    Scripting Engine                 ~2,350L   Phase 0
   3    Advanced Account Workflows       ~3,000L   Phase 0
   4    Watch Mode + DX                  ~1,850L   Phase 0, notify crate
   5    Rich Testing Framework           ~2,150L   Phase 2 (for integration)
   6    Embedded Move Compiler           ~2,500L   move-compiler crate
   7    Plugin System                    ~2,700L   wasmtime crate
   8    Keyless Auth + Gas Station       ~2,500L   SDK keyless, Geomi API
   9    Project Scaffolding              ~2,200L   Phase 2 (deploy scripts)
                                         ────────
                                   Total: ~27,000L additional
```

```
 Timeline (suggested)
 ────────────────────

 Q1 2026  ██████████  Phase 1 (Indexer) + Phase 4 (Watch Mode)
 Q2 2026  ██████████  Phase 2 (Scripting) + Phase 3 (Multi-Account)
 Q3 2026  ██████████  Phase 5 (Testing) + Phase 6 (Compiler)
 Q4 2026  ██████████  Phase 7 (Plugins) + Phase 8 (Keyless/Gas)
 Q1 2027  ██████████  Phase 9 (Templates) + polish + 1.0 release
```

---

## Appendix B — File Storage Layout

```
~/.aptos/
├── credentials/
│   └── vault.json           # Encrypted private keys (0o600)
├── config/
│   └── settings.json        # Persistent configuration (0o600)
├── history                  # REPL command history (0o600, secrets filtered)
├── scripts/                 # [Phase 2] User scripts (.aptos files)
├── plugins/                 # [Phase 7] Installed plugins
│   └── <plugin-name>/
│       ├── plugin.toml
│       └── plugin.wasm
└── templates/               # [Phase 9] Custom project templates
    └── <template-name>/
        └── ...
```

---

## Appendix C — Command Reference (Full Planned Surface)

```
aptos-cli [global-opts] <command>

Global Options:
  --network <net>       Network: mainnet, testnet, devnet, local
  --node-url <url>      Custom fullnode URL
  --api-key <key>       API key for authenticated access
  --json                JSON output mode
  --file <path>         [Phase 2] Run script file
  --verbose             Verbose output

Account Commands:
  account create        Generate new account keypair
  account fund          Fund account via faucet
  account balance       Check APT balance
  account lookup        Look up account info
  account resources     List all resources
  account resource      Get specific resource
  account modules       List deployed modules
  account transfer      Transfer APT/coins

Key Commands:
  key generate          Generate random keypair
  key from-mnemonic     Derive key from mnemonic
  key show              Show address/pubkey from private key

Move Commands:
  move init             Initialize Move package
  move compile          Compile Move package
  move test             Run Move unit tests
  move view             Call view function
  move run              Execute entry function
  move publish          Publish compiled package
  move build-publish    Compile + publish
  move inspect          Inspect module ABI
  move watch            [Phase 4] Watch + auto-compile

Transaction Commands:
  transaction lookup    Look up transaction by hash
  transaction simulate  Simulate transaction
  transaction sponsor   [Phase 3] Create sponsored txn

Info Commands:
  info ledger           Current ledger info
  info gas-price        Gas price estimates
  info block            Block by height/version

Indexer Commands:                          [Phase 1]
  indexer tokens        Token/NFT listing
  indexer balances      Fungible asset balances
  indexer history       Transaction history
  indexer events        Event stream
  indexer query         Raw GraphQL query

Multi-sig Commands:                        [Phase 3]
  multisig create       Create multi-sig account
  multisig propose      Propose transaction
  multisig approve      Approve proposal
  multisig reject       Reject proposal
  multisig execute      Execute approved txn
  multisig pending      List pending proposals
  multisig info         Multi-sig config

Batch Commands:                            [Phase 3]
  batch transfer        Batch transfers from CSV
  batch run             Run batch script
  batch submit          Submit pre-built txns

Test Commands:                             [Phase 5]
  test unit             Run unit tests
  test gas-profile      Profile gas usage
  test verify-deploy    Verify deployed code
  test integration      Run integration tests
  test benchmark        Benchmark function

Node Commands:                             [Phase 4]
  node start            Start localnet
  node stop             Stop localnet
  node status           Check status
  node reset            Reset state
  node logs             View logs

Plugin Commands:                           [Phase 7]
  plugin install        Install plugin
  plugin remove         Remove plugin
  plugin list           List plugins
  plugin update         Update plugins
  plugin create         Scaffold new plugin

REPL-Only Commands:
  credential init       Create new vault
  credential unlock     Unlock vault
  credential lock       Lock vault
  credential add        Add credential
  credential generate   Generate + add credential
  credential remove     Remove credential
  credential list       List credentials
  credential import     Import legacy profiles
  credential keyless    [Phase 8] Keyless auth flow
  use <alias>           Set active account
  whoami                Show active account
  network <name>        Switch network
  config <sub>          Persistent settings
  help                  Show help
  quit / exit           Exit REPL
```
