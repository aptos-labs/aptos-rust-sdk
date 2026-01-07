# Testing Strategy

## Overview

Comprehensive testing approach for the SDK including unit tests, behavioral tests, and E2E tests against localnet.

## Goals

1. High code coverage (>80%)
2. Catch regressions early
3. Validate real network behavior
4. Document expected behavior through tests

## Non-Goals

- Performance benchmarks (separate effort)
- Fuzzing (future enhancement)

---

## Test Categories

### 1. Unit Tests

Location: `src/**/tests.rs` or `#[cfg(test)]` modules

**Coverage:**
- Type serialization/deserialization
- Cryptographic operations
- Address parsing and formatting
- Builder validation
- Error handling

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_address_from_hex() {
        let addr = AccountAddress::from_hex("0x1").unwrap();
        assert_eq!(addr, AccountAddress::ONE);
    }
}
```

### 2. Behavioral Tests

Location: `tests/behavior/`

**Purpose:** Test SDK workflows without network access

```rust
// tests/behavior/account_creation.rs
#[test]
fn test_mnemonic_produces_deterministic_account() {
    let phrase = "abandon abandon abandon...";
    let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
    
    let account1 = Ed25519Account::from_mnemonic(&mnemonic).unwrap();
    let account2 = Ed25519Account::from_mnemonic(&mnemonic).unwrap();
    
    assert_eq!(account1.address(), account2.address());
}

#[test]
fn test_transaction_building_workflow() {
    let sender = Ed25519Account::generate();
    let recipient = Ed25519Account::generate();
    
    let payload = EntryFunction::apt_transfer(recipient.address(), 100).unwrap();
    let raw_txn = TransactionBuilder::new()
        .sender(sender.address())
        .sequence_number(0)
        .payload(payload.into())
        .chain_id(ChainId::TESTNET)
        .expiration_from_now(600)
        .build()
        .unwrap();
    
    let signed = sign_transaction(&raw_txn, &sender).unwrap();
    assert!(!signed.to_bytes().is_empty());
}
```

### 3. E2E Tests (Localnet)

Location: `tests/e2e/`

**Prerequisites:**
- Aptos CLI installed
- Docker (optional, for containerized localnet)

```rust
// tests/e2e/transfer.rs
use aptos_rust_sdk_v2::testing::LocalNet;

#[tokio::test]
async fn test_apt_transfer_e2e() {
    // Start localnet
    let localnet = LocalNet::start().await.unwrap();
    let aptos = Aptos::new(localnet.config()).await.unwrap();
    
    // Create and fund accounts
    let sender = aptos.create_funded_account(100_000_000).await.unwrap();
    let recipient = Ed25519Account::generate();
    
    // Transfer
    let payload = EntryFunction::apt_transfer(recipient.address(), 1_000_000).unwrap();
    let result = aptos.sign_submit_and_wait(&sender, payload.into(), None).await.unwrap();
    
    assert!(result.success());
    
    // Verify balance
    let balance = aptos.get_balance(recipient.address()).await.unwrap();
    assert_eq!(balance, 1_000_000);
}
```

### 4. Integration Tests (Testnet)

Location: `tests/integration/`

**Note:** These require network access and are marked `#[ignore]`

```rust
#[tokio::test]
#[ignore = "requires testnet access"]
async fn test_view_function_on_testnet() {
    let aptos = Aptos::new(AptosConfig::testnet()).await.unwrap();
    
    let result = aptos.view(
        "0x1::coin::supply",
        vec!["0x1::aptos_coin::AptosCoin".to_string()],
        vec![],
    ).await.unwrap();
    
    assert!(!result.is_empty());
}
```

---

## Test Infrastructure

### LocalNet Helper

```rust
/// Manages a local Aptos network for testing.
pub struct LocalNet {
    process: Child,
    config: AptosConfig,
}

impl LocalNet {
    /// Start a new localnet instance.
    pub async fn start() -> Result<Self, AptosError> {
        // Run: aptos node run-local-testnet --with-faucet
        let process = Command::new("aptos")
            .args(["node", "run-local-testnet", "--with-faucet"])
            .spawn()?;
        
        // Wait for startup
        Self::wait_for_ready().await?;
        
        Ok(Self {
            process,
            config: AptosConfig::localnet(),
        })
    }
    
    /// Get configuration for this localnet.
    pub fn config(&self) -> AptosConfig {
        self.config.clone()
    }
}

impl Drop for LocalNet {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}
```

### Test Fixtures

```rust
/// Common test fixtures.
pub mod fixtures {
    /// Known test mnemonic (DO NOT USE IN PRODUCTION).
    pub const TEST_MNEMONIC: &str = 
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    /// Expected address for test mnemonic.
    pub const TEST_ADDRESS: &str = "0x...";
    
    /// Create a test account with known keys.
    pub fn test_account() -> Ed25519Account {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC).unwrap();
        Ed25519Account::from_mnemonic(&mnemonic).unwrap()
    }
}
```

---

## CI Configuration

```yaml
# .github/workflows/ci.yml
test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    
    # Unit and behavioral tests
    - name: Run tests
      run: cargo test --all-targets
    
    # Feature combination tests
    - name: Test feature combinations
      run: |
        cargo test -p aptos-rust-sdk-v2 --no-default-features --features ed25519
        cargo test -p aptos-rust-sdk-v2 --features full

e2e-tests:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    
    - name: Install Aptos CLI
      run: |
        curl -fsSL "https://aptos.dev/scripts/install_cli.py" | python3
    
    - name: Run E2E tests
      run: cargo test --test e2e -- --test-threads=1
```

---

## Coverage Goals

| Module | Target | Current |
|--------|--------|---------|
| types | 90% | TBD |
| crypto | 85% | TBD |
| account | 85% | TBD |
| transaction | 80% | TBD |
| api | 75% | TBD |

---

## Test Naming Convention

```rust
// Unit tests: test_<what>_<condition>_<expected>
#[test]
fn test_address_from_hex_valid_returns_address() { }

#[test]
fn test_address_from_hex_invalid_returns_error() { }

// Behavioral tests: test_<workflow>
#[test]
fn test_account_creation_from_mnemonic() { }

// E2E tests: test_<feature>_e2e
#[tokio::test]
async fn test_transfer_e2e() { }
```

