# Account Management

## Overview

The account management module provides abstractions for Aptos accounts, including key management, address derivation, and signing capabilities. It wraps cryptographic primitives with a user-friendly interface.

## Goals

1. Provide unified `Account` trait for all account types
2. Support multiple signature schemes transparently
3. Enable easy account creation from various sources
4. Secure key handling with proper memory management

## Non-Goals

- Wallet UI functionality
- Key storage/persistence (users handle this)
- Account state management (handled by API clients)

---

## API Design

### Account Trait

```rust
/// Common interface for all account types.
pub trait Account: Send + Sync {
    /// Get the account's address.
    fn address(&self) -> AccountAddress;
    
    /// Get the public key bytes.
    fn public_key_bytes(&self) -> Vec<u8>;
    
    /// Get the signature scheme.
    fn signature_scheme(&self) -> SignatureScheme;
    
    /// Sign arbitrary bytes.
    fn sign(&self, message: &[u8]) -> Vec<u8>;
    
    /// Get the authentication key.
    fn authentication_key(&self) -> AuthenticationKey;
}
```

### AuthenticationKey

```rust
/// 32-byte authentication key derived from public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthenticationKey([u8; 32]);

impl AuthenticationKey {
    /// Derive from Ed25519 public key.
    #[cfg(feature = "ed25519")]
    pub fn from_ed25519(public_key: &Ed25519PublicKey) -> Self;
    
    /// Derive from Secp256k1 public key.
    #[cfg(feature = "secp256k1")]
    pub fn from_secp256k1(public_key: &Secp256k1PublicKey) -> Self;
    
    /// Derive from any public key bytes and scheme.
    pub fn from_public_key(bytes: &[u8], scheme: SignatureScheme) -> Self;
    
    /// Get the derived account address.
    pub fn account_address(&self) -> AccountAddress;
    
    /// Get raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32];
    
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self;
}
```

### Ed25519Account

```rust
/// Single-key Ed25519 account.
#[cfg(feature = "ed25519")]
pub struct Ed25519Account {
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    address: AccountAddress,
}

impl Ed25519Account {
    /// Generate a new random account.
    pub fn generate() -> Self;
    
    /// Create from a private key.
    pub fn from_private_key(private_key: Ed25519PrivateKey) -> Self;
    
    /// Create from private key hex string.
    pub fn from_private_key_hex(hex: &str) -> Result<Self, AptosError>;
    
    /// Create from private key bytes.
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self, AptosError>;
    
    /// Create from mnemonic with default path.
    pub fn from_mnemonic(mnemonic: &Mnemonic) -> Result<Self, AptosError>;
    
    /// Create from mnemonic with custom derivation path.
    pub fn from_mnemonic_with_path(
        mnemonic: &Mnemonic,
        path: &str,
    ) -> Result<Self, AptosError>;
    
    /// Get the address.
    pub fn address(&self) -> AccountAddress;
    
    /// Get the public key.
    pub fn public_key(&self) -> &Ed25519PublicKey;
    
    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature;
    
    /// Sign a transaction (applies domain separator).
    pub fn sign_transaction(&self, raw_txn: &RawTransaction) -> SignedTransaction;
}

impl Account for Ed25519Account { ... }
```

### Secp256k1Account

```rust
/// Single-key Secp256k1 account.
#[cfg(feature = "secp256k1")]
pub struct Secp256k1Account {
    private_key: Secp256k1PrivateKey,
    public_key: Secp256k1PublicKey,
    address: AccountAddress,
}

impl Secp256k1Account {
    /// Generate a new random account.
    pub fn generate() -> Self;
    
    /// Create from a private key.
    pub fn from_private_key(private_key: Secp256k1PrivateKey) -> Self;
    
    /// Create from private key hex string.
    pub fn from_private_key_hex(hex: &str) -> Result<Self, AptosError>;
    
    /// Create from mnemonic with default path.
    pub fn from_mnemonic(mnemonic: &Mnemonic) -> Result<Self, AptosError>;
    
    // ... same interface as Ed25519Account
}

impl Account for Secp256k1Account { ... }
```

### AnyAccount (Type-Erased)

```rust
/// Type-erased account for dynamic dispatch.
pub enum AnyAccount {
    #[cfg(feature = "ed25519")]
    Ed25519(Ed25519Account),
    
    #[cfg(feature = "secp256k1")]
    Secp256k1(Secp256k1Account),
    
    // ... other variants
}

impl AnyAccount {
    /// Create from Ed25519 account.
    #[cfg(feature = "ed25519")]
    pub fn ed25519(account: Ed25519Account) -> Self;
    
    /// Create from Secp256k1 account.
    #[cfg(feature = "secp256k1")]
    pub fn secp256k1(account: Secp256k1Account) -> Self;
}

impl Account for AnyAccount { ... }
```

---

## Implementation Details

### Address Derivation Flow

```
Private Key
    ↓ derive
Public Key
    ↓ hash with scheme
Authentication Key (32 bytes)
    ↓ (identity for new accounts)
Account Address (32 bytes)
```

### Mnemonic Derivation Flow

```
Mnemonic Phrase (12-24 words)
    ↓ + passphrase (optional)
Seed (64 bytes via PBKDF2)
    ↓ BIP-44 derivation
Private Key
    ↓
Account (as above)
```

### Default Derivation Paths

| Account Type | Default Path |
|--------------|--------------|
| Ed25519 | `m/44'/637'/0'/0'/0'` |
| Secp256k1 | `m/44'/637'/0'/0'/0'` |
| Secp256r1 | `m/44'/637'/0'/0'/0'` |

---

## Usage Examples

### Creating Accounts

```rust
use aptos_sdk::account::{Ed25519Account, Mnemonic, Account};

// Generate random
let account = Ed25519Account::generate();
println!("Address: {}", account.address());

// From private key hex
let account = Ed25519Account::from_private_key_hex(
    "0x1234567890abcdef..."
)?;

// From mnemonic
let mnemonic = Mnemonic::generate(12)?;
println!("Save this: {}", mnemonic.phrase());
let account = Ed25519Account::from_mnemonic(&mnemonic)?;

// From mnemonic with custom path (multiple accounts)
let account_0 = Ed25519Account::from_mnemonic_with_path(&mnemonic, "m/44'/637'/0'/0'/0'")?;
let account_1 = Ed25519Account::from_mnemonic_with_path(&mnemonic, "m/44'/637'/0'/0'/1'")?;
```

### Using the Account Trait

```rust
fn sign_message(account: &dyn Account, message: &[u8]) -> Vec<u8> {
    account.sign(message)
}

// Works with any account type
let ed25519 = Ed25519Account::generate();
let sig1 = sign_message(&ed25519, b"hello");

let secp = Secp256k1Account::generate();
let sig2 = sign_message(&secp, b"hello");
```

### Dynamic Account Selection

```rust
use aptos_sdk::account::AnyAccount;

fn load_account(config: &Config) -> AnyAccount {
    match config.key_type.as_str() {
        "ed25519" => AnyAccount::ed25519(
            Ed25519Account::from_private_key_hex(&config.private_key).unwrap()
        ),
        "secp256k1" => AnyAccount::secp256k1(
            Secp256k1Account::from_private_key_hex(&config.private_key).unwrap()
        ),
        _ => panic!("Unknown key type"),
    }
}
```

---

## Error Handling

| Error | Cause |
|-------|-------|
| `InvalidPrivateKey` | Malformed private key bytes |
| `InvalidMnemonic` | Bad mnemonic phrase |
| `InvalidDerivationPath` | Malformed BIP-44 path |
| `KeyDerivationFailed` | Path derivation error |
| `UnsupportedScheme` | Requested scheme not compiled |

---

## Testing Requirements

### Unit Tests

```rust
#[test]
fn test_generate_unique_accounts() {
    let a1 = Ed25519Account::generate();
    let a2 = Ed25519Account::generate();
    assert_ne!(a1.address(), a2.address());
}

#[test]
fn test_deterministic_from_mnemonic() {
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ).unwrap();
    
    let a1 = Ed25519Account::from_mnemonic(&mnemonic).unwrap();
    let a2 = Ed25519Account::from_mnemonic(&mnemonic).unwrap();
    
    assert_eq!(a1.address(), a2.address());
}

#[test]
fn test_different_paths_different_addresses() {
    let mnemonic = Mnemonic::generate(12).unwrap();
    
    let a0 = Ed25519Account::from_mnemonic_with_path(&mnemonic, "m/44'/637'/0'/0'/0'").unwrap();
    let a1 = Ed25519Account::from_mnemonic_with_path(&mnemonic, "m/44'/637'/0'/0'/1'").unwrap();
    
    assert_ne!(a0.address(), a1.address());
}

#[test]
fn test_sign_verify_roundtrip() {
    let account = Ed25519Account::generate();
    let message = b"test message";
    
    let signature = account.sign(message);
    assert!(account.public_key().verify(message, &signature));
}

#[test]
fn test_account_trait_object() {
    let ed25519: Box<dyn Account> = Box::new(Ed25519Account::generate());
    let secp256k1: Box<dyn Account> = Box::new(Secp256k1Account::generate());
    
    // Both can be used through trait
    assert_eq!(ed25519.signature_scheme(), SignatureScheme::Ed25519);
    assert_eq!(secp256k1.signature_scheme(), SignatureScheme::Secp256k1);
}
```

### Cross-SDK Compatibility Tests

Verify addresses match TypeScript SDK for same inputs:

```rust
#[test]
fn test_typescript_sdk_compatibility() {
    // Test vector from TypeScript SDK
    let mnemonic = Mnemonic::from_phrase("...").unwrap();
    let account = Ed25519Account::from_mnemonic(&mnemonic).unwrap();
    
    // This address should match what TS SDK produces
    assert_eq!(
        account.address().to_hex(),
        "0x..."  // Expected from TS SDK
    );
}
```

---

## Security Considerations

### Private Key Handling

1. **Memory Zeroization**: Private keys zeroized on drop
2. **No Display/Debug**: Private keys don't implement Display/Debug
3. **No Serialize**: Private keys don't implement Serialize by default
4. **Clone Explicit**: Cloning requires explicit `.clone()` call

### Mnemonic Security

1. **Entropy**: Use cryptographic RNG for generation
2. **Checksum**: Validate mnemonic checksum on parse
3. **Memory**: Zeroize seed after derivation

### Address Security

1. **Validation**: Always validate addresses before use
2. **No Arithmetic**: Don't perform arithmetic on addresses

---

## Dependencies

### External Crates
- `rand`: Random number generation
- `zeroize`: Secure memory zeroization
- Crypto crates (per feature flag)

### Internal Modules
- `crypto`: Key types and signing
- `types`: `AccountAddress`, `AuthenticationKey`

---

## Open Questions

1. ~~Should Account trait require Sync?~~ (Decided: Yes, for async usage)
2. ~~Should we support key export?~~ (Decided: Yes, with clear warnings)
3. Should we add account serialization? (Decided: No, security risk)

