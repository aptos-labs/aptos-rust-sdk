# Feature Plan: Secp256r1 / P-256 / WebAuthn Support

## Overview

Secp256r1 (also known as P-256 or prime256v1) is the elliptic curve commonly used in WebAuthn/Passkey implementations for browser-based authentication. This feature provides full support for Secp256r1 accounts in the Aptos SDK.

## Goals

1. **Full cryptographic support** - Key generation, signing, verification
2. **Account abstraction** - `Secp256r1Account` implementing the `Account` trait
3. **Transaction signing** - Sign transactions with Secp256r1 keys
4. **Multi-key support** - Use Secp256r1 in multi-key accounts
5. **WebAuthn compatibility** - Compatible with browser Passkey implementations

## Cryptographic Primitives (Already Implemented)

### Secp256r1PrivateKey

```rust
pub struct Secp256r1PrivateKey { ... }

impl Secp256r1PrivateKey {
    pub fn generate() -> Self;
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self>;
    pub fn from_hex(hex_str: &str) -> AptosResult<Self>;
    pub fn to_bytes(&self) -> [u8; 32];
    pub fn to_hex(&self) -> String;
    pub fn public_key(&self) -> Secp256r1PublicKey;
    pub fn sign(&self, message: &[u8]) -> Secp256r1Signature;
    pub fn sign_prehashed(&self, hash: &[u8; 32]) -> Secp256r1Signature;
}
```

### Secp256r1PublicKey

```rust
pub struct Secp256r1PublicKey { ... }

impl Secp256r1PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self>;
    pub fn from_hex(hex_str: &str) -> AptosResult<Self>;
    pub fn to_bytes(&self) -> Vec<u8>;  // 33 bytes compressed
    pub fn to_uncompressed_bytes(&self) -> Vec<u8>;  // 65 bytes
    pub fn to_hex(&self) -> String;
    pub fn verify(&self, message: &[u8], signature: &Secp256r1Signature) -> AptosResult<()>;
    pub fn to_address(&self) -> AccountAddress;
}
```

### Secp256r1Signature

```rust
pub struct Secp256r1Signature { ... }

impl Secp256r1Signature {
    pub fn from_bytes(bytes: &[u8]) -> AptosResult<Self>;  // 64 bytes
    pub fn from_hex(hex_str: &str) -> AptosResult<Self>;
    pub fn to_bytes(&self) -> [u8; 64];
    pub fn to_hex(&self) -> String;
}
```

## New: Secp256r1Account

```rust
/// A Secp256r1 (P-256) ECDSA account for signing transactions.
pub struct Secp256r1Account {
    private_key: Secp256r1PrivateKey,
    public_key: Secp256r1PublicKey,
    address: AccountAddress,
}

impl Secp256r1Account {
    /// Generates a new random Secp256r1 account.
    pub fn generate() -> Self;

    /// Creates an account from a private key.
    pub fn from_private_key(private_key: Secp256r1PrivateKey) -> Self;

    /// Creates an account from private key bytes.
    pub fn from_private_key_bytes(bytes: &[u8]) -> AptosResult<Self>;

    /// Creates an account from a private key hex string.
    pub fn from_private_key_hex(hex_str: &str) -> AptosResult<Self>;

    /// Returns the account address.
    pub fn address(&self) -> AccountAddress;

    /// Returns the public key.
    pub fn public_key(&self) -> &Secp256r1PublicKey;

    /// Returns a reference to the private key.
    pub fn private_key(&self) -> &Secp256r1PrivateKey;

    /// Signs a message and returns the Secp256r1 signature.
    pub fn sign_message(&self, message: &[u8]) -> Secp256r1Signature;
}

impl Account for Secp256r1Account { ... }
```

## Usage Examples

### Basic Account Usage

```rust
use aptos_rust_sdk_v2::account::Secp256r1Account;

// Generate new account
let account = Secp256r1Account::generate();
println!("Address: {}", account.address());

// Import from private key
let account = Secp256r1Account::from_private_key_hex("0x...")?;
```

### Sign and Submit Transaction

```rust
let aptos = Aptos::testnet()?;
let account = Secp256r1Account::generate();

// Fund the account first (testnet)
aptos.fund_account(account.address(), 100_000_000).await?;

// Sign and submit
let payload = InputEntryFunctionData::transfer_apt(recipient, 1_000_000)?;
let result = aptos.sign_submit_and_wait(&account, payload, None).await?;
```

### Multi-Key Account with Secp256r1

```rust
use aptos_rust_sdk_v2::account::{MultiKeyAccount, AnyPrivateKey};

let secp256r1_key = Secp256r1PrivateKey::generate();
let ed25519_key = Ed25519PrivateKey::generate();

let multi_account = MultiKeyAccount::new(
    vec![
        AnyPrivateKey::secp256r1(secp256r1_key),
        AnyPrivateKey::ed25519(ed25519_key),
    ],
    1,  // threshold
)?;
```

### WebAuthn Integration (Future)

```rust
// Example of how WebAuthn attestation could be used
let webauthn_public_key = Secp256r1PublicKey::from_bytes(&attestation.public_key)?;
let address = webauthn_public_key.to_address();

// Verify WebAuthn signature
let signature = Secp256r1Signature::from_bytes(&assertion.signature)?;
webauthn_public_key.verify(&client_data_json, &signature)?;
```

## Feature Flag

The Secp256r1 support is behind the `secp256r1` feature flag:

```toml
[dependencies]
aptos-rust-sdk-v2 = { version = "0.1", features = ["secp256r1"] }
```

## Key Differences from Other Curves

| Property | Ed25519 | Secp256k1 | Secp256r1 |
|----------|---------|-----------|-----------|
| Private key size | 32 bytes | 32 bytes | 32 bytes |
| Public key (compressed) | 32 bytes | 33 bytes | 33 bytes |
| Signature size | 64 bytes | 64 bytes | 64 bytes |
| Use case | General | Bitcoin/Ethereum | WebAuthn/Passkey |
| NIST approved | No | No | Yes |

## Testing

### Unit Tests

1. **Key generation** - Generate random keys
2. **Key roundtrip** - Serialize/deserialize keys
3. **Signing** - Sign messages
4. **Verification** - Verify signatures
5. **Account trait** - Test Account implementation

### Integration Tests

1. **Transaction signing** - Sign actual transactions
2. **Multi-key accounts** - Use in MultiKeyAccount
3. **Address derivation** - Correct address from public key

## Dependencies

- `p256` crate - P-256 ECDSA implementation
- Feature gated with `secp256r1` feature

## Files Changed

1. `src/account/secp256r1.rs` - New account implementation
2. `src/account/mod.rs` - Export Secp256r1Account
3. `src/crypto/secp256r1.rs` - Fix compressed public key encoding
4. `feature-plans/20-secp256r1-passkey.md` - This document

## Future Enhancements

1. **WebAuthn helpers** - Parse attestation/assertion objects
2. **COSE key parsing** - Parse COSE-encoded public keys
3. **Browser integration** - Utilities for web-based signing
4. **Hardware security** - Support for secure enclaves
5. **Recovery flows** - Account recovery with passkeys

## Security Considerations

1. **Private key handling** - Keys are zeroized on drop
2. **SHA-256 hashing** - Messages are hashed before signing
3. **Compressed format** - Public keys use compressed SEC1 encoding (33 bytes)
4. **NIST standard** - P-256 is a NIST-approved curve

