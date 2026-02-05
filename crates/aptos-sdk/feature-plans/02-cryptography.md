# Cryptography

## Overview

The cryptography module provides signature schemes, key generation, and hashing functions required for Aptos transactions. All cryptographic operations are feature-gated to allow minimal builds.

## Goals

1. Support all Aptos signature schemes (Ed25519, Secp256k1, Secp256r1, BLS)
2. Provide secure key generation and derivation
3. Enable mnemonic-based account recovery
4. Minimize binary size via feature flags

## Non-Goals

- Implementing cryptographic primitives from scratch (use audited libraries)
- Supporting deprecated signature schemes
- Providing encryption (only signing)

---

## Feature Flags

| Feature | Crates Used | Purpose |
|---------|-------------|---------|
| `ed25519` | `ed25519-dalek` | Ed25519 signatures (default) |
| `secp256k1` | `k256` | Secp256k1 ECDSA signatures |
| `secp256r1` | `p256` | P-256/WebAuthn signatures |
| `bls` | `blst` | BLS12-381 signatures |

---

## API Design

### Hash Functions

```rust
/// SHA3-256 hash function.
pub fn sha3_256(data: &[u8]) -> HashValue;

/// Domain-separated hashing with a prefix.
pub fn hash_with_domain(domain: &[u8], data: &[u8]) -> HashValue;

/// Compute authentication key from public key bytes.
pub fn authentication_key(
    scheme: SignatureScheme,
    public_key_bytes: &[u8],
) -> AuthenticationKey;
```

### Signature Scheme Enum

```rust
/// Supported signature schemes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SignatureScheme {
    Ed25519 = 0,
    MultiEd25519 = 1,
    Secp256k1 = 2,
    Secp256r1 = 3,  // P-256 / WebAuthn
    // 4 reserved for MultiKey
    // 5 reserved for Keyless
}
```

### Ed25519 (Feature: `ed25519`)

```rust
pub mod ed25519 {
    /// Ed25519 private key (32 bytes).
    pub struct Ed25519PrivateKey([u8; 32]);
    
    impl Ed25519PrivateKey {
        /// Generate a random private key.
        pub fn generate() -> Self;
        
        /// Create from raw bytes.
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, AptosError>;
        
        /// Create from hex string.
        pub fn from_hex(hex: &str) -> Result<Self, AptosError>;
        
        /// Derive public key.
        pub fn public_key(&self) -> Ed25519PublicKey;
        
        /// Sign a message.
        pub fn sign(&self, message: &[u8]) -> Ed25519Signature;
        
        /// Get raw bytes (SECURITY: handle with care).
        pub fn to_bytes(&self) -> [u8; 32];
    }
    
    impl Drop for Ed25519PrivateKey {
        fn drop(&mut self) {
            // Zeroize memory
        }
    }
    
    /// Ed25519 public key (32 bytes).
    pub struct Ed25519PublicKey([u8; 32]);
    
    impl Ed25519PublicKey {
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, AptosError>;
        pub fn to_bytes(&self) -> [u8; 32];
        pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> bool;
    }
    
    /// Ed25519 signature (64 bytes).
    pub struct Ed25519Signature([u8; 64]);
    
    impl Ed25519Signature {
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, AptosError>;
        pub fn to_bytes(&self) -> [u8; 64];
    }
}
```

### Secp256k1 (Feature: `secp256k1`)

```rust
pub mod secp256k1 {
    /// Secp256k1 private key (32 bytes).
    pub struct Secp256k1PrivateKey { ... }
    
    impl Secp256k1PrivateKey {
        pub fn generate() -> Self;
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, AptosError>;
        pub fn public_key(&self) -> Secp256k1PublicKey;
        pub fn sign(&self, message: &[u8]) -> Secp256k1Signature;
    }
    
    /// Secp256k1 public key (33 bytes compressed).
    pub struct Secp256k1PublicKey { ... }
    
    impl Secp256k1PublicKey {
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, AptosError>;
        pub fn to_bytes(&self) -> Vec<u8>;  // 33 bytes compressed
        pub fn verify(&self, message: &[u8], signature: &Secp256k1Signature) -> bool;
    }
    
    /// Secp256k1 ECDSA signature (64 bytes, non-malleable).
    pub struct Secp256k1Signature { ... }
}
```

### Secp256r1 / P-256 (Feature: `secp256r1`)

```rust
pub mod secp256r1 {
    /// P-256 private key.
    pub struct Secp256r1PrivateKey { ... }
    
    /// P-256 public key.
    pub struct Secp256r1PublicKey { ... }
    
    /// P-256 signature.
    pub struct Secp256r1Signature { ... }
    
    // Same interface as Secp256k1
}
```

### BLS12-381 (Feature: `bls`)

```rust
pub mod bls12381 {
    /// BLS private key.
    pub struct BlsPrivateKey { ... }
    
    impl BlsPrivateKey {
        pub fn generate() -> Self;
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, AptosError>;
        pub fn public_key(&self) -> BlsPublicKey;
        pub fn sign(&self, message: &[u8]) -> BlsSignature;
    }
    
    /// BLS public key (48 bytes compressed G1).
    pub struct BlsPublicKey { ... }
    
    /// BLS signature (96 bytes compressed G2).
    pub struct BlsSignature { ... }
    
    impl BlsSignature {
        /// Aggregate multiple signatures.
        pub fn aggregate(signatures: &[BlsSignature]) -> Self;
    }
    
    impl BlsPublicKey {
        /// Verify aggregated signature against multiple public keys.
        pub fn aggregate_verify(
            public_keys: &[BlsPublicKey],
            messages: &[&[u8]],
            signature: &BlsSignature,
        ) -> bool;
    }
}
```

### Key Derivation (Mnemonic)

```rust
/// BIP-39 mnemonic phrase.
pub struct Mnemonic {
    phrase: String,
    // Derived seed cached
}

impl Mnemonic {
    /// Generate a new random mnemonic (12, 15, 18, 21, or 24 words).
    pub fn generate(word_count: usize) -> Result<Self, AptosError>;
    
    /// Parse from space-separated words.
    pub fn from_phrase(phrase: &str) -> Result<Self, AptosError>;
    
    /// Get the phrase as a string.
    pub fn phrase(&self) -> &str;
    
    /// Derive seed with optional passphrase.
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64];
    
    /// Derive Ed25519 key at path.
    #[cfg(feature = "ed25519")]
    pub fn derive_ed25519(&self, path: &str) -> Result<Ed25519PrivateKey, AptosError>;
    
    /// Derive Secp256k1 key at path.
    #[cfg(feature = "secp256k1")]
    pub fn derive_secp256k1(&self, path: &str) -> Result<Secp256k1PrivateKey, AptosError>;
}

/// Standard Aptos derivation path.
pub const APTOS_DERIVATION_PATH: &str = "m/44'/637'/0'/0'/0'";
```

---

## Implementation Details

### Signing Message Format

For transaction signing, the message is constructed as:

```
signing_message = domain_separator || bcs_bytes(raw_transaction)

where domain_separator depends on transaction type:
- Single signer: APTOS::RawTransaction (sha3_256 of prefix)
- Multi-agent: APTOS::RawTransactionWithData
- Fee payer: APTOS::RawTransactionWithData
```

### Authentication Key Derivation

```
auth_key = sha3_256(public_key_bytes || scheme_byte)

where scheme_byte is:
- 0x00 for Ed25519
- 0x01 for MultiEd25519
- 0x02 for Secp256k1
- 0x03 for Secp256r1
```

### Address Derivation

```
address = auth_key (for new accounts)
```

For existing accounts, the address may differ from the authentication key if the key has been rotated.

### BIP-44 Path Format

```
m / purpose' / coin_type' / account' / change' / address_index'

Aptos: m/44'/637'/0'/0'/0'
- purpose: 44 (BIP-44)
- coin_type: 637 (Aptos)
- account: 0 (first account)
- change: 0 (external)
- address_index: 0 (first address)
```

---

## Error Handling

| Error | Cause |
|-------|-------|
| `InvalidKeyLength` | Wrong number of bytes for key type |
| `InvalidSignature` | Malformed signature bytes |
| `SignatureVerificationFailed` | Signature doesn't match message |
| `InvalidMnemonic` | Bad mnemonic phrase or checksum |
| `InvalidDerivationPath` | Malformed BIP-44 path |
| `KeyDerivationFailed` | Could not derive key from seed |

---

## Testing Requirements

### Unit Tests

```rust
#[test]
fn test_ed25519_sign_verify() {
    let private_key = Ed25519PrivateKey::generate();
    let public_key = private_key.public_key();
    let message = b"test message";
    
    let signature = private_key.sign(message);
    assert!(public_key.verify(message, &signature));
    
    // Wrong message fails
    assert!(!public_key.verify(b"wrong message", &signature));
}

#[test]
fn test_mnemonic_derivation() {
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ).unwrap();
    
    let key = mnemonic.derive_ed25519(APTOS_DERIVATION_PATH).unwrap();
    let address = AuthenticationKey::from_ed25519(&key.public_key()).account_address();
    
    // Should derive deterministically
    assert_eq!(address.to_hex(), "0x...");  // Known test vector
}

#[test]
fn test_auth_key_derivation() {
    let private_key = Ed25519PrivateKey::from_hex("0x...").unwrap();
    let public_key = private_key.public_key();
    let auth_key = AuthenticationKey::from_ed25519(&public_key);
    
    assert_eq!(auth_key.to_hex(), "0x...");  // Known test vector
}
```

### Test Vectors

Include test vectors from:
- RFC 8032 (Ed25519)
- BIP-39 test vectors
- Aptos-specific test vectors from TypeScript SDK

---

## Security Considerations

### Key Protection

1. **Memory Zeroization**: All private key types implement `Drop` with zeroization
2. **No Clone for Private Keys**: Private keys should not be easily cloned
3. **Constant-Time Operations**: Use constant-time comparison for signatures

### Randomness

1. Use `getrandom` crate for cryptographic randomness
2. Never use `rand::thread_rng()` for key generation
3. Seed from OS entropy source only

### Signature Malleability

1. **Secp256k1**: Use low-S normalization (BIP-146)
2. **Ed25519**: Verify signature is in canonical form
3. **BLS**: Use proof-of-possession scheme

---

## Dependencies

### External Crates

| Feature | Crate | Version | Notes |
|---------|-------|---------|-------|
| `ed25519` | `ed25519-dalek` | 2.x | DALEK implementation |
| `secp256k1` | `k256` | 0.13 | Pure Rust, audited |
| `secp256r1` | `p256` | 0.13 | Pure Rust, audited |
| `bls` | `blst` | 0.3 | C library, audited |
| all | `sha3` | 0.10 | SHA3 implementation |
| all | `bip39` | 2.0 | Mnemonic handling |
| all | `tiny-bip39` | 1.0 | Alternative mnemonic |

### Internal Modules

- `types`: `HashValue`, `AccountAddress`

---

## Open Questions

1. ~~Should we support hardware wallet signing?~~ (Decided: Future feature)
2. ~~Should BLS be default-enabled?~~ (Decided: No, opt-in due to size)
3. Should we support legacy key formats? (Decided: No, strict formats only)

