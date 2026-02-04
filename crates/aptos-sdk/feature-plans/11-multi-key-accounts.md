# Multi-Key Accounts

## Status: ✅ Implemented

## Overview

Multi-Key accounts support M-of-N threshold signatures with **mixed key types**. Unlike Multi-Ed25519 accounts which only support Ed25519 keys, Multi-Key accounts can combine different signature schemes (Ed25519, Secp256k1, Secp256r1) in a single account.

This enables:
- Hardware wallet + mobile key combinations
- Cross-platform key compatibility
- Progressive security upgrades without account rotation

## Goals

1. Support M-of-N threshold signing with mixed key types
2. Enable distributed signing across multiple parties
3. Provide view-only accounts for monitoring
4. Integrate seamlessly with existing transaction building

## Non-Goals

- Key rotation within multi-key (requires on-chain operation)
- Social recovery (handled by Move contracts)
- Hardware wallet integration (SDK provides primitives only)

## API Design

### Crypto Types

```rust
/// Supported signature schemes for multi-key.
pub enum AnyPublicKeyVariant {
    Ed25519 = 0,
    Secp256k1 = 1,
    Secp256r1 = 2,
    Keyless = 3,
}

/// A public key that can be any supported signature scheme.
pub struct AnyPublicKey {
    pub variant: AnyPublicKeyVariant,
    pub bytes: Vec<u8>,
}

/// A signature that can be any supported signature scheme.
pub struct AnySignature {
    pub variant: AnyPublicKeyVariant,
    pub bytes: Vec<u8>,
}

/// Multi-key public key supporting mixed signature schemes.
pub struct MultiKeyPublicKey {
    public_keys: Vec<AnyPublicKey>,
    threshold: u8,
}

/// Multi-key signature with bitmap.
pub struct MultiKeySignature {
    signatures: Vec<(u8, AnySignature)>,
    bitmap: [u8; 4],  // Supports up to 32 keys
}
```

### Account Type

```rust
/// Wrapper for any private key type.
pub enum AnyPrivateKey {
    Ed25519(Ed25519PrivateKey),
    Secp256k1(Secp256k1PrivateKey),
    Secp256r1(Secp256r1PrivateKey),
}

/// Multi-key account with M-of-N threshold signing.
pub struct MultiKeyAccount {
    private_keys: Vec<(u8, AnyPrivateKey)>,  // Indexed keys owned by this instance
    public_key: MultiKeyPublicKey,
    address: AccountAddress,
}

impl MultiKeyAccount {
    /// Create with all private keys (full signing capability).
    pub fn new(private_keys: Vec<AnyPrivateKey>, threshold: u8) -> AptosResult<Self>;
    
    /// Create with subset of private keys (partial signing).
    pub fn from_keys(
        public_keys: Vec<AnyPublicKey>,
        private_keys: Vec<(u8, AnyPrivateKey)>,
        threshold: u8,
    ) -> AptosResult<Self>;
    
    /// Create view-only account (no signing capability).
    pub fn view_only(public_keys: Vec<AnyPublicKey>, threshold: u8) -> AptosResult<Self>;
    
    /// Check if this instance can sign (has enough keys).
    pub fn can_sign(&self) -> bool;
    
    /// Sign a message using owned keys.
    pub fn sign_message(&self, message: &[u8]) -> AptosResult<MultiKeySignature>;
    
    /// Create a signature contribution for distributed signing.
    pub fn create_signature_contribution(
        &self,
        message: &[u8],
        key_index: u8,
    ) -> AptosResult<(u8, AnySignature)>;
    
    /// Aggregate individual signatures into a multi-key signature.
    pub fn aggregate_signatures(
        signatures: Vec<(u8, AnySignature)>,
    ) -> AptosResult<MultiKeySignature>;
}

impl Account for MultiKeyAccount { /* ... */ }
```

### Transaction Authenticator

```rust
pub enum TransactionAuthenticator {
    // ... existing variants ...
    MultiKey {
        public_key: Vec<u8>,
        signature: Vec<u8>,
    },
}

pub enum AccountAuthenticator {
    // ... existing variants ...
    MultiKey {
        public_key: Vec<u8>,
        signature: Vec<u8>,
    },
}
```

## Implementation Details

### Address Derivation

```
auth_key = SHA3-256(MultiKeyPublicKey::to_bytes() || MULTI_KEY_SCHEME)
address = auth_key  // For new accounts
```

### Public Key Serialization

```
format: num_keys (1 byte) || pk1_bcs || pk2_bcs || ... || threshold (1 byte)
pk_bcs: variant (1 byte) || length (4 bytes LE) || key_bytes
```

### Signature Serialization

```
format: num_sigs (1 byte) || sig1_bcs || sig2_bcs || ... || bitmap (4 bytes)
sig_bcs: variant (1 byte) || length (4 bytes LE) || sig_bytes
bitmap: little-endian, bit i = 1 if key i signed
```

### Distributed Signing Flow

1. Each party creates a `MultiKeyAccount` with only their key
2. All parties receive the message to sign
3. Each party calls `create_signature_contribution()`
4. Contributions are collected (via any transport)
5. Any party calls `aggregate_signatures()` to combine
6. Final `MultiKeySignature` is used in transaction

## Error Handling

- `AptosError::InvalidPublicKey` - Bad public key format
- `AptosError::InvalidSignature` - Bad signature format
- `AptosError::InsufficientSignatures` - Not enough signatures for threshold
- `AptosError::InvalidPrivateKey` - Private key doesn't match public key

## Testing Requirements

### Unit Tests
- [x] Create multi-key public key with valid/invalid thresholds
- [x] Create multi-key account with mixed key types
- [x] Sign and verify with multi-key account
- [x] Partial key ownership (insufficient keys should fail signing)
- [x] View-only account creation
- [x] Signature aggregation from multiple parties
- [x] Bytes serialization/deserialization roundtrip

### Integration Tests
- [ ] Submit transaction with multi-key account
- [ ] Multi-key as fee payer
- [ ] Multi-key in multi-agent transaction

## Security Considerations

1. **Threshold validation** - Must be > 0 and <= num_keys
2. **Key type verification** - Private keys must match public keys by type and content
3. **Bitmap validation** - Signatures must match bitmap bits
4. **No duplicate signatures** - Each key index can only sign once

## Dependencies

- `ed25519-dalek` (optional, feature "ed25519")
- `k256` (optional, feature "secp256k1")
- `p256` (optional, feature "secp256r1")
- `sha3` for address derivation

## Open Questions

All resolved.

