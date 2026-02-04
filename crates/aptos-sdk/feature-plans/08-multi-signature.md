# Multi-Signature Accounts

## Overview

Support for multi-signature (multisig) accounts that require M-of-N signatures to authorize transactions.

## Status: ✅ Implemented

## Goals

1. Support MultiEd25519 accounts (M-of-N Ed25519 keys)
2. Support MultiKey accounts (mixed key types)
3. Enable threshold signature collection
4. Integrate with transaction building

## Non-Goals

- On-chain multisig governance (use Move modules)
- Hardware wallet integration (future)

---

## API Design

### MultiEd25519Account

```rust
/// Multi-signature Ed25519 account.
pub struct MultiEd25519Account {
    /// Public keys (N keys).
    public_keys: Vec<Ed25519PublicKey>,
    /// Private keys owned by this instance.
    private_keys: Vec<Ed25519PrivateKey>,
    /// Threshold (M signatures required).
    threshold: u8,
    /// Derived address.
    address: AccountAddress,
}

impl MultiEd25519Account {
    /// Create from multiple private keys with threshold.
    pub fn new(
        private_keys: Vec<Ed25519PrivateKey>,
        threshold: u8,
    ) -> Result<Self, AptosError>;
    
    /// Create from public keys (no signing capability).
    pub fn from_public_keys(
        public_keys: Vec<Ed25519PublicKey>,
        threshold: u8,
    ) -> Result<Self, AptosError>;
    
    /// Add a private key to enable signing.
    pub fn with_private_key(self, key: Ed25519PrivateKey) -> Self;
    
    /// Get required threshold.
    pub fn threshold(&self) -> u8;
    
    /// Get number of keys.
    pub fn num_keys(&self) -> usize;
    
    /// Check if we can sign (have enough keys).
    pub fn can_sign(&self) -> bool;
}

impl Account for MultiEd25519Account {
    fn address(&self) -> AccountAddress;
    fn public_key_bytes(&self) -> Vec<u8>;
    fn signature_scheme(&self) -> SignatureScheme;
    fn sign(&self, message: &[u8]) -> Vec<u8>;
    fn authentication_key(&self) -> AuthenticationKey;
}
```

### MultiEd25519PublicKey

```rust
/// Combined multi-Ed25519 public key.
pub struct MultiEd25519PublicKey {
    public_keys: Vec<Ed25519PublicKey>,
    threshold: u8,
}

impl MultiEd25519PublicKey {
    pub fn new(keys: Vec<Ed25519PublicKey>, threshold: u8) -> Result<Self, AptosError>;
    pub fn threshold(&self) -> u8;
    pub fn public_keys(&self) -> &[Ed25519PublicKey];
    pub fn to_bytes(&self) -> Vec<u8>;
}
```

### MultiEd25519Signature

```rust
/// Aggregated multi-Ed25519 signature.
pub struct MultiEd25519Signature {
    signatures: Vec<(u8, Ed25519Signature)>,  // (index, signature)
}

impl MultiEd25519Signature {
    /// Create from individual signatures with signer indices.
    pub fn new(signatures: Vec<(u8, Ed25519Signature)>) -> Self;
    
    /// Add a signature.
    pub fn add_signature(&mut self, index: u8, signature: Ed25519Signature);
    
    /// Check if threshold is met.
    pub fn is_complete(&self, threshold: u8) -> bool;
    
    pub fn to_bytes(&self) -> Vec<u8>;
}
```

---

## Authentication Key Derivation

```
MultiEd25519 Auth Key = sha3_256(
    public_key_1 || public_key_2 || ... || public_key_n || threshold || 0x01
)

where 0x01 is the MultiEd25519 scheme identifier
```

---

## Signature Collection Workflow

```rust
// 1. Create multisig account (2-of-3)
let pub_keys = vec![key1.public_key(), key2.public_key(), key3.public_key()];
let multisig = MultiEd25519Account::from_public_keys(pub_keys, 2)?;

// 2. Build transaction
let raw_txn = TransactionBuilder::new()
    .sender(multisig.address())
    .payload(payload)
    .build()?;

// 3. Collect signatures from M signers
let msg = raw_txn.signing_message();
let sig1 = key1.sign(&msg);  // Signer 1
let sig3 = key3.sign(&msg);  // Signer 3

// 4. Combine signatures
let multi_sig = MultiEd25519Signature::new(vec![
    (0, sig1),  // Index 0
    (2, sig3),  // Index 2
]);

// 5. Create signed transaction
let authenticator = TransactionAuthenticator::MultiEd25519 {
    public_key: multisig.public_key(),
    signature: multi_sig,
};
let signed = SignedTransaction::new(raw_txn, authenticator);
```

---

## Testing Requirements

```rust
#[test]
fn test_multisig_2_of_3() {
    let key1 = Ed25519PrivateKey::generate();
    let key2 = Ed25519PrivateKey::generate();
    let key3 = Ed25519PrivateKey::generate();
    
    let multisig = MultiEd25519Account::new(vec![key1, key2], 2).unwrap();
    assert!(multisig.can_sign());
    
    let message = b"test";
    let signature = multisig.sign(message);
    
    // Verify
    let pub_key = multisig.public_key();
    assert!(pub_key.verify(message, &signature));
}

#[test]
fn test_multisig_address_derivation() {
    // Known test vectors
    let keys = vec![/* known keys */];
    let multisig = MultiEd25519Account::from_public_keys(keys, 2).unwrap();
    assert_eq!(multisig.address().to_hex(), "0x...");
}
```

---

## Security Considerations

1. **Threshold Validation**: Ensure 1 <= threshold <= num_keys
2. **Key Ordering**: Keys must be in canonical order
3. **Signature Uniqueness**: Each signer can only sign once
4. **Index Validation**: Signature indices must be valid

---

## Dependencies

- Ed25519 crypto module
- Transaction building module

