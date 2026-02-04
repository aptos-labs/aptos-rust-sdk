# Transaction Building

## Overview

The transaction building module provides types and utilities for constructing, signing, and serializing Aptos transactions. It supports various transaction types including entry functions, scripts, and multi-signature transactions.

## Goals

1. Type-safe transaction construction
2. Support all transaction payload types
3. Enable multi-agent and fee payer transactions
4. Provide ergonomic builder pattern

## Non-Goals

- Transaction simulation (handled by API clients)
- Transaction submission (handled by API clients)
- Gas estimation (handled by API clients)

---

## API Design

### RawTransaction

```rust
/// Unsigned transaction ready for signing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawTransaction {
    sender: AccountAddress,
    sequence_number: u64,
    payload: TransactionPayload,
    max_gas_amount: u64,
    gas_unit_price: u64,
    expiration_timestamp_secs: u64,
    chain_id: ChainId,
}

impl RawTransaction {
    /// Create a new raw transaction.
    pub fn new(
        sender: AccountAddress,
        sequence_number: u64,
        payload: TransactionPayload,
        max_gas_amount: u64,
        gas_unit_price: u64,
        expiration_timestamp_secs: u64,
        chain_id: ChainId,
    ) -> Self;
    
    /// Get the sender address.
    pub fn sender(&self) -> AccountAddress;
    
    /// Get the sequence number.
    pub fn sequence_number(&self) -> u64;
    
    /// Get the payload.
    pub fn payload(&self) -> &TransactionPayload;
    
    /// Generate the signing message (with domain separator).
    pub fn signing_message(&self) -> Vec<u8>;
    
    /// Sign with a single signer.
    pub fn sign(self, signer: &impl Account) -> SignedTransaction;
}
```

### TransactionPayload

```rust
/// Transaction payload variants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionPayload {
    /// Call a Move entry function.
    EntryFunction(EntryFunction),
    
    /// Execute a Move script.
    Script(Script),
    
    /// Execute through a multisig account.
    Multisig(Multisig),
}

impl From<EntryFunction> for TransactionPayload { ... }
impl From<Script> for TransactionPayload { ... }
impl From<Multisig> for TransactionPayload { ... }
```

### EntryFunction

```rust
/// Entry function call payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryFunction {
    module: MoveModuleId,
    function: String,
    type_args: Vec<TypeTag>,
    args: Vec<Vec<u8>>,  // BCS-encoded arguments
}

impl EntryFunction {
    /// Create a new entry function call.
    pub fn new(
        module: MoveModuleId,
        function: impl Into<String>,
        type_args: Vec<TypeTag>,
        args: Vec<Vec<u8>>,
    ) -> Self;
    
    /// Create an APT transfer.
    pub fn apt_transfer(to: AccountAddress, amount: u64) -> Result<Self, AptosError>;
    
    /// Create a coin transfer.
    pub fn coin_transfer(
        coin_type: TypeTag,
        to: AccountAddress,
        amount: u64,
    ) -> Result<Self, AptosError>;
    
    /// Get the module ID.
    pub fn module(&self) -> &MoveModuleId;
    
    /// Get the function name.
    pub fn function(&self) -> &str;
    
    /// Get type arguments.
    pub fn type_args(&self) -> &[TypeTag];
    
    /// Get encoded arguments.
    pub fn args(&self) -> &[Vec<u8>];
}
```

### Script

```rust
/// Move script execution payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Script {
    code: Vec<u8>,  // Compiled script bytecode
    type_args: Vec<TypeTag>,
    args: Vec<ScriptArgument>,
}

impl Script {
    pub fn new(
        code: Vec<u8>,
        type_args: Vec<TypeTag>,
        args: Vec<ScriptArgument>,
    ) -> Self;
}

/// Script argument types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptArgument {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    U256(U256),
    Address(AccountAddress),
    Bool(bool),
    U8Vector(Vec<u8>),
}
```

### Multisig

```rust
/// Multisig account transaction payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Multisig {
    multisig_address: AccountAddress,
    transaction_payload: Option<MultisigTransactionPayload>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultisigTransactionPayload {
    EntryFunction(EntryFunction),
}
```

### SignedTransaction

```rust
/// Signed transaction ready for submission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransaction {
    raw_txn: RawTransaction,
    authenticator: TransactionAuthenticator,
}

impl SignedTransaction {
    /// Create from raw transaction and authenticator.
    pub fn new(
        raw_txn: RawTransaction,
        authenticator: TransactionAuthenticator,
    ) -> Self;
    
    /// Get the raw transaction.
    pub fn raw_transaction(&self) -> &RawTransaction;
    
    /// Get the authenticator.
    pub fn authenticator(&self) -> &TransactionAuthenticator;
    
    /// Serialize to BCS bytes for submission.
    pub fn to_bytes(&self) -> Vec<u8>;
    
    /// Compute transaction hash.
    pub fn hash(&self) -> HashValue;
}
```

### TransactionAuthenticator

```rust
/// Transaction signature container.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionAuthenticator {
    /// Single Ed25519 signature.
    Ed25519 {
        public_key: Ed25519PublicKey,
        signature: Ed25519Signature,
    },
    
    /// Single Secp256k1 signature.
    Secp256k1Ecdsa {
        public_key: Secp256k1PublicKey,
        signature: Secp256k1Signature,
    },
    
    /// Multi-agent transaction (multiple signers).
    MultiAgent {
        sender: AccountAuthenticator,
        secondary_signer_addresses: Vec<AccountAddress>,
        secondary_signers: Vec<AccountAuthenticator>,
    },
    
    /// Fee payer transaction (sponsor pays gas).
    FeePayer {
        sender: AccountAuthenticator,
        secondary_signer_addresses: Vec<AccountAddress>,
        secondary_signers: Vec<AccountAuthenticator>,
        fee_payer_address: AccountAddress,
        fee_payer_signer: AccountAuthenticator,
    },
}

/// Individual account authenticator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountAuthenticator {
    Ed25519 {
        public_key: Ed25519PublicKey,
        signature: Ed25519Signature,
    },
    Secp256k1Ecdsa {
        public_key: Secp256k1PublicKey,
        signature: Secp256k1Signature,
    },
    // ... other schemes
}
```

### TransactionBuilder

```rust
/// Fluent builder for transactions.
pub struct TransactionBuilder {
    sender: Option<AccountAddress>,
    sequence_number: Option<u64>,
    payload: Option<TransactionPayload>,
    max_gas_amount: u64,
    gas_unit_price: u64,
    expiration_timestamp_secs: Option<u64>,
    chain_id: Option<ChainId>,
}

impl TransactionBuilder {
    /// Create a new builder with defaults.
    pub fn new() -> Self;
    
    /// Set the sender address.
    pub fn sender(self, sender: AccountAddress) -> Self;
    
    /// Set the sequence number.
    pub fn sequence_number(self, seq: u64) -> Self;
    
    /// Set the payload.
    pub fn payload(self, payload: TransactionPayload) -> Self;
    
    /// Set max gas amount (default: 200_000).
    pub fn max_gas_amount(self, amount: u64) -> Self;
    
    /// Set gas unit price (default: 100).
    pub fn gas_unit_price(self, price: u64) -> Self;
    
    /// Set expiration timestamp.
    pub fn expiration_timestamp_secs(self, timestamp: u64) -> Self;
    
    /// Set expiration from now (seconds).
    pub fn expiration_from_now(self, seconds: u64) -> Self;
    
    /// Set chain ID.
    pub fn chain_id(self, chain_id: ChainId) -> Self;
    
    /// Build the raw transaction.
    pub fn build(self) -> Result<RawTransaction, AptosError>;
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self {
            sender: None,
            sequence_number: None,
            payload: None,
            max_gas_amount: 200_000,
            gas_unit_price: 100,
            expiration_timestamp_secs: None,
            chain_id: None,
        }
    }
}
```

### Helper Functions

```rust
/// Sign a raw transaction with an account.
pub fn sign_transaction(
    raw_txn: &RawTransaction,
    signer: &impl Account,
) -> Result<SignedTransaction, AptosError>;

/// Sign a multi-agent transaction.
pub fn sign_multi_agent_transaction(
    raw_txn: &RawTransaction,
    sender: &impl Account,
    secondary_signers: &[&dyn Account],
) -> Result<SignedTransaction, AptosError>;

/// Sign a fee payer transaction.
pub fn sign_fee_payer_transaction(
    raw_txn: &RawTransaction,
    sender: &impl Account,
    secondary_signers: &[&dyn Account],
    fee_payer: &impl Account,
) -> Result<SignedTransaction, AptosError>;
```

---

## Implementation Details

### Signing Message Construction

```rust
// Single signer
fn single_signer_signing_message(raw_txn: &RawTransaction) -> Vec<u8> {
    let domain = sha3_256(b"APTOS::RawTransaction");
    let bcs = aptos_bcs::to_bytes(raw_txn).unwrap();
    [domain.as_bytes(), &bcs].concat()
}

// Multi-agent
fn multi_agent_signing_message(
    raw_txn: &RawTransaction,
    secondary_addresses: &[AccountAddress],
) -> Vec<u8> {
    let domain = sha3_256(b"APTOS::RawTransactionWithData");
    let data = RawTransactionWithData::MultiAgent {
        raw_txn: raw_txn.clone(),
        secondary_signer_addresses: secondary_addresses.to_vec(),
    };
    let bcs = aptos_bcs::to_bytes(&data).unwrap();
    [domain.as_bytes(), &bcs].concat()
}

// Fee payer
fn fee_payer_signing_message(
    raw_txn: &RawTransaction,
    secondary_addresses: &[AccountAddress],
    fee_payer_address: AccountAddress,
) -> Vec<u8> {
    let domain = sha3_256(b"APTOS::RawTransactionWithData");
    let data = RawTransactionWithData::FeePayer {
        raw_txn: raw_txn.clone(),
        secondary_signer_addresses: secondary_addresses.to_vec(),
        fee_payer_address,
    };
    let bcs = aptos_bcs::to_bytes(&data).unwrap();
    [domain.as_bytes(), &bcs].concat()
}
```

### BCS Serialization Order

Transaction fields are serialized in this exact order:
1. sender (32 bytes)
2. sequence_number (u64)
3. payload (variant + data)
4. max_gas_amount (u64)
5. gas_unit_price (u64)
6. expiration_timestamp_secs (u64)
7. chain_id (u8)

---

## Usage Examples

### Simple Transfer

```rust
use aptos_rust_sdk_v2::transaction::{TransactionBuilder, EntryFunction};

// Create payload
let payload = EntryFunction::apt_transfer(recipient, 1_000_000)?;

// Build transaction
let raw_txn = TransactionBuilder::new()
    .sender(sender.address())
    .sequence_number(0)
    .payload(payload.into())
    .chain_id(ChainId::TESTNET)
    .expiration_from_now(600)
    .build()?;

// Sign
let signed = sign_transaction(&raw_txn, &sender)?;
```

### Entry Function with Type Arguments

```rust
let payload = EntryFunction::new(
    MoveModuleId::from_str_strict("0x1::coin")?,
    "transfer",
    vec![TypeTag::aptos_coin()],
    vec![
        aptos_bcs::to_bytes(&recipient)?,
        aptos_bcs::to_bytes(&amount)?,
    ],
);
```

### Multi-Agent Transaction

```rust
// Both sender and receiver sign
let raw_txn = TransactionBuilder::new()
    .sender(sender.address())
    .payload(payload.into())
    .build()?;

let signed = sign_multi_agent_transaction(
    &raw_txn,
    &sender,
    &[&receiver],  // Secondary signers
)?;
```

### Fee Payer (Sponsored) Transaction

```rust
let raw_txn = TransactionBuilder::new()
    .sender(user.address())  // User sends
    .payload(payload.into())
    .build()?;

let signed = sign_fee_payer_transaction(
    &raw_txn,
    &user,           // Sender
    &[],             // No secondary signers
    &sponsor,        // Sponsor pays gas
)?;
```

---

## Error Handling

| Error | Cause |
|-------|-------|
| `MissingSender` | Builder missing sender address |
| `MissingSequenceNumber` | Builder missing sequence number |
| `MissingPayload` | Builder missing payload |
| `MissingChainId` | Builder missing chain ID |
| `MissingExpiration` | Builder missing expiration |
| `SerializationError` | BCS encoding failed |
| `SigningError` | Signature creation failed |

---

## Testing Requirements

### Unit Tests

```rust
#[test]
fn test_builder_creates_valid_transaction() {
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
    
    assert_eq!(raw_txn.sender(), sender.address());
    assert_eq!(raw_txn.sequence_number(), 0);
}

#[test]
fn test_builder_fails_without_required_fields() {
    let result = TransactionBuilder::new().build();
    assert!(result.is_err());
}

#[test]
fn test_sign_verify_roundtrip() {
    let sender = Ed25519Account::generate();
    let raw_txn = create_test_transaction(&sender);
    
    let signed = sign_transaction(&raw_txn, &sender).unwrap();
    
    // Verify signature is valid
    let message = raw_txn.signing_message();
    let is_valid = sender.public_key().verify(&message, /* extract sig */);
    assert!(is_valid);
}

#[test]
fn test_multi_agent_signing() {
    let sender = Ed25519Account::generate();
    let secondary = Ed25519Account::generate();
    
    let raw_txn = create_test_transaction(&sender);
    let signed = sign_multi_agent_transaction(&raw_txn, &sender, &[&secondary]).unwrap();
    
    match signed.authenticator() {
        TransactionAuthenticator::MultiAgent { .. } => {}
        _ => panic!("Expected MultiAgent authenticator"),
    }
}

#[test]
fn test_fee_payer_signing() {
    let sender = Ed25519Account::generate();
    let fee_payer = Ed25519Account::generate();
    
    let raw_txn = create_test_transaction(&sender);
    let signed = sign_fee_payer_transaction(&raw_txn, &sender, &[], &fee_payer).unwrap();
    
    match signed.authenticator() {
        TransactionAuthenticator::FeePayer { fee_payer_address, .. } => {
            assert_eq!(*fee_payer_address, fee_payer.address());
        }
        _ => panic!("Expected FeePayer authenticator"),
    }
}

#[test]
fn test_bcs_serialization_matches_expected() {
    // Use known test vector
    let raw_txn = create_known_transaction();
    let bytes = aptos_bcs::to_bytes(&raw_txn).unwrap();
    
    // Compare against known BCS encoding
    assert_eq!(bytes, EXPECTED_BCS_BYTES);
}
```

---

## Security Considerations

1. **Signing Message**: Always use domain separator to prevent cross-protocol attacks
2. **Expiration**: Set reasonable expiration times (not too long)
3. **Sequence Number**: Ensure correct sequence to prevent replay
4. **Gas Limits**: Set appropriate gas limits to prevent draining

---

## Dependencies

### External Crates
- `aptos-bcs`: BCS serialization

### Internal Modules
- `types`: Core types
- `crypto`: Signing keys
- `account`: Account trait

---

## Open Questions

1. ~~Should builder auto-fetch sequence number?~~ (Decided: No, keep builder pure)
2. ~~Should we cache signing message?~~ (Decided: No, compute on demand)
3. Should we support batched transactions? (Decided: Future feature)

