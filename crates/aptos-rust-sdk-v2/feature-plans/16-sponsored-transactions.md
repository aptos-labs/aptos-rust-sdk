# Feature 16: Sponsored Transaction Helpers

## Overview

This feature provides high-level utilities for creating and managing sponsored (fee payer) transactions, where one account pays the gas fees on behalf of another account.

## Goals

1. **Simplicity**: Make sponsored transactions easy to create
2. **Flexibility**: Support various signing workflows (all-at-once, distributed)
3. **Type Safety**: Leverage Rust's type system for correct usage
4. **Composability**: Work with existing transaction building infrastructure

## Use Cases

- **User Onboarding**: New users without APT can still execute transactions
- **dApp Subsidization**: Applications pay gas fees for their users
- **Gasless UX**: Create seamless experiences without exposing gas costs
- **Enterprise**: Central fee payer account for organizational transactions

## API Design

### SponsoredTransactionBuilder

```rust
use aptos_rust_sdk_v2::transaction::{SponsoredTransactionBuilder, EntryFunction};
use aptos_rust_sdk_v2::types::ChainId;

// Build and sign in one step
let signed_txn = SponsoredTransactionBuilder::new()
    .sender(user_account.address())
    .sequence_number(0)
    .fee_payer(sponsor_account.address())
    .payload(payload)
    .chain_id(ChainId::testnet())
    .max_gas_amount(100_000)
    .gas_unit_price(100)
    .build_and_sign(&user_account, &[], &sponsor_account)?;

// Or build first, sign later
let fee_payer_txn = SponsoredTransactionBuilder::new()
    .sender(user_account.address())
    .sequence_number(0)
    .fee_payer(sponsor_account.address())
    .payload(payload)
    .chain_id(ChainId::testnet())
    .build()?;

let signed = sign_sponsored_transaction(
    &fee_payer_txn,
    &user_account,
    &[],  // secondary signers
    &sponsor_account,
)?;
```

### PartiallySigned (Distributed Signing)

For scenarios where signers are in different systems/processes:

```rust
use aptos_rust_sdk_v2::transaction::PartiallySigned;

// Create transaction structure
let fee_payer_txn = SponsoredTransactionBuilder::new()
    .sender(sender_address)
    .sequence_number(0)
    .fee_payer(sponsor_address)
    .payload(payload)
    .chain_id(ChainId::testnet())
    .build()?;

// Create partial signature collector
let mut partial = PartiallySigned::new(fee_payer_txn);

// Pass to sender for signing
partial.sign_as_sender(&sender_account)?;

// Pass to fee payer for signing
partial.sign_as_fee_payer(&sponsor_account)?;

// Check if complete
assert!(partial.is_complete());

// Finalize into signed transaction
let signed = partial.finalize()?;
```

### Sponsor Trait

Extension trait for accounts to easily sponsor transactions:

```rust
use aptos_rust_sdk_v2::transaction::Sponsor;

// Any account can sponsor another
let signed = sponsor_account.sponsor(
    &user_account,
    user_sequence_number,
    payload,
    ChainId::testnet(),
)?;

// With custom gas settings
let signed = sponsor_account.sponsor_with_gas(
    &user_account,
    user_sequence_number,
    payload,
    ChainId::testnet(),
    200_000,  // max_gas_amount
    150,      // gas_unit_price
)?;
```

### Convenience Function

For simple cases:

```rust
use aptos_rust_sdk_v2::transaction::sponsor_transaction;

let signed = sponsor_transaction(
    &sender_account,
    sender_sequence_number,
    &fee_payer_account,
    payload,
    ChainId::testnet(),
)?;
```

## Types

### SponsoredTransactionBuilder

```rust
pub struct SponsoredTransactionBuilder {
    sender_address: Option<AccountAddress>,
    sequence_number: Option<u64>,
    secondary_addresses: Vec<AccountAddress>,
    fee_payer_address: Option<AccountAddress>,
    payload: Option<TransactionPayload>,
    max_gas_amount: u64,
    gas_unit_price: u64,
    expiration_timestamp_secs: Option<u64>,
    chain_id: Option<ChainId>,
}
```

### PartiallySigned

```rust
pub struct PartiallySigned {
    pub fee_payer_txn: FeePayerRawTransaction,
    pub sender_auth: Option<AccountAuthenticator>,
    pub secondary_auths: Vec<Option<AccountAuthenticator>>,
    pub fee_payer_auth: Option<AccountAuthenticator>,
}
```

### Sponsor Trait

```rust
pub trait Sponsor: Account + Sized {
    fn sponsor<S: Account>(
        &self,
        sender: &S,
        sender_sequence_number: u64,
        payload: TransactionPayload,
        chain_id: ChainId,
    ) -> AptosResult<SignedTransaction>;

    fn sponsor_with_gas<S: Account>(
        &self,
        sender: &S,
        sender_sequence_number: u64,
        payload: TransactionPayload,
        chain_id: ChainId,
        max_gas_amount: u64,
        gas_unit_price: u64,
    ) -> AptosResult<SignedTransaction>;
}
```

## Secondary Signers

Support for multi-party transactions with secondary signers:

```rust
let signed = SponsoredTransactionBuilder::new()
    .sender(user_account.address())
    .sequence_number(0)
    .secondary_signer(co_signer1.address())
    .secondary_signer(co_signer2.address())
    .fee_payer(sponsor_account.address())
    .payload(payload)
    .chain_id(ChainId::testnet())
    .build_and_sign(
        &user_account,
        &[&co_signer1, &co_signer2],  // secondary signers
        &sponsor_account,
    )?;
```

## Error Handling

The builder validates required fields:

```rust
// Missing sender
let result = SponsoredTransactionBuilder::new()
    .sequence_number(0)
    .fee_payer(address)
    .payload(payload)
    .chain_id(chain_id)
    .build();
assert!(result.is_err()); // "sender is required"

// Missing fee_payer
let result = SponsoredTransactionBuilder::new()
    .sender(address)
    .sequence_number(0)
    .payload(payload)
    .chain_id(chain_id)
    .build();
assert!(result.is_err()); // "fee_payer is required"
```

## Testing

### Unit Tests
- Builder validation (missing fields)
- Complete builder flow
- Partially signed completion tracking
- Finalize with missing signatures

### Integration Tests (with Ed25519)
- Full sponsored transaction signing
- Sponsor trait usage
- Convenience function usage
- Partially signed flow

## Security Considerations

1. **Signature Verification**: Each party signs the same message
2. **Address Validation**: Addresses must match signers
3. **Replay Protection**: Normal transaction replay protection applies
4. **Fee Payer Trust**: Users must trust fee payers not to front-run

## Status

✅ **Implemented**
- SponsoredTransactionBuilder with fluent API
- sign_sponsored_transaction function
- PartiallySigned for distributed signing
- Sponsor trait for account extension
- sponsor_transaction convenience function
- Support for secondary signers
- Comprehensive unit and integration tests

