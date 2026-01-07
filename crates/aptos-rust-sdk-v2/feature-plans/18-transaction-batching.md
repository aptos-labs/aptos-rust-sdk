# Feature Plan: Transaction Batching

## Overview

Transaction batching allows efficient submission of multiple transactions at once. This is useful for bulk operations like multiple transfers, batch contract calls, or any scenario where multiple on-chain actions need to be performed.

## Goals

1. **Efficient multi-transaction submission** - Submit many transactions in parallel
2. **Automatic sequence number management** - Handle incrementing sequence numbers
3. **Flexible submission modes** - Support parallel and sequential submission
4. **Result tracking** - Track success/failure of each transaction in the batch
5. **Integration with Aptos client** - Convenience methods on main client

## API Design

### TransactionBatchBuilder

```rust
/// Builder for creating a batch of transactions.
#[derive(Debug, Clone)]
pub struct TransactionBatchBuilder {
    sender: Option<AccountAddress>,
    starting_sequence_number: Option<u64>,
    chain_id: Option<ChainId>,
    gas_unit_price: u64,
    max_gas_amount: u64,
    expiration_secs: u64,
    payloads: Vec<TransactionPayload>,
}

impl TransactionBatchBuilder {
    pub fn new() -> Self;
    pub fn sender(self, sender: AccountAddress) -> Self;
    pub fn starting_sequence_number(self, seq: u64) -> Self;
    pub fn chain_id(self, chain_id: ChainId) -> Self;
    pub fn gas_unit_price(self, price: u64) -> Self;
    pub fn max_gas_amount(self, amount: u64) -> Self;
    pub fn expiration_secs(self, secs: u64) -> Self;
    pub fn add_payload(self, payload: TransactionPayload) -> Self;
    pub fn add_payloads(self, payloads: impl IntoIterator<Item = TransactionPayload>) -> Self;
    pub fn build(self) -> AptosResult<Vec<RawTransaction>>;
    pub fn build_and_sign<A: Account>(self, account: &A) -> AptosResult<SignedTransactionBatch>;
}
```

### SignedTransactionBatch

```rust
/// A batch of signed transactions ready for submission.
#[derive(Debug, Clone)]
pub struct SignedTransactionBatch {
    transactions: Vec<SignedTransaction>,
}

impl SignedTransactionBatch {
    /// Submit all transactions in parallel.
    pub async fn submit_all(self, client: &FullnodeClient) -> Vec<BatchTransactionResult>;

    /// Submit all and wait for confirmation.
    pub async fn submit_and_wait_all(
        self,
        client: &FullnodeClient,
        timeout: Option<Duration>,
    ) -> Vec<BatchTransactionResult>;

    /// Submit one at a time.
    pub async fn submit_sequential(self, client: &FullnodeClient) -> Vec<BatchTransactionResult>;

    /// Submit and wait, one at a time.
    pub async fn submit_and_wait_sequential(
        self,
        client: &FullnodeClient,
        timeout: Option<Duration>,
    ) -> Vec<BatchTransactionResult>;
}
```

### BatchTransactionResult

```rust
/// Result of a single transaction in a batch.
#[derive(Debug)]
pub struct BatchTransactionResult {
    pub index: usize,
    pub transaction: SignedTransaction,
    pub result: Result<BatchTransactionStatus, AptosError>,
}

/// Status of a batch transaction after submission.
#[derive(Debug, Clone)]
pub enum BatchTransactionStatus {
    Pending { hash: String },
    Confirmed { hash: String, success: bool, version: u64, gas_used: u64 },
    Failed { error: String },
}
```

### BatchSummary

```rust
/// Summary of batch execution results.
#[derive(Debug, Clone)]
pub struct BatchSummary {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub pending: usize,
    pub total_gas_used: u64,
}

impl BatchSummary {
    pub fn from_results(results: &[BatchTransactionResult]) -> Self;
    pub fn all_succeeded(&self) -> bool;
    pub fn has_failures(&self) -> bool;
}
```

### Aptos Client Integration

```rust
impl Aptos {
    /// Returns a batch operations helper.
    pub fn batch(&self) -> BatchOperations<'_>;

    /// Submits multiple transactions in parallel.
    pub async fn submit_batch<A: Account>(
        &self,
        account: &A,
        payloads: Vec<TransactionPayload>,
    ) -> AptosResult<Vec<BatchTransactionResult>>;

    /// Submits and waits for multiple transactions.
    pub async fn submit_batch_and_wait<A: Account>(
        &self,
        account: &A,
        payloads: Vec<TransactionPayload>,
        timeout: Option<Duration>,
    ) -> AptosResult<Vec<BatchTransactionResult>>;

    /// Transfers APT to multiple recipients.
    pub async fn batch_transfer_apt<A: Account>(
        &self,
        sender: &A,
        transfers: Vec<(AccountAddress, u64)>,
    ) -> AptosResult<Vec<BatchTransactionResult>>;
}
```

## Usage Examples

### Basic Batch Submission

```rust
let aptos = Aptos::testnet()?;

let payloads = vec![
    EntryFunction::apt_transfer(addr1, 1_000_000)?.into(),
    EntryFunction::apt_transfer(addr2, 2_000_000)?.into(),
    EntryFunction::apt_transfer(addr3, 3_000_000)?.into(),
];

let results = aptos.submit_batch_and_wait(&sender, payloads, None).await?;

let summary = BatchSummary::from_results(&results);
println!("Succeeded: {}/{}", summary.succeeded, summary.total);
```

### Batch APT Transfers

```rust
let results = aptos.batch_transfer_apt(&sender, vec![
    (addr1, 1_000_000),
    (addr2, 2_000_000),
    (addr3, 3_000_000),
]).await?;
```

### Manual Batch Building

```rust
let seq_num = aptos.get_sequence_number(sender.address()).await?;

let batch = TransactionBatchBuilder::new()
    .sender(sender.address())
    .starting_sequence_number(seq_num)
    .chain_id(ChainId::testnet())
    .gas_unit_price(100)
    .add_payload(payload1)
    .add_payload(payload2)
    .add_payload(payload3)
    .build_and_sign(&sender)?;

// Submit all in parallel
let results = batch.submit_all(&aptos.fullnode()).await;

// Or submit sequentially (for dependent transactions)
let results = batch.submit_and_wait_sequential(&aptos.fullnode(), None).await;
```

### Checking Results

```rust
for result in &results {
    match &result.result {
        Ok(BatchTransactionStatus::Confirmed { hash, success, gas_used, .. }) => {
            println!("#{}: {} (gas: {})", result.index, if *success { "✓" } else { "✗" }, gas_used);
        }
        Ok(BatchTransactionStatus::Pending { hash }) => {
            println!("#{}: Pending ({})", result.index, hash);
        }
        Err(e) => {
            println!("#{}: Error - {}", result.index, e);
        }
        _ => {}
    }
}
```

## Implementation Details

### Sequence Number Management

Each transaction in a batch uses incrementing sequence numbers starting from `starting_sequence_number`:
- Transaction 0: `starting_sequence_number`
- Transaction 1: `starting_sequence_number + 1`
- Transaction N: `starting_sequence_number + N`

### Parallel vs Sequential Submission

**Parallel** (`submit_all`, `submit_and_wait_all`):
- All transactions submitted concurrently using `futures::join_all`
- Most efficient for independent transactions
- Network handles ordering based on sequence numbers

**Sequential** (`submit_sequential`, `submit_and_wait_sequential`):
- Transactions submitted one at a time
- Useful when transactions depend on each other
- Stops on first failure in `submit_and_wait_sequential`

### Error Handling

- Each transaction result is independent
- Failures in one transaction don't affect others (in parallel mode)
- `BatchSummary` provides aggregate statistics

## Testing

### Unit Tests

1. **Builder tests**
   - Missing required fields
   - Complete builds
   - Sequence number incrementing

2. **Batch summary tests**
   - Success/failure counting
   - Gas aggregation
   - All succeeded check

3. **Status method tests**
   - Hash extraction
   - Success/failure detection

### Integration Tests (require network)

1. **Parallel submission**
   - Multiple concurrent transfers
   - Order independence

2. **Sequential submission**
   - Dependent transactions
   - Stop-on-failure behavior

3. **Error handling**
   - Invalid sequence numbers
   - Insufficient balance
   - Timeout handling

## Dependencies

- `futures` crate for `join_all` parallel execution
- Existing `FullnodeClient` for submission
- Existing `TransactionBuilder` for building raw transactions

## Files Changed

1. `src/transaction/batch.rs` - New batch module
2. `src/transaction/mod.rs` - Export batch types
3. `src/aptos.rs` - Add batch convenience methods
4. `Cargo.toml` - Add `futures` dependency
5. `feature-plans/18-transaction-batching.md` - This document

## Future Enhancements

1. **Batch simulation** - Simulate all transactions before submission
2. **Retry failed transactions** - Automatically retry failed transactions
3. **Rate limiting** - Control submission rate to avoid overwhelming nodes
4. **Batch cancellation** - Cancel pending transactions
5. **Progress callbacks** - Report progress during submission

