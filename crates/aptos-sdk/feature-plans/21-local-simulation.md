# Feature Plan: Transaction Simulation

## Overview

Transaction simulation allows you to test transactions before submitting them to the network. This helps predict outcomes, estimate gas costs, and catch errors early without spending gas.

## Goals

1. **Pre-flight validation** - Check if transactions will succeed
2. **Accurate gas estimation** - Get precise gas usage via simulation
3. **Error extraction** - Parse and categorize VM errors
4. **State inspection** - See what changes a transaction would make
5. **Safe submission** - Simulate before submitting

## API Design

### SimulationResult

```rust
/// Result of a transaction simulation.
#[derive(Debug, Clone)]
pub struct SimulationResult {
    success: bool,
    vm_status: String,
    gas_used: u64,
    max_gas_amount: u64,
    gas_unit_price: u64,
    changes: Vec<StateChange>,
    events: Vec<SimulatedEvent>,
    hash: String,
    vm_error: Option<VmError>,
    raw: serde_json::Value,
}

impl SimulationResult {
    // Status
    pub fn success(&self) -> bool;
    pub fn failed(&self) -> bool;
    pub fn vm_status(&self) -> &str;

    // Gas
    pub fn gas_used(&self) -> u64;
    pub fn gas_cost(&self) -> u64;
    pub fn safe_gas_estimate(&self) -> u64;  // +20% safety margin

    // State
    pub fn changes(&self) -> &[StateChange];
    pub fn events(&self) -> &[SimulatedEvent];

    // Errors
    pub fn vm_error(&self) -> Option<&VmError>;
    pub fn is_insufficient_balance(&self) -> bool;
    pub fn is_sequence_number_error(&self) -> bool;
    pub fn is_out_of_gas(&self) -> bool;
    pub fn error_message(&self) -> Option<String>;
}
```

### VmError

```rust
/// Detailed VM error information.
#[derive(Debug, Clone)]
pub struct VmError {
    pub category: VmErrorCategory,
    pub status: String,
    pub abort_code: Option<u64>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmErrorCategory {
    InsufficientBalance,
    SequenceNumber,
    OutOfGas,
    MoveAbort,
    ResourceNotFound,
    ModuleNotFound,
    FunctionNotFound,
    TypeMismatch,
    Unknown,
}
```

### StateChange & SimulatedEvent

```rust
/// A state change from a simulated transaction.
#[derive(Debug, Clone)]
pub struct StateChange {
    pub change_type: String,
    pub address: String,
    pub resource_type: Option<String>,
    pub module: Option<String>,
    pub data: Option<serde_json::Value>,
}

/// An event from a simulated transaction.
#[derive(Debug, Clone)]
pub struct SimulatedEvent {
    pub event_type: String,
    pub sequence_number: u64,
    pub data: serde_json::Value,
}
```

### Aptos Client Methods

```rust
impl Aptos {
    /// Simulates a transaction and returns a parsed result.
    pub async fn simulate<A: Account>(
        &self,
        account: &A,
        payload: TransactionPayload,
    ) -> AptosResult<SimulationResult>;

    /// Simulates a pre-built signed transaction.
    pub async fn simulate_signed(
        &self,
        signed_txn: &SignedTransaction,
    ) -> AptosResult<SimulationResult>;

    /// Estimates gas by simulation (+20% safety margin).
    pub async fn estimate_gas<A: Account>(
        &self,
        account: &A,
        payload: TransactionPayload,
    ) -> AptosResult<u64>;

    /// Simulates and submits if successful.
    pub async fn simulate_and_submit<A: Account>(
        &self,
        account: &A,
        payload: TransactionPayload,
    ) -> AptosResult<AptosResponse<PendingTransaction>>;

    /// Simulates, submits, and waits.
    pub async fn simulate_submit_and_wait<A: Account>(
        &self,
        account: &A,
        payload: TransactionPayload,
        timeout: Option<Duration>,
    ) -> AptosResult<AptosResponse<serde_json::Value>>;
}
```

## Usage Examples

### Basic Simulation

```rust
let aptos = Aptos::testnet()?;
let payload = InputEntryFunctionData::transfer_apt(recipient, 1_000_000)?;

let result = aptos.simulate(&account, payload).await?;

if result.success() {
    println!("Transaction will succeed!");
    println!("Gas used: {}", result.gas_used());
    println!("Gas cost: {} octas", result.gas_cost());
} else {
    println!("Transaction will fail: {}", result.vm_status());
    if let Some(error) = result.vm_error() {
        println!("Error: {}", error.user_message());
    }
}
```

### Gas Estimation

```rust
let gas = aptos.estimate_gas(&account, payload).await?;
println!("Estimated gas (with 20% buffer): {}", gas);

// Use the estimate in transaction builder
let txn = TransactionBuilder::new()
    .max_gas_amount(gas)
    // ... other fields
    .build()?;
```

### Safe Submission

```rust
// Simulate first, only submit if successful
let result = aptos.simulate_and_submit(&account, payload).await?;
println!("Submitted: {}", result.data.hash);

// Or simulate, submit, and wait
let result = aptos.simulate_submit_and_wait(&account, payload, None).await?;
```

### Error Handling

```rust
let result = aptos.simulate(&account, payload).await?;

if result.is_insufficient_balance() {
    println!("Not enough balance!");
} else if result.is_out_of_gas() {
    println!("Need more gas!");
} else if result.is_sequence_number_error() {
    println!("Sequence number mismatch - retry with fresh number");
} else if result.failed() {
    if let Some(msg) = result.error_message() {
        println!("Error: {}", msg);
    }
}
```

### Inspecting State Changes

```rust
let result = aptos.simulate(&account, payload).await?;

for change in result.changes() {
    if change.is_write() {
        println!("Would write to: {} - {}", change.address, 
            change.resource_type.as_deref().unwrap_or("unknown"));
    }
}

for event in result.events() {
    println!("Would emit: {} (seq={})", event.event_type, event.sequence_number);
}
```

## Implementation Details

### Simulation Workflow

1. Build transaction with current sequence number and gas price
2. Sign transaction (signature is validated but not checked)
3. Send to `/transactions/simulate` endpoint
4. Parse response into `SimulationResult`
5. Extract errors, gas info, state changes, and events

### Gas Safety Margin

`safe_gas_estimate()` adds 20% to simulated gas because:
- Actual execution may vary slightly
- State changes between simulation and submission
- Safety buffer for edge cases

### Error Categories

| Category | Detected By |
|----------|-------------|
| `InsufficientBalance` | "INSUFFICIENT", "NOT_ENOUGH" |
| `SequenceNumber` | "SEQUENCE_NUMBER" |
| `OutOfGas` | "OUT_OF_GAS" |
| `MoveAbort` | "ABORT" |
| `ResourceNotFound` | "RESOURCE" + "NOT" |
| `ModuleNotFound` | "MODULE" + "NOT" |
| `FunctionNotFound` | "FUNCTION" + "NOT" |
| `TypeMismatch` | "TYPE" + "MISMATCH"/"ERROR" |

## Testing

### Unit Tests

1. **Result parsing** - Parse success/failure responses
2. **Error categorization** - Classify VM errors correctly
3. **Gas calculations** - Safety margin math
4. **Event parsing** - Extract event details
5. **Change parsing** - Extract state changes

### Integration Tests (require network)

1. **Successful simulation** - Transfer APT
2. **Failed simulation** - Insufficient balance
3. **Gas estimation accuracy** - Compare to actual
4. **Simulate and submit** - Full workflow

## Dependencies

- Uses existing `FullnodeClient::simulate_transaction`
- No new external dependencies

## Files Changed

1. `src/transaction/simulation.rs` - New simulation module
2. `src/transaction/mod.rs` - Export simulation types
3. `src/aptos.rs` - Add simulation convenience methods
4. `feature-plans/21-local-simulation.md` - This document

## Limitations

1. **Network Required** - Uses fullnode's simulation endpoint (not truly "local")
2. **State Changes** - State may change between simulation and submission
3. **Timing** - Adds latency to transaction submission workflow
4. **Rate Limits** - Simulation calls count toward API rate limits

## Future Enhancements

1. **Local VM** - Run Move VM locally for truly local simulation
2. **Caching** - Cache simulation results for repeated calls
3. **Batch simulation** - Simulate multiple transactions at once
4. **Diff view** - Show human-readable state diffs
5. **Cost analysis** - Break down gas by operation type

