# Feature 14: Automatic Retry with Exponential Backoff

## Overview

This feature implements automatic retry logic for API calls with exponential backoff and jitter. It helps applications handle transient failures gracefully, improving reliability in production environments.

## Goals

1. **Resilience**: Automatically recover from temporary network failures and rate limiting
2. **Configurable**: Allow customization of retry behavior per use case
3. **Smart Defaults**: Provide sensible defaults that work well for most applications
4. **Jitter Support**: Prevent thundering herd problems with randomized delays
5. **Non-Intrusive**: Enable retry without changing API call patterns

## API Design

### RetryConfig

```rust
use aptos_rust_sdk_v2::retry::RetryConfig;

// Default configuration (3 retries, 100ms initial delay, 2x backoff)
let config = RetryConfig::default();

// Preset configurations
let aggressive = RetryConfig::aggressive();  // 5 retries, 50ms initial, fast recovery
let conservative = RetryConfig::conservative();  // 3 retries, 500ms initial, slow recovery
let no_retry = RetryConfig::no_retry();  // Fail fast, no retries

// Custom configuration via builder
let custom = RetryConfig::builder()
    .max_retries(5)
    .initial_delay_ms(100)
    .max_delay_ms(10_000)
    .exponential_base(2.0)
    .jitter(true)
    .jitter_factor(0.5)
    .retryable_status_codes(vec![429, 503, 504])
    .build();
```

### Integration with AptosConfig

```rust
use aptos_rust_sdk_v2::{Aptos, AptosConfig};
use aptos_rust_sdk_v2::retry::RetryConfig;

// Configure retry at client level
let aptos = Aptos::new(
    AptosConfig::testnet()
        .with_retry(RetryConfig::aggressive())
)?;

// Or disable retry
let aptos = Aptos::new(
    AptosConfig::testnet().without_retry()
)?;

// Convenience method for max_retries
let aptos = Aptos::new(
    AptosConfig::testnet().with_max_retries(5)
)?;
```

### Network-Specific Defaults

| Network | Default Retry Strategy | Rationale |
|---------|----------------------|-----------|
| Mainnet | Conservative | Production workloads need careful retry |
| Testnet | Default | Balanced for development |
| Devnet | Default | Balanced for development |
| Local | Aggressive | Fast iteration during development |

## Implementation Details

### Exponential Backoff Formula

```
delay = min(initial_delay * (base ^ (attempt - 1)), max_delay)
```

With jitter:
```
jitter_range = delay * jitter_factor
delay = delay + random(-jitter_range, +jitter_range)
```

### Retryable Conditions

By default, the following conditions trigger a retry:

1. **HTTP Errors**: Network-level failures (connection refused, timeout)
2. **Status Codes**:
   - 408 Request Timeout
   - 429 Too Many Requests
   - 500 Internal Server Error
   - 502 Bad Gateway
   - 503 Service Unavailable
   - 504 Gateway Timeout
3. **Rate Limiting**: `AptosError::RateLimited`

Non-retryable errors (immediate failure):
- 400 Bad Request
- 401 Unauthorized
- 403 Forbidden
- 404 Not Found
- 422 Unprocessable Entity
- Validation errors
- Signature errors

### RetryExecutor

The `RetryExecutor` provides fine-grained control over retry behavior:

```rust
use aptos_rust_sdk_v2::retry::{RetryConfig, RetryExecutor};

let executor = RetryExecutor::new(RetryConfig::default());

// Standard retry
let result = executor.execute(|| async {
    // Your operation here
    client.get_ledger_info().await
}).await?;

// Custom retry predicate
let result = executor.execute_with_predicate(
    || async { /* operation */ },
    |error| {
        // Custom logic to determine if we should retry
        matches!(error, AptosError::RateLimited { .. })
    }
).await?;
```

### Convenience Functions

```rust
use aptos_rust_sdk_v2::retry::{retry, retry_with_config, RetryConfig};

// Retry with default config
let result = retry(|| async {
    fetch_data().await
}).await?;

// Retry with custom config
let config = RetryConfig::aggressive();
let result = retry_with_config(&config, || async {
    fetch_data().await
}).await?;
```

## Integrated Clients

Retry is automatically applied to all API clients:

### FullnodeClient
- GET requests (ledger info, accounts, resources, transactions)
- POST requests (submit, simulate, view functions)

### FaucetClient
- Fund requests (retries help with rate limiting)

### IndexerClient
- GraphQL queries

## Testing

### Unit Tests
- Configuration validation
- Delay calculation (with and without jitter)
- Retryable error detection
- Builder pattern
- Preset configurations

### Behavioral Tests
- Retry succeeds on first try (no unnecessary delay)
- Retry succeeds after N failures
- Retry exhausted after max attempts
- Non-retryable errors fail immediately
- Custom predicates work correctly

### Integration Tests
- Works with mock servers returning 503
- Works with rate-limited responses
- Maintains request idempotency for transactions

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_retries` | u32 | 3 | Maximum retry attempts |
| `initial_delay_ms` | u64 | 100 | Initial delay in milliseconds |
| `max_delay_ms` | u64 | 10,000 | Maximum delay cap |
| `exponential_base` | f64 | 2.0 | Backoff multiplier |
| `jitter` | bool | true | Enable random jitter |
| `jitter_factor` | f64 | 0.5 | How much jitter (0.0-1.0) |
| `retryable_status_codes` | Vec<u16> | [408,429,500,502,503,504] | HTTP codes to retry |

## Error Handling

When all retries are exhausted, the last error is returned. This ensures:
- Clear error messages for debugging
- Proper error types maintained
- No loss of error context

## Performance Considerations

1. **Memory**: Minimal overhead (config cloned once per client)
2. **CPU**: Negligible - only activates on failures
3. **Network**: Reduces unnecessary reconnection storms
4. **Latency**: First successful request has zero overhead

## Security Considerations

1. **Idempotency**: Transaction submission is safe to retry (same hash)
2. **No Secrets in Logs**: Retry doesn't log sensitive data
3. **Rate Limit Respect**: Jitter helps avoid hammer attacks

## Example Usage

```rust
use aptos_rust_sdk_v2::{Aptos, AptosConfig};
use aptos_rust_sdk_v2::retry::RetryConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Production: conservative retry for stability
    let mainnet_client = Aptos::new(
        AptosConfig::mainnet()
            .with_retry(RetryConfig::conservative())
    )?;
    
    // Development: aggressive retry for fast iteration
    let devnet_client = Aptos::new(
        AptosConfig::devnet()
            .with_retry(RetryConfig::aggressive())
    )?;
    
    // Testing: no retry for predictable behavior
    let test_client = Aptos::new(
        AptosConfig::testnet().without_retry()
    )?;
    
    // Custom: specific requirements
    let custom_client = Aptos::new(
        AptosConfig::custom("https://my-node.example.com/v1")?
            .with_retry(
                RetryConfig::builder()
                    .max_retries(10)
                    .initial_delay_ms(50)
                    .max_delay_ms(30_000)
                    .build()
            )
    )?;
    
    // All API calls now automatically retry on transient failures
    let ledger_info = mainnet_client.ledger_info().await?;
    println!("Version: {}", ledger_info.version());
    
    Ok(())
}
```

## Status

✅ **Implemented**
- RetryConfig with builder pattern
- Preset configurations (default, aggressive, conservative, no_retry)
- Exponential backoff with jitter
- RetryExecutor for custom retry logic
- Integration with AptosConfig
- Integration with FullnodeClient
- Integration with FaucetClient
- Integration with IndexerClient
- Comprehensive unit tests
- RateLimited error type added

