# Feature 15: Connection Pooling

## Overview

This feature adds configurable HTTP connection pooling for all API clients, improving performance by reusing connections across multiple requests.

## Goals

1. **Performance**: Reduce connection overhead for high-frequency API calls
2. **Configurability**: Allow tuning for different use cases (high-throughput, low-latency, minimal)
3. **Smart Defaults**: Provide sensible defaults that work well for most applications
4. **Network Optimization**: Enable TCP keepalive and nodelay for better performance

## API Design

### PoolConfig

```rust
use aptos_sdk::config::PoolConfig;

// Default configuration
let config = PoolConfig::default();

// Preset configurations
let high = PoolConfig::high_throughput();  // Many idle connections, long timeout
let low = PoolConfig::low_latency();       // Fewer connections, TCP nodelay
let minimal = PoolConfig::minimal();       // Constrained environments

// Custom configuration via builder
let custom = PoolConfig::builder()
    .max_idle_per_host(16)
    .max_idle_total(64)
    .idle_timeout(Duration::from_secs(60))
    .tcp_keepalive(Duration::from_secs(30))
    .tcp_nodelay(true)
    .build();
```

### Integration with AptosConfig

```rust
use aptos_sdk::{Aptos, AptosConfig};
use aptos_sdk::config::PoolConfig;

// Configure pool at client level
let aptos = Aptos::new(
    AptosConfig::testnet()
        .with_pool(PoolConfig::high_throughput())
)?;

// Network-specific defaults are applied automatically
let aptos = Aptos::new(AptosConfig::local())?;  // Uses low_latency preset
```

### Network-Specific Defaults

| Network | Pool Preset | Rationale |
|---------|-------------|-----------|
| Mainnet | Default | Balanced for production |
| Testnet | Default | Balanced for development |
| Devnet | Default | Balanced for development |
| Local | Low Latency | Fast iteration during development |

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_idle_per_host` | Option<usize> | None (unlimited) | Max idle connections per host |
| `max_idle_total` | usize | 100 | Max total idle connections |
| `idle_timeout` | Duration | 90s | How long to keep idle connections |
| `tcp_keepalive` | Option<Duration> | Some(60s) | TCP keepalive interval |
| `tcp_nodelay` | bool | true | Disable Nagle's algorithm |

## Preset Configurations

### `PoolConfig::default()`
- `max_idle_per_host`: unlimited
- `max_idle_total`: 100
- `idle_timeout`: 90 seconds
- `tcp_keepalive`: 60 seconds
- `tcp_nodelay`: true

### `PoolConfig::high_throughput()`
- `max_idle_per_host`: 32
- `max_idle_total`: 256
- `idle_timeout`: 5 minutes
- `tcp_keepalive`: 30 seconds
- `tcp_nodelay`: true

### `PoolConfig::low_latency()`
- `max_idle_per_host`: 8
- `max_idle_total`: 32
- `idle_timeout`: 30 seconds
- `tcp_keepalive`: 15 seconds
- `tcp_nodelay`: true

### `PoolConfig::minimal()`
- `max_idle_per_host`: 2
- `max_idle_total`: 8
- `idle_timeout`: 10 seconds
- `tcp_keepalive`: None
- `tcp_nodelay`: true

## Implementation Details

### HTTP Client Configuration

The pool configuration is applied to `reqwest::Client`:

```rust
let mut builder = Client::builder()
    .timeout(config.timeout)
    .pool_max_idle_per_host(pool.max_idle_per_host.unwrap_or(usize::MAX))
    .pool_idle_timeout(pool.idle_timeout)
    .tcp_nodelay(pool.tcp_nodelay);

if let Some(keepalive) = pool.tcp_keepalive {
    builder = builder.tcp_keepalive(keepalive);
}
```

### Applied To

Connection pooling is applied to all API clients:
- `FullnodeClient`
- `FaucetClient`
- `IndexerClient`

## Testing

### Unit Tests
- Default configuration values
- Preset configurations
- Builder pattern
- Integration with `AptosConfig`

## Performance Considerations

1. **Connection Reuse**: Avoid TCP handshake overhead for subsequent requests
2. **HTTP/2 Multiplexing**: `reqwest` automatically uses HTTP/2 when available
3. **Memory Usage**: Idle connections consume memory; tune `max_idle_total` accordingly
4. **Stale Connections**: `idle_timeout` prevents using connections that may have been closed

## Security Considerations

1. **Connection Limits**: Prevent resource exhaustion with reasonable limits
2. **Idle Timeouts**: Clean up unused connections to free resources
3. **TCP Keepalive**: Detect dead connections early

## Status

✅ **Implemented**
- PoolConfig with builder pattern
- Preset configurations (default, high_throughput, low_latency, minimal)
- Integration with AptosConfig
- Applied to all API clients (Fullnode, Faucet, Indexer)
- Comprehensive unit tests

