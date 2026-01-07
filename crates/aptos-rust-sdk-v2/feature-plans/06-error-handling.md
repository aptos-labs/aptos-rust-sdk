# Error Handling

## Overview

Unified error handling across the SDK with rich context and proper error propagation.

## Goals

1. Single error type for all SDK operations
2. Rich error context for debugging
3. Proper error conversion from dependencies
4. Actionable error messages

## Non-Goals

- Error recovery (user responsibility)
- Logging (user chooses logging framework)

---

## API Design

### AptosError

```rust
/// Main SDK error type.
#[derive(Debug, thiserror::Error)]
pub enum AptosError {
    /// Network/HTTP error.
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    
    /// Request timed out.
    #[error("Request timed out")]
    Timeout,
    
    /// API returned an error.
    #[error("API error ({code}): {message}")]
    Api {
        message: String,
        code: String,
        vm_error: Option<u64>,
    },
    
    /// Resource not found (404).
    #[error("{resource} not found")]
    NotFound { resource: String },
    
    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    /// Invalid input.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    /// Cryptographic error.
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    /// Transaction failed.
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
}

impl AptosError {
    /// Check if error is "not found".
    pub fn is_not_found(&self) -> bool;
    
    /// Check if error is retryable.
    pub fn is_retryable(&self) -> bool;
    
    /// Get VM error code if available.
    pub fn vm_error_code(&self) -> Option<u64>;
}

/// Result type alias.
pub type AptosResult<T> = Result<T, AptosError>;
```

---

## Error Categories

| Category | Examples | Retryable |
|----------|----------|-----------|
| Network | Connection refused, DNS failure | Yes |
| Timeout | Request timeout | Yes |
| API | Rate limited, invalid request | Sometimes |
| NotFound | Account not found, resource missing | No |
| Serialization | Invalid BCS, bad JSON | No |
| Crypto | Invalid key, signature failure | No |

---

## Testing Requirements

```rust
#[test]
fn test_error_display() {
    let error = AptosError::NotFound { 
        resource: "account 0x1".into() 
    };
    assert_eq!(error.to_string(), "account 0x1 not found");
}

#[test]
fn test_is_not_found() {
    let error = AptosError::NotFound { resource: "x".into() };
    assert!(error.is_not_found());
}
```

---

## Dependencies

- `thiserror`: Derive Error trait
- `reqwest`: Network errors

