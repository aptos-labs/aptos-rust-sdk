//! Error types for the Aptos SDK.
//!
//! This module provides a unified error type [`AptosError`] that encompasses
//! all possible errors that can occur when using the SDK.

use std::fmt;
use thiserror::Error;

/// A specialized Result type for Aptos SDK operations.
pub type AptosResult<T> = Result<T, AptosError>;

/// The main error type for the Aptos SDK.
///
/// This enum covers all possible error conditions that can occur when
/// interacting with the Aptos blockchain through this SDK.
#[derive(Error, Debug)]
pub enum AptosError {
    /// Error occurred during HTTP communication
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Error occurred during JSON serialization/deserialization
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Error occurred during BCS serialization/deserialization
    #[error("BCS error: {0}")]
    Bcs(String),

    /// Error occurred during URL parsing
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),

    /// Error occurred during hex encoding/decoding
    #[error("Hex error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// Invalid account address
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid private key
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Invalid type tag format
    #[error("Invalid type tag: {0}")]
    InvalidTypeTag(String),

    /// Transaction building error
    #[error("Transaction error: {0}")]
    Transaction(String),

    /// Transaction simulation failed
    #[error("Simulation failed: {0}")]
    SimulationFailed(String),

    /// Transaction submission failed
    #[error("Submission failed: {0}")]
    SubmissionFailed(String),

    /// Transaction execution failed on chain
    #[error("Execution failed: {vm_status}")]
    ExecutionFailed {
        /// The VM status message explaining the failure
        vm_status: String,
    },

    /// Transaction timed out waiting for confirmation
    #[error("Transaction timed out after {timeout_secs} seconds")]
    TransactionTimeout {
        /// The hash of the transaction that timed out
        hash: String,
        /// How long we waited before timing out
        timeout_secs: u64,
    },

    /// API returned an error response
    #[error("API error ({status_code}): {message}")]
    Api {
        /// HTTP status code
        status_code: u16,
        /// Error message from the API
        message: String,
        /// Optional error code from the API
        error_code: Option<String>,
        /// Optional VM error code
        vm_error_code: Option<u64>,
    },

    /// Rate limited by the API
    #[error("Rate limited: retry after {retry_after_secs:?} seconds")]
    RateLimited {
        /// How long to wait before retrying (if provided)
        retry_after_secs: Option<u64>,
    },

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Account not found
    #[error("Account not found: {0}")]
    AccountNotFound(String),

    /// Invalid mnemonic phrase
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Invalid JWT
    #[error("Invalid JWT: {0}")]
    InvalidJwt(String),

    /// Key derivation error
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    /// Insufficient signatures for multi-signature operation
    #[error("Insufficient signatures: need {required}, got {provided}")]
    InsufficientSignatures {
        /// Number of signatures required
        required: usize,
        /// Number of signatures provided
        provided: usize,
    },

    /// Feature not enabled
    #[error("Feature not enabled: {0}. Enable the '{0}' feature in Cargo.toml")]
    FeatureNotEnabled(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Internal SDK error (should not happen)
    #[error("Internal error: {0}")]
    Internal(String),

    /// Any other error
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl AptosError {
    /// Creates a new BCS error
    pub fn bcs<E: fmt::Display>(err: E) -> Self {
        Self::Bcs(err.to_string())
    }

    /// Creates a new transaction error
    pub fn transaction<S: Into<String>>(msg: S) -> Self {
        Self::Transaction(msg.into())
    }

    /// Creates a new API error from response details
    pub fn api(status_code: u16, message: impl Into<String>) -> Self {
        Self::Api {
            status_code,
            message: message.into(),
            error_code: None,
            vm_error_code: None,
        }
    }

    /// Creates a new API error with additional details
    pub fn api_with_details(
        status_code: u16,
        message: impl Into<String>,
        error_code: Option<String>,
        vm_error_code: Option<u64>,
    ) -> Self {
        Self::Api {
            status_code,
            message: message.into(),
            error_code,
            vm_error_code,
        }
    }

    /// Returns true if this is a "not found" error
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::NotFound(_)
                | Self::AccountNotFound(_)
                | Self::Api {
                    status_code: 404,
                    ..
                }
        )
    }

    /// Returns true if this is a timeout error
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::TransactionTimeout { .. })
    }

    /// Returns true if this is a transient error that might succeed on retry
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(e) => e.is_timeout() || e.is_connect(),
            Self::Api { status_code, .. } => {
                matches!(status_code, 429 | 500 | 502 | 503 | 504)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = AptosError::InvalidAddress("bad address".to_string());
        assert_eq!(err.to_string(), "Invalid address: bad address");
    }

    #[test]
    fn test_is_not_found() {
        assert!(AptosError::NotFound("test".to_string()).is_not_found());
        assert!(AptosError::AccountNotFound("0x1".to_string()).is_not_found());
        assert!(AptosError::api(404, "not found").is_not_found());
        assert!(!AptosError::api(500, "server error").is_not_found());
    }

    #[test]
    fn test_is_retryable() {
        assert!(AptosError::api(429, "rate limited").is_retryable());
        assert!(AptosError::api(503, "unavailable").is_retryable());
        assert!(AptosError::api(500, "internal error").is_retryable());
        assert!(AptosError::api(502, "bad gateway").is_retryable());
        assert!(AptosError::api(504, "timeout").is_retryable());
        assert!(!AptosError::api(400, "bad request").is_retryable());
    }

    #[test]
    fn test_is_timeout() {
        let err = AptosError::TransactionTimeout {
            hash: "0x123".to_string(),
            timeout_secs: 30,
        };
        assert!(err.is_timeout());
        assert!(!AptosError::InvalidAddress("test".to_string()).is_timeout());
    }

    #[test]
    fn test_bcs_error() {
        let err = AptosError::bcs("serialization failed");
        assert!(matches!(err, AptosError::Bcs(_)));
        assert!(err.to_string().contains("serialization failed"));
    }

    #[test]
    fn test_transaction_error() {
        let err = AptosError::transaction("invalid payload");
        assert!(matches!(err, AptosError::Transaction(_)));
        assert!(err.to_string().contains("invalid payload"));
    }

    #[test]
    fn test_api_error() {
        let err = AptosError::api(400, "bad request");
        assert!(err.to_string().contains("400"));
        assert!(err.to_string().contains("bad request"));
    }

    #[test]
    fn test_api_error_with_details() {
        let err = AptosError::api_with_details(
            400,
            "invalid argument",
            Some("INVALID_ARGUMENT".to_string()),
            Some(42),
        );
        if let AptosError::Api {
            status_code,
            message,
            error_code,
            vm_error_code,
        } = err
        {
            assert_eq!(status_code, 400);
            assert_eq!(message, "invalid argument");
            assert_eq!(error_code, Some("INVALID_ARGUMENT".to_string()));
            assert_eq!(vm_error_code, Some(42));
        } else {
            panic!("Expected Api error variant");
        }
    }

    #[test]
    fn test_various_error_displays() {
        assert!(
            AptosError::InvalidPublicKey("bad key".to_string())
                .to_string()
                .contains("public key")
        );
        assert!(
            AptosError::InvalidPrivateKey("bad key".to_string())
                .to_string()
                .contains("private key")
        );
        assert!(
            AptosError::InvalidSignature("bad sig".to_string())
                .to_string()
                .contains("signature")
        );
        assert!(
            AptosError::SignatureVerificationFailed
                .to_string()
                .contains("verification")
        );
        assert!(
            AptosError::InvalidTypeTag("bad tag".to_string())
                .to_string()
                .contains("type tag")
        );
        assert!(
            AptosError::SimulationFailed("error".to_string())
                .to_string()
                .contains("Simulation")
        );
        assert!(
            AptosError::SubmissionFailed("error".to_string())
                .to_string()
                .contains("Submission")
        );
    }

    #[test]
    fn test_execution_failed() {
        let err = AptosError::ExecutionFailed {
            vm_status: "ABORTED".to_string(),
        };
        assert!(err.to_string().contains("ABORTED"));
    }

    #[test]
    fn test_rate_limited() {
        let err = AptosError::RateLimited {
            retry_after_secs: Some(30),
        };
        assert!(err.to_string().contains("Rate limited"));
    }

    #[test]
    fn test_insufficient_signatures() {
        let err = AptosError::InsufficientSignatures {
            required: 3,
            provided: 1,
        };
        assert!(err.to_string().contains("3"));
        assert!(err.to_string().contains("1"));
    }

    #[test]
    fn test_feature_not_enabled() {
        let err = AptosError::FeatureNotEnabled("ed25519".to_string());
        assert!(err.to_string().contains("ed25519"));
        assert!(err.to_string().contains("Cargo.toml"));
    }

    #[test]
    fn test_config_error() {
        let err = AptosError::Config("invalid config".to_string());
        assert!(err.to_string().contains("Configuration"));
    }

    #[test]
    fn test_internal_error() {
        let err = AptosError::Internal("bug".to_string());
        assert!(err.to_string().contains("Internal"));
    }

    #[test]
    fn test_invalid_mnemonic() {
        let err = AptosError::InvalidMnemonic("bad phrase".to_string());
        assert!(err.to_string().contains("mnemonic"));
    }

    #[test]
    fn test_invalid_jwt() {
        let err = AptosError::InvalidJwt("bad token".to_string());
        assert!(err.to_string().contains("JWT"));
    }

    #[test]
    fn test_key_derivation() {
        let err = AptosError::KeyDerivation("failed".to_string());
        assert!(err.to_string().contains("derivation"));
    }
}
