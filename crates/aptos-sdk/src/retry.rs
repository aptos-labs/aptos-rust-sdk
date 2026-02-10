//! Automatic retry with exponential backoff.
//!
//! This module provides retry functionality for handling transient failures
//! in API calls. It implements exponential backoff with optional jitter to
//! prevent thundering herd problems.
//!
//! # Example
//!
//! ```rust,ignore
//! use aptos_sdk::retry::{RetryConfig, RetryPolicy};
//!
//! // Create a custom retry policy
//! let config = RetryConfig::builder()
//!     .max_retries(5)
//!     .initial_delay_ms(100)
//!     .max_delay_ms(10_000)
//!     .exponential_base(2.0)
//!     .jitter(true)
//!     .build();
//!
//! // Use with the Aptos client
//! let aptos = Aptos::new(AptosConfig::testnet().with_retry(config))?;
//! ```

use crate::error::{AptosError, AptosResult};
use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (0 = no retries).
    pub max_retries: u32,
    /// Initial delay before the first retry (in milliseconds).
    pub initial_delay_ms: u64,
    /// Maximum delay between retries (in milliseconds).
    pub max_delay_ms: u64,
    /// Base for exponential backoff (typically 2.0).
    pub exponential_base: f64,
    /// Whether to add random jitter to delays.
    pub jitter: bool,
    /// Jitter factor (0.0 to 1.0) - how much randomness to add.
    pub jitter_factor: f64,
    /// HTTP status codes that should trigger a retry.
    /// Uses `HashSet` for O(1) lookups instead of O(n) linear search.
    pub retryable_status_codes: HashSet<u16>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 100,
            max_delay_ms: 10_000,
            exponential_base: 2.0,
            jitter: true,
            jitter_factor: 0.5,
            retryable_status_codes: [
                408, // Request Timeout
                429, // Too Many Requests
                500, // Internal Server Error
                502, // Bad Gateway
                503, // Service Unavailable
                504, // Gateway Timeout
            ]
            .into_iter()
            .collect(),
        }
    }
}

impl RetryConfig {
    /// Creates a new builder for `RetryConfig`.
    pub fn builder() -> RetryConfigBuilder {
        RetryConfigBuilder::default()
    }

    /// Creates a config with no retries (fail fast).
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Creates a config optimized for aggressive retrying.
    pub fn aggressive() -> Self {
        Self {
            max_retries: 5,
            initial_delay_ms: 50,
            max_delay_ms: 5_000,
            exponential_base: 1.5,
            jitter: true,
            jitter_factor: 0.3,
            ..Default::default()
        }
    }

    /// Creates a config optimized for conservative retrying.
    pub fn conservative() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 500,
            max_delay_ms: 30_000,
            exponential_base: 2.0,
            jitter: true,
            jitter_factor: 0.5,
            ..Default::default()
        }
    }

    /// Calculates the delay for a given attempt number.
    #[allow(clippy::cast_possible_truncation)] // Delay is bounded by max_delay_ms
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::from_millis(0);
        }

        // Calculate base delay with exponential backoff
        #[allow(clippy::cast_precision_loss)] // Delay is bounded by max_delay_ms
        let base_delay = self.initial_delay_ms as f64
            * self
                .exponential_base
                .powi(attempt.saturating_sub(1).cast_signed());

        // Cap at max delay
        #[allow(clippy::cast_precision_loss)] // Delay is bounded by max_delay_ms
        let capped_delay = base_delay.min(self.max_delay_ms as f64);

        // Add jitter if enabled
        let final_delay = if self.jitter {
            let jitter_range = capped_delay * self.jitter_factor;
            let jitter = rand::random::<f64>() * jitter_range * 2.0 - jitter_range;
            (capped_delay + jitter).max(0.0)
        } else {
            capped_delay
        };

        #[allow(clippy::cast_sign_loss)] // Delay is bounded by max_delay_ms
        Duration::from_millis(final_delay as u64)
    }

    /// Checks if a status code should trigger a retry.
    #[inline]
    pub fn is_retryable_status(&self, status_code: u16) -> bool {
        self.retryable_status_codes.contains(&status_code)
    }

    /// Checks if an error should trigger a retry.
    #[inline]
    pub fn is_retryable_error(&self, error: &AptosError) -> bool {
        match error {
            // Network errors are typically transient
            AptosError::Http(_) | AptosError::RateLimited { .. } => true,
            // API errors with retryable status codes
            AptosError::Api { status_code, .. } => self.is_retryable_status(*status_code),
            // Other errors are not retried
            _ => false,
        }
    }
}

/// Builder for `RetryConfig`.
#[derive(Debug, Clone, Default)]
pub struct RetryConfigBuilder {
    max_retries: Option<u32>,
    initial_delay_ms: Option<u64>,
    max_delay_ms: Option<u64>,
    exponential_base: Option<f64>,
    jitter: Option<bool>,
    jitter_factor: Option<f64>,
    retryable_status_codes: Option<HashSet<u16>>,
}

impl RetryConfigBuilder {
    /// Sets the maximum number of retry attempts.
    #[must_use]
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = Some(max_retries);
        self
    }

    /// Sets the initial delay before the first retry (in milliseconds).
    #[must_use]
    pub fn initial_delay_ms(mut self, initial_delay_ms: u64) -> Self {
        self.initial_delay_ms = Some(initial_delay_ms);
        self
    }

    /// Sets the maximum delay between retries (in milliseconds).
    #[must_use]
    pub fn max_delay_ms(mut self, max_delay_ms: u64) -> Self {
        self.max_delay_ms = Some(max_delay_ms);
        self
    }

    /// Sets the base for exponential backoff.
    #[must_use]
    pub fn exponential_base(mut self, base: f64) -> Self {
        self.exponential_base = Some(base);
        self
    }

    /// Enables or disables jitter.
    #[must_use]
    pub fn jitter(mut self, jitter: bool) -> Self {
        self.jitter = Some(jitter);
        self
    }

    /// Sets the jitter factor (0.0 to 1.0).
    #[must_use]
    pub fn jitter_factor(mut self, factor: f64) -> Self {
        self.jitter_factor = Some(factor.clamp(0.0, 1.0));
        self
    }

    /// Sets the HTTP status codes that should trigger a retry.
    #[must_use]
    pub fn retryable_status_codes(mut self, codes: impl IntoIterator<Item = u16>) -> Self {
        self.retryable_status_codes = Some(codes.into_iter().collect());
        self
    }

    /// Adds a status code to the set of retryable codes.
    #[must_use]
    pub fn add_retryable_status_code(mut self, code: u16) -> Self {
        let mut codes = self.retryable_status_codes.unwrap_or_default();
        codes.insert(code);
        self.retryable_status_codes = Some(codes);
        self
    }

    /// Builds the `RetryConfig`.
    #[must_use]
    pub fn build(self) -> RetryConfig {
        let default = RetryConfig::default();
        RetryConfig {
            max_retries: self.max_retries.unwrap_or(default.max_retries),
            initial_delay_ms: self.initial_delay_ms.unwrap_or(default.initial_delay_ms),
            max_delay_ms: self.max_delay_ms.unwrap_or(default.max_delay_ms),
            exponential_base: self.exponential_base.unwrap_or(default.exponential_base),
            jitter: self.jitter.unwrap_or(default.jitter),
            jitter_factor: self.jitter_factor.unwrap_or(default.jitter_factor),
            retryable_status_codes: self
                .retryable_status_codes
                .unwrap_or(default.retryable_status_codes),
        }
    }
}

/// Executes an async operation with automatic retry.
#[derive(Debug, Clone)]
pub struct RetryExecutor {
    config: Arc<RetryConfig>,
}

impl RetryExecutor {
    /// Creates a new retry executor with the given config.
    pub fn new(config: RetryConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Creates a retry executor from a shared config, avoiding a clone.
    pub fn from_shared(config: Arc<RetryConfig>) -> Self {
        Self { config }
    }

    /// Creates a retry executor with default config.
    pub fn with_defaults() -> Self {
        Self::new(RetryConfig::default())
    }

    /// Executes an async operation with retry logic.
    ///
    /// The operation will be retried if it returns a retryable error,
    /// up to the configured maximum number of retries.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails and either the maximum number of
    /// retries has been exhausted or the error is not retryable according to
    /// the retry configuration.
    pub async fn execute<F, Fut, T>(&self, operation: F) -> AptosResult<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = AptosResult<T>>,
    {
        let mut attempt = 0;

        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    // Check if we should retry
                    if attempt >= self.config.max_retries || !self.config.is_retryable_error(&error)
                    {
                        return Err(error);
                    }

                    attempt += 1;

                    // SECURITY: Respect Retry-After header for rate limiting
                    // This prevents aggressive retries that could worsen rate limiting
                    let delay = if let AptosError::RateLimited {
                        retry_after_secs: Some(secs),
                    } = &error
                    {
                        // Use the server's Retry-After value, but cap it to prevent DoS
                        let capped_secs = (*secs).min(300); // Max 5 minutes
                        Duration::from_secs(capped_secs)
                    } else {
                        self.config.delay_for_attempt(attempt)
                    };

                    if !delay.is_zero() {
                        sleep(delay).await;
                    }
                }
            }
        }
    }

    /// Executes an async operation with retry logic and a custom retry predicate.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails and either the maximum number of
    /// retries has been exhausted or the custom retry predicate returns `false`.
    pub async fn execute_with_predicate<F, Fut, T, P>(
        &self,
        operation: F,
        should_retry: P,
    ) -> AptosResult<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = AptosResult<T>>,
        P: Fn(&AptosError) -> bool,
    {
        let mut attempt = 0;

        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    if attempt >= self.config.max_retries || !should_retry(&error) {
                        return Err(error);
                    }

                    attempt += 1;

                    // SECURITY: Respect Retry-After header for rate limiting
                    let delay = if let AptosError::RateLimited {
                        retry_after_secs: Some(secs),
                    } = &error
                    {
                        let capped_secs = (*secs).min(300);
                        Duration::from_secs(capped_secs)
                    } else {
                        self.config.delay_for_attempt(attempt)
                    };

                    if !delay.is_zero() {
                        sleep(delay).await;
                    }
                }
            }
        }
    }
}

/// Extension trait for adding retry capability to futures.
pub trait RetryExt<T> {
    /// Executes this future with the given retry config.
    fn with_retry(self, config: &RetryConfig) -> impl Future<Output = AptosResult<T>>;
}

/// Convenience function to retry an operation with default config.
///
/// # Errors
///
/// Returns an error if the operation fails and either the maximum number of
/// retries has been exhausted or the error is not retryable according to
/// the default retry configuration.
pub async fn retry<F, Fut, T>(operation: F) -> AptosResult<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = AptosResult<T>>,
{
    RetryExecutor::with_defaults().execute(operation).await
}

/// Convenience function to retry an operation with custom config.
///
/// # Errors
///
/// Returns an error if the operation fails and either the maximum number of
/// retries has been exhausted or the error is not retryable according to
/// the provided retry configuration.
pub async fn retry_with_config<F, Fut, T>(config: &RetryConfig, operation: F) -> AptosResult<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = AptosResult<T>>,
{
    RetryExecutor::new(config.clone()).execute(operation).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_default_config() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay_ms, 100);
        assert!(config.jitter);
    }

    #[test]
    fn test_no_retry_config() {
        let config = RetryConfig::no_retry();
        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn test_builder() {
        let config = RetryConfig::builder()
            .max_retries(5)
            .initial_delay_ms(200)
            .max_delay_ms(5000)
            .exponential_base(1.5)
            .jitter(false)
            .build();

        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_delay_ms, 200);
        assert_eq!(config.max_delay_ms, 5000);
        assert!((config.exponential_base - 1.5).abs() < f64::EPSILON);
        assert!(!config.jitter);
    }

    #[test]
    fn test_delay_calculation_no_jitter() {
        let config = RetryConfig::builder()
            .initial_delay_ms(100)
            .exponential_base(2.0)
            .jitter(false)
            .build();

        // Attempt 0 should have no delay
        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(0));

        // Attempt 1: 100ms
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(100));

        // Attempt 2: 100 * 2^1 = 200ms
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(200));

        // Attempt 3: 100 * 2^2 = 400ms
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(400));
    }

    #[test]
    fn test_delay_capped_at_max() {
        let config = RetryConfig::builder()
            .initial_delay_ms(1000)
            .max_delay_ms(2000)
            .exponential_base(2.0)
            .jitter(false)
            .build();

        // Attempt 3 would be 1000 * 2^2 = 4000ms, but capped at 2000ms
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(2000));
    }

    #[test]
    fn test_retryable_status_codes() {
        let config = RetryConfig::default();

        assert!(config.is_retryable_status(429)); // Too Many Requests
        assert!(config.is_retryable_status(503)); // Service Unavailable
        assert!(!config.is_retryable_status(400)); // Bad Request
        assert!(!config.is_retryable_status(404)); // Not Found
    }

    #[test]
    fn test_retryable_errors() {
        let config = RetryConfig::default();

        // API errors with retryable status codes
        let api_error = AptosError::Api {
            status_code: 503,
            message: "Service Unavailable".to_string(),
            error_code: None,
            vm_error_code: None,
        };
        assert!(config.is_retryable_error(&api_error));

        // Rate limited error
        let rate_limited = AptosError::RateLimited {
            retry_after_secs: Some(30),
        };
        assert!(config.is_retryable_error(&rate_limited));

        // API errors with non-retryable status codes
        let api_error_400 = AptosError::Api {
            status_code: 400,
            message: "Bad Request".to_string(),
            error_code: None,
            vm_error_code: None,
        };
        assert!(!config.is_retryable_error(&api_error_400));

        // Not found is not retryable
        let not_found = AptosError::NotFound("resource".to_string());
        assert!(!config.is_retryable_error(&not_found));
    }

    #[tokio::test]
    async fn test_retry_succeeds_on_first_try() {
        let executor = RetryExecutor::with_defaults();
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = executor
            .execute(|| {
                let counter = counter_clone.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, AptosError>(42)
                }
            })
            .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_succeeds_after_failures() {
        let config = RetryConfig::builder()
            .max_retries(3)
            .initial_delay_ms(1) // Very short for testing
            .jitter(false)
            .build();
        let executor = RetryExecutor::new(config);
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = executor
            .execute(|| {
                let counter = counter_clone.clone();
                async move {
                    let count = counter.fetch_add(1, Ordering::SeqCst);
                    if count < 2 {
                        Err(AptosError::Api {
                            status_code: 503,
                            message: "Service Unavailable".to_string(),
                            error_code: None,
                            vm_error_code: None,
                        })
                    } else {
                        Ok(42)
                    }
                }
            })
            .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 3); // 2 failures + 1 success
    }

    #[tokio::test]
    async fn test_retry_exhausted() {
        let config = RetryConfig::builder()
            .max_retries(2)
            .initial_delay_ms(1)
            .jitter(false)
            .build();
        let executor = RetryExecutor::new(config);
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = executor
            .execute(|| {
                let counter = counter_clone.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Err::<i32, _>(AptosError::Api {
                        status_code: 503,
                        message: "Always fails".to_string(),
                        error_code: None,
                        vm_error_code: None,
                    })
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 3); // 1 initial + 2 retries
    }

    #[tokio::test]
    async fn test_no_retry_on_non_retryable_error() {
        let config = RetryConfig::builder()
            .max_retries(3)
            .initial_delay_ms(1)
            .build();
        let executor = RetryExecutor::new(config);
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = executor
            .execute(|| {
                let counter = counter_clone.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Err::<i32, _>(AptosError::Api {
                        status_code: 400, // Bad Request - not retryable
                        message: "Bad Request".to_string(),
                        error_code: None,
                        vm_error_code: None,
                    })
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 1); // No retries
    }

    #[test]
    fn test_aggressive_config() {
        let config = RetryConfig::aggressive();
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_delay_ms, 50);
        assert_eq!(config.max_delay_ms, 5_000);
        assert!((config.exponential_base - 1.5).abs() < f64::EPSILON);
        assert!(config.jitter);
    }

    #[test]
    fn test_conservative_config() {
        let config = RetryConfig::conservative();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay_ms, 500);
        assert_eq!(config.max_delay_ms, 30_000);
        assert!((config.exponential_base - 2.0).abs() < f64::EPSILON);
        assert!(config.jitter);
    }

    #[test]
    fn test_builder_jitter_factor() {
        let config = RetryConfig::builder().jitter_factor(0.25).build();

        assert!((config.jitter_factor - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_builder_retryable_status_codes() {
        let config = RetryConfig::builder()
            .retryable_status_codes([500, 502])
            .build();

        assert!(config.is_retryable_status(500));
        assert!(config.is_retryable_status(502));
        assert!(!config.is_retryable_status(503)); // Not in our custom list
    }

    #[test]
    fn test_delay_with_jitter() {
        let config = RetryConfig::builder()
            .initial_delay_ms(100)
            .jitter(true)
            .jitter_factor(0.5)
            .build();

        // With jitter, delays should vary
        let delay1 = config.delay_for_attempt(1);
        // Delay should be in range [50ms, 150ms] (100ms +/- 50%)
        assert!(delay1 >= Duration::from_millis(50));
        assert!(delay1 <= Duration::from_millis(150));
    }

    #[test]
    fn test_delay_zero_for_first_attempt() {
        let config = RetryConfig::default();
        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(0));
    }

    #[test]
    fn test_retryable_error_transaction_error() {
        let config = RetryConfig::default();

        // Transaction errors are not retryable
        let txn_error = AptosError::Transaction("failed".to_string());
        assert!(!config.is_retryable_error(&txn_error));
    }

    #[test]
    fn test_retryable_error_invalid_address() {
        let config = RetryConfig::default();

        // Invalid address errors are not retryable
        let addr_error = AptosError::InvalidAddress("bad".to_string());
        assert!(!config.is_retryable_error(&addr_error));
    }

    #[tokio::test]
    async fn test_retry_with_no_retry_config() {
        let config = RetryConfig::no_retry();
        let executor = RetryExecutor::new(config);
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = executor
            .execute(|| {
                let counter = counter_clone.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Err::<i32, _>(AptosError::Api {
                        status_code: 503,
                        message: "Service Unavailable".to_string(),
                        error_code: None,
                        vm_error_code: None,
                    })
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 1); // No retries with no_retry config
    }

    #[test]
    fn test_retry_config_clone() {
        let config = RetryConfig::builder()
            .max_retries(5)
            .initial_delay_ms(200)
            .build();

        let cloned = config.clone();
        assert_eq!(config.max_retries, cloned.max_retries);
        assert_eq!(config.initial_delay_ms, cloned.initial_delay_ms);
    }

    #[test]
    fn test_retry_config_debug() {
        let config = RetryConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("RetryConfig"));
        assert!(debug.contains("max_retries"));
    }

    #[test]
    fn test_builder_add_retryable_status_code() {
        let config = RetryConfig::builder()
            .add_retryable_status_code(599)
            .build();

        assert!(config.is_retryable_status(599));
    }

    #[test]
    fn test_builder_add_duplicate_status_code() {
        let config = RetryConfig::builder()
            .add_retryable_status_code(500)
            .add_retryable_status_code(500) // Duplicate
            .build();

        // HashSet automatically handles duplicates - 500 should be present
        assert!(config.is_retryable_status(500));
        // With HashSet, count will always be 1 for a present element
        assert_eq!(config.retryable_status_codes.len(), 1);
    }

    #[test]
    fn test_builder_jitter_factor_clamped() {
        let config = RetryConfig::builder()
            .jitter_factor(2.0) // Should be clamped to 1.0
            .build();

        assert!((config.jitter_factor - 1.0).abs() < f64::EPSILON);

        let config2 = RetryConfig::builder()
            .jitter_factor(-1.0) // Should be clamped to 0.0
            .build();

        assert!(config2.jitter_factor.abs() < f64::EPSILON);
    }

    #[test]
    fn test_retry_executor_new() {
        let config = RetryConfig::default();
        let executor = RetryExecutor::new(config.clone());

        let debug = format!("{executor:?}");
        assert!(debug.contains("RetryExecutor"));
    }

    #[tokio::test]
    async fn test_retry_with_custom_predicate() {
        let config = RetryConfig::builder()
            .max_retries(3)
            .initial_delay_ms(1)
            .jitter(false)
            .build();
        let executor = RetryExecutor::new(config);
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        // Custom predicate that always says "retry"
        let result = executor
            .execute_with_predicate(
                || {
                    let counter = counter_clone.clone();
                    async move {
                        let count = counter.fetch_add(1, Ordering::SeqCst);
                        if count < 2 {
                            Err(AptosError::NotFound("test".to_string()))
                        } else {
                            Ok(42)
                        }
                    }
                },
                |_| true, // Always retry
            )
            .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_with_predicate_no_retry() {
        let config = RetryConfig::builder()
            .max_retries(3)
            .initial_delay_ms(1)
            .build();
        let executor = RetryExecutor::new(config);
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        // Custom predicate that never retries
        let result = executor
            .execute_with_predicate(
                || {
                    let counter = counter_clone.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Err::<i32, _>(AptosError::Api {
                            status_code: 503,
                            message: "Fail".to_string(),
                            error_code: None,
                            vm_error_code: None,
                        })
                    }
                },
                |_| false, // Never retry
            )
            .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 1); // No retries
    }

    #[tokio::test]
    async fn test_retry_convenience_function() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = retry(|| {
            let counter = counter_clone.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok::<_, AptosError>(42)
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_with_config_convenience_function() {
        let config = RetryConfig::builder()
            .max_retries(1)
            .initial_delay_ms(1)
            .jitter(false)
            .build();
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = retry_with_config(&config, || {
            let counter = counter_clone.clone();
            async move {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                if count < 1 {
                    // Use a retryable API error instead of Http
                    Err(AptosError::Api {
                        status_code: 503,
                        message: "Service Unavailable".to_string(),
                        error_code: None,
                        vm_error_code: None,
                    })
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_retryable_rate_limited_error() {
        let config = RetryConfig::default();

        // Test RateLimited which is always retryable
        let rate_limited = AptosError::RateLimited {
            retry_after_secs: Some(5),
        };
        assert!(config.is_retryable_error(&rate_limited));
    }

    #[test]
    fn test_builder_default_debug() {
        let builder = RetryConfigBuilder::default();
        let debug = format!("{builder:?}");
        assert!(debug.contains("RetryConfigBuilder"));
    }
}
