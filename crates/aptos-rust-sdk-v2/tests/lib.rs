//! Integration tests for the Aptos SDK.
//!
//! ## Test Categories
//!
//! - **behavioral**: Behavioral/specification tests that don't require network access
//! - **e2e**: End-to-end tests that require a running localnet
//!
//! ## Running Tests
//!
//! ```bash
//! # Unit + behavioral tests (default)
//! cargo test -p aptos-rust-sdk-v2 --features "full"
//!
//! # Include E2E tests (requires localnet)
//! cargo test -p aptos-rust-sdk-v2 --features "full,e2e" -- --ignored
//! ```

mod behavioral;

// E2E tests are only compiled when the `e2e` feature is enabled
// They also require the `faucet` feature which is included in `e2e`
#[cfg(feature = "e2e")]
mod e2e;
