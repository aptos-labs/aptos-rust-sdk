//! Transaction batching for efficient multi-transaction submission.
//!
//! This module provides utilities for building, signing, and submitting
//! multiple transactions efficiently with automatic sequence number management.
//!
//! # Overview
//!
//! Transaction batching is useful when you need to:
//! - Submit multiple transfers at once
//! - Execute a series of contract calls
//! - Perform bulk operations efficiently
//!
//! # Example
//!
//! ```rust,ignore
//! use aptos_rust_sdk_v2::transaction::batch::TransactionBatch;
//!
//! let batch = TransactionBatch::new(&aptos, &sender)
//!     .add(payload1)
//!     .add(payload2)
//!     .add(payload3)
//!     .build()
//!     .await?;
//!
//! // Submit all transactions in parallel
//! let results = batch.submit_all().await;
//!
//! // Or submit and wait for all to complete
//! let results = batch.submit_and_wait_all().await;
//! ```

use crate::account::Account;
use crate::api::FullnodeClient;
use crate::config::AptosConfig;
use crate::error::{AptosError, AptosResult};
use crate::transaction::{
    RawTransaction, SignedTransaction, TransactionBuilder, TransactionPayload,
    builder::sign_transaction,
};
use crate::types::{AccountAddress, ChainId};
use futures::future::join_all;
use std::time::Duration;

/// Result of a single transaction in a batch.
#[derive(Debug)]
pub struct BatchTransactionResult {
    /// Index of the transaction in the batch.
    pub index: usize,
    /// The signed transaction that was submitted.
    pub transaction: SignedTransaction,
    /// Result of the submission/execution.
    pub result: Result<BatchTransactionStatus, AptosError>,
}

/// Status of a batch transaction after submission.
#[derive(Debug, Clone)]
pub enum BatchTransactionStatus {
    /// Transaction was submitted and is pending.
    Pending {
        /// The transaction hash.
        hash: String,
    },
    /// Transaction was submitted and confirmed.
    Confirmed {
        /// The transaction hash.
        hash: String,
        /// Whether the transaction succeeded on-chain.
        success: bool,
        /// The transaction version.
        version: u64,
        /// Gas used by the transaction.
        gas_used: u64,
    },
    /// Transaction failed to submit.
    Failed {
        /// Error message.
        error: String,
    },
}

impl BatchTransactionStatus {
    /// Returns the transaction hash if available.
    pub fn hash(&self) -> Option<&str> {
        match self {
            BatchTransactionStatus::Pending { hash }
            | BatchTransactionStatus::Confirmed { hash, .. } => Some(hash),
            BatchTransactionStatus::Failed { .. } => None,
        }
    }

    /// Returns true if the transaction is confirmed and successful.
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            BatchTransactionStatus::Confirmed { success: true, .. }
        )
    }

    /// Returns true if the transaction failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, BatchTransactionStatus::Failed { .. })
            || matches!(
                self,
                BatchTransactionStatus::Confirmed { success: false, .. }
            )
    }
}

/// Builder for creating a batch of transactions.
///
/// This builder handles:
/// - Automatic sequence number management
/// - Gas estimation
/// - Transaction signing
///
/// # Example
///
/// ```rust,ignore
/// let batch = TransactionBatchBuilder::new()
///     .sender(account.address())
///     .starting_sequence_number(10)
///     .chain_id(ChainId::testnet())
///     .gas_unit_price(100)
///     .add_payload(payload1)
///     .add_payload(payload2)
///     .build_and_sign(&account)?;
/// ```
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

impl Default for TransactionBatchBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionBatchBuilder {
    /// Creates a new batch builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sender: None,
            starting_sequence_number: None,
            chain_id: None,
            gas_unit_price: 100,
            max_gas_amount: 200_000,
            expiration_secs: 600,
            payloads: Vec::new(),
        }
    }

    /// Sets the sender address.
    #[must_use]
    pub fn sender(mut self, sender: AccountAddress) -> Self {
        self.sender = Some(sender);
        self
    }

    /// Sets the starting sequence number.
    ///
    /// Each transaction in the batch will use an incrementing sequence number
    /// starting from this value.
    #[must_use]
    pub fn starting_sequence_number(mut self, seq: u64) -> Self {
        self.starting_sequence_number = Some(seq);
        self
    }

    /// Sets the chain ID.
    #[must_use]
    pub fn chain_id(mut self, chain_id: ChainId) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Sets the gas unit price for all transactions.
    #[must_use]
    pub fn gas_unit_price(mut self, price: u64) -> Self {
        self.gas_unit_price = price;
        self
    }

    /// Sets the maximum gas amount for all transactions.
    #[must_use]
    pub fn max_gas_amount(mut self, amount: u64) -> Self {
        self.max_gas_amount = amount;
        self
    }

    /// Sets the expiration time in seconds from now.
    #[must_use]
    pub fn expiration_secs(mut self, secs: u64) -> Self {
        self.expiration_secs = secs;
        self
    }

    /// Adds a transaction payload to the batch.
    #[must_use]
    pub fn add_payload(mut self, payload: TransactionPayload) -> Self {
        self.payloads.push(payload);
        self
    }

    /// Adds multiple transaction payloads to the batch.
    #[must_use]
    pub fn add_payloads(mut self, payloads: impl IntoIterator<Item = TransactionPayload>) -> Self {
        self.payloads.extend(payloads);
        self
    }

    /// Returns the number of transactions in the batch.
    pub fn len(&self) -> usize {
        self.payloads.len()
    }

    /// Returns true if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.payloads.is_empty()
    }

    /// Builds raw transactions without signing.
    ///
    /// # Errors
    ///
    /// Returns an error if `sender`, `starting_sequence_number`, or `chain_id` is not set, or if building any transaction fails.
    pub fn build(self) -> AptosResult<Vec<RawTransaction>> {
        let sender = self
            .sender
            .ok_or_else(|| AptosError::Transaction("sender is required".into()))?;
        let starting_seq = self.starting_sequence_number.ok_or_else(|| {
            AptosError::Transaction("starting_sequence_number is required".into())
        })?;
        let chain_id = self
            .chain_id
            .ok_or_else(|| AptosError::Transaction("chain_id is required".into()))?;

        let mut transactions = Vec::with_capacity(self.payloads.len());

        for (i, payload) in self.payloads.into_iter().enumerate() {
            let txn = TransactionBuilder::new()
                .sender(sender)
                .sequence_number(starting_seq + i as u64)
                .payload(payload)
                .gas_unit_price(self.gas_unit_price)
                .max_gas_amount(self.max_gas_amount)
                .chain_id(chain_id)
                .expiration_from_now(self.expiration_secs)
                .build()?;
            transactions.push(txn);
        }

        Ok(transactions)
    }

    /// Builds and signs all transactions in the batch.
    ///
    /// # Errors
    ///
    /// Returns an error if building the transactions fails or if signing any transaction fails.
    pub fn build_and_sign<A: Account>(self, account: &A) -> AptosResult<SignedTransactionBatch> {
        let raw_transactions = self.build()?;
        let mut signed = Vec::with_capacity(raw_transactions.len());

        for raw_txn in raw_transactions {
            let signed_txn = sign_transaction(&raw_txn, account)?;
            signed.push(signed_txn);
        }

        Ok(SignedTransactionBatch {
            transactions: signed,
        })
    }
}

/// A batch of signed transactions ready for submission.
#[derive(Debug, Clone)]
pub struct SignedTransactionBatch {
    transactions: Vec<SignedTransaction>,
}

impl SignedTransactionBatch {
    /// Creates a new batch from signed transactions.
    pub fn new(transactions: Vec<SignedTransaction>) -> Self {
        Self { transactions }
    }

    /// Returns the transactions in the batch.
    pub fn transactions(&self) -> &[SignedTransaction] {
        &self.transactions
    }

    /// Consumes the batch and returns the transactions.
    pub fn into_transactions(self) -> Vec<SignedTransaction> {
        self.transactions
    }

    /// Returns the number of transactions in the batch.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Returns true if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Submits all transactions in parallel.
    ///
    /// Returns immediately after submission without waiting for confirmation.
    pub async fn submit_all(self, client: &FullnodeClient) -> Vec<BatchTransactionResult> {
        let futures: Vec<_> = self
            .transactions
            .into_iter()
            .enumerate()
            .map(|(index, txn)| {
                let client = client.clone();
                async move {
                    let result = client.submit_transaction(&txn).await;
                    BatchTransactionResult {
                        index,
                        transaction: txn,
                        result: result.map(|resp| BatchTransactionStatus::Pending {
                            hash: resp.data.hash.to_string(),
                        }),
                    }
                }
            })
            .collect();

        join_all(futures).await
    }

    /// Submits all transactions in parallel and waits for confirmation.
    ///
    /// Each transaction is submitted and then waited on independently.
    pub async fn submit_and_wait_all(
        self,
        client: &FullnodeClient,
        timeout: Option<Duration>,
    ) -> Vec<BatchTransactionResult> {
        let futures: Vec<_> = self
            .transactions
            .into_iter()
            .enumerate()
            .map(|(index, txn)| {
                let client = client.clone();
                async move {
                    let result = submit_and_wait_single(&client, &txn, timeout).await;
                    BatchTransactionResult {
                        index,
                        transaction: txn,
                        result,
                    }
                }
            })
            .collect();

        join_all(futures).await
    }

    /// Submits transactions sequentially (one at a time).
    ///
    /// This is slower but may be needed if transactions depend on each other.
    pub async fn submit_sequential(self, client: &FullnodeClient) -> Vec<BatchTransactionResult> {
        let mut results = Vec::with_capacity(self.transactions.len());

        for (index, txn) in self.transactions.into_iter().enumerate() {
            let result = client.submit_transaction(&txn).await;
            results.push(BatchTransactionResult {
                index,
                transaction: txn,
                result: result.map(|resp| BatchTransactionStatus::Pending {
                    hash: resp.data.hash.to_string(),
                }),
            });
        }

        results
    }

    /// Submits transactions sequentially and waits for each to complete.
    ///
    /// This ensures each transaction is confirmed before submitting the next.
    pub async fn submit_and_wait_sequential(
        self,
        client: &FullnodeClient,
        timeout: Option<Duration>,
    ) -> Vec<BatchTransactionResult> {
        let mut results = Vec::with_capacity(self.transactions.len());

        for (index, txn) in self.transactions.into_iter().enumerate() {
            let result = submit_and_wait_single(client, &txn, timeout).await;
            results.push(BatchTransactionResult {
                index,
                transaction: txn.clone(),
                result,
            });

            // Stop on first failure if sequential
            if results.last().is_some_and(|r| r.result.is_err()) {
                break;
            }
        }

        results
    }
}

/// Helper to submit and wait for a single transaction.
async fn submit_and_wait_single(
    client: &FullnodeClient,
    txn: &SignedTransaction,
    timeout: Option<Duration>,
) -> Result<BatchTransactionStatus, AptosError> {
    let response = client.submit_and_wait(txn, timeout).await?;
    let data = response.into_inner();

    let hash = data
        .get("hash")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let success = data
        .get("success")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let version = data
        .get("version")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let gas_used = data
        .get("gas_used")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    Ok(BatchTransactionStatus::Confirmed {
        hash,
        success,
        version,
        gas_used,
    })
}

/// Summary of batch execution results.
#[derive(Debug, Clone)]
pub struct BatchSummary {
    /// Total number of transactions.
    pub total: usize,
    /// Number of successful transactions.
    pub succeeded: usize,
    /// Number of failed transactions.
    pub failed: usize,
    /// Number of pending transactions.
    pub pending: usize,
    /// Total gas used across all confirmed transactions.
    pub total_gas_used: u64,
}

impl BatchSummary {
    /// Creates a summary from batch results.
    pub fn from_results(results: &[BatchTransactionResult]) -> Self {
        let mut succeeded = 0;
        let mut failed = 0;
        let mut pending = 0;
        let mut total_gas_used = 0u64;

        for result in results {
            match &result.result {
                Ok(status) => match status {
                    BatchTransactionStatus::Confirmed {
                        success, gas_used, ..
                    } => {
                        if *success {
                            succeeded += 1;
                        } else {
                            failed += 1;
                        }
                        total_gas_used = total_gas_used.saturating_add(*gas_used);
                    }
                    BatchTransactionStatus::Pending { .. } => {
                        pending += 1;
                    }
                    BatchTransactionStatus::Failed { .. } => {
                        failed += 1;
                    }
                },
                Err(_) => {
                    failed += 1;
                }
            }
        }

        Self {
            total: results.len(),
            succeeded,
            failed,
            pending,
            total_gas_used,
        }
    }

    /// Returns true if all transactions succeeded.
    pub fn all_succeeded(&self) -> bool {
        self.succeeded == self.total
    }

    /// Returns true if any transaction failed.
    pub fn has_failures(&self) -> bool {
        self.failed > 0
    }
}

/// High-level batch operations for the Aptos client.
#[allow(missing_debug_implementations)] // Contains references that may not implement Debug
pub struct BatchOperations<'a> {
    client: &'a FullnodeClient,
    config: &'a AptosConfig,
}

impl<'a> BatchOperations<'a> {
    /// Creates a new batch operations helper.
    pub fn new(client: &'a FullnodeClient, config: &'a AptosConfig) -> Self {
        Self { client, config }
    }

    /// Builds a batch of transactions for an account.
    ///
    /// This automatically fetches the current sequence number and gas price.
    ///
    /// # Errors
    ///
    /// Returns an error if fetching the sequence number fails, fetching gas price fails, or building/signing the batch fails.
    pub async fn build<A: Account>(
        &self,
        account: &A,
        payloads: Vec<TransactionPayload>,
    ) -> AptosResult<SignedTransactionBatch> {
        let sequence_number = self.client.get_sequence_number(account.address()).await?;
        let gas_estimation = self.client.estimate_gas_price().await?;

        let batch = TransactionBatchBuilder::new()
            .sender(account.address())
            .starting_sequence_number(sequence_number)
            .chain_id(self.config.chain_id())
            .gas_unit_price(gas_estimation.data.recommended())
            .add_payloads(payloads)
            .build_and_sign(account)?;

        Ok(batch)
    }

    /// Builds and submits a batch of transactions in parallel.
    ///
    /// # Errors
    ///
    /// Returns an error if building the batch fails.
    pub async fn submit<A: Account>(
        &self,
        account: &A,
        payloads: Vec<TransactionPayload>,
    ) -> AptosResult<Vec<BatchTransactionResult>> {
        let batch = self.build(account, payloads).await?;
        Ok(batch.submit_all(self.client).await)
    }

    /// Builds, submits, and waits for a batch of transactions.
    ///
    /// # Errors
    ///
    /// Returns an error if building the batch fails (e.g., fetching sequence number or gas price),
    /// signing the batch fails, or any transaction submission/waiting fails.
    pub async fn submit_and_wait<A: Account>(
        &self,
        account: &A,
        payloads: Vec<TransactionPayload>,
        timeout: Option<Duration>,
    ) -> AptosResult<Vec<BatchTransactionResult>> {
        let batch = self.build(account, payloads).await?;
        Ok(batch.submit_and_wait_all(self.client, timeout).await)
    }

    /// Creates multiple APT transfers as a batch.
    ///
    /// # Errors
    ///
    /// Returns an error if any transfer payload creation fails (e.g., invalid recipient address),
    /// building the batch fails, or submitting/waiting for transactions fails.
    pub async fn transfer_apt<A: Account>(
        &self,
        sender: &A,
        transfers: Vec<(AccountAddress, u64)>,
    ) -> AptosResult<Vec<BatchTransactionResult>> {
        use crate::transaction::EntryFunction;

        let payloads: Vec<_> = transfers
            .into_iter()
            .map(|(recipient, amount)| {
                EntryFunction::apt_transfer(recipient, amount).map(TransactionPayload::from)
            })
            .collect::<AptosResult<Vec<_>>>()?;

        self.submit_and_wait(sender, payloads, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_builder_missing_fields() {
        let builder = TransactionBatchBuilder::new().add_payload(TransactionPayload::Script(
            crate::transaction::Script {
                code: vec![],
                type_args: vec![],
                args: vec![],
            },
        ));

        let result = builder.build();
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_builder_complete() {
        let builder = TransactionBatchBuilder::new()
            .sender(AccountAddress::ONE)
            .starting_sequence_number(0)
            .chain_id(ChainId::testnet())
            .gas_unit_price(100)
            .add_payload(TransactionPayload::Script(crate::transaction::Script {
                code: vec![],
                type_args: vec![],
                args: vec![],
            }))
            .add_payload(TransactionPayload::Script(crate::transaction::Script {
                code: vec![],
                type_args: vec![],
                args: vec![],
            }));

        let transactions = builder.build().unwrap();
        assert_eq!(transactions.len(), 2);
        assert_eq!(transactions[0].sequence_number, 0);
        assert_eq!(transactions[1].sequence_number, 1);
    }

    #[test]
    fn test_batch_builder_sequence_numbers() {
        let builder = TransactionBatchBuilder::new()
            .sender(AccountAddress::ONE)
            .starting_sequence_number(10)
            .chain_id(ChainId::testnet())
            .add_payload(TransactionPayload::Script(crate::transaction::Script {
                code: vec![],
                type_args: vec![],
                args: vec![],
            }))
            .add_payload(TransactionPayload::Script(crate::transaction::Script {
                code: vec![],
                type_args: vec![],
                args: vec![],
            }))
            .add_payload(TransactionPayload::Script(crate::transaction::Script {
                code: vec![],
                type_args: vec![],
                args: vec![],
            }));

        let transactions = builder.build().unwrap();
        assert_eq!(transactions.len(), 3);
        assert_eq!(transactions[0].sequence_number, 10);
        assert_eq!(transactions[1].sequence_number, 11);
        assert_eq!(transactions[2].sequence_number, 12);
    }

    #[test]
    fn test_batch_summary() {
        let results = vec![
            BatchTransactionResult {
                index: 0,
                transaction: create_dummy_signed_txn(),
                result: Ok(BatchTransactionStatus::Confirmed {
                    hash: "0x1".to_string(),
                    success: true,
                    version: 100,
                    gas_used: 500,
                }),
            },
            BatchTransactionResult {
                index: 1,
                transaction: create_dummy_signed_txn(),
                result: Ok(BatchTransactionStatus::Confirmed {
                    hash: "0x2".to_string(),
                    success: true,
                    version: 101,
                    gas_used: 600,
                }),
            },
            BatchTransactionResult {
                index: 2,
                transaction: create_dummy_signed_txn(),
                result: Ok(BatchTransactionStatus::Confirmed {
                    hash: "0x3".to_string(),
                    success: false,
                    version: 102,
                    gas_used: 100,
                }),
            },
        ];

        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.succeeded, 2);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.pending, 0);
        assert_eq!(summary.total_gas_used, 1200);
        assert!(!summary.all_succeeded());
        assert!(summary.has_failures());
    }

    #[test]
    fn test_batch_status_methods() {
        let pending = BatchTransactionStatus::Pending {
            hash: "0x123".to_string(),
        };
        assert_eq!(pending.hash(), Some("0x123"));
        assert!(!pending.is_success());
        assert!(!pending.is_failed());

        let confirmed_success = BatchTransactionStatus::Confirmed {
            hash: "0x456".to_string(),
            success: true,
            version: 100,
            gas_used: 500,
        };
        assert_eq!(confirmed_success.hash(), Some("0x456"));
        assert!(confirmed_success.is_success());
        assert!(!confirmed_success.is_failed());

        let confirmed_failed = BatchTransactionStatus::Confirmed {
            hash: "0x789".to_string(),
            success: false,
            version: 101,
            gas_used: 100,
        };
        assert!(!confirmed_failed.is_success());
        assert!(confirmed_failed.is_failed());

        let failed = BatchTransactionStatus::Failed {
            error: "timeout".to_string(),
        };
        assert!(failed.hash().is_none());
        assert!(!failed.is_success());
        assert!(failed.is_failed());
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_batch_build_and_sign() {
        use crate::account::Ed25519Account;

        let account = Ed25519Account::generate();
        let batch = TransactionBatchBuilder::new()
            .sender(account.address())
            .starting_sequence_number(0)
            .chain_id(ChainId::testnet())
            .add_payload(TransactionPayload::Script(crate::transaction::Script {
                code: vec![],
                type_args: vec![],
                args: vec![],
            }))
            .add_payload(TransactionPayload::Script(crate::transaction::Script {
                code: vec![],
                type_args: vec![],
                args: vec![],
            }))
            .build_and_sign(&account)
            .unwrap();

        assert_eq!(batch.len(), 2);
    }

    fn create_dummy_signed_txn() -> SignedTransaction {
        use crate::transaction::TransactionAuthenticator;

        let raw_txn = RawTransaction {
            sender: AccountAddress::ONE,
            sequence_number: 0,
            payload: TransactionPayload::Script(crate::transaction::Script {
                code: vec![],
                type_args: vec![],
                args: vec![],
            }),
            max_gas_amount: 200_000,
            gas_unit_price: 100,
            expiration_timestamp_secs: 0,
            chain_id: ChainId::testnet(),
        };

        SignedTransaction {
            raw_txn,
            authenticator: TransactionAuthenticator::ed25519(vec![0u8; 32], vec![0u8; 64]),
        }
    }

    #[test]
    fn test_batch_summary_all_succeeded() {
        let results = vec![
            BatchTransactionResult {
                index: 0,
                transaction: create_dummy_signed_txn(),
                result: Ok(BatchTransactionStatus::Confirmed {
                    hash: "0x1".to_string(),
                    success: true,
                    version: 100,
                    gas_used: 500,
                }),
            },
            BatchTransactionResult {
                index: 1,
                transaction: create_dummy_signed_txn(),
                result: Ok(BatchTransactionStatus::Confirmed {
                    hash: "0x2".to_string(),
                    success: true,
                    version: 101,
                    gas_used: 600,
                }),
            },
        ];

        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.succeeded, 2);
        assert_eq!(summary.failed, 0);
        assert!(summary.all_succeeded());
        assert!(!summary.has_failures());
    }

    #[test]
    fn test_batch_summary_with_pending() {
        let results = vec![
            BatchTransactionResult {
                index: 0,
                transaction: create_dummy_signed_txn(),
                result: Ok(BatchTransactionStatus::Pending {
                    hash: "0x1".to_string(),
                }),
            },
            BatchTransactionResult {
                index: 1,
                transaction: create_dummy_signed_txn(),
                result: Ok(BatchTransactionStatus::Confirmed {
                    hash: "0x2".to_string(),
                    success: true,
                    version: 101,
                    gas_used: 600,
                }),
            },
        ];

        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.pending, 1);
        assert!(!summary.all_succeeded());
    }

    #[test]
    fn test_batch_summary_with_errors() {
        let results = vec![BatchTransactionResult {
            index: 0,
            transaction: create_dummy_signed_txn(),
            result: Err(AptosError::Transaction("failed".to_string())),
        }];

        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 1);
        assert_eq!(summary.failed, 1);
        assert!(summary.has_failures());
    }

    #[test]
    fn test_batch_builder_with_max_gas() {
        let builder = TransactionBatchBuilder::new()
            .sender(AccountAddress::ONE)
            .starting_sequence_number(0)
            .chain_id(ChainId::testnet())
            .max_gas_amount(500_000)
            .add_payload(TransactionPayload::Script(crate::transaction::Script {
                code: vec![],
                type_args: vec![],
                args: vec![],
            }));

        let transactions = builder.build().unwrap();
        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].max_gas_amount, 500_000);
    }

    #[test]
    fn test_batch_builder_with_expiration() {
        let builder = TransactionBatchBuilder::new()
            .sender(AccountAddress::ONE)
            .starting_sequence_number(0)
            .chain_id(ChainId::testnet())
            .expiration_secs(3600) // 1 hour from now
            .add_payload(TransactionPayload::Script(crate::transaction::Script {
                code: vec![],
                type_args: vec![],
                args: vec![],
            }));

        let transactions = builder.build().unwrap();
        // Expiration should be set to some future timestamp (> current time)
        assert!(transactions[0].expiration_timestamp_secs > 0);
    }

    #[test]
    fn test_batch_builder_empty_payloads() {
        let builder = TransactionBatchBuilder::new()
            .sender(AccountAddress::ONE)
            .starting_sequence_number(0)
            .chain_id(ChainId::testnet());

        // Empty payloads returns empty vec, not error
        let result = builder.build();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_batch_result_transaction_accessor() {
        let signed_txn = create_dummy_signed_txn();
        let result = BatchTransactionResult {
            index: 0,
            transaction: signed_txn.clone(),
            result: Ok(BatchTransactionStatus::Pending {
                hash: "0x123".to_string(),
            }),
        };

        assert_eq!(result.index, 0);
        assert_eq!(result.transaction.raw_txn.sender, AccountAddress::ONE);
    }

    #[test]
    fn test_batch_builder_default() {
        let builder = TransactionBatchBuilder::default();
        assert!(builder.is_empty());
        assert_eq!(builder.len(), 0);
    }

    #[test]
    fn test_batch_builder_len_and_is_empty() {
        let builder = TransactionBatchBuilder::new();
        assert!(builder.is_empty());
        assert_eq!(builder.len(), 0);

        let builder = builder.add_payload(TransactionPayload::Script(crate::transaction::Script {
            code: vec![],
            type_args: vec![],
            args: vec![],
        }));
        assert!(!builder.is_empty());
        assert_eq!(builder.len(), 1);
    }

    #[test]
    fn test_batch_builder_add_payloads() {
        let payloads = vec![
            TransactionPayload::Script(crate::transaction::Script {
                code: vec![1],
                type_args: vec![],
                args: vec![],
            }),
            TransactionPayload::Script(crate::transaction::Script {
                code: vec![2],
                type_args: vec![],
                args: vec![],
            }),
            TransactionPayload::Script(crate::transaction::Script {
                code: vec![3],
                type_args: vec![],
                args: vec![],
            }),
        ];

        let builder = TransactionBatchBuilder::new()
            .sender(AccountAddress::ONE)
            .starting_sequence_number(0)
            .chain_id(ChainId::testnet())
            .add_payloads(payloads);

        assert_eq!(builder.len(), 3);

        let transactions = builder.build().unwrap();
        assert_eq!(transactions.len(), 3);
    }

    #[test]
    fn test_batch_builder_missing_sequence_number() {
        let builder = TransactionBatchBuilder::new()
            .sender(AccountAddress::ONE)
            .chain_id(ChainId::testnet())
            .add_payload(TransactionPayload::Script(crate::transaction::Script {
                code: vec![],
                type_args: vec![],
                args: vec![],
            }));

        let result = builder.build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("sequence_number"));
    }

    #[test]
    fn test_batch_builder_missing_chain_id() {
        let builder = TransactionBatchBuilder::new()
            .sender(AccountAddress::ONE)
            .starting_sequence_number(0)
            .add_payload(TransactionPayload::Script(crate::transaction::Script {
                code: vec![],
                type_args: vec![],
                args: vec![],
            }));

        let result = builder.build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("chain_id"));
    }

    #[test]
    fn test_batch_summary_empty() {
        let results: Vec<BatchTransactionResult> = vec![];
        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 0);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.pending, 0);
        assert_eq!(summary.total_gas_used, 0);
        assert!(summary.all_succeeded());
        assert!(!summary.has_failures());
    }

    #[test]
    fn test_batch_status_failed_variant() {
        let failed = BatchTransactionStatus::Failed {
            error: "connection timeout".to_string(),
        };
        assert!(failed.is_failed());
        assert!(!failed.is_success());
        assert!(failed.hash().is_none());
    }

    #[test]
    fn test_signed_transaction_batch_len() {
        let batch = SignedTransactionBatch {
            transactions: vec![create_dummy_signed_txn(), create_dummy_signed_txn()],
        };
        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_signed_transaction_batch_iter() {
        let txn1 = create_dummy_signed_txn();
        let txn2 = create_dummy_signed_txn();
        let batch = SignedTransactionBatch {
            transactions: vec![txn1, txn2],
        };

        let collected: Vec<_> = batch.transactions.iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn test_batch_builder_gas_settings() {
        let builder = TransactionBatchBuilder::new()
            .max_gas_amount(50000)
            .gas_unit_price(200)
            .expiration_secs(120);

        assert_eq!(builder.max_gas_amount, 50000);
        assert_eq!(builder.gas_unit_price, 200);
        assert_eq!(builder.expiration_secs, 120);
    }

    #[test]
    fn test_batch_builder_missing_sender() {
        let builder = TransactionBatchBuilder::new()
            .starting_sequence_number(0)
            .chain_id(ChainId::testnet())
            .add_payload(TransactionPayload::Script(crate::transaction::Script {
                code: vec![],
                type_args: vec![],
                args: vec![],
            }));

        let result = builder.build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("sender"));
    }

    #[test]
    fn test_batch_summary_with_failures() {
        let txn = create_dummy_signed_txn();
        let results = vec![
            BatchTransactionResult {
                index: 0,
                transaction: txn.clone(),
                result: Ok(BatchTransactionStatus::Failed {
                    error: "error".to_string(),
                }),
            },
            BatchTransactionResult {
                index: 1,
                transaction: txn,
                result: Err(AptosError::Transaction("test".to_string())),
            },
        ];

        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.failed, 2);
        assert!(summary.has_failures());
    }

    #[test]
    fn test_batch_status_confirmed_variant() {
        let status = BatchTransactionStatus::Confirmed {
            hash: "0xabc".to_string(),
            success: true,
            version: 1,
            gas_used: 150,
        };
        assert!(status.is_success());
        assert!(!status.is_failed());
        assert_eq!(status.hash(), Some("0xabc"));
    }

    #[test]
    fn test_batch_status_pending_variant() {
        let status = BatchTransactionStatus::Pending {
            hash: "0xdef".to_string(),
        };
        assert!(!status.is_success());
        assert!(!status.is_failed());
        assert_eq!(status.hash(), Some("0xdef"));
    }

    #[test]
    fn test_signed_transaction_batch_new() {
        let txn1 = create_dummy_signed_txn();
        let txn2 = create_dummy_signed_txn();
        let batch = SignedTransactionBatch::new(vec![txn1, txn2]);
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn test_signed_transaction_batch_transactions() {
        let txn1 = create_dummy_signed_txn();
        let txn2 = create_dummy_signed_txn();
        let batch = SignedTransactionBatch::new(vec![txn1, txn2]);

        let txns = batch.transactions();
        assert_eq!(txns.len(), 2);
    }

    #[test]
    fn test_signed_transaction_batch_into_transactions() {
        let txn1 = create_dummy_signed_txn();
        let txn2 = create_dummy_signed_txn();
        let batch = SignedTransactionBatch::new(vec![txn1, txn2]);

        let txns = batch.into_transactions();
        assert_eq!(txns.len(), 2);
    }

    #[test]
    fn test_signed_transaction_batch_empty() {
        let batch = SignedTransactionBatch::new(vec![]);
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
    }

    #[test]
    fn test_batch_transaction_result_accessors() {
        let txn = create_dummy_signed_txn();
        let result = BatchTransactionResult {
            index: 5,
            transaction: txn.clone(),
            result: Ok(BatchTransactionStatus::Confirmed {
                hash: "0x123".to_string(),
                success: true,
                version: 1,
                gas_used: 100,
            }),
        };

        assert_eq!(result.index, 5);
        assert!(result.result.is_ok());
    }

    #[test]
    fn test_batch_builder_debug() {
        let builder = TransactionBatchBuilder::new().sender(AccountAddress::ONE);
        let debug = format!("{:?}", builder);
        assert!(debug.contains("TransactionBatchBuilder"));
    }

    #[test]
    fn test_signed_transaction_batch_debug() {
        let batch = SignedTransactionBatch::new(vec![create_dummy_signed_txn()]);
        let debug = format!("{:?}", batch);
        assert!(debug.contains("SignedTransactionBatch"));
    }

    #[test]
    fn test_batch_summary_debug() {
        let summary = BatchSummary {
            total: 5,
            succeeded: 3,
            failed: 1,
            pending: 1,
            total_gas_used: 500,
        };
        let debug = format!("{:?}", summary);
        assert!(debug.contains("BatchSummary"));
    }

    #[test]
    fn test_batch_transaction_status_debug() {
        let status = BatchTransactionStatus::Confirmed {
            hash: "0x123".to_string(),
            success: true,
            version: 1,
            gas_used: 100,
        };
        let debug = format!("{:?}", status);
        assert!(debug.contains("Confirmed"));
    }
}
