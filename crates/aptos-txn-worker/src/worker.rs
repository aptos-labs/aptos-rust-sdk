//! A worker for managing transaction submission and monitoring.
//!
//! This worker provides a framework for submitting and monitoring transactions. It
//! handles sequence number management, transaction building, submission, and
//! monitoring.
//!
//! This worker assumes that it is the only thing using the account. If you submit
//! txns from the account the transaction worker is using elsewhere, it will cause
//! issues with the sequence numbers and we will not attempt to recover.
//!
//! # Examples
//!
//! ```no_run
//! use anyhow::{Context, Result};
//! use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
//! use aptos_txn_worker::worker::TransactionWorkerBuilder;
//! use aptos_rust_sdk::client::builder::AptosClientBuilder;
//! use aptos_rust_sdk::client::config::AptosNetwork;
//! use aptos_rust_sdk::client::faucet::AptosFaucetClient;
//! use aptos_rust_sdk_types::api_types::address::AccountAddress;
//! use aptos_rust_sdk_types::api_types::module_id::ModuleId;
//! use aptos_rust_sdk_types::api_types::transaction::EntryFunction;
//! use std::time::Duration;
//! use tokio::sync::mpsc;
//!
//! async fn example() -> Result<()> {
//!     // Create a private key.
//!     let mut seed = [0u8; 32];
//!     let seed_bytes =
//!         hex::decode("4aeeeb3f286caa91984d4a16d424786c7aa26947050b00e84ab7033f2aab0c2d")
//!             .unwrap();
//!     seed[..seed_bytes.len()].copy_from_slice(&seed_bytes);
//!     let private_key = Ed25519PrivateKey::try_from(seed_bytes.as_slice()).unwrap();
//!
//!     // Get the account address so we can faucet.
//!     let public_key = Ed25519PublicKey::from(&private_key);
//!     let auth_key =
//!         aptos_rust_sdk_types::api_types::transaction_authenticator::AuthenticationKey::ed25519(
//!             &public_key,
//!         );
//!     let sender = auth_key.account_address();
//!     println!("Sender: {}", sender);
//!
//!     // Create the account.
//!     let faucet_client = AptosFaucetClient::new(AptosNetwork::devnet(), None);
//!     let txn_hash = faucet_client
//!         .mint(&sender.to_string(), 100_000_000)
//!         .await
//!         .expect("Failed to mint funds");
//!     println!("Faucet txn hash: {}", txn_hash);
//!
//!     // Wait for the transaction to complete.
//!     // TODO: There is no function for this in the client right now.
//!     tokio::time::sleep(Duration::from_millis(500)).await;
//!
//!     // Create a client.
//!     let client = AptosClientBuilder::new(AptosNetwork::devnet())
//!         .api_key("aptoslabs_dsfdsfdsf")?
//!         .build();
//!
//!     // Create a channel for events.
//!     let (event_sender, mut event_receiver) = mpsc::channel(100);
//!
//!     // Create worker using the builder
//!     let worker = TransactionWorkerBuilder::new(private_key, client.clone())
//!         .with_max_pending_responses(50)
//!         .with_poll_interval_ms(500)
//!         .with_event_sender(event_sender)
//!         .build()
//!         .await?;
//!
//!     // Spawn a task to log events.
//!     // let client_clone = client.clone();
//!     tokio::spawn(async move {
//!         while let Some(event) = event_receiver.recv().await {
//!             println!("Received event: {:?}", event);
//!         }
//!         println!("Event sender disconnected");
//!     });
//!
//!     // Start the worker
//!     let handle = worker.start().context("Failed to start worker")?;
//!
//!     // Demonstrate pushing a transaction (will fail since we don't have a real node)
//!     let payload = EntryFunction::new(
//!         ModuleId::new(AccountAddress::ONE, "aptos_account".to_string()),
//!         "transfer".to_string(),
//!         vec![],
//!         vec![],
//!     );
//!
//!     let result = worker
//!         .push(payload, None)
//!         .await
//!         .context("Failed to push transaction")?;
//!
//!     // Wait for the transaction to be processed.
//!     let result = result.await.context("Failed to get transaction result")?;
//!     println!("Transaction result: {:?}", result);
//!     assert!(result.is_ok(), "Transaction failed on chain");
//!
//!     // Stop worker
//!     worker.stop().context("Failed to stop worker")?;
//!
//!     // Wait for worker internal loop to complete
//!     worker.wait().await.context("Failed to wait for worker to complete")?;
//!
//!     // Wait for the worker to complete.
//!     let result = handle.await.unwrap();
//!     assert!(result.is_ok(), "Worker failed to complete");
//!
//!     Ok(())
//! }
//! ```

use anyhow::{anyhow, Context, Result};
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use aptos_rust_sdk::client::rest_api::AptosFullnodeClient;
use aptos_rust_sdk_types::api_types::address::AccountAddress;
use aptos_rust_sdk_types::api_types::chain_id::ChainId;
use aptos_rust_sdk_types::api_types::transaction::{
    EntryFunction, RawTransaction, TransactionPayload,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

use crate::submitter::{DirectSubmitter, Submitter};

#[derive(Clone, Debug)]
pub enum TransactionWorkerEvent {
    /// Fired after a transaction gets sent to the chain. This implies the transaction
    /// at least wasn't rejected, though it may fail during execution.
    TransactionSent { hash: String, sequence_number: u64 },
    /// Fired if there is an error sending the transaction to the chain, generally
    /// meaning either a 400 due to a bad transaction, a 429 due to rate limiting,
    /// or a 500 due to some server availability issue.
    TransactionSendFailed { sequence_number: u64, error: String },
    /// Fired when a single transaction has executed. It may have succeeded or failed,
    /// it is up to you to look up what happened if you care to do so.
    TransactionExecuted { hash: String, sequence_number: u64 },
    /// Fired if a single transaction fails in execution.
    TransactionExpired {
        hash: String,
        sequence_number: u64,
        error: String,
    },
}

/// Transaction options that can be passed when pushing a transaction.
#[derive(Clone, Debug)]
pub struct TransactionOptions {
    /// Maximum gas amount for the transaction.
    pub max_gas_amount: u64,
    // TODO: Support looking up the price using the gas estimation API.
    /// Gas unit price for the transaction.
    pub gas_unit_price: u64,
    /// Expiration time in seconds from now.
    pub expiration_time_secs: u64,
}

impl Default for TransactionOptions {
    fn default() -> Self {
        Self {
            max_gas_amount: 200000,
            gas_unit_price: 100,
            expiration_time_secs: 30,
        }
    }
}

/// See the module level comments.
pub struct TransactionWorkerBuilder {
    private_key: Ed25519PrivateKey,
    client: AptosFullnodeClient,
    max_pending_responses: usize,
    poll_interval_ms: u64,
    default_options: TransactionOptions,
    event_sender: Option<tokio::sync::mpsc::Sender<TransactionWorkerEvent>>,
    custom_submitter: Option<Arc<dyn Submitter>>,
}

impl TransactionWorkerBuilder {
    /// Create a new TransactionWorkerBuilder with required parameters.
    ///
    /// This constructor requires providing the mandatory private key and client.
    ///
    /// # Parameters
    /// * `private_key` - The private key used for signing transactions
    /// * `client` - The Aptos client for interacting with the blockchain
    pub fn new(private_key: Ed25519PrivateKey, client: AptosFullnodeClient) -> Self {
        Self {
            private_key,
            client,
            max_pending_responses: 100,
            poll_interval_ms: 1000,
            default_options: TransactionOptions::default(),
            event_sender: None,
            custom_submitter: None,
        }
    }

    /// Set the maximum number of pending responses.
    ///
    /// This controls how many transactions can be in flight at once.
    ///
    /// # Parameters
    /// * `max_pending_responses` - Maximum number of transactions that can be pending at once
    pub fn with_max_pending_responses(mut self, max_pending_responses: usize) -> Self {
        self.max_pending_responses = max_pending_responses.max(1);
        self
    }

    /// Set the polling interval in milliseconds.
    ///
    /// This controls how frequently the worker checks for completed transactions.
    ///
    /// # Parameters
    /// * `poll_interval_ms` - Polling interval in milliseconds
    pub fn with_poll_interval_ms(mut self, poll_interval_ms: u64) -> Self {
        self.poll_interval_ms = poll_interval_ms.max(100);
        self
    }

    /// Set the maximum gas amount for the transaction.
    ///
    /// This controls the maximum amount of gas that can be used for a transaction.
    ///
    /// # Parameters
    /// * `max_gas_amount` - Maximum gas amount for the transaction
    pub fn with_max_gas_amount(mut self, max_gas_amount: u64) -> Self {
        self.default_options.max_gas_amount = max_gas_amount;
        self
    }

    /// Set the gas unit price for the transaction.
    ///
    /// This controls the price per unit of gas for a transaction.
    ///
    /// # Parameters
    /// * `gas_unit_price` - Gas unit price for the transaction
    pub fn with_gas_unit_price(mut self, gas_unit_price: u64) -> Self {
        self.default_options.gas_unit_price = gas_unit_price;
        self
    }

    /// Set the expiration time for the transaction.
    ///
    /// This controls the time after which the transaction will expire.
    ///
    /// # Parameters
    /// * `expiration_time_secs` - Expiration time in seconds
    pub fn with_expiration_time_secs(mut self, expiration_time_secs: u64) -> Self {
        self.default_options.expiration_time_secs = expiration_time_secs;
        self
    }

    /// Set an event sender channel for receiving transaction events.
    ///
    /// # Parameters
    /// * `event_sender` - A tokio mpsc sender for TransactionWorkerEvent
    pub fn with_event_sender(
        mut self,
        event_sender: tokio::sync::mpsc::Sender<TransactionWorkerEvent>,
    ) -> Self {
        self.event_sender = Some(event_sender);
        self
    }

    /// Set a custom txn submitter for the worker.
    ///
    /// # Parameters
    /// * `custom_submitter` - A custom submitter for the worker
    pub fn with_custom_submitter(mut self, custom_submitter: Arc<dyn Submitter>) -> Self {
        self.custom_submitter = Some(custom_submitter);
        self
    }

    /// Build the TransactionWorker with the configured options.
    pub async fn build(self) -> Result<TransactionWorker> {
        TransactionWorker::new_with_options(
            self.private_key,
            self.client,
            self.max_pending_responses,
            self.poll_interval_ms,
            self.default_options,
            self.event_sender,
            self.custom_submitter,
        )
        .await
    }
}

/// See the module level comments.
#[derive(Clone)]
pub struct TransactionWorker {
    // TODO: Support other account types. We need an Account type first.
    /// Private key for signing transactions.
    private_key: Arc<Ed25519PrivateKey>,
    /// Sender address. We precompute this once because it doesn't change.
    sender: AccountAddress,
    /// Client for interacting with the Aptos blockchain.
    client: AptosFullnodeClient,
    /// The chain ID of the chain we're working on. We prefetch this once.
    chain_id: ChainId,
    /// The submitter for submitting transactions.
    submitter: Arc<dyn Submitter>,
    /// Default transaction options.
    default_options: TransactionOptions,
    /// Maximum number of pending responses.
    max_pending_responses: usize,
    /// Poll interval in milliseconds.
    poll_interval_ms: u64,
    /// Cancellation token for signaling shutdown.
    cancellation_token: CancellationToken,
    /// Sender for the input queue.
    input_sender: mpsc::Sender<TransactionWorkerInput>,
    /// Receiver for the input queue.
    input_receiver: Arc<Mutex<Option<mpsc::Receiver<TransactionWorkerInput>>>>,
    /// Set of pending responses. Keyed by sequence number.
    pending_responses: Arc<Mutex<HashMap<u64, PendingResponse>>>,
    /// Number of pending submissions.
    pending_submissions: Arc<AtomicUsize>,
    /// Failed sequence numbers that need to be reused.
    failed_sequence_numbers: Arc<Mutex<Vec<u64>>>,
    /// Current sequence number.
    current_sequence_number: Arc<AtomicU64>,
    /// Notifier for when a new pending response is added.
    new_pending_response: Arc<Notify>,
    /// Task tracker for managing spawned tasks
    task_tracker: TaskTracker,
    /// Event sender for transaction events
    event_sender: Option<mpsc::Sender<TransactionWorkerEvent>>,
}

impl TransactionWorker {
    /// Creates a new worker with explicit options.
    ///
    /// This is an internal constructor used by the builder.
    /// For public use, prefer using `TransactionWorkerBuilder`.
    pub async fn new_with_options(
        private_key: Ed25519PrivateKey,
        client: AptosFullnodeClient,
        max_pending_responses: usize,
        poll_interval_ms: u64,
        default_options: TransactionOptions,
        event_sender: Option<mpsc::Sender<TransactionWorkerEvent>>,
        custom_submitter: Option<Arc<dyn Submitter>>,
    ) -> Result<Self> {
        let (input_sender, input_receiver) = mpsc::channel(100);

        let public_key = Ed25519PublicKey::from(&private_key);
        let auth_key =
            aptos_rust_sdk_types::api_types::transaction_authenticator::AuthenticationKey::ed25519(
                &public_key,
            );
        let sender = auth_key.account_address();

        // TODO: There should be a helper for this on the ChainId function, or better
        // yet, `get_state` should use the ChainId type directly.
        // Get the chain ID from the state.
        let state = client.get_state().await?;
        let chain_id = match state.chain_id {
            1 => ChainId::Mainnet,
            2 => ChainId::Testnet,
            3 => ChainId::Testing,
            other => ChainId::Other(other as u8),
        };

        // Load the current sequence number to start with.
        let current_sequence_number = client
            .get_account_info(sender.to_string())
            .await?
            .into_inner()
            .sequence_number;

        info!(
            sender = %sender,
            current_sequence_number,
            "Initialized transaction worker"
        );

        // Build the regular transaction submitter if a custom submitter is not provided.
        let submitter = if let Some(custom_submitter) = custom_submitter {
            custom_submitter
        } else {
            Arc::new(DirectSubmitter {
                client: client.clone(),
            })
        };

        Ok(Self {
            private_key: Arc::new(private_key),
            sender: sender,
            client,
            chain_id,
            submitter,
            default_options,
            max_pending_responses,
            poll_interval_ms,
            cancellation_token: CancellationToken::new(),
            input_sender,
            input_receiver: Arc::new(Mutex::new(Some(input_receiver))),
            pending_responses: Arc::new(Mutex::new(HashMap::new())),
            pending_submissions: Arc::new(AtomicUsize::new(0)),
            failed_sequence_numbers: Arc::new(Mutex::new(Vec::new())),
            current_sequence_number: Arc::new(AtomicU64::new(current_sequence_number)),
            new_pending_response: Arc::new(Notify::new()),
            task_tracker: TaskTracker::new(),
            event_sender,
        })
    }

    /// Send an event through the event sender if one is configured.
    async fn send_event(&self, event: TransactionWorkerEvent) {
        if let Some(sender) = &self.event_sender {
            if let Err(e) = sender.send(event).await {
                warn!(error = %e, "Failed to send event");
            }
        }
    }

    /// Get the total number of pending responses (submissions + responses).
    fn total_pending_responses(&self) -> usize {
        let pending_responses = self.pending_responses.lock().unwrap().len();
        let pending_submissions = self.pending_submissions.load(Ordering::SeqCst);
        pending_responses + pending_submissions
    }

    /// Get the current account's sequence number from the blockchain.
    async fn get_current_sequence_number(&self) -> Result<u64> {
        let account_info = self
            .client
            .get_account_info(self.sender.to_string())
            .await?
            .into_inner();

        let sequence_number = account_info.sequence_number;
        debug!(sender = %self.sender, sequence_number, "Retrieved current sequence number");
        Ok(sequence_number)
    }

    /// Get the next sequence number to use for a transaction.
    fn get_next_sequence_number(&self) -> u64 {
        // Reclaim a failed sequence number if available
        {
            let mut failed_sequence_numbers = self.failed_sequence_numbers.lock().unwrap();
            if !failed_sequence_numbers.is_empty() {
                let sequence_number = failed_sequence_numbers.remove(0);
                warn!(
                    sequence_number = sequence_number,
                    "Reusing failed sequence number"
                );
                return sequence_number;
            }
        }

        // Get the current sequence number and increment it
        let current = self.current_sequence_number.load(Ordering::SeqCst);
        let next = current + 1;
        self.current_sequence_number.store(next, Ordering::SeqCst);

        debug!(
            sequence_number = next,
            previous = current,
            "Incremented sequence number"
        );

        current
    }

    /// Build a transaction from the given input and options. We also return the
    /// expiration timestamp.
    fn build_transaction(
        &self,
        data: TransactionPayload,
        sequence_number: u64,
        options: &Option<TransactionOptions>,
    ) -> (RawTransaction, u64) {
        // Use provided options or default options
        let options = options.as_ref().unwrap_or(&self.default_options);

        // Calculate expiration timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let expiration_time = options.expiration_time_secs;
        let expiration_timestamp_secs = now + expiration_time;

        debug!(
            sender = %self.sender,
            chain_id = %self.chain_id,
            sequence_number,
            max_gas_amount = options.max_gas_amount,
            gas_unit_price = options.gas_unit_price,
            expiration_timestamp_secs,
            "Building transaction"
        );

        // Create the raw transaction
        let raw_txn = RawTransaction::new(
            self.sender,
            sequence_number,
            data,
            options.max_gas_amount,
            options.gas_unit_price,
            expiration_timestamp_secs,
            self.chain_id,
        );

        (raw_txn, expiration_timestamp_secs)
    }

    /// Process a transaction input. This entails signing and submitting the
    /// transaction, but not waiting for the result of txn execution.
    async fn process_input(&self, input: TransactionWorkerInput) {
        let TransactionWorkerInput {
            data,
            options,
            result_sender,
        } = input;

        // Increment pending submissions count
        self.pending_submissions.fetch_add(1, Ordering::SeqCst);

        // Fetch the next sequence number and build the transaction.
        let sequence_number = self.get_next_sequence_number();
        let (transaction, expiration_timestamp_secs) =
            self.build_transaction(data, sequence_number, &options);

        // Sign and submit the transaction.
        match self
            .submitter
            .sign_and_submit_transaction(&self.private_key, transaction)
            .await
        {
            Ok(hash) => {
                // Add to pending responses
                let pending_response = PendingResponse {
                    hash: hash.clone(),
                    sequence_number,
                    expiration_timestamp_secs,
                    result_sender,
                };

                // Send transaction sent event
                self.send_event(TransactionWorkerEvent::TransactionSent {
                    hash: hash.clone(),
                    sequence_number,
                })
                .await;

                {
                    let mut pending_responses = self.pending_responses.lock().unwrap();
                    pending_responses.insert(sequence_number, pending_response);
                    debug!(
                        sequence_number = sequence_number,
                        txn_hash = %hash,
                        pending_responses = pending_responses.len(),
                        "Added transaction to pending responses"
                    );
                }

                // Notify that we have a new pending response
                self.new_pending_response.notify_one();
            }
            Err(err) => {
                // Send transaction failed event
                self.send_event(TransactionWorkerEvent::TransactionSendFailed {
                    sequence_number,
                    error: err.to_string(),
                })
                .await;

                // Failed to submit, add sequence number back to failed pool
                {
                    let mut failed_sequence_numbers = self.failed_sequence_numbers.lock().unwrap();
                    failed_sequence_numbers.push(sequence_number);
                    warn!(
                        sequence_number = sequence_number,
                        error = %err,
                        "Transaction submission failed, adding sequence number to failed pool"
                    );
                }

                // Send the error through the channel
                if let Err(e) = result_sender.send(Err(err)) {
                    debug!(error = ?e, "Failed to send transaction submission error to caller");
                }
            }
        }

        // Decrement pending submissions count
        self.pending_submissions.fetch_sub(1, Ordering::SeqCst);
    }

    /// Start the transaction worker.
    pub fn start(&self) -> Result<JoinHandle<Result<()>>> {
        if self.cancellation_token.is_cancelled() {
            return Err(anyhow!("Worker token is already cancelled"));
        }

        let worker = self.clone();
        let handle = tokio::spawn(async move { worker.inner_loop().await });

        Ok(handle)
    }

    async fn inner_loop(&self) -> Result<()> {
        // Take ownership of the receiver
        let mut receiver = {
            let mut receiver_guard = self.input_receiver.lock().unwrap();
            receiver_guard
                .take()
                .ok_or_else(|| anyhow!("Worker has already been started"))?
        };

        // Start the worker loop in a separate task and track it
        info!("Transaction worker loop started");

        'main: loop {
            // Wait until there are pending responses or the worker is cancelled
            let has_pending_responses = {
                let pending_responses_guard = self.pending_responses.lock().unwrap();
                !pending_responses_guard.is_empty()
            };

            if !has_pending_responses {
                let pending_submissions_val = self.pending_submissions.load(Ordering::SeqCst);

                debug!(
                    pending_responses = 0,
                    pending_submissions = pending_submissions_val,
                    cancelled = self.cancellation_token.is_cancelled(),
                    "Waiting for new transactions or cancellation"
                );

                if self.cancellation_token.is_cancelled() && pending_submissions_val == 0 {
                    info!("Worker cancelled and no pending submissions, exiting");
                    break 'main;
                }

                // Wait for a notification or timeout
                tokio::select! {
                    _ = self.new_pending_response.notified() => {
                        debug!("Received notification of new pending response");
                    },
                    _ = self.cancellation_token.cancelled() => {
                        // Only exit if no pending submissions
                        let pending_submissions_val = self.pending_submissions.load(Ordering::SeqCst);

                        info!(
                            pending_submissions = pending_submissions_val,
                            "Received cancellation signal"
                        );

                        if pending_submissions_val == 0 {
                            info!("No pending submissions, exiting worker loop");
                            break 'main;
                        } else {
                            info!("Waiting for pending submissions to complete before exiting");
                        }
                    },
                    _ = time::sleep(Duration::from_millis(self.poll_interval_ms)) => {
                        debug!("Poll interval elapsed");
                    },
                }
            }

            // Check if we should exit
            let total_pending = {
                let pending_responses_guard = self.pending_responses.lock().unwrap();
                pending_responses_guard.len() + self.pending_submissions.load(Ordering::SeqCst)
            };

            if self.cancellation_token.is_cancelled() && total_pending == 0 {
                info!("Worker cancelled and no pending transactions, exiting");
                break;
            }

            // Get the current sequence number but don't hold the mutex across await
            debug!("Checking for executed transactions");
            let sequence_number = self
                .get_current_sequence_number()
                .await
                .context("Failed to get sequence number from on chain")?;

            // Process pending responses
            let mut executed_txns = Vec::new();
            let mut expired_txns = Vec::new();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            info!(sequence_number, "Current on-chain sequence number");

            // Check each pending response
            {
                let pending_responses_guard = self.pending_responses.lock().unwrap();
                for (_, response) in pending_responses_guard.iter() {
                    if sequence_number > response.sequence_number {
                        // Transaction was executed, mark for removal and resolve.
                        executed_txns.push(response.sequence_number);
                        debug!(
                            txn_hash = %response.hash,
                            sequence_number = response.sequence_number,
                            "Transaction executed"
                        );
                    } else if now > response.expiration_timestamp_secs {
                        // Transaction expired, mark for removal and add to failed sequence numbers
                        expired_txns.push(response.sequence_number);
                        warn!(
                            txn_hash = %response.hash,
                            sequence_number = response.sequence_number,
                            "Transaction expired"
                        );
                    }
                }
            }

            // Process executed transactions (which may have succeeded or failed).
            for sequence_number in executed_txns {
                // Remove the pending response
                let response = {
                    let mut pending_responses_guard = self.pending_responses.lock().unwrap();
                    pending_responses_guard.remove(&sequence_number)
                };

                // Resolve the transaction
                if let Some(response) = response {
                    info!(
                        txn_hash = %response.hash,
                        sequence_number = response.sequence_number,
                        "Transaction confirmed on-chain"
                    );

                    // Send transaction executed event
                    self.send_event(TransactionWorkerEvent::TransactionExecuted {
                        hash: response.hash.clone(),
                        sequence_number: response.sequence_number,
                    })
                    .await;

                    let hash = response.hash.clone();
                    if let Err(e) = response.result_sender.send(Ok(response.hash)) {
                        debug!(
                            txn_hash = %hash,
                            sequence_number = response.sequence_number,
                            error = ?e,
                            "Failed to send transaction confirmation to caller"
                        );
                    }
                }
            }

            // Process failed (expired) transactions
            for sequence_number in expired_txns {
                // Remove the pending response
                let response = {
                    let mut pending_responses_guard = self.pending_responses.lock().unwrap();
                    pending_responses_guard.remove(&sequence_number)
                };

                // Add sequence number to failed pool
                {
                    let mut failed_sequence_numbers = self.failed_sequence_numbers.lock().unwrap();
                    failed_sequence_numbers.push(sequence_number);
                    info!(
                        sequence_number = sequence_number,
                        "Adding expired sequence number to failed pool"
                    );
                }

                // Signal failure with specific error
                if let Some(response) = response {
                    warn!(
                        txn_hash = %response.hash,
                        sequence_number = response.sequence_number,
                        "Transaction expired and dropped"
                    );

                    // Send transaction expired event
                    self.send_event(TransactionWorkerEvent::TransactionExpired {
                        hash: response.hash.clone(),
                        sequence_number: response.sequence_number,
                        error: "Transaction expired".to_string(),
                    })
                    .await;

                    let hash = response.hash.clone();
                    if let Err(e) = response
                        .result_sender
                        .send(Err(anyhow!("Transaction expired")))
                    {
                        debug!(
                            txn_hash = %hash,
                            sequence_number = response.sequence_number,
                            error = ?e,
                            "Failed to send transaction expiration error to caller"
                        );
                    }
                }
            }

            // Process input queue if not cancelled and not at capacity
            if !self.cancellation_token.is_cancelled() {
                let should_process = {
                    let total_pending = self.total_pending_responses();
                    total_pending < self.max_pending_responses
                };

                if should_process {
                    debug!(
                        max_pending = self.max_pending_responses,
                        current_pending = self.total_pending_responses(),
                        "Processing input queue"
                    );

                    while self.total_pending_responses() < self.max_pending_responses {
                        match receiver.try_recv() {
                            Ok(input) => {
                                // Process the input
                                debug!("Processing new transaction input");
                                self.process_input(input).await;
                            }
                            Err(mpsc::error::TryRecvError::Empty) => {
                                // No more inputs, break
                                debug!("Input queue empty");
                                break;
                            }
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                // Channel disconnected, exit loop
                                warn!("Input channel disconnected, exiting worker loop");
                                break 'main;
                            }
                        }
                    }
                }
            }

            // Sleep before checking again
            time::sleep(Duration::from_millis(self.poll_interval_ms)).await;
        }

        info!("Transaction worker loop terminated");

        Ok(())
    }

    /// Stop the transaction worker.
    pub fn stop(&self) -> Result<()> {
        if self.cancellation_token.is_cancelled() {
            return Err(anyhow!("Worker is already stopped"));
        }

        info!("Stopping transaction worker");
        self.cancellation_token.cancel();
        self.task_tracker.close();
        Ok(())
    }

    /// Push a transaction to be processed. This returns a oneshot channel that you can
    /// use to get the result of the transaction submission (not execution). Note that
    /// you can also just register an event receiver.
    pub async fn push(
        &self,
        payload: EntryFunction,
        options: Option<TransactionOptions>,
    ) -> Result<ResultReceiver> {
        if self.cancellation_token.is_cancelled() {
            return Err(anyhow!(
                "Worker is stopped and cannot accept new transactions"
            ));
        }

        // Create a oneshot channel for the result
        let (result_sender, result_receiver) = oneshot::channel();

        let data = TransactionPayload::EntryFunction(payload);
        let input = TransactionWorkerInput {
            data,
            options,
            result_sender,
        };

        let is_running = !self.cancellation_token.is_cancelled();
        let total_pending = self.total_pending_responses();

        debug!(
            is_running,
            total_pending,
            max_pending = self.max_pending_responses,
            "Pushing new transaction"
        );

        if is_running && total_pending < self.max_pending_responses {
            // Process directly if running and not at capacity, but do it in a separate
            // task so that we can return to the caller immediately.
            let worker_clone = self.clone();
            self.task_tracker.spawn(tokio::spawn(async move {
                worker_clone.process_input(input).await;
            }));
        } else {
            // Otherwise, queue for later processing
            debug!("Queueing transaction for later processing");
            self.input_sender.send(input).await.map_err(|e| {
                error!(error = %e, "Failed to send transaction to worker queue");
                anyhow!("Failed to send input to worker")
            })?;
        }

        Ok(result_receiver)
    }

    /// Wait for all pending transactions to complete.
    pub async fn wait(&self) -> Result<()> {
        info!("Waiting for all pending transactions to complete");
        self.task_tracker.wait().await;
        Ok(())
    }
}

type ResultSender = oneshot::Sender<Result<String, anyhow::Error>>;
type ResultReceiver = oneshot::Receiver<Result<String, anyhow::Error>>;

/// Input data for a transaction to be processed by the worker.
struct TransactionWorkerInput {
    /// The transaction payload data.
    data: TransactionPayload,
    /// Transaction options. If not provided, the worker will use the default options.
    options: Option<TransactionOptions>,
    /// Channel for resolving the transaction result
    result_sender: ResultSender,
}

/// A pending transaction response.
#[derive(Debug)]
struct PendingResponse {
    /// Transaction hash.
    hash: String,
    /// Sequence number used by the transaction.
    sequence_number: u64,
    /// Transaction expiration timestamp in seconds since UNIX epoch.
    expiration_timestamp_secs: u64,
    /// Channel for resolving the transaction result
    result_sender: ResultSender,
}
