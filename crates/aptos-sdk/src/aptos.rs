//! Main Aptos client entry point.
//!
//! The [`Aptos`] struct provides a unified interface for all SDK functionality.

use crate::account::Account;
use crate::api::{AptosResponse, FullnodeClient, PendingTransaction};
use crate::config::AptosConfig;
use crate::error::{AptosError, AptosResult};
use crate::transaction::{
    FeePayerRawTransaction, MultiAgentRawTransaction, RawTransaction, SignedTransaction,
    SimulateQueryOptions, SimulationResult, TransactionBuilder, TransactionPayload,
    build_simulation_signed_fee_payer, build_simulation_signed_multi_agent,
};
use crate::types::{AccountAddress, ChainId};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

#[cfg(feature = "ed25519")]
use crate::transaction::EntryFunction;
#[cfg(feature = "ed25519")]
use crate::types::TypeTag;

#[cfg(feature = "faucet")]
use crate::api::FaucetClient;
#[cfg(feature = "faucet")]
use crate::types::HashValue;

#[cfg(feature = "indexer")]
use crate::api::IndexerClient;

/// The main entry point for the Aptos SDK.
///
/// This struct provides a unified interface for interacting with the Aptos blockchain,
/// including account management, transaction building and submission, and queries.
///
/// # Example
///
/// ```rust,no_run
/// use aptos_sdk::{Aptos, AptosConfig};
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     // Create client for testnet
///     let aptos = Aptos::new(AptosConfig::testnet())?;
///
///     // Get ledger info
///     let ledger = aptos.ledger_info().await?;
///     println!("Ledger version: {:?}", ledger.version());
///
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct Aptos {
    config: AptosConfig,
    fullnode: Arc<FullnodeClient>,
    /// Resolved chain ID. Initialized from config; lazily fetched from node
    /// for custom networks where the chain ID is unknown (0).
    /// Stored as `AtomicU8` to avoid lock overhead for this single-byte value.
    chain_id: AtomicU8,
    #[cfg(feature = "faucet")]
    faucet: Option<FaucetClient>,
    #[cfg(feature = "indexer")]
    indexer: Option<IndexerClient>,
}

impl Aptos {
    /// Creates a new Aptos client with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client fails to build (e.g., invalid TLS configuration).
    pub fn new(config: AptosConfig) -> AptosResult<Self> {
        let fullnode = Arc::new(FullnodeClient::new(config.clone())?);

        #[cfg(feature = "faucet")]
        let faucet = FaucetClient::new(&config).ok();

        #[cfg(feature = "indexer")]
        let indexer = IndexerClient::new(&config).ok();

        let chain_id = AtomicU8::new(config.chain_id().id());

        Ok(Self {
            config,
            fullnode,
            chain_id,
            #[cfg(feature = "faucet")]
            faucet,
            #[cfg(feature = "indexer")]
            indexer,
        })
    }

    /// Creates a client for testnet with default settings.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client fails to build (e.g., invalid TLS configuration).
    pub fn testnet() -> AptosResult<Self> {
        Self::new(AptosConfig::testnet())
    }

    /// Creates a client for devnet with default settings.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client fails to build (e.g., invalid TLS configuration).
    pub fn devnet() -> AptosResult<Self> {
        Self::new(AptosConfig::devnet())
    }

    /// Creates a client for mainnet with default settings.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client fails to build (e.g., invalid TLS configuration).
    pub fn mainnet() -> AptosResult<Self> {
        Self::new(AptosConfig::mainnet())
    }

    /// Creates a client for local development network.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client fails to build (e.g., invalid TLS configuration).
    pub fn local() -> AptosResult<Self> {
        Self::new(AptosConfig::local())
    }

    /// Returns the configuration.
    pub fn config(&self) -> &AptosConfig {
        &self.config
    }

    /// Returns the fullnode client.
    pub fn fullnode(&self) -> &FullnodeClient {
        &self.fullnode
    }

    /// Returns the faucet client, if available.
    #[cfg(feature = "faucet")]
    pub fn faucet(&self) -> Option<&FaucetClient> {
        self.faucet.as_ref()
    }

    /// Returns the indexer client, if available.
    #[cfg(feature = "indexer")]
    pub fn indexer(&self) -> Option<&IndexerClient> {
        self.indexer.as_ref()
    }

    // === Ledger Info ===

    /// Gets the current ledger information.
    ///
    /// As a side effect, this also resolves the chain ID if it was unknown
    /// (e.g., for custom network configurations).
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// or the response cannot be parsed.
    pub async fn ledger_info(&self) -> AptosResult<crate::api::response::LedgerInfo> {
        let response = self.fullnode.get_ledger_info().await?;
        let info = response.into_inner();

        // Update chain_id if it was unknown (custom network).
        // NOTE: The load-then-store pattern has a benign TOCTOU race: multiple
        // threads may concurrently see chain_id == 0 and all store the same
        // value from the ledger info response. This is safe because they always
        // store the identical chain_id value returned by the node.
        if self.chain_id.load(Ordering::Relaxed) == 0 && info.chain_id > 0 {
            self.chain_id.store(info.chain_id, Ordering::Relaxed);
        }

        Ok(info)
    }

    /// Returns the current chain ID.
    ///
    /// For known networks (mainnet, testnet, devnet, local), this returns the
    /// well-known chain ID immediately. For custom networks, this returns
    /// `ChainId(0)` until the chain ID is resolved via [`ensure_chain_id`](Self::ensure_chain_id)
    /// or any method that makes a request to the node (e.g., [`build_transaction`](Self::build_transaction),
    /// [`ledger_info`](Self::ledger_info)).
    ///
    pub fn chain_id(&self) -> ChainId {
        ChainId::new(self.chain_id.load(Ordering::Relaxed))
    }

    /// Resolves the chain ID from the node if it is unknown.
    ///
    /// For known networks, this returns the chain ID immediately without
    /// making a network request. For custom networks (chain ID 0), this
    /// fetches the ledger info from the node to discover the actual chain ID
    /// and caches it for future use.
    ///
    /// This is called automatically by [`build_transaction`](Self::build_transaction)
    /// and other transaction methods, so you typically don't need to call it
    /// directly unless you need the chain ID before building a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request to fetch ledger info fails.
    ///
    pub async fn ensure_chain_id(&self) -> AptosResult<ChainId> {
        let id = self.chain_id.load(Ordering::Relaxed);
        if id > 0 {
            return Ok(ChainId::new(id));
        }
        // Chain ID is unknown; fetch from node
        let response = self.fullnode.get_ledger_info().await?;
        let info = response.into_inner();
        self.chain_id.store(info.chain_id, Ordering::Relaxed);
        Ok(ChainId::new(info.chain_id))
    }

    // === Account ===

    /// Gets the sequence number for an account.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code
    /// (e.g., account not found 404), or the response cannot be parsed.
    pub async fn get_sequence_number(&self, address: AccountAddress) -> AptosResult<u64> {
        self.fullnode.get_sequence_number(address).await
    }

    /// Gets the APT balance for an account.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// or the response cannot be parsed.
    pub async fn get_balance(&self, address: AccountAddress) -> AptosResult<u64> {
        self.fullnode.get_account_balance(address).await
    }

    /// Checks if an account exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the API returns an error status code
    /// other than 404 (not found). A 404 error is handled gracefully and returns `Ok(false)`.
    pub async fn account_exists(&self, address: AccountAddress) -> AptosResult<bool> {
        match self.fullnode.get_account(address).await {
            Ok(_) => Ok(true),
            Err(AptosError::Api {
                status_code: 404, ..
            }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    // === Transactions ===

    /// Builds a transaction for the given account.
    ///
    /// This automatically fetches the sequence number and gas price.
    ///
    /// # Errors
    ///
    /// Returns an error if fetching the sequence number fails, fetching the gas price fails,
    /// or if the transaction builder fails to construct a valid transaction (e.g., missing
    /// required fields).
    pub async fn build_transaction<A: Account>(
        &self,
        sender: &A,
        payload: TransactionPayload,
    ) -> AptosResult<RawTransaction> {
        // Fetch sequence number, gas price, and chain ID in parallel
        let (sequence_number, gas_estimation, chain_id) = tokio::join!(
            self.get_sequence_number(sender.address()),
            self.fullnode.estimate_gas_price(),
            self.ensure_chain_id()
        );
        let sequence_number = sequence_number?;
        let gas_estimation = gas_estimation?;
        let chain_id = chain_id?;

        TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(sequence_number)
            .payload(payload)
            .gas_unit_price(gas_estimation.data.recommended())
            .chain_id(chain_id)
            .expiration_from_now(600)
            .build()
    }

    /// Signs and submits a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if building the transaction fails, signing fails (e.g., invalid key),
    /// the transaction cannot be serialized to BCS, the HTTP request fails, or the API returns
    /// an error status code.
    #[cfg(feature = "ed25519")]
    pub async fn sign_and_submit<A: Account>(
        &self,
        account: &A,
        payload: TransactionPayload,
    ) -> AptosResult<AptosResponse<PendingTransaction>> {
        let raw_txn = self.build_transaction(account, payload).await?;
        let signed = crate::transaction::builder::sign_transaction(&raw_txn, account)?;
        self.fullnode.submit_transaction(&signed).await
    }

    /// Signs, submits, and waits for a transaction to complete.
    ///
    /// # Errors
    ///
    /// Returns an error if building the transaction fails, signing fails, submission fails,
    /// the transaction times out waiting for commitment, the transaction execution fails,
    /// or any HTTP/API errors occur.
    #[cfg(feature = "ed25519")]
    pub async fn sign_submit_and_wait<A: Account>(
        &self,
        account: &A,
        payload: TransactionPayload,
        timeout: Option<Duration>,
    ) -> AptosResult<AptosResponse<serde_json::Value>> {
        let raw_txn = self.build_transaction(account, payload).await?;
        let signed = crate::transaction::builder::sign_transaction(&raw_txn, account)?;
        self.fullnode.submit_and_wait(&signed, timeout).await
    }

    /// Submits a pre-signed transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be serialized to BCS, the HTTP request fails,
    /// or the API returns an error status code.
    pub async fn submit_transaction(
        &self,
        signed_txn: &SignedTransaction,
    ) -> AptosResult<AptosResponse<PendingTransaction>> {
        self.fullnode.submit_transaction(signed_txn).await
    }

    /// Submits and waits for a pre-signed transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if transaction submission fails, the transaction times out waiting
    /// for commitment, the transaction execution fails (`vm_status` indicates failure),
    /// or any HTTP/API errors occur.
    pub async fn submit_and_wait(
        &self,
        signed_txn: &SignedTransaction,
        timeout: Option<Duration>,
    ) -> AptosResult<AptosResponse<serde_json::Value>> {
        self.fullnode.submit_and_wait(signed_txn, timeout).await
    }

    /// Simulates a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be serialized to BCS, the HTTP request fails,
    /// the API returns an error status code, or the response cannot be parsed as JSON.
    pub async fn simulate_transaction(
        &self,
        signed_txn: &SignedTransaction,
    ) -> AptosResult<AptosResponse<Vec<serde_json::Value>>> {
        self.fullnode.simulate_transaction(signed_txn).await
    }

    /// Simulates a transaction and returns a parsed result.
    ///
    /// This method provides a more ergonomic way to simulate transactions
    /// with detailed result parsing.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let result = aptos.simulate(&account, payload).await?;
    /// if result.success() {
    ///     println!("Gas estimate: {}", result.gas_used());
    /// } else {
    ///     println!("Would fail: {}", result.error_message().unwrap_or_default());
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if building the transaction fails, signing fails, simulation fails,
    /// or the simulation response cannot be parsed.
    #[cfg(feature = "ed25519")]
    pub async fn simulate<A: Account>(
        &self,
        account: &A,
        payload: TransactionPayload,
    ) -> AptosResult<crate::transaction::SimulationResult> {
        use crate::transaction::SignedTransaction;

        let raw_txn = self.build_transaction(account, payload).await?;

        // The simulation endpoint *rejects* valid signatures
        // (it returns 400 "Simulated transactions must not have a valid
        // signature") because its job is gas estimation, not actual
        // execution. We attach the account's real public key (the simulator
        // still uses it to walk the signing-message hash) and a zeroed
        // signature of the appropriate shape for the account's
        // signature scheme.
        let auth = build_zero_signed_authenticator(account)?;
        let signed = SignedTransaction::new(raw_txn, auth);

        let response = self.fullnode.simulate_transaction(&signed).await?;
        crate::transaction::SimulationResult::from_response(response.into_inner())
    }

    /// Simulates a transaction with a pre-built signed transaction.
    ///
    /// For gas estimation options (e.g. `estimate_gas_unit_price`), use
    /// [`simulate_signed_with_options`](Self::simulate_signed_with_options).
    ///
    /// # Errors
    ///
    /// Returns an error if simulation fails or the simulation response cannot be parsed.
    pub async fn simulate_signed(
        &self,
        signed_txn: &SignedTransaction,
    ) -> AptosResult<SimulationResult> {
        let response = self.fullnode.simulate_transaction(signed_txn).await?;
        SimulationResult::from_response(response.into_inner())
    }

    /// Simulates a signed transaction with query options for the node.
    ///
    /// Use this when you need [`SimulateQueryOptions`] (e.g. `estimate_gas_unit_price`,
    /// `estimate_max_gas_amount`). For the common case without options, use
    /// [`simulate_signed`](Self::simulate_signed) instead.
    ///
    /// # Errors
    ///
    /// Returns an error if simulation fails or the simulation response cannot be parsed.
    pub async fn simulate_signed_with_options(
        &self,
        signed_txn: &SignedTransaction,
        options: SimulateQueryOptions,
    ) -> AptosResult<SimulationResult> {
        let response = self
            .fullnode
            .simulate_transaction_with_options(signed_txn, Some(options))
            .await?;
        SimulationResult::from_response(response.into_inner())
    }

    /// Simulates a multi-agent transaction without requiring real signatures.
    ///
    /// Builds a simulation-only signed transaction (using
    /// [`crate::transaction::authenticator::AccountAuthenticator::NoAccountAuthenticator`]) and sends it to the
    /// simulate endpoint. Use this to check outcome and gas before collecting
    /// signatures from sender and secondary signers.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let multi_agent = MultiAgentRawTransaction::new(raw_txn, secondary_addresses);
    /// let result = aptos.simulate_multi_agent(&multi_agent, None).await?;
    /// if result.success() {
    ///     println!("Gas: {}", result.gas_used());
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the simulate request fails or the response cannot be parsed.
    pub async fn simulate_multi_agent(
        &self,
        multi_agent: &MultiAgentRawTransaction,
        options: impl Into<Option<SimulateQueryOptions>>,
    ) -> AptosResult<SimulationResult> {
        let signed = build_simulation_signed_multi_agent(multi_agent);
        match options.into() {
            None => self.simulate_signed(&signed).await,
            Some(opts) => self.simulate_signed_with_options(&signed, opts).await,
        }
    }

    /// Simulates a fee-payer (sponsored) transaction without requiring real signatures.
    ///
    /// Builds a simulation-only signed transaction (using
    /// [`crate::transaction::authenticator::AccountAuthenticator::NoAccountAuthenticator`]) and sends it to the
    /// simulate endpoint. Use this to check outcome and gas before collecting
    /// signatures from sender, secondary signers, and fee payer.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let fee_payer_txn = FeePayerRawTransaction::new_simple(raw_txn, fee_payer_address);
    /// let result = aptos.simulate_fee_payer(&fee_payer_txn, None).await?;
    /// if result.success() {
    ///     println!("Gas: {}", result.gas_used());
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the simulate request fails or the response cannot be parsed.
    pub async fn simulate_fee_payer(
        &self,
        fee_payer_txn: &FeePayerRawTransaction,
        options: impl Into<Option<SimulateQueryOptions>>,
    ) -> AptosResult<SimulationResult> {
        let signed = build_simulation_signed_fee_payer(fee_payer_txn);
        match options.into() {
            None => self.simulate_signed(&signed).await,
            Some(opts) => self.simulate_signed_with_options(&signed, opts).await,
        }
    }

    /// Estimates gas for a transaction by simulating it.
    ///
    /// Returns the estimated gas usage with a 20% safety margin.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let gas = aptos.estimate_gas(&account, payload).await?;
    /// println!("Estimated gas: {}", gas);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if simulation fails or if the simulation indicates the transaction
    /// would fail (returns [`AptosError::SimulationFailed`]).
    #[cfg(feature = "ed25519")]
    pub async fn estimate_gas<A: Account>(
        &self,
        account: &A,
        payload: TransactionPayload,
    ) -> AptosResult<u64> {
        let result = self.simulate(account, payload).await?;
        if result.success() {
            Ok(result.safe_gas_estimate())
        } else {
            Err(AptosError::SimulationFailed(
                result
                    .error_message()
                    .unwrap_or_else(|| result.vm_status().to_string()),
            ))
        }
    }

    /// Simulates and submits a transaction if successful.
    ///
    /// This is a "dry run" approach that first simulates the transaction
    /// to verify it will succeed before actually submitting it.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let result = aptos.simulate_and_submit(&account, payload).await?;
    /// println!("Transaction submitted: {}", result.hash);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if building the transaction fails, signing fails, simulation fails,
    /// the simulation indicates the transaction would fail (returns [`AptosError::SimulationFailed`]),
    /// or transaction submission fails.
    #[cfg(feature = "ed25519")]
    pub async fn simulate_and_submit<A: Account>(
        &self,
        account: &A,
        payload: TransactionPayload,
    ) -> AptosResult<AptosResponse<PendingTransaction>> {
        // First simulate with an intentionally invalid (zeroed) signature;
        // the node rejects real signatures on the simulate endpoint.
        let raw_txn = self.build_transaction(account, payload).await?;
        let sim_auth = build_zero_signed_authenticator(account)?;
        let sim_signed = SignedTransaction::new(raw_txn.clone(), sim_auth);
        let sim_response = self.fullnode.simulate_transaction(&sim_signed).await?;
        let sim_result =
            crate::transaction::SimulationResult::from_response(sim_response.into_inner())?;

        if sim_result.failed() {
            return Err(AptosError::SimulationFailed(
                sim_result
                    .error_message()
                    .unwrap_or_else(|| sim_result.vm_status().to_string()),
            ));
        }

        let signed = crate::transaction::builder::sign_transaction(&raw_txn, account)?;
        self.fullnode.submit_transaction(&signed).await
    }

    /// Simulates, submits, and waits for a transaction.
    ///
    /// Like `simulate_and_submit` but also waits for the transaction to complete.
    ///
    /// # Errors
    ///
    /// Returns an error if building the transaction fails, signing fails, simulation fails,
    /// the simulation indicates the transaction would fail (returns [`AptosError::SimulationFailed`]),
    /// submission fails, the transaction times out waiting for commitment, or the transaction
    /// execution fails.
    #[cfg(feature = "ed25519")]
    pub async fn simulate_submit_and_wait<A: Account>(
        &self,
        account: &A,
        payload: TransactionPayload,
        timeout: Option<Duration>,
    ) -> AptosResult<AptosResponse<serde_json::Value>> {
        // First simulate with an intentionally invalid (zeroed) signature;
        // the node rejects real signatures on the simulate endpoint.
        let raw_txn = self.build_transaction(account, payload).await?;
        let sim_auth = build_zero_signed_authenticator(account)?;
        let sim_signed = SignedTransaction::new(raw_txn.clone(), sim_auth);
        let sim_response = self.fullnode.simulate_transaction(&sim_signed).await?;
        let sim_result =
            crate::transaction::SimulationResult::from_response(sim_response.into_inner())?;

        if sim_result.failed() {
            return Err(AptosError::SimulationFailed(
                sim_result
                    .error_message()
                    .unwrap_or_else(|| sim_result.vm_status().to_string()),
            ));
        }

        let signed = crate::transaction::builder::sign_transaction(&raw_txn, account)?;
        self.fullnode.submit_and_wait(&signed, timeout).await
    }

    // === Transfers ===

    /// Transfers APT from one account to another.
    ///
    /// # Errors
    ///
    /// Returns an error if building the transfer payload fails (e.g., invalid address),
    /// signing fails, submission fails, the transaction times out, or the transaction
    /// execution fails.
    #[cfg(feature = "ed25519")]
    pub async fn transfer_apt<A: Account>(
        &self,
        sender: &A,
        recipient: AccountAddress,
        amount: u64,
    ) -> AptosResult<AptosResponse<serde_json::Value>> {
        let payload = EntryFunction::apt_transfer(recipient, amount)?;
        self.sign_submit_and_wait(sender, payload.into(), None)
            .await
    }

    /// Transfers a coin from one account to another.
    ///
    /// # Errors
    ///
    /// Returns an error if building the transfer payload fails (e.g., invalid type tag or address),
    /// signing fails, submission fails, the transaction times out, or the transaction
    /// execution fails.
    #[cfg(feature = "ed25519")]
    pub async fn transfer_coin<A: Account>(
        &self,
        sender: &A,
        recipient: AccountAddress,
        coin_type: TypeTag,
        amount: u64,
    ) -> AptosResult<AptosResponse<serde_json::Value>> {
        let payload = EntryFunction::coin_transfer(coin_type, recipient, amount)?;
        self.sign_submit_and_wait(sender, payload.into(), None)
            .await
    }

    // === View Functions ===

    /// Calls a view function using JSON encoding.
    ///
    /// For lossless serialization of large integers, use [`view_bcs`](Self::view_bcs) instead.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// or the response cannot be parsed as JSON.
    pub async fn view(
        &self,
        function: &str,
        type_args: Vec<String>,
        args: Vec<serde_json::Value>,
    ) -> AptosResult<Vec<serde_json::Value>> {
        let response = self.fullnode.view(function, type_args, args).await?;
        Ok(response.into_inner())
    }

    /// Calls a view function using BCS encoding for both inputs and outputs.
    ///
    /// This method provides lossless serialization by using BCS (Binary Canonical Serialization)
    /// instead of JSON, which is important for large integers (u128, u256) and other types
    /// where JSON can lose precision.
    ///
    /// # Type Parameter
    ///
    /// * `T` - The expected return type. Must implement `serde::de::DeserializeOwned`.
    ///
    /// # Arguments
    ///
    /// * `function` - The fully qualified function name (e.g., `0x1::coin::balance`)
    /// * `type_args` - Type arguments as strings (e.g., `0x1::aptos_coin::AptosCoin`)
    /// * `args` - Pre-serialized BCS arguments as byte vectors
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use aptos_sdk::{Aptos, AptosConfig, AccountAddress};
    ///
    /// let aptos = Aptos::new(AptosConfig::testnet())?;
    /// let owner = AccountAddress::from_hex("0x1")?;
    ///
    /// // BCS-encode the argument
    /// let args = vec![aptos_bcs::to_bytes(&owner)?];
    ///
    /// // Call view function with typed return
    /// let balance: u64 = aptos.view_bcs(
    ///     "0x1::coin::balance",
    ///     vec!["0x1::aptos_coin::AptosCoin".to_string()],
    ///     args,
    /// ).await?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// or the BCS deserialization fails.
    pub async fn view_bcs<T: serde::de::DeserializeOwned>(
        &self,
        function: &str,
        type_args: Vec<String>,
        args: Vec<Vec<u8>>,
    ) -> AptosResult<T> {
        let response = self.fullnode.view_bcs(function, type_args, args).await?;
        let bytes = response.into_inner();
        aptos_bcs::from_bytes(&bytes).map_err(|e| AptosError::Bcs(e.to_string()))
    }

    /// Calls a view function with BCS inputs and returns raw BCS bytes.
    ///
    /// Use this when you need to manually deserialize the response or when
    /// the return type is complex or dynamic.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the API returns an error status code.
    pub async fn view_bcs_raw(
        &self,
        function: &str,
        type_args: Vec<String>,
        args: Vec<Vec<u8>>,
    ) -> AptosResult<Vec<u8>> {
        let response = self.fullnode.view_bcs(function, type_args, args).await?;
        Ok(response.into_inner())
    }

    // === Faucet ===

    /// Funds an account using the faucet.
    ///
    /// This method waits for the faucet transactions to be confirmed before returning.
    ///
    /// Some Aptos faucets (notably devnet) cap the amount delivered per request to a
    /// fixed value (typically 1 APT / 100,000,000 octas) regardless of the requested
    /// amount. This method automatically issues additional faucet requests, up to a
    /// reasonable limit, until the account's balance has been topped up by at least
    /// `amount` octas. The returned vector contains the transaction hashes from every
    /// underlying faucet call.
    ///
    /// # Errors
    ///
    /// Returns an error if the faucet feature is not enabled, the faucet request fails
    /// (e.g., rate limiting 429, server error 500), waiting for transaction confirmation
    /// times out, any HTTP/API errors occur, or if the requested amount cannot be
    /// delivered after several attempts.
    #[cfg(feature = "faucet")]
    pub async fn fund_account(
        &self,
        address: AccountAddress,
        amount: u64,
    ) -> AptosResult<Vec<String>> {
        // Hard-cap on how many faucet calls we'll make to satisfy a single
        // `fund_account` request. This prevents unbounded faucet usage if the
        // faucet is silently dropping requests.
        const MAX_FAUCET_ATTEMPTS: u32 = 16;

        let faucet = self
            .faucet
            .as_ref()
            .ok_or_else(|| AptosError::FeatureNotEnabled("faucet".into()))?;

        // Snapshot the starting balance (0 if the account doesn't yet exist).
        let starting_balance = self.get_balance(address).await.unwrap_or(0);
        let target_balance = starting_balance.saturating_add(amount);

        let mut all_hashes: Vec<String> = Vec::new();
        let mut current_balance = starting_balance;
        let mut attempts = 0u32;

        while current_balance < target_balance && attempts < MAX_FAUCET_ATTEMPTS {
            attempts += 1;
            let still_needed = target_balance.saturating_sub(current_balance);
            let txn_hashes = faucet.fund(address, still_needed).await?;

            // Parse hashes for waiting on confirmation.
            let hashes: Vec<HashValue> = txn_hashes
                .iter()
                .filter_map(|hash_str| {
                    let hash_str_clean = hash_str.strip_prefix("0x").unwrap_or(hash_str);
                    HashValue::from_hex(hash_str_clean).ok()
                })
                .collect();

            // Wait for all faucet transactions in this batch to be confirmed in parallel.
            let wait_futures: Vec<_> = hashes
                .iter()
                .map(|hash| {
                    self.fullnode
                        .wait_for_transaction(hash, Some(Duration::from_mins(1)))
                })
                .collect();
            let results = futures::future::join_all(wait_futures).await;
            for result in results {
                result?;
            }

            all_hashes.extend(txn_hashes);

            // Re-read balance; if it didn't move, the faucet isn't going to help.
            let new_balance = self.get_balance(address).await.unwrap_or(current_balance);
            if new_balance <= current_balance {
                return Err(AptosError::api(
                    400,
                    format!(
                        "faucet returned successful response but balance did not increase (\
                         attempts={attempts}, balance={new_balance}, requested top-up={amount})"
                    ),
                ));
            }
            current_balance = new_balance;
        }

        if current_balance < target_balance {
            return Err(AptosError::api(
                429,
                format!(
                    "faucet could not deliver {amount} octas in {attempts} attempts \
                     (starting balance={starting_balance}, current balance={current_balance})"
                ),
            ));
        }

        Ok(all_hashes)
    }

    #[cfg(all(feature = "faucet", feature = "ed25519"))]
    /// Creates a funded account.
    ///
    /// # Errors
    ///
    /// Returns an error if funding the account fails (see [`Self::fund_account`] for details).
    pub async fn create_funded_account(
        &self,
        amount: u64,
    ) -> AptosResult<crate::account::Ed25519Account> {
        let account = crate::account::Ed25519Account::generate();
        self.fund_account(account.address(), amount).await?;
        Ok(account)
    }

    // === Transaction Batching ===

    /// Returns a batch operations helper for submitting multiple transactions.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let aptos = Aptos::testnet()?;
    ///
    /// // Build and submit batch of transfers
    /// let payloads = vec![
    ///     EntryFunction::apt_transfer(addr1, 1000)?.into(),
    ///     EntryFunction::apt_transfer(addr2, 2000)?.into(),
    ///     EntryFunction::apt_transfer(addr3, 3000)?.into(),
    /// ];
    ///
    /// let results = aptos.batch().submit_and_wait(&sender, payloads, None).await?;
    /// ```
    pub fn batch(&self) -> crate::transaction::BatchOperations<'_> {
        crate::transaction::BatchOperations::new(&self.fullnode, &self.chain_id)
    }

    /// Submits multiple transactions in parallel.
    ///
    /// This is a convenience method that builds, signs, and submits
    /// multiple transactions at once.
    ///
    /// # Arguments
    ///
    /// * `account` - The account to sign with
    /// * `payloads` - The transaction payloads to submit
    ///
    /// # Returns
    ///
    /// Results for each transaction in the batch.
    ///
    /// # Errors
    ///
    /// Returns an error if building any transaction fails, signing fails, or submission fails
    /// for any transaction in the batch.
    #[cfg(feature = "ed25519")]
    pub async fn submit_batch<A: Account>(
        &self,
        account: &A,
        payloads: Vec<TransactionPayload>,
    ) -> AptosResult<Vec<crate::transaction::BatchTransactionResult>> {
        self.batch().submit(account, payloads).await
    }

    /// Submits multiple transactions and waits for all to complete.
    ///
    /// # Arguments
    ///
    /// * `account` - The account to sign with
    /// * `payloads` - The transaction payloads to submit
    /// * `timeout` - Optional timeout for waiting
    ///
    /// # Returns
    ///
    /// Results for each transaction in the batch.
    ///
    /// # Errors
    ///
    /// Returns an error if building any transaction fails, signing fails, submission fails,
    /// any transaction times out waiting for commitment, or any transaction execution fails.
    #[cfg(feature = "ed25519")]
    pub async fn submit_batch_and_wait<A: Account>(
        &self,
        account: &A,
        payloads: Vec<TransactionPayload>,
        timeout: Option<Duration>,
    ) -> AptosResult<Vec<crate::transaction::BatchTransactionResult>> {
        self.batch()
            .submit_and_wait(account, payloads, timeout)
            .await
    }

    /// Transfers APT to multiple recipients in a batch.
    ///
    /// # Arguments
    ///
    /// * `sender` - The sending account
    /// * `transfers` - List of (recipient, amount) pairs
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let results = aptos.batch_transfer_apt(&sender, vec![
    ///     (addr1, 1_000_000),  // 0.01 APT
    ///     (addr2, 2_000_000),  // 0.02 APT
    ///     (addr3, 3_000_000),  // 0.03 APT
    /// ]).await?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if building any transfer payload fails, signing fails, submission fails,
    /// any transaction times out, or any transaction execution fails.
    #[cfg(feature = "ed25519")]
    pub async fn batch_transfer_apt<A: Account>(
        &self,
        sender: &A,
        transfers: Vec<(AccountAddress, u64)>,
    ) -> AptosResult<Vec<crate::transaction::BatchTransactionResult>> {
        self.batch().transfer_apt(sender, transfers).await
    }
}

// The simulation helpers below are only reachable from `Aptos::simulate`,
// which is `#[cfg(feature = "ed25519")]`. Mirror that gate on the helpers so
// `cargo clippy -p aptos-sdk --no-default-features` does not flag them as
// dead code.

// Backticks on every identifier in this module-internal doc comment keep
// `clippy::doc_markdown` happy and make the rendering clearer too.

#[cfg(feature = "ed25519")]
/// Builds a [`TransactionAuthenticator`] containing the account's real
/// public key paired with an **all-zero** signature of the correct shape
/// for the account's signature scheme.
///
/// Used by [`Aptos::simulate`] / [`Aptos::estimate_gas`]: the on-chain
/// simulation endpoint rejects transactions carrying a valid signature
/// (it is a gas-estimation tool, not an execution tool) but it does need
/// to walk the signing-message hash to estimate gas correctly. A
/// well-shaped zero-signed authenticator is exactly what it expects.
///
/// Supported schemes (everything the SDK can already produce signatures for):
/// * `ED25519_SCHEME` -- `Ed25519` 32-byte pubkey + 64-byte zero signature.
/// * `MULTI_ED25519_SCHEME` -- `MultiEd25519` pubkey/signature wrapped as
///   `TransactionAuthenticator::MultiEd25519`; signature is `64 * t` zero
///   bytes plus a 4-byte bitmap with bits `0..t` set, where `t` is the
///   account's threshold (recovered from the pubkey's last byte).
/// * `SINGLE_KEY_SCHEME` -- Wraps any single-key account (`Ed25519SingleKey`,
///   `Secp256k1`, `Secp256r1`, `WebAuthn`) by emitting a zeroed `AnySignature`
///   whose variant tag matches the account's pubkey variant.
/// * `MULTI_KEY_SCHEME` -- Wraps a `MultiKey` account by emitting a zeroed
///   `MultiKeySignature` whose `AnySignature` variants match the pubkeys.
fn build_zero_signed_authenticator<A: Account>(
    account: &A,
) -> AptosResult<crate::transaction::TransactionAuthenticator> {
    use crate::crypto::{
        ED25519_SCHEME, MULTI_ED25519_SCHEME, MULTI_KEY_SCHEME, SINGLE_KEY_SCHEME,
    };
    use crate::transaction::TransactionAuthenticator;
    use crate::transaction::authenticator::{
        AccountAuthenticator, Ed25519PublicKey, Ed25519Signature,
    };

    let pubkey_bytes = account.public_key_bytes();
    let scheme = account.signature_scheme();

    match scheme {
        // Single Ed25519: 32-byte pubkey, 64-byte zero signature, top-level
        // TransactionAuthenticator::Ed25519 variant.
        s if s == ED25519_SCHEME => {
            let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into().map_err(|_| {
                crate::error::AptosError::transaction(
                    "simulate(): Ed25519 account exposed a non-32-byte public key",
                )
            })?;
            Ok(TransactionAuthenticator::Ed25519 {
                public_key: Ed25519PublicKey(pubkey_arr),
                signature: Ed25519Signature([0u8; 64]),
            })
        }

        // MultiEd25519: the pubkey blob is `pk_0 || pk_1 || ... || pk_{n-1} || threshold`
        // where each `pk_i` is 32 bytes. We can recover `n` and `t`, then emit
        // `t` zero signatures plus a bitmap with bits 0..t set (MSB-first
        // ordering, matching `MultiEd25519Signature::new`).
        s if s == MULTI_ED25519_SCHEME => {
            const PK_LEN: usize = 32;
            const SIG_LEN: usize = 64;
            if pubkey_bytes.is_empty() || !(pubkey_bytes.len() - 1).is_multiple_of(PK_LEN) {
                return Err(crate::error::AptosError::transaction(
                    "simulate(): MultiEd25519 public_key_bytes has invalid length",
                ));
            }
            let threshold = *pubkey_bytes.last().unwrap() as usize;
            if threshold == 0 {
                return Err(crate::error::AptosError::transaction(
                    "simulate(): MultiEd25519 threshold cannot be zero",
                ));
            }
            // MSB-first bitmap, threshold bits set starting at index 0.
            let mut bitmap = [0u8; 4];
            for i in 0..threshold {
                let byte = i / 8;
                let bit = i % 8;
                bitmap[byte] |= 0b1000_0000_u8 >> bit;
            }
            let mut signature = Vec::with_capacity(threshold * SIG_LEN + 4);
            signature.extend(std::iter::repeat_n(0u8, threshold * SIG_LEN));
            signature.extend_from_slice(&bitmap);
            Ok(TransactionAuthenticator::MultiEd25519 {
                public_key: pubkey_bytes,
                signature,
            })
        }

        // SingleKey: pubkey is already `BCS(AnyPublicKey)` (variant + ULEB128(len) + bytes).
        // We mirror the variant tag in a matching zero AnySignature and wrap
        // in a SingleSender top-level TransactionAuthenticator.
        s if s == SINGLE_KEY_SCHEME => {
            let zero_sig = zero_any_signature_for_pubkey(&pubkey_bytes).ok_or_else(|| {
                crate::error::AptosError::transaction(
                    "simulate(): unsupported AnyPublicKey variant in SingleKey account",
                )
            })?;
            Ok(TransactionAuthenticator::single_sender(
                AccountAuthenticator::single_key(pubkey_bytes, zero_sig),
            ))
        }

        // MultiKey: pubkey is `num_keys || (variant || ULEB128(len) || bytes) * n || threshold`.
        // Emit a zeroed MultiKeySignature: one zero AnySignature per pubkey
        // for the first `threshold` keys, plus the BCS BitVec length prefix
        // and a bitmap with bits 0..threshold set (MSB-first).
        s if s == MULTI_KEY_SCHEME => {
            let (variants, threshold) = parse_multi_key_pubkey(&pubkey_bytes)?;
            if threshold == 0 || (threshold as usize) > variants.len() {
                return Err(crate::error::AptosError::transaction(
                    "simulate(): invalid MultiKey threshold",
                ));
            }
            let mut sig_bytes = Vec::with_capacity(1 + threshold as usize * 66 + 1 + 4);
            sig_bytes.push(threshold); // ULEB128(num_sigs); fits in 1 byte for n <= 32.
            for variant in variants.iter().take(threshold as usize) {
                let zero_sig = zero_any_signature_for_variant(*variant).ok_or_else(|| {
                    crate::error::AptosError::transaction(
                        "simulate(): unsupported AnyPublicKey variant in MultiKey account",
                    )
                })?;
                sig_bytes.extend_from_slice(&zero_sig);
            }
            // BitVec length prefix + 4-byte bitmap (MSB-first).
            sig_bytes.push(4);
            let mut bitmap = [0u8; 4];
            for i in 0..threshold as usize {
                let byte = i / 8;
                let bit = i % 8;
                bitmap[byte] |= 0b1000_0000_u8 >> bit;
            }
            sig_bytes.extend_from_slice(&bitmap);
            Ok(TransactionAuthenticator::single_sender(
                AccountAuthenticator::multi_key(pubkey_bytes, sig_bytes),
            ))
        }

        _ => Err(crate::error::AptosError::transaction(format!(
            "simulate(): unsupported signature scheme {scheme}; \
             use simulate_signed() with a hand-built zero-signed transaction"
        ))),
    }
}

/// Builds a BCS-encoded zero `AnySignature` whose variant tag matches the
/// `AnyPublicKey` carried by the given `SingleKey` pubkey blob. Returns
/// `None` for unknown variants.
#[cfg(feature = "ed25519")]
fn zero_any_signature_for_pubkey(any_public_key_bcs: &[u8]) -> Option<Vec<u8>> {
    let variant = *any_public_key_bcs.first()?;
    zero_any_signature_for_variant(variant)
}

/// Builds a BCS-encoded zero `AnySignature` for the given variant tag.
#[cfg(feature = "ed25519")]
fn zero_any_signature_for_variant(variant: u8) -> Option<Vec<u8>> {
    // For all SDK-supported variants, the inner signature payload is 64
    // bytes (Ed25519, Secp256k1Ecdsa, and -- in the SDK's representation
    // -- the Secp256r1 raw signature carried inside the WebAuthn envelope).
    // Variant 2 on-chain is WebAuthn, but for *simulation* the inner
    // PartialAuthenticatorAssertionResponse is allowed to be all zeros: the
    // simulator never actually verifies the signature, and a 64-byte zero
    // payload with the variant tag and length prefix has the same shape as
    // the live signature.
    match variant {
        0..=2 => {
            let mut out = Vec::with_capacity(1 + 1 + 64);
            out.push(variant);
            out.push(64);
            out.extend(std::iter::repeat_n(0u8, 64));
            Some(out)
        }
        _ => None,
    }
}

/// Parses a `BCS(MultiKeyPublicKey)` blob into its variant tags and threshold.
///
/// Wire layout: `num_keys || (variant || ULEB128(len) || bytes) * n || threshold`.
#[cfg(feature = "ed25519")]
fn parse_multi_key_pubkey(bytes: &[u8]) -> AptosResult<(Vec<u8>, u8)> {
    if bytes.is_empty() {
        return Err(crate::error::AptosError::transaction(
            "simulate(): MultiKey public_key_bytes is empty",
        ));
    }
    let num_keys = bytes[0] as usize;
    let mut offset = 1;
    let mut variants = Vec::with_capacity(num_keys);
    for _ in 0..num_keys {
        if offset >= bytes.len() {
            return Err(crate::error::AptosError::transaction(
                "simulate(): MultiKey public_key truncated at variant tag",
            ));
        }
        let variant = bytes[offset];
        variants.push(variant);
        offset += 1;
        // ULEB128(len)
        let (len, len_bytes) = decode_uleb128_internal(&bytes[offset..])?;
        offset += len_bytes;
        offset = offset.checked_add(len).ok_or_else(|| {
            crate::error::AptosError::transaction("simulate(): MultiKey public_key overflow")
        })?;
        if offset > bytes.len() {
            return Err(crate::error::AptosError::transaction(
                "simulate(): MultiKey public_key truncated at key bytes",
            ));
        }
    }
    if offset >= bytes.len() {
        return Err(crate::error::AptosError::transaction(
            "simulate(): MultiKey public_key missing threshold byte",
        ));
    }
    let threshold = bytes[offset];
    Ok((variants, threshold))
}

/// Minimal ULEB128 decoder local to the simulation helper.
#[cfg(feature = "ed25519")]
fn decode_uleb128_internal(bytes: &[u8]) -> AptosResult<(usize, usize)> {
    let mut value: usize = 0;
    let mut shift = 0;
    for (i, &b) in bytes.iter().enumerate() {
        value |= ((b & 0x7F) as usize) << shift;
        if (b & 0x80) == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            break;
        }
    }
    Err(crate::error::AptosError::transaction(
        "simulate(): malformed ULEB128 in public key",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::authenticator::{
        Ed25519PublicKey, Ed25519Signature, TransactionAuthenticator,
    };
    use crate::transaction::payload::{EntryFunction, TransactionPayload};
    use crate::transaction::simulation::SimulateQueryOptions;
    use crate::transaction::types::{RawTransaction, SignedTransaction};
    use crate::types::ChainId;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, path_regex},
    };

    #[test]
    fn test_aptos_client_creation() {
        let aptos = Aptos::testnet();
        assert!(aptos.is_ok());
    }

    #[test]
    fn test_chain_id() {
        let aptos = Aptos::testnet().unwrap();
        assert_eq!(aptos.chain_id(), ChainId::testnet());

        let aptos = Aptos::mainnet().unwrap();
        assert_eq!(aptos.chain_id(), ChainId::mainnet());
    }

    fn create_mock_aptos(server: &MockServer) -> Aptos {
        let url = format!("{}/v1", server.uri());
        let config = AptosConfig::custom(&url).unwrap().without_retry();
        Aptos::new(config).unwrap()
    }

    #[tokio::test]
    async fn test_get_sequence_number() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/v1/accounts/0x[0-9a-f]+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sequence_number": "42",
                "authentication_key": "0x0000000000000000000000000000000000000000000000000000000000000001"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let aptos = create_mock_aptos(&server);
        let seq = aptos
            .get_sequence_number(AccountAddress::ONE)
            .await
            .unwrap();
        assert_eq!(seq, 42);
    }

    #[tokio::test]
    async fn test_get_balance() {
        let server = MockServer::start().await;

        // get_balance now uses view function instead of CoinStore resource
        Mock::given(method("POST"))
            .and(path("/v1/view"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!(["5000000000"])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let aptos = create_mock_aptos(&server);
        let balance = aptos.get_balance(AccountAddress::ONE).await.unwrap();
        assert_eq!(balance, 5_000_000_000);
    }

    #[tokio::test]
    async fn test_get_resources_via_fullnode() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/v1/accounts/0x[0-9a-f]+/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"type": "0x1::account::Account", "data": {}},
                {"type": "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>", "data": {}}
            ])))
            .expect(1)
            .mount(&server)
            .await;

        let aptos = create_mock_aptos(&server);
        let resources = aptos
            .fullnode()
            .get_account_resources(AccountAddress::ONE)
            .await
            .unwrap();
        assert_eq!(resources.data.len(), 2);
    }

    #[tokio::test]
    async fn test_ledger_info() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "chain_id": 2,
                "epoch": "100",
                "ledger_version": "12345",
                "oldest_ledger_version": "0",
                "ledger_timestamp": "1000000",
                "node_role": "full_node",
                "oldest_block_height": "0",
                "block_height": "5000"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let aptos = create_mock_aptos(&server);
        let info = aptos.ledger_info().await.unwrap();
        assert_eq!(info.version().unwrap(), 12345);
    }

    #[tokio::test]
    async fn test_config_builder() {
        let config = AptosConfig::testnet().with_timeout(Duration::from_mins(1));

        let aptos = Aptos::new(config).unwrap();
        assert_eq!(aptos.chain_id(), ChainId::testnet());
    }

    #[tokio::test]
    async fn test_fullnode_accessor() {
        let server = MockServer::start().await;
        let aptos = create_mock_aptos(&server);

        // Can access fullnode client directly
        let fullnode = aptos.fullnode();
        assert!(fullnode.base_url().as_str().contains(&server.uri()));
    }

    #[cfg(feature = "ed25519")]
    #[tokio::test]
    async fn test_build_transaction() {
        let server = MockServer::start().await;

        // Mock for getting account
        Mock::given(method("GET"))
            .and(path_regex(r"/v1/accounts/0x[0-9a-f]+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sequence_number": "0",
                "authentication_key": "0x0000000000000000000000000000000000000000000000000000000000000001"
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Mock for gas price
        Mock::given(method("GET"))
            .and(path("/v1/estimate_gas_price"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "gas_estimate": 100
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Mock for ledger info (needed for chain_id resolution on custom networks)
        Mock::given(method("GET"))
            .and(path("/v1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "chain_id": 4,
                "epoch": "1",
                "ledger_version": "100",
                "oldest_ledger_version": "0",
                "ledger_timestamp": "1000000",
                "node_role": "full_node",
                "oldest_block_height": "0",
                "block_height": "50"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let aptos = create_mock_aptos(&server);
        let account = crate::account::Ed25519Account::generate();
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let payload = crate::transaction::EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let raw_txn = aptos
            .build_transaction(&account, payload.into())
            .await
            .unwrap();
        assert_eq!(raw_txn.sender, account.address());
        assert_eq!(raw_txn.sequence_number, 0);
    }

    #[cfg(feature = "indexer")]
    #[tokio::test]
    async fn test_indexer_accessor() {
        let aptos = Aptos::testnet().unwrap();
        let indexer = aptos.indexer();
        assert!(indexer.is_some());
    }

    #[tokio::test]
    async fn test_account_exists_true() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"^/v1/accounts/0x[0-9a-f]+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sequence_number": "10",
                "authentication_key": "0x0000000000000000000000000000000000000000000000000000000000000001"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let aptos = create_mock_aptos(&server);
        let exists = aptos.account_exists(AccountAddress::ONE).await.unwrap();
        assert!(exists);
    }

    #[tokio::test]
    async fn test_account_exists_false() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"^/v1/accounts/0x[0-9a-f]+$"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "Account not found",
                "error_code": "account_not_found"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let aptos = create_mock_aptos(&server);
        let exists = aptos.account_exists(AccountAddress::ONE).await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn test_view_function() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/view"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(["1000000"])))
            .expect(1)
            .mount(&server)
            .await;

        let aptos = create_mock_aptos(&server);
        let result: Vec<serde_json::Value> = aptos
            .view(
                "0x1::coin::balance",
                vec!["0x1::aptos_coin::AptosCoin".to_string()],
                vec![serde_json::json!("0x1")],
            )
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].as_str().unwrap(), "1000000");
    }

    #[tokio::test]
    async fn test_chain_id_from_config() {
        let aptos = Aptos::mainnet().unwrap();
        assert_eq!(aptos.chain_id(), ChainId::mainnet());

        // Devnet's chain ID is intentionally reported as 0 (unknown) at
        // construction time -- the value is reset whenever devnet itself
        // is reset, so any hardcoded value would go stale. The Aptos client
        // populates the live chain ID lazily via `ensure_chain_id`, which is
        // exercised on the network and not in this offline unit test.
        let aptos = Aptos::devnet().unwrap();
        assert_eq!(aptos.chain_id(), ChainId::new(0));
    }

    #[tokio::test]
    async fn test_custom_config() {
        let server = MockServer::start().await;
        let url = format!("{}/v1", server.uri());
        let config = AptosConfig::custom(&url).unwrap();
        let aptos = Aptos::new(config).unwrap();

        // Custom config should have unknown chain ID
        assert_eq!(aptos.chain_id(), ChainId::new(0));
    }

    // ---------------------------------------------------------------
    // build_zero_signed_authenticator: cover every signature scheme
    // the SDK can sign for and confirm the helper does NOT fall back to
    // the Ed25519 path for non-Ed25519 accounts. This was the subject
    // of a Copilot review comment and now has explicit regression
    // coverage.
    // ---------------------------------------------------------------

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_zero_signed_authenticator_ed25519() {
        use crate::account::Ed25519Account;
        use crate::transaction::TransactionAuthenticator;

        let account = Ed25519Account::generate();
        let auth = super::build_zero_signed_authenticator(&account).unwrap();
        match auth {
            TransactionAuthenticator::Ed25519 {
                public_key,
                signature,
            } => {
                assert_eq!(public_key.0, account.public_key().to_bytes());
                assert_eq!(signature.0, [0u8; 64]);
            }
            other => panic!("expected TransactionAuthenticator::Ed25519, got {other:?}"),
        }
    }

    #[cfg(all(feature = "ed25519", feature = "secp256k1"))]
    #[test]
    fn test_zero_signed_authenticator_single_key_secp256k1() {
        use crate::account::Secp256k1Account;
        use crate::transaction::TransactionAuthenticator;
        use crate::transaction::authenticator::AccountAuthenticator;

        let account = Secp256k1Account::generate();
        let auth = super::build_zero_signed_authenticator(&account).unwrap();
        // Secp256k1Account is a SingleKey, so it must wrap in SingleSender +
        // SingleKey. No Ed25519 variant must appear anywhere.
        let TransactionAuthenticator::SingleSender { sender } = auth else {
            panic!("expected SingleSender, got {auth:?}");
        };
        let AccountAuthenticator::SingleKey {
            public_key,
            signature,
        } = sender
        else {
            panic!("expected AccountAuthenticator::SingleKey");
        };
        // Public key bytes are passed through unchanged.
        assert_eq!(public_key, account.public_key_bytes());
        // Signature is a zeroed BCS-encoded `AnySignature::Secp256k1Ecdsa`
        // (variant=1, len=64, 64 zero bytes).
        assert_eq!(signature.len(), 1 + 1 + 64);
        assert_eq!(signature[0], 0x01, "variant tag must match secp256k1");
        assert_eq!(signature[1], 64, "ULEB128(64)");
        assert!(signature[2..].iter().all(|b| *b == 0), "all-zero signature");
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_zero_signed_authenticator_single_key_ed25519() {
        use crate::account::Ed25519SingleKeyAccount;
        use crate::transaction::TransactionAuthenticator;
        use crate::transaction::authenticator::AccountAuthenticator;

        // Ed25519SingleKeyAccount uses scheme SINGLE_KEY_SCHEME and exposes
        // `public_key_bytes` as BCS(AnyPublicKey::Ed25519), not the raw 32-byte
        // pubkey, so the previous Ed25519-only fast path would have rejected
        // this account.
        let account = Ed25519SingleKeyAccount::generate();
        let auth = super::build_zero_signed_authenticator(&account).unwrap();
        let TransactionAuthenticator::SingleSender { sender } = auth else {
            panic!("expected SingleSender for Ed25519SingleKey, got {auth:?}");
        };
        let AccountAuthenticator::SingleKey {
            public_key,
            signature,
        } = sender
        else {
            panic!("expected AccountAuthenticator::SingleKey");
        };
        assert_eq!(public_key, account.public_key_bytes());
        assert_eq!(signature[0], 0x00, "AnySignature::Ed25519 variant");
        assert_eq!(signature[1], 64, "ULEB128(64)");
        assert!(signature[2..].iter().all(|b| *b == 0));
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_zero_signed_authenticator_multi_ed25519() {
        use crate::account::MultiEd25519Account;
        use crate::crypto::Ed25519PrivateKey;
        use crate::transaction::TransactionAuthenticator;

        // 2-of-3 multi-ed25519.
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let account = MultiEd25519Account::new(keys, 2).unwrap();
        let auth = super::build_zero_signed_authenticator(&account).unwrap();
        let TransactionAuthenticator::MultiEd25519 {
            public_key,
            signature,
        } = auth
        else {
            panic!("expected MultiEd25519, got {auth:?}");
        };
        assert_eq!(public_key, account.public_key_bytes());
        // signature = 2 * 64 zero bytes + 4-byte bitmap, MSB-first bits 0+1 set.
        assert_eq!(signature.len(), 2 * 64 + 4);
        assert!(signature[..128].iter().all(|b| *b == 0));
        assert_eq!(signature[128], 0b1100_0000, "bits 0 and 1 set (MSB-first)");
        assert_eq!(&signature[129..], &[0u8, 0u8, 0u8]);
    }

    #[cfg(all(feature = "ed25519", feature = "secp256k1"))]
    #[test]
    fn test_zero_signed_authenticator_multi_key() {
        use crate::account::{AnyPrivateKey, MultiKeyAccount};
        use crate::crypto::{Ed25519PrivateKey, Secp256k1PrivateKey};
        use crate::transaction::TransactionAuthenticator;
        use crate::transaction::authenticator::AccountAuthenticator;

        let keys = vec![
            AnyPrivateKey::ed25519(Ed25519PrivateKey::generate()),
            AnyPrivateKey::secp256k1(Secp256k1PrivateKey::generate()),
            AnyPrivateKey::ed25519(Ed25519PrivateKey::generate()),
        ];
        let account = MultiKeyAccount::new(keys, 2).unwrap();
        let auth = super::build_zero_signed_authenticator(&account).unwrap();
        let TransactionAuthenticator::SingleSender { sender } = auth else {
            panic!("expected SingleSender for MultiKey, got {auth:?}");
        };
        let AccountAuthenticator::MultiKey {
            public_key,
            signature,
        } = sender
        else {
            panic!("expected AccountAuthenticator::MultiKey");
        };
        assert_eq!(public_key, account.public_key_bytes());
        // signature = ULEB128(2) || two zero AnySignatures || ULEB128(4) || 4-byte bitmap.
        // First zero AnySignature is for the Ed25519 key at index 0 (variant 0).
        // Second is for the Secp256k1 key at index 1 (variant 1).
        // No reason for them to share variants; this regression-guards
        // the bug-prone assumption that all single-key accounts are Ed25519.
        assert_eq!(signature[0], 2, "num_sigs ULEB128");
        assert_eq!(signature[1], 0x00, "first AnySignature variant (Ed25519)");
        assert_eq!(
            signature[1 + 1 + 1 + 64],
            0x01,
            "second AnySignature variant (Secp256k1)"
        );
    }

    #[tokio::test]
    async fn test_simulate_signed_with_options() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/transactions/simulate"))
            .and(|req: &wiremock::Request| {
                req.url
                    .query()
                    .is_some_and(|q| q.contains("estimate_gas_unit_price=true"))
            })
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "success": true,
                    "vm_status": "Executed successfully",
                    "gas_used": "1500",
                    "max_gas_amount": "200000",
                    "gas_unit_price": "100",
                    "hash": "0xabc",
                    "changes": [],
                    "events": []
                }])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let raw = RawTransaction::new(
            AccountAddress::ONE,
            0,
            TransactionPayload::EntryFunction(
                EntryFunction::apt_transfer(AccountAddress::ONE, 0).unwrap(),
            ),
            100_000,
            100,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .saturating_add(600),
            ChainId::testnet(),
        );
        let signed = SignedTransaction::new(
            raw,
            TransactionAuthenticator::Ed25519 {
                public_key: Ed25519PublicKey([0u8; 32]),
                signature: Ed25519Signature([0u8; 64]),
            },
        );

        let aptos = create_mock_aptos(&server);
        let options = SimulateQueryOptions::new().estimate_gas_unit_price(true);
        let result = aptos
            .simulate_signed_with_options(&signed, options)
            .await
            .unwrap();

        assert!(result.success());
        assert_eq!(result.gas_used(), 1500);
        assert_eq!(result.gas_unit_price(), 100);
    }
}
