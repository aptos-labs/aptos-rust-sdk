//! Main Aptos client entry point.
//!
//! The [`Aptos`] struct provides a unified interface for all SDK functionality.

use crate::account::Account;
use crate::api::{AptosResponse, FullnodeClient, PendingTransaction};
use crate::config::AptosConfig;
use crate::error::{AptosError, AptosResult};
use crate::transaction::{
    RawTransaction, SignedTransaction, TransactionBuilder, TransactionPayload,
};
use crate::types::{AccountAddress, ChainId};
use std::sync::Arc;
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
/// use aptos_rust_sdk_v2::{Aptos, AptosConfig};
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

        Ok(Self {
            config,
            fullnode,
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
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// or the response cannot be parsed.
    pub async fn ledger_info(&self) -> AptosResult<crate::api::response::LedgerInfo> {
        let response = self.fullnode.get_ledger_info().await?;
        Ok(response.into_inner())
    }

    /// Returns the current chain ID.
    pub fn chain_id(&self) -> ChainId {
        self.config.chain_id()
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
        // Fetch sequence number and gas price in parallel - they're independent
        let (sequence_number, gas_estimation) = tokio::join!(
            self.get_sequence_number(sender.address()),
            self.fullnode.estimate_gas_price()
        );
        let sequence_number = sequence_number?;
        let gas_estimation = gas_estimation?;

        TransactionBuilder::new()
            .sender(sender.address())
            .sequence_number(sequence_number)
            .payload(payload)
            .gas_unit_price(gas_estimation.data.recommended())
            .chain_id(self.chain_id())
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
        let raw_txn = self.build_transaction(account, payload).await?;
        let signed = crate::transaction::builder::sign_transaction(&raw_txn, account)?;
        let response = self.fullnode.simulate_transaction(&signed).await?;
        crate::transaction::SimulationResult::from_response(response.into_inner())
    }

    /// Simulates a transaction with a pre-built signed transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if simulation fails or the simulation response cannot be parsed.
    pub async fn simulate_signed(
        &self,
        signed_txn: &SignedTransaction,
    ) -> AptosResult<crate::transaction::SimulationResult> {
        let response = self.fullnode.simulate_transaction(signed_txn).await?;
        crate::transaction::SimulationResult::from_response(response.into_inner())
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
        // First simulate
        let raw_txn = self.build_transaction(account, payload.clone()).await?;
        let signed = crate::transaction::builder::sign_transaction(&raw_txn, account)?;
        let sim_response = self.fullnode.simulate_transaction(&signed).await?;
        let sim_result =
            crate::transaction::SimulationResult::from_response(sim_response.into_inner())?;

        if sim_result.failed() {
            return Err(AptosError::SimulationFailed(
                sim_result
                    .error_message()
                    .unwrap_or_else(|| sim_result.vm_status().to_string()),
            ));
        }

        // Submit the same signed transaction
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
        // First simulate
        let raw_txn = self.build_transaction(account, payload.clone()).await?;
        let signed = crate::transaction::builder::sign_transaction(&raw_txn, account)?;
        let sim_response = self.fullnode.simulate_transaction(&signed).await?;
        let sim_result =
            crate::transaction::SimulationResult::from_response(sim_response.into_inner())?;

        if sim_result.failed() {
            return Err(AptosError::SimulationFailed(
                sim_result
                    .error_message()
                    .unwrap_or_else(|| sim_result.vm_status().to_string()),
            ));
        }

        // Submit and wait
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

    /// Calls a view function.
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

    // === Faucet ===

    /// Funds an account using the faucet.
    ///
    /// This method waits for the faucet transactions to be confirmed before returning.
    ///
    /// # Errors
    ///
    /// Returns an error if the faucet feature is not enabled, the faucet request fails
    /// (e.g., rate limiting 429, server error 500), waiting for transaction confirmation
    /// times out, or any HTTP/API errors occur.
    #[cfg(feature = "faucet")]
    pub async fn fund_account(
        &self,
        address: AccountAddress,
        amount: u64,
    ) -> AptosResult<Vec<String>> {
        let faucet = self
            .faucet
            .as_ref()
            .ok_or_else(|| AptosError::FeatureNotEnabled("faucet".into()))?;
        let txn_hashes = faucet.fund(address, amount).await?;

        // Parse hashes first to own them
        let hashes: Vec<HashValue> = txn_hashes
            .iter()
            .filter_map(|hash_str| {
                // Hash might have 0x prefix or not
                let hash_str_clean = hash_str.strip_prefix("0x").unwrap_or(hash_str);
                HashValue::from_hex(hash_str_clean).ok()
            })
            .collect();

        // Wait for all faucet transactions to be confirmed in parallel
        let wait_futures: Vec<_> = hashes
            .iter()
            .map(|hash| {
                self.fullnode
                    .wait_for_transaction(hash, Some(Duration::from_secs(60)))
            })
            .collect();

        // Wait for all transactions in parallel
        let results = futures::future::join_all(wait_futures).await;
        for result in results {
            result?;
        }

        Ok(txn_hashes)
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
        crate::transaction::BatchOperations::new(&self.fullnode, &self.config)
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

#[cfg(test)]
mod tests {
    use super::*;
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
        let config = AptosConfig::testnet().with_timeout(Duration::from_secs(60));

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

        let aptos = Aptos::devnet().unwrap();
        // Devnet uses chain_id 165
        assert_eq!(aptos.chain_id(), ChainId::new(165));
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
}
