//! Fullnode REST API client.

use crate::api::response::{
    AccountData, AptosResponse, GasEstimation, LedgerInfo, MoveModule, PendingTransaction, Resource,
};
use crate::config::AptosConfig;
use crate::error::{AptosError, AptosResult};
use crate::retry::{RetryConfig, RetryExecutor};
use crate::transaction::types::SignedTransaction;
use crate::types::{AccountAddress, HashValue};
use reqwest::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

const BCS_CONTENT_TYPE: &str = "application/x.aptos.signed_transaction+bcs";
const BCS_VIEW_CONTENT_TYPE: &str = "application/x-bcs";
const JSON_CONTENT_TYPE: &str = "application/json";
/// Default timeout for waiting for a transaction to be committed.
const DEFAULT_TRANSACTION_WAIT_TIMEOUT_SECS: u64 = 30;
/// Maximum size for error response bodies (8 KB).
///
/// # Security
///
/// This prevents memory exhaustion from malicious servers sending extremely
/// large error response bodies.
const MAX_ERROR_BODY_SIZE: usize = 8 * 1024;

/// Client for the Aptos fullnode REST API.
///
/// The client supports automatic retry with exponential backoff for transient
/// failures. Configure retry behavior via [`AptosConfig::with_retry`].
///
/// # Example
///
/// ```rust,no_run
/// use aptos_sdk::api::FullnodeClient;
/// use aptos_sdk::config::AptosConfig;
/// use aptos_sdk::retry::RetryConfig;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     // Default retry configuration
///     let client = FullnodeClient::new(AptosConfig::testnet())?;
///     
///     // Aggressive retry for unstable networks
///     let client = FullnodeClient::new(
///         AptosConfig::testnet().with_retry(RetryConfig::aggressive())
///     )?;
///     
///     // Disable retry for debugging
///     let client = FullnodeClient::new(
///         AptosConfig::testnet().without_retry()
///     )?;
///     
///     let ledger_info = client.get_ledger_info().await?;
///     println!("Ledger version: {:?}", ledger_info.data.version());
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct FullnodeClient {
    config: AptosConfig,
    client: Client,
    retry_config: Arc<RetryConfig>,
}

impl FullnodeClient {
    /// Creates a new fullnode client.
    ///
    /// # TLS Security
    ///
    /// This client uses `reqwest` with its default TLS configuration, which:
    /// - Validates server certificates against the system's certificate store
    /// - Requires valid TLS certificates for HTTPS connections
    /// - Uses secure TLS versions (TLS 1.2+)
    ///
    /// All Aptos network endpoints (mainnet, testnet, devnet) use HTTPS with
    /// valid certificates. The local configuration uses HTTP for development.
    ///
    /// For custom deployments requiring custom CA certificates, use the
    /// `REQUESTS_CA_BUNDLE` or `SSL_CERT_FILE` environment variables, or
    /// configure a custom `reqwest::Client` and use `from_client()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client fails to build (e.g., invalid TLS configuration).
    pub fn new(config: AptosConfig) -> AptosResult<Self> {
        let pool = config.pool_config();

        // SECURITY: TLS certificate validation is enabled by default via reqwest.
        // The client will reject connections to servers with invalid certificates.
        // All production Aptos endpoints use HTTPS with valid certificates.
        let mut builder = Client::builder()
            .timeout(config.timeout)
            .pool_max_idle_per_host(pool.max_idle_per_host.unwrap_or(usize::MAX))
            .pool_idle_timeout(pool.idle_timeout)
            .tcp_nodelay(pool.tcp_nodelay);

        if let Some(keepalive) = pool.tcp_keepalive {
            builder = builder.tcp_keepalive(keepalive);
        }

        let client = builder.build().map_err(AptosError::Http)?;

        let retry_config = Arc::new(config.retry_config().clone());

        Ok(Self {
            config,
            client,
            retry_config,
        })
    }

    /// Returns the base URL for the fullnode.
    pub fn base_url(&self) -> &Url {
        self.config.fullnode_url()
    }

    /// Returns the retry configuration.
    pub fn retry_config(&self) -> &RetryConfig {
        &self.retry_config
    }

    // === Ledger Info ===

    /// Gets the current ledger information.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// or the response cannot be parsed as JSON.
    pub async fn get_ledger_info(&self) -> AptosResult<AptosResponse<LedgerInfo>> {
        let url = self.build_url("");
        self.get_json(url).await
    }

    // === Account ===

    /// Gets account information.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// the response cannot be parsed as JSON, or the account is not found (404).
    pub async fn get_account(
        &self,
        address: AccountAddress,
    ) -> AptosResult<AptosResponse<AccountData>> {
        let url = self.build_url(&format!("accounts/{address}"));
        self.get_json(url).await
    }

    /// Gets the sequence number for an account.
    ///
    /// # Errors
    ///
    /// Returns an error if fetching the account fails, the account is not found (404),
    /// or the sequence number cannot be parsed from the account data.
    pub async fn get_sequence_number(&self, address: AccountAddress) -> AptosResult<u64> {
        let account = self.get_account(address).await?;
        account
            .data
            .sequence_number()
            .map_err(|e| AptosError::Internal(format!("failed to parse sequence number: {e}")))
    }

    /// Gets all resources for an account.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// or the response cannot be parsed as JSON.
    pub async fn get_account_resources(
        &self,
        address: AccountAddress,
    ) -> AptosResult<AptosResponse<Vec<Resource>>> {
        let url = self.build_url(&format!("accounts/{address}/resources"));
        self.get_json(url).await
    }

    /// Gets a specific resource for an account.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// the response cannot be parsed as JSON, or the resource is not found (404).
    pub async fn get_account_resource(
        &self,
        address: AccountAddress,
        resource_type: &str,
    ) -> AptosResult<AptosResponse<Resource>> {
        let url = self.build_url(&format!(
            "accounts/{}/resource/{}",
            address,
            urlencoding::encode(resource_type)
        ));
        self.get_json(url).await
    }

    /// Gets all modules for an account.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// or the response cannot be parsed as JSON.
    pub async fn get_account_modules(
        &self,
        address: AccountAddress,
    ) -> AptosResult<AptosResponse<Vec<MoveModule>>> {
        let url = self.build_url(&format!("accounts/{address}/modules"));
        self.get_json(url).await
    }

    /// Gets a specific module for an account.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// the response cannot be parsed as JSON, or the module is not found (404).
    pub async fn get_account_module(
        &self,
        address: AccountAddress,
        module_name: &str,
    ) -> AptosResult<AptosResponse<MoveModule>> {
        let url = self.build_url(&format!("accounts/{address}/module/{module_name}"));
        self.get_json(url).await
    }

    // === Balance ===

    /// Gets the APT balance for an account in octas.
    ///
    /// # Errors
    ///
    /// Returns an error if the view function call fails, the response cannot be parsed,
    /// or the balance value cannot be converted to u64.
    pub async fn get_account_balance(&self, address: AccountAddress) -> AptosResult<u64> {
        // Use the coin::balance view function which works with both legacy CoinStore
        // and the newer Fungible Asset standard
        let result = self
            .view(
                "0x1::coin::balance",
                vec!["0x1::aptos_coin::AptosCoin".to_string()],
                vec![serde_json::json!(address.to_string())],
            )
            .await?;

        // The view function returns an array with a single string value
        let balance_str = result
            .data
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| AptosError::Internal("failed to parse balance response".into()))?;

        balance_str
            .parse()
            .map_err(|_| AptosError::Internal("failed to parse balance as u64".into()))
    }

    // === Transactions ===

    /// Submits a signed transaction.
    ///
    /// Note: Transaction submission is automatically retried for transient errors.
    /// Duplicate transaction submissions (same hash) are safe and idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be serialized to BCS, the HTTP request fails,
    /// the API returns an error status code, or the response cannot be parsed as JSON.
    pub async fn submit_transaction(
        &self,
        signed_txn: &SignedTransaction,
    ) -> AptosResult<AptosResponse<PendingTransaction>> {
        let url = self.build_url("transactions");
        let bcs_bytes = signed_txn.to_bcs()?;
        let client = self.client.clone();
        let retry_config = self.retry_config.clone();
        let max_response_size = self.config.pool_config().max_response_size;

        let executor = RetryExecutor::from_shared(retry_config);
        executor
            .execute(|| {
                let client = client.clone();
                let url = url.clone();
                let bcs_bytes = bcs_bytes.clone();
                async move {
                    let response = client
                        .post(url)
                        .header(CONTENT_TYPE, BCS_CONTENT_TYPE)
                        .header(ACCEPT, JSON_CONTENT_TYPE)
                        .body(bcs_bytes)
                        .send()
                        .await?;

                    Self::handle_response_static(response, max_response_size).await
                }
            })
            .await
    }

    /// Submits a transaction and waits for it to be committed.
    ///
    /// # Errors
    ///
    /// Returns an error if transaction submission fails, the transaction times out waiting
    /// for commitment, the transaction execution fails, or any HTTP/API errors occur.
    pub async fn submit_and_wait(
        &self,
        signed_txn: &SignedTransaction,
        timeout: Option<Duration>,
    ) -> AptosResult<AptosResponse<serde_json::Value>> {
        let pending = self.submit_transaction(signed_txn).await?;
        self.wait_for_transaction(&pending.data.hash, timeout).await
    }

    /// Gets a transaction by hash.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// the response cannot be parsed as JSON, or the transaction is not found (404).
    pub async fn get_transaction_by_hash(
        &self,
        hash: &HashValue,
    ) -> AptosResult<AptosResponse<serde_json::Value>> {
        let url = self.build_url(&format!("transactions/by_hash/{hash}"));
        self.get_json(url).await
    }

    /// Waits for a transaction to be committed.
    ///
    /// Uses exponential backoff for polling, starting at 200ms and doubling up to 2s.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction times out waiting for commitment, the transaction
    /// execution fails (`vm_status` indicates failure), or HTTP/API errors occur while polling.
    pub async fn wait_for_transaction(
        &self,
        hash: &HashValue,
        timeout: Option<Duration>,
    ) -> AptosResult<AptosResponse<serde_json::Value>> {
        let timeout = timeout.unwrap_or(Duration::from_secs(DEFAULT_TRANSACTION_WAIT_TIMEOUT_SECS));
        let start = std::time::Instant::now();

        // Exponential backoff: start at 200ms, double each time, max 2s
        let initial_interval = Duration::from_millis(200);
        let max_interval = Duration::from_secs(2);
        let mut current_interval = initial_interval;

        loop {
            match self.get_transaction_by_hash(hash).await {
                Ok(response) => {
                    // Check if transaction is committed (has version)
                    if response.data.get("version").is_some() {
                        // Check success
                        let success = response
                            .data
                            .get("success")
                            .and_then(serde_json::Value::as_bool);
                        if success == Some(false) {
                            let vm_status = response
                                .data
                                .get("vm_status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            return Err(AptosError::ExecutionFailed { vm_status });
                        }
                        return Ok(response);
                    }
                }
                Err(AptosError::Api {
                    status_code: 404, ..
                }) => {
                    // Transaction not found yet, continue waiting
                }
                Err(e) => return Err(e),
            }

            if start.elapsed() >= timeout {
                return Err(AptosError::TransactionTimeout {
                    hash: hash.to_string(),
                    timeout_secs: timeout.as_secs(),
                });
            }

            tokio::time::sleep(current_interval).await;

            // Exponential backoff with cap
            current_interval = std::cmp::min(current_interval * 2, max_interval);
        }
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
        let url = self.build_url("transactions/simulate");
        let bcs_bytes = signed_txn.to_bcs()?;
        let client = self.client.clone();
        let retry_config = self.retry_config.clone();
        let max_response_size = self.config.pool_config().max_response_size;

        let executor = RetryExecutor::from_shared(retry_config);
        executor
            .execute(|| {
                let client = client.clone();
                let url = url.clone();
                let bcs_bytes = bcs_bytes.clone();
                async move {
                    let response = client
                        .post(url)
                        .header(CONTENT_TYPE, BCS_CONTENT_TYPE)
                        .header(ACCEPT, JSON_CONTENT_TYPE)
                        .body(bcs_bytes)
                        .send()
                        .await?;

                    Self::handle_response_static(response, max_response_size).await
                }
            })
            .await
    }

    // === Gas ===

    /// Gets the current gas estimation.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// or the response cannot be parsed as JSON.
    pub async fn estimate_gas_price(&self) -> AptosResult<AptosResponse<GasEstimation>> {
        let url = self.build_url("estimate_gas_price");
        self.get_json(url).await
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
    ) -> AptosResult<AptosResponse<Vec<serde_json::Value>>> {
        let url = self.build_url("view");

        let body = serde_json::json!({
            "function": function,
            "type_arguments": type_args,
            "arguments": args,
        });

        let client = self.client.clone();
        let retry_config = self.retry_config.clone();
        let max_response_size = self.config.pool_config().max_response_size;

        let executor = RetryExecutor::from_shared(retry_config);
        executor
            .execute(|| {
                let client = client.clone();
                let url = url.clone();
                let body = body.clone();
                async move {
                    let response = client
                        .post(url)
                        .header(CONTENT_TYPE, JSON_CONTENT_TYPE)
                        .header(ACCEPT, JSON_CONTENT_TYPE)
                        .json(&body)
                        .send()
                        .await?;

                    Self::handle_response_static(response, max_response_size).await
                }
            })
            .await
    }

    /// Calls a view function using BCS encoding for both inputs and outputs.
    ///
    /// This method provides lossless serialization by using BCS (Binary Canonical Serialization)
    /// instead of JSON, which is important for large integers (u128, u256) and other types
    /// where JSON can lose precision.
    ///
    /// # Arguments
    ///
    /// * `function` - The fully qualified function name (e.g., `0x1::coin::balance`)
    /// * `type_args` - Type arguments as strings (e.g., `0x1::aptos_coin::AptosCoin`)
    /// * `args` - Pre-serialized BCS arguments as byte vectors
    ///
    /// # Returns
    ///
    /// Returns the raw BCS-encoded response bytes, which can be deserialized
    /// into the expected return type using `aptos_bcs::from_bytes`.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// or the BCS serialization fails.
    pub async fn view_bcs(
        &self,
        function: &str,
        type_args: Vec<String>,
        args: Vec<Vec<u8>>,
    ) -> AptosResult<AptosResponse<Vec<u8>>> {
        let url = self.build_url("view");

        // Convert BCS args to hex strings for the JSON request body.
        // The Aptos API accepts hex-encoded BCS bytes in the arguments array.
        let hex_args: Vec<serde_json::Value> = args
            .iter()
            .map(|bytes| serde_json::json!(format!("0x{}", hex::encode(bytes))))
            .collect();

        let body = serde_json::json!({
            "function": function,
            "type_arguments": type_args,
            "arguments": hex_args,
        });

        let client = self.client.clone();
        let retry_config = self.retry_config.clone();
        let max_response_size = self.config.pool_config().max_response_size;

        let executor = RetryExecutor::from_shared(retry_config);
        executor
            .execute(|| {
                let client = client.clone();
                let url = url.clone();
                let body = body.clone();
                async move {
                    let response = client
                        .post(url)
                        .header(CONTENT_TYPE, JSON_CONTENT_TYPE)
                        .header(ACCEPT, BCS_VIEW_CONTENT_TYPE)
                        .json(&body)
                        .send()
                        .await?;

                    // Check for errors before reading body
                    let status = response.status();
                    if !status.is_success() {
                        // SECURITY: Truncate error body to prevent storing excessively
                        // large error messages from malicious servers
                        let error_text =
                            Self::truncate_error_body(response.text().await.unwrap_or_default());
                        return Err(AptosError::Api {
                            status_code: status.as_u16(),
                            message: error_text,
                            error_code: None,
                            vm_error_code: None,
                        });
                    }

                    // SECURITY: Stream body with size limit to prevent OOM
                    // from malicious responses (including chunked encoding).
                    let bytes =
                        crate::config::read_response_bounded(response, max_response_size).await?;
                    Ok(AptosResponse::new(bytes))
                }
            })
            .await
    }

    // === Events ===

    /// Gets events by event handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// or the response cannot be parsed as JSON.
    pub async fn get_events_by_event_handle(
        &self,
        address: AccountAddress,
        event_handle_struct: &str,
        field_name: &str,
        start: Option<u64>,
        limit: Option<u64>,
    ) -> AptosResult<AptosResponse<Vec<serde_json::Value>>> {
        let mut url = self.build_url(&format!(
            "accounts/{}/events/{}/{}",
            address,
            urlencoding::encode(event_handle_struct),
            field_name
        ));

        {
            let mut query = url.query_pairs_mut();
            if let Some(start) = start {
                query.append_pair("start", &start.to_string());
            }
            if let Some(limit) = limit {
                query.append_pair("limit", &limit.to_string());
            }
        }

        self.get_json(url).await
    }

    // === Blocks ===

    /// Gets block by height.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// the response cannot be parsed as JSON, or the block is not found (404).
    pub async fn get_block_by_height(
        &self,
        height: u64,
        with_transactions: bool,
    ) -> AptosResult<AptosResponse<serde_json::Value>> {
        let mut url = self.build_url(&format!("blocks/by_height/{height}"));
        url.query_pairs_mut()
            .append_pair("with_transactions", &with_transactions.to_string());
        self.get_json(url).await
    }

    /// Gets block by version.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the API returns an error status code,
    /// the response cannot be parsed as JSON, or the block is not found (404).
    pub async fn get_block_by_version(
        &self,
        version: u64,
        with_transactions: bool,
    ) -> AptosResult<AptosResponse<serde_json::Value>> {
        let mut url = self.build_url(&format!("blocks/by_version/{version}"));
        url.query_pairs_mut()
            .append_pair("with_transactions", &with_transactions.to_string());
        self.get_json(url).await
    }

    // === Helper Methods ===

    fn build_url(&self, path: &str) -> Url {
        let mut url = self.config.fullnode_url().clone();
        if !path.is_empty() {
            // Avoid format! allocations by building the path string manually
            let base_path = url.path();
            let needs_slash = !base_path.ends_with('/');
            let new_len = base_path.len() + path.len() + usize::from(needs_slash);
            let mut new_path = String::with_capacity(new_len);
            new_path.push_str(base_path);
            if needs_slash {
                new_path.push('/');
            }
            new_path.push_str(path);
            url.set_path(&new_path);
        }
        url
    }

    async fn get_json<T: for<'de> serde::Deserialize<'de>>(
        &self,
        url: Url,
    ) -> AptosResult<AptosResponse<T>> {
        let client = self.client.clone();
        let url_clone = url.clone();
        let retry_config = self.retry_config.clone();
        let max_response_size = self.config.pool_config().max_response_size;

        let executor = RetryExecutor::from_shared(retry_config);
        executor
            .execute(|| {
                let client = client.clone();
                let url = url_clone.clone();
                async move {
                    let response = client
                        .get(url)
                        .header(ACCEPT, JSON_CONTENT_TYPE)
                        .send()
                        .await?;

                    Self::handle_response_static(response, max_response_size).await
                }
            })
            .await
    }

    /// Truncates a string to the maximum error body size.
    ///
    /// # Security
    ///
    /// Prevents storing extremely large error messages from malicious servers.
    fn truncate_error_body(body: String) -> String {
        if body.len() > MAX_ERROR_BODY_SIZE {
            // Find the last valid UTF-8 char boundary at or before the limit
            let mut end = MAX_ERROR_BODY_SIZE;
            while end > 0 && !body.is_char_boundary(end) {
                end -= 1;
            }
            format!(
                "{}... [truncated, total: {} bytes]",
                &body[..end],
                body.len()
            )
        } else {
            body
        }
    }

    /// Handles an HTTP response without retry (for internal use).
    ///
    /// # Security
    ///
    /// This method enforces `max_response_size` on the actual response body,
    /// not just the Content-Length header, to prevent memory exhaustion even
    /// when the server uses chunked transfer encoding.
    async fn handle_response_static<T: for<'de> serde::Deserialize<'de>>(
        response: reqwest::Response,
        max_response_size: usize,
    ) -> AptosResult<AptosResponse<T>> {
        let status = response.status();

        // Extract headers before consuming response body
        let ledger_version = response
            .headers()
            .get("x-aptos-ledger-version")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let ledger_timestamp = response
            .headers()
            .get("x-aptos-ledger-timestamp")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let epoch = response
            .headers()
            .get("x-aptos-epoch")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let block_height = response
            .headers()
            .get("x-aptos-block-height")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let oldest_ledger_version = response
            .headers()
            .get("x-aptos-oldest-ledger-version")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let cursor = response
            .headers()
            .get("x-aptos-cursor")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);

        // Extract Retry-After header for rate limiting (before consuming body)
        let retry_after_secs = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());

        if status.is_success() {
            // SECURITY: Stream body with size limit to prevent OOM
            // from malicious responses (including chunked encoding).
            let bytes = crate::config::read_response_bounded(response, max_response_size).await?;
            let data: T = serde_json::from_slice(&bytes)?;
            Ok(AptosResponse {
                data,
                ledger_version,
                ledger_timestamp,
                epoch,
                block_height,
                oldest_ledger_version,
                cursor,
            })
        } else if status.as_u16() == 429 {
            // SECURITY: Return specific RateLimited error with Retry-After info
            // This allows callers to respect the server's rate limiting
            Err(AptosError::RateLimited { retry_after_secs })
        } else {
            // SECURITY: Truncate error body to prevent storing excessively
            // large error messages from malicious servers
            let error_text = Self::truncate_error_body(response.text().await.unwrap_or_default());
            let body: serde_json::Value = serde_json::from_str(&error_text).unwrap_or_default();
            let message = body
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error")
                .to_string();
            let error_code = body
                .get("error_code")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let vm_error_code = body
                .get("vm_error_code")
                .and_then(serde_json::Value::as_u64);

            Err(AptosError::api_with_details(
                status.as_u16(),
                message,
                error_code,
                vm_error_code,
            ))
        }
    }

    /// Legacy `handle_response` - delegates to static version.
    #[allow(dead_code)]
    async fn handle_response<T: for<'de> serde::Deserialize<'de>>(
        &self,
        response: reqwest::Response,
    ) -> AptosResult<AptosResponse<T>> {
        let max_response_size = self.config.pool_config().max_response_size;
        Self::handle_response_static(response, max_response_size).await
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
    fn test_build_url() {
        let client = FullnodeClient::new(AptosConfig::testnet()).unwrap();
        let url = client.build_url("accounts/0x1");
        assert!(url.as_str().contains("accounts/0x1"));
    }

    fn create_mock_client(server: &MockServer) -> FullnodeClient {
        // The mock server URL needs to include /v1 since that's part of the base URL
        let url = format!("{}/v1", server.uri());
        let config = AptosConfig::custom(&url).unwrap().without_retry();
        FullnodeClient::new(config).unwrap()
    }

    #[tokio::test]
    async fn test_get_ledger_info() {
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

        let client = create_mock_client(&server);
        let result = client.get_ledger_info().await.unwrap();

        assert_eq!(result.data.chain_id, 2);
        assert_eq!(result.data.version().unwrap(), 12345);
        assert_eq!(result.data.height().unwrap(), 5000);
    }

    #[tokio::test]
    async fn test_get_account() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"^/v1/accounts/0x[0-9a-f]+$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "sequence_number": "42",
                        "authentication_key": "0x0000000000000000000000000000000000000000000000000000000000000001"
                    }))
                    .insert_header("x-aptos-ledger-version", "12345"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let result = client.get_account(AccountAddress::ONE).await.unwrap();

        assert_eq!(result.data.sequence_number().unwrap(), 42);
        assert_eq!(result.ledger_version, Some(12345));
    }

    #[tokio::test]
    async fn test_get_account_not_found() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/v1/accounts/0x[0-9a-f]+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "Account not found",
                "error_code": "account_not_found"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let result = client.get_account(AccountAddress::ONE).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.is_not_found());
    }

    #[tokio::test]
    async fn test_get_account_resources() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/v1/accounts/0x[0-9a-f]+/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "type": "0x1::account::Account",
                    "data": {"sequence_number": "10"}
                },
                {
                    "type": "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
                    "data": {"coin": {"value": "1000000"}}
                }
            ])))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let result = client
            .get_account_resources(AccountAddress::ONE)
            .await
            .unwrap();

        assert_eq!(result.data.len(), 2);
        assert!(result.data[0].typ.contains("Account"));
    }

    #[tokio::test]
    async fn test_get_account_resource() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/v1/accounts/0x[0-9a-f]+/resource/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "type": "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
                "data": {"coin": {"value": "5000000"}}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let result = client
            .get_account_resource(
                AccountAddress::ONE,
                "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
            )
            .await
            .unwrap();

        assert!(result.data.typ.contains("CoinStore"));
    }

    #[tokio::test]
    async fn test_get_account_modules() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/v1/accounts/0x[0-9a-f]+/modules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "bytecode": "0xabc123",
                    "abi": {
                        "address": "0x1",
                        "name": "coin",
                        "exposed_functions": [],
                        "structs": []
                    }
                }
            ])))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let result = client
            .get_account_modules(AccountAddress::ONE)
            .await
            .unwrap();

        assert_eq!(result.data.len(), 1);
        assert!(result.data[0].abi.is_some());
    }

    #[tokio::test]
    async fn test_estimate_gas_price() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/estimate_gas_price"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "deprioritized_gas_estimate": 50,
                "gas_estimate": 100,
                "prioritized_gas_estimate": 150
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let result = client.estimate_gas_price().await.unwrap();

        assert_eq!(result.data.gas_estimate, 100);
        assert_eq!(result.data.low(), 50);
        assert_eq!(result.data.high(), 150);
    }

    #[tokio::test]
    async fn test_get_transaction_by_hash() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/v1/transactions/by_hash/0x[0-9a-f]+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "version": "12345",
                "hash": "0x0000000000000000000000000000000000000000000000000000000000000001",
                "success": true,
                "vm_status": "Executed successfully"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let hash = HashValue::from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let result = client.get_transaction_by_hash(&hash).await.unwrap();

        assert!(
            result
                .data
                .get("success")
                .and_then(serde_json::Value::as_bool)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_wait_for_transaction_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/v1/transactions/by_hash/0x[0-9a-f]+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "type": "user_transaction",
                "version": "12345",
                "hash": "0x0000000000000000000000000000000000000000000000000000000000000001",
                "success": true,
                "vm_status": "Executed successfully"
            })))
            .expect(1..)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let hash = HashValue::from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let result = client
            .wait_for_transaction(&hash, Some(Duration::from_secs(5)))
            .await
            .unwrap();

        assert!(
            result
                .data
                .get("success")
                .and_then(serde_json::Value::as_bool)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_server_error_retryable() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1"))
            .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
                "message": "Service temporarily unavailable"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let url = format!("{}/v1", server.uri());
        let config = AptosConfig::custom(&url).unwrap().without_retry();
        let client = FullnodeClient::new(config).unwrap();
        let result = client.get_ledger_info().await;

        assert!(result.is_err());
        assert!(result.unwrap_err().is_retryable());
    }

    #[tokio::test]
    async fn test_rate_limited() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1"))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_json(serde_json::json!({
                        "message": "Rate limited"
                    }))
                    .insert_header("retry-after", "30"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let url = format!("{}/v1", server.uri());
        let config = AptosConfig::custom(&url).unwrap().without_retry();
        let client = FullnodeClient::new(config).unwrap();
        let result = client.get_ledger_info().await;

        assert!(result.is_err());
        assert!(result.unwrap_err().is_retryable());
    }

    #[tokio::test]
    async fn test_get_block_by_height() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/v1/blocks/by_height/\d+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "block_height": "1000",
                "block_hash": "0xabc",
                "block_timestamp": "1234567890",
                "first_version": "100",
                "last_version": "200"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let result = client.get_block_by_height(1000, false).await.unwrap();

        assert!(result.data.get("block_height").is_some());
    }

    #[tokio::test]
    async fn test_view() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/view"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(["1000000"])))
            .expect(1)
            .mount(&server)
            .await;

        let client = create_mock_client(&server);
        let result: AptosResponse<Vec<serde_json::Value>> = client
            .view(
                "0x1::coin::balance",
                vec!["0x1::aptos_coin::AptosCoin".to_string()],
                vec![serde_json::json!("0x1")],
            )
            .await
            .unwrap();

        assert_eq!(result.data.len(), 1);
    }
}
