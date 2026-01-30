//! GraphQL indexer client.
//!
//! This module provides a client for querying the Aptos Indexer GraphQL API.
//! The indexer provides access to indexed blockchain data including tokens,
//! events, transaction history, and more.
//!
//! # Example
//!
//! ```rust,no_run
//! use aptos_rust_sdk_v2::api::{IndexerClient, PaginationParams};
//! use aptos_rust_sdk_v2::config::AptosConfig;
//! use aptos_rust_sdk_v2::types::AccountAddress;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = IndexerClient::new(AptosConfig::testnet())?;
//!     
//!     // Get fungible asset balances
//!     let balances = client.get_fungible_asset_balances(AccountAddress::ONE).await?;
//!     
//!     // Get account tokens with pagination
//!     let tokens = client.get_account_tokens_paginated(
//!         AccountAddress::ONE,
//!         Some(PaginationParams { limit: 10, offset: 0 }),
//!     ).await?;
//!     
//!     Ok(())
//! }
//! ```

use crate::config::AptosConfig;
use crate::error::{AptosError, AptosResult};
use crate::retry::{RetryConfig, RetryExecutor};
use crate::types::AccountAddress;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use url::Url;

/// Client for the Aptos indexer GraphQL API.
///
/// The indexer provides access to indexed blockchain data including
/// tokens, events, and transaction history. Queries are automatically
/// retried with exponential backoff for transient failures.
///
/// # Example
///
/// ```rust,no_run
/// use aptos_rust_sdk_v2::api::IndexerClient;
/// use aptos_rust_sdk_v2::config::AptosConfig;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let client = IndexerClient::new(AptosConfig::testnet())?;
///     // Use the client for GraphQL queries
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct IndexerClient {
    indexer_url: Url,
    client: Client,
    retry_config: Arc<RetryConfig>,
}

/// GraphQL request body.
#[derive(Debug, Serialize)]
struct GraphQLRequest {
    query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    variables: Option<serde_json::Value>,
}

/// GraphQL response body.
#[derive(Debug, Deserialize)]
struct GraphQLResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphQLError>>,
}

/// GraphQL error.
#[derive(Debug, Deserialize)]
struct GraphQLError {
    message: String,
}

impl IndexerClient {
    /// Creates a new indexer client.
    ///
    /// # TLS Security
    ///
    /// This client uses `reqwest` with its default TLS configuration, which
    /// validates server certificates against the system's certificate store.
    /// All Aptos indexer endpoints use HTTPS with valid certificates.
    pub fn new(config: &AptosConfig) -> AptosResult<Self> {
        let indexer_url = config
            .indexer_url()
            .cloned()
            .ok_or_else(|| AptosError::Config("indexer URL not configured".into()))?;

        let pool = config.pool_config();

        // SECURITY: TLS certificate validation is enabled by default via reqwest.
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
            indexer_url,
            client,
            retry_config,
        })
    }

    /// Creates an indexer client with a custom URL.
    pub fn with_url(url: &str) -> AptosResult<Self> {
        let indexer_url = Url::parse(url)?;
        let client = Client::new();
        Ok(Self {
            indexer_url,
            client,
            retry_config: Arc::new(RetryConfig::default()),
        })
    }

    /// Executes a GraphQL query.
    pub async fn query<T: for<'de> Deserialize<'de> + Send + 'static>(
        &self,
        query: &str,
        variables: Option<serde_json::Value>,
    ) -> AptosResult<T> {
        let request = GraphQLRequest {
            query: query.to_string(),
            variables,
        };

        let client = self.client.clone();
        let url = self.indexer_url.clone();
        let retry_config = self.retry_config.clone();

        let executor = RetryExecutor::new((*retry_config).clone());
        executor
            .execute(|| {
                let client = client.clone();
                let url = url.clone();
                let request = GraphQLRequest {
                    query: request.query.clone(),
                    variables: request.variables.clone(),
                };
                async move {
                    let response = client.post(url.as_str()).json(&request).send().await?;

                    if response.status().is_success() {
                        let graphql_response: GraphQLResponse<T> = response.json().await?;

                        if let Some(errors) = graphql_response.errors {
                            let messages: Vec<String> =
                                errors.iter().map(|e| e.message.clone()).collect();
                            return Err(AptosError::Api {
                                status_code: 400,
                                message: messages.join("; "),
                                error_code: Some("GRAPHQL_ERROR".to_string()),
                                vm_error_code: None,
                            });
                        }

                        graphql_response.data.ok_or_else(|| {
                            AptosError::Internal("no data in GraphQL response".into())
                        })
                    } else {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        Err(AptosError::api(status.as_u16(), body))
                    }
                }
            })
            .await
    }

    /// Gets the account's fungible asset balances.
    pub async fn get_fungible_asset_balances(
        &self,
        address: AccountAddress,
    ) -> AptosResult<Vec<FungibleAssetBalance>> {
        #[derive(Deserialize)]
        struct Response {
            current_fungible_asset_balances: Vec<FungibleAssetBalance>,
        }

        let query = r"
            query GetFungibleAssetBalances($address: String!) {
                current_fungible_asset_balances(
                    where: { owner_address: { _eq: $address } }
                ) {
                    asset_type
                    amount
                    metadata {
                        name
                        symbol
                        decimals
                    }
                }
            }
        ";

        let variables = serde_json::json!({
            "address": address.to_string()
        });

        let response: Response = self.query(query, Some(variables)).await?;
        Ok(response.current_fungible_asset_balances)
    }

    /// Gets the account's token (NFT) holdings.
    pub async fn get_account_tokens(
        &self,
        address: AccountAddress,
    ) -> AptosResult<Vec<TokenBalance>> {
        #[derive(Deserialize)]
        struct Response {
            current_token_ownerships_v2: Vec<TokenBalance>,
        }

        let query = r"
            query GetAccountTokens($address: String!) {
                current_token_ownerships_v2(
                    where: { owner_address: { _eq: $address }, amount: { _gt: 0 } }
                ) {
                    token_data_id
                    amount
                    current_token_data {
                        token_name
                        description
                        token_uri
                        current_collection {
                            collection_name
                        }
                    }
                }
            }
        ";

        let variables = serde_json::json!({
            "address": address.to_string()
        });

        let response: Response = self.query(query, Some(variables)).await?;
        Ok(response.current_token_ownerships_v2)
    }

    /// Gets recent transactions for an account.
    pub async fn get_account_transactions(
        &self,
        address: AccountAddress,
        limit: Option<u32>,
    ) -> AptosResult<Vec<Transaction>> {
        #[derive(Deserialize)]
        struct Response {
            account_transactions: Vec<Transaction>,
        }

        let query = r"
            query GetAccountTransactions($address: String!, $limit: Int!) {
                account_transactions(
                    where: { account_address: { _eq: $address } }
                    order_by: { transaction_version: desc }
                    limit: $limit
                ) {
                    transaction_version
                    coin_activities {
                        activity_type
                        amount
                        coin_type
                    }
                }
            }
        ";

        let variables = serde_json::json!({
            "address": address.to_string(),
            "limit": limit.unwrap_or(25)
        });

        let response: Response = self.query(query, Some(variables)).await?;
        Ok(response.account_transactions)
    }
}

/// Fungible asset balance from the indexer.
#[derive(Debug, Clone, Deserialize)]
pub struct FungibleAssetBalance {
    /// The asset type.
    pub asset_type: String,
    /// The balance amount.
    pub amount: String,
    /// Asset metadata.
    pub metadata: Option<FungibleAssetMetadata>,
}

/// Fungible asset metadata from the indexer.
#[derive(Debug, Clone, Deserialize)]
pub struct FungibleAssetMetadata {
    /// Asset name.
    pub name: String,
    /// Asset symbol.
    pub symbol: String,
    /// Number of decimals.
    pub decimals: u8,
}

/// Token (NFT) balance from the indexer.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenBalance {
    /// The token data ID.
    pub token_data_id: String,
    /// Amount owned.
    pub amount: String,
    /// Token data.
    pub current_token_data: Option<TokenData>,
}

/// Token data from the indexer.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenData {
    /// Token name.
    pub token_name: String,
    /// Token description.
    pub description: String,
    /// Token URI.
    pub token_uri: String,
    /// Collection data.
    pub current_collection: Option<CollectionData>,
}

/// Collection data from the indexer.
#[derive(Debug, Clone, Deserialize)]
pub struct CollectionData {
    /// Collection name.
    pub collection_name: String,
}

/// Transaction from the indexer.
#[derive(Debug, Clone, Deserialize)]
pub struct Transaction {
    /// Transaction version.
    pub transaction_version: String,
    /// Coin activities in this transaction.
    pub coin_activities: Vec<CoinActivity>,
}

/// Coin activity from the indexer.
#[derive(Debug, Clone, Deserialize)]
pub struct CoinActivity {
    /// Activity type.
    pub activity_type: String,
    /// Amount.
    pub amount: Option<String>,
    /// Coin type.
    pub coin_type: String,
}

/// Pagination parameters for indexer queries.
#[derive(Debug, Clone, Default)]
pub struct PaginationParams {
    /// Maximum number of items to return.
    pub limit: u32,
    /// Number of items to skip.
    pub offset: u32,
}

impl PaginationParams {
    /// Creates new pagination parameters.
    pub fn new(limit: u32, offset: u32) -> Self {
        Self { limit, offset }
    }

    /// Creates pagination for the first page.
    pub fn first(limit: u32) -> Self {
        Self { limit, offset: 0 }
    }
}

/// A paginated response.
#[derive(Debug, Clone)]
pub struct Page<T> {
    /// The items in this page.
    pub items: Vec<T>,
    /// Whether there are more items.
    pub has_more: bool,
    /// Total count if available.
    pub total_count: Option<u64>,
}

/// Event from the indexer.
#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    /// Event sequence number.
    pub sequence_number: String,
    /// Event type.
    #[serde(rename = "type")]
    pub event_type: String,
    /// Event data.
    pub data: serde_json::Value,
    /// Transaction version that emitted this event.
    pub transaction_version: Option<String>,
    /// Account address associated with the event.
    pub account_address: Option<String>,
    /// Creation number.
    pub creation_number: Option<String>,
}

/// Collection data from the indexer.
#[derive(Debug, Clone, Deserialize)]
pub struct Collection {
    /// Collection address.
    pub collection_id: String,
    /// Collection name.
    pub collection_name: String,
    /// Creator address.
    pub creator_address: String,
    /// Current supply.
    pub current_supply: String,
    /// Maximum supply (0 = unlimited).
    pub max_supply: Option<String>,
    /// Collection URI.
    pub uri: String,
    /// Description.
    pub description: String,
}

/// Coin balance from the indexer (legacy coin module).
#[derive(Debug, Clone, Deserialize)]
pub struct CoinBalance {
    /// Coin type.
    pub coin_type: String,
    /// Balance amount.
    pub amount: String,
}

/// Processor status from the indexer.
#[derive(Debug, Clone, Deserialize)]
pub struct ProcessorStatus {
    /// Processor name.
    pub processor: String,
    /// Last successfully processed version.
    pub last_success_version: u64,
    /// Last updated timestamp.
    pub last_updated: Option<String>,
}

impl IndexerClient {
    // ... existing methods ...

    /// Gets the account's token (NFT) holdings with pagination.
    pub async fn get_account_tokens_paginated(
        &self,
        address: AccountAddress,
        pagination: Option<PaginationParams>,
    ) -> AptosResult<Page<TokenBalance>> {
        #[derive(Deserialize)]
        struct AggregateCount {
            count: u64,
        }

        #[derive(Deserialize)]
        struct Aggregate {
            aggregate: Option<AggregateCount>,
        }

        #[derive(Deserialize)]
        struct Response {
            current_token_ownerships_v2: Vec<TokenBalance>,
            current_token_ownerships_v2_aggregate: Aggregate,
        }

        let pagination = pagination.unwrap_or(PaginationParams {
            limit: 25,
            offset: 0,
        });

        let query = r"
            query GetAccountTokens($address: String!, $limit: Int!, $offset: Int!) {
                current_token_ownerships_v2(
                    where: { owner_address: { _eq: $address }, amount: { _gt: 0 } }
                    limit: $limit
                    offset: $offset
                ) {
                    token_data_id
                    amount
                    current_token_data {
                        token_name
                        description
                        token_uri
                        current_collection {
                            collection_name
                        }
                    }
                }
                current_token_ownerships_v2_aggregate(
                    where: { owner_address: { _eq: $address }, amount: { _gt: 0 } }
                ) {
                    aggregate {
                        count
                    }
                }
            }
        ";

        let variables = serde_json::json!({
            "address": address.to_string(),
            "limit": pagination.limit,
            "offset": pagination.offset
        });

        let response: Response = self.query(query, Some(variables)).await?;
        let total_count = response
            .current_token_ownerships_v2_aggregate
            .aggregate
            .map(|a| a.count);
        let has_more = total_count.is_some_and(|total| {
            (u64::from(pagination.offset) + response.current_token_ownerships_v2.len() as u64)
                < total
        });

        Ok(Page {
            items: response.current_token_ownerships_v2,
            has_more,
            total_count,
        })
    }

    /// Gets the account's transaction history with pagination.
    pub async fn get_account_transactions_paginated(
        &self,
        address: AccountAddress,
        pagination: Option<PaginationParams>,
    ) -> AptosResult<Page<Transaction>> {
        #[derive(Deserialize)]
        struct AggregateCount {
            count: u64,
        }

        #[derive(Deserialize)]
        struct Aggregate {
            aggregate: Option<AggregateCount>,
        }

        #[derive(Deserialize)]
        struct Response {
            account_transactions: Vec<Transaction>,
            account_transactions_aggregate: Aggregate,
        }

        let pagination = pagination.unwrap_or(PaginationParams {
            limit: 25,
            offset: 0,
        });

        let query = r"
            query GetAccountTransactions($address: String!, $limit: Int!, $offset: Int!) {
                account_transactions(
                    where: { account_address: { _eq: $address } }
                    order_by: { transaction_version: desc }
                    limit: $limit
                    offset: $offset
                ) {
                    transaction_version
                    coin_activities {
                        activity_type
                        amount
                        coin_type
                    }
                }
                account_transactions_aggregate(
                    where: { account_address: { _eq: $address } }
                ) {
                    aggregate {
                        count
                    }
                }
            }
        ";

        let variables = serde_json::json!({
            "address": address.to_string(),
            "limit": pagination.limit,
            "offset": pagination.offset
        });

        let response: Response = self.query(query, Some(variables)).await?;
        let total_count = response
            .account_transactions_aggregate
            .aggregate
            .map(|a| a.count);
        let has_more = total_count.is_some_and(|total| {
            (u64::from(pagination.offset) + response.account_transactions.len() as u64) < total
        });

        Ok(Page {
            items: response.account_transactions,
            has_more,
            total_count,
        })
    }

    /// Gets events by type.
    pub async fn get_events_by_type(
        &self,
        event_type: &str,
        limit: Option<u32>,
    ) -> AptosResult<Vec<Event>> {
        #[derive(Deserialize)]
        struct Response {
            events: Vec<Event>,
        }

        let query = r"
            query GetEventsByType($type: String!, $limit: Int!) {
                events(
                    where: { type: { _eq: $type } }
                    order_by: { transaction_version: desc }
                    limit: $limit
                ) {
                    sequence_number
                    type
                    data
                    transaction_version
                    account_address
                    creation_number
                }
            }
        ";

        let variables = serde_json::json!({
            "type": event_type,
            "limit": limit.unwrap_or(25)
        });

        let response: Response = self.query(query, Some(variables)).await?;
        Ok(response.events)
    }

    /// Gets events involving an account.
    pub async fn get_events_by_account(
        &self,
        address: AccountAddress,
        limit: Option<u32>,
    ) -> AptosResult<Vec<Event>> {
        #[derive(Deserialize)]
        struct Response {
            events: Vec<Event>,
        }

        let query = r"
            query GetEventsByAccount($address: String!, $limit: Int!) {
                events(
                    where: { account_address: { _eq: $address } }
                    order_by: { transaction_version: desc }
                    limit: $limit
                ) {
                    sequence_number
                    type
                    data
                    transaction_version
                    account_address
                    creation_number
                }
            }
        ";

        let variables = serde_json::json!({
            "address": address.to_string(),
            "limit": limit.unwrap_or(25)
        });

        let response: Response = self.query(query, Some(variables)).await?;
        Ok(response.events)
    }

    /// Gets a collection by its address.
    pub async fn get_collection(
        &self,
        collection_address: AccountAddress,
    ) -> AptosResult<Collection> {
        #[derive(Deserialize)]
        struct Response {
            current_collections_v2: Vec<Collection>,
        }

        let query = r"
            query GetCollection($address: String!) {
                current_collections_v2(
                    where: { collection_id: { _eq: $address } }
                    limit: 1
                ) {
                    collection_id
                    collection_name
                    creator_address
                    current_supply
                    max_supply
                    uri
                    description
                }
            }
        ";

        let variables = serde_json::json!({
            "address": collection_address.to_string()
        });

        let response: Response = self.query(query, Some(variables)).await?;
        response
            .current_collections_v2
            .into_iter()
            .next()
            .ok_or_else(|| {
                AptosError::NotFound(format!("Collection not found: {collection_address}"))
            })
    }

    /// Gets tokens in a collection.
    pub async fn get_collection_tokens(
        &self,
        collection_address: AccountAddress,
        pagination: Option<PaginationParams>,
    ) -> AptosResult<Page<TokenBalance>> {
        #[derive(Deserialize)]
        struct Response {
            current_token_ownerships_v2: Vec<TokenBalance>,
        }

        let pagination = pagination.unwrap_or(PaginationParams {
            limit: 25,
            offset: 0,
        });

        let query = r"
            query GetCollectionTokens($address: String!, $limit: Int!, $offset: Int!) {
                current_token_ownerships_v2(
                    where: { 
                        current_token_data: { 
                            current_collection: { 
                                collection_id: { _eq: $address } 
                            } 
                        }
                        amount: { _gt: 0 }
                    }
                    limit: $limit
                    offset: $offset
                ) {
                    token_data_id
                    amount
                    current_token_data {
                        token_name
                        description
                        token_uri
                        current_collection {
                            collection_name
                        }
                    }
                }
            }
        ";

        let variables = serde_json::json!({
            "address": collection_address.to_string(),
            "limit": pagination.limit,
            "offset": pagination.offset
        });

        let response: Response = self.query(query, Some(variables)).await?;
        let items_count = response.current_token_ownerships_v2.len();

        Ok(Page {
            items: response.current_token_ownerships_v2,
            has_more: items_count == pagination.limit as usize,
            total_count: None,
        })
    }

    /// Gets coin balances for an account (legacy coin module).
    pub async fn get_coin_balances(
        &self,
        address: AccountAddress,
    ) -> AptosResult<Vec<CoinBalance>> {
        #[derive(Deserialize)]
        struct Response {
            current_coin_balances: Vec<CoinBalance>,
        }

        let query = r"
            query GetCoinBalances($address: String!) {
                current_coin_balances(
                    where: { owner_address: { _eq: $address } }
                ) {
                    coin_type
                    amount
                }
            }
        ";

        let variables = serde_json::json!({
            "address": address.to_string()
        });

        let response: Response = self.query(query, Some(variables)).await?;
        Ok(response.current_coin_balances)
    }

    /// Gets coin activities for an account.
    pub async fn get_coin_activities(
        &self,
        address: AccountAddress,
        limit: Option<u32>,
    ) -> AptosResult<Vec<CoinActivity>> {
        #[derive(Deserialize)]
        struct Response {
            coin_activities: Vec<CoinActivity>,
        }

        let query = r"
            query GetCoinActivities($address: String!, $limit: Int!) {
                coin_activities(
                    where: { owner_address: { _eq: $address } }
                    order_by: { transaction_version: desc }
                    limit: $limit
                ) {
                    activity_type
                    amount
                    coin_type
                }
            }
        ";

        let variables = serde_json::json!({
            "address": address.to_string(),
            "limit": limit.unwrap_or(25)
        });

        let response: Response = self.query(query, Some(variables)).await?;
        Ok(response.coin_activities)
    }

    /// Gets the processor status to check indexer health.
    pub async fn get_processor_status(&self) -> AptosResult<Vec<ProcessorStatus>> {
        #[derive(Deserialize)]
        struct Response {
            processor_status: Vec<ProcessorStatus>,
        }

        let query = r"
            query GetProcessorStatus {
                processor_status {
                    processor
                    last_success_version
                    last_updated
                }
            }
        ";

        let response: Response = self.query(query, None).await?;
        Ok(response.processor_status)
    }

    /// Gets the current indexer version (last processed transaction).
    pub async fn get_indexer_version(&self) -> AptosResult<u64> {
        let statuses = self.get_processor_status().await?;
        statuses
            .into_iter()
            .map(|s| s.last_success_version)
            .max()
            .ok_or_else(|| AptosError::Internal("No processor status available".into()))
    }

    /// Checks if the indexer is healthy by comparing with a reference version.
    pub async fn check_indexer_lag(
        &self,
        reference_version: u64,
        max_lag: u64,
    ) -> AptosResult<bool> {
        let indexer_version = self.get_indexer_version().await?;
        Ok(reference_version.saturating_sub(indexer_version) <= max_lag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indexer_client_creation() {
        let client = IndexerClient::new(&AptosConfig::testnet());
        assert!(client.is_ok());
    }

    #[test]
    fn test_pagination_params() {
        let params = PaginationParams::new(10, 20);
        assert_eq!(params.limit, 10);
        assert_eq!(params.offset, 20);

        let first_page = PaginationParams::first(50);
        assert_eq!(first_page.limit, 50);
        assert_eq!(first_page.offset, 0);
    }

    #[test]
    fn test_page_has_more() {
        let page: Page<u32> = Page {
            items: vec![1, 2, 3],
            has_more: true,
            total_count: Some(100),
        };
        assert!(page.has_more);
        assert_eq!(page.items.len(), 3);
        assert_eq!(page.total_count, Some(100));
    }

    #[test]
    fn test_custom_url() {
        let client = IndexerClient::with_url("https://custom-indexer.example.com/v1/graphql");
        assert!(client.is_ok());
    }
}
