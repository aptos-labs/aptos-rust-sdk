//! GraphQL indexer client.

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
    pub fn new(config: AptosConfig) -> AptosResult<Self> {
        let indexer_url = config
            .indexer_url()
            .cloned()
            .ok_or_else(|| AptosError::Config("indexer URL not configured".into()))?;

        let pool = config.pool_config();

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

                        graphql_response
                            .data
                            .ok_or_else(|| AptosError::Internal("no data in GraphQL response".into()))
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
        let query = r#"
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
        "#;

        let variables = serde_json::json!({
            "address": address.to_string()
        });

        #[derive(Deserialize)]
        struct Response {
            current_fungible_asset_balances: Vec<FungibleAssetBalance>,
        }

        let response: Response = self.query(query, Some(variables)).await?;
        Ok(response.current_fungible_asset_balances)
    }

    /// Gets the account's token (NFT) holdings.
    pub async fn get_account_tokens(
        &self,
        address: AccountAddress,
    ) -> AptosResult<Vec<TokenBalance>> {
        let query = r#"
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
        "#;

        let variables = serde_json::json!({
            "address": address.to_string()
        });

        #[derive(Deserialize)]
        struct Response {
            current_token_ownerships_v2: Vec<TokenBalance>,
        }

        let response: Response = self.query(query, Some(variables)).await?;
        Ok(response.current_token_ownerships_v2)
    }

    /// Gets recent transactions for an account.
    pub async fn get_account_transactions(
        &self,
        address: AccountAddress,
        limit: Option<u32>,
    ) -> AptosResult<Vec<Transaction>> {
        let query = r#"
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
        "#;

        let variables = serde_json::json!({
            "address": address.to_string(),
            "limit": limit.unwrap_or(25)
        });

        #[derive(Deserialize)]
        struct Response {
            account_transactions: Vec<Transaction>,
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indexer_client_creation() {
        let client = IndexerClient::new(AptosConfig::testnet());
        assert!(client.is_ok());
    }
}

