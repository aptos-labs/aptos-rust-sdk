use crate::client::config::AptosNetwork;
use aptos_rust_sdk_types::AptosResult;
use reqwest::Client as ReqwestClient;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct FundResponse {
    txn_hashes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AptosFaucetClient {
    pub(crate) network: AptosNetwork,
    pub(crate) rest_client: ReqwestClient,
    api_key: Option<String>,
}

impl AptosFaucetClient {
    /// Create a builder for the `AptosClient`
    pub fn new(network: AptosNetwork, api_key: Option<String>) -> AptosFaucetClient {
        if !(network.name() == "localnet"
            || network.name() == "devnet"
            || network.name() == "testnet")
        {
            if network.name() == "testnet" && api_key.is_none() {
                panic!("Faucet client only supports testnet with an API key. Consider using https://aptos.dev/en/network/faucet");
            } else {
                panic!("Faucet client only supports localnet and devnet");
            }
        }
        AptosFaucetClient {
            network,
            rest_client: ReqwestClient::new(),
            api_key,
        }
    }

    /// Mint funds to an account, creating it if it doesn't exist. If you set an amount
    /// that is too large, the service will clamp it to its configured maximum.
    pub async fn mint(&self, address: &str, amount_octas: u64) -> AptosResult<String> {
        let url = self.network.faucet_url().unwrap().join(&format!("fund"))?;
        let data = serde_json::json!({
            "address": address,
            "amount": amount_octas,
        });
        let request = self.rest_client.post(url).json(&data);
        let request = match &self.api_key {
            Some(api_key) => request.bearer_auth(api_key.clone()),
            None => request,
        };
        let response = request.send().await?;
        let body: FundResponse = response.json().await?;
        let txn_hash = body.txn_hashes.into_iter().take(1).next().unwrap();
        Ok(txn_hash)
    }
}
