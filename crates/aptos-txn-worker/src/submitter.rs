use anyhow::{anyhow, Result};
use aptos_crypto::compat::Sha3_256;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use aptos_rust_sdk::client::rest_api::AptosFullnodeClient;
use aptos_rust_sdk_types::api_types::transaction::{RawTransaction, SignedTransaction};
use aptos_rust_sdk_types::api_types::transaction_authenticator::TransactionAuthenticator;
use async_trait::async_trait;
use ed25519_dalek::Digest;
use tracing::{debug, info};

/// Structs that implement this trait can submit transactions to the chain. We provide
/// a default implementation that submits transactions directly to the chain. We have
/// this trait so you can submit transactions in a different way if you want, e.g. via
/// a gas station.
#[async_trait]
pub trait Submitter: Send + Sync + 'static {
    /// Sign and submit a transaction, returning the transaction hash.
    async fn sign_and_submit_transaction(
        &self,
        private_key: &Ed25519PrivateKey,
        transaction: RawTransaction,
    ) -> Result<String>;
}

pub struct DirectSubmitter {
    pub client: AptosFullnodeClient,
}

#[async_trait]
impl Submitter for DirectSubmitter {
    /// Sign and submit a transaction, returning the transaction hash.
    async fn sign_and_submit_transaction(
        &self,
        private_key: &Ed25519PrivateKey,
        transaction: RawTransaction,
    ) -> Result<String> {
        // Sign the transaction
        let mut sha3 = Sha3_256::new();
        sha3.update("APTOS::RawTransaction".as_bytes());
        let hash = sha3.finalize().to_vec();

        let mut bytes = vec![];
        bcs::serialize_into(&mut bytes, &transaction)?;

        let mut message = vec![];
        message.extend(hash);
        message.extend(bytes);

        let signature = private_key.sign_message(&message);
        let public_key = Ed25519PublicKey::from(private_key);

        let signed_transaction = SignedTransaction::new(
            transaction,
            TransactionAuthenticator::ed25519(public_key, signature),
        );

        debug!("Submitting transaction to chain");

        // Submit the transaction
        let response = self.client.submit_transaction(signed_transaction).await?;

        // Extract the transaction hash
        let hash = response
            .into_inner()
            .get("hash")
            .ok_or_else(|| anyhow!("No hash in transaction response"))?
            .as_str()
            .ok_or_else(|| anyhow!("Hash is not a string"))?
            .to_string();

        info!(
            txn_hash = %hash,
            "Transaction submitted successfully"
        );

        Ok(hash)
    }
}
