pub mod submitter;
pub mod worker;

#[cfg(test)]
mod tests {
    use crate::worker::TransactionWorkerBuilder;
    use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
    use aptos_crypto::Uniform;
    use aptos_rust_sdk::client::builder::AptosClientBuilder;
    use aptos_rust_sdk::client::config::AptosNetwork;
    use aptos_rust_sdk::client::faucet::AptosFaucetClient;
    use aptos_rust_sdk_types::api_types::address::AccountAddress;
    use aptos_rust_sdk_types::api_types::module_id::ModuleId;
    use aptos_rust_sdk_types::api_types::transaction::EntryFunction;
    use rand::rngs::OsRng;
    use std::time::Duration;
    use tokio::sync::mpsc;

    // This expects a localnet with a faucet to be running.
    #[tokio::test]
    async fn test_worker() {
        // Create a random private key.
        let private_key = Ed25519PrivateKey::generate(&mut OsRng);

        // Get the account address so we can faucet.
        let public_key = Ed25519PublicKey::from(&private_key);
        let auth_key =
            aptos_rust_sdk_types::api_types::transaction_authenticator::AuthenticationKey::ed25519(
                &public_key,
            );
        let sender = auth_key.account_address();

        println!("Sender: {}", sender);

        // Create the account.
        let faucet_client = AptosFaucetClient::new(AptosNetwork::localnet(), None);
        let txn_hash = faucet_client
            .mint(&sender.to_string(), 100_000_000)
            .await
            .expect("Failed to mint funds");
        println!("Faucet txn hash: {}", txn_hash);

        // Jankily wait 500ms for the minting to finish.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Create a client.
        let client = AptosClientBuilder::new(AptosNetwork::localnet()).build();

        // Create a channel for events.
        let (event_sender, mut event_receiver) = mpsc::channel(100);

        // Create worker using the builder
        let worker = TransactionWorkerBuilder::new(private_key, client.clone())
            .with_max_pending_responses(50)
            .with_poll_interval_ms(500)
            .with_event_sender(event_sender)
            .build()
            .await
            .unwrap();

        // Spawn a task to log events.
        // let client_clone = client.clone();
        tokio::spawn(async move {
            while let Some(event) = event_receiver.recv().await {
                /*
                // If it was executed, let's look up the result.
                // TODO: The client doesn't support retrieving the txn result right now.
                if let TransactionWorkerEvent::TransactionExecuted {
                    hash,
                    sequence_number: _,
                } = &event
                {
                    let txn = client_clone
                        .get_transaction_by_hash(hash.clone())
                        .await
                        .unwrap();
                    println!("Transaction result: {:?}", txn);
                }
                */
                println!("Received event: {:?}", event);
            }
            println!("Event sender disconnected");
        });

        // Start the worker
        let handle = worker.start().unwrap();

        // Demonstrate pushing a transaction (will fail since we don't have a real node)
        let payload = EntryFunction::new(
            ModuleId::new(AccountAddress::ONE, "aptos_account".to_string()),
            "transfer".to_string(),
            vec![],
            vec![],
        );

        let result = worker
            .push(payload, None)
            .await
            .expect("Failed to push transaction");

        // Wait for the transaction to be processed.
        let result = result.await.expect("Failed to get transaction result");
        println!("Transaction result: {:?}", result);
        assert!(result.is_ok(), "Transaction failed on chain");

        // Stop worker
        worker.stop().unwrap();

        // Wait for worker internal loop to complete
        worker.wait().await.unwrap();

        // Wait for the worker to complete.
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "Worker failed to complete");
    }
}
