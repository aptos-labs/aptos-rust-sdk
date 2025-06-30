#[cfg(test)]
mod tests {
    use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
    use aptos_crypto::Uniform;
    use aptos_rust_sdk::client::builder::AptosClientBuilder;
    use aptos_rust_sdk::client::config::AptosNetwork;
    use aptos_rust_sdk_types::api_types::address::AccountAddress;
    use aptos_rust_sdk_types::api_types::chain_id::ChainId;
    use aptos_rust_sdk_types::api_types::module_id::ModuleId;
    use aptos_rust_sdk_types::api_types::transaction::{
        EntryFunction, GenerateSigningMessage, RawTransaction, RawTransactionWithData,
        SignedTransaction, TransactionPayload,
    };
    use aptos_rust_sdk_types::api_types::transaction_authenticator::{
        AccountAuthenticator, AuthenticationKey, TransactionAuthenticator,
    };
    use std::str::FromStr;
    use std::vec;

    #[tokio::test]
    async fn submit_transaction() {
        let builder = AptosClientBuilder::new(AptosNetwork::testnet());
        let client = builder.build();

        let state = client.get_state().await.unwrap();

        let mut seed = [0u8; 32];
        let seed_bytes =
            hex::decode("4aeeeb3f286caa91984d4a16d424786c7aa26947050b00e84ab7033f2aab0c2d")
                .unwrap(); // Remove the 0x prefix
        seed[..seed_bytes.len()].copy_from_slice(&seed_bytes);

        let key = Ed25519PrivateKey::try_from(seed_bytes.as_slice()).unwrap();
        let auth_key = AuthenticationKey::ed25519(&Ed25519PublicKey::from(&key));
        let sender = auth_key.account_address();
        println!("Sender: {:?}", sender);
        let resource = client
            .get_account_resources(sender.to_string())
            .await
            .unwrap()
            .into_inner();
        let sequence_number = resource
            .iter()
            .find(|r| r.type_ == "0x1::account::Account")
            .unwrap()
            .data
            .get("sequence_number")
            .unwrap()
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(AccountAddress::ONE, "aptos_account".to_string()),
            "transfer".to_string(),
            vec![],
            vec![AccountAddress::ONE.to_vec(), 1u64.to_le_bytes().to_vec()],
        ));
        let max_gas_amount = 11;
        let gas_unit_price = 100;
        let expiration_timestamp_secs = state.timestamp_usecs / 1000 / 1000 + 60 * 10;
        let chain_id = ChainId::Testnet;

        let raw_txn = RawTransaction::new(
            sender,
            sequence_number,
            payload,
            max_gas_amount,
            gas_unit_price,
            expiration_timestamp_secs,
            chain_id,
        );

        let message = raw_txn.generate_signing_message().unwrap();

        let signature = key.sign_message(&message);

        let simulate_transaction = client
            .simulate_transaction(SignedTransaction::new(
                raw_txn.clone(),
                TransactionAuthenticator::single_sender(AccountAuthenticator::no_authenticator()),
            ))
            .await;

        println!("Simulate Transaction: {:?}", simulate_transaction);

        let transaction = client
            .submit_transaction(SignedTransaction::new(
                raw_txn.clone(),
                TransactionAuthenticator::ed25519(Ed25519PublicKey::from(&key), signature),
            ))
            .await;

        println!("Transaction: {:?}", transaction);
    }

    #[tokio::test]
    async fn submit_feepayer_transaction() {
        let builder = AptosClientBuilder::new(AptosNetwork::testnet());
        let client = builder.build();

        let state = client.get_state().await.unwrap();

        let mut seed = [0u8; 32];
        let seed_bytes =
            hex::decode("4aeeeb3f286caa91984d4a16d424786c7aa26947050b00e84ab7033f2aab0c2d")
                .unwrap(); // Remove the 0x prefix
        seed[..seed_bytes.len()].copy_from_slice(&seed_bytes);

        let fee_payer_key = Ed25519PrivateKey::try_from(seed_bytes.as_slice()).unwrap();
        let fee_payer_address =
            AuthenticationKey::ed25519(&Ed25519PublicKey::from(&fee_payer_key)).account_address();
        println!("Feepayer Address: {:?}", fee_payer_address.to_string());

        let txn_sender_key = Ed25519PrivateKey::generate(&mut rand::thread_rng());
        let txn_sender_address =
            AuthenticationKey::ed25519(&Ed25519PublicKey::from(&txn_sender_key)).account_address();

        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(
                AccountAddress::from_str(
                    "0x94bd6fa34dba07f935ea2288ba36d74aa5dda6ae541137844cc2f0af8b6b73f3",
                )
                .unwrap(),
                "create_object".to_string(),
            ),
            "create".to_string(),
            vec![],
            vec![],
        ));

        let max_gas_amount = 1500;
        let gas_unit_price = 100;
        let expiration_timestamp_secs = state.timestamp_usecs / 1000 / 1000 + 60 * 10;
        let chain_id = ChainId::Testnet;

        let raw_txn = RawTransaction::new(
            txn_sender_address,
            0,
            payload,
            max_gas_amount,
            gas_unit_price,
            expiration_timestamp_secs,
            chain_id,
        );

        let raw_txn_with_data = RawTransactionWithData::new_multi_agent_with_fee_payer(
            raw_txn.clone(),
            vec![],
            fee_payer_address,
        );

        let message = raw_txn_with_data.generate_signing_message().unwrap();

        let txn_sender_signature = txn_sender_key.sign_message(&message);

        let fee_payer_signature = fee_payer_key.sign_message(&message);

        let simulate_transaction = client
            .simulate_transaction(SignedTransaction::new(
                raw_txn.clone(),
                TransactionAuthenticator::fee_payer(
                    AccountAuthenticator::no_authenticator(),
                    vec![],
                    vec![],
                    fee_payer_address,
                    AccountAuthenticator::no_authenticator(),
                ),
            ))
            .await;
        println!("Simulate Transaction: {:?}", simulate_transaction);
        let transaction = client
            .submit_transaction(SignedTransaction::new(
                raw_txn.clone(),
                TransactionAuthenticator::fee_payer(
                    AccountAuthenticator::ed25519(
                        Ed25519PublicKey::from(&txn_sender_key),
                        txn_sender_signature,
                    ),
                    vec![],
                    vec![],
                    fee_payer_address,
                    AccountAuthenticator::ed25519(
                        Ed25519PublicKey::from(&fee_payer_key),
                        fee_payer_signature,
                    ),
                ),
            ))
            .await;
        println!("Transaction: {:?}", transaction);
    }

    #[tokio::test]
    async fn submit_multi_agent_transaction() {
        let builder = AptosClientBuilder::new(AptosNetwork::testnet());
        let client = builder.build();

        let state = client.get_state().await.unwrap();

        let seed_bytes =
            hex::decode("4aeeeb3f286caa91984d4a16d424786c7aa26947050b00e84ab7033f2aab0c2d")
                .unwrap();

        let key = Ed25519PrivateKey::try_from(seed_bytes.as_slice()).unwrap();
        let auth_key = AuthenticationKey::ed25519(&Ed25519PublicKey::from(&key));
        let sender = auth_key.account_address();
        println!("Sender: {:?}", sender);

        // Generate a new key for the secondary signer
        let secondary_key = Ed25519PrivateKey::generate(&mut rand::thread_rng());
        let secondary_auth_key =
            AuthenticationKey::ed25519(&Ed25519PublicKey::from(&secondary_key));
        let secondary_address = secondary_auth_key.account_address();
        println!("Secondary Address: {:?}", secondary_address);

        let resource = client
            .get_account_resources(sender.to_string())
            .await
            .unwrap()
            .into_inner();

        let sequence_number = resource
            .iter()
            .find(|r| r.type_ == "0x1::account::Account")
            .unwrap()
            .data
            .get("sequence_number")
            .unwrap()
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();

        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(
                AccountAddress::from_str(
                    "0x0d966e595a22a025302928fe9d6e3ac28c7f1b68c3a68015a4487f8a816ed239",
                )
                .unwrap(),
                "txn".to_string(),
            ),
            "multiAgentTxn".to_string(),
            vec![],
            vec![],
        ));

        let max_gas_amount = 1000;
        let gas_unit_price = 100;
        let expiration_timestamp_secs = state.timestamp_usecs / 1000 / 1000 + 60 * 10;
        let chain_id = ChainId::Testnet;

        let raw_txn = RawTransactionWithData::new_multi_agent(
            RawTransaction::new(
                sender,
                sequence_number,
                payload,
                max_gas_amount,
                gas_unit_price,
                expiration_timestamp_secs,
                chain_id,
            ),
            vec![secondary_address],
        );

        let message = raw_txn.generate_signing_message().unwrap();

        let signature = key.sign_message(&message);

        let simulate_transaction = client
            .simulate_transaction(SignedTransaction::new(
                raw_txn.raw_txn().to_owned(),
                TransactionAuthenticator::MultiAgent {
                    sender: AccountAuthenticator::no_authenticator(),
                    secondary_signer_addresses: vec![secondary_address],
                    secondary_signers: vec![AccountAuthenticator::no_authenticator()],
                },
            ))
            .await;
        println!("Simulate Transaction: {:?}", simulate_transaction);

        let transaction = client
            .submit_transaction(SignedTransaction::new(
                raw_txn.raw_txn().to_owned(),
                TransactionAuthenticator::MultiAgent {
                    sender: AccountAuthenticator::Ed25519 {
                        public_key: Ed25519PublicKey::from(&key),
                        signature,
                    },
                    secondary_signer_addresses: vec![secondary_address],
                    secondary_signers: vec![AccountAuthenticator::Ed25519 {
                        public_key: Ed25519PublicKey::from(&secondary_key),
                        signature: secondary_key.sign_message(&message),
                    }],
                },
            ))
            .await;
        println!("Transaction: {:?}", transaction);
    }
}
