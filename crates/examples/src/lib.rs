#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use aptos_crypto::compat::Sha3_256;
    use aptos_rust_sdk_types::mime_types::JSON;
    use ed25519_dalek::Digest;
    use serde::ser::Serialize;
    use serde::de::DeserializeOwned;
    use aptos_crypto::{PrivateKey, SigningKey};
    use aptos_rust_sdk::client::builder::AptosClientBuilder;
    use aptos_rust_sdk::client::config::AptosNetwork;
    use aptos_rust_sdk_types::api_types::address::AccountAddress;
    use aptos_rust_sdk_types::api_types::chain_id::ChainId;
    use aptos_rust_sdk_types::api_types::module_id::ModuleId;
    use aptos_rust_sdk_types::api_types::transaction::{EntryFunction, RawTransaction, TransactionPayload};
    use aptos_rust_sdk_types::api_types::transaction_authenticator::{AccountAuthenticator, AuthenticationKey, TransactionAuthenticator};
    use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
    use serde::Serializer;

    #[tokio::test]
    async fn submit_transaction() {
        let builder = AptosClientBuilder::new(AptosNetwork::testnet());
        let client = builder.build();

        let state = client.get_state().await.unwrap();

        let mut seed = [0u8; 32];
        let seed_bytes = hex::decode("4aeeeb3f286caa91984d4a16d424786c7aa26947050b00e84ab7033f2aab0c2d").unwrap(); // Remove the 0x prefix
        seed[..seed_bytes.len()].copy_from_slice(&seed_bytes);
        
    
        let key = Ed25519PrivateKey::try_from(seed_bytes.as_slice()).unwrap();
        let auth_key= AuthenticationKey::ed25519(&Ed25519PublicKey::from(&key));
        let sender = auth_key.account_address();
        println!("Sender: {:?}", sender);
        let resource = client.get_account_resources(sender.to_string()).await.unwrap().into_inner();
        let sequence_number =  resource.iter().find(|r|r.type_ == "0x1::account::Account").unwrap().data.get("sequence_number").unwrap().as_str().unwrap().parse::<u64>().unwrap();
        let payload = TransactionPayload::EntryFunction(
            EntryFunction::new(ModuleId::new(AccountAddress::ONE, "aptos_account".to_string()), "transfer".to_string(), vec![], vec![
                AccountAddress::ONE.to_vec(), 1u64.to_le_bytes().to_vec()
            ])
        );
        let max_gas_amount = 11;
        let gas_unit_price = 100;
        let expiration_timestamp_secs = state.timestamp_usecs / 1000 / 1000 + 60 * 10;
        let chain_id = ChainId::Testnet;

        let raw_txn = RawTransaction::new(sender, sequence_number, payload, max_gas_amount, gas_unit_price, expiration_timestamp_secs, chain_id);
    
        let mut sha3 = Sha3_256::new();
        sha3.update("APTOS::RawTransaction".as_bytes());
        let hash = sha3.finalize().to_vec();
        let mut bytes = vec![];
        bcs::serialize_into(&mut bytes, &raw_txn).unwrap();
        let mut message = vec![];
        message.extend(hash);
        message.extend(bytes);
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     
        let signature = key.sign_message( &message );

        let simulate_transaction = client.simulate_transaction( 
            raw_txn.clone(),
            TransactionAuthenticator::single_sender(AccountAuthenticator::no_authenticator())
        ).await;

        println!("Simulate Transaction: {:?}", simulate_transaction);

        let transaction = client.submit_transaction( 
            raw_txn.clone(),
            TransactionAuthenticator::ed25519(Ed25519PublicKey::from(&key), signature),
        ).await;

        println!("Transaction: {:?}", transaction);
    }
}
