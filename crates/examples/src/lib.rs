#[cfg(test)]
mod tests {
    use aptos_rust_sdk::client::builder::AptosClientBuilder;
    use aptos_rust_sdk::client::config::AptosNetwork;

    #[tokio::test]
    async fn submit_transaction() {
        let builder = AptosClientBuilder::new(AptosNetwork::devnet());
        let client = builder.build();

        println!("{:?}", client.get_state().await.unwrap())
    }
}
