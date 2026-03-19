use super::*;

#[tokio::test]
#[ignore]
async fn e2e_get_account_resource() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let account = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    wait_for_finality().await;

    // Get the Account resource via fullnode client
    let resource = aptos
        .fullnode()
        .get_account_resource(account.address(), "0x1::account::Account")
        .await;

    match resource {
        Ok(r) => {
            println!("Account resource: {:?}", r.data);
        }
        Err(e) => {
            println!("Failed to get resource: {}", e);
        }
    }
}

#[tokio::test]
#[ignore]
async fn e2e_get_coin_store_resource() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let account = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    wait_for_finality().await;

    // Get the CoinStore resource for APT
    let resource = aptos
        .fullnode()
        .get_account_resource(
            account.address(),
            "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
        )
        .await;

    match resource {
        Ok(r) => {
            println!("CoinStore resource: {:?}", r.data);
        }
        Err(e) => {
            println!("Failed to get CoinStore: {}", e);
        }
    }
}
