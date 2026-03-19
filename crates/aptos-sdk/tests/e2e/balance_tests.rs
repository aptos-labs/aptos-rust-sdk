use super::*;
use aptos_sdk::account::Ed25519Account;

#[tokio::test]
#[ignore]
async fn e2e_balance_multiple_accounts() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Create multiple accounts
    let accounts: Vec<_> = (0..3).map(|_| Ed25519Account::generate()).collect();

    // Fund all accounts
    for account in &accounts {
        aptos
            .fund_account(account.address(), 50_000_000)
            .await
            .expect("failed to fund account");
    }

    wait_for_finality().await;

    // Check all balances
    for (i, account) in accounts.iter().enumerate() {
        let balance = aptos
            .get_balance(account.address())
            .await
            .expect("failed to get balance");
        assert!(
            balance >= 50_000_000,
            "Account {} should have at least 50M octas",
            i
        );
        println!("Account {}: {} octas", i, balance);
    }
}
