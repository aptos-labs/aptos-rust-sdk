use aptos_sdk::account::Ed25519SingleKeyAccount;

#[tokio::test]
#[ignore]
async fn e2e_single_key_account_address_derivation() {
    // Test that SingleKey accounts derive addresses correctly
    let account = Ed25519SingleKeyAccount::generate();

    // Address should not be zero
    assert!(!account.address().is_zero());

    // Same key should produce same address
    let address1 = account.address();
    let address2 = account.address();
    assert_eq!(address1, address2);

    println!("SingleKey account address: {}", account.address());
}
