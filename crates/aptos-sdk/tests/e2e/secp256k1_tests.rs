use aptos_sdk::account::Secp256k1Account;

#[tokio::test]
#[ignore]
async fn e2e_secp256k1_account_address_derivation() {
    // Test that Secp256k1 accounts derive addresses correctly
    let account = Secp256k1Account::generate();

    // Address should not be zero
    assert!(!account.address().is_zero());

    // Same key should produce same address
    let address1 = account.address();
    let address2 = account.address();
    assert_eq!(address1, address2);

    println!("Secp256k1 account address: {}", account.address());
}
