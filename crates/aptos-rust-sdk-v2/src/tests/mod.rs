//! Test module for the Aptos SDK.

#[cfg(test)]
mod integration_tests {
    use crate::types::AccountAddress;
    use crate::config::AptosConfig;

    #[test]
    fn test_address_parsing() {
        let addr = AccountAddress::from_hex("0x1").unwrap();
        assert_eq!(addr, AccountAddress::ONE);

        let addr = AccountAddress::from_hex("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        assert_eq!(addr, AccountAddress::ONE);
    }

    #[test]
    fn test_config_creation() {
        let config = AptosConfig::testnet();
        assert!(config.fullnode_url().as_str().contains("testnet"));
        assert!(config.faucet_url().is_some());
    }
}

