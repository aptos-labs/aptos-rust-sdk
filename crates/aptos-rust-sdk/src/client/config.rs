use url::Url;

const MAINNET_REST_URL: &str = "https://api.mainnet.aptoslabs.com";
const TESTNET_REST_URL: &str = "https://api.testnet.aptoslabs.com";
const DEVNET_REST_URL: &str = "https://api.devnet.aptoslabs.com";
const LOCAL_REST_URL: &str = "http://127.0.0.1:8080";

const MAINNET_INDEXER_URL: &str = "https://api.mainnet.aptoslabs.com";
const TESTNET_INDEXER_URL: &str = "https://api.testnet.aptoslabs.com";
const DEVNET_INDEXER_URL: &str = "https://api.devnet.aptoslabs.com";
const LOCAL_INDEXER_URL: &str = "http://127.0.0.1:8090";

const TESTNET_FAUCET_URL: &str = "https://faucet.testnet.aptoslabs.com";
const DEVNET_FAUCET_URL: &str = "https://faucet.devnet.aptoslabs.com";
const LOCAL_FAUCET_URL: &str = "http://127.0.0.1:8081";

/// An immutable definition of a network configuration
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AptosNetwork {
    name: &'static str,
    rest_url: Url,
    indexer_url: Url,
    faucet_url: Option<Url>,
}

impl AptosNetwork {
    pub const fn new(
        name: &'static str,
        rest_url: Url,
        indexer_url: Url,
        faucet_url: Option<Url>,
    ) -> AptosNetwork {
        AptosNetwork {
            name,
            rest_url,
            indexer_url,
            faucet_url,
        }
    }

    pub fn mainnet() -> Self {
        Self::new(
            "mainnet",
            Url::parse(MAINNET_REST_URL).unwrap(),
            Url::parse(MAINNET_INDEXER_URL).unwrap(),
            None,
        )
    }

    pub fn testnet() -> Self {
        Self::new(
            "testnet",
            Url::parse(TESTNET_REST_URL).unwrap(),
            Url::parse(TESTNET_INDEXER_URL).unwrap(),
            Some(Url::parse(TESTNET_FAUCET_URL).unwrap()),
        )
    }

    pub fn devnet() -> Self {
        Self::new(
            "devnet",
            Url::parse(DEVNET_REST_URL).unwrap(),
            Url::parse(DEVNET_INDEXER_URL).unwrap(),
            Some(Url::parse(DEVNET_FAUCET_URL).unwrap()),
        )
    }

    pub fn localnet() -> Self {
        Self::new(
            "localnet",
            Url::parse(LOCAL_REST_URL).unwrap(),
            Url::parse(LOCAL_INDEXER_URL).unwrap(),
            Some(Url::parse(LOCAL_FAUCET_URL).unwrap()),
        )
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn rest_url(&self) -> &Url {
        &self.rest_url
    }

    pub fn indexer_url(&self) -> &Url {
        &self.indexer_url
    }

    pub fn faucet_url(&self) -> Option<&Url> {
        self.faucet_url.as_ref()
    }
}
