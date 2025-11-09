use aptos_rust_sdk_types::api_types::chain_id::ChainId;
use url::Url;

const MAINNET_REST_URL: &str = "https://api.mainnet.aptoslabs.com";
const TESTNET_REST_URL: &str = "https://api.testnet.aptoslabs.com";
const DEVNET_REST_URL: &str = "https://api.devnet.aptoslabs.com";
const LOCAL_REST_URL: &str = "http://127.0.0.1:8080";

const MAINNET_INDEXER_URL: &str = "https://api.mainnet.aptoslabs.com";
const TESTNET_INDEXER_URL: &str = "https://api.testnet.aptoslabs.com";
const DEVNET_INDEXER_URL: &str = "https://api.devnet.aptoslabs.com";
const LOCAL_INDEXER_URL: &str = "http://127.0.0.1:8090";

/// An immutable definition of a network configuration
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AptosNetwork {
    name: &'static str,
    rest_url: Url,
    indexer_url: Option<Url>,
    chain_id: Option<ChainId>,
}

impl AptosNetwork {
    pub const fn new(name: &'static str, rest_url: Url, indexer_url: Option<Url>, chain_id: Option<ChainId>) -> AptosNetwork {
        AptosNetwork {
            name,
            rest_url,
            indexer_url,
            chain_id,
        }
    }

    pub fn mainnet() -> Self {
        Self::new(
            "mainnet",
            Url::parse(MAINNET_REST_URL).unwrap(),
            Some(Url::parse(MAINNET_INDEXER_URL).unwrap()),
            Some(ChainId::Mainnet),
        )
    }

    pub fn testnet() -> Self {
        Self::new(
            "testnet",
            Url::parse(TESTNET_REST_URL).unwrap(),
            Some(Url::parse(TESTNET_INDEXER_URL).unwrap()),
            Some(ChainId::Testnet),
        )
    }

    pub fn devnet() -> Self {
        Self::new(
            "devnet",
            Url::parse(DEVNET_REST_URL).unwrap(),
            Some(Url::parse(DEVNET_INDEXER_URL).unwrap()),
            None,
        )
    }

    pub fn localnet() -> Self {
        Self::new(
            "localnet",
            Url::parse(LOCAL_REST_URL).unwrap(),
            Some(Url::parse(LOCAL_INDEXER_URL).unwrap()),
            Some(ChainId::Localnet),
        )
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn rest_url(&self) -> &Url {
        &self.rest_url
    }

    pub fn indexer_url(&self) -> Option<&Url> {
        self.indexer_url.as_ref()
    }

    pub fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }
    
    pub fn with_name(mut self, name: &'static str) -> Self {
        self.name = name;
        self
    }

    pub fn with_rest_url(mut self, rest_url: Url) -> Self {
        self.rest_url = rest_url;
        self
    }

    pub fn with_indexer_url(mut self, indexer_url: Option<Url>) -> Self {
        self.indexer_url = indexer_url;
        self
    }

    pub fn with_chain_id(mut self, chain_id: Option<ChainId>) -> Self {
        self.chain_id = chain_id;
        self
    }
}
