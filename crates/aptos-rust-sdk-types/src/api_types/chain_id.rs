use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Display};

// TODO: Handle plaintext deserialize / serialize
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ChainId {
    Mainnet = 1,
    Testnet = 2,
    Testing = 3,
    Other(u8),
}

const MAINNET: &str = "mainnet";
const TESTNET: &str = "testnet";
const TESTING: &str = "testing";

impl Debug for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self) // Use display
    }
}

impl Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainId::Mainnet => write!(f, "{}", MAINNET),
            ChainId::Testnet => write!(f, "{}", TESTNET),
            ChainId::Testing => write!(f, "{}", TESTING),
            ChainId::Other(other) => write!(f, "{}", other),
        }
    }
}

impl Serialize for ChainId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ChainId::Mainnet => serializer.serialize_u8(1),
            ChainId::Testnet => serializer.serialize_u8(2),
            ChainId::Testing => serializer.serialize_u8(3),
            ChainId::Other(inner) => serializer.serialize_u8(*inner),
        }
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let chain_id = u8::deserialize(deserializer)?;
        Ok(match chain_id {
            1 => ChainId::Mainnet,
            2 => ChainId::Testnet,
            3 => ChainId::Testing,
            other => ChainId::Other(other),
        })
    }
}
