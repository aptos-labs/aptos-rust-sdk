use serde::{Deserialize, Deserializer, Serializer};
use serde_bytes::Serialize;
use std::fmt::{Debug, Display};
use std::str::FromStr;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ChainId {
    Mainnet = 0,
    Testnet = 1,
    Testing = 2,
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
            ChainId::Mainnet => serializer.serialize_str(MAINNET),
            ChainId::Testnet => serializer.serialize_str(TESTNET),
            ChainId::Testing => serializer.serialize_str(TESTING),
            ChainId::Other(inner) => serializer.serialize_str(&inner.to_string()),
        }
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        Ok(match &str {
            MAINNET => ChainId::Mainnet,
            TESTNET => ChainId::Testnet,
            TESTING => ChainId::Testing,
            other => ChainId::Other(u8::from_str(other)?),
        })
    }
}
