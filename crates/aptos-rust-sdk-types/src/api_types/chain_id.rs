use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Display};

// TODO: Handle plaintext deserialize / serialize
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum ChainId {
    Mainnet,
    Testnet,
    Localnet,
    Other(u8),
}

impl ChainId {
    pub const MAINNET_ID: u8 = 1;
    pub const TESTNET_ID: u8 = 2;
    pub const LOCALNET_ID: u8 = 4;

    const MAINNET_NAME: &'static str = "mainnet";
    const TESTNET_NAME: &'static str = "testnet";
    const LOCALNET_NAME: &'static str = "localnet";

    pub const fn from_u8(raw: u8) -> Self {
        match raw {
            Self::MAINNET_ID => Self::Mainnet,
            Self::TESTNET_ID => Self::Testnet,
            Self::LOCALNET_ID => Self::Localnet,
            other => Self::Other(other),
        }
    }

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Mainnet => Self::MAINNET_ID,
            Self::Testnet => Self::TESTNET_ID,
            Self::Localnet => Self::LOCALNET_ID,
            Self::Other(other) => other,
        }
    }

    fn as_known_name(self) -> Option<&'static str> {
        match self {
            Self::Mainnet => Some(Self::MAINNET_NAME),
            Self::Testnet => Some(Self::TESTNET_NAME),
            Self::Localnet => Some(Self::LOCALNET_NAME),
            Self::Other(_) => None,
        }
    }
}

impl Debug for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self) // Use display
    }
}

impl Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.as_known_name() {
            Some(name) => write!(f, "{}", name),
            None => write!(f, "{}", self.as_u8()),
        }
    }
}

impl Serialize for ChainId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize as u8 (not string) - this is the correct format for ChainId
        // Previous implementation incorrectly used string deserialization
        Ok(Self::from_u8(u8::deserialize(deserializer)?))
    }
}

impl From<ChainId> for u8 {
    fn from(chain_id: ChainId) -> Self {
        chain_id.as_u8()
    }
}

impl From<u8> for ChainId {
    fn from(raw: u8) -> Self {
        ChainId::from_u8(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aptos_bcs;

    #[test]
    fn test_chain_id_serialization_roundtrip() {
        // Test all predefined chain IDs
        let test_cases = vec![
            ChainId::Mainnet,
            ChainId::Testnet,
            ChainId::Localnet,
            ChainId::Other(42),
            ChainId::Other(0),
            ChainId::Other(255),
        ];

        for chain_id in test_cases {
            // Test BCS serialization/deserialization
            let bcs_bytes =
                aptos_bcs::to_bytes(&chain_id).expect("BCS serialization should succeed");
            let deserialized: ChainId =
                aptos_bcs::from_bytes(&bcs_bytes).expect("BCS deserialization should succeed");
            assert_eq!(
                chain_id, deserialized,
                "ChainId should roundtrip correctly for {:?}",
                chain_id
            );
        }
    }

    #[test]
    fn test_chain_id_display() {
        assert_eq!(format!("{}", ChainId::Mainnet), "mainnet");
        assert_eq!(format!("{}", ChainId::Testnet), "testnet");
        assert_eq!(format!("{}", ChainId::Localnet), "localnet");
        assert_eq!(format!("{}", ChainId::Other(42)), "42");
    }

    #[test]
    fn test_chain_id_constants_consistency() {
        // Verify that the constants match the expected values
        assert_eq!(ChainId::MAINNET_ID, 1);
        assert_eq!(ChainId::TESTNET_ID, 2);
        assert_eq!(ChainId::LOCALNET_ID, 4);

        // Test that BCS serialization produces the expected byte values
        let mainnet_bcs = aptos_bcs::to_bytes(&ChainId::Mainnet).unwrap();
        assert_eq!(mainnet_bcs, vec![ChainId::MAINNET_ID]);

        let testnet_bcs = aptos_bcs::to_bytes(&ChainId::Testnet).unwrap();
        assert_eq!(testnet_bcs, vec![ChainId::TESTNET_ID]);

        let testing_bcs = aptos_bcs::to_bytes(&ChainId::Localnet).unwrap();
        assert_eq!(testing_bcs, vec![ChainId::LOCALNET_ID]);
    }

    #[test]
    fn test_chain_id_deserialization_from_values() {
        // Test BCS deserialization from specific byte values
        let mainnet: ChainId = aptos_bcs::from_bytes(&[1]).unwrap();
        assert_eq!(mainnet, ChainId::Mainnet);

        let testnet: ChainId = aptos_bcs::from_bytes(&[2]).unwrap();
        assert_eq!(testnet, ChainId::Testnet);

        let localnet: ChainId = aptos_bcs::from_bytes(&[4]).unwrap();
        assert_eq!(localnet, ChainId::Localnet);

        let other: ChainId = aptos_bcs::from_bytes(&[42]).unwrap();
        assert_eq!(other, ChainId::Other(42));
    }
}
