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

// Chain ID values
const MAINNET_ID: u8 = 1;
const TESTNET_ID: u8 = 2;
const TESTING_ID: u8 = 3;

// Chain name strings
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
            ChainId::Mainnet => serializer.serialize_u8(MAINNET_ID),
            ChainId::Testnet => serializer.serialize_u8(TESTNET_ID),
            ChainId::Testing => serializer.serialize_u8(TESTING_ID),
            ChainId::Other(inner) => serializer.serialize_u8(*inner),
        }
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize as u8 (not string) - this is the correct format for ChainId
        // Previous implementation incorrectly used string deserialization
        let chain_id = u8::deserialize(deserializer)?;
        Ok(match chain_id {
            MAINNET_ID => ChainId::Mainnet,
            TESTNET_ID => ChainId::Testnet,
            TESTING_ID => ChainId::Testing,
            other => ChainId::Other(other),
        })
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
            ChainId::Testing,
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
        assert_eq!(format!("{}", ChainId::Testing), "testing");
        assert_eq!(format!("{}", ChainId::Other(42)), "42");
    }

    #[test]
    fn test_chain_id_constants_consistency() {
        // Verify that the constants match the expected values
        assert_eq!(MAINNET_ID, 1);
        assert_eq!(TESTNET_ID, 2);
        assert_eq!(TESTING_ID, 3);

        // Test that BCS serialization produces the expected byte values
        let mainnet_bcs = aptos_bcs::to_bytes(&ChainId::Mainnet).unwrap();
        assert_eq!(mainnet_bcs, vec![MAINNET_ID]);

        let testnet_bcs = aptos_bcs::to_bytes(&ChainId::Testnet).unwrap();
        assert_eq!(testnet_bcs, vec![TESTNET_ID]);

        let testing_bcs = aptos_bcs::to_bytes(&ChainId::Testing).unwrap();
        assert_eq!(testing_bcs, vec![TESTING_ID]);
    }

    #[test]
    fn test_chain_id_deserialization_from_values() {
        // Test BCS deserialization from specific byte values
        let mainnet: ChainId = aptos_bcs::from_bytes(&[1]).unwrap();
        assert_eq!(mainnet, ChainId::Mainnet);

        let testnet: ChainId = aptos_bcs::from_bytes(&[2]).unwrap();
        assert_eq!(testnet, ChainId::Testnet);

        let testing: ChainId = aptos_bcs::from_bytes(&[3]).unwrap();
        assert_eq!(testing, ChainId::Testing);

        let other: ChainId = aptos_bcs::from_bytes(&[42]).unwrap();
        assert_eq!(other, ChainId::Other(42));
    }
}
