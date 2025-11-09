use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Eq, PartialOrd, PartialEq, Ord, Hash)]
pub struct U64(u64);

impl Serialize for U64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for U64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        u64::from_str(&string)
            .map(|inner| U64(inner))
            .map_err(|err| D::Error::custom(err.to_string()))
    }
}

impl U64 {
    /// Get the inner u64 value
    pub fn as_u64(&self) -> u64 {
        self.0
    }
    
    /// Convert into u64
    pub fn into_u64(self) -> u64 {
        self.0
    }
    
    /// Create a new U64 from a u64
    pub fn new(value: u64) -> Self {
        U64(value)
    }
}
