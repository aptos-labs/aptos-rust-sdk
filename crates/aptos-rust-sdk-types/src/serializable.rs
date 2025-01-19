use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::Deserialize as BytesDeserialize;

/// Type used for serializing byte based arrays to strings
pub struct SerializableBytes(pub Vec<u8>);

impl Serialize for SerializableBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let hex_string = hex::encode(self.0.as_slice());
            serializer.serialize_str(&format!("0x{}", hex_string))
        } else {
            serializer.serialize_bytes(self.0.as_slice())
        }
    }
}

impl<'de> Deserialize<'de> for SerializableBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let string = String::deserialize(deserializer)?;
            // Strip possible 0x in front
            let parsed_str = string.strip_prefix("0x").unwrap_or(string.as_str());
            hex::decode(parsed_str).map_err(serde::de::Error::custom)?
        } else {
            <Vec<u8> as serde_bytes::Deserialize>::deserialize(deserializer)
                .map_err(serde::de::Error::custom)?
        };
        Ok(SerializableBytes(bytes))
    }
}

impl AsRef<[u8]> for SerializableBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Type used for serializing fixed length arrays to strings
pub struct SerializableFixedBytes<const LENGTH: usize>(pub [u8; LENGTH]);

impl<const LENGTH: usize> Serialize for SerializableFixedBytes<LENGTH> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let hex_string = hex::encode(self.0);
            serializer.serialize_str(&format!("0x{}", hex_string))
        } else {
            serializer.serialize_bytes(self.0.as_slice())
        }
    }
}

impl<'de, const LENGTH: usize> Deserialize<'de> for SerializableFixedBytes<LENGTH> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let string = String::deserialize(deserializer)?;
            // Strip possible 0x in front
            let parsed_str = string.strip_prefix("0x").unwrap_or(string.as_str());
            let vec = hex::decode(parsed_str).map_err(serde::de::Error::custom)?;
            vec.try_into()
                .map_err(|vec| serde::de::Error::custom(format!("{:?}", vec)))?
        } else {
            <[u8; LENGTH]>::deserialize(deserializer).map_err(serde::de::Error::custom)?
        };
        Ok(SerializableFixedBytes(bytes))
    }
}

impl<const LENGTH: usize> AsRef<[u8; LENGTH]> for SerializableFixedBytes<LENGTH> {
    fn as_ref(&self) -> &[u8; LENGTH] {
        &self.0
    }
}
