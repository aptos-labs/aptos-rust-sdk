use crate::crypto::common::to_hex_string;
use crate::crypto::ed25519::signature::Ed25519Signature;
use crate::crypto::traits::PublicKey;
use crate::serializable::SerializableFixedBytes;
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Display, Formatter};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Ed25519PublicKey(VerifyingKey);

impl Serialize for Ed25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerializableFixedBytes(self.0.to_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = SerializableFixedBytes::<32>::deserialize(deserializer)?;
        VerifyingKey::from_bytes(bytes.as_ref())
            .map(|v| Ed25519PublicKey(v))
            .map_err(Error::custom)
    }
}

impl From<VerifyingKey> for Ed25519PublicKey {
    fn from(value: VerifyingKey) -> Self {
        Ed25519PublicKey(value)
    }
}

impl TryFrom<&str> for Ed25519PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        Ed25519PublicKey::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = bytes.try_into()?;

        Ok(Ed25519PublicKey(VerifyingKey::from_bytes(bytes)?))
    }
}

impl TryFrom<&[u8; 32]> for Ed25519PublicKey {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        Ok(Ed25519PublicKey(VerifyingKey::from_bytes(bytes)?))
    }
}

impl PublicKey<Ed25519Signature> for Ed25519PublicKey {
    fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> anyhow::Result<()> {
        Ok(self.0.verify(message, signature.inner())?)
    }
}

impl Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&to_hex_string(self.0.as_bytes()))
    }
}

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl Into<Vec<u8>> for &Ed25519PublicKey {
    fn into(self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
}
