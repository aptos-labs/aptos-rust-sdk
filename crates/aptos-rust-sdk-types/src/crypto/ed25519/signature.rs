use crate::crypto::traits::Signature;
use crate::serializable::SerializableFixedBytes;
use anyhow::anyhow;
use ed25519_dalek::ed25519::SignatureBytes;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};

const L: [u8; 32] = [
    0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[derive(Clone, Eq, PartialEq)]
pub struct Ed25519Signature(ed25519_dalek::Signature);

impl Ed25519Signature {
    pub(crate) fn inner(&self) -> &ed25519_dalek::Signature {
        &self.0
    }
}

impl Hash for Ed25519Signature {
    // TODO: This is a hack for now
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner().to_vec().hash(state);
    }
}

impl TryFrom<[u8; 64]> for Ed25519Signature {
    type Error = anyhow::Error;

    fn try_from(bytes: [u8; 64]) -> anyhow::Result<Self> {
        if !check_signature_canonical(&bytes[32..]) {
            return Err(anyhow! {"Non-canonical signature"});
        }

        Ok(Ed25519Signature(ed25519_dalek::Signature::from_bytes(
            &SignatureBytes::from(bytes),
        )))
    }
}

impl From<ed25519_dalek::Signature> for Ed25519Signature {
    fn from(signature: ed25519_dalek::Signature) -> Self {
        Ed25519Signature(signature)
    }
}

impl Signature for Ed25519Signature {}

impl Debug for Ed25519Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for Ed25519Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.to_bytes().as_slice()))
    }
}

impl Serialize for Ed25519Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerializableFixedBytes(self.inner().to_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Ed25519Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SerializableFixedBytes::<64>::deserialize(deserializer)
            .map_err(Error::custom)
            .and_then(|bytes| Ed25519Signature::try_from(bytes.0).map_err(Error::custom))
    }
}

impl Into<Vec<u8>> for &Ed25519Signature {
    fn into(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

pub fn check_signature_canonical(s: &[u8]) -> bool {
    for i in (0..32).rev() {
        match s[i].cmp(&L[i]) {
            Ordering::Less => return true,
            Ordering::Greater => return false,
            _ => {}
        }
    }
    // As this stage S == L which implies a non-canonical S.
    false
}

pub fn non_canonical_signature() -> [u8; 64] {
    let vec: Vec<u8> = vec![L, L].into_iter().flatten().collect();
    vec.try_into().unwrap()
}
