use crate::crypto::hash::HashValue;
use crate::crypto::secp256k1::public_key::Secp256k1PublicKey;
use crate::crypto::secp256k1::signature::Secp256k1Signature;
use crate::crypto::traits::PrivateKey;
use hex::FromHex;
use libsecp256k1::SecretKey;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

pub struct Secp256k1PrivateKey(SecretKey);

impl TryFrom<&[u8; 32]> for Secp256k1PrivateKey {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8; 32]) -> anyhow::Result<Self> {
        Ok(Secp256k1PrivateKey(SecretKey::parse(bytes)?))
    }
}

impl From<SecretKey> for Secp256k1PrivateKey {
    fn from(key: SecretKey) -> Self {
        Secp256k1PrivateKey(key)
    }
}

impl PrivateKey<Secp256k1PublicKey, Secp256k1Signature> for Secp256k1PrivateKey {
    fn sign<T: AsRef<[u8]>>(&self, bytes: T) -> Secp256k1Signature {
        let message = bytes_to_message(bytes).expect("SHA3-256 should never fail");
        let (signature, _) = libsecp256k1::sign(&message, &self.0);
        Secp256k1Signature::from(signature)
    }

    fn public_key(&self) -> Secp256k1PublicKey {
        Secp256k1PublicKey::from(libsecp256k1::PublicKey::from_secret_key(&self.0))
    }
}

impl Debug for Secp256k1PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for Secp256k1PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("REDACTED_PRIVATE_KEY")
    }
}

impl FromStr for Secp256k1PrivateKey {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let hex_chars = input.strip_prefix("0x").unwrap_or(input);
        let bytes = <[u8; 32]>::from_hex(hex_chars)?;

        Secp256k1PrivateKey::try_from(&bytes)
    }
}

pub fn bytes_to_message<T: AsRef<[u8]>>(message: T) -> anyhow::Result<libsecp256k1::Message> {
    let message_digest = HashValue::sha3_256(message.as_ref());
    Ok(libsecp256k1::Message::parse_slice(
        message_digest.as_slice(),
    )?)
}
