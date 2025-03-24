use crate::crypto::ed25519::public_key::Ed25519PublicKey;
use crate::crypto::ed25519::signature::Ed25519Signature;
use crate::crypto::traits::PrivateKey;
use ed25519_dalek::Signer;
use hex::FromHex;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

pub struct Ed25519PrivateKey(SigningKey);

impl From<[u8; 32]> for Ed25519PrivateKey {
    fn from(bytes: [u8; 32]) -> Self {
        Ed25519PrivateKey(ed25519_dalek::SigningKey::from(bytes))
    }
}

impl From<SigningKey> for Ed25519PrivateKey {
    fn from(signing_key: SigningKey) -> Self {
        Ed25519PrivateKey(signing_key)
    }
}

impl PrivateKey<Ed25519PublicKey, Ed25519Signature> for Ed25519PrivateKey {
    fn sign<T: AsRef<[u8]>>(&self, bytes: T) -> Ed25519Signature {
        let signature = self.0.sign(bytes.as_ref());
        Ed25519Signature::from(signature)
    }

    fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey::from(self.0.verifying_key())
    }
}

impl Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for Ed25519PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("REDACTED_PRIVATE_KEY")
    }
}

impl FromStr for Ed25519PrivateKey {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let hex_chars = input.strip_prefix("0x").unwrap_or(input);
        let bytes = <[u8; 32]>::from_hex(hex_chars)?;

        Ok(Ed25519PrivateKey::from(bytes))
    }
}
