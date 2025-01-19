use crate::crypto::common::to_hex_string;
use crate::crypto::secp256k1::private_key::bytes_to_message;
use crate::crypto::secp256k1::signature::Secp256k1Signature;
use crate::crypto::traits::PublicKey;
use anyhow::anyhow;
use std::fmt::{Debug, Display, Formatter};

#[derive(Clone)]
pub struct Secp256k1PublicKey(libsecp256k1::PublicKey);

impl From<libsecp256k1::PublicKey> for Secp256k1PublicKey {
    fn from(value: libsecp256k1::PublicKey) -> Self {
        Secp256k1PublicKey(value)
    }
}

impl TryFrom<&[u8; 65]> for Secp256k1PublicKey {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8; 65]) -> Result<Self, Self::Error> {
        Ok(Secp256k1PublicKey(libsecp256k1::PublicKey::parse(bytes)?))
    }
}

impl PublicKey<Secp256k1Signature> for Secp256k1PublicKey {
    fn verify<T: AsRef<[u8]>>(
        &self,
        message: T,
        signature: &Secp256k1Signature,
    ) -> anyhow::Result<()> {
        // Prevent malleability attacks, low order only. The library only signs in low
        // order, so this was done intentionally.

        let inner_signature = signature.inner();
        if inner_signature.s.is_high() {
            Err(anyhow!("Canonical representation error"))
        } else if libsecp256k1::verify(&bytes_to_message(message)?, inner_signature, &self.0) {
            Ok(())
        } else {
            Err(anyhow!("Unable to verify signature."))
        }
    }
}

impl Debug for Secp256k1PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for Secp256k1PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&to_hex_string(&self.0.serialize()))
    }
}
