use hex::FromHex;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AccountAddressParseError {
    #[error("Account address hex characters are invalid: {0}")]
    InvalidHexChars(String),
}

/// Represents an Aptos AccountAddress
///
/// An [`AccountAddress`] is underneath just a fixed 32 byte length.
#[derive(Ord, PartialOrd, Eq, PartialEq, Hash, Clone, Copy)]
pub struct AccountAddress([u8; AccountAddress::LENGTH]);

impl AccountAddress {
    /// The number of bytes in an address.
    pub const LENGTH: usize = 32;

    /// Hex address: 0x0
    pub const ZERO: Self = Self([0x00; Self::LENGTH]);
    /// Hex address: 0x1
    pub const ONE: Self = Self::get_byte_address(1);
    /// Hex address: 0x2
    pub const TWO: Self = Self::get_byte_address(2);
    /// Hex address: 0x3
    pub const THREE: Self = Self::get_byte_address(3);
    /// Hex address: 0x4
    pub const FOUR: Self = Self::get_byte_address(4);
    /// Max address: 0xff....
    pub const MAX_ADDRESS: Self = Self([0xFF; Self::LENGTH]);

    /// Creates an address form the raw bytes
    pub const fn new(address: [u8; Self::LENGTH]) -> Self {
        Self(address)
    }

    /// Helper function to create static single byte addresses
    const fn get_byte_address(byte: u8) -> Self {
        let mut addr = [0u8; AccountAddress::LENGTH];
        addr[AccountAddress::LENGTH - 1] = byte;
        Self(addr)
    }

    pub const fn to_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Debug for AccountAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self) // Default to use the Display implementation
    }
}

impl Display for AccountAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

impl FromStr for AccountAddress {
    type Err = AccountAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // We have to be pretty permissive here.
        // TODO: we should probably... prevent shorts without 0x
        let literal = s.strip_prefix("0x").unwrap_or(s);

        // Verify the hex string
        let hex_len = literal.len();

        // If the string is too short, pad it
        let hex_str = if hex_len < Self::LENGTH * 2 {
            let mut hex_str = String::with_capacity(Self::LENGTH * 2);
            for _ in 0..Self::LENGTH * 2 - hex_len {
                hex_str.push('0');
            }
            hex_str.push_str(&literal[2..]);
            hex_str
        } else {
            literal.to_string()
        };

        // Convert from hex string
        <[u8; Self::LENGTH]>::from_hex(hex_str)
            .map_err(|e| AccountAddressParseError::InvalidHexChars(format!("{:#}", e)))
            .map(Self)
    }
}

impl fmt::LowerHex for AccountAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }

        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }

        Ok(())
    }
}

impl fmt::UpperHex for AccountAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }

        for byte in &self.0 {
            write!(f, "{:02X}", byte)?;
        }

        Ok(())
    }
}

impl<'de> Deserialize<'de> for AccountAddress {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <String>::deserialize(deserializer)?;
            AccountAddress::from_str(&s).map_err(D::Error::custom)
        } else {
            // In order to preserve the Serde data model and help analysis tools,
            // make sure to wrap our value in a container with the same name
            // as the original type.
            #[derive(::serde::Deserialize)]
            #[serde(rename = "AccountAddress")]
            struct Value([u8; AccountAddress::LENGTH]);

            let value = Value::deserialize(deserializer)?;
            Ok(AccountAddress::new(value.0))
        }
    }
}

impl Serialize for AccountAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // TODO: We differ from the aptos core representation, by appending 0x (does it matter as it should be parsed)
            self.to_string().serialize(serializer)
        } else {
            // See comment in deserialize.
            serializer.serialize_newtype_struct("AccountAddress", &self.0)
        }
    }
}
