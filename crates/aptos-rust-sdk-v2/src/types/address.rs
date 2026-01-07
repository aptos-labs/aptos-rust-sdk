//! Account address type.
//!
//! Aptos account addresses are 32-byte values, typically displayed as
//! 64 hexadecimal characters with a `0x` prefix.

use crate::error::{AptosError, AptosResult};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// The length of an account address in bytes.
pub const ADDRESS_LENGTH: usize = 32;

/// A 32-byte Aptos account address.
///
/// Account addresses on Aptos are derived from public keys through a
/// specific derivation scheme that includes an authentication key prefix.
///
/// # Display Format
///
/// Addresses are typically displayed as 64 hexadecimal characters with a
/// `0x` prefix. Short addresses (like `0x1` for the core framework) are
/// zero-padded on the left.
///
/// # Example
///
/// ```rust
/// use aptos_rust_sdk_v2::AccountAddress;
///
/// // Parse from hex string
/// let addr = AccountAddress::from_hex("0x1").unwrap();
/// assert_eq!(addr.to_string(), "0x0000000000000000000000000000000000000000000000000000000000000001");
///
/// // Short display format
/// assert_eq!(addr.to_short_string(), "0x1");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountAddress([u8; ADDRESS_LENGTH]);

impl AccountAddress {
    /// The "zero" address (all zeros).
    pub const ZERO: Self = Self([0u8; ADDRESS_LENGTH]);

    /// The core framework address (0x1).
    pub const ONE: Self = Self::from_u64(1);

    /// The token framework address (0x3).
    pub const THREE: Self = Self::from_u64(3);

    /// The fungible asset framework address (0x4).
    pub const FOUR: Self = Self::from_u64(4);

    /// Creates an address from a byte array.
    pub const fn new(bytes: [u8; ADDRESS_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates an address from a u64 value (for small addresses like 0x1).
    const fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; ADDRESS_LENGTH];
        let value_bytes = value.to_be_bytes();
        bytes[ADDRESS_LENGTH - 8] = value_bytes[0];
        bytes[ADDRESS_LENGTH - 7] = value_bytes[1];
        bytes[ADDRESS_LENGTH - 6] = value_bytes[2];
        bytes[ADDRESS_LENGTH - 5] = value_bytes[3];
        bytes[ADDRESS_LENGTH - 4] = value_bytes[4];
        bytes[ADDRESS_LENGTH - 3] = value_bytes[5];
        bytes[ADDRESS_LENGTH - 2] = value_bytes[6];
        bytes[ADDRESS_LENGTH - 1] = value_bytes[7];
        Self(bytes)
    }

    /// Creates an address from a hex string (with or without `0x` prefix).
    ///
    /// The hex string must contain at least one hex digit. Empty strings and
    /// bare "0x" prefixes are rejected as invalid addresses.
    pub fn from_hex<T: AsRef<[u8]>>(hex_str: T) -> AptosResult<Self> {
        let hex_str = hex_str.as_ref();

        // Reject empty input
        if hex_str.is_empty() {
            return Err(AptosError::InvalidAddress(
                "address cannot be empty".to_string(),
            ));
        }

        let hex_str = if hex_str.starts_with(b"0x") || hex_str.starts_with(b"0X") {
            &hex_str[2..]
        } else {
            hex_str
        };

        // Handle short addresses by zero-padding
        let hex_string = std::str::from_utf8(hex_str)
            .map_err(|e| AptosError::InvalidAddress(e.to_string()))?;

        // Reject empty hex string (e.g., just "0x" prefix with no digits)
        if hex_string.is_empty() {
            return Err(AptosError::InvalidAddress(
                "address must contain at least one hex digit".to_string(),
            ));
        }

        if hex_string.len() > ADDRESS_LENGTH * 2 {
            return Err(AptosError::InvalidAddress(format!(
                "address too long: {} characters (max {})",
                hex_string.len(),
                ADDRESS_LENGTH * 2
            )));
        }

        // Zero-pad to full length
        let padded = format!("{:0>64}", hex_string);
        let bytes = hex::decode(&padded)?;

        let mut address = [0u8; ADDRESS_LENGTH];
        address.copy_from_slice(&bytes);
        Ok(Self(address))
    }

    /// Creates an address from a byte slice.
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> AptosResult<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() != ADDRESS_LENGTH {
            return Err(AptosError::InvalidAddress(format!(
                "expected {} bytes, got {}",
                ADDRESS_LENGTH,
                bytes.len()
            )));
        }
        let mut address = [0u8; ADDRESS_LENGTH];
        address.copy_from_slice(bytes);
        Ok(Self(address))
    }

    /// Returns the address as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the address as a byte array.
    pub fn to_bytes(&self) -> [u8; ADDRESS_LENGTH] {
        self.0
    }

    /// Returns the address as a hex string with `0x` prefix.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Returns a short hex string, trimming leading zeros.
    ///
    /// For example, `0x0000...0001` becomes `0x1`.
    pub fn to_short_string(&self) -> String {
        let hex = hex::encode(self.0);
        let trimmed = hex.trim_start_matches('0');
        if trimmed.is_empty() {
            "0x0".to_string()
        } else {
            format!("0x{}", trimmed)
        }
    }

    /// Returns true if this is the zero address.
    pub fn is_zero(&self) -> bool {
        self == &Self::ZERO
    }

    /// Returns true if this is a "special" address (first 63 bytes are zero,
    /// and the last byte is non-zero and less than 16).
    ///
    /// Special addresses include framework addresses like 0x1, 0x3, 0x4.
    pub fn is_special(&self) -> bool {
        self.0[..ADDRESS_LENGTH - 1].iter().all(|&b| b == 0)
            && self.0[ADDRESS_LENGTH - 1] > 0
            && self.0[ADDRESS_LENGTH - 1] < 16
    }
}

impl Default for AccountAddress {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Debug for AccountAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountAddress({})", self.to_short_string())
    }
}

impl fmt::Display for AccountAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for AccountAddress {
    type Err = AptosError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl Serialize for AccountAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            // BCS serialization: fixed-size array without length prefix
            // Use tuple serialization to serialize each byte individually
            use serde::ser::SerializeTuple;
            let mut tuple = serializer.serialize_tuple(ADDRESS_LENGTH)?;
            for byte in &self.0 {
                tuple.serialize_element(byte)?;
            }
            tuple.end()
        }
    }
}

impl<'de> Deserialize<'de> for AccountAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <[u8; ADDRESS_LENGTH]>::deserialize(deserializer)?;
            Ok(Self(bytes))
        }
    }
}

impl From<[u8; ADDRESS_LENGTH]> for AccountAddress {
    fn from(bytes: [u8; ADDRESS_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl From<AccountAddress> for [u8; ADDRESS_LENGTH] {
    fn from(addr: AccountAddress) -> Self {
        addr.0
    }
}

impl AsRef<[u8]> for AccountAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_hex() {
        // Full address
        let addr = AccountAddress::from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert_eq!(addr, AccountAddress::ONE);

        // Short address
        let addr = AccountAddress::from_hex("0x1").unwrap();
        assert_eq!(addr, AccountAddress::ONE);

        // Without prefix
        let addr = AccountAddress::from_hex("1").unwrap();
        assert_eq!(addr, AccountAddress::ONE);
    }

    #[test]
    fn test_to_string() {
        assert_eq!(
            AccountAddress::ONE.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(AccountAddress::ONE.to_short_string(), "0x1");
        assert_eq!(AccountAddress::ZERO.to_short_string(), "0x0");
    }

    #[test]
    fn test_special_addresses() {
        assert!(AccountAddress::ONE.is_special());
        assert!(AccountAddress::THREE.is_special());
        assert!(AccountAddress::FOUR.is_special());
        assert!(!AccountAddress::ZERO.is_special());
    }

    #[test]
    fn test_json_serialization() {
        let addr = AccountAddress::ONE;
        let json = serde_json::to_string(&addr).unwrap();
        assert_eq!(
            json,
            "\"0x0000000000000000000000000000000000000000000000000000000000000001\""
        );

        let parsed: AccountAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_from_str() {
        let addr: AccountAddress = "0x1".parse().unwrap();
        assert_eq!(addr, AccountAddress::ONE);
    }

    #[test]
    fn test_from_bytes() {
        let bytes = [0u8; ADDRESS_LENGTH];
        let addr = AccountAddress::new(bytes);
        assert_eq!(addr, AccountAddress::ZERO);
    }

    #[test]
    fn test_as_bytes() {
        let addr = AccountAddress::ONE;
        let bytes = addr.as_bytes();
        assert_eq!(bytes.len(), ADDRESS_LENGTH);
        assert_eq!(bytes[ADDRESS_LENGTH - 1], 1);
    }

    #[test]
    fn test_is_zero() {
        assert!(AccountAddress::ZERO.is_zero());
        assert!(!AccountAddress::ONE.is_zero());
    }

    #[test]
    fn test_debug() {
        let addr = AccountAddress::ONE;
        let debug = format!("{:?}", addr);
        assert!(debug.contains("AccountAddress"));
    }

    #[test]
    fn test_display() {
        let addr = AccountAddress::ONE;
        let display = format!("{}", addr);
        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 66);
    }

    #[test]
    fn test_from_hex_uppercase() {
        let addr = AccountAddress::from_hex("0X1").unwrap();
        assert_eq!(addr, AccountAddress::ONE);
    }

    #[test]
    fn test_from_hex_invalid() {
        let result = AccountAddress::from_hex("not_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_into_array() {
        let addr = AccountAddress::new([42u8; ADDRESS_LENGTH]);
        let bytes: [u8; ADDRESS_LENGTH] = addr.into();
        assert_eq!(bytes, [42u8; ADDRESS_LENGTH]);
    }

    #[test]
    fn test_as_ref() {
        let addr = AccountAddress::ONE;
        let slice: &[u8] = addr.as_ref();
        assert_eq!(slice.len(), ADDRESS_LENGTH);
    }

    #[test]
    fn test_equality() {
        assert_eq!(AccountAddress::ONE, AccountAddress::ONE);
        assert_ne!(AccountAddress::ONE, AccountAddress::THREE);
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AccountAddress::ONE);
        set.insert(AccountAddress::THREE);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&AccountAddress::ONE));
    }
}

