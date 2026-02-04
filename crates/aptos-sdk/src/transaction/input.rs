//! Type-safe entry function payload builders.
//!
//! This module provides ergonomic builders for constructing entry function
//! payloads with automatic BCS encoding of arguments.
//!
//! # Overview
//!
//! `InputEntryFunctionData` provides a builder pattern that:
//! - Accepts Rust types directly (no manual BCS encoding)
//! - Validates function IDs at construction
//! - Supports all Move types
//!
//! # Example
//!
//! ```rust,ignore
//! use aptos_sdk::transaction::InputEntryFunctionData;
//!
//! // Simple transfer
//! let payload = InputEntryFunctionData::new("0x1::aptos_account::transfer")
//!     .arg(recipient_address)
//!     .arg(1_000_000u64)
//!     .build()?;
//!
//! // Generic function with type args
//! let payload = InputEntryFunctionData::new("0x1::coin::transfer")
//!     .type_arg("0x1::aptos_coin::AptosCoin")
//!     .arg(recipient_address)
//!     .arg(amount)
//!     .build()?;
//! ```

use crate::error::{AptosError, AptosResult};
use crate::transaction::{EntryFunction, TransactionPayload};
use crate::types::{AccountAddress, EntryFunctionId, MoveModuleId, TypeTag};
use serde::Serialize;

/// A type-safe builder for entry function payloads.
///
/// This builder provides an ergonomic way to construct entry function calls
/// with automatic BCS encoding of arguments.
///
/// # Example
///
/// ```rust,ignore
/// use aptos_sdk::transaction::InputEntryFunctionData;
/// use aptos_sdk::types::AccountAddress;
///
/// let payload = InputEntryFunctionData::new("0x1::aptos_account::transfer")
///     .arg(AccountAddress::from_hex("0x123").unwrap())
///     .arg(1_000_000u64)  // 0.01 APT in octas
///     .build()?;
/// ```
#[allow(dead_code)] // Public API struct - fields used via builder pattern
#[derive(Debug, Clone)]
pub struct InputEntryFunctionData {
    module: MoveModuleId,
    function: String,
    type_args: Vec<TypeTag>,
    args: Vec<Vec<u8>>,
}

impl InputEntryFunctionData {
    /// Creates a new entry function data builder.
    ///
    /// # Arguments
    ///
    /// * `function_id` - The full function identifier (e.g., "`0x1::coin::transfer`")
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let builder = InputEntryFunctionData::new("0x1::aptos_account::transfer");
    /// ```
    #[allow(clippy::new_ret_no_self)] // Returns builder pattern intentionally
    pub fn new(function_id: &str) -> InputEntryFunctionDataBuilder {
        InputEntryFunctionDataBuilder::new(function_id)
    }

    /// Creates a builder from module and function name.
    ///
    /// # Arguments
    ///
    /// * `module` - The module ID
    /// * `function` - The function name
    pub fn from_parts(
        module: MoveModuleId,
        function: impl Into<String>,
    ) -> InputEntryFunctionDataBuilder {
        InputEntryFunctionDataBuilder {
            module: Ok(module),
            function: function.into(),
            type_args: Vec::new(),
            args: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Builds an APT transfer payload.
    ///
    /// # Arguments
    ///
    /// * `recipient` - The recipient address
    /// * `amount` - Amount in octas (1 APT = 10^8 octas)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let payload = InputEntryFunctionData::transfer_apt(recipient, 1_000_000)?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the function ID is invalid or if BCS encoding of arguments fails.
    pub fn transfer_apt(recipient: AccountAddress, amount: u64) -> AptosResult<TransactionPayload> {
        InputEntryFunctionData::new("0x1::aptos_account::transfer")
            .arg(recipient)
            .arg(amount)
            .build()
    }

    /// Builds a coin transfer payload for any coin type.
    ///
    /// # Arguments
    ///
    /// * `coin_type` - The coin type (e.g., "`0x1::aptos_coin::AptosCoin`")
    /// * `recipient` - The recipient address
    /// * `amount` - Amount in the coin's smallest unit
    ///
    /// # Errors
    ///
    /// Returns an error if the function ID is invalid, the coin type is invalid, or if BCS encoding of arguments fails.
    pub fn transfer_coin(
        coin_type: &str,
        recipient: AccountAddress,
        amount: u64,
    ) -> AptosResult<TransactionPayload> {
        InputEntryFunctionData::new("0x1::coin::transfer")
            .type_arg(coin_type)
            .arg(recipient)
            .arg(amount)
            .build()
    }

    /// Builds an account creation payload.
    ///
    /// # Arguments
    ///
    /// * `auth_key` - The authentication key (32 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if the function ID is invalid or if BCS encoding of arguments fails.
    pub fn create_account(auth_key: AccountAddress) -> AptosResult<TransactionPayload> {
        InputEntryFunctionData::new("0x1::aptos_account::create_account")
            .arg(auth_key)
            .build()
    }

    /// Builds a payload to rotate an account's authentication key.
    ///
    /// # Arguments
    ///
    /// * Various rotation parameters
    ///
    /// # Errors
    ///
    /// Returns an error if the function ID is invalid or if BCS encoding of arguments fails.
    pub fn rotate_authentication_key(
        from_scheme: u8,
        from_public_key_bytes: Vec<u8>,
        to_scheme: u8,
        to_public_key_bytes: Vec<u8>,
        cap_rotate_key: Vec<u8>,
        cap_update_table: Vec<u8>,
    ) -> AptosResult<TransactionPayload> {
        InputEntryFunctionData::new("0x1::account::rotate_authentication_key")
            .arg(from_scheme)
            .arg(from_public_key_bytes)
            .arg(to_scheme)
            .arg(to_public_key_bytes)
            .arg(cap_rotate_key)
            .arg(cap_update_table)
            .build()
    }

    /// Builds a payload to register a coin store.
    ///
    /// # Arguments
    ///
    /// * `coin_type` - The coin type to register
    ///
    /// # Errors
    ///
    /// Returns an error if the function ID is invalid, the coin type is invalid, or if building the payload fails.
    pub fn register_coin(coin_type: &str) -> AptosResult<TransactionPayload> {
        InputEntryFunctionData::new("0x1::managed_coin::register")
            .type_arg(coin_type)
            .build()
    }

    /// Builds a payload to publish a module.
    ///
    /// # Arguments
    ///
    /// * `metadata_serialized` - Serialized module metadata
    /// * `code` - Vector of module bytecode
    ///
    /// # Errors
    ///
    /// Returns an error if the function ID is invalid or if BCS encoding of arguments fails.
    pub fn publish_package(
        metadata_serialized: Vec<u8>,
        code: Vec<Vec<u8>>,
    ) -> AptosResult<TransactionPayload> {
        InputEntryFunctionData::new("0x1::code::publish_package_txn")
            .arg(metadata_serialized)
            .arg(code)
            .build()
    }
}

/// Builder for `InputEntryFunctionData`.
#[derive(Debug, Clone)]
pub struct InputEntryFunctionDataBuilder {
    module: Result<MoveModuleId, String>,
    function: String,
    type_args: Vec<TypeTag>,
    args: Vec<Vec<u8>>,
    errors: Vec<String>,
}

impl InputEntryFunctionDataBuilder {
    /// Creates a new builder from a function ID string.
    #[must_use]
    fn new(function_id: &str) -> Self {
        match EntryFunctionId::from_str_strict(function_id) {
            Ok(func_id) => Self {
                module: Ok(func_id.module),
                function: func_id.name.as_str().to_string(),
                type_args: Vec::new(),
                args: Vec::new(),
                errors: Vec::new(),
            },
            Err(e) => Self {
                module: Err(format!("Invalid function ID '{function_id}': {e}")),
                function: String::new(),
                type_args: Vec::new(),
                args: Vec::new(),
                errors: Vec::new(),
            },
        }
    }

    /// Adds a type argument.
    ///
    /// # Arguments
    ///
    /// * `type_arg` - A type tag string (e.g., "`0x1::aptos_coin::AptosCoin`")
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let builder = InputEntryFunctionData::new("0x1::coin::transfer")
    ///     .type_arg("0x1::aptos_coin::AptosCoin");
    /// ```
    #[must_use]
    pub fn type_arg(mut self, type_arg: &str) -> Self {
        match TypeTag::from_str_strict(type_arg) {
            Ok(tag) => self.type_args.push(tag),
            Err(e) => self
                .errors
                .push(format!("Invalid type argument '{type_arg}': {e}")),
        }
        self
    }

    /// Adds a type argument from a `TypeTag`.
    #[must_use]
    pub fn type_arg_typed(mut self, type_arg: TypeTag) -> Self {
        self.type_args.push(type_arg);
        self
    }

    /// Adds multiple type arguments.
    #[must_use]
    pub fn type_args(mut self, type_args: impl IntoIterator<Item = &'static str>) -> Self {
        for type_arg in type_args {
            self = self.type_arg(type_arg);
        }
        self
    }

    /// Adds multiple typed type arguments.
    #[must_use]
    pub fn type_args_typed(mut self, type_args: impl IntoIterator<Item = TypeTag>) -> Self {
        self.type_args.extend(type_args);
        self
    }

    /// Adds a BCS-encodable argument.
    ///
    /// Accepts any type that implements `Serialize` (BCS encoding).
    ///
    /// # Supported Types
    ///
    /// - Integers: `u8`, `u16`, `u32`, `u64`, `u128`
    /// - Boolean: `bool`
    /// - Strings: `String`, `&str`
    /// - Addresses: `AccountAddress`
    /// - Vectors: `Vec<T>` where T is serializable
    /// - Bytes: `Vec<u8>`, `&[u8]`
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let builder = InputEntryFunctionData::new("0x1::my_module::my_function")
    ///     .arg(42u64)
    ///     .arg(true)
    ///     .arg(AccountAddress::ONE)
    ///     .arg("hello".to_string());
    /// ```
    #[must_use]
    pub fn arg<T: Serialize>(mut self, value: T) -> Self {
        match aptos_bcs::to_bytes(&value) {
            Ok(bytes) => self.args.push(bytes),
            Err(e) => self
                .errors
                .push(format!("Failed to serialize argument: {e}")),
        }
        self
    }

    /// Adds a raw BCS-encoded argument.
    ///
    /// Use this when you have pre-encoded bytes.
    #[must_use]
    pub fn arg_raw(mut self, bytes: Vec<u8>) -> Self {
        self.args.push(bytes);
        self
    }

    /// Adds multiple BCS-encodable arguments.
    #[must_use]
    pub fn args<T: Serialize>(mut self, values: impl IntoIterator<Item = T>) -> Self {
        for value in values {
            self = self.arg(value);
        }
        self
    }

    /// Builds the transaction payload.
    ///
    /// # Returns
    ///
    /// The constructed `TransactionPayload`, or an error if any
    /// validation or serialization failed.
    ///
    /// # Errors
    ///
    /// Returns an error if the function ID is invalid, any type argument is invalid, or if any argument serialization failed.
    pub fn build(self) -> AptosResult<TransactionPayload> {
        // Check for module parsing error
        let module = self.module.map_err(AptosError::Transaction)?;

        // Check for any accumulated errors
        if !self.errors.is_empty() {
            return Err(AptosError::Transaction(self.errors.join("; ")));
        }

        Ok(TransactionPayload::EntryFunction(EntryFunction {
            module,
            function: self.function,
            type_args: self.type_args,
            args: self.args,
        }))
    }

    /// Builds just the entry function (without wrapping in `TransactionPayload`).
    ///
    /// # Errors
    ///
    /// Returns an error if the function ID is invalid, any type argument is invalid, or if any argument serialization failed.
    pub fn build_entry_function(self) -> AptosResult<EntryFunction> {
        let module = self.module.map_err(AptosError::Transaction)?;

        if !self.errors.is_empty() {
            return Err(AptosError::Transaction(self.errors.join("; ")));
        }

        Ok(EntryFunction {
            module,
            function: self.function,
            type_args: self.type_args,
            args: self.args,
        })
    }
}

/// Trait for types that can be converted to entry function arguments.
///
/// This trait is automatically implemented for types that implement `Serialize`.
pub trait IntoMoveArg {
    /// Converts this value into BCS-encoded bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if BCS serialization fails.
    fn into_move_arg(self) -> AptosResult<Vec<u8>>;
}

impl<T: Serialize> IntoMoveArg for T {
    fn into_move_arg(self) -> AptosResult<Vec<u8>> {
        aptos_bcs::to_bytes(&self).map_err(AptosError::bcs)
    }
}

/// Helper to create a vector argument for Move functions.
///
/// Move vectors are BCS-encoded with a length prefix followed by elements.
///
/// # Example
///
/// ```rust,ignore
/// let addresses = move_vec(&[addr1, addr2, addr3]);
/// let amounts = move_vec(&[100u64, 200u64, 300u64]);
/// ```
pub fn move_vec<T: Serialize>(items: &[T]) -> Vec<u8> {
    aptos_bcs::to_bytes(items).unwrap_or_default()
}

/// Helper to create a string argument for Move functions.
///
/// Move strings are UTF-8 encoded vectors of bytes.
///
/// # Example
///
/// ```rust,ignore
/// let name = move_string("Alice");
/// ```
pub fn move_string(s: &str) -> String {
    s.to_string()
}

/// Helper to create an `Option::Some` argument for Move.
///
/// # Example
///
/// ```rust,ignore
/// let maybe_value = move_some(42u64);
/// ```
pub fn move_some<T: Serialize>(value: T) -> Vec<u8> {
    // BCS encodes Option as: 0x01 followed by the value bytes for Some
    let mut bytes = vec![0x01];
    if let Ok(value_bytes) = aptos_bcs::to_bytes(&value) {
        bytes.extend(value_bytes);
    }
    bytes
}

/// Helper to create an `Option::None` argument for Move.
///
/// # Example
///
/// ```rust,ignore
/// let maybe_value: Vec<u8> = move_none();
/// ```
pub fn move_none() -> Vec<u8> {
    // BCS encodes Option as: 0x00 for None
    vec![0x00]
}

/// A u256 value for Move arguments.
///
/// Move's u256 is a 256-bit unsigned integer, represented as 32 bytes in little-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveU256(pub [u8; 32]);

impl MoveU256 {
    /// Creates a `MoveU256` from a decimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string cannot be parsed as a u256 value.
    pub fn parse(s: &str) -> AptosResult<Self> {
        // Parse as big integer and convert to little-endian bytes
        let mut bytes = [0u8; 32];

        // Simple parsing for small values
        if let Ok(val) = s.parse::<u128>() {
            bytes[..16].copy_from_slice(&val.to_le_bytes());
            return Ok(Self(bytes));
        }

        Err(AptosError::Transaction(format!("Invalid u256: {s}")))
    }

    /// Creates a `MoveU256` from a u128.
    pub fn from_u128(val: u128) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&val.to_le_bytes());
        Self(bytes)
    }

    /// Creates a `MoveU256` from raw bytes (little-endian).
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Serialize for MoveU256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // BCS serializes u256 as 32 little-endian bytes (as a tuple of bytes, not a vec)
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(32)?;
        for byte in &self.0 {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
}

/// An i128 value for Move arguments.
///
/// Move's i128 is a 128-bit signed integer, represented as 16 bytes in little-endian
/// using two's complement representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveI128(pub i128);

impl MoveI128 {
    /// Creates a new `MoveI128` from an i128 value.
    pub fn new(val: i128) -> Self {
        Self(val)
    }
}

impl Serialize for MoveI128 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // BCS serializes i128 as 16 little-endian bytes (two's complement)
        use serde::ser::SerializeTuple;
        let bytes = self.0.to_le_bytes();
        let mut tuple = serializer.serialize_tuple(16)?;
        for byte in &bytes {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
}

impl From<i128> for MoveI128 {
    fn from(val: i128) -> Self {
        Self(val)
    }
}

/// An i256 value for Move arguments.
///
/// Move's i256 is a 256-bit signed integer, represented as 32 bytes in little-endian
/// using two's complement representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveI256(pub [u8; 32]);

impl MoveI256 {
    /// Creates a `MoveI256` from an i128 value.
    pub fn from_i128(val: i128) -> Self {
        let mut bytes = [0u8; 32];
        let val_bytes = val.to_le_bytes();
        bytes[..16].copy_from_slice(&val_bytes);
        // Sign extend for negative values
        if val < 0 {
            bytes[16..].fill(0xFF);
        }
        Self(bytes)
    }

    /// Creates a `MoveI256` from raw bytes (little-endian, two's complement).
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Serialize for MoveI256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // BCS serializes i256 as 32 little-endian bytes (as a tuple of bytes, not a vec)
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(32)?;
        for byte in &self.0 {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
}

impl From<i128> for MoveI256 {
    fn from(val: i128) -> Self {
        Self::from_i128(val)
    }
}

/// Common function IDs for convenience.
pub mod functions {
    /// APT transfer function.
    pub const APT_TRANSFER: &str = "0x1::aptos_account::transfer";
    /// Coin transfer function.
    pub const COIN_TRANSFER: &str = "0x1::coin::transfer";
    /// Account creation function.
    pub const CREATE_ACCOUNT: &str = "0x1::aptos_account::create_account";
    /// Register a coin store.
    pub const REGISTER_COIN: &str = "0x1::managed_coin::register";
    /// Publish a package.
    pub const PUBLISH_PACKAGE: &str = "0x1::code::publish_package_txn";
    /// Rotate authentication key.
    pub const ROTATE_AUTH_KEY: &str = "0x1::account::rotate_authentication_key";
}

/// Common type tags for convenience.
pub mod types {
    /// APT coin type.
    pub const APT_COIN: &str = "0x1::aptos_coin::AptosCoin";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_transfer() {
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let payload = InputEntryFunctionData::new("0x1::aptos_account::transfer")
            .arg(recipient)
            .arg(1_000_000u64)
            .build()
            .unwrap();

        match payload {
            TransactionPayload::EntryFunction(ef) => {
                assert_eq!(ef.function, "transfer");
                assert_eq!(ef.module.name.as_str(), "aptos_account");
                assert!(ef.type_args.is_empty());
                assert_eq!(ef.args.len(), 2);
            }
            _ => panic!("Expected EntryFunction"),
        }
    }

    #[test]
    fn test_with_type_args() {
        let payload = InputEntryFunctionData::new("0x1::coin::transfer")
            .type_arg("0x1::aptos_coin::AptosCoin")
            .arg(AccountAddress::ONE)
            .arg(1000u64)
            .build()
            .unwrap();

        match payload {
            TransactionPayload::EntryFunction(ef) => {
                assert_eq!(ef.function, "transfer");
                assert_eq!(ef.type_args.len(), 1);
            }
            _ => panic!("Expected EntryFunction"),
        }
    }

    #[test]
    fn test_invalid_function_id() {
        let result = InputEntryFunctionData::new("invalid").arg(42u64).build();

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_type_arg() {
        let result = InputEntryFunctionData::new("0x1::coin::transfer")
            .type_arg("not a type")
            .arg(AccountAddress::ONE)
            .arg(1000u64)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_transfer_apt_helper() {
        let recipient = AccountAddress::from_hex("0x456").unwrap();
        let payload = InputEntryFunctionData::transfer_apt(recipient, 5_000_000).unwrap();

        match payload {
            TransactionPayload::EntryFunction(ef) => {
                assert_eq!(ef.function, "transfer");
                assert_eq!(ef.module.name.as_str(), "aptos_account");
            }
            _ => panic!("Expected EntryFunction"),
        }
    }

    #[test]
    fn test_transfer_coin_helper() {
        let recipient = AccountAddress::from_hex("0x789").unwrap();
        let payload =
            InputEntryFunctionData::transfer_coin("0x1::aptos_coin::AptosCoin", recipient, 1000)
                .unwrap();

        match payload {
            TransactionPayload::EntryFunction(ef) => {
                assert_eq!(ef.function, "transfer");
                assert_eq!(ef.module.name.as_str(), "coin");
                assert_eq!(ef.type_args.len(), 1);
            }
            _ => panic!("Expected EntryFunction"),
        }
    }

    #[test]
    fn test_various_arg_types() {
        let payload = InputEntryFunctionData::new("0x1::test::test_function")
            .arg(42u8)
            .arg(1000u64)
            .arg(true)
            .arg("hello".to_string())
            .arg(vec![1u8, 2u8, 3u8])
            .arg(AccountAddress::ONE)
            .build()
            .unwrap();

        match payload {
            TransactionPayload::EntryFunction(ef) => {
                assert_eq!(ef.args.len(), 6);
            }
            _ => panic!("Expected EntryFunction"),
        }
    }

    #[test]
    fn test_move_u256() {
        let val = MoveU256::from_u128(12345);
        let bytes = aptos_bcs::to_bytes(&val).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_move_some_none() {
        let some_bytes = move_some(42u64);
        assert_eq!(some_bytes[0], 0x01);

        let none_bytes = move_none();
        assert_eq!(none_bytes, vec![0x00]);
    }

    #[test]
    fn test_from_parts() {
        let module = MoveModuleId::from_str_strict("0x1::coin").unwrap();
        let payload = InputEntryFunctionData::from_parts(module, "transfer")
            .type_arg("0x1::aptos_coin::AptosCoin")
            .arg(AccountAddress::ONE)
            .arg(1000u64)
            .build()
            .unwrap();

        match payload {
            TransactionPayload::EntryFunction(ef) => {
                assert_eq!(ef.function, "transfer");
                assert_eq!(ef.module.name.as_str(), "coin");
            }
            _ => panic!("Expected EntryFunction"),
        }
    }

    #[test]
    fn test_build_entry_function() {
        let ef = InputEntryFunctionData::new("0x1::aptos_account::transfer")
            .arg(AccountAddress::ONE)
            .arg(1000u64)
            .build_entry_function()
            .unwrap();

        assert_eq!(ef.function, "transfer");
        assert_eq!(ef.args.len(), 2);
    }

    #[test]
    fn test_function_constants() {
        assert_eq!(functions::APT_TRANSFER, "0x1::aptos_account::transfer");
        assert_eq!(functions::COIN_TRANSFER, "0x1::coin::transfer");
    }

    #[test]
    fn test_move_u256_from_u128() {
        let val = MoveU256::from_u128(123_456_789);
        // First 16 bytes should contain the value in little-endian
        let expected = 123_456_789_u128.to_le_bytes();
        assert_eq!(&val.0[..16], &expected);
        // Upper 16 bytes should be zero
        assert_eq!(&val.0[16..], &[0u8; 16]);
    }

    #[test]
    fn test_move_u256_from_le_bytes() {
        let bytes = [0xab; 32];
        let val = MoveU256::from_le_bytes(bytes);
        assert_eq!(val.0, bytes);
    }

    #[test]
    fn test_move_u256_parse() {
        let val = MoveU256::parse("12345678901234567890").unwrap();
        let expected = 12_345_678_901_234_567_890_u128;
        let mut expected_bytes = [0u8; 32];
        expected_bytes[..16].copy_from_slice(&expected.to_le_bytes());
        assert_eq!(val.0, expected_bytes);
    }

    #[test]
    fn test_move_u256_parse_invalid() {
        // Value larger than u128 currently returns error
        let result = MoveU256::parse("999999999999999999999999999999999999999999999");
        assert!(result.is_err());
    }

    #[test]
    fn test_move_u256_serialization() {
        let val = MoveU256::from_u128(0x0102_0304_0506_0708);
        let bcs = aptos_bcs::to_bytes(&val).unwrap();
        // Should serialize as 32 bytes (tuple, not vector with length prefix)
        assert_eq!(bcs.len(), 32);
        // First 8 bytes should be our value in little-endian
        assert_eq!(&bcs[..8], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_move_i128_new() {
        let val = MoveI128::new(42);
        assert_eq!(val.0, 42);
    }

    #[test]
    fn test_move_i128_from_i128() {
        let val: MoveI128 = (-100i128).into();
        assert_eq!(val.0, -100);
    }

    #[test]
    fn test_move_i128_serialization_positive() {
        let val = MoveI128::new(0x0102_0304_0506_0708);
        let bcs = aptos_bcs::to_bytes(&val).unwrap();
        // Should serialize as 16 bytes (tuple, not vector)
        assert_eq!(bcs.len(), 16);
        // First 8 bytes should be our value in little-endian
        assert_eq!(&bcs[..8], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        // Upper 8 bytes should be zeros for positive value
        assert_eq!(&bcs[8..], &[0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_move_i128_serialization_negative() {
        let val = MoveI128::new(-1);
        let bcs = aptos_bcs::to_bytes(&val).unwrap();
        assert_eq!(bcs.len(), 16);
        // -1 in two's complement is all 0xFF bytes
        assert_eq!(bcs, vec![0xFF; 16]);
    }

    #[test]
    fn test_move_i256_from_i128_positive() {
        let val = MoveI256::from_i128(42);
        // First 16 bytes should contain the value
        let expected = 42i128.to_le_bytes();
        assert_eq!(&val.0[..16], &expected);
        // Upper 16 bytes should be zeros for positive value
        assert_eq!(&val.0[16..], &[0u8; 16]);
    }

    #[test]
    fn test_move_i256_from_i128_negative() {
        let val = MoveI256::from_i128(-1);
        // -1 in two's complement should be all 0xFF bytes
        assert_eq!(val.0, [0xFF; 32]);
    }

    #[test]
    fn test_move_i256_from_le_bytes() {
        let bytes = [0xcd; 32];
        let val = MoveI256::from_le_bytes(bytes);
        assert_eq!(val.0, bytes);
    }

    #[test]
    fn test_move_i256_from_trait() {
        let val: MoveI256 = (-100i128).into();
        let expected = MoveI256::from_i128(-100);
        assert_eq!(val, expected);
    }

    #[test]
    fn test_move_i256_serialization() {
        let val = MoveI256::from_i128(0x0102_0304_0506_0708);
        let bcs = aptos_bcs::to_bytes(&val).unwrap();
        // Should serialize as 32 bytes (tuple, not vector)
        assert_eq!(bcs.len(), 32);
        // First 8 bytes should be our value in little-endian
        assert_eq!(&bcs[..8], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_move_i256_serialization_negative() {
        let val = MoveI256::from_i128(-1);
        let bcs = aptos_bcs::to_bytes(&val).unwrap();
        assert_eq!(bcs.len(), 32);
        // -1 in two's complement is all 0xFF bytes
        assert_eq!(bcs, vec![0xFF; 32]);
    }

    #[test]
    fn test_input_entry_function_data_new() {
        let builder = InputEntryFunctionData::new("0x1::coin::transfer");
        let result = builder.build();
        // Should build successfully (no args required yet)
        assert!(result.is_ok());
    }

    #[test]
    fn test_input_entry_function_data_invalid_function_id() {
        let builder = InputEntryFunctionData::new("invalid");
        let result = builder.build();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid function ID")
        );
    }

    #[test]
    fn test_input_entry_function_data_type_arg() {
        let builder = InputEntryFunctionData::new("0x1::coin::transfer")
            .type_arg("0x1::aptos_coin::AptosCoin");
        let result = builder.build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_input_entry_function_data_invalid_type_arg() {
        let builder =
            InputEntryFunctionData::new("0x1::coin::transfer").type_arg("not a valid type");
        let result = builder.build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("type argument"));
    }

    #[test]
    fn test_input_entry_function_data_type_arg_typed() {
        use crate::types::TypeTag;

        let builder =
            InputEntryFunctionData::new("0x1::coin::transfer").type_arg_typed(TypeTag::U64);
        let result = builder.build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_input_entry_function_data_type_args() {
        let builder = InputEntryFunctionData::new("0x1::coin::transfer").type_args(["u64", "u128"]);
        let result = builder.build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_input_entry_function_data_type_args_typed() {
        use crate::types::TypeTag;

        let builder = InputEntryFunctionData::new("0x1::coin::transfer")
            .type_args_typed([TypeTag::U64, TypeTag::Bool]);
        let result = builder.build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_input_entry_function_data_arg() {
        let builder = InputEntryFunctionData::new("0x1::coin::transfer")
            .arg(42u64)
            .arg(true)
            .arg("hello".to_string());
        let result = builder.build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_input_entry_function_data_arg_raw() {
        let raw_bytes = vec![0x01, 0x02, 0x03];
        let builder = InputEntryFunctionData::new("0x1::coin::transfer").arg_raw(raw_bytes);
        let result = builder.build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_input_entry_function_data_args() {
        let builder = InputEntryFunctionData::new("0x1::coin::transfer").args([1u64, 2u64, 3u64]);
        let result = builder.build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_input_entry_function_data_transfer_apt() {
        use crate::types::AccountAddress;

        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let result = InputEntryFunctionData::transfer_apt(recipient, 1000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_input_entry_function_data_builder_debug() {
        let builder = InputEntryFunctionData::new("0x1::coin::transfer");
        let debug = format!("{builder:?}");
        assert!(debug.contains("InputEntryFunctionDataBuilder"));
    }

    #[test]
    fn test_input_entry_function_data_builder_clone() {
        let builder = InputEntryFunctionData::new("0x1::coin::transfer").arg(42u64);
        let cloned = builder.clone();
        assert!(cloned.build().is_ok());
    }

    #[test]
    fn test_move_u256_debug() {
        let val = MoveU256::from_u128(123_456_789);
        let debug = format!("{val:?}");
        assert!(debug.contains("MoveU256"));
    }

    #[test]
    fn test_move_i128_debug() {
        let val = MoveI128::new(-42);
        let debug = format!("{val:?}");
        assert!(debug.contains("MoveI128"));
    }

    #[test]
    fn test_move_i256_debug() {
        let val = MoveI256::from_i128(-42);
        let debug = format!("{val:?}");
        assert!(debug.contains("MoveI256"));
    }

    #[test]
    fn test_move_u256_equality() {
        let val1 = MoveU256::from_u128(100);
        let val2 = MoveU256::from_u128(100);
        let val3 = MoveU256::from_u128(200);
        assert_eq!(val1, val2);
        assert_ne!(val1, val3);
    }

    #[test]
    fn test_move_i256_equality() {
        let val1 = MoveI256::from_i128(-50);
        let val2 = MoveI256::from_i128(-50);
        let val3 = MoveI256::from_i128(50);
        assert_eq!(val1, val2);
        assert_ne!(val1, val3);
    }

    #[test]
    fn test_move_u256_clone() {
        let val1 = MoveU256::from_u128(999);
        let val2 = val1;
        assert_eq!(val1, val2);
    }

    #[test]
    fn test_move_i256_clone() {
        let val1 = MoveI256::from_i128(-999);
        let val2 = val1;
        assert_eq!(val1, val2);
    }
}
