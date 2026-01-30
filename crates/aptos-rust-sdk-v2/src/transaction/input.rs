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
//! use aptos_rust_sdk_v2::transaction::InputEntryFunctionData;
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
/// use aptos_rust_sdk_v2::transaction::InputEntryFunctionData;
/// use aptos_rust_sdk_v2::types::AccountAddress;
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
}
