//! Move type system representations.
//!
//! This module provides Rust types that mirror the Move type system,
//! including type tags, struct tags, and move values.
//!
//! # Security
//!
//! All parsing functions enforce length limits to prevent denial-of-service
//! attacks via excessive memory allocation or CPU usage.

use crate::error::{AptosError, AptosResult};
use crate::types::AccountAddress;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Maximum length for type tag strings to prevent `DoS` via excessive parsing.
/// This limit is generous enough for any realistic type tag while preventing abuse.
const MAX_TYPE_TAG_LENGTH: usize = 1024;

/// Maximum length for identifier strings.
const MAX_IDENTIFIER_LENGTH: usize = 128;

/// Maximum depth for nested type arguments (e.g., vector<vector<vector<...>>>).
const MAX_TYPE_NESTING_DEPTH: usize = 8;

/// An identifier in Move (module name, function name, etc.).
///
/// Identifiers must start with a letter or underscore and contain
/// only alphanumeric characters and underscores.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    /// Creates a new identifier, validating the format.
    ///
    /// # Security
    ///
    /// This function enforces a length limit of 128 characters to prevent
    /// denial-of-service attacks via excessive memory allocation.
    ///
    /// # Errors
    ///
    /// Returns an error if the identifier is empty, exceeds 128 characters, does not start
    /// with a letter or underscore, or contains characters that are not alphanumeric or underscore.
    pub fn new(s: impl Into<String>) -> AptosResult<Self> {
        let s = s.into();
        // Security: enforce length limit to prevent DoS
        if s.len() > MAX_IDENTIFIER_LENGTH {
            return Err(AptosError::InvalidTypeTag(format!(
                "identifier too long: {} bytes (max {})",
                s.len(),
                MAX_IDENTIFIER_LENGTH
            )));
        }
        let maybe_first = s.chars().next();
        let Some(first) = maybe_first else {
            return Err(AptosError::InvalidTypeTag(
                "identifier cannot be empty".into(),
            ));
        };

        if !first.is_ascii_alphabetic() && first != '_' {
            return Err(AptosError::InvalidTypeTag(format!(
                "identifier must start with letter or underscore: {s}"
            )));
        }
        if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(AptosError::InvalidTypeTag(format!(
                "identifier contains invalid characters: {s}"
            )));
        }
        Ok(Self(s))
    }

    /// Creates an identifier without validation (for internal use).
    pub(crate) fn from_string_unchecked(s: String) -> Self {
        Self(s)
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Identifier {
    type Err = AptosError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// A Move module identifier (`address::module_name`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MoveModuleId {
    /// The address where the module is published.
    pub address: AccountAddress,
    /// The name of the module.
    pub name: Identifier,
}

impl MoveModuleId {
    /// Creates a new module ID.
    pub fn new(address: AccountAddress, name: Identifier) -> Self {
        Self { address, name }
    }

    /// Parses a module ID from a string (e.g., "`0x1::coin`").
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not in the format `address::module_name`, the address
    /// is invalid, or the module name is not a valid identifier.
    pub fn from_str_strict(s: &str) -> AptosResult<Self> {
        let parts: Vec<&str> = s.split("::").collect();
        if parts.len() != 2 {
            return Err(AptosError::InvalidTypeTag(format!(
                "invalid module ID format: {s}"
            )));
        }
        let address = AccountAddress::from_str(parts[0])?;
        let name = Identifier::new(parts[1])?;
        Ok(Self { address, name })
    }
}

impl fmt::Display for MoveModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.address.to_short_string(), self.name)
    }
}

impl FromStr for MoveModuleId {
    type Err = AptosError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_strict(s)
    }
}

/// A struct tag identifies a specific struct type in Move.
///
/// Format: `address::module::StructName<TypeArg1, TypeArg2, ...>`
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StructTag {
    /// The address where the module is published.
    pub address: AccountAddress,
    /// The module name.
    pub module: Identifier,
    /// The struct name.
    pub name: Identifier,
    /// Type arguments (for generic structs).
    #[serde(default)]
    pub type_args: Vec<TypeTag>,
}

impl StructTag {
    /// Creates a new struct tag.
    pub fn new(
        address: AccountAddress,
        module: Identifier,
        name: Identifier,
        type_args: Vec<TypeTag>,
    ) -> Self {
        Self {
            address,
            module,
            name,
            type_args,
        }
    }

    /// Creates a struct tag with no type arguments.
    ///
    /// # Errors
    ///
    /// Returns an error if the module or name is not a valid identifier.
    pub fn simple(
        address: AccountAddress,
        module: impl Into<String>,
        name: impl Into<String>,
    ) -> AptosResult<Self> {
        Ok(Self {
            address,
            module: Identifier::new(module)?,
            name: Identifier::new(name)?,
            type_args: vec![],
        })
    }

    /// The `AptosCoin` struct tag (`0x1::aptos_coin::AptosCoin`).
    pub fn aptos_coin() -> Self {
        Self {
            address: AccountAddress::ONE,
            module: Identifier::from_string_unchecked("aptos_coin".to_string()),
            name: Identifier::from_string_unchecked("AptosCoin".to_string()),
            type_args: vec![],
        }
    }
}

impl fmt::Display for StructTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}::{}::{}",
            self.address.to_short_string(),
            self.module,
            self.name
        )?;
        if !self.type_args.is_empty() {
            write!(f, "<")?;
            for (i, arg) in self.type_args.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{arg}")?;
            }
            write!(f, ">")?;
        }
        Ok(())
    }
}

/// Alias for `StructTag` used in some API responses.
pub type MoveStructTag = StructTag;

/// A type tag represents a Move type.
///
/// Type tags are used to specify types in entry function calls and
/// to describe the types of resources and values.
///
/// Note: Variant indices must match Move core for BCS compatibility:
/// - 0: Bool
/// - 1: U8
/// - 2: U64
/// - 3: U128
/// - 4: Address
/// - 5: Signer
/// - 6: Vector
/// - 7: Struct
/// - 8: U16 (added later)
/// - 9: U32 (added later)
/// - 10: U256 (added later)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TypeTag {
    /// Boolean type (variant 0)
    Bool,
    /// 8-bit unsigned integer (variant 1)
    U8,
    /// 64-bit unsigned integer (variant 2)
    U64,
    /// 128-bit unsigned integer (variant 3)
    U128,
    /// Address type (variant 4)
    Address,
    /// Signer type (variant 5, only valid in certain contexts)
    Signer,
    /// Vector type with element type (variant 6)
    Vector(Box<TypeTag>),
    /// Struct type (variant 7)
    Struct(Box<StructTag>),
    /// 16-bit unsigned integer (variant 8, added later)
    U16,
    /// 32-bit unsigned integer (variant 9, added later)
    U32,
    /// 256-bit unsigned integer (variant 10, added later)
    U256,
    // Signed integer types (added for completeness - may not be supported on all networks)
    /// 8-bit signed integer (variant 11)
    I8,
    /// 16-bit signed integer (variant 12)
    I16,
    /// 32-bit signed integer (variant 13)
    I32,
    /// 64-bit signed integer (variant 14)
    I64,
    /// 128-bit signed integer (variant 15)
    I128,
    /// 256-bit signed integer (variant 16)
    I256,
}

impl TypeTag {
    /// Creates a vector type tag with the given element type.
    pub fn vector(element: TypeTag) -> Self {
        Self::Vector(Box::new(element))
    }

    /// Creates a struct type tag.
    pub fn struct_tag(tag: StructTag) -> Self {
        Self::Struct(Box::new(tag))
    }

    /// Returns the `AptosCoin` type tag (`0x1::aptos_coin::AptosCoin`).
    pub fn aptos_coin() -> Self {
        Self::Struct(Box::new(StructTag::aptos_coin()))
    }

    /// Parses a type tag from a string.
    ///
    /// Supports:
    /// - Primitive types: bool, u8, u16, u32, u64, u128, u256, address, signer
    /// - Struct types: `address::module::StructName`
    /// - Vector types: vector<`element_type`>
    /// - Generic struct types: `address::module::StructName`<`TypeArg1`, `TypeArg2`>
    ///
    /// # Security
    ///
    /// This function enforces length and depth limits to prevent denial-of-service
    /// attacks via excessive parsing or memory allocation.
    ///
    /// # Errors
    ///
    /// Returns an error if the type tag string exceeds 1024 characters, has excessive nesting
    /// depth (more than 8 levels), contains invalid syntax, or any component (address, module,
    /// struct name, or type arguments) is invalid.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aptos_sdk::types::TypeTag;
    ///
    /// let tag = TypeTag::from_str_strict("0x1::aptos_coin::AptosCoin").unwrap();
    /// let tag = TypeTag::from_str_strict("u64").unwrap();
    /// let tag = TypeTag::from_str_strict("vector<u8>").unwrap();
    /// ```
    pub fn from_str_strict(s: &str) -> AptosResult<Self> {
        let s = s.trim();

        // Security: enforce length limit to prevent DoS
        if s.len() > MAX_TYPE_TAG_LENGTH {
            return Err(AptosError::InvalidTypeTag(format!(
                "type tag too long: {} bytes (max {})",
                s.len(),
                MAX_TYPE_TAG_LENGTH
            )));
        }

        Self::parse_type_tag_with_depth(s, 0)
    }

    /// Internal parser with depth tracking to prevent stack overflow.
    fn parse_type_tag_with_depth(s: &str, depth: usize) -> AptosResult<Self> {
        // Security: prevent excessive nesting depth
        if depth > MAX_TYPE_NESTING_DEPTH {
            return Err(AptosError::InvalidTypeTag(format!(
                "type tag nesting too deep: {depth} levels (max {MAX_TYPE_NESTING_DEPTH})"
            )));
        }

        // Check primitive types first
        match s {
            "bool" => return Ok(TypeTag::Bool),
            "u8" => return Ok(TypeTag::U8),
            "u16" => return Ok(TypeTag::U16),
            "u32" => return Ok(TypeTag::U32),
            "u64" => return Ok(TypeTag::U64),
            "u128" => return Ok(TypeTag::U128),
            "u256" => return Ok(TypeTag::U256),
            "i8" => return Ok(TypeTag::I8),
            "i16" => return Ok(TypeTag::I16),
            "i32" => return Ok(TypeTag::I32),
            "i64" => return Ok(TypeTag::I64),
            "i128" => return Ok(TypeTag::I128),
            "i256" => return Ok(TypeTag::I256),
            "address" => return Ok(TypeTag::Address),
            "signer" => return Ok(TypeTag::Signer),
            _ => {}
        }

        // Check for vector type
        if s.starts_with("vector<") && s.ends_with('>') {
            let inner = &s[7..s.len() - 1];
            let inner_tag = Self::parse_type_tag_with_depth(inner, depth + 1)?;
            return Ok(TypeTag::Vector(Box::new(inner_tag)));
        }

        // Parse as struct type (address::module::name or with generics)
        Self::parse_struct_type_with_depth(s, depth)
    }

    /// Parses a struct type tag with depth tracking.
    fn parse_struct_type_with_depth(s: &str, depth: usize) -> AptosResult<Self> {
        // Find the opening < for generics (if any)
        let generic_start = s.find('<');

        let (base, type_args_str) = if let Some(idx) = generic_start {
            if !s.ends_with('>') {
                return Err(AptosError::InvalidTypeTag(format!(
                    "malformed generic type: {s}"
                )));
            }
            (&s[..idx], Some(&s[idx + 1..s.len() - 1]))
        } else {
            (s, None)
        };

        // Parse the base struct (address::module::name)
        let parts: Vec<&str> = base.split("::").collect();
        if parts.len() != 3 {
            return Err(AptosError::InvalidTypeTag(format!(
                "invalid struct type format (expected address::module::name): {s}"
            )));
        }

        let address = AccountAddress::from_str(parts[0])?;
        let module = Identifier::new(parts[1])?;
        let name = Identifier::new(parts[2])?;

        // Parse type arguments if present
        let type_args = if let Some(args_str) = type_args_str {
            Self::parse_type_args_with_depth(args_str, depth)?
        } else {
            vec![]
        };

        Ok(TypeTag::Struct(Box::new(StructTag {
            address,
            module,
            name,
            type_args,
        })))
    }

    /// Parses comma-separated type arguments with depth tracking.
    fn parse_type_args_with_depth(s: &str, depth: usize) -> AptosResult<Vec<TypeTag>> {
        if s.trim().is_empty() {
            return Ok(vec![]);
        }

        let mut result = Vec::new();
        let mut bracket_depth = 0;
        let mut start = 0;

        for (i, c) in s.char_indices() {
            match c {
                '<' => bracket_depth += 1,
                '>' => bracket_depth -= 1,
                ',' if bracket_depth == 0 => {
                    let arg = s[start..i].trim();
                    if !arg.is_empty() {
                        result.push(Self::parse_type_tag_with_depth(arg, depth + 1)?);
                    }
                    start = i + 1;
                }
                _ => {}
            }
        }

        // Handle the last argument
        let last_arg = s[start..].trim();
        if !last_arg.is_empty() {
            result.push(Self::parse_type_tag_with_depth(last_arg, depth + 1)?);
        }

        Ok(result)
    }
}

impl fmt::Display for TypeTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeTag::Bool => write!(f, "bool"),
            TypeTag::U8 => write!(f, "u8"),
            TypeTag::U16 => write!(f, "u16"),
            TypeTag::U32 => write!(f, "u32"),
            TypeTag::U64 => write!(f, "u64"),
            TypeTag::U128 => write!(f, "u128"),
            TypeTag::U256 => write!(f, "u256"),
            TypeTag::I8 => write!(f, "i8"),
            TypeTag::I16 => write!(f, "i16"),
            TypeTag::I32 => write!(f, "i32"),
            TypeTag::I64 => write!(f, "i64"),
            TypeTag::I128 => write!(f, "i128"),
            TypeTag::I256 => write!(f, "i256"),
            TypeTag::Address => write!(f, "address"),
            TypeTag::Signer => write!(f, "signer"),
            TypeTag::Vector(inner) => write!(f, "vector<{inner}>"),
            TypeTag::Struct(tag) => write!(f, "{tag}"),
        }
    }
}

/// An entry function identifier (`address::module::function`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntryFunctionId {
    /// The module containing the function.
    pub module: MoveModuleId,
    /// The function name.
    pub name: Identifier,
}

impl EntryFunctionId {
    /// Creates a new entry function ID.
    pub fn new(module: MoveModuleId, name: Identifier) -> Self {
        Self { module, name }
    }

    /// Parses an entry function ID from a string (e.g., "`0x1::coin::transfer`").
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not in the format `address::module::function`, the address
    /// is invalid, or the module or function name is not a valid identifier.
    pub fn from_str_strict(s: &str) -> AptosResult<Self> {
        let parts: Vec<&str> = s.split("::").collect();
        if parts.len() != 3 {
            return Err(AptosError::InvalidTypeTag(format!(
                "invalid entry function ID format: {s}"
            )));
        }
        let address = AccountAddress::from_str(parts[0])?;
        let module = Identifier::new(parts[1])?;
        let name = Identifier::new(parts[2])?;
        Ok(Self {
            module: MoveModuleId::new(address, module),
            name,
        })
    }
}

impl fmt::Display for EntryFunctionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.module, self.name)
    }
}

impl FromStr for EntryFunctionId {
    type Err = AptosError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_strict(s)
    }
}

/// A Move struct type from the API (with string representation).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveType(String);

impl MoveType {
    /// Creates a new `MoveType` from a string.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Returns the type as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MoveType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A Move resource (struct value with abilities).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveResource {
    /// The type of this resource.
    #[serde(rename = "type")]
    pub typ: String,
    /// The data contained in this resource.
    pub data: serde_json::Value,
}

/// A Move struct value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MoveStruct {
    /// The fields of the struct as a JSON object.
    #[serde(flatten)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

/// A Move value (for view function returns, etc.).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MoveValue {
    /// A boolean value.
    Bool(bool),
    /// An integer value (stored as string for large numbers).
    Number(String),
    /// A string value.
    String(String),
    /// An address value.
    Address(AccountAddress),
    /// A vector value.
    Vector(Vec<MoveValue>),
    /// A struct value.
    Struct(MoveStruct),
    /// A null/unit value.
    Null,
}

impl MoveValue {
    /// Tries to extract a boolean value.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            MoveValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Tries to extract a u64 value.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            MoveValue::Number(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// Tries to extract a u128 value.
    pub fn as_u128(&self) -> Option<u128> {
        match self {
            MoveValue::Number(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// Tries to extract a string value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            MoveValue::String(s) | MoveValue::Number(s) => Some(s),
            _ => None,
        }
    }

    /// Tries to extract an address value.
    pub fn as_address(&self) -> Option<&AccountAddress> {
        match self {
            MoveValue::Address(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to extract a vector value.
    pub fn as_vec(&self) -> Option<&[MoveValue]> {
        match self {
            MoveValue::Vector(v) => Some(v),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identifier() {
        assert!(Identifier::new("hello").is_ok());
        assert!(Identifier::new("_private").is_ok());
        assert!(Identifier::new("CamelCase123").is_ok());
        assert!(Identifier::new("").is_err());
        assert!(Identifier::new("123start").is_err());
        assert!(Identifier::new("has-dash").is_err());
    }

    #[test]
    fn test_identifier_as_str() {
        let id = Identifier::new("test").unwrap();
        assert_eq!(id.as_str(), "test");
    }

    #[test]
    fn test_identifier_display() {
        let id = Identifier::new("my_func").unwrap();
        assert_eq!(format!("{id}"), "my_func");
    }

    #[test]
    fn test_module_id() {
        let module_id = MoveModuleId::from_str_strict("0x1::coin").unwrap();
        assert_eq!(module_id.address, AccountAddress::ONE);
        assert_eq!(module_id.name.as_str(), "coin");
        assert_eq!(module_id.to_string(), "0x1::coin");
    }

    #[test]
    fn test_module_id_invalid() {
        assert!(MoveModuleId::from_str_strict("invalid").is_err());
        assert!(MoveModuleId::from_str_strict("0x1").is_err());
        assert!(MoveModuleId::from_str_strict("0x1::").is_err());
    }

    #[test]
    fn test_struct_tag() {
        let tag = StructTag::aptos_coin();
        assert_eq!(tag.to_string(), "0x1::aptos_coin::AptosCoin");
    }

    #[test]
    fn test_struct_tag_with_type_args() {
        let coin_store = StructTag::new(
            AccountAddress::ONE,
            Identifier::new("coin").unwrap(),
            Identifier::new("CoinStore").unwrap(),
            vec![TypeTag::aptos_coin()],
        );
        assert!(coin_store.to_string().contains("CoinStore"));
        assert!(coin_store.to_string().contains("AptosCoin"));
    }

    #[test]
    fn test_struct_tag_aptos_coin() {
        let tag = StructTag::aptos_coin();
        assert_eq!(tag.address, AccountAddress::ONE);
        assert_eq!(tag.module.as_str(), "aptos_coin");
        assert_eq!(tag.name.as_str(), "AptosCoin");
    }

    #[test]
    fn test_type_tag_display() {
        assert_eq!(TypeTag::Bool.to_string(), "bool");
        assert_eq!(TypeTag::U8.to_string(), "u8");
        assert_eq!(TypeTag::U16.to_string(), "u16");
        assert_eq!(TypeTag::U32.to_string(), "u32");
        assert_eq!(TypeTag::U64.to_string(), "u64");
        assert_eq!(TypeTag::U128.to_string(), "u128");
        assert_eq!(TypeTag::U256.to_string(), "u256");
        assert_eq!(TypeTag::Address.to_string(), "address");
        assert_eq!(TypeTag::Signer.to_string(), "signer");
        assert_eq!(TypeTag::vector(TypeTag::U8).to_string(), "vector<u8>");
        assert_eq!(
            TypeTag::aptos_coin().to_string(),
            "0x1::aptos_coin::AptosCoin"
        );
    }

    #[test]
    fn test_type_tag_from_str_strict() {
        assert_eq!(TypeTag::from_str_strict("bool").unwrap(), TypeTag::Bool);
        assert_eq!(TypeTag::from_str_strict("u8").unwrap(), TypeTag::U8);
        assert_eq!(TypeTag::from_str_strict("u64").unwrap(), TypeTag::U64);
        assert_eq!(
            TypeTag::from_str_strict("address").unwrap(),
            TypeTag::Address
        );
        assert_eq!(TypeTag::from_str_strict("signer").unwrap(), TypeTag::Signer);
    }

    #[test]
    fn test_type_tag_from_str_struct() {
        let tag = TypeTag::from_str_strict("0x1::aptos_coin::AptosCoin").unwrap();
        if let TypeTag::Struct(s) = tag {
            assert_eq!(s.name.as_str(), "AptosCoin");
        } else {
            panic!("Expected struct type tag");
        }
    }

    #[test]
    fn test_type_tag_from_str_vector() {
        let tag = TypeTag::from_str_strict("vector<u8>").unwrap();
        if let TypeTag::Vector(inner) = tag {
            assert_eq!(*inner, TypeTag::U8);
        } else {
            panic!("Expected vector type tag");
        }
    }

    #[test]
    fn test_type_tag_nested_vector() {
        let tag = TypeTag::from_str_strict("vector<vector<u64>>").unwrap();
        if let TypeTag::Vector(outer) = tag {
            if let TypeTag::Vector(inner) = *outer {
                assert_eq!(*inner, TypeTag::U64);
            } else {
                panic!("Expected nested vector");
            }
        } else {
            panic!("Expected vector type tag");
        }
    }

    #[test]
    fn test_type_tag_invalid() {
        assert!(TypeTag::from_str_strict("invalid").is_err());
        assert!(TypeTag::from_str_strict("vector<").is_err());
    }

    #[test]
    fn test_entry_function_id() {
        let func = EntryFunctionId::from_str_strict("0x1::coin::transfer").unwrap();
        assert_eq!(func.to_string(), "0x1::coin::transfer");
    }

    #[test]
    fn test_entry_function_id_invalid() {
        assert!(EntryFunctionId::from_str_strict("0x1::coin").is_err());
        assert!(EntryFunctionId::from_str_strict("invalid").is_err());
    }

    #[test]
    fn test_move_value_as_bool() {
        let val = MoveValue::Bool(true);
        assert_eq!(val.as_bool(), Some(true));
        assert!(MoveValue::Number("123".to_string()).as_bool().is_none());
    }

    #[test]
    fn test_move_value_as_u64() {
        let val = MoveValue::Number("12345".to_string());
        assert_eq!(val.as_u64(), Some(12345));
        assert!(MoveValue::Bool(true).as_u64().is_none());
    }

    #[test]
    fn test_move_value_as_u128() {
        let val = MoveValue::Number("340282366920938463463374607431768211455".to_string());
        assert_eq!(val.as_u128(), Some(u128::MAX));
    }

    #[test]
    fn test_move_value_as_str() {
        let val = MoveValue::String("hello".to_string());
        assert_eq!(val.as_str(), Some("hello"));
        let num = MoveValue::Number("123".to_string());
        assert_eq!(num.as_str(), Some("123"));
    }

    #[test]
    fn test_move_value_as_address() {
        let val = MoveValue::Address(AccountAddress::ONE);
        assert_eq!(val.as_address(), Some(&AccountAddress::ONE));
        assert!(MoveValue::Bool(true).as_address().is_none());
    }

    #[test]
    fn test_move_value_as_vec() {
        let val = MoveValue::Vector(vec![MoveValue::Bool(true), MoveValue::Bool(false)]);
        let vec = val.as_vec().unwrap();
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn test_move_resource_deserialization() {
        let json = r#"{
            "type": "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
            "data": {"coin": {"value": "1000"}}
        }"#;
        let resource: MoveResource = serde_json::from_str(json).unwrap();
        assert_eq!(
            resource.typ,
            "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"
        );
    }

    #[test]
    fn test_identifier_bcs_serialization() {
        let id = Identifier::new("test_function").unwrap();
        let serialized = aptos_bcs::to_bytes(&id).unwrap();
        let deserialized: Identifier = aptos_bcs::from_bytes(&serialized).unwrap();
        assert_eq!(id, deserialized);
    }

    #[test]
    fn test_module_id_new() {
        let module =
            MoveModuleId::new(AccountAddress::ONE, Identifier::new("test_module").unwrap());
        assert_eq!(module.address, AccountAddress::ONE);
        assert_eq!(module.name.as_str(), "test_module");
    }

    #[test]
    fn test_module_id_bcs_serialization() {
        let module = MoveModuleId::from_str_strict("0x1::coin").unwrap();
        let serialized = aptos_bcs::to_bytes(&module).unwrap();
        let deserialized: MoveModuleId = aptos_bcs::from_bytes(&serialized).unwrap();
        assert_eq!(module, deserialized);
    }

    #[test]
    fn test_struct_tag_new() {
        let tag = StructTag::new(
            AccountAddress::from_hex("0x123").unwrap(),
            Identifier::new("my_module").unwrap(),
            Identifier::new("MyStruct").unwrap(),
            vec![TypeTag::U64, TypeTag::Bool],
        );
        assert_eq!(tag.address, AccountAddress::from_hex("0x123").unwrap());
        assert_eq!(tag.module.as_str(), "my_module");
        assert_eq!(tag.name.as_str(), "MyStruct");
        assert_eq!(tag.type_args.len(), 2);
    }

    #[test]
    fn test_struct_tag_display_with_type_args() {
        let tag = StructTag::new(
            AccountAddress::ONE,
            Identifier::new("coin").unwrap(),
            Identifier::new("CoinStore").unwrap(),
            vec![TypeTag::aptos_coin()],
        );
        let display = tag.to_string();
        assert!(display.contains("CoinStore"));
        assert!(display.contains('<'));
        assert!(display.contains('>'));
    }

    #[test]
    fn test_struct_tag_bcs_serialization() {
        let tag = StructTag::aptos_coin();
        let serialized = aptos_bcs::to_bytes(&tag).unwrap();
        let deserialized: StructTag = aptos_bcs::from_bytes(&serialized).unwrap();
        assert_eq!(tag, deserialized);
    }

    #[test]
    fn test_type_tag_vector_constructor() {
        let vec_type = TypeTag::vector(TypeTag::Address);
        if let TypeTag::Vector(inner) = vec_type {
            assert_eq!(*inner, TypeTag::Address);
        } else {
            panic!("Expected Vector type");
        }
    }

    #[test]
    fn test_type_tag_struct_constructor() {
        let struct_type = TypeTag::struct_tag(StructTag::aptos_coin());
        if let TypeTag::Struct(s) = struct_type {
            assert_eq!(s.name.as_str(), "AptosCoin");
        } else {
            panic!("Expected Struct type");
        }
    }

    #[test]
    fn test_type_tag_from_str_u16_u32_u256() {
        assert_eq!(TypeTag::from_str_strict("u16").unwrap(), TypeTag::U16);
        assert_eq!(TypeTag::from_str_strict("u32").unwrap(), TypeTag::U32);
        assert_eq!(TypeTag::from_str_strict("u256").unwrap(), TypeTag::U256);
    }

    #[test]
    fn test_type_tag_from_str_vector_of_struct() {
        let tag = TypeTag::from_str_strict("vector<0x1::aptos_coin::AptosCoin>").unwrap();
        if let TypeTag::Vector(inner) = tag {
            if let TypeTag::Struct(s) = *inner {
                assert_eq!(s.name.as_str(), "AptosCoin");
            } else {
                panic!("Expected Struct inside Vector");
            }
        } else {
            panic!("Expected Vector type");
        }
    }

    #[test]
    fn test_type_tag_from_str_struct_with_multiple_type_args() {
        let tag = TypeTag::from_str_strict("0x1::table::Table<address, u64>").unwrap();
        if let TypeTag::Struct(s) = tag {
            assert_eq!(s.name.as_str(), "Table");
            assert_eq!(s.type_args.len(), 2);
            assert_eq!(s.type_args[0], TypeTag::Address);
            assert_eq!(s.type_args[1], TypeTag::U64);
        } else {
            panic!("Expected Struct type");
        }
    }

    #[test]
    fn test_type_tag_from_str_malformed_generic() {
        // Missing closing bracket
        assert!(TypeTag::from_str_strict("vector<u8").is_err());
        // Missing opening bracket
        assert!(TypeTag::from_str_strict("vectoru8>").is_err());
        // Malformed struct generic
        assert!(TypeTag::from_str_strict("0x1::coin::Store<u64").is_err());
    }

    #[test]
    fn test_type_tag_bcs_serialization() {
        let types = vec![
            TypeTag::Bool,
            TypeTag::U8,
            TypeTag::U16,
            TypeTag::U32,
            TypeTag::U64,
            TypeTag::U128,
            TypeTag::U256,
            TypeTag::Address,
            TypeTag::Signer,
            TypeTag::vector(TypeTag::U8),
            TypeTag::aptos_coin(),
        ];

        for t in types {
            let serialized = aptos_bcs::to_bytes(&t).unwrap();
            let deserialized: TypeTag = aptos_bcs::from_bytes(&serialized).unwrap();
            assert_eq!(t, deserialized);
        }
    }

    #[test]
    fn test_entry_function_id_new() {
        let module = MoveModuleId::from_str_strict("0x1::coin").unwrap();
        let name = Identifier::new("transfer").unwrap();
        let func = EntryFunctionId::new(module, name);
        assert_eq!(func.to_string(), "0x1::coin::transfer");
    }

    #[test]
    fn test_entry_function_id_from_str() {
        let func: EntryFunctionId = "0x1::coin::transfer".parse().unwrap();
        assert_eq!(func.module.address, AccountAddress::ONE);
        assert_eq!(func.module.name.as_str(), "coin");
        assert_eq!(func.name.as_str(), "transfer");
    }

    #[test]
    fn test_move_type_new_and_as_str() {
        let t = MoveType::new("0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>");
        assert_eq!(
            t.as_str(),
            "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"
        );
    }

    #[test]
    fn test_move_type_display() {
        let t = MoveType::new("bool");
        assert_eq!(format!("{t}"), "bool");
    }

    #[test]
    fn test_move_struct_fields() {
        let mut fields = serde_json::Map::new();
        fields.insert("value".to_string(), serde_json::json!("1000"));
        let s = MoveStruct { fields };
        assert_eq!(s.fields.get("value").unwrap(), &serde_json::json!("1000"));
    }

    #[test]
    fn test_move_value_null() {
        let val = MoveValue::Null;
        assert!(val.as_bool().is_none());
        assert!(val.as_u64().is_none());
        assert!(val.as_str().is_none());
        assert!(val.as_address().is_none());
        assert!(val.as_vec().is_none());
    }

    #[test]
    fn test_move_value_struct() {
        let mut fields = serde_json::Map::new();
        fields.insert("name".to_string(), serde_json::json!("test"));
        let s = MoveStruct { fields };
        let val = MoveValue::Struct(s);

        // Struct doesn't have direct accessors
        if let MoveValue::Struct(inner) = val {
            assert!(inner.fields.contains_key("name"));
        } else {
            panic!("Expected Struct");
        }
    }

    #[test]
    fn test_move_value_json_roundtrip() {
        // Test values that have unambiguous JSON representations
        let val = MoveValue::Bool(true);
        let json = serde_json::to_string(&val).unwrap();
        let deserialized: MoveValue = serde_json::from_str(&json).unwrap();
        assert_eq!(val, deserialized);

        let val = MoveValue::Null;
        let json = serde_json::to_string(&val).unwrap();
        let deserialized: MoveValue = serde_json::from_str(&json).unwrap();
        assert_eq!(val, deserialized);

        // Note: String and Number both serialize to JSON strings
        // and are both deserialized as the same variant based on serde's untagged enum logic
        let val = MoveValue::Number("12345".to_string());
        let json = serde_json::to_string(&val).unwrap();
        assert_eq!(json, "\"12345\"");

        let val = MoveValue::String("hello".to_string());
        let json = serde_json::to_string(&val).unwrap();
        assert_eq!(json, "\"hello\"");
    }

    // Security tests for input length limits

    #[test]
    fn test_identifier_length_limit() {
        // Valid length
        let valid = "a".repeat(128);
        assert!(Identifier::new(&valid).is_ok());

        // Too long
        let too_long = "a".repeat(129);
        let result = Identifier::new(&too_long);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_type_tag_length_limit() {
        // Valid length
        let valid = format!("0x1::{}::Test", "a".repeat(100));
        assert!(TypeTag::from_str_strict(&valid).is_ok());

        // Too long
        let too_long = format!("0x1::{}::Test", "a".repeat(2000));
        let result = TypeTag::from_str_strict(&too_long);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_type_tag_nesting_depth_limit() {
        // Valid nesting depth
        let valid = "vector<vector<vector<u8>>>";
        assert!(TypeTag::from_str_strict(valid).is_ok());

        // Too deeply nested (9 levels)
        let too_deep = "vector<vector<vector<vector<vector<vector<vector<vector<vector<u8>>>>>>>>>";
        let result = TypeTag::from_str_strict(too_deep);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too deep"));
    }

    #[test]
    fn test_identifier_from_str() {
        // Test FromStr trait implementation for Identifier
        let id: Identifier = "my_function".parse().unwrap();
        assert_eq!(id.as_str(), "my_function");

        // Invalid identifier via FromStr
        let result: Result<Identifier, _> = "123invalid".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_module_id_from_str() {
        // Test FromStr trait implementation for MoveModuleId
        let module: MoveModuleId = "0x1::coin".parse().unwrap();
        assert_eq!(module.address, AccountAddress::ONE);
        assert_eq!(module.name.as_str(), "coin");

        // Invalid module via FromStr
        let result: Result<MoveModuleId, _> = "invalid".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_struct_tag_simple() {
        // Test StructTag::simple constructor
        let tag = StructTag::simple(AccountAddress::ONE, "coin", "CoinStore").unwrap();
        assert_eq!(tag.address, AccountAddress::ONE);
        assert_eq!(tag.module.as_str(), "coin");
        assert_eq!(tag.name.as_str(), "CoinStore");
        assert!(tag.type_args.is_empty());

        // Invalid module name
        let result = StructTag::simple(AccountAddress::ONE, "123invalid", "CoinStore");
        assert!(result.is_err());

        // Invalid struct name
        let result = StructTag::simple(AccountAddress::ONE, "coin", "123invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_struct_tag_display_with_multiple_type_args() {
        // Test Display with multiple type args (exercises line 224 comma separator)
        let tag = StructTag::new(
            AccountAddress::ONE,
            Identifier::new("table").unwrap(),
            Identifier::new("Table").unwrap(),
            vec![TypeTag::Address, TypeTag::U64, TypeTag::Bool],
        );
        let display = tag.to_string();
        assert_eq!(display, "0x1::table::Table<address, u64, bool>");
    }

    #[test]
    fn test_type_tag_signed_integers_display() {
        // Test Display for signed integer types (i8, i16, i32, i64, i128, i256)
        assert_eq!(TypeTag::I8.to_string(), "i8");
        assert_eq!(TypeTag::I16.to_string(), "i16");
        assert_eq!(TypeTag::I32.to_string(), "i32");
        assert_eq!(TypeTag::I64.to_string(), "i64");
        assert_eq!(TypeTag::I128.to_string(), "i128");
        assert_eq!(TypeTag::I256.to_string(), "i256");
    }

    #[test]
    fn test_move_value_as_u128_comprehensive() {
        // Test as_u128 method with max value
        let val = MoveValue::Number("340282366920938463463374607431768211455".to_string()); // max u128
        assert_eq!(val.as_u128(), Some(u128::MAX));

        let val = MoveValue::Number("0".to_string());
        assert_eq!(val.as_u128(), Some(0));

        // Non-number returns None
        let val = MoveValue::Bool(true);
        assert_eq!(val.as_u128(), None);

        // Invalid number string returns None
        let val = MoveValue::Number("not_a_number".to_string());
        assert_eq!(val.as_u128(), None);
    }

    #[test]
    fn test_type_tag_parse_empty_type_args() {
        // Struct with no type args
        let tag = TypeTag::from_str_strict("0x1::coin::CoinInfo").unwrap();
        if let TypeTag::Struct(s) = tag {
            assert!(s.type_args.is_empty());
        } else {
            panic!("Expected Struct");
        }
    }

    #[test]
    fn test_type_tag_parse_nested_generics() {
        // Tests bracket tracking with nested generics (lines 448-449)
        let tag = TypeTag::from_str_strict(
            "0x1::table::Table<0x1::string::String, vector<0x1::aptos_coin::AptosCoin>>",
        )
        .unwrap();
        if let TypeTag::Struct(s) = tag {
            assert_eq!(s.name.as_str(), "Table");
            assert_eq!(s.type_args.len(), 2);
            // First arg is a struct
            assert!(matches!(s.type_args[0], TypeTag::Struct(_)));
            // Second arg is a vector
            assert!(matches!(s.type_args[1], TypeTag::Vector(_)));
        } else {
            panic!("Expected Struct");
        }
    }
}
