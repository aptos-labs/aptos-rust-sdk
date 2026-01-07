//! ABI type definitions for parsing Move module ABIs.

use serde::{Deserialize, Serialize};

/// Move module ABI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveModuleABI {
    /// The module address.
    pub address: String,
    /// The module name.
    pub name: String,
    /// Exposed functions.
    #[serde(default)]
    pub exposed_functions: Vec<MoveFunction>,
    /// Structs defined in the module.
    #[serde(default)]
    pub structs: Vec<MoveStructDef>,
}

/// A function defined in a Move module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveFunction {
    /// Function name.
    pub name: String,
    /// Visibility.
    #[serde(default)]
    pub visibility: String,
    /// Whether this is an entry function.
    #[serde(default)]
    pub is_entry: bool,
    /// Whether this is a view function.
    #[serde(default)]
    pub is_view: bool,
    /// Generic type parameters.
    #[serde(default)]
    pub generic_type_params: Vec<MoveFunctionGenericTypeParam>,
    /// Function parameters.
    #[serde(default)]
    pub params: Vec<String>,
    /// Return types.
    #[serde(default, rename = "return")]
    pub returns: Vec<String>,
}

/// Generic type parameter in a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveFunctionGenericTypeParam {
    /// Constraints on the type parameter.
    #[serde(default)]
    pub constraints: Vec<String>,
}

/// A struct defined in a Move module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveStructDef {
    /// Struct name.
    pub name: String,
    /// Whether this is a native struct.
    #[serde(default)]
    pub is_native: bool,
    /// Abilities of the struct.
    #[serde(default)]
    pub abilities: Vec<String>,
    /// Generic type parameters.
    #[serde(default)]
    pub generic_type_params: Vec<MoveStructGenericTypeParam>,
    /// Fields of the struct.
    #[serde(default)]
    pub fields: Vec<MoveStructField>,
}

/// Generic type parameter in a struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveStructGenericTypeParam {
    /// Constraints on the type parameter.
    #[serde(default)]
    pub constraints: Vec<String>,
}

/// A field in a Move struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveStructField {
    /// Field name.
    pub name: String,
    /// Field type.
    #[serde(rename = "type")]
    pub typ: String,
}

