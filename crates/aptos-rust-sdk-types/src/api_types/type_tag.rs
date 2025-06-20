use crate::api_types::address::AccountAddress;
use crate::api_types::module_id::ModuleId;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::str::FromStr;

pub const CODE_TAG: u8 = 0;
pub const RESOURCE_TAG: u8 = 1;

#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone, PartialOrd, Ord)]
pub enum TypeTag {
    // alias for compatibility with old json serialized data.
    #[serde(rename = "bool", alias = "Bool")]
    Bool,
    #[serde(rename = "u8", alias = "U8")]
    U8,
    #[serde(rename = "u64", alias = "U64")]
    U64,
    #[serde(rename = "u128", alias = "U128")]
    U128,
    #[serde(rename = "address", alias = "Address")]
    Address,
    #[serde(rename = "signer", alias = "Signer")]
    Signer,
    #[serde(rename = "vector", alias = "Vector")]
    Vector(Box<TypeTag>),
    #[serde(rename = "struct", alias = "Struct")]
    Struct(Box<StructTag>),

    // NOTE: Added in bytecode version v6, do not reorder!
    #[serde(rename = "u16", alias = "U16")]
    U16,
    #[serde(rename = "u32", alias = "U32")]
    U32,
    #[serde(rename = "u256", alias = "U256")]
    U256,
}

impl TypeTag {
    /// Return a canonical string representation of the type. All types are represented
    /// using their source syntax:
    /// "u8", "u64", "u128", "bool", "address", "vector", "signer" for ground types.
    /// Struct types are represented as fully qualified type names; e.g.
    /// `00000000000000000000000000000001::string::String` or
    /// `0000000000000000000000000000000a::module_name1::type_name1<0000000000000000000000000000000a::module_name2::type_name2<u64>>`
    /// Addresses are hex-encoded lowercase values of length ADDRESS_LENGTH (16, 20, or 32 depending on the Move platform)
    /// Note: this function is guaranteed to be stable, and this is suitable for use inside
    /// Move native functions or the VM. By contrast, the `Display` implementation is subject
    /// to change and should not be used inside stable code.
    pub fn to_canonical_string(&self) -> String {
        use TypeTag::*;
        match self {
            Bool => "bool".to_owned(),
            U8 => "u8".to_owned(),
            U16 => "u16".to_owned(),
            U32 => "u32".to_owned(),
            U64 => "u64".to_owned(),
            U128 => "u128".to_owned(),
            U256 => "u256".to_owned(),
            Address => "address".to_owned(),
            Signer => "signer".to_owned(),
            Vector(t) => format!("vector<{}>", t.to_canonical_string()),
            Struct(s) => s.to_canonical_string(),
        }
    }
}

impl FromStr for TypeTag {
    type Err = anyhow::Error;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        //parse_type_tag(s)
        unimplemented!("Need to implement parse type tag")
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone, PartialOrd, Ord)]
pub struct StructTag {
    pub address: AccountAddress,
    pub module: String,
    pub name: String,
    // alias for compatibility with old json serialized data.
    #[serde(rename = "type_args", alias = "type_params")]
    pub type_params: Vec<TypeTag>,
}

impl StructTag {
    pub fn access_vector(&self) -> Vec<u8> {
        let mut key = vec![RESOURCE_TAG];
        key.append(&mut aptos_bcs::to_bytes(self).unwrap());
        key
    }

    /// Returns true if this is a `StructTag` for an `std::ascii::String` struct defined in the
    /// standard library at address `move_std_addr`.
    pub fn is_ascii_string(&self, move_std_addr: &AccountAddress) -> bool {
        self.address == *move_std_addr
            && self.module.as_str().eq("ascii")
            && self.name.as_str().eq("String")
    }

    /// Returns true if this is a `StructTag` for an `std::string::String` struct defined in the
    /// standard library at address `move_std_addr`.
    pub fn is_std_string(&self, move_std_addr: &AccountAddress) -> bool {
        self.address == *move_std_addr
            && self.module.as_str().eq("string")
            && self.name.as_str().eq("String")
    }

    /// Returns true if this is a `StructTag` for a `std::option::Option` struct defined in the
    /// standard library at address `move_std_addr`.
    pub fn is_std_option(&self, move_std_addr: &AccountAddress) -> bool {
        self.address == *move_std_addr
            && self.module.as_str().eq("option")
            && self.name.as_str().eq("Option")
    }

    pub fn module_id(&self) -> ModuleId {
        ModuleId::new(self.address, self.module.to_owned())
    }

    /// Return a canonical string representation of the struct.
    /// Struct types are represented as fully qualified type names; e.g.
    /// `00000000000000000000000000000001::string::String` or
    /// `0000000000000000000000000000000a::module_name1::type_name1<0000000000000000000000000000000a::module_name2::type_name2<u64>>`
    /// Addresses are hex-encoded lowercase values of length ADDRESS_LENGTH (16, 20, or 32 depending on the Move platform)
    /// Note: this function is guaranteed to be stable, and this is suitable for use inside
    /// Move native functions or the VM. By contrast, the `Display` implementation is subject
    /// to change and should not be used inside stable code.
    pub fn to_canonical_string(&self) -> String {
        let mut generics = String::new();
        if let Some(first_ty) = self.type_params.first() {
            generics.push('<');
            generics.push_str(&first_ty.to_canonical_string());
            for ty in self.type_params.iter().skip(1) {
                generics.push_str(&ty.to_canonical_string())
            }
            generics.push('>');
        }
        format!(
            "{}::{}::{}{}",
            self.address, self.module, self.name, generics
        )
    }
}

impl FromStr for StructTag {
    type Err = anyhow::Error;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        // TODO
        unimplemented!("Need to implement parse struct tag")
    }
}
