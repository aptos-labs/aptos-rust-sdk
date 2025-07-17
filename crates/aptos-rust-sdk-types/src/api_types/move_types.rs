use crate::api_types::type_tag::{StructTag, TypeTag};
use anyhow::format_err;
use serde::{Deserialize, Serialize, Serializer};
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct MoveStructTag {
    pub address: String,
    pub module: String,
    pub name: String,
    pub generic_type_params: Vec<MoveType>,
}

impl fmt::Display for MoveStructTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}::{}", self.address, self.module, self.name)?;
        if let Some(first_ty) = self.generic_type_params.first() {
            write!(f, "<{}", first_ty)?;
            for ty in self.generic_type_params.iter().skip(1) {
                write!(f, ", {}", ty)?;
            }
            write!(f, ">")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Hash)]
pub enum MoveType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    Address,
    Signer,
    Vector(Box<MoveType>),
    Struct(MoveStructTag),
    Reference { mutable: bool, to: Box<MoveType> },
    GenericTypeParam { index: u16 },
}

impl fmt::Display for MoveType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MoveType::Bool => write!(f, "bool"),
            MoveType::U8 => write!(f, "u8"),
            MoveType::U16 => write!(f, "u16"),
            MoveType::U32 => write!(f, "u32"),
            MoveType::U64 => write!(f, "u64"),
            MoveType::U128 => write!(f, "u128"),
            MoveType::U256 => write!(f, "u256"),
            MoveType::Address => write!(f, "address"),
            MoveType::Signer => write!(f, "signer"),
            MoveType::Vector(items) => write!(f, "vector<{}>", items),
            MoveType::Struct(s) => write!(f, "{}", s),
            MoveType::Reference { mutable, to } => {
                if *mutable {
                    write!(f, "&mut {}", to)
                } else {
                    write!(f, "&{}", to)
                }
            }
            MoveType::GenericTypeParam { index } => write!(f, "T{}", index),
        }
    }
}

impl serde::Serialize for MoveType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

impl TryFrom<MoveType> for TypeTag {
    type Error = anyhow::Error;

    fn try_from(move_type: MoveType) -> Result<Self, Self::Error> {
        match move_type {
            MoveType::Bool => Ok(TypeTag::Bool),
            MoveType::U8 => Ok(TypeTag::U8),
            MoveType::U16 => Ok(TypeTag::U16),
            MoveType::U32 => Ok(TypeTag::U32),
            MoveType::U64 => Ok(TypeTag::U64),
            MoveType::U128 => Ok(TypeTag::U128),
            MoveType::U256 => Ok(TypeTag::U256),
            MoveType::Address => Ok(TypeTag::Address),
            MoveType::Signer => Ok(TypeTag::Signer),
            MoveType::Vector(items) => {
                let inner_type = TypeTag::try_from(*items)?;
                Ok(TypeTag::Vector(Box::new(inner_type)))
            }
            MoveType::Struct(struct_tag) => {
                let type_tag_struct = StructTag {
                    address: crate::api_types::address::AccountAddress::from_str(
                        &struct_tag.address,
                    )?,
                    module: struct_tag.module,
                    name: struct_tag.name,
                    type_args: struct_tag
                        .generic_type_params
                        .into_iter()
                        .map(|t| TypeTag::try_from(t))
                        .collect::<Result<Vec<_>, _>>()?,
                };
                Ok(TypeTag::Struct(Box::new(type_tag_struct)))
            }
            MoveType::Reference { mutable: _, to } => {
                // For view functions, we can't use references, so we convert to the inner type
                // Handle nested cases by recursively converting the inner type
                // But we need to handle nested GenericTypeParam cases properly
                match to.as_ref() {
                    MoveType::Vector(inner) => {
                        // If the inner type is a GenericTypeParam, convert it to a concrete type
                        match inner.as_ref() {
                            MoveType::GenericTypeParam { index: _ } => {
                                Ok(TypeTag::Vector(Box::new(TypeTag::U64)))
                            }
                            _ => {
                                let inner_type = TypeTag::try_from(inner.as_ref().clone())?;
                                Ok(TypeTag::Vector(Box::new(inner_type)))
                            }
                        }
                    }
                    MoveType::Struct(struct_tag) => {
                        // Handle struct with generic parameters
                        let mut type_args = Vec::new();
                        for param in &struct_tag.generic_type_params {
                            let converted = match param {
                                MoveType::GenericTypeParam { index: _ } => TypeTag::U64,
                                _ => TypeTag::try_from(param.clone())?,
                            };
                            type_args.push(converted);
                        }

                        let type_tag_struct = StructTag {
                            address: crate::api_types::address::AccountAddress::from_str(
                                &struct_tag.address,
                            )?,
                            module: struct_tag.module.clone(),
                            name: struct_tag.name.clone(),
                            type_args,
                        };
                        Ok(TypeTag::Struct(Box::new(type_tag_struct)))
                    }
                    _ => TypeTag::try_from(to.as_ref().clone()),
                }
            }
            MoveType::GenericTypeParam { index: _ } => {
                // For view functions, we can't use generic type parameters, so we use a concrete type
                Ok(TypeTag::U64)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_move_struct_tag_display() {
        let tag = MoveStructTag {
            address: "0x1".to_string(),
            module: "Test".to_string(),
            name: "MyStruct".to_string(),
            generic_type_params: vec![MoveType::U8, MoveType::U64],
        };
        let s = format!("{}", tag);
        assert!(s.starts_with("0x1::Test::MyStruct<"));
    }

    #[test]
    fn test_move_type_display() {
        let t = MoveType::Vector(Box::new(MoveType::U8));
        assert_eq!(format!("{}", t), "vector<u8>");
    }
}
