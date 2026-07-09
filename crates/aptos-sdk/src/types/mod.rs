//! Core Aptos types.
//!
//! This module contains the fundamental types used throughout the SDK,
//! including addresses, chain IDs, type tags, and hash values.

mod address;
mod chain_id;
mod events;
mod hash;
mod move_types;
mod resources;

pub use address::{ADDRESS_LENGTH, AccountAddress};
pub use chain_id::ChainId;
pub use events::{
    Event, EventGuid, EventHandle, EventHandleGuid, EventHandleGuidId, EventKey, VersionedEvent,
    framework as event_types,
};
pub use hash::{HASH_LENGTH, HashValue};
pub use move_types::{
    EntryFunctionId, Identifier, MoveModuleId, MoveResource, MoveStruct, MoveStructTag, MoveType,
    MoveValue, StructTag, TypeTag,
};
pub use resources::{
    APT_COIN_STORE_TYPE, AccountResource, CoinInfo, CoinStoreResource, CollectionData,
    FungibleAssetBalance, FungibleAssetMetadata, StakePool, StakingConfig, TokenData,
};

/// Serde helpers for integers that the Aptos REST (fullnode) API encodes as
/// JSON strings (e.g. `"42"`).
///
/// The fullnode encodes all `u64` / `u128` values as JSON strings to avoid
/// precision loss in JSON parsers that use IEEE-754 doubles. The resource and
/// event types in this module deserialize that shape. For convenience (and to
/// keep round-tripping simple) these helpers also accept a plain JSON number,
/// and always serialize back to a string so the output matches the API shape.
pub(crate) mod string_num {
    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;
    use std::marker::PhantomData;
    use std::str::FromStr;

    /// Serializes a value as its decimal string representation.
    pub(crate) fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: fmt::Display,
    {
        serializer.collect_str(value)
    }

    /// Deserializes a value from either a JSON string or a JSON number.
    pub(crate) fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromStr,
        <T as FromStr>::Err: fmt::Display,
    {
        deserializer.deserialize_any(NumVisitor(PhantomData))
    }

    struct NumVisitor<T>(PhantomData<T>);

    impl<T> Visitor<'_> for NumVisitor<T>
    where
        T: FromStr,
        <T as FromStr>::Err: fmt::Display,
    {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string-encoded integer or an integer")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.parse().map_err(de::Error::custom)
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.to_string().parse().map_err(de::Error::custom)
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.to_string().parse().map_err(de::Error::custom)
        }

        fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.to_string().parse().map_err(de::Error::custom)
        }

        fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.to_string().parse().map_err(de::Error::custom)
        }
    }
}
