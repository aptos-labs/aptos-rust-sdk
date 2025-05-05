use hex::FromHex;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountResource {
    #[serde(rename = "type")]
    pub type_: String,
    pub data: serde_json::Value,
}