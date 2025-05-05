use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountResource {
    #[serde(rename = "type")]
    pub type_: String,
    pub data: serde_json::Value,
}