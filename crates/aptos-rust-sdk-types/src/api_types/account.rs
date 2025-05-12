use super::transaction_authenticator::AuthenticationKey;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, str::FromStr};

#[derive(Debug)]
pub struct Account {
    pub sequence_number: u64,
    pub authentication_key: AuthenticationKey,
}

impl<'de> Deserialize<'de> for Account {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawAccount {
            sequence_number: String,
            authentication_key: String,
        }

        let raw = RawAccount::deserialize(deserializer)?;

        let sequence_number = raw.sequence_number.parse::<u64>().map_err(|e| {
            serde::de::Error::custom(format!("Failed to parse sequence_number: {}", e))
        })?;

        let authentication_key =
            AuthenticationKey::from_str(&raw.authentication_key).map_err(|e| {
                serde::de::Error::custom(format!("Failed to parse authentication_key: {}", e))
            })?;

        Ok(Account {
            sequence_number,
            authentication_key,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountResource {
    #[serde(rename = "type")]
    pub type_: String,
    pub data: serde_json::Value,
}
