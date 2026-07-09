//! Event types.
//!
//! Events are emitted by Move modules and can be used to track
//! on-chain activity without reading full transaction data.
//!
//! These types deserialize the JSON shape returned by the Aptos REST
//! (fullnode) API. In particular, the API encodes every `u64` value as a JSON
//! string (e.g. `"42"`), and the on-chain event-handle GUID nests its fields
//! under an `id` object (`{"id":{"addr":...,"creation_num":...}}`). The types
//! here match those shapes; for convenience the string-encoded integers also
//! accept a plain JSON number when deserializing.

use crate::types::{AccountAddress, HashValue};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A unique identifier for an event stream.
///
/// Event keys are composed of a creation number and an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventKey {
    /// The creation number (unique within the account).
    pub creation_number: u64,
    /// The account address that owns this event stream.
    pub account_address: AccountAddress,
}

impl EventKey {
    /// Creates a new event key.
    pub fn new(creation_number: u64, account_address: AccountAddress) -> Self {
        Self {
            creation_number,
            account_address,
        }
    }
}

impl fmt::Display for EventKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.account_address, self.creation_number)
    }
}

/// A handle to an event stream stored on chain.
///
/// This matches the REST API shape of an on-chain `0x1::event::EventHandle`,
/// where the `guid` is a `0x1::guid::GUID` nested under an `id` object:
/// `{"counter":"N","guid":{"id":{"addr":"0x..","creation_num":"N"}}}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventHandle {
    /// The number of events that have been emitted to this handle.
    #[serde(with = "crate::types::string_num")]
    pub counter: u64,
    /// The globally unique ID for this event stream.
    pub guid: EventHandleGuid,
}

/// The GUID of an on-chain event handle.
///
/// Mirrors the REST API's `0x1::guid::GUID`, which wraps the identifying
/// fields under an `id` object: `{"id":{"addr":...,"creation_num":...}}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventHandleGuid {
    /// The inner identifier (address + creation number).
    pub id: EventHandleGuidId,
}

/// The inner identifier of an [`EventHandleGuid`] (`0x1::guid::ID`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventHandleGuidId {
    /// The account address that created the event stream.
    pub addr: AccountAddress,
    /// The creation number (unique within the creating account).
    #[serde(with = "crate::types::string_num")]
    pub creation_num: u64,
}

/// A globally unique identifier for an event stream.
///
/// This matches the shape used by the REST API for an emitted [`Event`]'s
/// `guid` field (`{"creation_number":...,"account_address":...}`), which
/// differs from the nested [`EventHandleGuid`] shape used inside on-chain
/// event handles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventGuid {
    /// The creation number.
    #[serde(with = "crate::types::string_num")]
    pub creation_number: u64,
    /// The account address.
    pub account_address: AccountAddress,
}

/// An event emitted during transaction execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// The globally unique identifier for this event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guid: Option<EventGuid>,
    /// The sequence number of this event within its stream.
    #[serde(with = "crate::types::string_num")]
    pub sequence_number: u64,
    /// The type of the event data.
    #[serde(rename = "type")]
    pub typ: String,
    /// The event data as JSON.
    pub data: serde_json::Value,
}

impl Event {
    /// Returns the event type as a string.
    pub fn event_type(&self) -> &str {
        &self.typ
    }

    /// Tries to deserialize the event data into a specific type.
    ///
    /// # Errors
    ///
    /// Returns an error if the event data cannot be deserialized into the requested type.
    pub fn data_as<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.data.clone())
    }
}

/// A versioned event from the indexer (includes transaction context).
#[allow(dead_code)] // Public API for users
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedEvent {
    /// The transaction version that emitted this event.
    #[serde(with = "crate::types::string_num")]
    pub version: u64,
    /// The event itself.
    #[serde(flatten)]
    pub event: Event,
    /// The transaction hash (optional, from indexer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_hash: Option<HashValue>,
}

/// Common event types in the Aptos framework.
#[allow(dead_code)] // Public API constants for users
pub mod framework {
    /// Event type for coin deposits.
    pub const DEPOSIT_EVENT: &str = "0x1::coin::DepositEvent";
    /// Event type for coin withdrawals.
    pub const WITHDRAW_EVENT: &str = "0x1::coin::WithdrawEvent";
    /// Event type for account creation.
    pub const ACCOUNT_CREATE_EVENT: &str = "0x1::account::CreateAccountEvent";
    /// Event type for key rotation.
    pub const KEY_ROTATION_EVENT: &str = "0x1::account::KeyRotationEvent";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_key() {
        let key = EventKey::new(42, AccountAddress::ONE);
        assert_eq!(key.creation_number, 42);
        assert_eq!(key.account_address, AccountAddress::ONE);
    }

    #[test]
    fn test_event_key_display() {
        let key = EventKey::new(42, AccountAddress::ONE);
        let display = format!("{key}");
        assert!(display.contains("42"));
        assert!(display.contains(':'));
    }

    #[test]
    fn test_event_deserialization() {
        let json = r#"{
            "sequence_number": 1,
            "type": "0x1::coin::DepositEvent",
            "data": {"amount": "1000"}
        }"#;

        let event: Event = serde_json::from_str(json).unwrap();
        assert_eq!(event.sequence_number, 1);
        assert_eq!(event.typ, "0x1::coin::DepositEvent");
    }

    #[test]
    fn test_event_type() {
        let json = r#"{
            "sequence_number": 1,
            "type": "0x1::coin::DepositEvent",
            "data": {"amount": "1000"}
        }"#;

        let event: Event = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type(), "0x1::coin::DepositEvent");
    }

    #[test]
    fn test_event_data_as() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct DepositEvent {
            amount: String,
        }

        let json = r#"{
            "sequence_number": 1,
            "type": "0x1::coin::DepositEvent",
            "data": {"amount": "1000"}
        }"#;

        let event: Event = serde_json::from_str(json).unwrap();
        let data: DepositEvent = event.data_as().unwrap();
        assert_eq!(data.amount, "1000");
    }

    #[test]
    fn test_event_handle_deserialization() {
        // Realistic fullnode shape: string-encoded integers and a nested
        // `guid.id` object.
        let json = r#"{
            "counter": "100",
            "guid": {
                "id": {
                    "addr": "0x1",
                    "creation_num": "5"
                }
            }
        }"#;

        let handle: EventHandle = serde_json::from_str(json).unwrap();
        assert_eq!(handle.counter, 100);
        assert_eq!(handle.guid.id.creation_num, 5);
        assert_eq!(handle.guid.id.addr, AccountAddress::ONE);
    }

    #[test]
    fn test_event_handle_roundtrips_to_api_shape() {
        let handle = EventHandle {
            counter: 7,
            guid: EventHandleGuid {
                id: EventHandleGuidId {
                    addr: AccountAddress::ONE,
                    creation_num: 3,
                },
            },
        };
        let json = serde_json::to_value(&handle).unwrap();
        // Integers must serialize back as strings to match the API.
        assert_eq!(json["counter"], serde_json::json!("7"));
        assert_eq!(json["guid"]["id"]["creation_num"], serde_json::json!("3"));
        let back: EventHandle = serde_json::from_value(json).unwrap();
        assert_eq!(back, handle);
    }

    #[test]
    fn test_event_deserialization_api_shape() {
        // Realistic fullnode event: u64 fields are JSON strings and the guid
        // uses the {creation_number, account_address} shape.
        let json = r#"{
            "guid": {
                "creation_number": "2",
                "account_address": "0x1"
            },
            "sequence_number": "42",
            "type": "0x1::coin::DepositEvent",
            "data": {"amount": "1000"}
        }"#;

        let event: Event = serde_json::from_str(json).unwrap();
        assert_eq!(event.sequence_number, 42);
        assert_eq!(event.typ, "0x1::coin::DepositEvent");
        let guid = event.guid.expect("guid present");
        assert_eq!(guid.creation_number, 2);
        assert_eq!(guid.account_address, AccountAddress::ONE);
    }

    #[test]
    fn test_event_guid() {
        let guid = EventGuid {
            creation_number: 10,
            account_address: AccountAddress::ONE,
        };
        assert_eq!(guid.creation_number, 10);
        assert_eq!(guid.account_address, AccountAddress::ONE);
    }

    #[test]
    fn test_versioned_event_deserialization() {
        let json = r#"{
            "version": 12345,
            "sequence_number": 1,
            "type": "0x1::coin::DepositEvent",
            "data": {"amount": "1000"}
        }"#;

        let event: VersionedEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.version, 12345);
        assert_eq!(event.event.sequence_number, 1);
    }

    #[test]
    fn test_framework_event_constants() {
        assert_eq!(framework::DEPOSIT_EVENT, "0x1::coin::DepositEvent");
        assert_eq!(framework::WITHDRAW_EVENT, "0x1::coin::WithdrawEvent");
        assert_eq!(
            framework::ACCOUNT_CREATE_EVENT,
            "0x1::account::CreateAccountEvent"
        );
        assert_eq!(
            framework::KEY_ROTATION_EVENT,
            "0x1::account::KeyRotationEvent"
        );
    }
}
