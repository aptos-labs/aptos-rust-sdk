//! Event types.
//!
//! Events are emitted by Move modules and can be used to track
//! on-chain activity without reading full transaction data.

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventHandle {
    /// The number of events that have been emitted to this handle.
    pub counter: u64,
    /// The globally unique ID for this event stream.
    pub guid: EventGuid,
}

/// A globally unique identifier for an event stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventGuid {
    /// The creation number.
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
        let display = format!("{}", key);
        assert!(display.contains("42"));
        assert!(display.contains(":"));
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
        let json = r#"{
            "counter": 100,
            "guid": {
                "creation_number": 5,
                "account_address": "0x1"
            }
        }"#;

        let handle: EventHandle = serde_json::from_str(json).unwrap();
        assert_eq!(handle.counter, 100);
        assert_eq!(handle.guid.creation_number, 5);
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
