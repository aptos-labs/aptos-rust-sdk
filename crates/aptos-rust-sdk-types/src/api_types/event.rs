use crate::api_types::address::AccountAddress;
use crate::api_types::type_tag::TypeTag;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EventKey {
    creation_number: u64,
    account_address: AccountAddress,
}

#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContractEvent {
    V1(ContractEventV1),
    V2(ContractEventV2),
}

#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractEventV1 {
    /// The unique key that the event was emitted to
    key: EventKey,
    /// The number of messages that have been emitted to the path previously
    sequence_number: u64,
    /// The type of the data
    type_tag: TypeTag,
    /// The data payload of the event
    #[serde(with = "serde_bytes")]
    event_data: Vec<u8>,
}

/// Entry produced via a call to the `emit` builtin.
#[derive(Debug, Hash, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractEventV2 {
    /// The type of the data
    type_tag: TypeTag,
    /// The data payload of the event
    #[serde(with = "serde_bytes")]
    event_data: Vec<u8>,
}
