use crate::api_types::address::AccountAddress;
use serde::{Deserialize, Serialize};

/// Represents the initial key into global storage where we first index by the address, and then
/// the struct tag. The struct fields are public to support pattern matching.
#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone, PartialOrd, Ord)]
pub struct ModuleId {
    pub address: AccountAddress,
    pub name: String,
}

impl From<ModuleId> for (AccountAddress, String) {
    fn from(module_id: ModuleId) -> Self {
        (module_id.address, module_id.name)
    }
}

impl ModuleId {
    pub fn new(address: AccountAddress, name: String) -> Self {
        ModuleId { address, name }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address(&self) -> &AccountAddress {
        &self.address
    }
}
