use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

// TODO: Convert to bytes?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashValue(String); // TODO: add validation and all

impl Display for HashValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
