use serde::{Deserialize, Serialize};

use crate::api_types::type_tag::TypeTag;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ViewRequest {
    pub function: String,
    pub ty_args: Vec<TypeTag>,
    pub args: Vec<Vec<u8>>,
}
