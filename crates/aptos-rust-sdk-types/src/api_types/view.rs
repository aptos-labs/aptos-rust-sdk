use serde::{Deserialize, Serialize};

use crate::api_types::type_tag::TypeTag;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ViewRequest {
    pub function: String,
    pub type_arguments: Vec<TypeTag>,
    pub arguments: Vec<Vec<u8>>,
}
