mod api_types;
pub mod crypto;
pub mod error;
pub mod headers;
pub mod mime_types;
pub mod state;
pub mod serializable;

use crate::error::RestError;

pub type AptosResult<T> = Result<T, RestError>;
