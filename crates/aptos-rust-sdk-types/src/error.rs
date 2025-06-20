// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::state::State;
use reqwest::header::{InvalidHeaderName, InvalidHeaderValue};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// These codes provide more granular error information beyond just the HTTP
/// status code of the response.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u32)]
pub enum AptosErrorCode {
    /// Account not found at the requested version
    AccountNotFound = 101,
    /// Resource not found at the requested version
    ResourceNotFound = 102,
    /// Module not found at the requested version
    ModuleNotFound = 103,
    /// Struct field not found at the requested version
    StructFieldNotFound = 104,
    /// Ledger version not found at the requested version
    ///
    /// Usually means that the version is ahead of the latest version
    VersionNotFound = 105,
    /// Transaction not found at the requested version or with the requested hash
    TransactionNotFound = 106,
    /// Table item not found at the requested version
    TableItemNotFound = 107,
    /// Block not found at the requested version or height
    ///
    /// Usually means the block is fully or partially pruned or the height / version is ahead
    /// of the latest version
    BlockNotFound = 108,
    ///  StateValue not found at the requested version
    StateValueNotFound = 109,

    /// Ledger version is pruned
    VersionPruned = 200,
    /// Block is fully or partially pruned
    BlockPruned = 201,

    /// The API's inputs were invalid
    InvalidInput = 300,

    /// The transaction was an invalid update to an already submitted transaction.
    InvalidTransactionUpdate = 401,
    /// The sequence number for the transaction is behind the latest sequence number.
    SequenceNumberTooOld = 402,
    /// The submitted transaction failed VM checks.
    VmError = 403,

    /// Health check failed.
    HealthCheckFailed = 500,
    /// The mempool is full, no new transactions can be submitted.
    MempoolIsFull = 501,

    /// Internal server error
    InternalError = 600,
    /// Error from the web framework
    WebFrameworkError = 601,
    /// BCS format is not supported on this API.
    BcsNotSupported = 602,
    /// API Disabled
    ApiDisabled = 603,
}

/// This is the generic struct we use for all API errors, it contains a string
/// message and an Aptos API specific error code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AptosError {
    /// A message describing the error
    pub message: String,
    pub error_code: AptosErrorCode,
    /// A code providing VM error details when submitting transactions to the VM
    pub vm_error_code: Option<u64>,
}

#[derive(Debug)]
pub struct FaucetClientError {
    inner: Box<Inner>,
}

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug)]
struct Inner {
    kind: Kind,
    source: Option<BoxError>,
}

#[derive(Debug)]
enum Kind {
    HttpStatus(u16),
    Timeout,
    Request,
    RpcResponse,
    ChainId,
    StaleResponse,
    Batch,
    Decode,
    InvalidProof,
    NeedSync,
    StateStore,
    Unknown,
}

impl FaucetClientError {
    pub fn is_retriable(&self) -> bool {
        match self.inner.kind {
            // internal server errors are retriable
            Kind::HttpStatus(status) => (500..=599).contains(&status),
            Kind::Timeout | Kind::StaleResponse | Kind::NeedSync => true,
            Kind::RpcResponse
            | Kind::Request
            | Kind::ChainId
            | Kind::Batch
            | Kind::Decode
            | Kind::InvalidProof
            | Kind::StateStore
            | Kind::Unknown => false,
        }
    }

    pub fn is_need_sync(&self) -> bool {
        matches!(self.inner.kind, Kind::NeedSync)
    }

    //
    // Private Constructors
    //

    fn new<E: Into<BoxError>>(kind: Kind, source: Option<E>) -> Self {
        Self {
            inner: Box::new(Inner {
                kind,
                source: source.map(Into::into),
            }),
        }
    }

    pub fn status(status: u16) -> Self {
        Self::new(Kind::HttpStatus(status), None::<FaucetClientError>)
    }

    pub fn timeout<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::Timeout, Some(e))
    }

    pub fn rpc_response<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::RpcResponse, Some(e))
    }

    pub fn batch<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::Batch, Some(e))
    }

    pub fn decode<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::Decode, Some(e))
    }

    pub fn encode<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::Decode, Some(e))
    }

    pub fn invalid_proof<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::InvalidProof, Some(e))
    }

    pub fn state_store<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::StateStore, Some(e))
    }

    pub fn need_sync<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::NeedSync, Some(e))
    }

    pub fn unknown<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::Unknown, Some(e))
    }

    pub fn request<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::Request, Some(e))
    }

    pub fn chain_id(expected: u8, recieved: u8) -> Self {
        Self::new(
            Kind::ChainId,
            Some(format!("expected: {} recieved: {}", expected, recieved)),
        )
    }

    pub fn stale<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::StaleResponse, Some(e))
    }
}

impl std::fmt::Display for FaucetClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for FaucetClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source.as_ref().map(|e| &**e as _)
    }
}

impl From<serde_json::Error> for FaucetClientError {
    fn from(e: serde_json::Error) -> Self {
        Self::decode(e)
    }
}

#[derive(Debug, Error)]
pub enum RestError {
    #[error("API error {0}")]
    Api(AptosErrorResponse),
    #[error("BCS ser/de error {0}")]
    Bcs(aptos_bcs::Error),
    #[error("JSON er/de error {0}")]
    Json(serde_json::Error),
    #[error("URL Parse error {0}")]
    UrlParse(url::ParseError),
    #[error("Timeout waiting for transaction {0}")]
    Timeout(&'static str),
    #[error("Unknown error {0}")]
    Unknown(anyhow::Error),
    #[error("HTTP error {0}: {1}")]
    Http(StatusCode, reqwest::Error),
}

impl From<(AptosError, Option<State>, StatusCode)> for RestError {
    fn from((error, state, status_code): (AptosError, Option<State>, StatusCode)) -> Self {
        Self::Api(AptosErrorResponse {
            error,
            state,
            status_code,
        })
    }
}

impl From<aptos_bcs::Error> for RestError {
    fn from(err: aptos_bcs::Error) -> Self {
        Self::Bcs(err)
    }
}

impl From<url::ParseError> for RestError {
    fn from(err: url::ParseError) -> Self {
        Self::UrlParse(err)
    }
}

impl From<serde_json::Error> for RestError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

impl From<anyhow::Error> for RestError {
    fn from(err: anyhow::Error) -> Self {
        Self::Unknown(err)
    }
}

impl From<reqwest::Error> for RestError {
    fn from(err: reqwest::Error) -> Self {
        if let Some(status) = err.status() {
            RestError::Http(status, err)
        } else {
            RestError::Unknown(err.into())
        }
    }
}

impl From<InvalidHeaderName> for RestError {
    fn from(value: InvalidHeaderName) -> Self {
        RestError::Unknown(value.into())
    }
}

impl From<InvalidHeaderValue> for RestError {
    fn from(value: InvalidHeaderValue) -> Self {
        RestError::Unknown(value.into())
    }
}

#[derive(Debug)]
pub struct AptosErrorResponse {
    pub error: AptosError,
    pub state: Option<State>,
    pub status_code: StatusCode,
}

impl std::fmt::Display for AptosErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.error)
    }
}
