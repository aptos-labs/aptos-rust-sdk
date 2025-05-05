// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use aptos_rust_sdk_types::error::{AptosError, RestError};
use aptos_rust_sdk_types::state::State;
use aptos_rust_sdk_types::AptosResult;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use std::fmt::Debug;

/// A response type to hold fullnode responses with strong typing
#[derive(Debug)]
pub struct FullnodeResponse<T> {
    inner: T,
    /// The common state for a Fullnode API response, e.g. current ledger version
    state: State,
}

impl<T> FullnodeResponse<T> {
    /// Create a new response, this shouldn't be created outside of the client
    pub(crate) fn new(inner: T, state: State) -> Self {
        Self { inner, state }
    }

    /// Retrieve the inner type by reference
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Retrieve the inner type by destroying the response
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Retrieve the inner blockchain state by reference
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Retrieve both the inner type and the state by destroying the response
    pub fn into_parts(self) -> (T, State) {
        (self.inner, self.state)
    }

    /// Allow for chaining of blocks on the response based on result
    pub fn and_then<U, E, F>(self, f: F) -> Result<FullnodeResponse<U>, E>
    where
        F: FnOnce(T) -> Result<U, E>,
    {
        let (inner, state) = self.into_parts();
        match f(inner) {
            Ok(new_inner) => Ok(FullnodeResponse::new(new_inner, state)),
            Err(err) => Err(err),
        }
    }

    /// Map the response into a new response
    pub fn map<U, F>(self, f: F) -> FullnodeResponse<U>
    where
        F: FnOnce(T) -> U,
    {
        let (inner, state) = self.into_parts();
        FullnodeResponse::new(f(inner), state)
    }
}

/// A wrapper struct to make operations around the parsed HTTP response much easier
pub struct ParsableResponse(pub reqwest::Response);

impl ParsableResponse {
    /// Retrieves the blockchain state from the headers
    pub(crate) fn state(&self) -> anyhow::Result<State> {
        State::from_headers(self.0.headers())
    }

    /// Retrieves the HTTP status code
    fn status(&self) -> StatusCode {
        self.0.status()
    }

    /// Checks the responses headers, and parses the state out of the response
    pub(crate) async fn parse_response<T: DeserializeOwned>(
        self,
    ) -> AptosResult<FullnodeResponse<T>> {
        if !self.status().is_success() {
            println!("Error: {:?}", self.status());
            Err(self.parse_error().await)
        } else {
            let state = self.state()?;

            Ok(FullnodeResponse::new(self.0.bytes().await?, state)
                .and_then(|inner| serde_json::from_slice(&inner))?)
        }
    }

    /// Parses an error if it was an error state
    async fn parse_error(self) -> RestError {
        let status_code = self.status();

        let maybe_state = self.state().map(Some).unwrap_or(None);
        match self.0.json::<AptosError>().await {
            Ok(error) => (error, maybe_state, status_code).into(),
            Err(e) => RestError::Http(status_code, e),
        }
    }
}
