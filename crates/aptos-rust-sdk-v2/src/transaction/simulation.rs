//! Transaction simulation for pre-flight validation.
//!
//! This module provides utilities for simulating transactions before submission
//! to predict outcomes, estimate gas costs, and catch errors early.
//!
//! # Overview
//!
//! Transaction simulation allows you to:
//! - **Predict success/failure** before spending gas
//! - **Estimate gas costs** more accurately than the gas estimator
//! - **Debug transactions** by examining execution details
//! - **Validate payloads** before committing to transactions
//!
//! # Example
//!
//! ```rust,ignore
//! use aptos_rust_sdk_v2::transaction::simulation::SimulationResult;
//!
//! let aptos = Aptos::testnet()?;
//!
//! // Simulate a transaction
//! let result = aptos.simulate_payload(&account, payload).await?;
//!
//! if result.success() {
//!     println!("Transaction will succeed!");
//!     println!("Estimated gas: {}", result.gas_used());
//! } else {
//!     println!("Transaction will fail: {}", result.vm_status());
//! }
//! ```

use crate::error::{AptosError, AptosResult};
use serde::{Deserialize, Serialize};

/// Result of a transaction simulation.
///
/// Contains detailed information about what would happen if the transaction
/// were submitted to the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    /// Whether the transaction would succeed.
    success: bool,
    /// The VM status (explains failure if not successful).
    vm_status: String,
    /// Gas used by the transaction.
    gas_used: u64,
    /// Maximum gas amount specified.
    max_gas_amount: u64,
    /// Gas unit price.
    gas_unit_price: u64,
    /// Changes that would be made to the state.
    changes: Vec<StateChange>,
    /// Events that would be emitted.
    events: Vec<SimulatedEvent>,
    /// The transaction hash (would be this if submitted).
    hash: String,
    /// Detailed VM error information (if failed).
    vm_error: Option<VmError>,
    /// Raw response data for advanced use.
    raw: serde_json::Value,
}

impl SimulationResult {
    /// Parses a simulation result from the API response.
    pub fn from_response(response: Vec<serde_json::Value>) -> AptosResult<Self> {
        let data = response.into_iter().next().ok_or_else(|| AptosError::Api {
            status_code: 200,
            message: "Empty simulation response".into(),
            error_code: None,
            vm_error_code: None,
        })?;

        Self::from_json(data)
    }

    /// Parses a simulation result from JSON.
    pub fn from_json(data: serde_json::Value) -> AptosResult<Self> {
        let success = data
            .get("success")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let vm_status = data
            .get("vm_status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Unknown")
            .to_string();

        let gas_used = data
            .get("gas_used")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let max_gas_amount = data
            .get("max_gas_amount")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let gas_unit_price = data
            .get("gas_unit_price")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let hash = data
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();

        // Parse state changes
        let changes = data
            .get("changes")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|c| StateChange::from_json(c).ok())
                    .collect()
            })
            .unwrap_or_default();

        // Parse events
        let events = data
            .get("events")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| SimulatedEvent::from_json(e).ok())
                    .collect()
            })
            .unwrap_or_default();

        // Parse VM error if present
        let vm_error = if !success {
            VmError::from_status(&vm_status)
        } else {
            None
        };

        Ok(Self {
            success,
            vm_status,
            gas_used,
            max_gas_amount,
            gas_unit_price,
            changes,
            events,
            hash,
            vm_error,
            raw: data,
        })
    }

    /// Returns whether the transaction would succeed.
    pub fn success(&self) -> bool {
        self.success
    }

    /// Returns whether the transaction would fail.
    pub fn failed(&self) -> bool {
        !self.success
    }

    /// Returns the VM status message.
    pub fn vm_status(&self) -> &str {
        &self.vm_status
    }

    /// Returns the gas that would be used.
    pub fn gas_used(&self) -> u64 {
        self.gas_used
    }

    /// Returns the maximum gas amount specified.
    pub fn max_gas_amount(&self) -> u64 {
        self.max_gas_amount
    }

    /// Returns the gas unit price.
    pub fn gas_unit_price(&self) -> u64 {
        self.gas_unit_price
    }

    /// Returns the total gas cost in octas.
    pub fn gas_cost(&self) -> u64 {
        self.gas_used.saturating_mul(self.gas_unit_price)
    }

    /// Returns the estimated gas cost with a safety margin.
    ///
    /// Adds 20% to the simulated gas to account for variations.
    pub fn safe_gas_estimate(&self) -> u64 {
        self.gas_used.saturating_mul(120) / 100
    }

    /// Returns the state changes that would be made.
    pub fn changes(&self) -> &[StateChange] {
        &self.changes
    }

    /// Returns the events that would be emitted.
    pub fn events(&self) -> &[SimulatedEvent] {
        &self.events
    }

    /// Returns the transaction hash (would be this if submitted).
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Returns detailed VM error information if the simulation failed.
    pub fn vm_error(&self) -> Option<&VmError> {
        self.vm_error.as_ref()
    }

    /// Returns the raw JSON response for advanced use.
    pub fn raw(&self) -> &serde_json::Value {
        &self.raw
    }

    /// Checks if the failure is due to insufficient balance.
    pub fn is_insufficient_balance(&self) -> bool {
        self.vm_error
            .as_ref()
            .is_some_and(VmError::is_insufficient_balance)
    }

    /// Checks if the failure is due to sequence number issues.
    pub fn is_sequence_number_error(&self) -> bool {
        self.vm_error
            .as_ref()
            .is_some_and(VmError::is_sequence_number_error)
    }

    /// Checks if the failure is due to out of gas.
    pub fn is_out_of_gas(&self) -> bool {
        self.vm_error.as_ref().is_some_and(VmError::is_out_of_gas)
    }

    /// Returns a user-friendly error message if the simulation failed.
    pub fn error_message(&self) -> Option<String> {
        if self.success {
            return None;
        }

        self.vm_error
            .as_ref()
            .map(VmError::user_message)
            .or_else(|| Some(self.vm_status.clone()))
    }
}

/// A state change from a simulated transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    /// Type of change (write_resource, delete_resource, etc.)
    pub change_type: String,
    /// Address affected.
    pub address: String,
    /// Resource type (for resource changes).
    pub resource_type: Option<String>,
    /// Module name (for module changes).
    pub module: Option<String>,
    /// The new data (for writes).
    pub data: Option<serde_json::Value>,
}

impl StateChange {
    fn from_json(json: &serde_json::Value) -> AptosResult<Self> {
        Ok(Self {
            change_type: json
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            address: json
                .get("address")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
            resource_type: json
                .get("data")
                .and_then(|d| d.get("type"))
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string),
            module: json
                .get("module")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string),
            data: json.get("data").cloned(),
        })
    }

    /// Returns true if this is a resource write.
    pub fn is_write(&self) -> bool {
        self.change_type == "write_resource"
    }

    /// Returns true if this is a resource delete.
    pub fn is_delete(&self) -> bool {
        self.change_type == "delete_resource"
    }
}

/// An event from a simulated transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedEvent {
    /// The event type.
    pub event_type: String,
    /// Sequence number of the event.
    pub sequence_number: u64,
    /// Event data.
    pub data: serde_json::Value,
}

impl SimulatedEvent {
    fn from_json(json: &serde_json::Value) -> AptosResult<Self> {
        Ok(Self {
            event_type: json
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sequence_number: json
                .get("sequence_number")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            data: json.get("data").cloned().unwrap_or(serde_json::Value::Null),
        })
    }
}

/// Detailed VM error information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmError {
    /// Error category.
    pub category: VmErrorCategory,
    /// The raw VM status string.
    pub status: String,
    /// Abort code (if applicable).
    pub abort_code: Option<u64>,
    /// Location of the error (module::function).
    pub location: Option<String>,
}

impl VmError {
    fn from_status(status: &str) -> Option<Self> {
        let category = VmErrorCategory::from_status(status);

        // Try to extract abort code
        let abort_code = if status.contains("ABORTED") {
            // Parse abort code from status like "Move abort in 0x1::coin: EINSUFFICIENT_BALANCE(0x10001)"
            status
                .split('(')
                .nth(1)
                .and_then(|s| s.trim_end_matches(')').parse().ok())
        } else {
            None
        };

        // Try to extract location
        let location = if status.contains("::") {
            status
                .split_whitespace()
                .find(|s| s.contains("::"))
                .map(|s| s.trim_end_matches(':').to_string())
        } else {
            None
        };

        Some(Self {
            category,
            status: status.to_string(),
            abort_code,
            location,
        })
    }

    /// Returns true if this is an insufficient balance error.
    pub fn is_insufficient_balance(&self) -> bool {
        matches!(self.category, VmErrorCategory::InsufficientBalance)
            || self.status.contains("INSUFFICIENT")
            || self.status.contains("NOT_ENOUGH")
    }

    /// Returns true if this is a sequence number error.
    pub fn is_sequence_number_error(&self) -> bool {
        matches!(self.category, VmErrorCategory::SequenceNumber)
    }

    /// Returns true if this is an out of gas error.
    pub fn is_out_of_gas(&self) -> bool {
        matches!(self.category, VmErrorCategory::OutOfGas)
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self.category {
            VmErrorCategory::InsufficientBalance => {
                "Insufficient balance to complete this transaction".to_string()
            }
            VmErrorCategory::SequenceNumber => {
                "Transaction sequence number mismatch - the account's sequence number may have changed".to_string()
            }
            VmErrorCategory::OutOfGas => {
                "Transaction ran out of gas - try increasing max_gas_amount".to_string()
            }
            VmErrorCategory::MoveAbort => {
                if let Some(code) = self.abort_code {
                    format!("Transaction aborted with code {code}")
                } else {
                    "Transaction was aborted by the Move VM".to_string()
                }
            }
            VmErrorCategory::ResourceNotFound => {
                "Required resource not found on chain".to_string()
            }
            VmErrorCategory::ModuleNotFound => {
                "Required module not found on chain".to_string()
            }
            VmErrorCategory::FunctionNotFound => {
                "Function not found in the specified module".to_string()
            }
            VmErrorCategory::TypeMismatch => {
                "Type argument mismatch in function call".to_string()
            }
            VmErrorCategory::Unknown => self.status.clone(),
        }
    }
}

/// Categories of VM errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmErrorCategory {
    /// Insufficient account balance.
    InsufficientBalance,
    /// Sequence number mismatch.
    SequenceNumber,
    /// Ran out of gas.
    OutOfGas,
    /// Move abort (smart contract error).
    MoveAbort,
    /// Resource not found.
    ResourceNotFound,
    /// Module not found.
    ModuleNotFound,
    /// Function not found.
    FunctionNotFound,
    /// Type argument mismatch.
    TypeMismatch,
    /// Unknown error.
    Unknown,
}

impl VmErrorCategory {
    fn from_status(status: &str) -> Self {
        let status_upper = status.to_uppercase();

        if status_upper.contains("INSUFFICIENT") || status_upper.contains("NOT_ENOUGH") {
            Self::InsufficientBalance
        } else if status_upper.contains("SEQUENCE_NUMBER")
            || status_upper.contains("SEQUENCE NUMBER")
        {
            Self::SequenceNumber
        } else if status_upper.contains("OUT_OF_GAS") || status_upper.contains("OUT OF GAS") {
            Self::OutOfGas
        } else if status_upper.contains("ABORT") {
            Self::MoveAbort
        } else if status_upper.contains("RESOURCE") && status_upper.contains("NOT") {
            Self::ResourceNotFound
        } else if status_upper.contains("MODULE") && status_upper.contains("NOT") {
            Self::ModuleNotFound
        } else if status_upper.contains("FUNCTION") && status_upper.contains("NOT") {
            Self::FunctionNotFound
        } else if status_upper.contains("TYPE")
            && (status_upper.contains("MISMATCH") || status_upper.contains("ERROR"))
        {
            Self::TypeMismatch
        } else {
            Self::Unknown
        }
    }
}

/// Options for simulation.
#[derive(Debug, Clone, Default)]
pub struct SimulationOptions {
    /// Whether to estimate gas only (faster).
    pub estimate_gas_only: bool,
    /// Override the sender's sequence number.
    pub sequence_number_override: Option<u64>,
    /// Override the gas unit price.
    pub gas_unit_price_override: Option<u64>,
    /// Override the max gas amount.
    pub max_gas_amount_override: Option<u64>,
}

impl SimulationOptions {
    /// Creates new simulation options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets gas-only estimation mode.
    pub fn estimate_gas_only(mut self) -> Self {
        self.estimate_gas_only = true;
        self
    }

    /// Overrides the sequence number.
    pub fn with_sequence_number(mut self, seq: u64) -> Self {
        self.sequence_number_override = Some(seq);
        self
    }

    /// Overrides the gas unit price.
    pub fn with_gas_unit_price(mut self, price: u64) -> Self {
        self.gas_unit_price_override = Some(price);
        self
    }

    /// Overrides the max gas amount.
    pub fn with_max_gas_amount(mut self, amount: u64) -> Self {
        self.max_gas_amount_override = Some(amount);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_success_result() {
        let json = serde_json::json!({
            "success": true,
            "vm_status": "Executed successfully",
            "gas_used": "100",
            "max_gas_amount": "200000",
            "gas_unit_price": "100",
            "hash": "0x123",
            "changes": [],
            "events": []
        });

        let result = SimulationResult::from_json(json).unwrap();
        assert!(result.success());
        assert_eq!(result.gas_used(), 100);
        assert_eq!(result.gas_cost(), 10000);
    }

    #[test]
    fn test_parse_failed_result() {
        let json = serde_json::json!({
            "success": false,
            "vm_status": "Move abort in 0x1::coin: EINSUFFICIENT_BALANCE(0x10001)",
            "gas_used": "50",
            "max_gas_amount": "200000",
            "gas_unit_price": "100",
            "hash": "0x456",
            "changes": [],
            "events": []
        });

        let result = SimulationResult::from_json(json).unwrap();
        assert!(result.failed());
        assert!(result.is_insufficient_balance());
        assert!(result.vm_error().is_some());
    }

    #[test]
    fn test_error_categories() {
        assert_eq!(
            VmErrorCategory::from_status("INSUFFICIENT_BALANCE"),
            VmErrorCategory::InsufficientBalance
        );
        assert_eq!(
            VmErrorCategory::from_status("SEQUENCE_NUMBER_TOO_OLD"),
            VmErrorCategory::SequenceNumber
        );
        assert_eq!(
            VmErrorCategory::from_status("OUT_OF_GAS"),
            VmErrorCategory::OutOfGas
        );
        assert_eq!(
            VmErrorCategory::from_status("Move abort"),
            VmErrorCategory::MoveAbort
        );
    }

    #[test]
    fn test_safe_gas_estimate() {
        let json = serde_json::json!({
            "success": true,
            "vm_status": "Executed successfully",
            "gas_used": "1000",
            "max_gas_amount": "200000",
            "gas_unit_price": "100",
            "hash": "0x123",
            "changes": [],
            "events": []
        });

        let result = SimulationResult::from_json(json).unwrap();
        assert_eq!(result.gas_used(), 1000);
        assert_eq!(result.safe_gas_estimate(), 1200); // 20% more
    }

    #[test]
    fn test_parse_events() {
        let json = serde_json::json!({
            "success": true,
            "vm_status": "Executed successfully",
            "gas_used": "100",
            "max_gas_amount": "200000",
            "gas_unit_price": "100",
            "hash": "0x123",
            "changes": [],
            "events": [
                {
                    "type": "0x1::coin::DepositEvent",
                    "sequence_number": "5",
                    "data": {"amount": "1000"}
                }
            ]
        });

        let result = SimulationResult::from_json(json).unwrap();
        assert_eq!(result.events().len(), 1);
        assert_eq!(result.events()[0].event_type, "0x1::coin::DepositEvent");
        assert_eq!(result.events()[0].sequence_number, 5);
    }

    #[test]
    fn test_parse_changes() {
        let json = serde_json::json!({
            "success": true,
            "vm_status": "Executed successfully",
            "gas_used": "100",
            "max_gas_amount": "200000",
            "gas_unit_price": "100",
            "hash": "0x123",
            "changes": [
                {
                    "type": "write_resource",
                    "address": "0x1",
                    "data": {"type": "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"}
                }
            ],
            "events": []
        });

        let result = SimulationResult::from_json(json).unwrap();
        assert_eq!(result.changes().len(), 1);
        assert!(result.changes()[0].is_write());
    }

    #[test]
    fn test_simulation_options_default() {
        let opts = SimulationOptions::default();
        assert!(!opts.estimate_gas_only);
        assert!(opts.sequence_number_override.is_none());
        assert!(opts.gas_unit_price_override.is_none());
        assert!(opts.max_gas_amount_override.is_none());
    }

    #[test]
    fn test_simulation_options_builder() {
        let opts = SimulationOptions::new()
            .estimate_gas_only()
            .with_sequence_number(5)
            .with_gas_unit_price(200)
            .with_max_gas_amount(500_000);

        assert!(opts.estimate_gas_only);
        assert_eq!(opts.sequence_number_override, Some(5));
        assert_eq!(opts.gas_unit_price_override, Some(200));
        assert_eq!(opts.max_gas_amount_override, Some(500_000));
    }

    #[test]
    fn test_vm_error_category_resource_not_found() {
        assert_eq!(
            VmErrorCategory::from_status("RESOURCE_NOT_FOUND"),
            VmErrorCategory::ResourceNotFound
        );
    }

    #[test]
    fn test_vm_error_category_module_not_found() {
        assert_eq!(
            VmErrorCategory::from_status("MODULE_NOT_PUBLISHED"),
            VmErrorCategory::ModuleNotFound
        );
    }

    #[test]
    fn test_vm_error_category_function_not_found() {
        assert_eq!(
            VmErrorCategory::from_status("FUNCTION_NOT_FOUND"),
            VmErrorCategory::FunctionNotFound
        );
    }

    #[test]
    fn test_vm_error_category_type_mismatch() {
        assert_eq!(
            VmErrorCategory::from_status("TYPE_MISMATCH"),
            VmErrorCategory::TypeMismatch
        );
        assert_eq!(
            VmErrorCategory::from_status("TYPE_ERROR"),
            VmErrorCategory::TypeMismatch
        );
    }

    #[test]
    fn test_vm_error_category_unknown() {
        assert_eq!(
            VmErrorCategory::from_status("SOME_RANDOM_ERROR"),
            VmErrorCategory::Unknown
        );
    }

    #[test]
    fn test_simulation_result_accessors() {
        let json = serde_json::json!({
            "success": true,
            "vm_status": "Executed successfully",
            "gas_used": "1500",
            "max_gas_amount": "200000",
            "gas_unit_price": "100",
            "hash": "0xabc123",
            "changes": [],
            "events": []
        });

        let result = SimulationResult::from_json(json).unwrap();
        assert!(result.success());
        assert!(!result.failed());
        assert_eq!(result.vm_status(), "Executed successfully");
        assert_eq!(result.gas_used(), 1500);
        assert_eq!(result.max_gas_amount(), 200000);
        assert_eq!(result.gas_unit_price(), 100);
        assert_eq!(result.gas_cost(), 150000); // 1500 * 100
        assert_eq!(result.hash(), "0xabc123");
        assert!(result.events().is_empty());
        assert!(result.changes().is_empty());
    }

    #[test]
    fn test_simulation_result_from_response() {
        let response = vec![serde_json::json!({
            "success": true,
            "vm_status": "Executed successfully",
            "gas_used": "100",
            "max_gas_amount": "200000",
            "gas_unit_price": "100",
            "hash": "0x123",
            "changes": [],
            "events": []
        })];

        let result = SimulationResult::from_response(response).unwrap();
        assert!(result.success());
    }

    #[test]
    fn test_simulation_result_from_empty_response() {
        let response: Vec<serde_json::Value> = vec![];
        let result = SimulationResult::from_response(response);
        assert!(result.is_err());
    }

    #[test]
    fn test_state_change_delete() {
        let json = serde_json::json!({
            "success": true,
            "vm_status": "Executed successfully",
            "gas_used": "100",
            "max_gas_amount": "200000",
            "gas_unit_price": "100",
            "hash": "0x123",
            "changes": [
                {
                    "type": "delete_resource",
                    "address": "0x1",
                    "data": {}
                }
            ],
            "events": []
        });

        let result = SimulationResult::from_json(json).unwrap();
        assert_eq!(result.changes().len(), 1);
        assert!(result.changes()[0].is_delete());
        assert!(!result.changes()[0].is_write());
    }

    #[test]
    fn test_simulation_result_with_vm_error() {
        let json = serde_json::json!({
            "success": false,
            "vm_status": "INSUFFICIENT_BALANCE",
            "gas_used": "0",
            "max_gas_amount": "200000",
            "gas_unit_price": "100",
            "hash": "0x123",
            "changes": [],
            "events": []
        });

        let result = SimulationResult::from_json(json).unwrap();
        assert!(result.failed());
        assert!(result.is_insufficient_balance());
        assert!(!result.is_out_of_gas());
        assert!(!result.is_sequence_number_error());
    }

    #[test]
    fn test_simulation_result_out_of_gas() {
        let json = serde_json::json!({
            "success": false,
            "vm_status": "OUT_OF_GAS",
            "gas_used": "200000",
            "max_gas_amount": "200000",
            "gas_unit_price": "100",
            "hash": "0x123",
            "changes": [],
            "events": []
        });

        let result = SimulationResult::from_json(json).unwrap();
        assert!(result.is_out_of_gas());
    }

    #[test]
    fn test_simulation_result_sequence_error() {
        let json = serde_json::json!({
            "success": false,
            "vm_status": "SEQUENCE_NUMBER_TOO_OLD",
            "gas_used": "0",
            "max_gas_amount": "200000",
            "gas_unit_price": "100",
            "hash": "0x123",
            "changes": [],
            "events": []
        });

        let result = SimulationResult::from_json(json).unwrap();
        assert!(result.is_sequence_number_error());
    }

    #[test]
    fn test_simulated_event_parsing() {
        let json = serde_json::json!({
            "success": true,
            "vm_status": "Executed successfully",
            "gas_used": "100",
            "max_gas_amount": "200000",
            "gas_unit_price": "100",
            "hash": "0x123",
            "changes": [],
            "events": [
                {
                    "type": "0x1::coin::WithdrawEvent",
                    "sequence_number": "10",
                    "data": {"amount": "500"}
                },
                {
                    "type": "0x1::coin::DepositEvent",
                    "sequence_number": "20",
                    "data": {"amount": "500"}
                }
            ]
        });

        let result = SimulationResult::from_json(json).unwrap();
        assert_eq!(result.events().len(), 2);
        assert_eq!(result.events()[0].event_type, "0x1::coin::WithdrawEvent");
        assert_eq!(result.events()[0].sequence_number, 10);
        assert_eq!(result.events()[1].event_type, "0x1::coin::DepositEvent");
        assert_eq!(result.events()[1].sequence_number, 20);
    }
}
