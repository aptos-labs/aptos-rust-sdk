//! Transaction payloads.

use crate::types::{MoveModuleId, TypeTag};
use serde::{Deserialize, Serialize};

/// The payload of a transaction, specifying what action to take.
///
/// Note: Variant indices must match Aptos core for BCS compatibility:
/// - 0: Script
/// - 1: ModuleBundle (deprecated)
/// - 2: EntryFunction
/// - 3: Multisig
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionPayload {
    /// Execute a script with bytecode (variant 0).
    Script(Script),
    /// Deprecated module bundle payload (variant 1).
    /// This variant exists only for BCS compatibility.
    #[doc(hidden)]
    ModuleBundle(DeprecatedModuleBundle),
    /// Call an entry function on a module (variant 2).
    EntryFunction(EntryFunction),
    /// Multisig transaction payload (variant 3).
    Multisig(Multisig),
}

/// Deprecated module bundle payload.
/// This type exists only for BCS enum variant compatibility.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeprecatedModuleBundle {
    #[doc(hidden)]
    _private: (),
}

/// Multisig transaction payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Multisig {
    /// The multisig account address.
    pub multisig_address: crate::types::AccountAddress,
    /// The inner transaction payload (optional).
    pub transaction_payload: Option<MultisigTransactionPayload>,
}

/// Inner payload for multisig transactions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultisigTransactionPayload {
    /// Entry function call.
    EntryFunction(EntryFunction),
}

/// A script payload with inline bytecode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Script {
    /// The Move bytecode to execute.
    #[serde(with = "serde_bytes")]
    pub code: Vec<u8>,
    /// Type arguments for the script.
    pub type_args: Vec<TypeTag>,
    /// Arguments to the script.
    pub args: Vec<ScriptArgument>,
}

impl Script {
    /// Creates a new script payload.
    pub fn new(code: Vec<u8>, type_args: Vec<TypeTag>, args: Vec<ScriptArgument>) -> Self {
        Self {
            code,
            type_args,
            args,
        }
    }
}

/// An argument to a script.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptArgument {
    /// A u8 value.
    U8(u8),
    /// A u16 value.
    U16(u16),
    /// A u32 value.
    U32(u32),
    /// A u64 value.
    U64(u64),
    /// A u128 value.
    U128(u128),
    /// A u256 value (as bytes).
    U256([u8; 32]),
    /// An address value.
    Address(crate::types::AccountAddress),
    /// A vector of u8 (bytes).
    U8Vector(#[serde(with = "serde_bytes")] Vec<u8>),
    /// A boolean value.
    Bool(bool),
}

/// An entry function call payload.
///
/// Entry functions are the most common type of transaction payload.
/// They call a function marked as `entry` in a Move module.
///
/// # Example
///
/// ```rust
/// use aptos_rust_sdk_v2::transaction::EntryFunction;
/// use aptos_rust_sdk_v2::types::{MoveModuleId, TypeTag, AccountAddress};
///
/// // Create a coin transfer payload
/// let module = MoveModuleId::from_str_strict("0x1::coin").unwrap();
/// let recipient = AccountAddress::from_hex("0x123").unwrap();
/// let entry_function = EntryFunction {
///     module,
///     function: "transfer".to_string(),
///     type_args: vec![TypeTag::aptos_coin()],
///     args: vec![
///         aptos_bcs::to_bytes(&recipient).unwrap(),
///         aptos_bcs::to_bytes(&1000u64).unwrap(),
///     ],
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryFunction {
    /// The module containing the function.
    pub module: MoveModuleId,
    /// The function name.
    pub function: String,
    /// Type arguments for generic functions.
    pub type_args: Vec<TypeTag>,
    /// BCS-encoded arguments.
    pub args: Vec<Vec<u8>>,
}

impl EntryFunction {
    /// Creates a new entry function payload.
    pub fn new(
        module: MoveModuleId,
        function: impl Into<String>,
        type_args: Vec<TypeTag>,
        args: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            module,
            function: function.into(),
            type_args,
            args,
        }
    }

    /// Creates an entry function from a function identifier string.
    ///
    /// # Arguments
    ///
    /// * `function_id` - Full function ID (e.g., "0x1::coin::transfer")
    /// * `type_args` - Type arguments
    /// * `args` - BCS-encoded arguments
    pub fn from_function_id(
        function_id: &str,
        type_args: Vec<TypeTag>,
        args: Vec<Vec<u8>>,
    ) -> crate::error::AptosResult<Self> {
        let func_id = crate::types::EntryFunctionId::from_str_strict(function_id)?;
        Ok(Self {
            module: func_id.module,
            function: func_id.name.as_str().to_string(),
            type_args,
            args,
        })
    }

    /// Creates a simple APT transfer payload.
    ///
    /// # Arguments
    ///
    /// * `recipient` - The recipient's address
    /// * `amount` - Amount in octas (1 APT = 10^8 octas)
    pub fn apt_transfer(
        recipient: crate::types::AccountAddress,
        amount: u64,
    ) -> crate::error::AptosResult<Self> {
        let module = MoveModuleId::from_str_strict("0x1::aptos_account")?;
        Ok(Self {
            module,
            function: "transfer".to_string(),
            type_args: vec![],
            args: vec![
                aptos_bcs::to_bytes(&recipient).map_err(crate::error::AptosError::bcs)?,
                aptos_bcs::to_bytes(&amount).map_err(crate::error::AptosError::bcs)?,
            ],
        })
    }

    /// Creates a coin transfer payload for any coin type.
    ///
    /// # Arguments
    ///
    /// * `coin_type` - The coin type tag
    /// * `recipient` - The recipient's address
    /// * `amount` - Amount in the coin's smallest unit
    pub fn coin_transfer(
        coin_type: TypeTag,
        recipient: crate::types::AccountAddress,
        amount: u64,
    ) -> crate::error::AptosResult<Self> {
        let module = MoveModuleId::from_str_strict("0x1::coin")?;
        Ok(Self {
            module,
            function: "transfer".to_string(),
            type_args: vec![coin_type],
            args: vec![
                aptos_bcs::to_bytes(&recipient).map_err(crate::error::AptosError::bcs)?,
                aptos_bcs::to_bytes(&amount).map_err(crate::error::AptosError::bcs)?,
            ],
        })
    }
}

impl From<EntryFunction> for TransactionPayload {
    fn from(entry_function: EntryFunction) -> Self {
        TransactionPayload::EntryFunction(entry_function)
    }
}

impl From<Script> for TransactionPayload {
    fn from(script: Script) -> Self {
        TransactionPayload::Script(script)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AccountAddress;

    #[test]
    fn test_apt_transfer() {
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let entry_fn = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        assert_eq!(entry_fn.function, "transfer");
        assert!(entry_fn.type_args.is_empty());
        assert_eq!(entry_fn.args.len(), 2);
    }

    #[test]
    fn test_from_function_id() {
        let entry_fn = EntryFunction::from_function_id(
            "0x1::coin::transfer",
            vec![TypeTag::aptos_coin()],
            vec![],
        )
        .unwrap();

        assert_eq!(entry_fn.module.address, AccountAddress::ONE);
        assert_eq!(entry_fn.module.name.as_str(), "coin");
        assert_eq!(entry_fn.function, "transfer");
    }
}
