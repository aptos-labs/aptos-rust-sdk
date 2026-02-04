//! Transaction building and signing.
//!
//! This module provides types and utilities for constructing, signing,
//! and submitting transactions to the Aptos blockchain.
//!
//! # Overview
//!
//! The transaction module supports several transaction types:
//!
//! - **Simple transactions** - Single sender, self-paid gas
//! - **Multi-agent transactions** - Multiple signers required
//! - **Sponsored transactions** - Fee payer pays gas on sender's behalf
//! - **Batch transactions** - Multiple transactions submitted efficiently
//!
//! # Example: Simple Transaction
//!
//! ```rust,ignore
//! use aptos_rust_sdk_v2::transaction::{TransactionBuilder, EntryFunction};
//! use aptos_rust_sdk_v2::types::AccountAddress;
//!
//! let payload = EntryFunction::apt_transfer(recipient, 1000)?;
//!
//! let signed_txn = TransactionBuilder::new()
//!     .sender(sender.address())
//!     .sequence_number(0)
//!     .payload(payload.into())
//!     .chain_id(ChainId::testnet())
//!     .build_and_sign(&sender)?;
//! ```
//!
//! # Example: Type-Safe Payload Building
//!
//! ```rust,ignore
//! use aptos_rust_sdk_v2::transaction::InputEntryFunctionData;
//!
//! // Simple and ergonomic payload construction
//! let payload = InputEntryFunctionData::new("0x1::aptos_account::transfer")
//!     .arg(recipient)
//!     .arg(1_000_000u64)
//!     .build()?;
//!
//! // With type arguments
//! let payload = InputEntryFunctionData::new("0x1::coin::transfer")
//!     .type_arg("0x1::aptos_coin::AptosCoin")
//!     .arg(recipient)
//!     .arg(amount)
//!     .build()?;
//! ```
//!
//! # Example: Sponsored Transaction
//!
//! ```rust,ignore
//! use aptos_rust_sdk_v2::transaction::{SponsoredTransactionBuilder, EntryFunction};
//!
//! let payload = EntryFunction::apt_transfer(recipient, 1000)?;
//!
//! let signed_txn = SponsoredTransactionBuilder::new()
//!     .sender(&user_account)
//!     .sequence_number(0)
//!     .fee_payer(&sponsor_account)
//!     .payload(payload.into())
//!     .chain_id(ChainId::testnet())
//!     .build_and_sign()?;
//! ```
//!
//! # Example: Batch Transactions
//!
//! ```rust,ignore
//! use aptos_rust_sdk_v2::transaction::batch::TransactionBatchBuilder;
//!
//! let batch = TransactionBatchBuilder::new()
//!     .sender(account.address())
//!     .starting_sequence_number(seq_num)
//!     .chain_id(ChainId::testnet())
//!     .add_payload(payload1)
//!     .add_payload(payload2)
//!     .build_and_sign(&account)?;
//!
//! // Submit all in parallel
//! let results = batch.submit_all(&client).await;
//! ```

pub mod authenticator;
pub mod batch;
pub mod builder;
pub mod input;
pub mod payload;
pub mod simulation;
pub mod sponsored;
pub mod types;

pub use authenticator::{AccountAuthenticator, Ed25519Authenticator, TransactionAuthenticator};
pub use batch::{
    BatchOperations, BatchSummary, BatchTransactionResult, BatchTransactionStatus,
    SignedTransactionBatch, TransactionBatchBuilder,
};
pub use builder::{TransactionBuilder, sign_transaction};
pub use input::{
    InputEntryFunctionData, InputEntryFunctionDataBuilder, IntoMoveArg, MoveI128, MoveI256,
    MoveU256, functions, move_none, move_some, move_string, move_vec, types as move_types,
};
pub use payload::{EntryFunction, Script, ScriptArgument, TransactionPayload};
pub use simulation::{
    SimulatedEvent, SimulationOptions, SimulationResult, StateChange, VmError, VmErrorCategory,
};
pub use sponsored::{PartiallySigned, Sponsor, SponsoredTransactionBuilder, sponsor_transaction};
pub use types::{
    RawTransaction, RawTransactionOrderless, SignedTransaction, SignedTransactionOrderless,
    TransactionInfo,
};
