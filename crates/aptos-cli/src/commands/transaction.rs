//! Transaction operation commands.

use crate::common::{self, GlobalOpts};
use crate::output;
use anyhow::{Context, Result};
use aptos_sdk::transaction::EntryFunction;
use aptos_sdk::types::{HashValue, TypeTag};
use clap::Args;

/// Transaction operation commands.
#[derive(clap::Subcommand, Debug)]
pub enum TransactionCommand {
    /// Look up a transaction by its hash
    Lookup(LookupArgs),
    /// Simulate a transaction without submitting it
    Simulate(SimulateArgs),
}

#[derive(Args, Debug)]
pub struct LookupArgs {
    /// Transaction hash
    #[arg(long)]
    hash: String,
}

#[derive(Args, Debug)]
pub struct SimulateArgs {
    /// Function ID (e.g., "0x1::aptos_account::transfer")
    #[arg(long)]
    function: String,

    /// Sender address (defaults to active account in interactive mode)
    #[arg(long)]
    sender: Option<String>,

    /// Type arguments
    #[arg(long, num_args = 0..)]
    type_args: Vec<String>,

    /// BCS arguments (e.g., "address:0x1", "u64:1000")
    #[arg(long, num_args = 0..)]
    args: Vec<String>,
}

impl TransactionCommand {
    pub async fn run(&self, global: &GlobalOpts) -> Result<()> {
        match self {
            TransactionCommand::Lookup(args) => cmd_lookup(args, global).await,
            TransactionCommand::Simulate(args) => cmd_simulate(args, global).await,
        }
    }
}

async fn cmd_lookup(args: &LookupArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;

    let hash = HashValue::from_hex(&args.hash).context("invalid transaction hash")?;

    let txn = aptos
        .fullnode()
        .get_transaction_by_hash(&hash)
        .await
        .context("failed to get transaction")?;

    if global.json {
        output::print_json(&txn.data)?;
    } else {
        output::print_header("Transaction");
        if let Some(hash) = txn.data.get("hash").and_then(|v| v.as_str()) {
            output::print_kv("Hash", hash);
        }
        if let Some(version) = txn.data.get("version").and_then(|v| v.as_str()) {
            output::print_kv("Version", version);
        }
        if let Some(success) = txn.data.get("success").and_then(|v| v.as_bool()) {
            output::print_kv("Success", &success.to_string());
        }
        if let Some(gas) = txn.data.get("gas_used").and_then(|v| v.as_str()) {
            output::print_kv("Gas Used", gas);
        }
        if let Some(vm_status) = txn.data.get("vm_status").and_then(|v| v.as_str()) {
            output::print_kv("VM Status", vm_status);
        }
        if let Some(sender) = txn.data.get("sender").and_then(|v| v.as_str()) {
            output::print_kv("Sender", sender);
        }
        if let Some(seq) = txn.data.get("sequence_number").and_then(|v| v.as_str()) {
            output::print_kv("Sequence Number", seq);
        }
        if let Some(ts) = txn.data.get("timestamp").and_then(|v| v.as_str()) {
            output::print_kv("Timestamp", ts);
        }
        if let Some(typ) = txn.data.get("type").and_then(|v| v.as_str()) {
            output::print_kv("Type", typ);
        }

        // Show payload summary if available
        if let Some(payload) = txn.data.get("payload")
            && let Some(func) = payload.get("function").and_then(|v| v.as_str())
        {
            output::print_kv("Function", func);
        }
    }
    Ok(())
}

async fn cmd_simulate(args: &SimulateArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;

    // Parse type args
    let type_args: Vec<TypeTag> = args
        .type_args
        .iter()
        .map(|t| TypeTag::from_str_strict(t).context(format!("invalid type argument: {t}")))
        .collect::<Result<_>>()?;

    // Parse BCS args
    let bcs_args: Vec<Vec<u8>> = args
        .args
        .iter()
        .map(|a| common::parse_bcs_arg(a))
        .collect::<Result<_>>()?;

    let payload = EntryFunction::from_function_id(&args.function, type_args, bcs_args)
        .context("invalid function ID")?;

    // For simulation we need an account - create a dummy one from the sender address.
    // We use an Ed25519Account since simulation doesn't verify signatures.
    let sender = common::require_address(&args.sender)?;
    let dummy_account = aptos_sdk::account::Ed25519Account::generate();

    // Build the raw transaction with the sender address and simulate
    let sequence_number = aptos
        .get_sequence_number(sender)
        .await
        .context("failed to get sequence number")?;

    let raw_txn = aptos_sdk::transaction::TransactionBuilder::new()
        .sender(sender)
        .sequence_number(sequence_number)
        .payload(aptos_sdk::transaction::TransactionPayload::EntryFunction(
            payload,
        ))
        .max_gas_amount(200_000)
        .gas_unit_price(100)
        .chain_id(aptos.chain_id())
        .expiration_from_now(600)
        .build()
        .context("failed to build transaction")?;

    let signed = aptos_sdk::transaction::builder::sign_transaction(&raw_txn, &dummy_account)
        .context("failed to sign transaction for simulation")?;

    let sim_result = aptos
        .simulate_transaction(&signed)
        .await
        .context("simulation failed")?;

    if global.json {
        output::print_json(&serde_json::json!(sim_result.data))?;
    } else {
        output::print_header(&format!("Simulation: {}", args.function));
        if let Some(first) = sim_result.data.first() {
            if let Some(success) = first.get("success").and_then(|v| v.as_bool()) {
                output::print_kv("Success", &success.to_string());
            }
            if let Some(gas) = first.get("gas_used").and_then(|v| v.as_str()) {
                output::print_kv("Gas Used", gas);
            }
            if let Some(vm) = first.get("vm_status").and_then(|v| v.as_str()) {
                output::print_kv("VM Status", vm);
            }
        } else {
            println!("  No simulation results returned.");
        }
    }
    Ok(())
}
