//! Network information commands.

use crate::common::GlobalOpts;
use crate::output;
use anyhow::{Context, Result};
use clap::Args;

/// Network information commands.
#[derive(clap::Subcommand, Debug)]
pub enum InfoCommand {
    /// Show current ledger information
    Ledger,
    /// Show current gas price estimates
    GasPrice,
    /// Get a block by height or version
    Block(BlockArgs),
}

#[derive(Args, Debug)]
pub struct BlockArgs {
    /// Block height to look up
    #[arg(long, conflicts_with = "version")]
    height: Option<u64>,

    /// Block version to look up
    #[arg(long, conflicts_with = "height")]
    version: Option<u64>,

    /// Include transactions in the response
    #[arg(long, default_value_t = false)]
    with_transactions: bool,
}

impl InfoCommand {
    pub async fn run(&self, global: &GlobalOpts) -> Result<()> {
        match self {
            InfoCommand::Ledger => cmd_ledger(global).await,
            InfoCommand::GasPrice => cmd_gas_price(global).await,
            InfoCommand::Block(args) => cmd_block(args, global).await,
        }
    }
}

async fn cmd_ledger(global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;

    let info = aptos
        .ledger_info()
        .await
        .context("failed to get ledger info")?;

    if global.json {
        output::print_json(&serde_json::json!({
            "chain_id": info.chain_id,
            "epoch": info.epoch,
            "ledger_version": info.ledger_version,
            "oldest_ledger_version": info.oldest_ledger_version,
            "ledger_timestamp": info.ledger_timestamp,
            "node_role": info.node_role,
            "oldest_block_height": info.oldest_block_height,
            "block_height": info.block_height,
            "git_hash": info.git_hash,
        }))?;
    } else {
        output::print_header("Ledger Info");
        output::print_kv("Chain ID", &info.chain_id.to_string());
        output::print_kv("Epoch", &info.epoch);
        output::print_kv("Ledger Version", &info.ledger_version);
        output::print_kv("Block Height", &info.block_height);
        output::print_kv("Node Role", &info.node_role);

        // Convert microseconds timestamp to readable format
        if let Ok(us) = info.ledger_timestamp.parse::<u64>() {
            let secs = us / 1_000_000;
            output::print_kv(
                "Timestamp",
                &format!("{} ({secs}s unix)", info.ledger_timestamp),
            );
        } else {
            output::print_kv("Timestamp", &info.ledger_timestamp);
        }
    }
    Ok(())
}

async fn cmd_gas_price(global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;

    let gas = aptos
        .fullnode()
        .estimate_gas_price()
        .await
        .context("failed to estimate gas price")?;

    if global.json {
        output::print_json(&serde_json::json!({
            "deprioritized_gas_estimate": gas.data.deprioritized_gas_estimate,
            "gas_estimate": gas.data.gas_estimate,
            "prioritized_gas_estimate": gas.data.prioritized_gas_estimate,
        }))?;
    } else {
        output::print_header("Gas Price Estimate");
        output::print_kv("Low (deprioritized)", &format!("{} octas", gas.data.low()));
        output::print_kv(
            "Medium (estimate)",
            &format!("{} octas", gas.data.gas_estimate),
        );
        output::print_kv("High (prioritized)", &format!("{} octas", gas.data.high()));
    }
    Ok(())
}

async fn cmd_block(args: &BlockArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;

    let block = if let Some(height) = args.height {
        aptos
            .fullnode()
            .get_block_by_height(height, args.with_transactions)
            .await
            .context("failed to get block by height")?
    } else if let Some(version) = args.version {
        aptos
            .fullnode()
            .get_block_by_version(version, args.with_transactions)
            .await
            .context("failed to get block by version")?
    } else {
        anyhow::bail!("Either --height or --version must be specified");
    };

    if global.json {
        output::print_json(&block.data)?;
    } else {
        output::print_header("Block");
        if let Some(height) = block.data.get("block_height").and_then(|v| v.as_str()) {
            output::print_kv("Block Height", height);
        }
        if let Some(hash) = block.data.get("block_hash").and_then(|v| v.as_str()) {
            output::print_kv("Block Hash", hash);
        }
        if let Some(ts) = block.data.get("block_timestamp").and_then(|v| v.as_str()) {
            output::print_kv("Timestamp", ts);
        }
        if let Some(version) = block.data.get("first_version").and_then(|v| v.as_str()) {
            output::print_kv("First Version", version);
        }
        if let Some(version) = block.data.get("last_version").and_then(|v| v.as_str()) {
            output::print_kv("Last Version", version);
        }
        if let Some(txns) = block.data.get("transactions").and_then(|v| v.as_array()) {
            output::print_kv("Transactions", &txns.len().to_string());
        }
    }
    Ok(())
}
