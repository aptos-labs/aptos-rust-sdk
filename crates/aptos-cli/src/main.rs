//! Aptos SDK CLI - A command-line interface for the Aptos blockchain.
//!
//! This CLI wraps the Aptos Rust SDK to provide command-line access to
//! account management, transfers, Move interactions, transaction operations,
//! key management, and network queries.

mod commands;
mod common;
mod output;

use clap::Parser;
use commands::{AccountCommand, InfoCommand, KeyCommand, MoveCommand, TransactionCommand};
use common::GlobalOpts;

/// Aptos SDK CLI - Interact with the Aptos blockchain from the command line.
#[derive(Parser, Debug)]
#[command(name = "aptos-sdk-cli", version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    global: GlobalOpts,

    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Account management (create, fund, balance, lookup, transfer)
    #[command(subcommand)]
    Account(AccountCommand),

    /// Key management (generate, derive from mnemonic, show)
    #[command(subcommand)]
    Key(KeyCommand),

    /// Move interactions (view functions, run entry functions, publish, inspect)
    #[command(subcommand, name = "move")]
    Move(MoveCommand),

    /// Transaction operations (lookup, simulate)
    #[command(subcommand)]
    Transaction(TransactionCommand),

    /// Network information (ledger info, gas price, blocks)
    #[command(subcommand)]
    Info(InfoCommand),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Account(cmd) => cmd.run(&cli.global).await,
        Command::Key(cmd) => cmd.run(&cli.global),
        Command::Move(cmd) => cmd.run(&cli.global).await,
        Command::Transaction(cmd) => cmd.run(&cli.global).await,
        Command::Info(cmd) => cmd.run(&cli.global).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }

    Ok(())
}
