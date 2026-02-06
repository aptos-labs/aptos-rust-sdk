//! Aptos SDK CLI - A command-line interface for the Aptos blockchain.
//!
//! This CLI wraps the Aptos Rust SDK to provide command-line access to
//! account management, transfers, Move interactions, transaction operations,
//! key management, network queries, and an interactive REPL with encrypted
//! credential storage.

mod commands;
mod common;
mod config;
mod credentials;
mod import;
mod output;
mod repl;

use clap::Parser;
use commands::{AccountCommand, InfoCommand, KeyCommand, MoveCommand, TransactionCommand};
use common::GlobalOpts;

/// Aptos SDK CLI - Interact with the Aptos blockchain from the command line.
#[derive(Parser, Debug)]
#[command(name = "aptos-sdk-cli", version, about, long_about = None)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOpts,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
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

    /// Start interactive REPL with encrypted credential support
    Repl,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let result = match cli.command {
        Some(Command::Account(cmd)) => cmd.run(&cli.global).await,
        Some(Command::Key(cmd)) => cmd.run(&cli.global),
        Some(Command::Move(cmd)) => cmd.run(&cli.global).await,
        Some(Command::Transaction(cmd)) => cmd.run(&cli.global).await,
        Some(Command::Info(cmd)) => cmd.run(&cli.global).await,
        Some(Command::Repl) | None => repl::run_repl(cli.global).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn no_subcommand_yields_none() {
        let cli = Cli::try_parse_from(["aptos-sdk-cli"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn repl_subcommand() {
        let cli = Cli::try_parse_from(["aptos-sdk-cli", "repl"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Repl)));
    }

    #[test]
    fn network_flag_mainnet() {
        let cli = Cli::try_parse_from(["aptos-sdk-cli", "--network", "mainnet"]).unwrap();
        assert!(matches!(cli.global.network, common::NetworkArg::Mainnet));
    }

    #[test]
    fn network_flag_testnet() {
        let cli = Cli::try_parse_from(["aptos-sdk-cli", "--network", "testnet", "repl"]).unwrap();
        assert!(matches!(cli.global.network, common::NetworkArg::Testnet));
    }

    #[test]
    fn json_flag() {
        let cli = Cli::try_parse_from(["aptos-sdk-cli", "--json", "repl"]).unwrap();
        assert!(cli.global.json);
    }

    #[test]
    fn default_network_is_mainnet() {
        let cli = Cli::try_parse_from(["aptos-sdk-cli"]).unwrap();
        assert!(matches!(cli.global.network, common::NetworkArg::Mainnet));
    }

    #[test]
    fn node_url_flag() {
        let cli =
            Cli::try_parse_from(["aptos-sdk-cli", "--node-url", "https://custom.example.com"])
                .unwrap();
        assert_eq!(
            cli.global.node_url,
            Some("https://custom.example.com".to_string())
        );
    }

    #[test]
    fn api_key_flag() {
        let cli = Cli::try_parse_from(["aptos-sdk-cli", "--api-key", "my-key", "repl"]).unwrap();
        assert_eq!(cli.global.api_key, Some("my-key".to_string()));
    }

    #[test]
    fn account_subcommand_parses() {
        let cli = Cli::try_parse_from(["aptos-sdk-cli", "account", "balance", "--address", "0x1"])
            .unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn key_generate_subcommand_parses() {
        let cli = Cli::try_parse_from(["aptos-sdk-cli", "key", "generate"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Key(_))));
    }

    #[test]
    fn info_subcommand_parses() {
        let cli = Cli::try_parse_from(["aptos-sdk-cli", "info", "ledger"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Info(_))));
    }

    #[test]
    fn move_subcommand_parses() {
        let cli =
            Cli::try_parse_from(["aptos-sdk-cli", "move", "init", "--name", "test_pkg"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    #[test]
    fn invalid_subcommand_fails() {
        assert!(Cli::try_parse_from(["aptos-sdk-cli", "nonexistent"]).is_err());
    }

    #[test]
    fn invalid_network_fails() {
        assert!(Cli::try_parse_from(["aptos-sdk-cli", "--network", "foobar"]).is_err());
    }
}
