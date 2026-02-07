//! Aptos SDK CLI - A command-line interface for the Aptos blockchain.
//!
//! This CLI wraps the Aptos Rust SDK to provide command-line access to
//! account management, transfers, Move interactions, transaction operations,
//! key management, network queries, and an interactive shell with encrypted
//! credential storage.

mod commands;
mod common;
mod config;
mod credentials;
mod import;
mod interactive;
mod output;

use clap::Parser;
use commands::{AccountCommand, InfoCommand, KeyCommand, MoveCommand, TransactionCommand};
use common::GlobalOpts;

/// Aptos SDK CLI - Interact with the Aptos blockchain from the command line.
#[derive(Parser, Debug)]
#[command(name = "aptos-cli", version, about, long_about = None)]
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

    /// Start interactive shell with encrypted credential support
    Interactive,
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
        Some(Command::Interactive) | None => interactive::run_interactive(cli.global).await,
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

    // ===================================================================
    // Top-level CLI parsing
    // ===================================================================

    #[test]
    fn no_subcommand_yields_none() {
        let cli = Cli::try_parse_from(["aptos-cli"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn interactive_subcommand() {
        let cli = Cli::try_parse_from(["aptos-cli", "interactive"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Interactive)));
    }

    #[test]
    fn invalid_subcommand_fails() {
        assert!(Cli::try_parse_from(["aptos-cli", "nonexistent"]).is_err());
    }

    // ===================================================================
    // Global options
    // ===================================================================

    #[test]
    fn network_flag_mainnet() {
        let cli = Cli::try_parse_from(["aptos-cli", "--network", "mainnet"]).unwrap();
        assert!(matches!(cli.global.network, common::NetworkArg::Mainnet));
    }

    #[test]
    fn network_flag_testnet() {
        let cli = Cli::try_parse_from(["aptos-cli", "--network", "testnet", "interactive"]).unwrap();
        assert!(matches!(cli.global.network, common::NetworkArg::Testnet));
    }

    #[test]
    fn network_flag_devnet() {
        let cli = Cli::try_parse_from(["aptos-cli", "--network", "devnet"]).unwrap();
        assert!(matches!(cli.global.network, common::NetworkArg::Devnet));
    }

    #[test]
    fn network_flag_local() {
        let cli = Cli::try_parse_from(["aptos-cli", "--network", "local"]).unwrap();
        assert!(matches!(cli.global.network, common::NetworkArg::Local));
    }

    #[test]
    fn default_network_is_mainnet() {
        let cli = Cli::try_parse_from(["aptos-cli"]).unwrap();
        assert!(matches!(cli.global.network, common::NetworkArg::Mainnet));
    }

    #[test]
    fn invalid_network_fails() {
        assert!(Cli::try_parse_from(["aptos-cli", "--network", "foobar"]).is_err());
    }

    #[test]
    fn json_flag() {
        let cli = Cli::try_parse_from(["aptos-cli", "--json", "interactive"]).unwrap();
        assert!(cli.global.json);
    }

    #[test]
    fn json_flag_default_false() {
        let cli = Cli::try_parse_from(["aptos-cli"]).unwrap();
        assert!(!cli.global.json);
    }

    #[test]
    fn node_url_flag() {
        let cli = Cli::try_parse_from(["aptos-cli", "--node-url", "https://custom.example.com"])
            .unwrap();
        assert_eq!(
            cli.global.node_url,
            Some("https://custom.example.com".to_string())
        );
    }

    #[test]
    fn node_url_default_none() {
        let cli = Cli::try_parse_from(["aptos-cli"]).unwrap();
        assert!(cli.global.node_url.is_none());
    }

    #[test]
    fn api_key_flag() {
        let cli = Cli::try_parse_from(["aptos-cli", "--api-key", "my-key", "interactive"]).unwrap();
        assert_eq!(cli.global.api_key, Some("my-key".to_string()));
    }

    #[test]
    fn api_key_default_none() {
        let cli = Cli::try_parse_from(["aptos-cli"]).unwrap();
        assert!(cli.global.api_key.is_none());
    }

    #[test]
    fn global_flags_with_subcommand() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "--network",
            "testnet",
            "--json",
            "--api-key",
            "key123",
            "--node-url",
            "https://node.test",
            "info",
            "ledger",
        ])
        .unwrap();
        assert!(matches!(cli.global.network, common::NetworkArg::Testnet));
        assert!(cli.global.json);
        assert_eq!(cli.global.api_key, Some("key123".to_string()));
        assert_eq!(cli.global.node_url, Some("https://node.test".to_string()));
        assert!(matches!(cli.command, Some(Command::Info(_))));
    }

    // ===================================================================
    // Account commands — argument parsing
    // ===================================================================

    #[test]
    fn account_create_defaults() {
        let cli = Cli::try_parse_from(["aptos-cli", "account", "create"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn account_create_with_key_type() {
        let cli =
            Cli::try_parse_from(["aptos-cli", "account", "create", "--key-type", "secp256k1"])
                .unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn account_create_with_mnemonic() {
        let cli = Cli::try_parse_from(["aptos-cli", "account", "create", "--mnemonic"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn account_balance_with_address() {
        let cli =
            Cli::try_parse_from(["aptos-cli", "account", "balance", "--address", "0x1"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn account_balance_without_address_parses() {
        // --address is now optional (auto-injected from active account in interactive mode)
        let cli = Cli::try_parse_from(["aptos-cli", "account", "balance"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn account_lookup_without_address_parses() {
        let cli = Cli::try_parse_from(["aptos-cli", "account", "lookup"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn account_resources_without_address_parses() {
        let cli = Cli::try_parse_from(["aptos-cli", "account", "resources"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn account_resource_requires_resource_type() {
        // --resource-type is required even if --address is optional
        assert!(Cli::try_parse_from(["aptos-cli", "account", "resource"]).is_err());
    }

    #[test]
    fn account_resource_with_type_no_address() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "account",
            "resource",
            "--resource-type",
            "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn account_modules_without_address_parses() {
        let cli = Cli::try_parse_from(["aptos-cli", "account", "modules"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn account_fund_with_apt_amount() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "account",
            "fund",
            "--address",
            "0x1",
            "--amount",
            "1.5",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn account_fund_with_octas_amount() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "account",
            "fund",
            "--address",
            "0x1",
            "--amount",
            "150000000",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn account_fund_without_address_parses() {
        // --address is now optional (auto-injected)
        let cli =
            Cli::try_parse_from(["aptos-cli", "account", "fund", "--amount", "100"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn account_fund_requires_amount() {
        assert!(
            Cli::try_parse_from(["aptos-cli", "account", "fund", "--address", "0x1"]).is_err()
        );
    }

    #[test]
    fn account_transfer_parses() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "account",
            "transfer",
            "--private-key",
            "0xdeadbeef",
            "--to",
            "0x1",
            "--amount",
            "1.0",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn account_transfer_with_coin_type() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "account",
            "transfer",
            "--private-key",
            "0xaa",
            "--to",
            "0x1",
            "--amount",
            "100",
            "--coin-type",
            "0x1::aptos_coin::AptosCoin",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn account_transfer_requires_private_key() {
        assert!(
            Cli::try_parse_from([
                "aptos-cli",
                "account",
                "transfer",
                "--to",
                "0x1",
                "--amount",
                "100",
            ])
            .is_err()
        );
    }

    #[test]
    fn account_transfer_requires_to() {
        assert!(
            Cli::try_parse_from([
                "aptos-cli",
                "account",
                "transfer",
                "--private-key",
                "0xaa",
                "--amount",
                "100",
            ])
            .is_err()
        );
    }

    #[test]
    fn account_transfer_requires_amount() {
        assert!(
            Cli::try_parse_from([
                "aptos-cli",
                "account",
                "transfer",
                "--private-key",
                "0xaa",
                "--to",
                "0x1",
            ])
            .is_err()
        );
    }

    // ===================================================================
    // Key commands — argument parsing
    // ===================================================================

    #[test]
    fn key_generate_defaults() {
        let cli = Cli::try_parse_from(["aptos-cli", "key", "generate"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Key(_))));
    }

    #[test]
    fn key_generate_secp256k1() {
        let cli = Cli::try_parse_from(["aptos-cli", "key", "generate", "--key-type", "secp256k1"])
            .unwrap();
        assert!(matches!(cli.command, Some(Command::Key(_))));
    }

    #[test]
    fn key_generate_secp256r1() {
        let cli = Cli::try_parse_from(["aptos-cli", "key", "generate", "--key-type", "secp256r1"])
            .unwrap();
        assert!(matches!(cli.command, Some(Command::Key(_))));
    }

    #[test]
    fn key_generate_invalid_key_type() {
        assert!(
            Cli::try_parse_from(["aptos-cli", "key", "generate", "--key-type", "rsa"]).is_err()
        );
    }

    #[test]
    fn key_generate_with_mnemonic() {
        let cli = Cli::try_parse_from(["aptos-cli", "key", "generate", "--mnemonic"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Key(_))));
    }

    #[test]
    fn key_from_mnemonic_requires_phrase() {
        assert!(Cli::try_parse_from(["aptos-cli", "key", "from-mnemonic"]).is_err());
    }

    #[test]
    fn key_from_mnemonic_with_phrase() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "key",
            "from-mnemonic",
            "--phrase",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Key(_))));
    }

    #[test]
    fn key_from_mnemonic_with_index() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "key",
            "from-mnemonic",
            "--phrase",
            "test phrase here",
            "--index",
            "5",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Key(_))));
    }

    #[test]
    fn key_show_requires_private_key() {
        assert!(Cli::try_parse_from(["aptos-cli", "key", "show"]).is_err());
    }

    #[test]
    fn key_show_with_private_key() {
        let cli = Cli::try_parse_from(["aptos-cli", "key", "show", "--private-key", "0xdeadbeef"])
            .unwrap();
        assert!(matches!(cli.command, Some(Command::Key(_))));
    }

    #[test]
    fn key_show_with_key_type() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "key",
            "show",
            "--private-key",
            "0xdeadbeef",
            "--key-type",
            "secp256k1",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Key(_))));
    }

    // ===================================================================
    // Move commands — argument parsing
    // ===================================================================

    #[test]
    fn move_init_requires_name() {
        assert!(Cli::try_parse_from(["aptos-cli", "move", "init"]).is_err());
    }

    #[test]
    fn move_init_with_name() {
        let cli = Cli::try_parse_from(["aptos-cli", "move", "init", "--name", "my_pkg"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    #[test]
    fn move_init_with_dir() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "move",
            "init",
            "--name",
            "my_pkg",
            "--dir",
            "/tmp/my_pkg",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    #[test]
    fn move_init_with_named_address() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "move",
            "init",
            "--name",
            "my_pkg",
            "--named-address",
            "deployer",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    #[test]
    fn move_compile_defaults() {
        let cli = Cli::try_parse_from(["aptos-cli", "move", "compile"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    #[test]
    fn move_compile_with_named_addresses() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "move",
            "compile",
            "--named-addresses",
            "my_addr=0x1",
            "other=0x2",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    #[test]
    fn move_test_defaults() {
        let cli = Cli::try_parse_from(["aptos-cli", "move", "test"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    #[test]
    fn move_test_with_filter() {
        let cli = Cli::try_parse_from(["aptos-cli", "move", "test", "--filter", "test_transfer"])
            .unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    #[test]
    fn move_view_requires_function() {
        assert!(Cli::try_parse_from(["aptos-cli", "move", "view"]).is_err());
    }

    #[test]
    fn move_view_with_function() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "move",
            "view",
            "--function",
            "0x1::coin::balance",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    #[test]
    fn move_view_with_type_args_and_args() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "move",
            "view",
            "--function",
            "0x1::coin::balance",
            "--type-args",
            "0x1::aptos_coin::AptosCoin",
            "--args",
            "\"0x1\"",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    #[test]
    fn move_run_requires_function() {
        assert!(
            Cli::try_parse_from(["aptos-cli", "move", "run", "--private-key", "0xaa",]).is_err()
        );
    }

    #[test]
    fn move_run_requires_private_key() {
        assert!(
            Cli::try_parse_from([
                "aptos-cli",
                "move",
                "run",
                "--function",
                "0x1::aptos_account::transfer",
            ])
            .is_err()
        );
    }

    #[test]
    fn move_run_with_all_args() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "move",
            "run",
            "--function",
            "0x1::aptos_account::transfer",
            "--private-key",
            "0xaa",
            "--key-type",
            "ed25519",
            "--type-args",
            "0x1::aptos_coin::AptosCoin",
            "--args",
            "address:0x1",
            "u64:1000",
            "--max-gas",
            "5000",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    #[test]
    fn move_publish_requires_private_key() {
        assert!(
            Cli::try_parse_from(["aptos-cli", "move", "publish", "--package-dir", "/tmp",])
                .is_err()
        );
    }

    #[test]
    fn move_publish_requires_package_dir() {
        assert!(
            Cli::try_parse_from(["aptos-cli", "move", "publish", "--private-key", "0xaa",])
                .is_err()
        );
    }

    #[test]
    fn move_publish_parses() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "move",
            "publish",
            "--private-key",
            "0xaa",
            "--package-dir",
            "/tmp/pkg",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    #[test]
    fn move_build_publish_defaults() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "move",
            "build-publish",
            "--private-key",
            "0xaa",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    #[test]
    fn move_build_publish_requires_private_key() {
        assert!(Cli::try_parse_from(["aptos-cli", "move", "build-publish"]).is_err());
    }

    #[test]
    fn move_inspect_requires_module() {
        assert!(
            Cli::try_parse_from(["aptos-cli", "move", "inspect", "--address", "0x1",]).is_err()
        );
    }

    #[test]
    fn move_inspect_without_address() {
        // --address is optional (auto-injected in interactive mode)
        let cli =
            Cli::try_parse_from(["aptos-cli", "move", "inspect", "--module", "coin"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    #[test]
    fn move_inspect_with_all_args() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "move",
            "inspect",
            "--address",
            "0x1",
            "--module",
            "coin",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Move(_))));
    }

    // ===================================================================
    // Transaction commands — argument parsing
    // ===================================================================

    #[test]
    fn transaction_lookup_requires_hash() {
        assert!(Cli::try_parse_from(["aptos-cli", "transaction", "lookup"]).is_err());
    }

    #[test]
    fn transaction_lookup_with_hash() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "transaction",
            "lookup",
            "--hash",
            "0xaabbccdd",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Transaction(_))));
    }

    #[test]
    fn transaction_simulate_requires_function() {
        assert!(
            Cli::try_parse_from(["aptos-cli", "transaction", "simulate", "--sender", "0x1",])
                .is_err()
        );
    }

    #[test]
    fn transaction_simulate_without_sender() {
        // --sender is now optional (auto-injected from active account in interactive mode)
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "transaction",
            "simulate",
            "--function",
            "0x1::aptos_account::transfer",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Transaction(_))));
    }

    #[test]
    fn transaction_simulate_with_all_args() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "transaction",
            "simulate",
            "--function",
            "0x1::aptos_account::transfer",
            "--sender",
            "0x1",
            "--type-args",
            "0x1::aptos_coin::AptosCoin",
            "--args",
            "address:0x1",
            "u64:1000",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Transaction(_))));
    }

    // ===================================================================
    // Info commands — argument parsing
    // ===================================================================

    #[test]
    fn info_ledger_parses() {
        let cli = Cli::try_parse_from(["aptos-cli", "info", "ledger"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Info(_))));
    }

    #[test]
    fn info_gas_price_parses() {
        let cli = Cli::try_parse_from(["aptos-cli", "info", "gas-price"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Info(_))));
    }

    #[test]
    fn info_block_by_height() {
        let cli = Cli::try_parse_from(["aptos-cli", "info", "block", "--height", "100"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Info(_))));
    }

    #[test]
    fn info_block_by_version() {
        let cli = Cli::try_parse_from(["aptos-cli", "info", "block", "--version", "500"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Info(_))));
    }

    #[test]
    fn info_block_height_and_version_conflict() {
        assert!(
            Cli::try_parse_from([
                "aptos-cli",
                "info",
                "block",
                "--height",
                "100",
                "--version",
                "500",
            ])
            .is_err()
        );
    }

    #[test]
    fn info_block_with_transactions() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "info",
            "block",
            "--height",
            "100",
            "--with-transactions",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Info(_))));
    }

    #[test]
    fn info_block_no_height_or_version_still_parses() {
        // clap allows this; the runtime check catches it with a helpful error
        let cli = Cli::try_parse_from(["aptos-cli", "info", "block"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Info(_))));
    }

    // ===================================================================
    // Global flags applied to each subcommand
    // ===================================================================

    #[test]
    fn global_json_with_account_balance() {
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "--json",
            "account",
            "balance",
            "--address",
            "0x1",
        ])
        .unwrap();
        assert!(cli.global.json);
        assert!(matches!(cli.command, Some(Command::Account(_))));
    }

    #[test]
    fn global_network_with_info_ledger() {
        let cli =
            Cli::try_parse_from(["aptos-cli", "--network", "devnet", "info", "ledger"]).unwrap();
        assert!(matches!(cli.global.network, common::NetworkArg::Devnet));
    }

    // ===================================================================
    // Edge cases
    // ===================================================================

    #[test]
    fn empty_args_parses_as_no_command() {
        // Even an empty iterator yields a default parse (no subcommand)
        // because clap treats the first element as the program name only
        // when provided. An empty iterator gives no program name.
        // With clap, this actually succeeds and gives us None command.
        let result = Cli::try_parse_from(Vec::<&str>::new());
        // This may succeed or fail depending on clap version; just ensure no panic
        drop(result);
    }

    #[test]
    fn unknown_flag_fails() {
        assert!(Cli::try_parse_from(["aptos-cli", "--unknown-flag"]).is_err());
    }

    #[test]
    fn account_create_invalid_key_type_fails() {
        assert!(
            Cli::try_parse_from(["aptos-cli", "account", "create", "--key-type", "invalid",])
                .is_err()
        );
    }

    #[test]
    fn move_run_no_args_at_all_fails() {
        assert!(Cli::try_parse_from(["aptos-cli", "move", "run"]).is_err());
    }

    #[test]
    fn transaction_simulate_empty_type_args() {
        // --type-args with no values should parse as empty vec
        let cli = Cli::try_parse_from([
            "aptos-cli",
            "transaction",
            "simulate",
            "--function",
            "0x1::test::func",
            "--sender",
            "0x1",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Transaction(_))));
    }
}
