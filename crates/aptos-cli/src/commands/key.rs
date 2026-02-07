//! Key management commands.

use crate::common::{GlobalOpts, KeyType};
use crate::output;
use anyhow::{Context, Result};
use aptos_sdk::account::{Ed25519Account, Secp256k1Account, Secp256r1Account};
use clap::Args;

/// Key management commands.
#[derive(clap::Subcommand, Debug)]
pub enum KeyCommand {
    /// Generate a new random keypair
    Generate(GenerateArgs),
    /// Derive a key from a BIP-39 mnemonic phrase
    FromMnemonic(FromMnemonicArgs),
    /// Show address and public key from a private key
    Show(ShowArgs),
}

#[derive(Args, Debug)]
pub struct GenerateArgs {
    /// Key type to generate
    #[arg(long, default_value = "ed25519")]
    key_type: KeyType,

    /// Also generate and display a BIP-39 mnemonic phrase (Ed25519 only)
    #[arg(long, default_value_t = false)]
    mnemonic: bool,
}

#[derive(Args, Debug)]
pub struct FromMnemonicArgs {
    /// BIP-39 mnemonic phrase
    #[arg(long)]
    phrase: String,

    /// Derivation index (default 0)
    #[arg(long, default_value_t = 0)]
    index: u32,
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Private key hex
    #[arg(long)]
    private_key: String,

    /// Key type
    #[arg(long, default_value = "ed25519")]
    key_type: KeyType,
}

impl KeyCommand {
    pub fn run(&self, global: &GlobalOpts) -> Result<()> {
        match self {
            KeyCommand::Generate(args) => cmd_generate(args, global),
            KeyCommand::FromMnemonic(args) => cmd_from_mnemonic(args, global),
            KeyCommand::Show(args) => cmd_show(args, global),
        }
    }
}

fn cmd_generate(args: &GenerateArgs, global: &GlobalOpts) -> Result<()> {
    match args.key_type {
        KeyType::Ed25519 => {
            if args.mnemonic {
                let (account, phrase) = Ed25519Account::generate_with_mnemonic()
                    .context("failed to generate mnemonic")?;
                if global.json {
                    output::print_json(&serde_json::json!({
                        "address": account.address().to_string(),
                        "public_key": account.public_key().to_string(),
                        "private_key": hex::encode(account.private_key().to_bytes()),
                        "mnemonic": phrase,
                        "key_type": "ed25519",
                    }))?;
                } else {
                    output::print_header("Generated Ed25519 Keypair (with mnemonic)");
                    output::print_kv("Address", &account.address().to_string());
                    output::print_kv("Public Key", &account.public_key().to_string());
                    output::print_kv(
                        "Private Key",
                        &hex::encode(account.private_key().to_bytes()),
                    );
                    output::print_kv("Mnemonic", &phrase);
                    println!();
                    output::print_warning("Store your keys and mnemonic securely!");
                }
            } else {
                let account = Ed25519Account::generate();
                if global.json {
                    output::print_json(&serde_json::json!({
                        "address": account.address().to_string(),
                        "public_key": account.public_key().to_string(),
                        "private_key": hex::encode(account.private_key().to_bytes()),
                        "key_type": "ed25519",
                    }))?;
                } else {
                    output::print_header("Generated Ed25519 Keypair");
                    output::print_kv("Address", &account.address().to_string());
                    output::print_kv("Public Key", &account.public_key().to_string());
                    output::print_kv(
                        "Private Key",
                        &hex::encode(account.private_key().to_bytes()),
                    );
                    println!();
                    output::print_warning("Store your keys securely!");
                }
            }
        }
        KeyType::Secp256k1 => {
            if args.mnemonic {
                output::print_warning(
                    "Mnemonic generation is only supported for Ed25519. Generating without mnemonic.",
                );
            }
            let account = Secp256k1Account::generate();
            if global.json {
                output::print_json(&serde_json::json!({
                    "address": account.address().to_string(),
                    "public_key": account.public_key().to_string(),
                    "private_key": hex::encode(account.private_key().to_bytes()),
                    "key_type": "secp256k1",
                }))?;
            } else {
                output::print_header("Generated Secp256k1 Keypair");
                output::print_kv("Address", &account.address().to_string());
                output::print_kv("Public Key", &account.public_key().to_string());
                output::print_kv(
                    "Private Key",
                    &hex::encode(account.private_key().to_bytes()),
                );
                println!();
                output::print_warning("Store your keys securely!");
            }
        }
        KeyType::Secp256r1 => {
            if args.mnemonic {
                output::print_warning(
                    "Mnemonic generation is only supported for Ed25519. Generating without mnemonic.",
                );
            }
            let account = Secp256r1Account::generate();
            if global.json {
                output::print_json(&serde_json::json!({
                    "address": account.address().to_string(),
                    "public_key": account.public_key().to_string(),
                    "private_key": hex::encode(account.private_key().to_bytes()),
                    "key_type": "secp256r1",
                }))?;
            } else {
                output::print_header("Generated Secp256r1 Keypair");
                output::print_kv("Address", &account.address().to_string());
                output::print_kv("Public Key", &account.public_key().to_string());
                output::print_kv(
                    "Private Key",
                    &hex::encode(account.private_key().to_bytes()),
                );
                println!();
                output::print_warning("Store your keys securely!");
            }
        }
    }
    Ok(())
}

fn cmd_from_mnemonic(args: &FromMnemonicArgs, global: &GlobalOpts) -> Result<()> {
    // Mnemonic derivation is only supported for Ed25519
    let account = Ed25519Account::from_mnemonic(&args.phrase, args.index)
        .context("failed to derive from mnemonic")?;

    if global.json {
        output::print_json(&serde_json::json!({
            "address": account.address().to_string(),
            "public_key": account.public_key().to_string(),
            "private_key": hex::encode(account.private_key().to_bytes()),
            "key_type": "ed25519",
            "derivation_index": args.index,
        }))?;
    } else {
        output::print_header(&format!("Ed25519 Key (index {})", args.index));
        output::print_kv("Address", &account.address().to_string());
        output::print_kv("Public Key", &account.public_key().to_string());
        output::print_kv(
            "Private Key",
            &hex::encode(account.private_key().to_bytes()),
        );
    }
    Ok(())
}

fn cmd_show(args: &ShowArgs, global: &GlobalOpts) -> Result<()> {
    let hex_key = args
        .private_key
        .strip_prefix("0x")
        .unwrap_or(&args.private_key);

    match args.key_type {
        KeyType::Ed25519 => {
            let account =
                Ed25519Account::from_private_key_hex(hex_key).context("invalid private key")?;
            if global.json {
                output::print_json(&serde_json::json!({
                    "address": account.address().to_string(),
                    "public_key": account.public_key().to_string(),
                    "key_type": "ed25519",
                }))?;
            } else {
                output::print_header("Ed25519 Key Info");
                output::print_kv("Address", &account.address().to_string());
                output::print_kv("Public Key", &account.public_key().to_string());
            }
        }
        KeyType::Secp256k1 => {
            let account =
                Secp256k1Account::from_private_key_hex(hex_key).context("invalid private key")?;
            if global.json {
                output::print_json(&serde_json::json!({
                    "address": account.address().to_string(),
                    "public_key": account.public_key().to_string(),
                    "key_type": "secp256k1",
                }))?;
            } else {
                output::print_header("Secp256k1 Key Info");
                output::print_kv("Address", &account.address().to_string());
                output::print_kv("Public Key", &account.public_key().to_string());
            }
        }
        KeyType::Secp256r1 => {
            let account =
                Secp256r1Account::from_private_key_hex(hex_key).context("invalid private key")?;
            if global.json {
                output::print_json(&serde_json::json!({
                    "address": account.address().to_string(),
                    "public_key": account.public_key().to_string(),
                    "key_type": "secp256r1",
                }))?;
            } else {
                output::print_header("Secp256r1 Key Info");
                output::print_kv("Address", &account.address().to_string());
                output::print_kv("Public Key", &account.public_key().to_string());
            }
        }
    }
    Ok(())
}
