//! Account management commands.

use crate::common::{self, GlobalOpts, KeyType};
use crate::output;
use anyhow::{Context, Result};
use aptos_sdk::types::TypeTag;
use clap::Args;

/// Account management commands.
#[derive(clap::Subcommand, Debug)]
pub enum AccountCommand {
    /// Generate a new account keypair
    Create(CreateArgs),
    /// Fund an account via faucet (testnet/devnet only)
    Fund(FundArgs),
    /// Check APT balance for an address
    Balance(BalanceArgs),
    /// Look up account information (sequence number, auth key)
    Lookup(LookupArgs),
    /// List all resources on an account
    Resources(ResourcesArgs),
    /// Get a specific resource from an account
    Resource(ResourceArgs),
    /// List deployed modules on an account
    Modules(ModulesArgs),
    /// Transfer APT to another address
    Transfer(TransferArgs),
}

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Key type to generate
    #[arg(long, default_value = "ed25519")]
    key_type: KeyType,

    /// Also generate and display a BIP-39 mnemonic phrase
    #[arg(long, default_value_t = false)]
    mnemonic: bool,
}

#[derive(Args, Debug)]
pub struct FundArgs {
    /// Address to fund
    #[arg(long)]
    address: String,

    /// Amount in octas (1 APT = 100,000,000 octas)
    #[arg(long)]
    amount: u64,
}

#[derive(Args, Debug)]
pub struct BalanceArgs {
    /// Account address
    #[arg(long)]
    address: String,
}

#[derive(Args, Debug)]
pub struct LookupArgs {
    /// Account address
    #[arg(long)]
    address: String,
}

#[derive(Args, Debug)]
pub struct ResourcesArgs {
    /// Account address
    #[arg(long)]
    address: String,
}

#[derive(Args, Debug)]
pub struct ResourceArgs {
    /// Account address
    #[arg(long)]
    address: String,

    /// Resource type (e.g., "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>")
    #[arg(long, name = "type")]
    resource_type: String,
}

#[derive(Args, Debug)]
pub struct ModulesArgs {
    /// Account address
    #[arg(long)]
    address: String,
}

#[derive(Args, Debug)]
pub struct TransferArgs {
    /// Sender's private key (hex)
    #[arg(long)]
    private_key: String,

    /// Key type of the sender
    #[arg(long, default_value = "ed25519")]
    key_type: KeyType,

    /// Recipient address
    #[arg(long)]
    to: String,

    /// Amount in octas (1 APT = 100,000,000 octas)
    #[arg(long)]
    amount: u64,

    /// Coin type for non-APT transfers (e.g., "0x1::aptos_coin::AptosCoin")
    #[arg(long)]
    coin_type: Option<String>,
}

impl AccountCommand {
    pub async fn run(&self, global: &GlobalOpts) -> Result<()> {
        match self {
            AccountCommand::Create(args) => cmd_create(args, global),
            AccountCommand::Fund(args) => cmd_fund(args, global).await,
            AccountCommand::Balance(args) => cmd_balance(args, global).await,
            AccountCommand::Lookup(args) => cmd_lookup(args, global).await,
            AccountCommand::Resources(args) => cmd_resources(args, global).await,
            AccountCommand::Resource(args) => cmd_resource(args, global).await,
            AccountCommand::Modules(args) => cmd_modules(args, global).await,
            AccountCommand::Transfer(args) => cmd_transfer(args, global).await,
        }
    }
}

fn cmd_create(args: &CreateArgs, global: &GlobalOpts) -> Result<()> {
    use aptos_sdk::account::{Ed25519Account, Secp256k1Account, Secp256r1Account};

    match args.key_type {
        KeyType::Ed25519 => {
            if args.mnemonic {
                let (account, phrase) = Ed25519Account::generate_with_mnemonic()
                    .context("failed to generate mnemonic account")?;
                if global.json {
                    output::print_json(&serde_json::json!({
                        "address": account.address().to_string(),
                        "public_key": account.public_key().to_string(),
                        "private_key": hex::encode(account.private_key().to_bytes()),
                        "mnemonic": phrase,
                        "key_type": "ed25519",
                    }))?;
                } else {
                    output::print_header("New Ed25519 Account (with mnemonic)");
                    output::print_kv("Address", &account.address().to_string());
                    output::print_kv("Public Key", &account.public_key().to_string());
                    output::print_kv(
                        "Private Key",
                        &hex::encode(account.private_key().to_bytes()),
                    );
                    output::print_kv("Mnemonic", &phrase);
                    println!();
                    output::print_warning("Store your private key and mnemonic securely!");
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
                    output::print_header("New Ed25519 Account");
                    output::print_kv("Address", &account.address().to_string());
                    output::print_kv("Public Key", &account.public_key().to_string());
                    output::print_kv(
                        "Private Key",
                        &hex::encode(account.private_key().to_bytes()),
                    );
                    println!();
                    output::print_warning("Store your private key securely!");
                }
            }
        }
        KeyType::Secp256k1 => {
            let account = Secp256k1Account::generate();
            if global.json {
                output::print_json(&serde_json::json!({
                    "address": account.address().to_string(),
                    "public_key": account.public_key().to_string(),
                    "private_key": hex::encode(account.private_key().to_bytes()),
                    "key_type": "secp256k1",
                }))?;
            } else {
                output::print_header("New Secp256k1 Account");
                output::print_kv("Address", &account.address().to_string());
                output::print_kv("Public Key", &account.public_key().to_string());
                output::print_kv(
                    "Private Key",
                    &hex::encode(account.private_key().to_bytes()),
                );
                println!();
                output::print_warning("Store your private key securely!");
            }
        }
        KeyType::Secp256r1 => {
            let account = Secp256r1Account::generate();
            if global.json {
                output::print_json(&serde_json::json!({
                    "address": account.address().to_string(),
                    "public_key": account.public_key().to_string(),
                    "private_key": hex::encode(account.private_key().to_bytes()),
                    "key_type": "secp256r1",
                }))?;
            } else {
                output::print_header("New Secp256r1 Account");
                output::print_kv("Address", &account.address().to_string());
                output::print_kv("Public Key", &account.public_key().to_string());
                output::print_kv(
                    "Private Key",
                    &hex::encode(account.private_key().to_bytes()),
                );
                println!();
                output::print_warning("Store your private key securely!");
            }
        }
    }

    Ok(())
}

async fn cmd_fund(args: &FundArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;
    let address = common::parse_address(&args.address)?;

    aptos
        .fund_account(address, args.amount)
        .await
        .context("failed to fund account")?;

    if global.json {
        output::print_json(&serde_json::json!({
            "address": address.to_string(),
            "amount_funded": args.amount,
            "status": "success",
        }))?;
    } else {
        output::print_success(&format!(
            "Funded {} with {}",
            address,
            output::format_apt(args.amount),
        ));
    }
    Ok(())
}

async fn cmd_balance(args: &BalanceArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;
    let address = common::parse_address(&args.address)?;

    let balance = aptos
        .get_balance(address)
        .await
        .context("failed to get balance")?;

    if global.json {
        output::print_json(&serde_json::json!({
            "address": address.to_string(),
            "balance_octas": balance,
            "balance_apt": balance as f64 / 100_000_000.0,
        }))?;
    } else {
        output::print_header("Account Balance");
        output::print_kv("Address", &address.to_string());
        output::print_kv("Balance", &output::format_apt(balance));
    }
    Ok(())
}

async fn cmd_lookup(args: &LookupArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;
    let address = common::parse_address(&args.address)?;

    let account_data = aptos
        .fullnode()
        .get_account(address)
        .await
        .context("failed to get account")?;

    if global.json {
        output::print_json(&serde_json::json!({
            "address": address.to_string(),
            "sequence_number": account_data.data.sequence_number,
            "authentication_key": account_data.data.authentication_key,
        }))?;
    } else {
        output::print_header("Account Info");
        output::print_kv("Address", &address.to_string());
        output::print_kv("Sequence Number", &account_data.data.sequence_number);
        output::print_kv("Authentication Key", &account_data.data.authentication_key);
    }
    Ok(())
}

async fn cmd_resources(args: &ResourcesArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;
    let address = common::parse_address(&args.address)?;

    let resources = aptos
        .fullnode()
        .get_account_resources(address)
        .await
        .context("failed to get account resources")?;

    if global.json {
        let json_resources: Vec<_> = resources
            .data
            .iter()
            .map(|r| {
                serde_json::json!({
                    "type": r.typ,
                    "data": r.data,
                })
            })
            .collect();
        output::print_json(&serde_json::json!(json_resources))?;
    } else {
        output::print_header(&format!(
            "Resources for {} ({} total)",
            address,
            resources.data.len()
        ));
        for resource in &resources.data {
            println!("  - {}", resource.typ);
        }
    }
    Ok(())
}

async fn cmd_resource(args: &ResourceArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;
    let address = common::parse_address(&args.address)?;

    let resource = aptos
        .fullnode()
        .get_account_resource(address, &args.resource_type)
        .await
        .context("failed to get account resource")?;

    if global.json {
        output::print_json(&serde_json::json!({
            "type": resource.data.typ,
            "data": resource.data.data,
        }))?;
    } else {
        output::print_header(&format!("Resource: {}", resource.data.typ));
        println!("{}", serde_json::to_string_pretty(&resource.data.data)?);
    }
    Ok(())
}

async fn cmd_modules(args: &ModulesArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;
    let address = common::parse_address(&args.address)?;

    let modules = aptos
        .fullnode()
        .get_account_modules(address)
        .await
        .context("failed to get account modules")?;

    if global.json {
        let json_modules: Vec<_> = modules
            .data
            .iter()
            .map(|m| {
                if let Some(abi) = &m.abi {
                    let entry_count = abi.exposed_functions.iter().filter(|f| f.is_entry).count();
                    let view_count = abi.exposed_functions.iter().filter(|f| f.is_view).count();
                    serde_json::json!({
                        "name": abi.name,
                        "address": abi.address,
                        "entry_functions": entry_count,
                        "view_functions": view_count,
                        "structs": abi.structs.len(),
                    })
                } else {
                    serde_json::json!({ "name": "unknown" })
                }
            })
            .collect();
        output::print_json(&serde_json::json!(json_modules))?;
    } else {
        output::print_header(&format!(
            "Modules at {} ({} total)",
            address,
            modules.data.len()
        ));
        for module in &modules.data {
            if let Some(abi) = &module.abi {
                let entry_count = abi.exposed_functions.iter().filter(|f| f.is_entry).count();
                let view_count = abi.exposed_functions.iter().filter(|f| f.is_view).count();
                println!(
                    "  - {}::{} ({} entry, {} view, {} structs)",
                    abi.address,
                    abi.name,
                    entry_count,
                    view_count,
                    abi.structs.len(),
                );
            }
        }
    }
    Ok(())
}

async fn cmd_transfer(args: &TransferArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;
    let account = common::load_account(&args.private_key, &args.key_type)?;
    let recipient = common::parse_address(&args.to)?;

    let result = if let Some(coin_type_str) = &args.coin_type {
        let coin_type = TypeTag::from_str_strict(coin_type_str).context("invalid coin type")?;
        account
            .transfer_coin(&aptos, recipient, coin_type, args.amount)
            .await
            .context("coin transfer failed")?
    } else {
        account
            .transfer_apt(&aptos, recipient, args.amount)
            .await
            .context("APT transfer failed")?
    };

    let success = result.data.get("success").and_then(|v| v.as_bool());
    let hash = result
        .data
        .get("hash")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let gas_used = result
        .data
        .get("gas_used")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let version = result
        .data
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    if global.json {
        output::print_json(&result.data)?;
    } else if success == Some(true) {
        output::print_success("Transfer completed");
        output::print_kv("Transaction Hash", hash);
        output::print_kv("Version", version);
        output::print_kv("Gas Used", gas_used);
        output::print_kv("Amount", &output::format_apt(args.amount));
        output::print_kv("Recipient", &recipient.to_string());
    } else {
        let vm_status = result
            .data
            .get("vm_status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        eprintln!("Transfer failed: {vm_status}");
        std::process::exit(1);
    }
    Ok(())
}
