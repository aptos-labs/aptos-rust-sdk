//! Move interaction commands.

use crate::common::{self, GlobalOpts, KeyType};
use crate::output;
use anyhow::{Context, Result};
use aptos_sdk::transaction::EntryFunction;
use aptos_sdk::types::{MoveModuleId, TypeTag};
use clap::Args;

/// Move interaction commands.
#[derive(clap::Subcommand, Debug)]
pub enum MoveCommand {
    /// Call a view function (read-only, no transaction)
    View(ViewArgs),
    /// Execute an entry function (submits a transaction)
    Run(RunArgs),
    /// Publish a compiled Move package
    Publish(PublishArgs),
    /// Inspect a module's ABI (structs, functions)
    Inspect(InspectArgs),
}

#[derive(Args, Debug)]
pub struct ViewArgs {
    /// Function ID (e.g., "0x1::coin::balance")
    #[arg(long)]
    function: String,

    /// Type arguments (e.g., "0x1::aptos_coin::AptosCoin")
    #[arg(long, num_args = 0..)]
    type_args: Vec<String>,

    /// Arguments as JSON values (e.g., '"0x1"' or '100')
    #[arg(long, num_args = 0..)]
    args: Vec<String>,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Function ID (e.g., "0x1::aptos_account::transfer")
    #[arg(long)]
    function: String,

    /// Sender's private key (hex)
    #[arg(long)]
    private_key: String,

    /// Key type of the sender
    #[arg(long, default_value = "ed25519")]
    key_type: KeyType,

    /// Type arguments (e.g., "0x1::aptos_coin::AptosCoin")
    #[arg(long, num_args = 0..)]
    type_args: Vec<String>,

    /// BCS arguments (e.g., "address:0x1", "u64:1000", "bool:true", "string:hello")
    #[arg(long, num_args = 0..)]
    args: Vec<String>,

    /// Max gas amount
    #[arg(long)]
    max_gas: Option<u64>,
}

#[derive(Args, Debug)]
pub struct PublishArgs {
    /// Sender's private key (hex)
    #[arg(long)]
    private_key: String,

    /// Key type of the sender
    #[arg(long, default_value = "ed25519")]
    key_type: KeyType,

    /// Path to the compiled package directory (containing package-metadata.bcs and bytecode_modules/)
    #[arg(long)]
    package_dir: String,
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Account address that owns the module
    #[arg(long)]
    address: String,

    /// Module name (e.g., "coin")
    #[arg(long)]
    module: String,
}

impl MoveCommand {
    pub async fn run(&self, global: &GlobalOpts) -> Result<()> {
        match self {
            MoveCommand::View(args) => cmd_view(args, global).await,
            MoveCommand::Run(args) => cmd_run(args, global).await,
            MoveCommand::Publish(args) => cmd_publish(args, global).await,
            MoveCommand::Inspect(args) => cmd_inspect(args, global).await,
        }
    }
}

async fn cmd_view(args: &ViewArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;

    // Parse arguments as JSON values
    let json_args: Vec<serde_json::Value> = args
        .args
        .iter()
        .map(|a| common::parse_json_arg(a))
        .collect::<Result<_>>()?;

    let result = aptos
        .view(&args.function, args.type_args.clone(), json_args)
        .await
        .context("view function call failed")?;

    if global.json {
        output::print_json(&serde_json::json!(result))?;
    } else {
        output::print_header(&format!("View: {}", args.function));
        println!("{}", serde_json::to_string_pretty(&result)?);
    }
    Ok(())
}

async fn cmd_run(args: &RunArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;
    let account = common::load_account(&args.private_key, &args.key_type)?;

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

    // Parse function ID into module + function name
    let payload = EntryFunction::from_function_id(&args.function, type_args, bcs_args)
        .context("invalid function ID")?;

    let result = account
        .sign_submit_and_wait(&aptos, payload.into())
        .await
        .context("transaction submission failed")?;

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
        output::print_success(&format!("Entry function {} executed", args.function));
        output::print_kv("Transaction Hash", hash);
        output::print_kv("Version", version);
        output::print_kv("Gas Used", gas_used);
    } else {
        let vm_status = result
            .data
            .get("vm_status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        eprintln!("Transaction failed: {vm_status}");
        std::process::exit(1);
    }
    Ok(())
}

async fn cmd_publish(args: &PublishArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;
    let account = common::load_account(&args.private_key, &args.key_type)?;

    let package_dir = std::path::Path::new(&args.package_dir);

    // Read package metadata
    let metadata_path = package_dir.join("package-metadata.bcs");
    let metadata = std::fs::read(&metadata_path)
        .context(format!("failed to read {}", metadata_path.display()))?;

    // Read all .mv bytecode files from bytecode_modules/
    let modules_dir = package_dir.join("bytecode_modules");
    let mut module_bytecodes: Vec<Vec<u8>> = Vec::new();

    if modules_dir.exists() {
        let mut entries: Vec<_> = std::fs::read_dir(&modules_dir)
            .context(format!("failed to read {}", modules_dir.display()))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "mv"))
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let bytecode = std::fs::read(entry.path())
                .context(format!("failed to read {}", entry.path().display()))?;
            module_bytecodes.push(bytecode);
        }
    }

    if module_bytecodes.is_empty() {
        anyhow::bail!(
            "No .mv bytecode files found in {}. \
             Compile your Move package first with `aptos move compile --save-metadata`.",
            modules_dir.display()
        );
    }

    // Build the publish payload: 0x1::code::publish_package_txn(metadata, code)
    let module_id =
        MoveModuleId::from_str_strict("0x1::code").context("failed to parse module ID")?;

    let payload = EntryFunction::new(
        module_id,
        "publish_package_txn",
        vec![],
        vec![
            aptos_bcs::to_bytes(&metadata).context("BCS encode metadata")?,
            aptos_bcs::to_bytes(&module_bytecodes).context("BCS encode modules")?,
        ],
    );

    let result = account
        .sign_submit_and_wait(&aptos, payload.into())
        .await
        .context("publish transaction failed")?;

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

    if global.json {
        output::print_json(&result.data)?;
    } else if success == Some(true) {
        output::print_success("Package published successfully");
        output::print_kv("Transaction Hash", hash);
        output::print_kv("Gas Used", gas_used);
        output::print_kv("Modules Published", &module_bytecodes.len().to_string());
    } else {
        let vm_status = result
            .data
            .get("vm_status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        eprintln!("Publish failed: {vm_status}");
        std::process::exit(1);
    }
    Ok(())
}

async fn cmd_inspect(args: &InspectArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;
    let address = common::parse_address(&args.address)?;

    let module = aptos
        .fullnode()
        .get_account_module(address, &args.module)
        .await
        .context("failed to get module")?;

    let Some(abi) = &module.data.abi else {
        anyhow::bail!(
            "Module {}::{} does not have ABI information",
            address,
            args.module
        );
    };

    if global.json {
        let entry_fns: Vec<_> = abi
            .exposed_functions
            .iter()
            .filter(|f| f.is_entry)
            .map(|f| {
                serde_json::json!({
                    "name": f.name,
                    "params": f.params,
                    "generic_type_params": f.generic_type_params,
                })
            })
            .collect();
        let view_fns: Vec<_> = abi
            .exposed_functions
            .iter()
            .filter(|f| f.is_view)
            .map(|f| {
                serde_json::json!({
                    "name": f.name,
                    "params": f.params,
                    "returns": f.returns,
                    "generic_type_params": f.generic_type_params,
                })
            })
            .collect();
        let structs: Vec<_> = abi
            .structs
            .iter()
            .map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "fields": s.fields,
                    "abilities": s.abilities,
                    "generic_type_params": s.generic_type_params,
                })
            })
            .collect();

        output::print_json(&serde_json::json!({
            "module": format!("{}::{}", abi.address, abi.name),
            "entry_functions": entry_fns,
            "view_functions": view_fns,
            "structs": structs,
        }))?;
    } else {
        output::print_header(&format!("Module: {}::{}", abi.address, abi.name));

        println!("\n  Entry Functions:");
        let entry_fns: Vec<_> = abi
            .exposed_functions
            .iter()
            .filter(|f| f.is_entry)
            .collect();
        if entry_fns.is_empty() {
            println!("    (none)");
        }
        for f in &entry_fns {
            println!("    - {}({})", f.name, f.params.join(", "));
        }

        println!("\n  View Functions:");
        let view_fns: Vec<_> = abi.exposed_functions.iter().filter(|f| f.is_view).collect();
        if view_fns.is_empty() {
            println!("    (none)");
        }
        for f in &view_fns {
            let returns = if f.returns.is_empty() {
                String::new()
            } else {
                format!(" -> ({})", f.returns.join(", "))
            };
            println!("    - {}({}){}", f.name, f.params.join(", "), returns);
        }

        println!("\n  Structs:");
        if abi.structs.is_empty() {
            println!("    (none)");
        }
        for s in &abi.structs {
            let abilities = if s.abilities.is_empty() {
                String::new()
            } else {
                format!(" [{}]", s.abilities.join(", "))
            };
            println!("    - {}{}", s.name, abilities);
            for field in &s.fields {
                println!("        {}: {}", field.name, field.typ);
            }
        }
    }
    Ok(())
}
