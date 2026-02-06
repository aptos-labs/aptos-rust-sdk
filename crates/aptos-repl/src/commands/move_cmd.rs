//! Move interaction commands.

use crate::common::{self, GlobalOpts, KeyType};
use crate::output;
use anyhow::{Context, Result};
use aptos_sdk::transaction::EntryFunction;
use aptos_sdk::types::{MoveModuleId, TypeTag};
use clap::Args;
use std::path::PathBuf;
use std::process::Command;

/// Move interaction commands.
#[derive(clap::Subcommand, Debug)]
pub enum MoveCommand {
    /// Initialize a new Move package
    Init(InitArgs),
    /// Compile a Move package
    Compile(CompileArgs),
    /// Run Move unit tests
    Test(TestArgs),
    /// Call a view function (read-only, no transaction)
    View(ViewArgs),
    /// Execute an entry function (submits a transaction)
    Run(RunArgs),
    /// Publish a compiled Move package
    Publish(PublishArgs),
    /// Compile and publish a Move package in one step
    BuildPublish(BuildPublishArgs),
    /// Inspect a module's ABI (structs, functions)
    Inspect(InspectArgs),
}

// =============================================================================
// Argument structs
// =============================================================================

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Package name
    #[arg(long)]
    name: String,

    /// Directory to create the package in (defaults to ./<name>)
    #[arg(long)]
    dir: Option<PathBuf>,

    /// Named address for the package (e.g., "my_addr")
    #[arg(long, default_value = "my_addr")]
    named_address: String,
}

#[derive(Args, Debug)]
pub struct CompileArgs {
    /// Path to the Move package directory (defaults to current directory)
    #[arg(long, default_value = ".")]
    package_dir: PathBuf,

    /// Also save metadata for publishing (--save-metadata)
    #[arg(long, default_value_t = true)]
    save_metadata: bool,

    /// Named addresses (e.g., "my_addr=0x1234")
    #[arg(long, num_args = 0..)]
    named_addresses: Vec<String>,
}

#[derive(Args, Debug)]
pub struct TestArgs {
    /// Path to the Move package directory (defaults to current directory)
    #[arg(long, default_value = ".")]
    package_dir: PathBuf,

    /// Filter to run specific tests (substring match)
    #[arg(long)]
    filter: Option<String>,

    /// Named addresses (e.g., "my_addr=0x1234")
    #[arg(long, num_args = 0..)]
    named_addresses: Vec<String>,
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
pub struct BuildPublishArgs {
    /// Sender's private key (hex)
    #[arg(long)]
    private_key: String,

    /// Key type of the sender
    #[arg(long, default_value = "ed25519")]
    key_type: KeyType,

    /// Path to the Move package directory (defaults to current directory)
    #[arg(long, default_value = ".")]
    package_dir: PathBuf,

    /// Named addresses (e.g., "my_addr=0x1234")
    #[arg(long, num_args = 0..)]
    named_addresses: Vec<String>,
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

// =============================================================================
// Command dispatch
// =============================================================================

impl MoveCommand {
    pub async fn run(&self, global: &GlobalOpts) -> Result<()> {
        match self {
            MoveCommand::Init(args) => cmd_init(args, global),
            MoveCommand::Compile(args) => cmd_compile(args, global),
            MoveCommand::Test(args) => cmd_test(args, global),
            MoveCommand::View(args) => cmd_view(args, global).await,
            MoveCommand::Run(args) => cmd_run(args, global).await,
            MoveCommand::Publish(args) => cmd_publish(args, global).await,
            MoveCommand::BuildPublish(args) => cmd_build_publish(args, global).await,
            MoveCommand::Inspect(args) => cmd_inspect(args, global).await,
        }
    }
}

// =============================================================================
// Helpers for invoking the Move compiler
// =============================================================================

/// Find the `aptos` CLI binary, preferring the newest version available.
fn find_aptos_cli() -> Result<PathBuf> {
    // Find all `aptos` binaries in PATH and pick the best one.
    // The `which::which` crate may find an older version first depending on PATH order,
    // so we check all candidates and prefer the newest.
    let candidates: Vec<PathBuf> = which::which_all("aptos")
        .map(|iter| iter.collect())
        .unwrap_or_default();

    if candidates.is_empty() {
        anyhow::bail!(
            "Could not find the `aptos` CLI.\n\
             Install it with: curl -fsSL https://aptos.dev/scripts/install_cli.py | python3\n\
             Or see: https://aptos.dev/tools/aptos-cli/install-cli/"
        );
    }

    // If there's only one, use it
    if candidates.len() == 1 {
        return Ok(candidates.into_iter().next().unwrap());
    }

    // Check versions and pick the newest
    let mut best: Option<(PathBuf, (u32, u32, u32))> = None;
    for candidate in &candidates {
        if let Ok(output) = Command::new(candidate).arg("--version").output() {
            let version_str = String::from_utf8_lossy(&output.stdout);
            if let Some(version) = parse_version(&version_str)
                && best
                    .as_ref()
                    .is_none_or(|(_, best_ver)| version > *best_ver)
            {
                best = Some((candidate.clone(), version));
            }
        }
    }

    best.map(|(path, _)| path)
        .or_else(|| candidates.into_iter().next())
        .context(
            "Could not find a working `aptos` CLI.\n\
             Install it with: curl -fsSL https://aptos.dev/scripts/install_cli.py | python3",
        )
}

/// Parse a version string like "aptos 7.14.2" into (major, minor, patch).
pub(crate) fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.trim();
    let version_part = s.strip_prefix("aptos ").unwrap_or(s);
    let mut parts = version_part.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

/// Build a `Command` for the `aptos` CLI with clean environment.
fn aptos_command(args: &[&str], package_dir: &std::path::Path) -> Result<Command> {
    let aptos_bin = find_aptos_cli()?;

    let mut cmd = Command::new(&aptos_bin);
    cmd.args(args);
    cmd.arg("--package-dir");
    cmd.arg(package_dir);

    // Use a clean environment to prevent Rust/Cargo env vars from interfering
    // with the Move compiler embedded in the aptos CLI.
    cmd.env_clear();

    // Re-add essential env vars
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    if let Ok(home) = std::env::var("HOME") {
        cmd.env("HOME", home);
    }
    if let Ok(term) = std::env::var("TERM") {
        cmd.env("TERM", term);
    }
    // Support custom Move home directory
    if let Ok(move_home) = std::env::var("MOVE_HOME") {
        cmd.env("MOVE_HOME", move_home);
    }

    Ok(cmd)
}

/// Run the `aptos` CLI with the given arguments, streaming output.
fn run_aptos_cmd(args: &[&str], package_dir: &std::path::Path) -> Result<bool> {
    let status = aptos_command(args, package_dir)?
        .status()
        .context("failed to execute aptos CLI")?;

    Ok(status.success())
}

// =============================================================================
// Init command
// =============================================================================

fn cmd_init(args: &InitArgs, global: &GlobalOpts) -> Result<()> {
    let target_dir = args
        .dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(&args.name));

    if target_dir.exists() {
        anyhow::bail!("Directory {} already exists", target_dir.display());
    }

    std::fs::create_dir_all(&target_dir)
        .context(format!("failed to create {}", target_dir.display()))?;

    // Create Move.toml
    let move_toml = format!(
        r#"[package]
name = "{name}"
version = "1.0.0"
authors = []

[addresses]
{named_address} = "_"

[dev-addresses]
{named_address} = "0xcafe"

[dependencies.AptosFramework]
git = "https://github.com/aptos-labs/aptos-framework.git"
rev = "mainnet"
subdir = "aptos-framework"
"#,
        name = args.name,
        named_address = args.named_address,
    );

    std::fs::write(target_dir.join("Move.toml"), move_toml).context("failed to write Move.toml")?;

    // Create sources directory
    let sources_dir = target_dir.join("sources");
    std::fs::create_dir_all(&sources_dir).context("failed to create sources/")?;

    // Create a sample module
    let module_source = format!(
        r#"module {named_address}::{name} {{
    use std::string::String;
    use std::signer;

    /// A resource that holds a message.
    struct MessageHolder has key {{
        message: String,
    }}

    /// Initialize with a message.
    public entry fun set_message(account: &signer, message: String) acquires MessageHolder {{
        let addr = signer::address_of(account);
        if (exists<MessageHolder>(addr)) {{
            let holder = borrow_global_mut<MessageHolder>(addr);
            holder.message = message;
        }} else {{
            move_to(account, MessageHolder {{ message }});
        }};
    }}

    #[view]
    /// Get the message for an address.
    public fun get_message(addr: address): String acquires MessageHolder {{
        assert!(exists<MessageHolder>(addr), 1);
        borrow_global<MessageHolder>(addr).message
    }}
}}
"#,
        name = args.name,
        named_address = args.named_address,
    );

    std::fs::write(
        sources_dir.join(format!("{}.move", args.name)),
        module_source,
    )
    .context("failed to write module source")?;

    // Create tests directory with a sample test
    let tests_dir = target_dir.join("tests");
    std::fs::create_dir_all(&tests_dir).context("failed to create tests/")?;

    let test_source = format!(
        r#"#[test_only]
module {named_address}::{name}_tests {{
    use std::string;
    use {named_address}::{name};

    #[test(account = @{named_address})]
    fun test_set_and_get_message(account: &signer) {{
        let msg = string::utf8(b"Hello, Aptos!");
        {name}::set_message(account, msg);
        let result = {name}::get_message(@{named_address});
        assert!(result == string::utf8(b"Hello, Aptos!"), 0);
    }}
}}
"#,
        name = args.name,
        named_address = args.named_address,
    );

    std::fs::write(
        tests_dir.join(format!("{}_tests.move", args.name)),
        test_source,
    )
    .context("failed to write test source")?;

    if global.json {
        output::print_json(&serde_json::json!({
            "package_name": args.name,
            "directory": target_dir.display().to_string(),
            "named_address": args.named_address,
            "files": [
                "Move.toml",
                format!("sources/{}.move", args.name),
                format!("tests/{}_tests.move", args.name),
            ],
        }))?;
    } else {
        output::print_success(&format!(
            "Created Move package '{}' at {}",
            args.name,
            target_dir.display()
        ));
        println!();
        println!("  Files created:");
        println!("    Move.toml");
        println!("    sources/{}.move", args.name);
        println!("    tests/{}_tests.move", args.name);
        println!();
        println!("  Next steps:");
        println!("    cd {}", target_dir.display());
        println!(
            "    aptos-sdk-cli move compile --named-addresses {}=0x<YOUR_ADDRESS>",
            args.named_address
        );
        println!(
            "    aptos-sdk-cli move test --named-addresses {}=0x42",
            args.named_address
        );
    }

    Ok(())
}

// =============================================================================
// Compile command
// =============================================================================

fn cmd_compile(args: &CompileArgs, global: &GlobalOpts) -> Result<()> {
    let package_dir = args
        .package_dir
        .canonicalize()
        .unwrap_or(args.package_dir.clone());

    if !package_dir.join("Move.toml").exists() {
        anyhow::bail!(
            "No Move.toml found in {}. Is this a Move package directory?",
            package_dir.display()
        );
    }

    let mut cmd_args = vec!["move", "compile"];

    if args.save_metadata {
        cmd_args.push("--save-metadata");
    }

    // Build named-addresses string
    let named_addr_str = args.named_addresses.join(",");
    if !args.named_addresses.is_empty() {
        cmd_args.push("--named-addresses");
        cmd_args.push(&named_addr_str);
    }

    if !global.json {
        output::print_header("Compiling Move package");
        println!("  Directory: {}", package_dir.display());
        println!();
    }

    let success = run_aptos_cmd(&cmd_args, &package_dir)?;

    if global.json {
        output::print_json(&serde_json::json!({
            "success": success,
            "package_dir": package_dir.display().to_string(),
        }))?;
    } else if success {
        println!();
        output::print_success("Compilation succeeded");

        // Show what was generated
        let build_dir = package_dir.join("build");
        if build_dir.exists()
            && let Ok(entries) = std::fs::read_dir(&build_dir)
        {
            let packages: Vec<_> = entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_ok_and(|ft| ft.is_dir()))
                .collect();
            for pkg in &packages {
                let pkg_path = pkg.path();
                let modules_dir = pkg_path.join("bytecode_modules");
                if modules_dir.exists()
                    && let Ok(modules) = std::fs::read_dir(&modules_dir)
                {
                    let mv_files: Vec<_> = modules
                        .filter_map(|e| e.ok())
                        .filter(|e| e.path().extension().is_some_and(|ext| ext == "mv"))
                        .collect();
                    println!(
                        "  Package '{}': {} module(s) compiled",
                        pkg.file_name().to_string_lossy(),
                        mv_files.len()
                    );
                    for mv in &mv_files {
                        println!("    - {}", mv.file_name().to_string_lossy());
                    }
                }
                if pkg_path.join("package-metadata.bcs").exists() {
                    println!("  Metadata saved (ready for publishing)");
                }
            }
        }
    } else {
        eprintln!("\nCompilation failed. Check the errors above.");
        std::process::exit(1);
    }

    Ok(())
}

// =============================================================================
// Test command
// =============================================================================

fn cmd_test(args: &TestArgs, global: &GlobalOpts) -> Result<()> {
    let package_dir = args
        .package_dir
        .canonicalize()
        .unwrap_or(args.package_dir.clone());

    if !package_dir.join("Move.toml").exists() {
        anyhow::bail!(
            "No Move.toml found in {}. Is this a Move package directory?",
            package_dir.display()
        );
    }

    let mut cmd_args = vec!["move", "test"];

    if let Some(filter) = &args.filter {
        cmd_args.push("--filter");
        cmd_args.push(filter);
    }

    let named_addr_str = args.named_addresses.join(",");
    if !args.named_addresses.is_empty() {
        cmd_args.push("--named-addresses");
        cmd_args.push(&named_addr_str);
    }

    if !global.json {
        output::print_header("Running Move tests");
        println!("  Directory: {}", package_dir.display());
        if let Some(f) = &args.filter {
            println!("  Filter: {f}");
        }
        println!();
    }

    let success = run_aptos_cmd(&cmd_args, &package_dir)?;

    if global.json {
        output::print_json(&serde_json::json!({
            "success": success,
            "package_dir": package_dir.display().to_string(),
        }))?;
    } else if success {
        println!();
        output::print_success("All tests passed");
    } else {
        eprintln!("\nSome tests failed. Check the output above.");
        std::process::exit(1);
    }

    Ok(())
}

// =============================================================================
// View command
// =============================================================================

async fn cmd_view(args: &ViewArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;

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

// =============================================================================
// Run command
// =============================================================================

async fn cmd_run(args: &RunArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;
    let account = common::load_account(&args.private_key, &args.key_type)?;

    let type_args: Vec<TypeTag> = args
        .type_args
        .iter()
        .map(|t| TypeTag::from_str_strict(t).context(format!("invalid type argument: {t}")))
        .collect::<Result<_>>()?;

    let bcs_args: Vec<Vec<u8>> = args
        .args
        .iter()
        .map(|a| common::parse_bcs_arg(a))
        .collect::<Result<_>>()?;

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

// =============================================================================
// Publish command
// =============================================================================

async fn cmd_publish(args: &PublishArgs, global: &GlobalOpts) -> Result<()> {
    let aptos = global.build_client()?;
    let account = common::load_account(&args.private_key, &args.key_type)?;

    let package_dir = std::path::Path::new(&args.package_dir);

    let metadata_path = package_dir.join("package-metadata.bcs");
    let metadata = std::fs::read(&metadata_path)
        .context(format!("failed to read {}", metadata_path.display()))?;

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
             Run `aptos-sdk-cli move compile` first.",
            modules_dir.display()
        );
    }

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

// =============================================================================
// Build + Publish command
// =============================================================================

async fn cmd_build_publish(args: &BuildPublishArgs, global: &GlobalOpts) -> Result<()> {
    let package_dir = args
        .package_dir
        .canonicalize()
        .unwrap_or(args.package_dir.clone());

    if !package_dir.join("Move.toml").exists() {
        anyhow::bail!(
            "No Move.toml found in {}. Is this a Move package directory?",
            package_dir.display()
        );
    }

    // Step 1: Compile
    if !global.json {
        output::print_header("Step 1: Compiling Move package");
        println!("  Directory: {}", package_dir.display());
        println!();
    }

    let mut compile_args = vec!["move", "compile", "--save-metadata"];

    let named_addr_str = args.named_addresses.join(",");
    if !args.named_addresses.is_empty() {
        compile_args.push("--named-addresses");
        compile_args.push(&named_addr_str);
    }

    let success = run_aptos_cmd(&compile_args, &package_dir)?;
    if !success {
        anyhow::bail!("Compilation failed. Fix errors before publishing.");
    }

    if !global.json {
        println!();
        output::print_success("Compilation succeeded");
    }

    // Step 2: Find the build output
    let build_dir = package_dir.join("build");
    let build_package = find_build_package(&build_dir)?;

    if !global.json {
        output::print_header("Step 2: Publishing to chain");
    }

    // Step 3: Publish using the SDK
    let publish_args = PublishArgs {
        private_key: args.private_key.clone(),
        key_type: args.key_type.clone(),
        package_dir: build_package.display().to_string(),
    };

    cmd_publish(&publish_args, global).await
}

/// Find the build output package directory.
fn find_build_package(build_dir: &std::path::Path) -> Result<PathBuf> {
    if !build_dir.exists() {
        anyhow::bail!("Build directory not found at {}", build_dir.display());
    }

    let entries: Vec<_> = std::fs::read_dir(build_dir)
        .context("failed to read build directory")?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|ft| ft.is_dir()))
        .filter(|e| e.path().join("package-metadata.bcs").exists())
        .collect();

    match entries.len() {
        0 => anyhow::bail!(
            "No compiled package found in {}. Make sure compilation succeeded.",
            build_dir.display()
        ),
        1 => Ok(entries[0].path()),
        _ => {
            // Multiple packages - pick the first one with bytecode
            for entry in &entries {
                let modules = entry.path().join("bytecode_modules");
                if modules.exists() {
                    return Ok(entry.path());
                }
            }
            Ok(entries[0].path())
        }
    }
}

// =============================================================================
// Inspect command
// =============================================================================

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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_version
    // -----------------------------------------------------------------------

    #[test]
    fn parse_version_standard() {
        assert_eq!(parse_version("aptos 7.14.2"), Some((7, 14, 2)));
    }

    #[test]
    fn parse_version_with_newline() {
        assert_eq!(parse_version("aptos 7.14.2\n"), Some((7, 14, 2)));
    }

    #[test]
    fn parse_version_just_numbers() {
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
    }

    #[test]
    fn parse_version_large_numbers() {
        assert_eq!(parse_version("aptos 10.200.3000"), Some((10, 200, 3000)));
    }

    #[test]
    fn parse_version_zero() {
        assert_eq!(parse_version("aptos 0.0.0"), Some((0, 0, 0)));
    }

    #[test]
    fn parse_version_missing_patch() {
        assert_eq!(parse_version("aptos 7.14"), None);
    }

    #[test]
    fn parse_version_empty() {
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn parse_version_garbage() {
        assert_eq!(parse_version("not a version"), None);
    }

    #[test]
    fn parse_version_partial() {
        assert_eq!(parse_version("aptos "), None);
    }

    #[test]
    fn parse_version_non_numeric() {
        assert_eq!(parse_version("aptos a.b.c"), None);
    }

    #[test]
    fn parse_version_comparison() {
        let v1 = parse_version("aptos 7.9.0").unwrap();
        let v2 = parse_version("aptos 7.14.2").unwrap();
        assert!(v2 > v1, "7.14.2 should be greater than 7.9.0");
    }
}
