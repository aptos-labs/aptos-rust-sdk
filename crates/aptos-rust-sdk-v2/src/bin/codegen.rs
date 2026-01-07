//! Code generation CLI for Aptos Move modules.
//!
//! This binary generates type-safe Rust bindings from Move module ABIs.
//!
//! # Usage
//!
//! ```bash
//! # Generate from a local ABI JSON file
//! aptos-codegen --input module_abi.json --output src/generated/
//!
//! # Generate from an on-chain module
//! aptos-codegen --module 0x1::coin --network testnet --output src/generated/
//!
//! # Generate with Move source for better parameter names
//! aptos-codegen --input abi.json --source my_module.move --output src/
//!
//! # Generate with custom module name
//! aptos-codegen --input abi.json --output src/ --module-name my_module
//! ```

use aptos_rust_sdk_v2::{
    api::response::MoveModuleABI,
    codegen::{GeneratorConfig, ModuleGenerator, MoveSourceParser},
    Aptos, AptosConfig,
};
use clap::{Parser, ValueEnum};
use std::{fs, path::PathBuf};

#[derive(Debug, Clone, ValueEnum)]
enum Network {
    Mainnet,
    Testnet,
    Devnet,
    Local,
}

impl Network {
    fn to_config(&self) -> AptosConfig {
        match self {
            Network::Mainnet => AptosConfig::mainnet(),
            Network::Testnet => AptosConfig::testnet(),
            Network::Devnet => AptosConfig::devnet(),
            Network::Local => AptosConfig::local(),
        }
    }
}

/// Generate type-safe Rust bindings from Move module ABIs.
#[derive(Parser, Debug)]
#[command(name = "aptos-codegen")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to a local ABI JSON file
    #[arg(short, long, conflicts_with_all = ["module", "network"])]
    input: Option<PathBuf>,

    /// On-chain module to fetch (format: address::module_name)
    #[arg(short, long, requires = "network")]
    module: Option<String>,

    /// Network to fetch the module from
    #[arg(short, long, value_enum)]
    network: Option<Network>,

    /// Path to Move source file for parameter names and documentation
    #[arg(short, long)]
    source: Option<PathBuf>,

    /// Output directory for generated code
    #[arg(short, long, default_value = ".")]
    output: PathBuf,

    /// Custom module name for the generated code
    #[arg(long)]
    module_name: Option<String>,

    /// Generate synchronous functions instead of async
    #[arg(long)]
    sync: bool,

    /// Skip entry function generation
    #[arg(long)]
    no_entry_functions: bool,

    /// Skip view function generation
    #[arg(long)]
    no_view_functions: bool,

    /// Skip struct generation
    #[arg(long)]
    no_structs: bool,

    /// Use builder pattern for entry functions
    #[arg(long)]
    builder: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Load the ABI
    let abi = if let Some(input_path) = &args.input {
        // Load from file
        println!("Loading ABI from: {}", input_path.display());
        let content = fs::read_to_string(input_path)?;
        serde_json::from_str::<MoveModuleABI>(&content)?
    } else if let Some(module_str) = &args.module {
        // Fetch from network
        let network = args.network.as_ref().unwrap();
        println!(
            "Fetching module {} from {:?}...",
            module_str, network
        );

        let config = network.to_config();
        let aptos = Aptos::new(config)?;

        // Parse module ID
        let parts: Vec<&str> = module_str.split("::").collect();
        if parts.len() != 2 {
            anyhow::bail!(
                "Invalid module format. Expected 'address::module_name', got: {}",
                module_str
            );
        }

        let address = aptos_rust_sdk_v2::types::AccountAddress::from_hex(parts[0])?;
        let module_name = parts[1];

        // Fetch module
        let response = aptos.fullnode().get_account_module(address, module_name).await?;
        
        response
            .data
            .abi
            .ok_or_else(|| anyhow::anyhow!("Module {} does not have ABI information", module_str))?
    } else {
        anyhow::bail!("Either --input or --module must be specified");
    };

    println!("Generating code for module: {}::{}", abi.address, abi.name);

    // Parse Move source if provided
    let source_info = if let Some(source_path) = &args.source {
        println!("Parsing Move source: {}", source_path.display());
        let source_content = fs::read_to_string(source_path)?;
        let info = MoveSourceParser::parse(&source_content);
        println!(
            "  Found {} functions, {} structs",
            info.functions.len(),
            info.structs.len()
        );
        Some(info)
    } else {
        None
    };

    // Configure generator
    let mut config = GeneratorConfig::new()
        .with_entry_functions(!args.no_entry_functions)
        .with_view_functions(!args.no_view_functions)
        .with_structs(!args.no_structs)
        .with_async(!args.sync)
        .with_builder_pattern(args.builder);

    if let Some(name) = &args.module_name {
        config = config.with_module_name(name);
    }

    // Generate code
    let mut generator = ModuleGenerator::new(&abi, config);
    if let Some(info) = source_info {
        generator = generator.with_source_info(info);
    }
    let code = generator.generate()?;

    // Write output
    let output_filename = format!("{}.rs", args.module_name.as_deref().unwrap_or(&abi.name));
    let output_path = args.output.join(&output_filename);

    // Create output directory if needed
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&output_path, &code)?;
    println!("Generated: {}", output_path.display());

    // Print summary
    let entry_count = abi.exposed_functions.iter().filter(|f| f.is_entry).count();
    let view_count = abi.exposed_functions.iter().filter(|f| f.is_view).count();
    let struct_count = abi.structs.len();

    println!();
    println!("Summary:");
    println!("  - Entry functions: {}", entry_count);
    println!("  - View functions: {}", view_count);
    println!("  - Structs: {}", struct_count);

    if args.source.is_some() {
        println!("  - (Parameter names enriched from Move source)");
    }

    Ok(())
}
