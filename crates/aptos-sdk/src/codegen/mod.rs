//! Code generation for Move modules.
//!
//! This module provides utilities to generate type-safe Rust code from Move module ABIs.
//!
//! # Overview
//!
//! The code generator can create:
//! - Entry function wrappers with typed arguments
//! - View function wrappers with typed returns
//! - Struct definitions matching Move structs
//! - Event types for parsing on-chain events
//!
//! # Runtime Code Generation
//!
//! ```rust,ignore
//! use aptos_sdk::codegen::{ModuleGenerator, GeneratorConfig};
//! use aptos_sdk::api::response::MoveModuleABI;
//!
//! // Load ABI from file or API
//! let abi_json = std::fs::read_to_string("my_module_abi.json")?;
//! let abi: MoveModuleABI = serde_json::from_str(&abi_json)?;
//!
//! // Generate code
//! let generator = ModuleGenerator::new(&abi, GeneratorConfig::default());
//! let code = generator.generate()?;
//!
//! // Write to file
//! std::fs::write("src/generated/my_module.rs", code)?;
//! ```
//!
//! # Build-Time Code Generation
//!
//! For compile-time code generation, use the `build_helper` module in your `build.rs`:
//!
//! ```rust,ignore
//! // build.rs
//! use aptos_sdk::codegen::build_helper;
//!
//! fn main() {
//!     // Generate from local ABI files
//!     build_helper::generate_from_abi(
//!         "abi/my_module.json",
//!         "src/generated/",
//!     ).expect("code generation failed");
//!
//!     // Or generate from a directory of ABIs
//!     build_helper::generate_from_directory(
//!         "abi/",
//!         "src/generated/",
//!     ).expect("code generation failed");
//!
//!     println!("cargo:rerun-if-changed=abi/");
//! }
//! ```
//!
//! # With Move Source (Better Parameter Names)
//!
//! ```rust,ignore
//! use aptos_sdk::codegen::{ModuleGenerator, GeneratorConfig, MoveSourceParser};
//!
//! // Load ABI
//! let abi: MoveModuleABI = serde_json::from_str(&abi_json)?;
//!
//! // Parse Move source for parameter names and docs
//! let move_source = std::fs::read_to_string("sources/my_module.move")?;
//! let source_info = MoveSourceParser::parse(&move_source);
//!
//! // Generate with enriched information
//! let generator = ModuleGenerator::new(&abi, GeneratorConfig::default())
//!     .with_source_info(source_info);
//! let code = generator.generate()?;
//! ```
//!
//! # CLI Usage
//!
//! ```bash
//! # Generate from a local ABI file
//! aptos-codegen --input my_module_abi.json --output src/generated/
//!
//! # Generate from on-chain module with Move source
//! aptos-codegen --module 0x1::coin --network testnet --source coin.move --output src/
//!
//! # Generate from a directory of ABIs
//! aptos-codegen --input-dir abi/ --output src/generated/
//! ```

pub mod build_helper;
mod generator;
mod move_parser;
mod types;

pub use generator::{GeneratorConfig, ModuleGenerator};
pub use move_parser::{
    EnrichedFunctionInfo, EnrichedParam, MoveFunctionInfo, MoveModuleInfo, MoveSourceParser,
    MoveStructInfo,
};
pub use types::{MoveTypeMapper, RustType, to_pascal_case, to_snake_case};
