//! Build script helper for code generation.
//!
//! This module provides utilities for generating code at compile time via `build.rs`.
//!
//! # Example
//!
//! Add to your `build.rs`:
//!
//! ```rust,ignore
//! use aptos_rust_sdk_v2::codegen::build_helper;
//!
//! fn main() {
//!     // Generate from a local ABI file
//!     build_helper::generate_from_abi(
//!         "abi/my_module.json",
//!         "src/generated/",
//!     ).expect("code generation failed");
//!
//!     // Generate from multiple modules
//!     build_helper::generate_from_abis(&[
//!         "abi/coin.json",
//!         "abi/token.json",
//!     ], "src/generated/").expect("code generation failed");
//!
//!     // Rerun if ABI files change
//!     println!("cargo:rerun-if-changed=abi/");
//! }
//! ```
//!
//! # Directory Structure
//!
//! ```text
//! my_project/
//! ├── build.rs
//! ├── abi/
//! │   ├── my_module.json
//! │   └── another_module.json
//! └── src/
//!     └── generated/
//!         ├── mod.rs          (auto-generated)
//!         ├── my_module.rs
//!         └── another_module.rs
//! ```

use crate::api::response::MoveModuleABI;
use crate::codegen::{GeneratorConfig, ModuleGenerator, MoveSourceParser};
use crate::error::{AptosError, AptosResult};
use std::fs;
use std::path::Path;

/// Configuration for build-time code generation.
#[derive(Debug, Clone)]
pub struct BuildConfig {
    /// Generator configuration.
    pub generator_config: GeneratorConfig,
    /// Whether to generate a `mod.rs` file.
    pub generate_mod_file: bool,
    /// Whether to print build instructions to cargo.
    pub print_cargo_instructions: bool,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            generator_config: GeneratorConfig::default(),
            generate_mod_file: true,
            print_cargo_instructions: true,
        }
    }
}

impl BuildConfig {
    /// Creates a new build configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether to generate a mod.rs file.
    #[must_use]
    pub fn with_mod_file(mut self, enabled: bool) -> Self {
        self.generate_mod_file = enabled;
        self
    }

    /// Sets the generator configuration.
    #[must_use]
    pub fn with_generator_config(mut self, config: GeneratorConfig) -> Self {
        self.generator_config = config;
        self
    }

    /// Sets whether to print cargo instructions.
    #[must_use]
    pub fn with_cargo_instructions(mut self, enabled: bool) -> Self {
        self.print_cargo_instructions = enabled;
        self
    }
}

/// Generates Rust code from a single ABI file.
///
/// # Arguments
///
/// * `abi_path` - Path to the ABI JSON file
/// * `output_dir` - Directory where generated code will be written
///
/// # Errors
///
/// Returns an error if:
/// * The ABI file cannot be read
/// * The ABI JSON cannot be parsed
/// * Code generation fails
/// * The output directory cannot be created
/// * The output file cannot be written
///
/// # Example
///
/// ```rust,ignore
/// build_helper::generate_from_abi("abi/coin.json", "src/generated/")?;
/// ```
pub fn generate_from_abi(
    abi_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> AptosResult<()> {
    generate_from_abi_with_config(abi_path, output_dir, BuildConfig::default())
}

/// Generates Rust code from a single ABI file with custom configuration.
///
/// # Errors
///
/// Returns an error if:
/// * The ABI file cannot be read
/// * The ABI JSON cannot be parsed
/// * Code generation fails
/// * The output directory cannot be created
/// * The output file cannot be written
pub fn generate_from_abi_with_config(
    abi_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    config: BuildConfig,
) -> AptosResult<()> {
    let abi_path = abi_path.as_ref();
    let output_dir = output_dir.as_ref();

    // Read and parse ABI
    let abi_content = fs::read_to_string(abi_path).map_err(|e| {
        AptosError::Config(format!(
            "Failed to read ABI file {}: {}",
            abi_path.display(),
            e
        ))
    })?;

    let abi: MoveModuleABI = serde_json::from_str(&abi_content)
        .map_err(|e| AptosError::Config(format!("Failed to parse ABI JSON: {e}")))?;

    // Generate code
    let generator = ModuleGenerator::new(&abi, config.generator_config);
    let code = generator.generate()?;

    // Create output directory
    fs::create_dir_all(output_dir)
        .map_err(|e| AptosError::Config(format!("Failed to create output directory: {e}")))?;

    // Write output file
    let output_filename = format!("{}.rs", abi.name);
    let output_path = output_dir.join(&output_filename);

    fs::write(&output_path, &code)
        .map_err(|e| AptosError::Config(format!("Failed to write output file: {e}")))?;

    if config.print_cargo_instructions {
        println!("cargo:rerun-if-changed={}", abi_path.display());
    }

    Ok(())
}

/// Generates Rust code from multiple ABI files.
///
/// Also generates a `mod.rs` file that re-exports all generated modules.
///
/// # Arguments
///
/// * `abi_paths` - Paths to ABI JSON files
/// * `output_dir` - Directory where generated code will be written
///
/// # Errors
///
/// Returns an error if:
/// * Any ABI file cannot be read
/// * Any ABI JSON cannot be parsed
/// * Code generation fails for any module
/// * The output directory cannot be created
/// * Any output file cannot be written
/// * The `mod.rs` file cannot be written
///
/// # Example
///
/// ```rust,ignore
/// build_helper::generate_from_abis(&[
///     "abi/coin.json",
///     "abi/token.json",
/// ], "src/generated/")?;
/// ```
pub fn generate_from_abis(
    abi_paths: &[impl AsRef<Path>],
    output_dir: impl AsRef<Path>,
) -> AptosResult<()> {
    generate_from_abis_with_config(abi_paths, output_dir, &BuildConfig::default())
}

/// Generates Rust code from multiple ABI files with custom configuration.
///
/// # Errors
///
/// Returns an error if:
/// * Any ABI file cannot be read
/// * Any ABI JSON cannot be parsed
/// * Code generation fails for any module
/// * The output directory cannot be created
/// * Any output file cannot be written
/// * The `mod.rs` file cannot be written (if enabled)
pub fn generate_from_abis_with_config(
    abi_paths: &[impl AsRef<Path>],
    output_dir: impl AsRef<Path>,
    config: &BuildConfig,
) -> AptosResult<()> {
    let output_dir = output_dir.as_ref();
    let mut module_names = Vec::new();

    // Generate code for each ABI
    for abi_path in abi_paths {
        let abi_path = abi_path.as_ref();

        let abi_content = fs::read_to_string(abi_path).map_err(|e| {
            AptosError::Config(format!(
                "Failed to read ABI file {}: {}",
                abi_path.display(),
                e
            ))
        })?;

        let abi: MoveModuleABI = serde_json::from_str(&abi_content).map_err(|e| {
            AptosError::Config(format!(
                "Failed to parse ABI JSON from {}: {}",
                abi_path.display(),
                e
            ))
        })?;

        let generator = ModuleGenerator::new(&abi, config.generator_config.clone());
        let code = generator.generate()?;

        // Create output directory
        fs::create_dir_all(output_dir)
            .map_err(|e| AptosError::Config(format!("Failed to create output directory: {e}")))?;

        // Write output file
        let output_filename = format!("{}.rs", abi.name);
        let output_path = output_dir.join(&output_filename);

        fs::write(&output_path, &code)
            .map_err(|e| AptosError::Config(format!("Failed to write output file: {e}")))?;

        module_names.push(abi.name);

        if config.print_cargo_instructions {
            println!("cargo:rerun-if-changed={}", abi_path.display());
        }
    }

    // Generate mod.rs
    if config.generate_mod_file && !module_names.is_empty() {
        let mod_content = generate_mod_file(&module_names);
        let mod_path = output_dir.join("mod.rs");

        fs::write(&mod_path, mod_content)
            .map_err(|e| AptosError::Config(format!("Failed to write mod.rs: {e}")))?;
    }

    Ok(())
}

/// Generates Rust code from an ABI file with Move source for better names.
///
/// # Arguments
///
/// * `abi_path` - Path to the ABI JSON file
/// * `source_path` - Path to the Move source file
/// * `output_dir` - Directory where generated code will be written
///
/// # Errors
///
/// Returns an error if:
/// * The ABI file cannot be read
/// * The ABI JSON cannot be parsed
/// * The Move source file cannot be read
/// * Code generation fails
/// * The output directory cannot be created
/// * The output file cannot be written
pub fn generate_from_abi_with_source(
    abi_path: impl AsRef<Path>,
    source_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> AptosResult<()> {
    let abi_path = abi_path.as_ref();
    let source_path = source_path.as_ref();
    let output_dir = output_dir.as_ref();

    // Read and parse ABI
    let abi_content = fs::read_to_string(abi_path)
        .map_err(|e| AptosError::Config(format!("Failed to read ABI file: {e}")))?;

    let abi: MoveModuleABI = serde_json::from_str(&abi_content)
        .map_err(|e| AptosError::Config(format!("Failed to parse ABI JSON: {e}")))?;

    // Read and parse Move source
    let source_content = fs::read_to_string(source_path)
        .map_err(|e| AptosError::Config(format!("Failed to read Move source: {e}")))?;

    let source_info = MoveSourceParser::parse(&source_content);

    // Generate code
    let generator =
        ModuleGenerator::new(&abi, GeneratorConfig::default()).with_source_info(source_info);
    let code = generator.generate()?;

    // Create output directory
    fs::create_dir_all(output_dir)
        .map_err(|e| AptosError::Config(format!("Failed to create output directory: {e}")))?;

    // Write output file
    let output_filename = format!("{}.rs", abi.name);
    let output_path = output_dir.join(&output_filename);

    fs::write(&output_path, &code)
        .map_err(|e| AptosError::Config(format!("Failed to write output file: {e}")))?;

    println!("cargo:rerun-if-changed={}", abi_path.display());
    println!("cargo:rerun-if-changed={}", source_path.display());

    Ok(())
}

/// Generates a mod.rs file for the given module names.
fn generate_mod_file(module_names: &[String]) -> String {
    use std::fmt::Write as _;
    let mut content = String::new();
    let _ = writeln!(&mut content, "//! Auto-generated module exports.");
    let _ = writeln!(&mut content, "//!");
    let _ = writeln!(
        &mut content,
        "//! This file was auto-generated by aptos-rust-sdk-v2 codegen."
    );
    let _ = writeln!(&mut content, "//! Do not edit manually.");
    let _ = writeln!(&mut content);

    for name in module_names {
        let _ = writeln!(&mut content, "pub mod {name};");
    }
    let _ = writeln!(&mut content);

    // Re-export all modules
    let _ = writeln!(&mut content, "// Re-exports for convenience");
    for name in module_names {
        let _ = writeln!(&mut content, "pub use {name}::*;");
    }

    content
}

/// Scans a directory for ABI files and generates code for all of them.
///
/// # Arguments
///
/// * `abi_dir` - Directory containing ABI JSON files
/// * `output_dir` - Directory where generated code will be written
///
/// # Errors
///
/// Returns an error if:
/// * The directory cannot be read
/// * No JSON files are found in the directory
/// * Any ABI file cannot be read or parsed
/// * Code generation fails for any module
/// * The output directory cannot be created
/// * Any output file cannot be written
///
/// # Example
///
/// ```rust,ignore
/// build_helper::generate_from_directory("abi/", "src/generated/")?;
/// ```
pub fn generate_from_directory(
    abi_dir: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> AptosResult<()> {
    let abi_dir = abi_dir.as_ref();

    let entries = fs::read_dir(abi_dir)
        .map_err(|e| AptosError::Config(format!("Failed to read ABI directory: {e}")))?;

    let abi_paths: Vec<_> = entries
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .map(|e| e.path())
        .collect();

    if abi_paths.is_empty() {
        return Err(AptosError::Config(format!(
            "No JSON files found in {}",
            abi_dir.display()
        )));
    }

    // Convert PathBuf to Path references for the function
    let path_refs: Vec<&Path> = abi_paths.iter().map(std::path::PathBuf::as_path).collect();
    generate_from_abis(&path_refs, output_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn sample_abi_json() -> &'static str {
        r#"{
            "address": "0x1",
            "name": "coin",
            "exposed_functions": [
                {
                    "name": "transfer",
                    "visibility": "public",
                    "is_entry": true,
                    "is_view": false,
                    "generic_type_params": [{"constraints": []}],
                    "params": ["&signer", "address", "u64"],
                    "return": []
                }
            ],
            "structs": []
        }"#
    }

    #[test]
    fn test_generate_from_abi() {
        let temp_dir = TempDir::new().unwrap();
        let abi_path = temp_dir.path().join("coin.json");
        let output_dir = temp_dir.path().join("generated");

        // Write sample ABI
        let mut file = fs::File::create(&abi_path).unwrap();
        file.write_all(sample_abi_json().as_bytes()).unwrap();

        // Generate
        let config = BuildConfig::new().with_cargo_instructions(false);
        generate_from_abi_with_config(&abi_path, &output_dir, config).unwrap();

        // Verify output exists
        let output_path = output_dir.join("coin.rs");
        assert!(output_path.exists());

        // Verify content
        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("Generated Rust bindings"));
        assert!(content.contains("pub fn transfer"));
    }

    #[test]
    fn test_generate_mod_file() {
        let modules = vec!["coin".to_string(), "token".to_string()];
        let mod_content = generate_mod_file(&modules);

        assert!(mod_content.contains("pub mod coin;"));
        assert!(mod_content.contains("pub mod token;"));
        assert!(mod_content.contains("pub use coin::*;"));
        assert!(mod_content.contains("pub use token::*;"));
    }

    #[test]
    fn test_build_config() {
        let config = BuildConfig::new()
            .with_mod_file(false)
            .with_cargo_instructions(false);

        assert!(!config.generate_mod_file);
        assert!(!config.print_cargo_instructions);
    }
}
