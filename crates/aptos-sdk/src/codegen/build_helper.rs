//! Build script helper for code generation.
//!
//! This module provides utilities for generating code at compile time via `build.rs`.
//!
//! # Example
//!
//! Add to your `build.rs`:
//!
//! ```rust,ignore
//! use aptos_sdk::codegen::build_helper;
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

/// Returns true if `name` is a Rust keyword that cannot be used as a module name.
fn is_rust_keyword(name: &str) -> bool {
    matches!(
        name,
        "as" | "break"
            | "const"
            | "continue"
            | "crate"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "pub"
            | "ref"
            | "return"
            | "self"
            | "Self"
            | "static"
            | "struct"
            | "super"
            | "trait"
            | "true"
            | "type"
            | "unsafe"
            | "use"
            | "where"
            | "while"
            | "async"
            | "await"
            | "dyn"
    )
}

/// Validates that a module name is a safe Rust identifier (no path traversal, injection, or keywords).
///
/// # Security
///
/// This prevents:
/// - Path traversal attacks via names like `../../../tmp/evil`
/// - Invalid `pub mod` declarations in generated mod.rs (e.g., `pub mod fn;`)
fn validate_module_name(name: &str) -> AptosResult<()> {
    if name.is_empty() {
        return Err(AptosError::Config(
            "module name cannot be empty".to_string(),
        ));
    }

    // Must be a valid Rust identifier: starts with letter or underscore,
    // contains only alphanumeric or underscore characters
    let mut chars = name.chars();
    let first = chars.next().unwrap(); // safe: name is non-empty
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(AptosError::Config(format!(
            "invalid module name '{name}': must start with a letter or underscore"
        )));
    }

    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(AptosError::Config(format!(
            "invalid module name '{name}': must contain only ASCII alphanumeric characters or underscores"
        )));
    }

    if is_rust_keyword(name) {
        return Err(AptosError::Config(format!(
            "invalid module name '{name}': Rust keywords cannot be used as module names"
        )));
    }

    Ok(())
}

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

    // SECURITY: Validate module name to prevent path traversal
    validate_module_name(&abi.name)?;

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

        // SECURITY: Validate module name to prevent path traversal
        validate_module_name(&abi.name)?;

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

    // SECURITY: Validate module name to prevent path traversal
    validate_module_name(&abi.name)?;

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
        "//! This file was auto-generated by aptos-sdk codegen."
    );
    let _ = writeln!(&mut content, "//! Do not edit manually.");
    let _ = writeln!(&mut content);

    for name in module_names {
        // SECURITY: Module names are validated by validate_module_name() before reaching here,
        // but double-check they are safe identifiers to prevent code injection in mod.rs
        debug_assert!(
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "module name should have been validated"
        );
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

    /// Builds a minimal, valid ABI JSON string for a module with the given name.
    fn abi_json_with_name(name: &str) -> String {
        format!(
            r#"{{
                "address": "0x1",
                "name": "{name}",
                "exposed_functions": [
                    {{
                        "name": "transfer",
                        "visibility": "public",
                        "is_entry": true,
                        "is_view": false,
                        "generic_type_params": [{{"constraints": []}}],
                        "params": ["&signer", "address", "u64"],
                        "return": []
                    }}
                ],
                "structs": []
            }}"#
        )
    }

    /// Writes `contents` to `path`, creating parent dirs as needed.
    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = fs::File::create(path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
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

    #[test]
    fn test_build_config_defaults() {
        let config = BuildConfig::default();
        assert!(config.generate_mod_file);
        assert!(config.print_cargo_instructions);
        // Debug/Clone are derived; exercise them so they are covered.
        let cloned = config.clone();
        assert!(cloned.generate_mod_file);
        assert!(format!("{config:?}").contains("BuildConfig"));
    }

    #[test]
    fn test_build_config_with_generator_config() {
        let gen_config = GeneratorConfig::default();
        let config = BuildConfig::new().with_generator_config(gen_config);
        // The builder returns Self; the generator config field is populated.
        assert!(config.generate_mod_file);
    }

    // --- validate_module_name ---------------------------------------------

    #[test]
    fn test_validate_module_name_valid() {
        assert!(validate_module_name("coin").is_ok());
        assert!(validate_module_name("_private").is_ok());
        assert!(validate_module_name("token_v2").is_ok());
        assert!(validate_module_name("MyModule").is_ok());
        assert!(validate_module_name("a1b2c3").is_ok());
    }

    #[test]
    fn test_validate_module_name_empty() {
        let err = validate_module_name("").unwrap_err();
        assert!(matches!(err, AptosError::Config(ref m) if m.contains("empty")));
    }

    #[test]
    fn test_validate_module_name_bad_first_char() {
        // Starts with a digit.
        let err = validate_module_name("1coin").unwrap_err();
        assert!(matches!(err, AptosError::Config(ref m) if m.contains("must start with")));
        // Starts with a non-alphanumeric character (path traversal attempt).
        let err = validate_module_name("../evil").unwrap_err();
        assert!(matches!(err, AptosError::Config(ref m) if m.contains("must start with")));
    }

    #[test]
    fn test_validate_module_name_bad_inner_char() {
        // Contains a path separator.
        let err = validate_module_name("coin/evil").unwrap_err();
        assert!(matches!(err, AptosError::Config(ref m) if m.contains("only ASCII")));
        // Contains a non-ASCII character.
        let err = validate_module_name("café").unwrap_err();
        assert!(matches!(err, AptosError::Config(ref m) if m.contains("only ASCII")));
    }

    #[test]
    fn test_validate_module_name_keyword() {
        for kw in ["fn", "mod", "struct", "type", "use", "async", "dyn", "move"] {
            let err = validate_module_name(kw).unwrap_err();
            assert!(
                matches!(err, AptosError::Config(ref m) if m.contains("keyword")),
                "expected keyword rejection for {kw}"
            );
        }
    }

    #[test]
    fn test_is_rust_keyword() {
        assert!(is_rust_keyword("fn"));
        assert!(is_rust_keyword("Self"));
        assert!(is_rust_keyword("await"));
        assert!(!is_rust_keyword("coin"));
        assert!(!is_rust_keyword("self_ish"));
    }

    // --- generate_from_abi -------------------------------------------------

    #[test]
    fn test_generate_from_abi_default_wrapper() {
        let temp_dir = TempDir::new().unwrap();
        let abi_path = temp_dir.path().join("coin.json");
        let output_dir = temp_dir.path().join("generated");
        write_file(&abi_path, sample_abi_json());

        generate_from_abi(&abi_path, &output_dir).unwrap();

        let content = fs::read_to_string(output_dir.join("coin.rs")).unwrap();
        assert!(content.contains("pub fn transfer"));
    }

    #[test]
    fn test_generate_from_abi_missing_file() {
        let temp_dir = TempDir::new().unwrap();
        let abi_path = temp_dir.path().join("does_not_exist.json");
        let output_dir = temp_dir.path().join("generated");

        let err = generate_from_abi(&abi_path, &output_dir).unwrap_err();
        assert!(matches!(err, AptosError::Config(ref m) if m.contains("Failed to read ABI file")));
    }

    #[test]
    fn test_generate_from_abi_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let abi_path = temp_dir.path().join("bad.json");
        let output_dir = temp_dir.path().join("generated");
        write_file(&abi_path, "{ this is not valid json");

        let err = generate_from_abi(&abi_path, &output_dir).unwrap_err();
        assert!(matches!(err, AptosError::Config(ref m) if m.contains("Failed to parse ABI JSON")));
    }

    #[test]
    fn test_generate_from_abi_rejects_bad_module_name() {
        let temp_dir = TempDir::new().unwrap();
        let abi_path = temp_dir.path().join("evil.json");
        let output_dir = temp_dir.path().join("generated");
        // A path-traversal module name should be rejected before any file is written.
        write_file(&abi_path, &abi_json_with_name("../../evil"));

        let err = generate_from_abi(&abi_path, &output_dir).unwrap_err();
        assert!(matches!(err, AptosError::Config(ref m) if m.contains("must start with")));
        assert!(!output_dir.exists());
    }

    // --- generate_from_abis ------------------------------------------------

    #[test]
    fn test_generate_from_abis_multiple_with_mod_file() {
        let temp_dir = TempDir::new().unwrap();
        let coin_path = temp_dir.path().join("coin.json");
        let token_path = temp_dir.path().join("token.json");
        let output_dir = temp_dir.path().join("generated");
        write_file(&coin_path, &abi_json_with_name("coin"));
        write_file(&token_path, &abi_json_with_name("token"));

        let config = BuildConfig::new().with_cargo_instructions(false);
        generate_from_abis_with_config(&[&coin_path, &token_path], &output_dir, &config).unwrap();

        assert!(output_dir.join("coin.rs").exists());
        assert!(output_dir.join("token.rs").exists());
        let mod_content = fs::read_to_string(output_dir.join("mod.rs")).unwrap();
        assert!(mod_content.contains("pub mod coin;"));
        assert!(mod_content.contains("pub mod token;"));
    }

    #[test]
    fn test_generate_from_abis_no_mod_file_when_disabled() {
        let temp_dir = TempDir::new().unwrap();
        let coin_path = temp_dir.path().join("coin.json");
        let output_dir = temp_dir.path().join("generated");
        write_file(&coin_path, &abi_json_with_name("coin"));

        let config = BuildConfig::new()
            .with_mod_file(false)
            .with_cargo_instructions(false);
        generate_from_abis_with_config(&[&coin_path], &output_dir, &config).unwrap();

        assert!(output_dir.join("coin.rs").exists());
        assert!(!output_dir.join("mod.rs").exists());
    }

    #[test]
    fn test_generate_from_abis_default_wrapper() {
        let temp_dir = TempDir::new().unwrap();
        let coin_path = temp_dir.path().join("coin.json");
        let output_dir = temp_dir.path().join("generated");
        write_file(&coin_path, &abi_json_with_name("coin"));

        generate_from_abis(&[&coin_path], &output_dir).unwrap();
        assert!(output_dir.join("coin.rs").exists());
        // The default config generates a mod.rs.
        assert!(output_dir.join("mod.rs").exists());
    }

    #[test]
    fn test_generate_from_abis_missing_file_errors() {
        let temp_dir = TempDir::new().unwrap();
        let missing = temp_dir.path().join("missing.json");
        let output_dir = temp_dir.path().join("generated");

        let err = generate_from_abis(&[&missing], &output_dir).unwrap_err();
        assert!(matches!(err, AptosError::Config(ref m) if m.contains("Failed to read ABI file")));
    }

    #[test]
    fn test_generate_from_abis_invalid_json_errors() {
        let temp_dir = TempDir::new().unwrap();
        let bad = temp_dir.path().join("bad.json");
        let output_dir = temp_dir.path().join("generated");
        write_file(&bad, "not json");

        let err = generate_from_abis(&[&bad], &output_dir).unwrap_err();
        assert!(
            matches!(err, AptosError::Config(ref m) if m.contains("Failed to parse ABI JSON from"))
        );
    }

    #[test]
    fn test_generate_from_abis_bad_module_name_errors() {
        let temp_dir = TempDir::new().unwrap();
        let evil = temp_dir.path().join("evil.json");
        let output_dir = temp_dir.path().join("generated");
        write_file(&evil, &abi_json_with_name("mod"));

        let err = generate_from_abis(&[&evil], &output_dir).unwrap_err();
        assert!(matches!(err, AptosError::Config(ref m) if m.contains("keyword")));
    }

    #[test]
    fn test_generate_from_abis_empty_input_writes_nothing() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().join("generated");
        let empty: [&Path; 0] = [];

        // No ABIs -> succeeds but produces no mod.rs (module_names is empty).
        generate_from_abis(&empty, &output_dir).unwrap();
        assert!(!output_dir.join("mod.rs").exists());
    }

    // --- generate_from_abi_with_source ------------------------------------

    #[test]
    fn test_generate_from_abi_with_source() {
        let temp_dir = TempDir::new().unwrap();
        let abi_path = temp_dir.path().join("coin.json");
        let source_path = temp_dir.path().join("coin.move");
        let output_dir = temp_dir.path().join("generated");
        write_file(&abi_path, sample_abi_json());
        write_file(
            &source_path,
            "module 0x1::coin {\n\
             /// Transfers coins.\n\
             public entry fun transfer(from: &signer, to: address, amount: u64) {}\n\
             }\n",
        );

        generate_from_abi_with_source(&abi_path, &source_path, &output_dir).unwrap();

        let content = fs::read_to_string(output_dir.join("coin.rs")).unwrap();
        assert!(content.contains("pub fn transfer"));
    }

    #[test]
    fn test_generate_from_abi_with_source_missing_abi() {
        let temp_dir = TempDir::new().unwrap();
        let abi_path = temp_dir.path().join("missing.json");
        let source_path = temp_dir.path().join("coin.move");
        let output_dir = temp_dir.path().join("generated");
        write_file(&source_path, "module 0x1::coin {}");

        let err = generate_from_abi_with_source(&abi_path, &source_path, &output_dir).unwrap_err();
        assert!(matches!(err, AptosError::Config(ref m) if m.contains("Failed to read ABI file")));
    }

    #[test]
    fn test_generate_from_abi_with_source_missing_source() {
        let temp_dir = TempDir::new().unwrap();
        let abi_path = temp_dir.path().join("coin.json");
        let source_path = temp_dir.path().join("missing.move");
        let output_dir = temp_dir.path().join("generated");
        write_file(&abi_path, sample_abi_json());

        let err = generate_from_abi_with_source(&abi_path, &source_path, &output_dir).unwrap_err();
        assert!(
            matches!(err, AptosError::Config(ref m) if m.contains("Failed to read Move source"))
        );
    }

    #[test]
    fn test_generate_from_abi_with_source_bad_module_name() {
        let temp_dir = TempDir::new().unwrap();
        let abi_path = temp_dir.path().join("evil.json");
        let source_path = temp_dir.path().join("evil.move");
        let output_dir = temp_dir.path().join("generated");
        write_file(&abi_path, &abi_json_with_name("has space"));
        write_file(&source_path, "module 0x1::x {}");

        let err = generate_from_abi_with_source(&abi_path, &source_path, &output_dir).unwrap_err();
        assert!(matches!(err, AptosError::Config(ref m) if m.contains("only ASCII")));
    }

    // --- generate_from_directory ------------------------------------------

    #[test]
    fn test_generate_from_directory_success() {
        let temp_dir = TempDir::new().unwrap();
        let abi_dir = temp_dir.path().join("abi");
        let output_dir = temp_dir.path().join("generated");
        write_file(&abi_dir.join("coin.json"), &abi_json_with_name("coin"));
        write_file(&abi_dir.join("token.json"), &abi_json_with_name("token"));
        // A non-JSON file should be ignored by the extension filter.
        write_file(&abi_dir.join("README.txt"), "ignore me");

        generate_from_directory(&abi_dir, &output_dir).unwrap();

        assert!(output_dir.join("coin.rs").exists());
        assert!(output_dir.join("token.rs").exists());
        assert!(output_dir.join("mod.rs").exists());
    }

    #[test]
    fn test_generate_from_directory_no_json_files() {
        let temp_dir = TempDir::new().unwrap();
        let abi_dir = temp_dir.path().join("abi");
        let output_dir = temp_dir.path().join("generated");
        fs::create_dir_all(&abi_dir).unwrap();
        write_file(&abi_dir.join("notes.txt"), "no abis here");

        let err = generate_from_directory(&abi_dir, &output_dir).unwrap_err();
        assert!(matches!(err, AptosError::Config(ref m) if m.contains("No JSON files found")));
    }

    #[test]
    fn test_generate_from_directory_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        let abi_dir = temp_dir.path().join("abi");
        let output_dir = temp_dir.path().join("generated");
        fs::create_dir_all(&abi_dir).unwrap();

        let err = generate_from_directory(&abi_dir, &output_dir).unwrap_err();
        assert!(matches!(err, AptosError::Config(ref m) if m.contains("No JSON files found")));
    }

    #[test]
    fn test_generate_from_directory_unreadable_dir() {
        let temp_dir = TempDir::new().unwrap();
        // Point at a path that does not exist -> read_dir fails.
        let abi_dir = temp_dir.path().join("nonexistent");
        let output_dir = temp_dir.path().join("generated");

        let err = generate_from_directory(&abi_dir, &output_dir).unwrap_err();
        assert!(
            matches!(err, AptosError::Config(ref m) if m.contains("Failed to read ABI directory"))
        );
    }

    // --- generate_mod_file -------------------------------------------------

    #[test]
    fn test_generate_mod_file_header_and_reexports() {
        let modules = vec!["alpha".to_string()];
        let content = generate_mod_file(&modules);
        assert!(content.contains("Auto-generated module exports"));
        assert!(content.contains("Do not edit manually"));
        assert!(content.contains("pub mod alpha;"));
        assert!(content.contains("pub use alpha::*;"));
    }
}
