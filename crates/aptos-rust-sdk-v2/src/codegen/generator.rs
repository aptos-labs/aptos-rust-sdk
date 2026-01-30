//! Code generator for Move modules.

use crate::api::response::{MoveFunction, MoveModuleABI, MoveStructDef, MoveStructField};
use crate::codegen::move_parser::{EnrichedFunctionInfo, MoveModuleInfo};
use crate::codegen::types::{MoveTypeMapper, to_pascal_case, to_snake_case};
use crate::error::{AptosError, AptosResult};
use std::fmt::Write;

/// Configuration for code generation.
#[derive(Debug, Clone)]
pub struct GeneratorConfig {
    /// The module name for the generated code (defaults to module name from ABI).
    pub module_name: Option<String>,
    /// Whether to generate entry function wrappers.
    pub generate_entry_functions: bool,
    /// Whether to generate view function wrappers.
    pub generate_view_functions: bool,
    /// Whether to generate struct definitions.
    pub generate_structs: bool,
    /// Whether to generate event type helpers.
    pub generate_events: bool,
    /// Whether to generate async functions (vs sync).
    pub async_functions: bool,
    /// Custom type mapper.
    pub type_mapper: MoveTypeMapper,
    /// Whether to include the module address constant.
    pub include_address_constant: bool,
    /// Whether to generate builder pattern for entry functions.
    pub use_builder_pattern: bool,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            module_name: None,
            generate_entry_functions: true,
            generate_view_functions: true,
            generate_structs: true,
            generate_events: true,
            async_functions: true,
            type_mapper: MoveTypeMapper::new(),
            include_address_constant: true,
            use_builder_pattern: false,
        }
    }
}

impl GeneratorConfig {
    /// Creates a new configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the module name.
    #[must_use]
    pub fn with_module_name(mut self, name: impl Into<String>) -> Self {
        self.module_name = Some(name.into());
        self
    }

    /// Enables or disables entry function generation.
    #[must_use]
    pub fn with_entry_functions(mut self, enabled: bool) -> Self {
        self.generate_entry_functions = enabled;
        self
    }

    /// Enables or disables view function generation.
    #[must_use]
    pub fn with_view_functions(mut self, enabled: bool) -> Self {
        self.generate_view_functions = enabled;
        self
    }

    /// Enables or disables struct generation.
    #[must_use]
    pub fn with_structs(mut self, enabled: bool) -> Self {
        self.generate_structs = enabled;
        self
    }

    /// Enables or disables event type generation.
    #[must_use]
    pub fn with_events(mut self, enabled: bool) -> Self {
        self.generate_events = enabled;
        self
    }

    /// Enables or disables async functions.
    #[must_use]
    pub fn with_async(mut self, enabled: bool) -> Self {
        self.async_functions = enabled;
        self
    }

    /// Enables builder pattern for entry functions.
    #[must_use]
    pub fn with_builder_pattern(mut self, enabled: bool) -> Self {
        self.use_builder_pattern = enabled;
        self
    }
}

/// Generates Rust code from a Move module ABI.
#[allow(missing_debug_implementations)] // Contains references that don't implement Debug
pub struct ModuleGenerator<'a> {
    abi: &'a MoveModuleABI,
    config: GeneratorConfig,
    source_info: Option<MoveModuleInfo>,
}

impl<'a> ModuleGenerator<'a> {
    /// Creates a new generator for the given ABI.
    #[must_use]
    pub fn new(abi: &'a MoveModuleABI, config: GeneratorConfig) -> Self {
        Self {
            abi,
            config,
            source_info: None,
        }
    }

    /// Adds Move source information for better parameter names and documentation.
    #[must_use]
    pub fn with_source_info(mut self, source_info: MoveModuleInfo) -> Self {
        self.source_info = Some(source_info);
        self
    }

    /// Gets enriched function info by combining ABI and source data.
    fn get_enriched_function(&self, func: &MoveFunction) -> EnrichedFunctionInfo {
        let source_func = self
            .source_info
            .as_ref()
            .and_then(|s| s.functions.get(&func.name));

        EnrichedFunctionInfo::from_abi_and_source(
            &func.name,
            &func.params,
            func.generic_type_params.len(),
            source_func,
        )
    }

    /// Generates the complete Rust module code.
    pub fn generate(&self) -> AptosResult<String> {
        let mut output = String::new();

        self.write_all(&mut output)
            .map_err(|e| AptosError::Internal(format!("Code generation failed: {e}")))?;

        Ok(output)
    }

    /// Writes all code to the output string.
    fn write_all(&self, output: &mut String) -> std::fmt::Result {
        // File header
        self.write_header(output)?;

        // Imports
        self.write_imports(output)?;

        // Module address constant
        if self.config.include_address_constant {
            self.write_address_constant(output)?;
        }

        // Struct definitions
        if self.config.generate_structs {
            self.write_structs(output)?;
        }

        // Event types
        if self.config.generate_events {
            self.write_events(output)?;
        }

        // Entry functions
        if self.config.generate_entry_functions {
            self.write_entry_functions(output)?;
        }

        // View functions
        if self.config.generate_view_functions {
            self.write_view_functions(output)?;
        }

        Ok(())
    }

    /// Writes event type helpers.
    fn write_events(&self, output: &mut String) -> std::fmt::Result {
        // Find structs that are likely events (heuristic: name ends with "Event")
        let event_structs: Vec<_> = self
            .abi
            .structs
            .iter()
            .filter(|s| s.name.ends_with("Event") && !s.is_native)
            .collect();

        if event_structs.is_empty() {
            return Ok(());
        }

        writeln!(output, "// =============================================")?;
        writeln!(output, "// Event Types")?;
        writeln!(output, "// =============================================")?;
        writeln!(output)?;

        // Generate event type enum
        writeln!(output, "/// All event types defined in this module.")?;
        writeln!(output, "#[derive(Debug, Clone, PartialEq)]")?;
        writeln!(output, "pub enum ModuleEvent {{")?;
        for struct_def in &event_structs {
            let variant_name = to_pascal_case(&struct_def.name);
            writeln!(output, "    {variant_name}({variant_name}),")?;
        }
        writeln!(output, "    /// Unknown event type.")?;
        writeln!(output, "    Unknown(serde_json::Value),")?;
        writeln!(output, "}}")?;
        writeln!(output)?;

        // Generate event type string constants
        writeln!(output, "/// Event type strings for this module.")?;
        writeln!(output, "pub mod event_types {{")?;
        for struct_def in &event_structs {
            let const_name = to_snake_case(&struct_def.name).to_uppercase();
            writeln!(
                output,
                "    pub const {}: &str = \"{}::{}::{}\";",
                const_name, self.abi.address, self.abi.name, struct_def.name
            )?;
        }
        writeln!(output, "}}")?;
        writeln!(output)?;

        // Generate parse_event function
        writeln!(output, "/// Parses a raw event into a typed ModuleEvent.")?;
        writeln!(output, "///")?;
        writeln!(output, "/// # Arguments")?;
        writeln!(output, "///")?;
        writeln!(output, "/// * `event_type` - The event type string")?;
        writeln!(output, "/// * `data` - The event data as JSON")?;
        writeln!(
            output,
            "pub fn parse_event(event_type: &str, data: serde_json::Value) -> AptosResult<ModuleEvent> {{"
        )?;
        writeln!(output, "    match event_type {{")?;
        for struct_def in &event_structs {
            let const_name = to_snake_case(&struct_def.name).to_uppercase();
            let variant_name = to_pascal_case(&struct_def.name);
            writeln!(output, "        event_types::{const_name} => {{")?;
            writeln!(
                output,
                "            let event: {variant_name} = serde_json::from_value(data)"
            )?;
            writeln!(
                output,
                "                .map_err(|e| AptosError::Internal(format!(\"Failed to parse {}: {{}}\", e)))?;",
                struct_def.name
            )?;
            writeln!(output, "            Ok(ModuleEvent::{variant_name}(event))")?;
            writeln!(output, "        }}")?;
        }
        writeln!(output, "        _ => Ok(ModuleEvent::Unknown(data)),")?;
        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;
        writeln!(output)?;

        // Generate is_module_event helper
        writeln!(
            output,
            "/// Checks if an event type belongs to this module."
        )?;
        writeln!(
            output,
            "pub fn is_module_event(event_type: &str) -> bool {{"
        )?;
        writeln!(
            output,
            "    event_type.starts_with(\"{}::{}::\")",
            self.abi.address, self.abi.name
        )?;
        writeln!(output, "}}")?;
        writeln!(output)
    }

    /// Writes the file header comment.
    fn write_header(&self, output: &mut String) -> std::fmt::Result {
        writeln!(
            output,
            "//! Generated Rust bindings for `{}::{}`.",
            self.abi.address, self.abi.name
        )?;
        writeln!(output, "//!")?;
        writeln!(
            output,
            "//! This file was auto-generated by aptos-rust-sdk-v2 codegen."
        )?;
        writeln!(output, "//! Do not edit manually.")?;
        writeln!(output)?;
        writeln!(output, "#![allow(dead_code)]")?;
        writeln!(output, "#![allow(unused_imports)]")?;
        writeln!(output)
    }

    /// Writes import statements.
    fn write_imports(&self, output: &mut String) -> std::fmt::Result {
        writeln!(output, "use aptos_rust_sdk_v2::{{")?;
        writeln!(output, "    account::Account,")?;
        writeln!(output, "    error::{{AptosError, AptosResult}},")?;
        writeln!(
            output,
            "    transaction::{{EntryFunction, TransactionPayload}},"
        )?;
        writeln!(output, "    types::{{AccountAddress, TypeTag}},")?;
        writeln!(output, "    Aptos,")?;
        writeln!(output, "}};")?;
        writeln!(output, "use serde::{{Deserialize, Serialize}};")?;
        writeln!(output)
    }

    /// Writes the module address constant.
    fn write_address_constant(&self, output: &mut String) -> std::fmt::Result {
        writeln!(output, "/// The address where this module is deployed.")?;
        writeln!(
            output,
            "pub const MODULE_ADDRESS: &str = \"{}\";",
            self.abi.address
        )?;
        writeln!(output)?;
        writeln!(output, "/// The module name.")?;
        writeln!(
            output,
            "pub const MODULE_NAME: &str = \"{}\";",
            self.abi.name
        )?;
        writeln!(output)
    }

    /// Writes struct definitions.
    fn write_structs(&self, output: &mut String) -> std::fmt::Result {
        if self.abi.structs.is_empty() {
            return Ok(());
        }

        writeln!(output, "// =============================================")?;
        writeln!(output, "// Struct Definitions")?;
        writeln!(output, "// =============================================")?;
        writeln!(output)?;

        for struct_def in &self.abi.structs {
            self.write_struct(output, struct_def)?;
        }

        Ok(())
    }

    /// Writes a single struct definition.
    fn write_struct(&self, output: &mut String, struct_def: &MoveStructDef) -> std::fmt::Result {
        // Skip native structs
        if struct_def.is_native {
            return Ok(());
        }

        let rust_name = to_pascal_case(&struct_def.name);

        // Documentation
        writeln!(
            output,
            "/// Move struct: `{}::{}`",
            self.abi.name, struct_def.name
        )?;
        if !struct_def.abilities.is_empty() {
            writeln!(output, "///")?;
            writeln!(output, "/// Abilities: {}", struct_def.abilities.join(", "))?;
        }

        // Derive macros
        writeln!(
            output,
            "#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]"
        )?;

        // Generic type parameters
        if !struct_def.generic_type_params.is_empty() {
            let type_params: Vec<String> = struct_def
                .generic_type_params
                .iter()
                .enumerate()
                .map(|(i, _)| format!("T{i}"))
                .collect();

            writeln!(
                output,
                "pub struct {}<{}> {{",
                rust_name,
                type_params.join(", ")
            )?;
        } else {
            writeln!(output, "pub struct {rust_name} {{")?;
        }

        // Fields
        for field in &struct_def.fields {
            self.write_struct_field(output, field)?;
        }

        writeln!(output, "}}")?;
        writeln!(output)
    }

    /// Writes a struct field.
    fn write_struct_field(&self, output: &mut String, field: &MoveStructField) -> std::fmt::Result {
        let rust_type = self.config.type_mapper.map_type(&field.typ);
        let rust_name = to_snake_case(&field.name);

        // Handle reserved Rust keywords
        let rust_name = match rust_name.as_str() {
            "type" => "r#type".to_string(),
            "self" => "r#self".to_string(),
            "move" => "r#move".to_string(),
            _ => rust_name,
        };

        if let Some(doc) = &rust_type.doc {
            writeln!(output, "    /// {doc}")?;
        }

        // Add serde rename if field name differs
        if rust_name != field.name && !rust_name.starts_with("r#") {
            writeln!(output, "    #[serde(rename = \"{}\")]", field.name)?;
        }

        writeln!(output, "    pub {}: {},", rust_name, rust_type.path)
    }

    /// Writes entry function wrappers.
    fn write_entry_functions(&self, output: &mut String) -> std::fmt::Result {
        let entry_functions: Vec<_> = self
            .abi
            .exposed_functions
            .iter()
            .filter(|f| f.is_entry)
            .collect();

        if entry_functions.is_empty() {
            return Ok(());
        }

        writeln!(output, "// =============================================")?;
        writeln!(output, "// Entry Functions")?;
        writeln!(output, "// =============================================")?;
        writeln!(output)?;

        for func in entry_functions {
            self.write_entry_function(output, func)?;
        }

        Ok(())
    }

    /// Writes a single entry function wrapper.
    fn write_entry_function(&self, output: &mut String, func: &MoveFunction) -> std::fmt::Result {
        let rust_name = to_snake_case(&func.name);
        let enriched = self.get_enriched_function(func);

        // Get non-signer parameters with their enriched names
        let params: Vec<_> = enriched
            .non_signer_params()
            .into_iter()
            .map(|p| {
                let rust_type = self.config.type_mapper.map_type(&p.move_type);
                (p.name.clone(), p.move_type.clone(), rust_type)
            })
            .collect();

        // Documentation from source or generated
        if let Some(doc) = &enriched.doc {
            for line in doc.lines() {
                writeln!(output, "/// {line}")?;
            }
            writeln!(output, "///")?;
        } else {
            writeln!(
                output,
                "/// Entry function: `{}::{}`",
                self.abi.name, func.name
            )?;
            writeln!(output, "///")?;
        }

        // Arguments documentation
        if !params.is_empty() {
            writeln!(output, "/// # Arguments")?;
            writeln!(output, "///")?;
            for (name, move_type, rust_type) in &params {
                writeln!(
                    output,
                    "/// * `{}` - {} (Move type: `{}`)",
                    name, rust_type.path, move_type
                )?;
            }
        }
        if !enriched.type_param_names.is_empty() {
            writeln!(
                output,
                "/// * `type_args` - Type arguments: {}",
                enriched.type_param_names.join(", ")
            )?;
        }

        // Function signature
        write!(output, "pub fn {rust_name}(")?;

        // Parameters with meaningful names
        let mut param_strs = Vec::new();
        for (name, _, rust_type) in &params {
            // Convert to snake_case and handle reserved words
            let safe_name = Self::safe_param_name(name);
            param_strs.push(format!("{}: {}", safe_name, rust_type.as_arg_type()));
        }
        if !enriched.type_param_names.is_empty() {
            param_strs.push("type_args: Vec<TypeTag>".to_string());
        }
        write!(output, "{}", param_strs.join(", "))?;

        writeln!(output, ") -> AptosResult<TransactionPayload> {{")?;

        // Function body
        writeln!(output, "    let function_id = format!(")?;
        writeln!(
            output,
            "        \"{}::{}::{}\",",
            self.abi.address, self.abi.name, func.name
        )?;
        writeln!(output, "    );")?;
        writeln!(output)?;

        // Build arguments using the parameter names
        writeln!(output, "    let args = vec![")?;
        for (name, move_type, _) in &params {
            let safe_name = Self::safe_param_name(name);
            let bcs_expr = self.config.type_mapper.to_bcs_arg(move_type, &safe_name);
            writeln!(output, "        {bcs_expr},")?;
        }
        writeln!(output, "    ];")?;
        writeln!(output)?;

        // Type arguments
        if func.generic_type_params.is_empty() {
            writeln!(output, "    let type_args = vec![];")?;
        }
        writeln!(output)?;

        // Create entry function
        writeln!(
            output,
            "    let entry_fn = EntryFunction::from_function_id(&function_id, type_args, args)?;"
        )?;
        writeln!(
            output,
            "    Ok(TransactionPayload::EntryFunction(entry_fn))"
        )?;
        writeln!(output, "}}")?;
        writeln!(output)
    }

    /// Writes view function wrappers.
    fn write_view_functions(&self, output: &mut String) -> std::fmt::Result {
        let view_functions: Vec<_> = self
            .abi
            .exposed_functions
            .iter()
            .filter(|f| f.is_view)
            .collect();

        if view_functions.is_empty() {
            return Ok(());
        }

        writeln!(output, "// =============================================")?;
        writeln!(output, "// View Functions")?;
        writeln!(output, "// =============================================")?;
        writeln!(output)?;

        for func in view_functions {
            self.write_view_function(output, func)?;
        }

        Ok(())
    }

    /// Converts a parameter name to a safe Rust identifier.
    fn safe_param_name(name: &str) -> String {
        let snake = to_snake_case(name);
        match snake.as_str() {
            "type" => "r#type".to_string(),
            "self" => "r#self".to_string(),
            "move" => "r#move".to_string(),
            "ref" => "r#ref".to_string(),
            "mut" => "r#mut".to_string(),
            "fn" => "r#fn".to_string(),
            "mod" => "r#mod".to_string(),
            "use" => "r#use".to_string(),
            "pub" => "r#pub".to_string(),
            "let" => "r#let".to_string(),
            "if" => "r#if".to_string(),
            "else" => "r#else".to_string(),
            "match" => "r#match".to_string(),
            "loop" => "r#loop".to_string(),
            "while" => "r#while".to_string(),
            "for" => "r#for".to_string(),
            "in" => "r#in".to_string(),
            "return" => "r#return".to_string(),
            "break" => "r#break".to_string(),
            "continue" => "r#continue".to_string(),
            "async" => "r#async".to_string(),
            "await" => "r#await".to_string(),
            "struct" => "r#struct".to_string(),
            "enum" => "r#enum".to_string(),
            "trait" => "r#trait".to_string(),
            "impl" => "r#impl".to_string(),
            "dyn" => "r#dyn".to_string(),
            "const" => "r#const".to_string(),
            "static" => "r#static".to_string(),
            "unsafe" => "r#unsafe".to_string(),
            "extern" => "r#extern".to_string(),
            "crate" => "r#crate".to_string(),
            "super" => "r#super".to_string(),
            "where" => "r#where".to_string(),
            "as" => "r#as".to_string(),
            "true" => "r#true".to_string(),
            "false" => "r#false".to_string(),
            _ => snake,
        }
    }

    /// Writes a single view function wrapper.
    fn write_view_function(&self, output: &mut String, func: &MoveFunction) -> std::fmt::Result {
        let rust_name = format!("view_{}", to_snake_case(&func.name));
        let enriched = self.get_enriched_function(func);

        // Get all parameters with their enriched names (view functions can have any params)
        let params: Vec<_> = enriched
            .params
            .iter()
            .map(|p| {
                let rust_type = self.config.type_mapper.map_type(&p.move_type);
                (p.name.clone(), p.move_type.clone(), rust_type)
            })
            .collect();

        // Return type
        let return_type = if func.returns.is_empty() {
            "()".to_string()
        } else if func.returns.len() == 1 {
            self.config.type_mapper.map_type(&func.returns[0]).path
        } else {
            let types: Vec<String> = func
                .returns
                .iter()
                .map(|r| self.config.type_mapper.map_type(r).path)
                .collect();
            format!("({})", types.join(", "))
        };

        // Documentation from source or generated
        if let Some(doc) = &enriched.doc {
            for line in doc.lines() {
                writeln!(output, "/// {line}")?;
            }
            writeln!(output, "///")?;
        } else {
            writeln!(
                output,
                "/// View function: `{}::{}`",
                self.abi.name, func.name
            )?;
            writeln!(output, "///")?;
        }

        // Arguments documentation
        if !params.is_empty() {
            writeln!(output, "/// # Arguments")?;
            writeln!(output, "///")?;
            for (name, move_type, rust_type) in &params {
                writeln!(
                    output,
                    "/// * `{}` - {} (Move type: `{}`)",
                    name, rust_type.path, move_type
                )?;
            }
        }
        if !enriched.type_param_names.is_empty() {
            writeln!(
                output,
                "/// * `type_args` - Type arguments: {}",
                enriched.type_param_names.join(", ")
            )?;
        }
        if !func.returns.is_empty() {
            writeln!(output, "///")?;
            writeln!(output, "/// # Returns")?;
            writeln!(output, "///")?;
            writeln!(output, "/// `{return_type}`")?;
        }

        // Function signature
        let async_kw = if self.config.async_functions {
            "async "
        } else {
            ""
        };

        write!(output, "pub {async_kw}fn {rust_name}(aptos: &Aptos")?;

        // Parameters with meaningful names
        for (name, _, rust_type) in &params {
            let safe_name = Self::safe_param_name(name);
            write!(output, ", {}: {}", safe_name, rust_type.as_arg_type())?;
        }
        if !enriched.type_param_names.is_empty() {
            write!(output, ", type_args: Vec<String>")?;
        }

        writeln!(output, ") -> AptosResult<Vec<serde_json::Value>> {{")?;

        // Function body
        writeln!(output, "    let function_id = format!(")?;
        writeln!(
            output,
            "        \"{}::{}::{}\",",
            self.abi.address, self.abi.name, func.name
        )?;
        writeln!(output, "    );")?;
        writeln!(output)?;

        // Type arguments
        if enriched.type_param_names.is_empty() {
            writeln!(output, "    let type_args: Vec<String> = vec![];")?;
        }

        // Build view arguments as JSON using parameter names
        writeln!(output, "    let args = vec![")?;
        for (name, move_type, _) in &params {
            let safe_name = Self::safe_param_name(name);
            let arg_expr = self.view_arg_json_expr(move_type, &safe_name);
            writeln!(output, "        {arg_expr},")?;
        }
        writeln!(output, "    ];")?;
        writeln!(output)?;

        // Call view function
        let await_kw = if self.config.async_functions {
            ".await"
        } else {
            ""
        };
        writeln!(
            output,
            "    aptos.view(&function_id, type_args, args){await_kw}"
        )?;
        writeln!(output, "}}")?;
        writeln!(output)
    }

    /// Creates a JSON expression for a view function argument.
    fn view_arg_json_expr(&self, move_type: &str, var_name: &str) -> String {
        match move_type {
            "address" => format!("serde_json::json!({var_name}.to_string())"),
            "bool" | "u8" | "u16" | "u32" | "u64" | "u128" => {
                format!("serde_json::json!({var_name}.to_string())")
            }
            _ if move_type.starts_with("vector<u8>") => {
                format!("serde_json::json!(hex::encode({var_name}))")
            }
            "0x1::string::String" => format!("serde_json::json!({var_name})"),
            _ if move_type.ends_with("::string::String") => {
                format!("serde_json::json!({var_name})")
            }
            _ => format!("serde_json::json!({var_name})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::response::{MoveFunctionGenericTypeParam, MoveStructGenericTypeParam};

    fn sample_abi() -> MoveModuleABI {
        MoveModuleABI {
            address: "0x1".to_string(),
            name: "coin".to_string(),
            exposed_functions: vec![
                MoveFunction {
                    name: "transfer".to_string(),
                    visibility: "public".to_string(),
                    is_entry: true,
                    is_view: false,
                    generic_type_params: vec![MoveFunctionGenericTypeParam {
                        constraints: vec![],
                    }],
                    params: vec![
                        "&signer".to_string(),
                        "address".to_string(),
                        "u64".to_string(),
                    ],
                    returns: vec![],
                },
                MoveFunction {
                    name: "balance".to_string(),
                    visibility: "public".to_string(),
                    is_entry: false,
                    is_view: true,
                    generic_type_params: vec![MoveFunctionGenericTypeParam {
                        constraints: vec![],
                    }],
                    params: vec!["address".to_string()],
                    returns: vec!["u64".to_string()],
                },
            ],
            structs: vec![MoveStructDef {
                name: "Coin".to_string(),
                is_native: false,
                abilities: vec!["store".to_string()],
                generic_type_params: vec![MoveStructGenericTypeParam {
                    constraints: vec![],
                }],
                fields: vec![MoveStructField {
                    name: "value".to_string(),
                    typ: "u64".to_string(),
                }],
            }],
        }
    }

    fn sample_abi_with_events() -> MoveModuleABI {
        MoveModuleABI {
            address: "0x1".to_string(),
            name: "token".to_string(),
            exposed_functions: vec![],
            structs: vec![
                MoveStructDef {
                    name: "MintEvent".to_string(),
                    is_native: false,
                    abilities: vec!["drop".to_string(), "store".to_string()],
                    generic_type_params: vec![],
                    fields: vec![
                        MoveStructField {
                            name: "id".to_string(),
                            typ: "u64".to_string(),
                        },
                        MoveStructField {
                            name: "creator".to_string(),
                            typ: "address".to_string(),
                        },
                    ],
                },
                MoveStructDef {
                    name: "BurnEvent".to_string(),
                    is_native: false,
                    abilities: vec!["drop".to_string(), "store".to_string()],
                    generic_type_params: vec![],
                    fields: vec![MoveStructField {
                        name: "id".to_string(),
                        typ: "u64".to_string(),
                    }],
                },
                MoveStructDef {
                    name: "Token".to_string(),
                    is_native: false,
                    abilities: vec!["key".to_string()],
                    generic_type_params: vec![],
                    fields: vec![MoveStructField {
                        name: "value".to_string(),
                        typ: "u64".to_string(),
                    }],
                },
            ],
        }
    }

    #[test]
    fn test_generate_module() {
        let abi = sample_abi();
        let generator = ModuleGenerator::new(&abi, GeneratorConfig::default());
        let code = generator.generate().unwrap();

        // Verify header
        assert!(code.contains("Generated Rust bindings"));
        assert!(code.contains("0x1::coin"));

        // Verify constants
        assert!(code.contains("MODULE_ADDRESS"));
        assert!(code.contains("MODULE_NAME"));

        // Verify struct
        assert!(code.contains("pub struct Coin"));
        assert!(code.contains("pub value: u64"));

        // Verify entry function
        assert!(code.contains("pub fn transfer"));

        // Verify view function
        assert!(code.contains("pub async fn view_balance"));
    }

    #[test]
    fn test_entry_function_excludes_signer() {
        let abi = sample_abi();
        let generator = ModuleGenerator::new(&abi, GeneratorConfig::default());
        let code = generator.generate().unwrap();

        // transfer should have 2 args (address, u64), not 3 (signer is excluded)
        // Without source info, names are generated from types: addr, amount
        assert!(code.contains("addr: AccountAddress"));
        assert!(code.contains("amount: u64"));
        // Should not have account (signer) as an argument
        assert!(!code.contains("account: AccountAddress"));
        // Function should exist
        assert!(code.contains("pub fn transfer("));
    }

    #[test]
    fn test_entry_function_with_source_info() {
        use crate::codegen::move_parser::MoveSourceParser;

        let abi = sample_abi();
        let source = r#"
            module 0x1::coin {
                /// Transfers coins from sender to recipient.
                public entry fun transfer<CoinType>(
                    from: &signer,
                    to: address,
                    value: u64,
                ) { }
            }
        "#;
        let source_info = MoveSourceParser::parse(source);

        let generator =
            ModuleGenerator::new(&abi, GeneratorConfig::default()).with_source_info(source_info);
        let code = generator.generate().unwrap();

        // With source info, should have the actual parameter names
        assert!(code.contains("to: AccountAddress"));
        assert!(code.contains("value: u64"));
        // Should have the documentation
        assert!(code.contains("Transfers coins from sender to recipient"));
    }

    #[test]
    fn test_generate_events() {
        let abi = sample_abi_with_events();
        let generator = ModuleGenerator::new(&abi, GeneratorConfig::default());
        let code = generator.generate().unwrap();

        // Should generate event enum
        assert!(code.contains("pub enum ModuleEvent"));
        assert!(code.contains("MintEvent(MintEvent)"));
        assert!(code.contains("BurnEvent(BurnEvent)"));
        assert!(code.contains("Unknown(serde_json::Value)"));

        // Should generate event type constants
        assert!(code.contains("pub mod event_types"));
        assert!(code.contains("MINT_EVENT"));
        assert!(code.contains("BURN_EVENT"));

        // Should generate parse_event function
        assert!(code.contains("pub fn parse_event"));
        assert!(code.contains("is_module_event"));

        // Non-event struct (Token) should not be in event enum
        assert!(!code.contains("Token(Token)"));
    }

    #[test]
    fn test_config_disable_events() {
        let abi = sample_abi_with_events();
        let config = GeneratorConfig::default().with_events(false);
        let generator = ModuleGenerator::new(&abi, config);
        let code = generator.generate().unwrap();

        // Should not generate event helpers
        assert!(!code.contains("pub enum ModuleEvent"));
        assert!(!code.contains("pub fn parse_event"));
    }

    #[test]
    fn test_config_disable_structs() {
        let abi = sample_abi();
        let config = GeneratorConfig::default().with_structs(false);
        let generator = ModuleGenerator::new(&abi, config);
        let code = generator.generate().unwrap();

        // Should not generate struct definitions
        assert!(!code.contains("pub struct Coin"));
    }

    #[test]
    fn test_config_sync_functions() {
        let abi = sample_abi();
        let config = GeneratorConfig::default().with_async(false);
        let generator = ModuleGenerator::new(&abi, config);
        let code = generator.generate().unwrap();

        // Should generate sync view function, not async
        assert!(code.contains("pub fn view_balance"));
        assert!(!code.contains("pub async fn view_balance"));
    }

    #[test]
    fn test_config_no_address_constant() {
        let abi = sample_abi();
        let config = GeneratorConfig {
            include_address_constant: false,
            ..Default::default()
        };
        let generator = ModuleGenerator::new(&abi, config);
        let code = generator.generate().unwrap();

        // Should not include module address constant
        assert!(!code.contains("MODULE_ADDRESS"));
    }

    #[test]
    fn test_generator_config_builder() {
        let config = GeneratorConfig::new()
            .with_module_name("custom_name")
            .with_entry_functions(false)
            .with_view_functions(false)
            .with_structs(false)
            .with_events(false)
            .with_async(false)
            .with_builder_pattern(true);

        assert_eq!(config.module_name, Some("custom_name".to_string()));
        assert!(!config.generate_entry_functions);
        assert!(!config.generate_view_functions);
        assert!(!config.generate_structs);
        assert!(!config.generate_events);
        assert!(!config.async_functions);
        assert!(config.use_builder_pattern);
    }

    #[test]
    fn test_empty_module() {
        let abi = MoveModuleABI {
            address: "0x1".to_string(),
            name: "empty".to_string(),
            exposed_functions: vec![],
            structs: vec![],
        };
        let generator = ModuleGenerator::new(&abi, GeneratorConfig::default());
        let code = generator.generate().unwrap();

        // Should still generate valid code
        assert!(code.contains("Generated Rust bindings"));
        assert!(code.contains("MODULE_ADDRESS"));
        assert!(code.contains("MODULE_NAME"));
    }
}
