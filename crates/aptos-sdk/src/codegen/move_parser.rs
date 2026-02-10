//! Move source code parser for extracting function signatures and documentation.
//!
//! This module parses Move source files to extract:
//! - Function parameter names
//! - Documentation comments
//! - Struct field documentation
//!
//! This information is combined with ABI data to generate more readable bindings.

use std::collections::HashMap;

/// Information extracted from a Move function definition.
#[derive(Debug, Clone, Default)]
pub struct MoveFunctionInfo {
    /// The function name.
    pub name: String,
    /// Documentation comment (from `///` comments).
    pub doc: Option<String>,
    /// Parameter names in order.
    pub param_names: Vec<String>,
    /// Type parameter names (e.g., `T`, `CoinType`).
    pub type_param_names: Vec<String>,
}

/// Information extracted from a Move struct definition.
#[derive(Debug, Clone, Default)]
pub struct MoveStructInfo {
    /// The struct name.
    pub name: String,
    /// Documentation comment.
    pub doc: Option<String>,
    /// Field names to documentation.
    pub field_docs: HashMap<String, String>,
}

/// Information extracted from a Move module.
#[derive(Debug, Clone, Default)]
pub struct MoveModuleInfo {
    /// Module documentation.
    pub doc: Option<String>,
    /// Functions by name.
    pub functions: HashMap<String, MoveFunctionInfo>,
    /// Structs by name.
    pub structs: HashMap<String, MoveStructInfo>,
}

/// Parses Move source code to extract metadata.
#[derive(Debug, Clone, Copy, Default)]
pub struct MoveSourceParser;

/// Maximum Move source file size for parsing (10 MB).
///
/// # Security
///
/// Prevents excessive memory usage when parsing very large or malicious input.
const MAX_SOURCE_SIZE: usize = 10 * 1024 * 1024;

impl MoveSourceParser {
    /// Parses Move source code and extracts module information.
    ///
    /// # Security
    ///
    /// Returns an empty `MoveModuleInfo` if the source exceeds [`MAX_SOURCE_SIZE`]
    /// to prevent memory exhaustion from extremely large inputs.
    pub fn parse(source: &str) -> MoveModuleInfo {
        if source.len() > MAX_SOURCE_SIZE {
            return MoveModuleInfo::default();
        }
        MoveModuleInfo {
            doc: Self::extract_leading_doc(source),
            functions: Self::parse_functions(source),
            structs: Self::parse_structs(source),
        }
    }

    /// Extracts leading documentation comments.
    fn extract_leading_doc(source: &str) -> Option<String> {
        let mut doc_lines = Vec::new();
        let mut in_doc = false;

        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("///") {
                in_doc = true;
                let doc_content = trimmed.strip_prefix("///").unwrap_or("").trim();
                doc_lines.push(doc_content.to_string());
            } else if trimmed.starts_with("module ")
                || trimmed.starts_with("script ")
                || (in_doc && !trimmed.is_empty() && !trimmed.starts_with("//"))
            {
                break;
            }
        }

        if doc_lines.is_empty() {
            None
        } else {
            Some(doc_lines.join("\n"))
        }
    }

    /// Parses all function definitions from the source.
    fn parse_functions(source: &str) -> HashMap<String, MoveFunctionInfo> {
        let mut functions = HashMap::new();
        let lines: Vec<&str> = source.lines().collect();

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim();

            // Look for function definitions
            if Self::is_function_start(line) {
                let (func_info, consumed) = Self::parse_function(&lines, i);
                if !func_info.name.is_empty() {
                    functions.insert(func_info.name.clone(), func_info);
                }
                i += consumed.max(1);
            } else {
                i += 1;
            }
        }

        functions
    }

    /// Checks if a line starts a function definition.
    fn is_function_start(line: &str) -> bool {
        let patterns = [
            "public fun ",
            "public entry fun ",
            "public(friend) fun ",
            "entry fun ",
            "fun ",
            "#[view]",
        ];
        patterns.iter().any(|p| line.contains(p))
    }

    /// Parses a single function definition.
    fn parse_function(lines: &[&str], start: usize) -> (MoveFunctionInfo, usize) {
        let mut info = MoveFunctionInfo::default();
        let mut consumed = 0;

        // Look backwards for doc comments
        let mut doc_lines = Vec::new();
        let mut j = start;
        while j > 0 {
            j -= 1;
            let prev_line = lines[j].trim();
            if prev_line.starts_with("///") {
                let doc_content = prev_line.strip_prefix("///").unwrap_or("").trim();
                doc_lines.insert(0, doc_content.to_string());
            } else if prev_line.is_empty() || prev_line.starts_with("#[") {
                // Skip empty lines and attributes
            } else {
                break;
            }
        }

        if !doc_lines.is_empty() {
            info.doc = Some(doc_lines.join("\n"));
        }

        // Collect the full function signature (may span multiple lines)
        let mut signature = String::new();
        let mut i = start;
        let mut paren_depth = 0;

        while i < lines.len() {
            let line = lines[i].trim();
            consumed += 1;

            signature.push_str(line);
            signature.push(' ');

            // Track parenthesis depth
            for c in line.chars() {
                match c {
                    '(' => paren_depth += 1,
                    ')' => paren_depth -= 1,
                    _ => {}
                }
            }

            // Stop when we've closed the parameter list and hit the body
            if paren_depth == 0 && (line.contains('{') || line.ends_with(';')) {
                break;
            }

            i += 1;
        }

        // Extract function name
        if let Some(name) = Self::extract_function_name(&signature) {
            info.name = name;
        }

        // Extract type parameters
        info.type_param_names = Self::extract_type_params(&signature);

        // Extract parameter names
        info.param_names = Self::extract_param_names(&signature);

        (info, consumed)
    }

    /// Extracts the function name from a signature.
    fn extract_function_name(signature: &str) -> Option<String> {
        // Look for "fun name" or "fun name<"
        let fun_idx = signature.find("fun ")?;
        let after_fun = &signature[fun_idx + 4..];
        let after_fun = after_fun.trim_start();

        // Get until the first non-identifier character
        let name: String = after_fun
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();

        if name.is_empty() { None } else { Some(name) }
    }

    /// Extracts type parameter names from a signature.
    fn extract_type_params(signature: &str) -> Vec<String> {
        let mut params = Vec::new();

        // Find the type params section after function name
        if let Some(fun_idx) = signature.find("fun ") {
            let after_fun = &signature[fun_idx..];

            // Look for <...> before (
            if let Some(lt_idx) = after_fun.find('<')
                && let Some(gt_idx) = after_fun.find('>')
                && lt_idx < gt_idx
            {
                let type_params = &after_fun[lt_idx + 1..gt_idx];
                for param in type_params.split(',') {
                    let param = param.trim();
                    // Extract just the name (before any constraints)
                    let name: String = param
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        params.push(name);
                    }
                }
            }
        }

        params
    }

    /// Extracts parameter names from a function signature.
    fn extract_param_names(signature: &str) -> Vec<String> {
        let mut params = Vec::new();

        // Find the parameter section (...) after function name
        // We need to handle nested generics properly
        let Some(paren_start) = signature.find('(') else {
            return params;
        };

        let after_paren = &signature[paren_start + 1..];

        // Find matching closing paren
        let mut depth = 1;
        let mut end_idx = 0;
        for (i, c) in after_paren.chars().enumerate() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end_idx = i;
                        break;
                    }
                }
                _ => {}
            }
        }

        let params_str = &after_paren[..end_idx];

        // Split by comma, handling nested generics
        let mut current_param = String::new();
        let mut angle_depth = 0;

        for c in params_str.chars() {
            match c {
                '<' => {
                    angle_depth += 1;
                    current_param.push(c);
                }
                '>' => {
                    angle_depth -= 1;
                    current_param.push(c);
                }
                ',' if angle_depth == 0 => {
                    if let Some(name) = Self::extract_single_param_name(&current_param) {
                        params.push(name);
                    }
                    current_param.clear();
                }
                _ => current_param.push(c),
            }
        }

        // Don't forget the last parameter
        if let Some(name) = Self::extract_single_param_name(&current_param) {
            params.push(name);
        }

        params
    }

    /// Extracts the parameter name from a single "name: Type" declaration.
    fn extract_single_param_name(param: &str) -> Option<String> {
        let param = param.trim();
        if param.is_empty() {
            return None;
        }

        // Handle "name: Type" format
        if let Some(colon_idx) = param.find(':') {
            let name = param[..colon_idx].trim();
            // Remove any leading & for references
            let name = name.trim_start_matches('&').trim();
            if name.is_empty() || name == "_" {
                None
            } else {
                Some(name.to_string())
            }
        } else {
            None
        }
    }

    /// Parses all struct definitions from the source.
    fn parse_structs(source: &str) -> HashMap<String, MoveStructInfo> {
        let mut structs = HashMap::new();
        let lines: Vec<&str> = source.lines().collect();

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim();

            // Look for struct definitions
            if line.contains("struct ") && (line.contains(" has ") || line.contains('{')) {
                let (struct_info, consumed) = Self::parse_struct(&lines, i);
                if !struct_info.name.is_empty() {
                    structs.insert(struct_info.name.clone(), struct_info);
                }
                i += consumed.max(1);
            } else {
                i += 1;
            }
        }

        structs
    }

    /// Parses a single struct definition.
    fn parse_struct(lines: &[&str], start: usize) -> (MoveStructInfo, usize) {
        let mut info = MoveStructInfo::default();
        let mut consumed = 0;

        // Look backwards for doc comments
        let mut doc_lines = Vec::new();
        let mut j = start;
        while j > 0 {
            j -= 1;
            let prev_line = lines[j].trim();
            if prev_line.starts_with("///") {
                let doc_content = prev_line.strip_prefix("///").unwrap_or("").trim();
                doc_lines.insert(0, doc_content.to_string());
            } else if prev_line.is_empty() || prev_line.starts_with("#[") {
                // Skip empty lines and attributes
            } else {
                break;
            }
        }

        if !doc_lines.is_empty() {
            info.doc = Some(doc_lines.join("\n"));
        }

        // Extract struct name
        let line = lines[start].trim();
        if let Some(struct_idx) = line.find("struct ") {
            let after_struct = &line[struct_idx + 7..];
            let name: String = after_struct
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            info.name = name;
        }

        // Parse struct body for field documentation
        let mut i = start;
        let mut in_struct = false;
        let mut current_doc: Option<String> = None;

        while i < lines.len() {
            let line = lines[i].trim();
            consumed += 1;

            if line.contains('{') {
                in_struct = true;
            }

            if in_struct {
                if line.starts_with("///") {
                    let doc = line.strip_prefix("///").unwrap_or("").trim();
                    current_doc = Some(doc.to_string());
                } else if line.contains(':') && !line.starts_with("//") {
                    // This is a field
                    let field_name: String = line
                        .trim()
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();

                    if !field_name.is_empty()
                        && let Some(doc) = current_doc.take()
                    {
                        info.field_docs.insert(field_name, doc);
                    }
                } else if !line.starts_with("//") && !line.is_empty() {
                    current_doc = None;
                }

                if line.contains('}') {
                    break;
                }
            }

            i += 1;
        }

        (info, consumed)
    }
}

/// Merges Move source information with ABI function parameters.
#[derive(Debug, Clone)]
pub struct EnrichedFunctionInfo {
    /// Function name.
    pub name: String,
    /// Documentation from Move source.
    pub doc: Option<String>,
    /// Parameters with names and types.
    pub params: Vec<EnrichedParam>,
    /// Type parameter names.
    pub type_param_names: Vec<String>,
}

/// A parameter with both name and type information.
#[derive(Debug, Clone)]
pub struct EnrichedParam {
    /// Parameter name from Move source.
    pub name: String,
    /// Parameter type from ABI.
    pub move_type: String,
    /// Whether this is a signer parameter.
    pub is_signer: bool,
}

impl EnrichedFunctionInfo {
    /// Creates enriched function info by merging Move source and ABI data.
    pub fn from_abi_and_source(
        func_name: &str,
        abi_params: &[String],
        abi_type_params_count: usize,
        source_info: Option<&MoveFunctionInfo>,
    ) -> Self {
        let mut info = Self {
            name: func_name.to_string(),
            doc: source_info.and_then(|s| s.doc.clone()),
            params: Vec::new(),
            type_param_names: Vec::new(),
        };

        // Get parameter names from source, or generate defaults
        let source_names = source_info
            .map(|s| s.param_names.clone())
            .unwrap_or_default();

        // Get type parameter names
        if let Some(src) = source_info {
            info.type_param_names.clone_from(&src.type_param_names);
        }
        // Fill in missing type param names
        while info.type_param_names.len() < abi_type_params_count {
            info.type_param_names
                .push(format!("T{}", info.type_param_names.len()));
        }

        // Create enriched params
        let mut source_idx = 0;
        for (i, move_type) in abi_params.iter().enumerate() {
            let is_signer = move_type == "&signer" || move_type == "signer";

            // Get name from source if available
            let name = if source_idx < source_names.len() {
                let name = source_names[source_idx].clone();
                source_idx += 1;
                name
            } else {
                // Generate a meaningful name based on type
                Self::generate_param_name(move_type, i)
            };

            info.params.push(EnrichedParam {
                name,
                move_type: move_type.clone(),
                is_signer,
            });
        }

        info
    }

    /// Generates a parameter name based on its type.
    fn generate_param_name(move_type: &str, index: usize) -> String {
        match move_type {
            "&signer" | "signer" => "account".to_string(),
            "address" => "addr".to_string(),
            "u8" | "u16" | "u32" | "u64" | "u128" | "u256" => "amount".to_string(),
            "bool" => "flag".to_string(),
            t if t.starts_with("vector<u8>") => "bytes".to_string(),
            t if t.starts_with("vector<") => "items".to_string(),
            t if t.contains("::string::String") => "name".to_string(),
            t if t.contains("::object::Object") => "object".to_string(),
            t if t.contains("::option::Option") => "maybe_value".to_string(),
            _ => format!("arg{index}"),
        }
    }

    /// Returns non-signer parameters.
    pub fn non_signer_params(&self) -> Vec<&EnrichedParam> {
        self.params.iter().filter(|p| !p.is_signer).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MOVE_SOURCE: &str = r"
/// A module for managing tokens.
///
/// This module provides functionality for minting and transferring tokens.
module my_addr::my_token {
    use std::string::String;
    use aptos_framework::object::Object;

    /// Represents token information.
    struct TokenInfo has key {
        /// The name of the token.
        name: String,
        /// The symbol of the token.
        symbol: String,
        /// Number of decimal places.
        decimals: u8,
    }

    /// Mints new tokens to a recipient.
    ///
    /// # Arguments
    /// * `admin` - The admin account
    /// * `recipient` - The address to receive tokens
    /// * `amount` - The amount to mint
    public entry fun mint(
        admin: &signer,
        recipient: address,
        amount: u64,
    ) acquires TokenInfo {
        // implementation
    }

    /// Transfers tokens between accounts.
    public entry fun transfer<CoinType>(
        sender: &signer,
        to: address,
        amount: u64,
    ) {
        // implementation
    }

    /// Gets the balance of an account.
    #[view]
    public fun balance(owner: address): u64 {
        0
    }

    /// Gets the total supply.
    #[view]
    public fun total_supply(): u64 {
        0
    }
}
";

    #[test]
    fn test_parse_module_doc() {
        let info = MoveSourceParser::parse(SAMPLE_MOVE_SOURCE);
        assert!(info.doc.is_some());
        assert!(info.doc.unwrap().contains("managing tokens"));
    }

    #[test]
    fn test_parse_function_names() {
        let info = MoveSourceParser::parse(SAMPLE_MOVE_SOURCE);

        assert!(info.functions.contains_key("mint"));
        assert!(info.functions.contains_key("transfer"));
        assert!(info.functions.contains_key("balance"));
        assert!(info.functions.contains_key("total_supply"));
    }

    #[test]
    fn test_parse_function_params() {
        let info = MoveSourceParser::parse(SAMPLE_MOVE_SOURCE);

        let mint = info.functions.get("mint").unwrap();
        assert_eq!(mint.param_names, vec!["admin", "recipient", "amount"]);

        let transfer = info.functions.get("transfer").unwrap();
        assert_eq!(transfer.param_names, vec!["sender", "to", "amount"]);

        let balance = info.functions.get("balance").unwrap();
        assert_eq!(balance.param_names, vec!["owner"]);
    }

    #[test]
    fn test_parse_type_params() {
        let info = MoveSourceParser::parse(SAMPLE_MOVE_SOURCE);

        let transfer = info.functions.get("transfer").unwrap();
        assert_eq!(transfer.type_param_names, vec!["CoinType"]);
    }

    #[test]
    fn test_parse_function_docs() {
        let info = MoveSourceParser::parse(SAMPLE_MOVE_SOURCE);

        let mint = info.functions.get("mint").unwrap();
        assert!(mint.doc.is_some());
        assert!(mint.doc.as_ref().unwrap().contains("Mints new tokens"));
    }

    #[test]
    fn test_parse_struct() {
        let info = MoveSourceParser::parse(SAMPLE_MOVE_SOURCE);

        assert!(info.structs.contains_key("TokenInfo"));
        let token_info = info.structs.get("TokenInfo").unwrap();
        assert!(token_info.doc.is_some());
        assert!(
            token_info
                .doc
                .as_ref()
                .unwrap()
                .contains("token information")
        );

        // Field docs
        assert!(token_info.field_docs.contains_key("name"));
        assert!(
            token_info
                .field_docs
                .get("name")
                .unwrap()
                .contains("name of the token")
        );
    }

    #[test]
    fn test_enriched_function() {
        let info = MoveSourceParser::parse(SAMPLE_MOVE_SOURCE);
        let mint_source = info.functions.get("mint");

        let abi_params = vec![
            "&signer".to_string(),
            "address".to_string(),
            "u64".to_string(),
        ];

        let enriched =
            EnrichedFunctionInfo::from_abi_and_source("mint", &abi_params, 0, mint_source);

        assert_eq!(enriched.params[0].name, "admin");
        assert!(enriched.params[0].is_signer);
        assert_eq!(enriched.params[1].name, "recipient");
        assert_eq!(enriched.params[2].name, "amount");

        let non_signers = enriched.non_signer_params();
        assert_eq!(non_signers.len(), 2);
    }

    #[test]
    fn test_enriched_function_without_source() {
        let abi_params = vec![
            "&signer".to_string(),
            "address".to_string(),
            "u64".to_string(),
        ];

        let enriched = EnrichedFunctionInfo::from_abi_and_source("transfer", &abi_params, 0, None);

        // Should generate reasonable names
        assert_eq!(enriched.params[0].name, "account");
        assert_eq!(enriched.params[1].name, "addr");
        assert_eq!(enriched.params[2].name, "amount");
    }
}
