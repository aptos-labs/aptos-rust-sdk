//! Parser for macro input and Move source files.

use proc_macro2::Span;
use std::collections::HashMap;
use syn::{
    braced,
    parse::{Parse, ParseStream},
    Ident, LitStr, Result, Token,
};

/// Input for the `aptos_contract!` macro.
pub struct ContractInput {
    /// The name of the generated struct.
    pub name: Ident,
    /// The ABI JSON string.
    pub abi: String,
    /// Optional Move source for parameter names.
    pub source: Option<String>,
}

impl Parse for ContractInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut name = None;
        let mut abi = None;
        let mut source = None;

        // Parse key-value pairs
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![:]>()?;

            match key.to_string().as_str() {
                "name" => {
                    name = Some(input.parse::<Ident>()?);
                }
                "abi" => {
                    let lit: LitStr = input.parse()?;
                    abi = Some(lit.value());
                }
                "source" => {
                    let lit: LitStr = input.parse()?;
                    source = Some(lit.value());
                }
                _ => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!("Unknown key '{}'. Expected 'name', 'abi', or 'source'", key),
                    ));
                }
            }

            // Optional comma
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        let name = name.ok_or_else(|| syn::Error::new(Span::call_site(), "Missing 'name' field"))?;
        let abi = abi.ok_or_else(|| syn::Error::new(Span::call_site(), "Missing 'abi' field"))?;

        Ok(ContractInput { name, abi, source })
    }
}

/// Input for the `aptos_contract_file!` macro.
pub struct FileInput {
    /// Path to the ABI file.
    pub path: String,
    /// Name of the generated struct.
    pub name: Ident,
    /// Optional path to Move source file.
    pub source_path: Option<String>,
}

impl Parse for FileInput {
    fn parse(input: ParseStream) -> Result<Self> {
        // First argument: file path
        let path: LitStr = input.parse()?;
        input.parse::<Token![,]>()?;

        // Second argument: struct name
        let name: Ident = input.parse()?;

        // Optional third argument: source file path
        let source_path = if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            let source: LitStr = input.parse()?;
            Some(source.value())
        } else {
            None
        };

        Ok(FileInput {
            path: path.value(),
            name,
            source_path,
        })
    }
}

/// Information extracted from a Move function definition.
#[derive(Debug, Clone, Default)]
pub struct MoveFunctionInfo {
    /// The function name.
    pub name: String,
    /// Documentation comment.
    pub doc: Option<String>,
    /// Parameter names in order.
    pub param_names: Vec<String>,
    /// Type parameter names.
    pub type_param_names: Vec<String>,
}

/// Information extracted from a Move module.
#[derive(Debug, Clone, Default)]
pub struct MoveSourceInfo {
    /// Module documentation.
    pub doc: Option<String>,
    /// Functions by name.
    pub functions: HashMap<String, MoveFunctionInfo>,
}

/// Parses Move source code to extract function info.
pub fn parse_move_source(source: &str) -> MoveSourceInfo {
    let mut info = MoveSourceInfo::default();
    let lines: Vec<&str> = source.lines().collect();

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();

        // Look for function definitions
        if is_function_start(line) {
            let func_info = parse_function(&lines, i);
            if !func_info.name.is_empty() {
                info.functions.insert(func_info.name.clone(), func_info);
            }
        }

        i += 1;
    }

    info
}

fn is_function_start(line: &str) -> bool {
    let patterns = [
        "public fun ",
        "public entry fun ",
        "public(friend) fun ",
        "entry fun ",
        "fun ",
    ];
    patterns.iter().any(|p| line.contains(p))
}

fn parse_function(lines: &[&str], start: usize) -> MoveFunctionInfo {
    let mut info = MoveFunctionInfo::default();

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
            continue;
        } else {
            break;
        }
    }

    if !doc_lines.is_empty() {
        info.doc = Some(doc_lines.join("\n"));
    }

    // Collect the full function signature
    let mut signature = String::new();
    let mut i = start;
    let mut paren_depth = 0;

    while i < lines.len() {
        let line = lines[i].trim();
        signature.push_str(line);
        signature.push(' ');

        for c in line.chars() {
            match c {
                '(' => paren_depth += 1,
                ')' => paren_depth -= 1,
                _ => {}
            }
        }

        if paren_depth == 0 && (line.contains('{') || line.ends_with(';')) {
            break;
        }

        i += 1;
    }

    // Extract function name
    if let Some(name) = extract_function_name(&signature) {
        info.name = name;
    }

    // Extract type parameters
    info.type_param_names = extract_type_params(&signature);

    // Extract parameter names
    info.param_names = extract_param_names(&signature);

    info
}

fn extract_function_name(signature: &str) -> Option<String> {
    let fun_idx = signature.find("fun ")?;
    let after_fun = &signature[fun_idx + 4..];
    let after_fun = after_fun.trim_start();

    let name: String = after_fun
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn extract_type_params(signature: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(fun_idx) = signature.find("fun ") {
        let after_fun = &signature[fun_idx..];

        if let Some(lt_idx) = after_fun.find('<') {
            if let Some(gt_idx) = after_fun.find('>') {
                if lt_idx < gt_idx {
                    let type_params = &after_fun[lt_idx + 1..gt_idx];
                    for param in type_params.split(',') {
                        let param = param.trim();
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
        }
    }

    params
}

fn extract_param_names(signature: &str) -> Vec<String> {
    let mut params = Vec::new();

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
                if let Some(name) = extract_single_param_name(&current_param) {
                    params.push(name);
                }
                current_param.clear();
            }
            _ => current_param.push(c),
        }
    }

    if let Some(name) = extract_single_param_name(&current_param) {
        params.push(name);
    }

    params
}

fn extract_single_param_name(param: &str) -> Option<String> {
    let param = param.trim();
    if param.is_empty() {
        return None;
    }

    if let Some(colon_idx) = param.find(':') {
        let name = param[..colon_idx].trim();
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

