//! Code generation for contract bindings.

use crate::abi::{MoveFunction, MoveModuleABI, MoveStructDef};
use crate::parser::MoveSourceInfo;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::Ident;

/// Generates the contract implementation.
pub fn generate_contract_impl(
    name: &Ident,
    abi: &MoveModuleABI,
    source_info: Option<&MoveSourceInfo>,
) -> TokenStream {
    let address = &abi.address;
    let module_name = &abi.name;

    // Generate struct definitions
    let structs = generate_structs(&abi.structs);

    // Generate entry functions
    let entry_fns: Vec<_> = abi
        .exposed_functions
        .iter()
        .filter(|f| f.is_entry)
        .map(|f| generate_entry_function(f, address, module_name, source_info))
        .collect();

    // Generate view functions
    let view_fns: Vec<_> = abi
        .exposed_functions
        .iter()
        .filter(|f| f.is_view)
        .map(|f| generate_view_function(f, address, module_name, source_info))
        .collect();

    // Constants
    let address_const = address.to_string();
    let module_const = module_name.to_string();

    quote! {
        /// Generated contract bindings for `#address::#module_name`.
        ///
        /// This struct provides type-safe methods for interacting with the contract.
        #[derive(Debug, Clone, Copy)]
        pub struct #name;

        impl #name {
            /// The address where this module is deployed.
            pub const ADDRESS: &'static str = #address_const;

            /// The module name.
            pub const MODULE: &'static str = #module_const;

            #(#entry_fns)*

            #(#view_fns)*
        }

        #structs
    }
}

/// Generates struct definitions.
fn generate_structs(structs: &[MoveStructDef]) -> TokenStream {
    let struct_defs: Vec<_> = structs
        .iter()
        .filter(|s| !s.is_native)
        .map(generate_struct)
        .collect();

    quote! {
        #(#struct_defs)*
    }
}

/// Generates a single struct definition.
fn generate_struct(struct_def: &MoveStructDef) -> TokenStream {
    let name = format_ident!("{}", to_pascal_case(&struct_def.name));
    let abilities = struct_def.abilities.join(", ");
    let doc = format!("Move struct with abilities: {}", abilities);

    let fields: Vec<_> = struct_def
        .fields
        .iter()
        .map(|f| {
            let field_name = format_ident!("{}", to_snake_case(&f.name));
            let field_type = move_type_to_rust(&f.typ);
            quote! {
                pub #field_name: #field_type
            }
        })
        .collect();

    // Generate generic type params if any
    let type_params: Vec<_> = struct_def
        .generic_type_params
        .iter()
        .enumerate()
        .map(|(i, _)| format_ident!("T{}", i))
        .collect();

    if type_params.is_empty() {
        quote! {
            #[doc = #doc]
            #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
            pub struct #name {
                #(#fields),*
            }
        }
    } else {
        quote! {
            #[doc = #doc]
            #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
            pub struct #name<#(#type_params),*> {
                #(#fields),*
            }
        }
    }
}

/// Generates an entry function.
fn generate_entry_function(
    func: &MoveFunction,
    address: &str,
    module: &str,
    source_info: Option<&MoveSourceInfo>,
) -> TokenStream {
    let fn_name = format_ident!("{}", to_snake_case(&func.name));
    let function_id = format!("{}::{}::{}", address, module, func.name);

    // Get enriched param info
    let source_func = source_info.and_then(|s| s.functions.get(&func.name));

    // Filter out signer params and get names
    let params: Vec<_> = func
        .params
        .iter()
        .enumerate()
        .filter(|(_, p)| !is_signer_param(p))
        .map(|(i, move_type)| {
            let name = get_param_name(i, move_type, source_func);
            let rust_type = move_type_to_rust(move_type);
            (
                format_ident!("{}", safe_ident(&name)),
                rust_type,
                move_type.clone(),
            )
        })
        .collect();

    // Build param list for function signature
    let param_defs: Vec<_> = params
        .iter()
        .map(|(name, rust_type, _)| {
            quote! { #name: #rust_type }
        })
        .collect();

    // Build BCS encoding for args
    let arg_encodings: Vec<_> = params
        .iter()
        .map(|(name, _, _)| {
            quote! {
                aptos_bcs::to_bytes(&#name)
                    .map_err(|e| aptos_rust_sdk_v2::error::AptosError::Bcs(e.to_string()))?
            }
        })
        .collect();

    // Type arguments
    let has_type_params = !func.generic_type_params.is_empty();
    let _type_param_names: Vec<_> = source_func
        .map(|f| f.type_param_names.clone())
        .unwrap_or_default();

    let type_args_param = if has_type_params {
        quote! { , type_args: Vec<aptos_rust_sdk_v2::types::TypeTag> }
    } else {
        quote! {}
    };

    let type_args_use = if has_type_params {
        quote! { type_args }
    } else {
        quote! { vec![] }
    };

    // Documentation
    let doc = source_func
        .and_then(|f| f.doc.as_ref())
        .map(|d| format!("{}\n\n", d))
        .unwrap_or_default();
    let full_doc = format!("{}Entry function: `{}`", doc, function_id);

    quote! {
        #[doc = #full_doc]
        pub fn #fn_name(#(#param_defs),* #type_args_param) -> aptos_rust_sdk_v2::error::AptosResult<aptos_rust_sdk_v2::transaction::TransactionPayload> {
            let args = vec![
                #(#arg_encodings),*
            ];

            let entry_fn = aptos_rust_sdk_v2::transaction::EntryFunction::from_function_id(
                #function_id,
                #type_args_use,
                args,
            )?;

            Ok(aptos_rust_sdk_v2::transaction::TransactionPayload::EntryFunction(entry_fn))
        }
    }
}

/// Generates a view function.
fn generate_view_function(
    func: &MoveFunction,
    address: &str,
    module: &str,
    source_info: Option<&MoveSourceInfo>,
) -> TokenStream {
    let fn_name = format_ident!("view_{}", to_snake_case(&func.name));
    let function_id = format!("{}::{}::{}", address, module, func.name);

    // Get enriched param info
    let source_func = source_info.and_then(|s| s.functions.get(&func.name));

    // View functions can have any params
    let params: Vec<_> = func
        .params
        .iter()
        .enumerate()
        .map(|(i, move_type)| {
            let name = get_param_name(i, move_type, source_func);
            let rust_type = move_type_to_rust(move_type);
            (
                format_ident!("{}", safe_ident(&name)),
                rust_type,
                move_type.clone(),
            )
        })
        .collect();

    // Build param list for function signature
    let param_defs: Vec<_> = params
        .iter()
        .map(|(name, rust_type, _)| {
            quote! { #name: #rust_type }
        })
        .collect();

    // Build JSON encoding for args
    let arg_encodings: Vec<_> = params
        .iter()
        .map(|(name, _, move_type)| view_arg_encoding(name, move_type))
        .collect();

    // Type arguments
    let has_type_params = !func.generic_type_params.is_empty();

    let type_args_param = if has_type_params {
        quote! { , type_args: Vec<String> }
    } else {
        quote! {}
    };

    let type_args_use = if has_type_params {
        quote! { type_args }
    } else {
        quote! { vec![] }
    };

    // Documentation
    let doc = source_func
        .and_then(|f| f.doc.as_ref())
        .map(|d| format!("{}\n\n", d))
        .unwrap_or_default();
    let full_doc = format!("{}View function: `{}`", doc, function_id);

    quote! {
        #[doc = #full_doc]
        pub async fn #fn_name(
            aptos: &aptos_rust_sdk_v2::Aptos,
            #(#param_defs),*
            #type_args_param
        ) -> aptos_rust_sdk_v2::error::AptosResult<Vec<serde_json::Value>> {
            let args = vec![
                #(#arg_encodings),*
            ];

            aptos.view(#function_id, #type_args_use, args).await
        }
    }
}

/// Generates JSON encoding for a view function argument.
fn view_arg_encoding(name: &Ident, move_type: &str) -> TokenStream {
    match move_type {
        "address" => quote! { serde_json::json!(#name.to_string()) },
        "bool" | "u8" | "u16" | "u32" | "u64" | "u128" => {
            quote! { serde_json::json!(#name.to_string()) }
        }
        t if t.starts_with("vector<u8>") => {
            quote! { serde_json::json!(hex::encode(&#name)) }
        }
        _ => quote! { serde_json::json!(#name) },
    }
}

/// Gets a parameter name from source info or generates one.
fn get_param_name(
    index: usize,
    move_type: &str,
    source_func: Option<&crate::parser::MoveFunctionInfo>,
) -> String {
    // Try to get from source
    if let Some(func) = source_func
        && let Some(name) = func.param_names.get(index)
    {
        return name.clone();
    }

    // Generate from type
    match move_type {
        "&signer" | "signer" => "account".to_string(),
        "address" => "addr".to_string(),
        "u8" | "u16" | "u32" | "u64" | "u128" | "u256" => "amount".to_string(),
        "bool" => "flag".to_string(),
        t if t.starts_with("vector<u8>") => "bytes".to_string(),
        t if t.starts_with("vector<") => "items".to_string(),
        t if t.contains("::string::String") => "name".to_string(),
        t if t.contains("::object::Object") => "object".to_string(),
        _ => format!("arg{}", index),
    }
}

/// Converts a Move type to a Rust type token.
fn move_type_to_rust(move_type: &str) -> TokenStream {
    match move_type {
        "bool" => quote! { bool },
        "u8" => quote! { u8 },
        "u16" => quote! { u16 },
        "u32" => quote! { u32 },
        "u64" => quote! { u64 },
        "u128" => quote! { u128 },
        "u256" => quote! { aptos_rust_sdk_v2::types::U256 },
        "address" | "&signer" | "signer" => quote! { aptos_rust_sdk_v2::types::AccountAddress },
        t if t.starts_with("vector<u8>") => quote! { Vec<u8> },
        t if t.starts_with("vector<") => {
            // Extract inner type
            let inner = &t[7..t.len() - 1];
            let inner_type = move_type_to_rust(inner);
            quote! { Vec<#inner_type> }
        }
        t if t.contains("::string::String") => quote! { String },
        t if t.contains("::option::Option<") => {
            // Extract inner type
            if let Some(start) = t.find("Option<") {
                let rest = &t[start + 7..];
                if let Some(end) = rest.rfind('>') {
                    let inner = &rest[..end];
                    let inner_type = move_type_to_rust(inner);
                    return quote! { Option<#inner_type> };
                }
            }
            quote! { serde_json::Value }
        }
        t if t.contains("::object::Object<") => quote! { aptos_rust_sdk_v2::types::AccountAddress },
        _ => quote! { serde_json::Value },
    }
}

/// Checks if a parameter is a signer type.
fn is_signer_param(move_type: &str) -> bool {
    move_type == "&signer" || move_type == "signer"
}

/// Converts snake_case to PascalCase.
fn to_pascal_case(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = true;

    for c in s.chars() {
        if c == '_' || c == '-' || c == ' ' {
            capitalize_next = true;
        } else if capitalize_next {
            result.push(c.to_ascii_uppercase());
            capitalize_next = false;
        } else {
            result.push(c);
        }
    }

    result
}

/// Converts PascalCase to snake_case.
fn to_snake_case(s: &str) -> String {
    let mut result = String::new();

    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.push(c.to_ascii_lowercase());
        } else {
            result.push(c);
        }
    }

    result
}

/// Makes an identifier safe for Rust.
fn safe_ident(name: &str) -> String {
    let snake = to_snake_case(name);
    match snake.as_str() {
        "type" | "self" | "move" | "ref" | "mut" | "fn" | "mod" | "use" | "pub" | "let" | "if"
        | "else" | "match" | "loop" | "while" | "for" | "in" | "return" | "break" | "continue"
        | "async" | "await" | "struct" | "enum" | "trait" | "impl" | "dyn" | "const" | "static"
        | "unsafe" | "extern" | "crate" | "super" | "where" | "as" | "true" | "false" => {
            format!("r#{}", snake)
        }
        _ => snake,
    }
}
