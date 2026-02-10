//! Procedural macros for type-safe Aptos contract bindings.
//!
//! This crate provides macros for generating Rust bindings from Move module ABIs
//! at compile time.
//!
//! # Example
//!
//! ```rust,ignore
//! use aptos_sdk_macros::aptos_contract;
//!
//! aptos_contract! {
//!     name: CoinModule,
//!     abi: r#"{"address": "0x1", "name": "coin", ...}"#
//! }
//!
//! // Generated:
//! // pub struct CoinModule;
//! // impl CoinModule {
//! //     pub fn transfer(...) -> AptosResult<TransactionPayload> { ... }
//! //     pub async fn view_balance(...) -> AptosResult<Vec<Value>> { ... }
//! // }
//! ```

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{LitStr, parse_macro_input, spanned::Spanned};

mod abi;
mod codegen;
mod parser;

use abi::MoveModuleABI;
use codegen::generate_contract_impl;

/// Generates type-safe contract bindings from an ABI.
///
/// # Syntax
///
/// ```rust,ignore
/// aptos_contract! {
///     name: StructName,
///     abi: "{ ... JSON ABI ... }",
///     // Optional: Move source for better parameter names
///     source: "module 0x1::coin { ... }"
/// }
/// ```
///
/// # Example
///
/// ```rust,ignore
/// use aptos_sdk_macros::aptos_contract;
///
/// aptos_contract! {
///     name: AptosCoin,
///     abi: r#"{
///         "address": "0x1",
///         "name": "aptos_coin",
///         "exposed_functions": [
///             {
///                 "name": "transfer",
///                 "visibility": "public",
///                 "is_entry": true,
///                 "is_view": false,
///                 "generic_type_params": [],
///                 "params": ["&signer", "address", "u64"],
///                 "return": []
///             }
///         ],
///         "structs": []
///     }"#
/// }
///
/// // Now you can use:
/// let payload = AptosCoin::transfer(recipient_addr, 1000)?;
/// ```
#[proc_macro]
pub fn aptos_contract(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as parser::ContractInput);

    // Parse ABI - use the name's span for error reporting since that's a known token
    let abi: MoveModuleABI = match serde_json::from_str(&input.abi) {
        Ok(abi) => abi,
        Err(e) => {
            return syn::Error::new(input.name.span(), format!("Failed to parse ABI JSON: {e}"))
                .to_compile_error()
                .into();
        }
    };

    // Parse optional Move source
    let source_info = input.source.as_ref().map(|s| parser::parse_move_source(s));

    // Generate the implementation
    let tokens = generate_contract_impl(&input.name, &abi, source_info.as_ref());

    tokens.into()
}

/// Generates contract bindings from an ABI file path.
///
/// # Example
///
/// ```rust,ignore
/// use aptos_sdk_macros::aptos_contract_file;
///
/// aptos_contract_file!("abi/my_module.json", MyModule);
/// ```
#[proc_macro]
pub fn aptos_contract_file(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as parser::FileInput);

    // Read the file content at compile time
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let manifest_path = std::path::Path::new(&manifest_dir);
    let file_path = manifest_path.join(&input.path);

    // SECURITY: Verify the resolved path is under CARGO_MANIFEST_DIR to prevent
    // path traversal attacks (e.g., "../../../../etc/passwd")
    if let (Ok(canonical_manifest), Ok(canonical_file)) =
        (manifest_path.canonicalize(), file_path.canonicalize())
        && !canonical_file.starts_with(&canonical_manifest)
    {
        return syn::Error::new(
            input.name.span(),
            format!(
                "ABI file path '{}' resolves outside the project directory",
                input.path
            ),
        )
        .to_compile_error()
        .into();
    }

    let abi_content = match std::fs::read_to_string(&file_path) {
        Ok(content) => content,
        Err(e) => {
            // Use name's span for better error location
            return syn::Error::new(
                input.name.span(),
                format!("Failed to read ABI file '{}': {e}", file_path.display()),
            )
            .to_compile_error()
            .into();
        }
    };

    let abi: MoveModuleABI = match serde_json::from_str(&abi_content) {
        Ok(abi) => abi,
        Err(e) => {
            return syn::Error::new(
                input.name.span(),
                format!(
                    "Failed to parse ABI JSON from '{}': {e}",
                    file_path.display(),
                ),
            )
            .to_compile_error()
            .into();
        }
    };

    // Read optional source file - emit error if source_path is provided but unreadable
    let source_info = if let Some(source_path) = input.source_path.as_ref() {
        let source_file = std::path::Path::new(&manifest_dir).join(source_path);
        match std::fs::read_to_string(&source_file) {
            Ok(content) => Some(parser::parse_move_source(&content)),
            Err(e) => {
                return syn::Error::new(
                    input.name.span(),
                    format!(
                        "Failed to read Move source file '{}': {e}",
                        source_file.display(),
                    ),
                )
                .to_compile_error()
                .into();
            }
        }
    } else {
        None
    };

    let tokens = generate_contract_impl(&input.name, &abi, source_info.as_ref());

    tokens.into()
}

/// Derive macro for Move-compatible struct serialization.
///
/// Implements BCS serialization and the necessary traits for
/// using a Rust struct as a Move struct argument or return type.
///
/// # Example
///
/// ```rust,ignore
/// use aptos_sdk_macros::MoveStruct;
///
/// #[derive(MoveStruct)]
/// #[move_struct(address = "0x1", module = "coin", name = "CoinStore")]
/// pub struct CoinStore {
///     pub coin: u64,
///     pub frozen: bool,
/// }
/// ```
#[proc_macro_derive(MoveStruct, attributes(move_struct))]
pub fn derive_move_struct(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);

    let name = &input.ident;

    // Parse attributes - collect errors to report them properly
    let mut address = None;
    let mut module = None;
    let mut struct_name = None;
    let mut parse_error: Option<syn::Error> = None;

    for attr in &input.attrs {
        if attr.path().is_ident("move_struct") {
            let result = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("address") {
                    let value: LitStr = meta.value()?.parse()?;
                    address = Some(value.value());
                } else if meta.path.is_ident("module") {
                    let value: LitStr = meta.value()?.parse()?;
                    module = Some(value.value());
                } else if meta.path.is_ident("name") {
                    let value: LitStr = meta.value()?.parse()?;
                    struct_name = Some(value.value());
                } else {
                    return Err(syn::Error::new(
                        meta.path.span(),
                        format!(
                            "Unknown attribute '{}'. Expected 'address', 'module', or 'name'",
                            meta.path
                                .get_ident()
                                .map_or_else(|| "?".to_string(), ToString::to_string)
                        ),
                    ));
                }
                Ok(())
            });

            if let Err(e) = result {
                parse_error = Some(e);
                break;
            }
        }
    }

    // Return any parsing errors
    if let Some(e) = parse_error {
        return e.to_compile_error().into();
    }

    let address = address.unwrap_or_else(|| "0x1".to_string());
    let module = module.unwrap_or_else(|| "unknown".to_string());
    let struct_name = struct_name.unwrap_or_else(|| name.to_string());

    let type_tag = format!("{address}::{module}::{struct_name}");
    // Convert String to LitStr for quote! interpolation
    let type_tag_lit = LitStr::new(&type_tag, Span::call_site());

    let expanded = quote! {
        impl #name {
            /// Returns the Move type tag for this struct.
            pub fn type_tag() -> &'static str {
                #type_tag_lit
            }

            /// Serializes this struct to BCS bytes.
            pub fn to_bcs(&self) -> ::aptos_sdk::error::AptosResult<Vec<u8>> {
                ::aptos_sdk::aptos_bcs::to_bytes(self)
                    .map_err(|e| ::aptos_sdk::error::AptosError::Bcs(e.to_string()))
            }

            /// Deserializes this struct from BCS bytes.
            pub fn from_bcs(bytes: &[u8]) -> ::aptos_sdk::error::AptosResult<Self> {
                ::aptos_sdk::aptos_bcs::from_bytes(bytes)
                    .map_err(|e| ::aptos_sdk::error::AptosError::Bcs(e.to_string()))
            }
        }
    };

    expanded.into()
}
