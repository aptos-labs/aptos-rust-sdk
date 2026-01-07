//! Procedural macros for type-safe Aptos contract bindings.
//!
//! This crate provides macros for generating Rust bindings from Move module ABIs
//! at compile time.
//!
//! # Example
//!
//! ```rust,ignore
//! use aptos_rust_sdk_v2_macros::aptos_contract;
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
use quote::{format_ident, quote};
use syn::{parse_macro_input, LitStr, Token};

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
/// use aptos_rust_sdk_v2_macros::aptos_contract;
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

    // Parse ABI
    let abi: MoveModuleABI = match serde_json::from_str(&input.abi) {
        Ok(abi) => abi,
        Err(e) => {
            return syn::Error::new_spanned(
                proc_macro2::TokenStream::new(),
                format!("Failed to parse ABI JSON: {}", e),
            )
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
/// use aptos_rust_sdk_v2_macros::aptos_contract_file;
///
/// aptos_contract_file!("abi/my_module.json", MyModule);
/// ```
#[proc_macro]
pub fn aptos_contract_file(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as parser::FileInput);

    // Read the file content at compile time
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let file_path = std::path::Path::new(&manifest_dir).join(&input.path);

    let abi_content = match std::fs::read_to_string(&file_path) {
        Ok(content) => content,
        Err(e) => {
            return syn::Error::new_spanned(
                proc_macro2::TokenStream::new(),
                format!("Failed to read ABI file '{}': {}", file_path.display(), e),
            )
            .to_compile_error()
            .into();
        }
    };

    let abi: MoveModuleABI = match serde_json::from_str(&abi_content) {
        Ok(abi) => abi,
        Err(e) => {
            return syn::Error::new_spanned(
                proc_macro2::TokenStream::new(),
                format!("Failed to parse ABI JSON from '{}': {}", file_path.display(), e),
            )
            .to_compile_error()
            .into();
        }
    };

    // Read optional source file
    let source_info = input.source_path.as_ref().and_then(|source_path| {
        let source_file = std::path::Path::new(&manifest_dir).join(source_path);
        std::fs::read_to_string(&source_file)
            .ok()
            .map(|content| parser::parse_move_source(&content))
    });

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
/// use aptos_rust_sdk_v2_macros::MoveStruct;
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

    // Parse attributes
    let mut address = None;
    let mut module = None;
    let mut struct_name = None;

    for attr in &input.attrs {
        if attr.path().is_ident("move_struct") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("address") {
                    let value: LitStr = meta.value()?.parse()?;
                    address = Some(value.value());
                } else if meta.path.is_ident("module") {
                    let value: LitStr = meta.value()?.parse()?;
                    module = Some(value.value());
                } else if meta.path.is_ident("name") {
                    let value: LitStr = meta.value()?.parse()?;
                    struct_name = Some(value.value());
                }
                Ok(())
            });
        }
    }

    let address = address.unwrap_or_else(|| "0x1".to_string());
    let module = module.unwrap_or_else(|| "unknown".to_string());
    let struct_name = struct_name.unwrap_or_else(|| name.to_string());

    let type_tag = format!("{}::{}::{}", address, module, struct_name);

    let expanded = quote! {
        impl #name {
            /// Returns the Move type tag for this struct.
            pub fn type_tag() -> &'static str {
                #type_tag
            }

            /// Serializes this struct to BCS bytes.
            pub fn to_bcs(&self) -> aptos_rust_sdk_v2::error::AptosResult<Vec<u8>> {
                aptos_bcs::to_bytes(self)
                    .map_err(|e| aptos_rust_sdk_v2::error::AptosError::Bcs(e.to_string()))
            }

            /// Deserializes this struct from BCS bytes.
            pub fn from_bcs(bytes: &[u8]) -> aptos_rust_sdk_v2::error::AptosResult<Self> {
                aptos_bcs::from_bytes(bytes)
                    .map_err(|e| aptos_rust_sdk_v2::error::AptosError::Bcs(e.to_string()))
            }
        }
    };

    expanded.into()
}

