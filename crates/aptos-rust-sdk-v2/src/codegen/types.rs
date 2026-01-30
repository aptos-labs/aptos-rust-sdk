//! Type mapping between Move and Rust types.

use std::collections::HashMap;

/// A Rust type representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustType {
    /// The full type path (e.g., "`Vec<u8>`", "AccountAddress").
    pub path: String,
    /// Whether this type requires BCS serialization as an argument.
    pub needs_bcs: bool,
    /// Whether this type is a reference.
    pub is_ref: bool,
    /// Documentation for this type.
    pub doc: Option<String>,
}

impl RustType {
    /// Creates a new Rust type.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            needs_bcs: true,
            is_ref: false,
            doc: None,
        }
    }

    /// Creates a type that doesn't need BCS serialization.
    pub fn primitive(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            needs_bcs: false,
            is_ref: false,
            doc: None,
        }
    }

    /// Creates a reference type.
    pub fn reference(mut self) -> Self {
        self.is_ref = true;
        self
    }

    /// Adds documentation.
    pub fn with_doc(mut self, doc: impl Into<String>) -> Self {
        self.doc = Some(doc.into());
        self
    }

    /// Returns the type as a function argument type.
    pub fn as_arg_type(&self) -> String {
        if self.is_ref {
            format!("&{}", self.path)
        } else {
            self.path.clone()
        }
    }

    /// Returns the type as a return type.
    pub fn as_return_type(&self) -> String {
        self.path.clone()
    }
}

/// Maps Move types to Rust types.
#[derive(Debug, Clone)]
pub struct MoveTypeMapper {
    /// Custom type mappings.
    custom_mappings: HashMap<String, RustType>,
}

impl Default for MoveTypeMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl MoveTypeMapper {
    /// Creates a new type mapper with default mappings.
    pub fn new() -> Self {
        Self {
            custom_mappings: HashMap::new(),
        }
    }

    /// Adds a custom type mapping.
    pub fn add_mapping(&mut self, move_type: impl Into<String>, rust_type: RustType) {
        self.custom_mappings.insert(move_type.into(), rust_type);
    }

    /// Maps a Move type string to a Rust type.
    pub fn map_type(&self, move_type: &str) -> RustType {
        // Check custom mappings first
        if let Some(rust_type) = self.custom_mappings.get(move_type) {
            return rust_type.clone();
        }

        // Handle primitive types
        match move_type {
            "bool" => RustType::primitive("bool"),
            "u8" => RustType::primitive("u8"),
            "u16" => RustType::primitive("u16"),
            "u32" => RustType::primitive("u32"),
            "u64" => RustType::primitive("u64"),
            "u128" => RustType::primitive("u128"),
            "u256" => RustType::new("U256"),
            "address" => RustType::new("AccountAddress"),
            "signer" | "&signer" => RustType::new("AccountAddress")
                .with_doc("Signer address (automatically set to sender)"),
            _ => self.map_complex_type(move_type),
        }
    }

    /// Maps complex Move types (vectors, structs, etc.)
    fn map_complex_type(&self, move_type: &str) -> RustType {
        // Handle vector types
        if move_type.starts_with("vector<") && move_type.ends_with('>') {
            let inner = &move_type[7..move_type.len() - 1];
            let inner_type = self.map_type(inner);

            // Special case: `vector<u8>` -> `Vec<u8>` (bytes)
            if inner == "u8" {
                return RustType::new("Vec<u8>").with_doc("Bytes");
            }

            return RustType::new(format!("Vec<{}>", inner_type.path));
        }

        // Handle Option types (0x1::option::Option<T>)
        if move_type.contains("::option::Option<")
            && let Some(start) = move_type.find("Option<")
        {
            let rest = &move_type[start + 7..];
            if let Some(end) = rest.rfind('>') {
                let inner = &rest[..end];
                let inner_type = self.map_type(inner);
                return RustType::new(format!("Option<{}>", inner_type.path));
            }
        }

        // Handle String type
        if move_type == "0x1::string::String" || move_type.ends_with("::string::String") {
            return RustType::new("String");
        }

        // Handle Object types
        if move_type.contains("::object::Object<") {
            return RustType::new("AccountAddress").with_doc("Object address");
        }

        // Handle generic struct types (e.g., 0x1::coin::Coin<0x1::aptos_coin::AptosCoin>)
        if move_type.contains("::") {
            // Extract the struct name for the Rust type
            let parts: Vec<&str> = move_type.split("::").collect();
            if parts.len() >= 3 {
                // Get the base struct name (without generics)
                let struct_name = parts.last().unwrap();
                let base_name = struct_name.split('<').next().unwrap_or(struct_name);

                // Create a pascal case name
                let rust_name = to_pascal_case(base_name);
                return RustType::new(rust_name).with_doc(format!("Move type: {move_type}"));
            }
        }

        // Default: use serde_json::Value for unknown types
        RustType::new("serde_json::Value").with_doc(format!("Unknown Move type: {move_type}"))
    }

    /// Maps a Move type to a BCS argument encoding expression.
    pub fn to_bcs_arg(&self, move_type: &str, var_name: &str) -> String {
        let rust_type = self.map_type(move_type);

        if !rust_type.needs_bcs {
            // Primitives that don't need special handling
            return format!("aptos_bcs::to_bytes(&{var_name}).unwrap()");
        }

        match move_type {
            "address" => format!("aptos_bcs::to_bytes(&{var_name}).unwrap()"),
            _ if move_type.starts_with("vector<u8>") => {
                format!("aptos_bcs::to_bytes(&{var_name}).unwrap()")
            }
            _ if move_type.starts_with("vector<") => {
                format!("aptos_bcs::to_bytes(&{var_name}).unwrap()")
            }
            "0x1::string::String" => format!("aptos_bcs::to_bytes(&{var_name}).unwrap()"),
            _ if move_type.ends_with("::string::String") => {
                format!("aptos_bcs::to_bytes(&{var_name}).unwrap()")
            }
            _ => format!("aptos_bcs::to_bytes(&{var_name}).unwrap()"),
        }
    }

    /// Determines if a parameter should be excluded from the function signature.
    /// (e.g., &signer is always the sender)
    pub fn is_signer_param(&self, move_type: &str) -> bool {
        move_type == "&signer" || move_type == "signer"
    }
}

/// Converts a snake_case or other string to PascalCase.
pub fn to_pascal_case(s: &str) -> String {
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

/// Converts a PascalCase or other string to snake_case.
pub fn to_snake_case(s: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_mapping() {
        let mapper = MoveTypeMapper::new();

        assert_eq!(mapper.map_type("bool").path, "bool");
        assert_eq!(mapper.map_type("u8").path, "u8");
        assert_eq!(mapper.map_type("u64").path, "u64");
        assert_eq!(mapper.map_type("u128").path, "u128");
        assert_eq!(mapper.map_type("address").path, "AccountAddress");
    }

    #[test]
    fn test_vector_mapping() {
        let mapper = MoveTypeMapper::new();

        assert_eq!(mapper.map_type("vector<u8>").path, "Vec<u8>");
        assert_eq!(
            mapper.map_type("vector<address>").path,
            "Vec<AccountAddress>"
        );
        assert_eq!(mapper.map_type("vector<u64>").path, "Vec<u64>");
    }

    #[test]
    fn test_string_mapping() {
        let mapper = MoveTypeMapper::new();

        assert_eq!(mapper.map_type("0x1::string::String").path, "String");
    }

    #[test]
    fn test_to_pascal_case() {
        assert_eq!(to_pascal_case("hello_world"), "HelloWorld");
        assert_eq!(to_pascal_case("coin"), "Coin");
        assert_eq!(to_pascal_case("aptos_coin"), "AptosCoin");
    }

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("HelloWorld"), "hello_world");
        assert_eq!(to_snake_case("Coin"), "coin");
        assert_eq!(to_snake_case("AptosCoin"), "aptos_coin");
    }
}
