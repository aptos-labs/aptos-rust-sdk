# Core Types

## Overview

The core types module provides fundamental data types used throughout the Aptos SDK. These types handle addresses, hashes, chain identifiers, and Move language type representations.

## Goals

1. Provide type-safe representations of Aptos blockchain primitives
2. Enable efficient serialization/deserialization (BCS and JSON)
3. Support Display and Debug formatting for developer ergonomics
4. Maintain compatibility with on-chain data formats

## Non-Goals

- Cryptographic operations (handled by crypto module)
- Network communication (handled by API clients)
- Transaction logic (handled by transaction module)

---

## API Design

### AccountAddress

A 32-byte address uniquely identifying an account on Aptos.

```rust
/// A 32-byte account address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct AccountAddress([u8; 32]);

impl AccountAddress {
    /// The "zero" address (all zeros).
    pub const ZERO: Self;
    
    /// Address 0x1 (framework address).
    pub const ONE: Self;
    
    /// Address 0x3 (token address).
    pub const THREE: Self;
    
    /// Address 0x4 (objects address).
    pub const FOUR: Self;
    
    /// Create from a 32-byte array.
    pub const fn new(bytes: [u8; 32]) -> Self;
    
    /// Create from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AptosError>;
    
    /// Parse from hex string (with or without 0x prefix).
    pub fn from_hex(hex: &str) -> Result<Self, AptosError>;
    
    /// Get the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32];
    
    /// Convert to hex string with 0x prefix.
    pub fn to_hex(&self) -> String;
    
    /// Convert to short hex (leading zeros removed).
    pub fn to_short_string(&self) -> String;
}

// Trait implementations
impl Display for AccountAddress { ... }  // "0x..." format
impl Debug for AccountAddress { ... }    // Same as Display
impl FromStr for AccountAddress { ... }  // Parse from string
impl Serialize for AccountAddress { ... } // BCS as [u8; 32]
impl<'de> Deserialize<'de> for AccountAddress { ... }
```

### HashValue

A 32-byte cryptographic hash value.

```rust
/// A 32-byte hash value (SHA3-256).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct HashValue([u8; 32]);

impl HashValue {
    /// All zeros hash.
    pub const ZERO: Self;
    
    /// Hash length in bytes.
    pub const LENGTH: usize = 32;
    
    /// Create from bytes.
    pub fn new(bytes: [u8; 32]) -> Self;
    
    /// Create from byte slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, AptosError>;
    
    /// Compute SHA3-256 hash of data.
    pub fn sha3_256_of(data: &[u8]) -> Self;
    
    /// Parse from hex string.
    pub fn from_hex(hex: &str) -> Result<Self, AptosError>;
    
    /// Get underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32];
    
    /// Convert to hex string.
    pub fn to_hex(&self) -> String;
}
```

### ChainId

Network chain identifier.

```rust
/// Aptos chain identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainId(u8);

impl ChainId {
    /// Mainnet chain ID.
    pub const MAINNET: Self = Self(1);
    
    /// Testnet chain ID.
    pub const TESTNET: Self = Self(2);
    
    /// Devnet chain ID (may change).
    pub const DEVNET: Self = Self(3);
    
    /// Local testing chain ID.
    pub const LOCAL: Self = Self(4);
    
    /// Create from u8 value.
    pub const fn new(id: u8) -> Self;
    
    /// Get the numeric value.
    pub fn id(&self) -> u8;
}
```

### U256

256-bit unsigned integer for Move's u256 type.

```rust
/// 256-bit unsigned integer.
#[derive(Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct U256([u64; 4]); // Little-endian limbs

impl U256 {
    pub const ZERO: Self;
    pub const ONE: Self;
    pub const MAX: Self;
    
    pub fn from_u64(value: u64) -> Self;
    pub fn from_u128(value: u128) -> Self;
    pub fn from_bytes_be(bytes: &[u8; 32]) -> Self;
    pub fn from_bytes_le(bytes: &[u8; 32]) -> Self;
    pub fn to_bytes_be(&self) -> [u8; 32];
    pub fn to_bytes_le(&self) -> [u8; 32];
}
```

### TypeTag

Move type representation for generic type arguments.

```rust
/// Representation of a Move type.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum TypeTag {
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    Address,
    Signer,
    Vector(Box<TypeTag>),
    Struct(Box<MoveStructTag>),
}

impl TypeTag {
    /// Create AptosCoin type tag.
    pub fn aptos_coin() -> Self;
    
    /// Parse from string like "0x1::aptos_coin::AptosCoin".
    pub fn from_str(s: &str) -> Result<Self, AptosError>;
}
```

### MoveModuleId

Module identifier (address + name).

```rust
/// Identifies a Move module.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MoveModuleId {
    pub address: AccountAddress,
    pub name: String,
}

impl MoveModuleId {
    pub fn new(address: AccountAddress, name: impl Into<String>) -> Self;
    
    /// Parse from "0x1::module_name" format.
    pub fn from_str_strict(s: &str) -> Result<Self, AptosError>;
}
```

### MoveStructTag

Full struct type with address, module, name, and type parameters.

```rust
/// Full Move struct type.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MoveStructTag {
    pub address: AccountAddress,
    pub module: String,
    pub name: String,
    pub type_args: Vec<TypeTag>,
}

impl MoveStructTag {
    pub fn new(
        address: AccountAddress,
        module: impl Into<String>,
        name: impl Into<String>,
        type_args: Vec<TypeTag>,
    ) -> Self;
    
    /// Parse from "0x1::module::Struct<T>" format.
    pub fn from_str(s: &str) -> Result<Self, AptosError>;
}
```

---

## Implementation Details

### Serialization Strategy

1. **BCS Serialization**: Used for on-chain data and transaction signing
   - `AccountAddress`: Serialized as raw 32 bytes
   - `TypeTag`: Enum with variant index prefix
   - `MoveStructTag`: Struct fields in order

2. **JSON Serialization**: Used for REST API communication
   - `AccountAddress`: Hex string with "0x" prefix
   - `TypeTag`: String representation
   - `MoveStructTag`: Object with fields

### Address Parsing Rules

```
Valid formats:
- "0x1"                    → Pads to 32 bytes (framework address)
- "0x0000...0001"          → Full 64 hex chars
- "1"                      → Same as "0x1"
- "0x1234abcd..."          → Standard hex

Invalid:
- "0x" (empty)
- "0xGG" (invalid hex)
- "0x" + 65+ chars (too long)
```

### TypeTag Parsing Grammar

```
TypeTag = "bool" | "u8" | "u16" | "u32" | "u64" | "u128" | "u256"
        | "address" | "signer"
        | "vector<" TypeTag ">"
        | StructTag

StructTag = Address "::" ModuleName "::" StructName TypeArgs?
TypeArgs = "<" TypeTag ("," TypeTag)* ">"
```

---

## Error Handling

| Error | Cause | Message |
|-------|-------|---------|
| `InvalidAddress` | Bad hex format | "Invalid address: {details}" |
| `InvalidHex` | Non-hex characters | "Invalid hex character at position {n}" |
| `InvalidLength` | Wrong byte count | "Expected 32 bytes, got {n}" |
| `ParseError` | TypeTag parse failure | "Failed to parse type: {input}" |

---

## Testing Requirements

### Unit Tests

```rust
#[test]
fn test_address_from_hex() {
    // Standard hex
    let addr = AccountAddress::from_hex("0x1").unwrap();
    assert_eq!(addr, AccountAddress::ONE);
    
    // Full hex
    let full = "0x0000000000000000000000000000000000000000000000000000000000000001";
    let addr2 = AccountAddress::from_hex(full).unwrap();
    assert_eq!(addr, addr2);
    
    // Without prefix
    let addr3 = AccountAddress::from_hex("1").unwrap();
    assert_eq!(addr, addr3);
}

#[test]
fn test_address_display() {
    assert_eq!(AccountAddress::ONE.to_string(), "0x0000...0001");
    assert_eq!(AccountAddress::ONE.to_short_string(), "0x1");
}

#[test]
fn test_type_tag_parsing() {
    let tag = TypeTag::from_str("0x1::aptos_coin::AptosCoin").unwrap();
    assert!(matches!(tag, TypeTag::Struct(_)));
    
    let vector = TypeTag::from_str("vector<u8>").unwrap();
    assert!(matches!(vector, TypeTag::Vector(_)));
}

#[test]
fn test_bcs_serialization() {
    let addr = AccountAddress::ONE;
    let bytes = aptos_bcs::to_bytes(&addr).unwrap();
    assert_eq!(bytes.len(), 32);
    
    let decoded: AccountAddress = aptos_bcs::from_bytes(&bytes).unwrap();
    assert_eq!(addr, decoded);
}
```

### Property Tests

- Address round-trip: `from_hex(to_hex(addr)) == addr`
- TypeTag round-trip: `from_str(to_string(tag)) == tag`
- BCS round-trip for all types

---

## Security Considerations

1. **Address Validation**: Always validate address length and format
2. **No Address Arithmetic**: Addresses are opaque identifiers, not numbers
3. **Constant-Time Comparison**: Use constant-time comparison for security-sensitive contexts

---

## Dependencies

### External Crates
- `aptos-bcs`: BCS serialization
- `serde`: Serialization traits
- `hex`: Hex encoding/decoding

### Internal Modules
- None (this is a foundational module)

---

## Open Questions

1. Should `AccountAddress` implement `From<[u8; 32]>`? (Decided: Yes, for ergonomics)
2. Should we support non-standard address formats? (Decided: No, strict parsing only)
3. Should `U256` support arithmetic operations? (Decided: Basic ops only, not full math)

