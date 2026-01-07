# Feature Plan: ANS (Aptos Names Service) Integration

## Overview

ANS (Aptos Names Service) is the naming service for Aptos, similar to ENS on Ethereum. It allows users to register human-readable names (like `alice.apt`) that map to their addresses. This feature provides SDK integration for ANS name resolution.

## Goals

1. **Resolve names to addresses** - Convert `.apt` names to `AccountAddress`
2. **Reverse lookup** - Get the primary name for an address
3. **Check availability** - Determine if a name is available for registration
4. **Convenience methods** - Accept either address or name in API calls
5. **Network awareness** - Automatically use correct ANS contract addresses per network

## API Design

### AnsClient

```rust
/// Client for interacting with the Aptos Names Service.
pub struct AnsClient {
    fullnode: Arc<FullnodeClient>,
    ans_address: AccountAddress,
    network: Network,
}

impl AnsClient {
    /// Creates a new ANS client.
    pub fn new(config: AptosConfig) -> AptosResult<Self>;

    /// Creates an ANS client from an existing fullnode client.
    pub fn from_fullnode(fullnode: Arc<FullnodeClient>, network: Network) -> AptosResult<Self>;

    /// Resolves an ANS name to an address.
    pub async fn get_address(&self, name: &str) -> AptosResult<Option<AccountAddress>>;

    /// Gets the primary ANS name for an address.
    pub async fn get_primary_name(&self, address: AccountAddress) -> AptosResult<Option<String>>;

    /// Checks if an ANS name is available for registration.
    pub async fn is_name_available(&self, name: &str) -> AptosResult<bool>;

    /// Gets the expiration timestamp for a domain.
    pub async fn get_expiration(&self, name: &str) -> AptosResult<Option<u64>>;

    /// Resolves an address or ANS name to an address.
    pub async fn resolve(&self, address_or_name: &str) -> AptosResult<AccountAddress>;
}
```

### Aptos Client Integration

```rust
impl Aptos {
    /// Returns the ANS client, if available.
    pub fn ans(&self) -> Option<&AnsClient>;

    /// Resolves an ANS name to an address.
    pub async fn resolve_name(&self, name: &str) -> AptosResult<Option<AccountAddress>>;

    /// Gets the primary ANS name for an address.
    pub async fn get_primary_name(&self, address: AccountAddress) -> AptosResult<Option<String>>;

    /// Resolves an address or ANS name to an address.
    pub async fn resolve(&self, address_or_name: &str) -> AptosResult<AccountAddress>;

    /// Checks if an ANS name is available for registration.
    pub async fn is_name_available(&self, name: &str) -> AptosResult<bool>;
}
```

### AnsResolvable Trait

```rust
/// Extension trait for types that can be resolved via ANS.
pub trait AnsResolvable {
    /// Resolves this value to an AccountAddress.
    fn resolve_address(&self, ans: &AnsClient) -> impl Future<Output = AptosResult<AccountAddress>>;
}

// Implemented for:
impl AnsResolvable for str { ... }
impl AnsResolvable for String { ... }
impl AnsResolvable for AccountAddress { ... }
```

## Implementation Details

### ANS Contract Addresses

| Network | Contract Address |
|---------|-----------------|
| Mainnet | `0x867ed1f6bf916171b1de3ee92849b8978b7d1b9e0a8cc982a3d19d535dfd9c0c` |
| Testnet | `0x5f8fd2347449685cf41d4db97926ec3a096eaf381c397f0e3d7cbc17fbdd0bce` |

### Name Parsing

Names are parsed to extract domain and optional subdomain:
- `alice` → domain: "alice", subdomain: None
- `alice.apt` → domain: "alice", subdomain: None
- `sub.alice` → domain: "alice", subdomain: "sub"
- `sub.alice.apt` → domain: "alice", subdomain: "sub"

### View Functions Used

1. **`get_target_addr(domain, subdomain)`** - Resolves name to address
2. **`get_reverse_lookup(address)`** - Gets primary name for address
3. **`get_expiration(domain, subdomain)`** - Gets domain expiration

### Network Availability

ANS is only available on:
- **Mainnet** - Production ANS
- **Testnet** - Test ANS for development

For devnet and local networks, ANS methods will return an error indicating the feature is not available.

## Usage Examples

### Basic Name Resolution

```rust
let aptos = Aptos::mainnet()?;

// Resolve name to address
if let Some(addr) = aptos.resolve_name("alice.apt").await? {
    println!("alice.apt -> {}", addr);
}

// Reverse lookup
if let Some(name) = aptos.get_primary_name(addr).await? {
    println!("{} -> {}", addr, name);
}
```

### Universal Resolve

```rust
let aptos = Aptos::mainnet()?;

// Works with either addresses or names
let addr = aptos.resolve("alice.apt").await?;
let addr = aptos.resolve("0x1234...").await?;
```

### Using AnsClient Directly

```rust
let ans = AnsClient::new(AptosConfig::mainnet())?;

// Check availability
if ans.is_name_available("myname").await? {
    println!("myname.apt is available!");
}

// Get expiration
if let Some(exp) = ans.get_expiration("alice").await? {
    println!("alice.apt expires at: {}", exp);
}
```

### With Subdomains

```rust
let ans = AnsClient::new(AptosConfig::mainnet())?;

// Resolve subdomain
let addr = ans.get_address("work.alice.apt").await?;
```

## Testing

### Unit Tests

1. **Name parsing**
   - Simple names (`alice`)
   - Names with TLD (`alice.apt`)
   - Subdomains (`sub.alice.apt`)
   - Case insensitivity
   - Invalid names

2. **Name validation**
   - Valid characters (alphanumeric, hyphens)
   - Invalid characters (special chars, spaces)
   - Length limits
   - Edge cases (empty, too long)

3. **Address constant validation**
   - Verify mainnet/testnet addresses are valid

### Integration Tests (requires network)

1. **Mainnet name resolution**
   - Resolve known names
   - Handle non-existent names
   - Reverse lookup

2. **Error handling**
   - Network errors
   - Invalid network (devnet)
   - Malformed responses

## Future Enhancements

1. **Name registration** - Build transactions to register names
2. **Subdomain management** - Create/transfer subdomains
3. **Domain transfer** - Transfer ownership
4. **Set target address** - Update where a name points
5. **Set primary name** - Update primary name for address
6. **Caching** - Cache resolved names to reduce API calls
7. **Batch resolution** - Resolve multiple names in one call

## Dependencies

- Uses existing `FullnodeClient` for view function calls
- No additional external dependencies

## Files Changed

1. `src/api/ans.rs` - New ANS client implementation
2. `src/api/mod.rs` - Export ANS types
3. `src/aptos.rs` - Add ANS methods to main client
4. `src/lib.rs` - Documentation updates
5. `feature-plans/17-ans-integration.md` - This document

