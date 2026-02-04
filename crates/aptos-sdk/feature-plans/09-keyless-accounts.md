# Keyless Accounts

## Overview

Support for keyless accounts that use OpenID Connect (OIDC) authentication instead of cryptographic keys.

## Status: ✅ Implemented

## Goals

1. Support Google, Apple, and other OIDC providers
2. Enable account recovery via email/social login
3. Zero-knowledge proof generation for privacy
4. Integration with Aptos keyless infrastructure

## Non-Goals

- Running OIDC provider (use existing providers)
- Storing user credentials (handled by OIDC flow)
- Supporting non-OIDC authentication

---

## Background

Keyless accounts allow users to authenticate using their existing identity providers (Google, Apple, etc.) without managing cryptographic keys. The authentication flow uses:

1. **JWT Token**: User authenticates with OIDC provider
2. **Ephemeral Key**: Short-lived key for signing
3. **ZK Proof**: Proves JWT validity without revealing details
4. **Pepper Service**: Provides privacy-preserving salt

---

## API Design

### KeylessAccount

```rust
/// Account authenticated via OIDC.
pub struct KeylessAccount {
    /// Ephemeral key pair for signing.
    ephemeral_key: EphemeralKeyPair,
    /// OIDC provider identifier.
    provider: OidcProvider,
    /// User's unique identifier (sub claim).
    user_id: String,
    /// Zero-knowledge proof.
    proof: Option<ZkProof>,
    /// Account address.
    address: AccountAddress,
}

impl KeylessAccount {
    /// Create from OIDC JWT token.
    pub async fn from_jwt(
        jwt: &str,
        ephemeral_key: EphemeralKeyPair,
        pepper_service: &PepperService,
        prover_service: &ProverService,
    ) -> Result<Self, AptosError>;
    
    /// Get the OIDC provider.
    pub fn provider(&self) -> OidcProvider;
    
    /// Check if proof is valid (not expired).
    pub fn is_valid(&self) -> bool;
    
    /// Refresh the proof.
    pub async fn refresh_proof(
        &mut self,
        jwt: &str,
        prover_service: &ProverService,
    ) -> Result<(), AptosError>;
}

impl Account for KeylessAccount {
    fn address(&self) -> AccountAddress;
    fn public_key_bytes(&self) -> Vec<u8>;
    fn signature_scheme(&self) -> SignatureScheme;
    fn sign(&self, message: &[u8]) -> Vec<u8>;
    fn authentication_key(&self) -> AuthenticationKey;
}
```

### EphemeralKeyPair

```rust
/// Short-lived key pair for keyless signing.
pub struct EphemeralKeyPair {
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    expiry: SystemTime,
    nonce: String,
}

impl EphemeralKeyPair {
    /// Generate with specified expiry.
    pub fn generate(expiry_secs: u64) -> Self;
    
    /// Check if expired.
    pub fn is_expired(&self) -> bool;
    
    /// Get the nonce for OIDC authentication.
    pub fn nonce(&self) -> &str;
}
```

### OidcProvider

```rust
/// Supported OIDC providers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OidcProvider {
    Google,
    Apple,
    Microsoft,
    Custom(String),
}

impl OidcProvider {
    /// Get the issuer URL.
    pub fn issuer(&self) -> &str;
    
    /// Get the JWKS URL.
    pub fn jwks_url(&self) -> &str;
}
```

### Services

```rust
/// Service for obtaining pepper values.
pub struct PepperService {
    url: Url,
    client: reqwest::Client,
}

impl PepperService {
    /// Get pepper for a JWT.
    pub async fn get_pepper(&self, jwt: &str) -> Result<Pepper, AptosError>;
}

/// Service for generating ZK proofs.
pub struct ProverService {
    url: Url,
    client: reqwest::Client,
}

impl ProverService {
    /// Generate proof for keyless authentication.
    pub async fn generate_proof(
        &self,
        jwt: &str,
        ephemeral_key: &EphemeralKeyPair,
        pepper: &Pepper,
    ) -> Result<ZkProof, AptosError>;
}
```

---

## Authentication Flow

```
1. User clicks "Sign in with Google"
         ↓
2. Generate ephemeral key pair with nonce
         ↓
3. Redirect to Google OAuth with nonce
         ↓
4. User authenticates, receives JWT
         ↓
5. Send JWT to Pepper Service → get pepper
         ↓
6. Send JWT + ephemeral key + pepper to Prover → get ZK proof
         ↓
7. Create KeylessAccount with proof
         ↓
8. Sign transactions with ephemeral key + proof
```

---

## Address Derivation

```
Keyless Address = sha3_256(
    iss_hash || audience_hash || uid_hash || pepper || 0x05
)

where:
- iss_hash = sha3_256(issuer)
- audience_hash = sha3_256(client_id)  
- uid_hash = sha3_256(user_id)
- 0x05 = Keyless scheme identifier
```

---

## Testing Requirements

```rust
#[tokio::test]
async fn test_keyless_account_creation() {
    let ephemeral = EphemeralKeyPair::generate(3600);
    let mock_jwt = create_test_jwt(&ephemeral.nonce());
    
    let pepper_service = MockPepperService::new();
    let prover_service = MockProverService::new();
    
    let account = KeylessAccount::from_jwt(
        &mock_jwt,
        ephemeral,
        &pepper_service,
        &prover_service,
    ).await.unwrap();
    
    assert!(!account.address().is_zero());
}
```

---

## Security Considerations

1. **Ephemeral Key Expiry**: Keys should expire (max 24 hours)
2. **JWT Validation**: Verify JWT signature and claims before calling `from_jwt`
3. **Pepper Privacy**: Never expose pepper values
4. **Proof Freshness**: Proofs have limited validity

---

## Dependencies

- Ed25519 crypto module
- HTTP client (reqwest)
- JWT parsing library
- ZK proof verification (future)
