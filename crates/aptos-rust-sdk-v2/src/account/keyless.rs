//! Keyless (OIDC-based) account support.

use crate::account::account::{Account, AuthenticationKey};
use crate::crypto::{Ed25519PrivateKey, Ed25519PublicKey, KEYLESS_SCHEME};
use crate::error::{AptosError, AptosResult};
use crate::types::AccountAddress;
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

/// Keyless signature payload for transaction authentication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeylessSignature {
    /// Ephemeral public key bytes.
    pub ephemeral_public_key: Vec<u8>,
    /// Signature produced by the ephemeral key.
    pub ephemeral_signature: Vec<u8>,
    /// Zero-knowledge proof bytes.
    pub proof: Vec<u8>,
}

impl KeylessSignature {
    /// Serializes the signature using BCS.
    pub fn to_bcs(&self) -> AptosResult<Vec<u8>> {
        aptos_bcs::to_bytes(self).map_err(AptosError::bcs)
    }
}

/// Short-lived key pair used for keyless signing.
#[derive(Clone)]
pub struct EphemeralKeyPair {
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    expiry: SystemTime,
    nonce: String,
}

impl EphemeralKeyPair {
    /// Generates a new ephemeral key pair with the given expiry (in seconds).
    pub fn generate(expiry_secs: u64) -> Self {
        let private_key = Ed25519PrivateKey::generate();
        let public_key = private_key.public_key();
        let nonce = {
            let mut bytes = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            hex::encode(bytes)
        };
        Self {
            private_key,
            public_key,
            expiry: SystemTime::now() + Duration::from_secs(expiry_secs),
            nonce,
        }
    }

    /// Returns true if the key pair has expired.
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expiry
    }

    /// Returns the nonce associated with this key pair.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Returns the public key.
    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }
}

impl fmt::Debug for EphemeralKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralKeyPair")
            .field("public_key", &self.public_key)
            .field("expiry", &self.expiry)
            .field("nonce", &self.nonce)
            .finish_non_exhaustive()
    }
}

/// Supported OIDC providers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OidcProvider {
    /// Google identity provider.
    Google,
    /// Apple identity provider.
    Apple,
    /// Microsoft identity provider.
    Microsoft,
    /// Custom OIDC provider.
    Custom {
        /// Issuer URL.
        issuer: String,
        /// JWKS URL.
        jwks_url: String,
    },
}

impl OidcProvider {
    /// Returns the issuer URL.
    pub fn issuer(&self) -> &str {
        match self {
            OidcProvider::Google => "https://accounts.google.com",
            OidcProvider::Apple => "https://appleid.apple.com",
            OidcProvider::Microsoft => "https://login.microsoftonline.com/common/v2.0",
            OidcProvider::Custom { issuer, .. } => issuer,
        }
    }

    /// Returns the JWKS URL.
    pub fn jwks_url(&self) -> &str {
        match self {
            OidcProvider::Google => "https://www.googleapis.com/oauth2/v3/certs",
            OidcProvider::Apple => "https://appleid.apple.com/auth/keys",
            OidcProvider::Microsoft => {
                "https://login.microsoftonline.com/common/discovery/v2.0/keys"
            }
            OidcProvider::Custom { jwks_url, .. } => jwks_url,
        }
    }

    /// Infers a provider from an issuer URL.
    pub fn from_issuer(issuer: &str) -> Self {
        match issuer {
            "https://accounts.google.com" => OidcProvider::Google,
            "https://appleid.apple.com" => OidcProvider::Apple,
            "https://login.microsoftonline.com/common/v2.0" => OidcProvider::Microsoft,
            _ => OidcProvider::Custom {
                issuer: issuer.to_string(),
                jwks_url: format!("{issuer}/.well-known/jwks.json"),
            },
        }
    }
}

/// Pepper bytes used in keyless address derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pepper(Vec<u8>);

impl Pepper {
    /// Creates a new pepper from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the pepper as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Creates a pepper from hex.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        Ok(Self(hex::decode(hex_str)?))
    }

    /// Returns the pepper as hex.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.0))
    }
}

/// Zero-knowledge proof bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkProof(Vec<u8>);

impl ZkProof {
    /// Creates a new proof from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the proof as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Creates a proof from hex.
    pub fn from_hex(hex_str: &str) -> AptosResult<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        Ok(Self(hex::decode(hex_str)?))
    }

    /// Returns the proof as hex.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.0))
    }
}

/// Service for obtaining pepper values.
#[async_trait]
pub trait PepperService: Send + Sync {
    /// Fetches the pepper for a JWT.
    async fn get_pepper(&self, jwt: &str) -> AptosResult<Pepper>;
}

/// Service for generating zero-knowledge proofs.
#[async_trait]
pub trait ProverService: Send + Sync {
    /// Generates the proof for keyless authentication.
    async fn generate_proof(
        &self,
        jwt: &str,
        ephemeral_key: &EphemeralKeyPair,
        pepper: &Pepper,
    ) -> AptosResult<ZkProof>;
}

/// HTTP pepper service client.
#[derive(Clone, Debug)]
pub struct HttpPepperService {
    url: Url,
    client: reqwest::Client,
}

impl HttpPepperService {
    /// Creates a new HTTP pepper service client.
    pub fn new(url: Url) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
        }
    }
}

#[derive(Serialize)]
struct PepperRequest<'a> {
    jwt: &'a str,
}

#[derive(Deserialize)]
struct PepperResponse {
    pepper: String,
}

#[async_trait]
impl PepperService for HttpPepperService {
    async fn get_pepper(&self, jwt: &str) -> AptosResult<Pepper> {
        let response = self
            .client
            .post(self.url.clone())
            .json(&PepperRequest { jwt })
            .send()
            .await?
            .error_for_status()?;

        let payload: PepperResponse = response.json().await?;
        Pepper::from_hex(&payload.pepper)
    }
}

/// HTTP prover service client.
#[derive(Clone, Debug)]
pub struct HttpProverService {
    url: Url,
    client: reqwest::Client,
}

impl HttpProverService {
    /// Creates a new HTTP prover service client.
    pub fn new(url: Url) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
        }
    }
}

#[derive(Serialize)]
struct ProverRequest<'a> {
    jwt: &'a str,
    ephemeral_public_key: String,
    nonce: &'a str,
    pepper: String,
}

#[derive(Deserialize)]
struct ProverResponse {
    proof: String,
}

#[async_trait]
impl ProverService for HttpProverService {
    async fn generate_proof(
        &self,
        jwt: &str,
        ephemeral_key: &EphemeralKeyPair,
        pepper: &Pepper,
    ) -> AptosResult<ZkProof> {
        let request = ProverRequest {
            jwt,
            ephemeral_public_key: format!("0x{}", hex::encode(ephemeral_key.public_key.to_bytes())),
            nonce: ephemeral_key.nonce(),
            pepper: pepper.to_hex(),
        };

        let response = self
            .client
            .post(self.url.clone())
            .json(&request)
            .send()
            .await?
            .error_for_status()?;

        let payload: ProverResponse = response.json().await?;
        ZkProof::from_hex(&payload.proof)
    }
}

/// Account authenticated via OIDC.
pub struct KeylessAccount {
    ephemeral_key: EphemeralKeyPair,
    provider: OidcProvider,
    issuer: String,
    audience: String,
    user_id: String,
    pepper: Pepper,
    proof: ZkProof,
    address: AccountAddress,
    auth_key: AuthenticationKey,
    jwt_expiration: Option<SystemTime>,
}

impl KeylessAccount {
    /// Creates a keyless account from an OIDC JWT token.
    ///
    /// Note: JWT signature validation is not performed. Validate the JWT
    /// using the OIDC provider before calling this method.
    pub async fn from_jwt(
        jwt: &str,
        ephemeral_key: EphemeralKeyPair,
        pepper_service: &dyn PepperService,
        prover_service: &dyn ProverService,
    ) -> AptosResult<Self> {
        let claims = decode_claims(jwt)?;
        let (issuer, audience, user_id, exp, nonce) = extract_claims(&claims)?;

        if nonce != ephemeral_key.nonce() {
            return Err(AptosError::InvalidJwt("JWT nonce mismatch".into()));
        }

        let pepper = pepper_service.get_pepper(jwt).await?;
        let proof = prover_service
            .generate_proof(jwt, &ephemeral_key, &pepper)
            .await?;

        let address = derive_keyless_address(&issuer, &audience, &user_id, &pepper);
        let auth_key = AuthenticationKey::new(address.to_bytes());

        Ok(Self {
            provider: OidcProvider::from_issuer(&issuer),
            issuer,
            audience,
            user_id,
            pepper,
            proof,
            address,
            auth_key,
            jwt_expiration: exp,
            ephemeral_key,
        })
    }

    /// Returns the OIDC provider.
    pub fn provider(&self) -> &OidcProvider {
        &self.provider
    }

    /// Returns the issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the audience.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Returns the user identifier (sub claim).
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Returns the proof.
    pub fn proof(&self) -> &ZkProof {
        &self.proof
    }

    /// Returns true if the account is still valid.
    pub fn is_valid(&self) -> bool {
        if self.ephemeral_key.is_expired() {
            return false;
        }

        match self.jwt_expiration {
            Some(exp) => SystemTime::now() < exp,
            None => true,
        }
    }

    /// Refreshes the proof using a new JWT.
    pub async fn refresh_proof(
        &mut self,
        jwt: &str,
        prover_service: &dyn ProverService,
    ) -> AptosResult<()> {
        let claims = decode_claims(jwt)?;
        let (issuer, audience, user_id, exp, nonce) = extract_claims(&claims)?;

        if nonce != self.ephemeral_key.nonce() {
            return Err(AptosError::InvalidJwt("JWT nonce mismatch".into()));
        }

        if issuer != self.issuer || audience != self.audience || user_id != self.user_id {
            return Err(AptosError::InvalidJwt(
                "JWT identity does not match account".into(),
            ));
        }

        let proof = prover_service
            .generate_proof(jwt, &self.ephemeral_key, &self.pepper)
            .await?;
        self.proof = proof;
        self.jwt_expiration = exp;
        Ok(())
    }

    /// Signs a message and returns the structured keyless signature.
    pub fn sign_keyless(&self, message: &[u8]) -> KeylessSignature {
        let signature = self.ephemeral_key.private_key.sign(message).to_bytes();
        KeylessSignature {
            ephemeral_public_key: self.ephemeral_key.public_key.to_bytes().to_vec(),
            ephemeral_signature: signature.to_vec(),
            proof: self.proof.as_bytes().to_vec(),
        }
    }
}

impl Account for KeylessAccount {
    fn address(&self) -> AccountAddress {
        self.address
    }

    fn authentication_key(&self) -> AuthenticationKey {
        self.auth_key
    }

    fn sign(&self, message: &[u8]) -> crate::error::AptosResult<Vec<u8>> {
        let signature = self.sign_keyless(message);
        signature
            .to_bcs()
            .map_err(|e| crate::error::AptosError::Bcs(e.to_string()))
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.ephemeral_key.public_key.to_bytes().to_vec()
    }

    fn signature_scheme(&self) -> u8 {
        KEYLESS_SCHEME
    }
}

impl fmt::Debug for KeylessAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeylessAccount")
            .field("address", &self.address)
            .field("provider", &self.provider)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("user_id", &self.user_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    iss: Option<String>,
    aud: Option<AudClaim>,
    sub: Option<String>,
    exp: Option<u64>,
    nonce: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AudClaim {
    Single(String),
    Multiple(Vec<String>),
}

impl AudClaim {
    fn first(&self) -> Option<&str> {
        match self {
            AudClaim::Single(value) => Some(value.as_str()),
            AudClaim::Multiple(values) => values.first().map(|value| value.as_str()),
        }
    }
}

/// Decodes JWT claims without performing signature validation.
///
/// # Security Notice
///
/// **IMPORTANT**: This function intentionally disables JWT signature validation.
/// This is NOT a security vulnerability - it is by design for the keyless account flow.
///
/// ## Why signature validation is disabled here:
///
/// In the Aptos keyless authentication flow, JWT signature verification is performed
/// separately through a different mechanism:
///
/// 1. The user obtains a JWT from an OIDC provider (Google, Apple, etc.)
/// 2. This function extracts claims (iss, aud, sub, nonce) for address derivation
/// 3. The actual cryptographic verification happens via:
///    - The pepper service validates the JWT before returning a pepper
///    - The prover service validates the JWT before generating a ZK proof
///    - On-chain verification uses the ZK proof to validate the JWT was legitimate
///
/// The ZK proof cryptographically proves that the user possessed a valid JWT from
/// the claimed issuer, without revealing the JWT itself on-chain.
///
/// ## Do NOT use this function for general JWT validation
///
/// This function should ONLY be used within the keyless account creation flow where
/// JWT authenticity is verified through the pepper/prover services and ZK proofs.
/// For general JWT validation, use the `jsonwebtoken` crate with proper signature
/// verification using the OIDC provider's JWKS endpoint.
///
/// ## Security model
///
/// - Pepper service: Validates JWT signature using OIDC provider's JWKS
/// - Prover service: Validates JWT signature before generating proof
/// - Blockchain: Verifies ZK proof that commits to valid JWT claims
fn decode_claims(jwt: &str) -> AptosResult<JwtClaims> {
    // SECURITY: Signature validation is intentionally disabled.
    // See function documentation for the security rationale.
    // JWT authenticity is verified by pepper/prover services and ZK proofs.
    let mut validation = Validation::new(Algorithm::RS256);
    validation.insecure_disable_signature_validation();
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.set_required_spec_claims::<String>(&[]);

    let data = decode::<JwtClaims>(jwt, &DecodingKey::from_secret(&[]), &validation)
        .map_err(|e| AptosError::InvalidJwt(format!("failed to decode JWT claims: {e}")))?;
    Ok(data.claims)
}

fn extract_claims(
    claims: &JwtClaims,
) -> AptosResult<(String, String, String, Option<SystemTime>, String)> {
    let issuer = claims
        .iss
        .clone()
        .ok_or_else(|| AptosError::InvalidJwt("missing iss claim".into()))?;
    let audience = claims
        .aud
        .as_ref()
        .and_then(|aud| aud.first())
        .map(|value| value.to_string())
        .ok_or_else(|| AptosError::InvalidJwt("missing aud claim".into()))?;
    let user_id = claims
        .sub
        .clone()
        .ok_or_else(|| AptosError::InvalidJwt("missing sub claim".into()))?;
    let nonce = claims
        .nonce
        .clone()
        .ok_or_else(|| AptosError::InvalidJwt("missing nonce claim".into()))?;

    let exp_time = claims.exp.map(|exp| UNIX_EPOCH + Duration::from_secs(exp));
    if let Some(exp) = exp_time
        && SystemTime::now() >= exp
    {
        let exp_secs = claims.exp.unwrap_or(0);
        return Err(AptosError::InvalidJwt(format!(
            "JWT is expired (exp: {} seconds since UNIX_EPOCH)",
            exp_secs
        )));
    }

    Ok((issuer, audience, user_id, exp_time, nonce))
}

fn derive_keyless_address(
    issuer: &str,
    audience: &str,
    user_id: &str,
    pepper: &Pepper,
) -> AccountAddress {
    let issuer_hash = sha3_256_bytes(issuer.as_bytes());
    let audience_hash = sha3_256_bytes(audience.as_bytes());
    let user_hash = sha3_256_bytes(user_id.as_bytes());

    let mut hasher = Sha3_256::new();
    hasher.update(issuer_hash);
    hasher.update(audience_hash);
    hasher.update(user_hash);
    hasher.update(pepper.as_bytes());
    hasher.update([KEYLESS_SCHEME]);
    let result = hasher.finalize();

    let mut address = [0u8; 32];
    address.copy_from_slice(&result);
    AccountAddress::new(address)
}

fn sha3_256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};

    struct StaticPepperService {
        pepper: Pepper,
    }

    #[async_trait]
    impl PepperService for StaticPepperService {
        async fn get_pepper(&self, _jwt: &str) -> AptosResult<Pepper> {
            Ok(self.pepper.clone())
        }
    }

    struct StaticProverService {
        proof: ZkProof,
    }

    #[async_trait]
    impl ProverService for StaticProverService {
        async fn generate_proof(
            &self,
            _jwt: &str,
            _ephemeral_key: &EphemeralKeyPair,
            _pepper: &Pepper,
        ) -> AptosResult<ZkProof> {
            Ok(self.proof.clone())
        }
    }

    #[derive(Serialize, Deserialize)]
    struct TestClaims {
        iss: String,
        aud: String,
        sub: String,
        exp: u64,
        nonce: String,
    }

    #[tokio::test]
    async fn test_keyless_account_creation() {
        let ephemeral = EphemeralKeyPair::generate(3600);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let claims = TestClaims {
            iss: "https://accounts.google.com".to_string(),
            aud: "client-id".to_string(),
            sub: "user-123".to_string(),
            exp: now + 3600,
            nonce: ephemeral.nonce().to_string(),
        };

        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        let pepper_service = StaticPepperService {
            pepper: Pepper::new(vec![1, 2, 3, 4]),
        };
        let prover_service = StaticProverService {
            proof: ZkProof::new(vec![9, 9, 9]),
        };

        let account = KeylessAccount::from_jwt(&jwt, ephemeral, &pepper_service, &prover_service)
            .await
            .unwrap();

        assert_eq!(account.issuer(), "https://accounts.google.com");
        assert_eq!(account.audience(), "client-id");
        assert_eq!(account.user_id(), "user-123");
        assert!(account.is_valid());
        assert!(!account.address().is_zero());
    }
}
