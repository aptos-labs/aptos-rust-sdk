//! Keyless (OIDC-based) account support.

use crate::account::account::{Account, AuthenticationKey};
use crate::crypto::{Ed25519PrivateKey, Ed25519PublicKey, KEYLESS_SCHEME};
use crate::error::{AptosError, AptosResult};
use crate::types::AccountAddress;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

// Re-export JwkSet for use with from_jwt_with_jwks and refresh_proof_with_jwks
pub use jsonwebtoken::jwk::JwkSet;

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
    ///
    /// # Errors
    ///
    /// Returns an error if BCS serialization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or cannot be decoded.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or cannot be decoded.
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
pub trait PepperService: Send + Sync {
    /// Fetches the pepper for a JWT.
    fn get_pepper(
        &self,
        jwt: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AptosResult<Pepper>> + Send + '_>>;
}

/// Service for generating zero-knowledge proofs.
pub trait ProverService: Send + Sync {
    /// Generates the proof for keyless authentication.
    fn generate_proof<'a>(
        &'a self,
        jwt: &'a str,
        ephemeral_key: &'a EphemeralKeyPair,
        pepper: &'a Pepper,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AptosResult<ZkProof>> + Send + 'a>>;
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

impl PepperService for HttpPepperService {
    fn get_pepper(
        &self,
        jwt: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AptosResult<Pepper>> + Send + '_>>
    {
        let jwt = jwt.to_owned();
        Box::pin(async move {
            let response = self
                .client
                .post(self.url.clone())
                .json(&PepperRequest { jwt: &jwt })
                .send()
                .await?
                .error_for_status()?;

            let payload: PepperResponse = response.json().await?;
            Pepper::from_hex(&payload.pepper)
        })
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

impl ProverService for HttpProverService {
    fn generate_proof<'a>(
        &'a self,
        jwt: &'a str,
        ephemeral_key: &'a EphemeralKeyPair,
        pepper: &'a Pepper,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AptosResult<ZkProof>> + Send + 'a>>
    {
        Box::pin(async move {
            let request = ProverRequest {
                jwt,
                ephemeral_public_key: format!(
                    "0x{}",
                    hex::encode(ephemeral_key.public_key.to_bytes())
                ),
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
        })
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
    /// This method verifies the JWT signature using the OIDC provider's JWKS endpoint
    /// before extracting claims and creating the account.
    ///
    /// # Network Requests
    ///
    /// This method makes HTTP requests to:
    /// - The OIDC provider's JWKS endpoint to fetch signing keys
    /// - The pepper service to obtain the pepper
    /// - The prover service to generate a ZK proof
    ///
    /// For more control over network calls and caching, use [`Self::from_jwt_with_jwks`]
    /// with pre-fetched JWKS.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The JWT signature verification fails
    /// - The JWT cannot be decoded or is missing required claims (iss, aud, sub, nonce)
    /// - The JWT nonce doesn't match the ephemeral key's nonce
    /// - The JWT is expired
    /// - The JWKS cannot be fetched from the provider (network timeout, DNS failure,
    ///   connection errors, HTTP errors, or invalid JWKS response)
    /// - The pepper service fails to return a pepper
    /// - The prover service fails to generate a proof
    pub async fn from_jwt(
        jwt: &str,
        ephemeral_key: EphemeralKeyPair,
        pepper_service: &dyn PepperService,
        prover_service: &dyn ProverService,
    ) -> AptosResult<Self> {
        // First, decode without verification to get the issuer for JWKS lookup
        let unverified_claims = decode_claims_unverified(jwt)?;
        let issuer = unverified_claims
            .iss
            .as_ref()
            .ok_or_else(|| AptosError::InvalidJwt("missing iss claim".into()))?;

        // Determine provider and fetch JWKS
        let provider = OidcProvider::from_issuer(issuer);
        let client = reqwest::Client::builder()
            .timeout(JWKS_FETCH_TIMEOUT)
            .build()
            .map_err(|e| AptosError::InvalidJwt(format!("failed to create HTTP client: {e}")))?;
        let jwks = fetch_jwks(&client, provider.jwks_url()).await?;

        // Now verify and decode the JWT properly
        let claims = decode_and_verify_jwt(jwt, &jwks)?;
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

    /// Creates a keyless account from a JWT with pre-fetched JWKS.
    ///
    /// This method is useful when you want to:
    /// - Cache the JWKS to avoid repeated network requests
    /// - Have more control over HTTP client configuration
    /// - Implement custom caching strategies based on HTTP cache headers
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The JWT signature verification fails
    /// - The JWT cannot be decoded or is missing required claims (iss, aud, sub, nonce)
    /// - The JWT nonce doesn't match the ephemeral key's nonce
    /// - The JWT is expired
    /// - The pepper service fails to return a pepper
    /// - The prover service fails to generate a proof
    pub async fn from_jwt_with_jwks(
        jwt: &str,
        jwks: &JwkSet,
        ephemeral_key: EphemeralKeyPair,
        pepper_service: &dyn PepperService,
        prover_service: &dyn ProverService,
    ) -> AptosResult<Self> {
        // Verify and decode the JWT using the provided JWKS
        let claims = decode_and_verify_jwt(jwt, jwks)?;
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
    ///
    /// This method verifies the JWT signature using the OIDC provider's JWKS endpoint.
    ///
    /// # Network Requests
    ///
    /// This method makes HTTP requests to fetch the JWKS from the OIDC provider.
    /// For more control over network calls and caching, use [`Self::refresh_proof_with_jwks`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The JWKS cannot be fetched (network timeout, DNS failure, connection errors)
    /// - The JWT signature verification fails
    /// - The JWT cannot be decoded
    /// - The JWT nonce does not match the ephemeral key
    /// - The JWT identity does not match the account
    /// - The prover service fails to generate a new proof
    pub async fn refresh_proof(
        &mut self,
        jwt: &str,
        prover_service: &dyn ProverService,
    ) -> AptosResult<()> {
        // Fetch JWKS and verify JWT
        let client = reqwest::Client::builder()
            .timeout(JWKS_FETCH_TIMEOUT)
            .build()
            .map_err(|e| AptosError::InvalidJwt(format!("failed to create HTTP client: {e}")))?;
        let jwks = fetch_jwks(&client, self.provider.jwks_url()).await?;
        self.refresh_proof_with_jwks(jwt, &jwks, prover_service)
            .await
    }

    /// Refreshes the proof using a new JWT with pre-fetched JWKS.
    ///
    /// This method is useful for caching the JWKS or using a custom HTTP client.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The JWT signature verification fails
    /// - The JWT cannot be decoded
    /// - The JWT nonce does not match the ephemeral key
    /// - The JWT identity does not match the account
    /// - The prover service fails to generate a new proof
    pub async fn refresh_proof_with_jwks(
        &mut self,
        jwt: &str,
        jwks: &JwkSet,
        prover_service: &dyn ProverService,
    ) -> AptosResult<()> {
        let claims = decode_and_verify_jwt(jwt, jwks)?;
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

    /// Creates a keyless account from pre-verified JWT claims.
    ///
    /// This is useful for testing or when JWT verification is handled externally.
    /// The caller is responsible for ensuring the JWT was properly verified.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The nonce doesn't match the ephemeral key's nonce
    /// - The pepper service fails to return a pepper
    /// - The prover service fails to generate a proof
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub async fn from_verified_claims(
        issuer: String,
        audience: String,
        user_id: String,
        nonce: String,
        exp: Option<SystemTime>,
        ephemeral_key: EphemeralKeyPair,
        pepper_service: &dyn PepperService,
        prover_service: &dyn ProverService,
        jwt_for_services: &str,
    ) -> AptosResult<Self> {
        if nonce != ephemeral_key.nonce() {
            return Err(AptosError::InvalidJwt("nonce mismatch".into()));
        }

        let pepper = pepper_service.get_pepper(jwt_for_services).await?;
        let proof = prover_service
            .generate_proof(jwt_for_services, &ephemeral_key, &pepper)
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
            AudClaim::Multiple(values) => values.first().map(std::string::String::as_str),
        }
    }
}

/// Default timeout for JWKS fetch requests (10 seconds).
const JWKS_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Fetches the JWKS (JSON Web Key Set) from an OIDC provider.
///
/// # Errors
///
/// Returns an error if:
/// - The JWKS cannot be fetched (network timeouts, DNS resolution failures,
///   TLS/connection errors, or HTTP errors)
/// - The JWKS endpoint returns a non-success status code
/// - The response cannot be parsed as valid JWKS JSON
async fn fetch_jwks(client: &reqwest::Client, jwks_url: &str) -> AptosResult<JwkSet> {
    // Note: timeout is configured on the client, not per-request
    let response = client.get(jwks_url).send().await?;

    if !response.status().is_success() {
        return Err(AptosError::InvalidJwt(format!(
            "JWKS endpoint returned status: {}",
            response.status()
        )));
    }

    let jwks: JwkSet = response.json().await?;
    Ok(jwks)
}

/// Decodes and verifies a JWT using the provided JWKS.
///
/// This function:
/// 1. Extracts the `kid` (key ID) from the JWT header
/// 2. Finds the matching key in the JWKS
/// 3. Verifies the signature and decodes the claims
///
/// # Errors
///
/// Returns an error if:
/// - The JWT header cannot be decoded
/// - No matching key is found in the JWKS
/// - The signature verification fails
/// - The claims cannot be decoded
fn decode_and_verify_jwt(jwt: &str, jwks: &JwkSet) -> AptosResult<JwtClaims> {
    // Decode header to get the key ID
    let header = decode_header(jwt)
        .map_err(|e| AptosError::InvalidJwt(format!("failed to decode JWT header: {e}")))?;

    let kid = header
        .kid
        .as_ref()
        .ok_or_else(|| AptosError::InvalidJwt("JWT header missing 'kid' field".into()))?;

    // Find the matching key in the JWKS
    let signing_key = jwks.find(kid).ok_or_else(|| {
        AptosError::InvalidJwt("no matching key found for provided key identifier".into())
    })?;

    // Create decoding key from JWK
    let decoding_key = DecodingKey::from_jwk(signing_key)
        .map_err(|e| AptosError::InvalidJwt(format!("failed to create decoding key: {e}")))?;

    // Determine the algorithm strictly from the JWK to prevent algorithm substitution attacks
    let jwk_alg = signing_key
        .common
        .key_algorithm
        .ok_or_else(|| AptosError::InvalidJwt("JWK missing 'alg' (key_algorithm) field".into()))?;

    let algorithm = match jwk_alg {
        // RSA algorithms
        jsonwebtoken::jwk::KeyAlgorithm::RS256 => Algorithm::RS256,
        jsonwebtoken::jwk::KeyAlgorithm::RS384 => Algorithm::RS384,
        jsonwebtoken::jwk::KeyAlgorithm::RS512 => Algorithm::RS512,
        // RSA-PSS algorithms
        jsonwebtoken::jwk::KeyAlgorithm::PS256 => Algorithm::PS256,
        jsonwebtoken::jwk::KeyAlgorithm::PS384 => Algorithm::PS384,
        jsonwebtoken::jwk::KeyAlgorithm::PS512 => Algorithm::PS512,
        // ECDSA algorithms
        jsonwebtoken::jwk::KeyAlgorithm::ES256 => Algorithm::ES256,
        jsonwebtoken::jwk::KeyAlgorithm::ES384 => Algorithm::ES384,
        // EdDSA algorithm
        jsonwebtoken::jwk::KeyAlgorithm::EdDSA => Algorithm::EdDSA,
        _ => {
            return Err(AptosError::InvalidJwt(format!(
                "unsupported JWK algorithm: {jwk_alg:?}"
            )));
        }
    };

    // Ensure the JWT header algorithm matches the JWK algorithm to prevent substitution
    if header.alg != algorithm {
        return Err(AptosError::InvalidJwt(format!(
            "JWT header algorithm ({:?}) does not match JWK algorithm ({:?})",
            header.alg, algorithm
        )));
    }

    // Configure validation - we'll validate exp ourselves with more detailed errors
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false;
    validation.validate_aud = false; // We'll check aud after decoding
    validation.set_required_spec_claims::<String>(&[]);

    let data = decode::<JwtClaims>(jwt, &decoding_key, &validation)
        .map_err(|e| AptosError::InvalidJwt(format!("JWT verification failed: {e}")))?;

    Ok(data.claims)
}

/// Decodes JWT claims without signature verification.
///
/// This is used only to extract the issuer (and other metadata) before we know
/// which JWKS endpoint to fetch. This is safe because:
/// 1. The extracted issuer is only used to determine which JWKS endpoint to fetch.
/// 2. The JWT is fully verified immediately afterwards using `decode_and_verify_jwt`.
/// 3. No security decisions are made based on these unverified claims.
fn decode_claims_unverified(jwt: &str) -> AptosResult<JwtClaims> {
    // Use dangerous decode only for initial issuer extraction to select the JWKS.
    // The JWT is not trusted at this point: no authorization decisions are made
    // based on these unverified claims, and the token is fully verified (including
    // signature and claims validation) in `decode_and_verify_jwt` right after the
    // appropriate JWKS has been fetched.
    let data = jsonwebtoken::dangerous::insecure_decode::<JwtClaims>(jwt)
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
        .map(std::string::ToString::to_string)
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
            "JWT is expired (exp: {exp_secs} seconds since UNIX_EPOCH)"
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
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    struct StaticPepperService {
        pepper: Pepper,
    }

    impl PepperService for StaticPepperService {
        fn get_pepper(
            &self,
            _jwt: &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = AptosResult<Pepper>> + Send + '_>,
        > {
            Box::pin(async move { Ok(self.pepper.clone()) })
        }
    }

    struct StaticProverService {
        proof: ZkProof,
    }

    impl ProverService for StaticProverService {
        fn generate_proof<'a>(
            &'a self,
            _jwt: &'a str,
            _ephemeral_key: &'a EphemeralKeyPair,
            _pepper: &'a Pepper,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = AptosResult<ZkProof>> + Send + 'a>,
        > {
            Box::pin(async move { Ok(self.proof.clone()) })
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

        // Create a test JWT for the services (they don't validate it)
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

        // Use from_verified_claims for unit testing since we can't mock JWKS
        let exp_time = UNIX_EPOCH + std::time::Duration::from_secs(now + 3600);
        let account = KeylessAccount::from_verified_claims(
            "https://accounts.google.com".to_string(),
            "client-id".to_string(),
            "user-123".to_string(),
            ephemeral.nonce().to_string(),
            Some(exp_time),
            ephemeral,
            &pepper_service,
            &prover_service,
            &jwt,
        )
        .await
        .unwrap();

        assert_eq!(account.issuer(), "https://accounts.google.com");
        assert_eq!(account.audience(), "client-id");
        assert_eq!(account.user_id(), "user-123");
        assert!(account.is_valid());
        assert!(!account.address().is_zero());
    }

    #[tokio::test]
    async fn test_keyless_account_nonce_mismatch() {
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

        // Use a different nonce to trigger mismatch
        let result = KeylessAccount::from_verified_claims(
            "https://accounts.google.com".to_string(),
            "client-id".to_string(),
            "user-123".to_string(),
            "wrong-nonce".to_string(), // This doesn't match ephemeral.nonce()
            None,
            ephemeral,
            &pepper_service,
            &prover_service,
            &jwt,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result, Err(AptosError::InvalidJwt(_))));
    }

    #[test]
    fn test_decode_claims_unverified() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let claims = TestClaims {
            iss: "https://accounts.google.com".to_string(),
            aud: "test-aud".to_string(),
            sub: "test-sub".to_string(),
            exp: now + 3600,
            nonce: "test-nonce".to_string(),
        };

        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        let decoded = decode_claims_unverified(&jwt).unwrap();
        assert_eq!(decoded.iss.unwrap(), "https://accounts.google.com");
        assert_eq!(decoded.sub.unwrap(), "test-sub");
        assert_eq!(decoded.nonce.unwrap(), "test-nonce");
    }

    #[test]
    fn test_oidc_provider_detection() {
        assert!(matches!(
            OidcProvider::from_issuer("https://accounts.google.com"),
            OidcProvider::Google
        ));
        assert!(matches!(
            OidcProvider::from_issuer("https://appleid.apple.com"),
            OidcProvider::Apple
        ));
        assert!(matches!(
            OidcProvider::from_issuer("https://unknown.example.com"),
            OidcProvider::Custom { .. }
        ));
    }

    #[test]
    fn test_decode_and_verify_jwt_missing_kid() {
        // Create a JWT without a kid in the header
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let claims = TestClaims {
            iss: "https://accounts.google.com".to_string(),
            aud: "test-aud".to_string(),
            sub: "test-sub".to_string(),
            exp: now + 3600,
            nonce: "test-nonce".to_string(),
        };

        // HS256 JWT without kid
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        // Empty JWKS
        let jwks = JwkSet { keys: vec![] };

        let result = decode_and_verify_jwt(&jwt, &jwks);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, AptosError::InvalidJwt(msg) if msg.contains("kid")),
            "Expected error about missing kid, got: {err:?}"
        );
    }

    #[test]
    fn test_decode_and_verify_jwt_no_matching_key() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let claims = TestClaims {
            iss: "https://accounts.google.com".to_string(),
            aud: "test-aud".to_string(),
            sub: "test-sub".to_string(),
            exp: now + 3600,
            nonce: "test-nonce".to_string(),
        };

        // Create JWT with a kid in header (using HS256 for encoding)
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-kid-123".to_string());

        let jwt = encode(&header, &claims, &EncodingKey::from_secret(b"secret")).unwrap();

        // Empty JWKS - no matching key
        let jwks = JwkSet { keys: vec![] };

        let result = decode_and_verify_jwt(&jwt, &jwks);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, AptosError::InvalidJwt(msg) if msg.contains("no matching key")),
            "Expected error about no matching key, got: {err:?}"
        );
    }

    #[test]
    fn test_decode_and_verify_jwt_invalid_jwt_format() {
        let jwks = JwkSet { keys: vec![] };

        // Completely invalid JWT
        let result = decode_and_verify_jwt("not-a-valid-jwt", &jwks);
        assert!(result.is_err());

        // JWT with invalid base64
        let result = decode_and_verify_jwt("aaa.bbb.ccc", &jwks);
        assert!(result.is_err());
    }
}
