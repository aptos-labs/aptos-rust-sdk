//! SLH-DSA-SHA2-128s (post-quantum) account implementation.
//!
//! This is a `SingleKey` account (the TypeScript SDK's
//! `SingleKeyAccount` with `SigningSchemeInput.SlhDsaSha2128s`): there is no
//! legacy authenticator for this scheme.
//!
//! Note the on-chain feature gate: SLH-DSA transaction verification is
//! gated behind Aptos feature flag 107 in `aptos-core`, so transactions from
//! this account only verify on networks where that feature is enabled.

#[cfg(feature = "mnemonic")]
use crate::account::Mnemonic;
use crate::account::account::{Account, AuthenticationKey};
use crate::crypto::{
    SINGLE_KEY_SCHEME, SlhDsaSha2128sPrivateKey, SlhDsaSha2128sPublicKey, derive_authentication_key,
};
use crate::error::AptosResult;
use crate::types::AccountAddress;
use std::fmt;

/// An SLH-DSA-SHA2-128s account for signing transactions.
///
/// # Example
///
/// ```rust
/// use aptos_sdk::account::SlhDsaSha2128sAccount;
///
/// let account = SlhDsaSha2128sAccount::generate();
/// println!("Address: {}", account.address());
/// ```
#[derive(Clone)]
pub struct SlhDsaSha2128sAccount {
    private_key: SlhDsaSha2128sPrivateKey,
    public_key: SlhDsaSha2128sPublicKey,
    address: AccountAddress,
}

impl SlhDsaSha2128sAccount {
    /// Generates a new random SLH-DSA-SHA2-128s account.
    pub fn generate() -> Self {
        let private_key = SlhDsaSha2128sPrivateKey::generate();
        Self::from_private_key(private_key)
    }

    /// Creates an account from a private key.
    pub fn from_private_key(private_key: SlhDsaSha2128sPrivateKey) -> Self {
        let public_key = private_key.public_key();
        let address = public_key.to_address();
        Self {
            private_key,
            public_key,
            address,
        }
    }

    /// Creates an account from private key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid SLH-DSA-SHA2-128s
    /// private key (must be exactly 48 bytes: the three 16-byte seeds).
    pub fn from_private_key_bytes(bytes: &[u8]) -> AptosResult<Self> {
        let private_key = SlhDsaSha2128sPrivateKey::from_bytes(bytes)?;
        Ok(Self::from_private_key(private_key))
    }

    /// Creates an account from a private key hex string.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or the decoded bytes
    /// are not 48 bytes.
    pub fn from_private_key_hex(hex_str: &str) -> AptosResult<Self> {
        let private_key = SlhDsaSha2128sPrivateKey::from_hex(hex_str)?;
        Ok(Self::from_private_key(private_key))
    }

    /// Creates an account from a BIP-39 mnemonic phrase.
    ///
    /// Uses the standard Aptos hardened derivation path
    /// `m/44'/637'/0'/0'/index'` with the SLIP-0010-style
    /// `"SLH-DSA-SHA2-128s seed"` master-key string, matching the TypeScript
    /// SDK's `SlhDsaSha2128sPrivateKey.fromDerivationPath`.
    ///
    /// # Errors
    ///
    /// Returns an error if the mnemonic phrase is invalid or if key
    /// derivation fails.
    #[cfg(feature = "mnemonic")]
    pub fn from_mnemonic(mnemonic: &str, index: u32) -> AptosResult<Self> {
        let mnemonic = Mnemonic::from_phrase(mnemonic)?;
        let private_key = mnemonic.derive_slh_dsa_sha2_128s_key(index)?;
        Ok(Self::from_private_key(private_key))
    }

    /// Overrides the account address, keeping this key (for use after an
    /// authentication-key rotation).
    #[must_use]
    pub fn with_address(mut self, address: AccountAddress) -> Self {
        self.address = address;
        self
    }

    /// Returns the account address.
    pub fn address(&self) -> AccountAddress {
        self.address
    }

    /// Returns the public key.
    pub fn public_key(&self) -> &SlhDsaSha2128sPublicKey {
        &self.public_key
    }

    /// Returns a reference to the private key.
    pub fn private_key(&self) -> &SlhDsaSha2128sPrivateKey {
        &self.private_key
    }

    /// Signs a message and returns the SLH-DSA-SHA2-128s signature.
    pub fn sign_message(&self, message: &[u8]) -> crate::crypto::SlhDsaSha2128sSignature {
        self.private_key.sign(message)
    }
}

impl Account for SlhDsaSha2128sAccount {
    fn address(&self) -> AccountAddress {
        self.address
    }

    fn authentication_key(&self) -> AuthenticationKey {
        let key = derive_authentication_key(&self.public_key.to_bcs_bytes(), SINGLE_KEY_SCHEME);
        AuthenticationKey::new(key)
    }

    fn sign(&self, message: &[u8]) -> AptosResult<Vec<u8>> {
        // BCS-serialized `AnySignature::SlhDsa_Sha2_128s`
        // (variant=4, ULEB128(7856), 7,856 raw signature bytes).
        Ok(self.private_key.sign(message).to_bcs_bytes())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        // BCS-serialized `AnyPublicKey::SlhDsa_Sha2_128s`
        // (variant=5, ULEB128(32), 32-byte public key).
        self.public_key.to_bcs_bytes()
    }

    fn signature_scheme(&self) -> u8 {
        SINGLE_KEY_SCHEME
    }
}

impl fmt::Debug for SlhDsaSha2128sAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlhDsaSha2128sAccount")
            .field("address", &self.address)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let account = SlhDsaSha2128sAccount::generate();
        assert!(!account.address().is_zero());
    }

    #[test]
    fn test_from_private_key_roundtrip() {
        let account = SlhDsaSha2128sAccount::generate();
        let restored =
            SlhDsaSha2128sAccount::from_private_key_bytes(&account.private_key().to_bytes())
                .unwrap();
        assert_eq!(account.address(), restored.address());
        let restored =
            SlhDsaSha2128sAccount::from_private_key_hex(&account.private_key().to_hex()).unwrap();
        assert_eq!(account.address(), restored.address());
    }

    #[test]
    fn test_sign_and_verify() {
        let account = SlhDsaSha2128sAccount::generate();
        let signature = account.sign_message(b"hello aptos");
        assert!(
            account
                .public_key()
                .verify(b"hello aptos", &signature)
                .is_ok()
        );
    }

    #[test]
    fn test_public_key_bytes_framing() {
        let account = SlhDsaSha2128sAccount::generate();
        let bytes = account.public_key_bytes();
        // BCS(AnyPublicKey::SlhDsa_Sha2_128s): variant 5 + ULEB128(32) + 32 bytes.
        assert_eq!(bytes.len(), 34);
        assert_eq!(bytes[0], 5, "AnyPublicKey::SlhDsa_Sha2_128s variant tag");
        assert_eq!(bytes[1], 32, "ULEB128(32)");
    }

    #[test]
    fn test_sign_trait_framing() {
        let account = SlhDsaSha2128sAccount::generate();
        let sig_bytes = account.sign(b"test message").unwrap();
        // BCS(AnySignature::SlhDsa_Sha2_128s): variant 4 + ULEB128(7856) + 7,856 bytes.
        assert_eq!(sig_bytes.len(), 1 + 2 + 7856);
        assert_eq!(
            sig_bytes[0], 4,
            "AnySignature::SlhDsa_Sha2_128s variant tag"
        );
        assert_eq!(&sig_bytes[1..3], &[0xB0, 0x3D], "ULEB128(7856)");
    }

    #[test]
    fn test_authentication_key_matches_address() {
        let account = SlhDsaSha2128sAccount::generate();
        assert_eq!(
            account.authentication_key().as_bytes(),
            account.address().as_bytes()
        );
        assert_eq!(account.signature_scheme(), SINGLE_KEY_SCHEME);
    }

    #[test]
    fn test_invalid_private_key_bytes() {
        assert!(SlhDsaSha2128sAccount::from_private_key_bytes(&[0u8; 16]).is_err());
        assert!(SlhDsaSha2128sAccount::from_private_key_hex("invalid").is_err());
    }

    #[test]
    fn test_debug_output() {
        let account = SlhDsaSha2128sAccount::generate();
        assert!(format!("{account:?}").contains("SlhDsaSha2128sAccount"));
    }

    #[test]
    #[cfg(feature = "mnemonic")]
    fn test_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let account = SlhDsaSha2128sAccount::from_mnemonic(mnemonic, 0).unwrap();
        let account2 = SlhDsaSha2128sAccount::from_mnemonic(mnemonic, 0).unwrap();
        assert_eq!(account.address(), account2.address());
        let account3 = SlhDsaSha2128sAccount::from_mnemonic(mnemonic, 1).unwrap();
        assert_ne!(account.address(), account3.address());
    }
}
