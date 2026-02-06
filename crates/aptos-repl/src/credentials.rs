//! Encrypted credential storage.
//!
//! Private keys are encrypted with AES-256-GCM using a key derived from a
//! user-supplied password via Argon2id. The encrypted vault is stored at
//! `~/.aptos/credentials/vault.json`.
//!
//! On-disk format (JSON):
//! ```json
//! {
//!   "version": 1,
//!   "salt": "<base64>",
//!   "entries": {
//!     "<alias>": {
//!       "key_type": "ed25519",
//!       "nonce": "<base64>",
//!       "ciphertext": "<base64>"
//!     }
//!   }
//! }
//! ```

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng},
};
use anyhow::{Context, Result, bail};
use argon2::Argon2;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use zeroize::Zeroize;

use crate::common::{CliAccount, KeyType};

// ---------------------------------------------------------------------------
// Vault types (on-disk)
// ---------------------------------------------------------------------------

const VAULT_VERSION: u32 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
// Argon2 parameters – tuned for interactive use (fast-ish on modern hardware)
const ARGON2_MEM_KIB: u32 = 64 * 1024; // 64 MiB
const ARGON2_ITERS: u32 = 3;
const ARGON2_PARALLEL: u32 = 1;

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    salt: String,
    entries: BTreeMap<String, VaultEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct VaultEntry {
    key_type: String,
    nonce: String,
    ciphertext: String,
}

// ---------------------------------------------------------------------------
// Decrypted credential
// ---------------------------------------------------------------------------

/// A single decrypted credential held in memory.
pub struct Credential {
    pub alias: String,
    pub key_type: KeyType,
    /// Hex-encoded private key (zeroized on drop).
    private_key_hex: String,
}

impl Credential {
    pub fn to_cli_account(&self) -> Result<CliAccount> {
        crate::common::load_account(&self.private_key_hex, &self.key_type)
    }

    /// Access the private key hex for injection into CLI arguments.
    /// This value is zeroized when the `Credential` is dropped.
    pub fn private_key_hex(&self) -> &str {
        &self.private_key_hex
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.private_key_hex.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Vault (in-memory, unlocked)
// ---------------------------------------------------------------------------

/// An unlocked credential vault. The derived encryption key is held in memory
/// so that new entries can be added without re-prompting for the password.
pub struct Vault {
    path: PathBuf,
    cipher: Aes256Gcm,
    salt: [u8; SALT_LEN],
    credentials: BTreeMap<String, Credential>,
}

impl Vault {
    /// The default vault file path: `~/.aptos/credentials/vault.json`.
    pub fn default_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("cannot determine home directory")?;
        Ok(home.join(".aptos").join("credentials").join("vault.json"))
    }

    /// Create a brand-new vault with the given password.
    pub fn create(password: &str) -> Result<Self> {
        let path = Self::default_path()?;
        if path.exists() {
            bail!(
                "Vault already exists at {}. Use `credential unlock` to open it.",
                path.display()
            );
        }

        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        let cipher = derive_cipher(password, &salt)?;

        let vault = Vault {
            path,
            cipher,
            salt,
            credentials: BTreeMap::new(),
        };
        vault.save()?;
        Ok(vault)
    }

    /// Open and decrypt an existing vault.
    pub fn open(password: &str) -> Result<Self> {
        let path = Self::default_path()?;
        if !path.exists() {
            bail!(
                "No vault found at {}. Use `credential init` to create one.",
                path.display()
            );
        }

        let data =
            std::fs::read_to_string(&path).context(format!("failed to read {}", path.display()))?;
        let file: VaultFile = serde_json::from_str(&data).context("corrupt vault file")?;

        if file.version != VAULT_VERSION {
            bail!("unsupported vault version {}", file.version);
        }

        let salt_bytes = B64.decode(&file.salt).context("invalid salt")?;
        let mut salt = [0u8; SALT_LEN];
        if salt_bytes.len() != SALT_LEN {
            bail!("invalid salt length");
        }
        salt.copy_from_slice(&salt_bytes);

        let cipher = derive_cipher(password, &salt)?;

        // Decrypt all entries to verify the password is correct
        let mut credentials = BTreeMap::new();
        for (alias, entry) in &file.entries {
            let nonce_bytes = B64.decode(&entry.nonce).context("invalid nonce")?;
            let ciphertext = B64
                .decode(&entry.ciphertext)
                .context("invalid ciphertext")?;

            if nonce_bytes.len() != NONCE_LEN {
                bail!("invalid nonce length for '{alias}'");
            }
            let nonce = Nonce::from_slice(&nonce_bytes);

            let plaintext = cipher
                .decrypt(nonce, ciphertext.as_slice())
                .map_err(|_| anyhow::anyhow!("wrong password or corrupt entry '{alias}'"))?;

            let key_type = parse_key_type(&entry.key_type)?;
            let private_key_hex =
                String::from_utf8(plaintext).context("decrypted key is not valid UTF-8")?;

            credentials.insert(
                alias.clone(),
                Credential {
                    alias: alias.clone(),
                    key_type,
                    private_key_hex,
                },
            );
        }

        Ok(Vault {
            path,
            cipher,
            salt,
            credentials,
        })
    }

    /// Add a new credential to the vault (and persist).
    pub fn add(&mut self, alias: &str, key_type: &KeyType, private_key_hex: &str) -> Result<()> {
        if self.credentials.contains_key(alias) {
            bail!("credential '{alias}' already exists. Remove it first or use a different alias.");
        }

        // Validate the key by loading it
        let _account = crate::common::load_account(private_key_hex, key_type)
            .context("invalid private key")?;

        let hex_clean = private_key_hex
            .strip_prefix("0x")
            .unwrap_or(private_key_hex)
            .to_string();

        self.credentials.insert(
            alias.to_string(),
            Credential {
                alias: alias.to_string(),
                key_type: key_type.clone(),
                private_key_hex: hex_clean.clone(),
            },
        );

        self.save()?;
        Ok(())
    }

    /// Remove a credential from the vault (and persist).
    pub fn remove(&mut self, alias: &str) -> Result<()> {
        if self.credentials.remove(alias).is_none() {
            bail!("credential '{alias}' not found");
        }
        self.save()?;
        Ok(())
    }

    /// List all credential aliases with their key type and address.
    pub fn list(&self) -> Vec<(&str, &KeyType, String)> {
        self.credentials
            .values()
            .map(|c| {
                let address = c
                    .to_cli_account()
                    .map(|a| format!("{}", a.address()))
                    .unwrap_or_else(|_| "???".to_string());
                (c.alias.as_str(), &c.key_type, address)
            })
            .collect()
    }

    /// Get a credential by alias.
    pub fn get(&self, alias: &str) -> Option<&Credential> {
        self.credentials.get(alias)
    }

    /// Check if vault is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    /// Get number of credentials.
    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    fn save(&self) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .context(format!("failed to create {}", parent.display()))?;
        }

        let mut entries = BTreeMap::new();
        for (alias, cred) in &self.credentials {
            let mut nonce_bytes = [0u8; NONCE_LEN];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext = self
                .cipher
                .encrypt(nonce, cred.private_key_hex.as_bytes())
                .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

            entries.insert(
                alias.clone(),
                VaultEntry {
                    key_type: key_type_str(&cred.key_type),
                    nonce: B64.encode(nonce_bytes),
                    ciphertext: B64.encode(ciphertext),
                },
            );
        }

        let file = VaultFile {
            version: VAULT_VERSION,
            salt: B64.encode(self.salt),
            entries,
        };

        let json = serde_json::to_string_pretty(&file)?;

        // Write atomically via temp file
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &json).context(format!("failed to write {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .context(format!("failed to rename to {}", self.path.display()))?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&self.path, perms);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn derive_cipher(password: &str, salt: &[u8]) -> Result<Aes256Gcm> {
    let params = argon2::Params::new(ARGON2_MEM_KIB, ARGON2_ITERS, ARGON2_PARALLEL, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 parameters: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("cipher creation failed: {e}"))?;

    key.zeroize();
    Ok(cipher)
}

pub(crate) fn key_type_str(kt: &KeyType) -> String {
    match kt {
        KeyType::Ed25519 => "ed25519".to_string(),
        KeyType::Secp256k1 => "secp256k1".to_string(),
        KeyType::Secp256r1 => "secp256r1".to_string(),
    }
}

pub(crate) fn parse_key_type(s: &str) -> Result<KeyType> {
    match s {
        "ed25519" => Ok(KeyType::Ed25519),
        "secp256k1" => Ok(KeyType::Secp256k1),
        "secp256r1" => Ok(KeyType::Secp256r1),
        _ => bail!("unknown key type: {s}"),
    }
}

/// Prompt for a password without echoing.
pub fn prompt_password(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("failed to read password")
}

/// Check if a vault file exists.
pub fn vault_exists() -> bool {
    Vault::default_path().map(|p| p.exists()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // key_type_str / parse_key_type
    // -----------------------------------------------------------------------

    #[test]
    fn key_type_str_ed25519() {
        assert_eq!(key_type_str(&KeyType::Ed25519), "ed25519");
    }

    #[test]
    fn key_type_str_secp256k1() {
        assert_eq!(key_type_str(&KeyType::Secp256k1), "secp256k1");
    }

    #[test]
    fn key_type_str_secp256r1() {
        assert_eq!(key_type_str(&KeyType::Secp256r1), "secp256r1");
    }

    #[test]
    fn parse_key_type_ed25519() {
        let kt = parse_key_type("ed25519").unwrap();
        assert!(matches!(kt, KeyType::Ed25519));
    }

    #[test]
    fn parse_key_type_secp256k1() {
        let kt = parse_key_type("secp256k1").unwrap();
        assert!(matches!(kt, KeyType::Secp256k1));
    }

    #[test]
    fn parse_key_type_secp256r1() {
        let kt = parse_key_type("secp256r1").unwrap();
        assert!(matches!(kt, KeyType::Secp256r1));
    }

    #[test]
    fn parse_key_type_unknown_fails() {
        assert!(parse_key_type("rsa").is_err());
    }

    #[test]
    fn key_type_roundtrip() {
        for kt in &[KeyType::Ed25519, KeyType::Secp256k1, KeyType::Secp256r1] {
            let s = key_type_str(kt);
            let parsed = parse_key_type(&s).unwrap();
            assert_eq!(key_type_str(&parsed), s);
        }
    }

    // -----------------------------------------------------------------------
    // derive_cipher
    // -----------------------------------------------------------------------

    #[test]
    fn derive_cipher_produces_valid_cipher() {
        let salt = [42u8; SALT_LEN];
        let cipher = derive_cipher("test-password", &salt).unwrap();

        // Should be able to encrypt and decrypt
        let nonce = aes_gcm::Nonce::from_slice(&[0u8; NONCE_LEN]);
        let plaintext = b"hello world";
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        let decrypted = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn derive_cipher_different_passwords_yield_different_keys() {
        let salt = [42u8; SALT_LEN];
        let cipher1 = derive_cipher("password1", &salt).unwrap();
        let cipher2 = derive_cipher("password2", &salt).unwrap();

        let nonce = aes_gcm::Nonce::from_slice(&[0u8; NONCE_LEN]);
        let plaintext = b"secret data";

        let ct1 = cipher1.encrypt(nonce, plaintext.as_ref()).unwrap();
        // cipher2 should NOT be able to decrypt cipher1's ciphertext
        assert!(cipher2.decrypt(nonce, ct1.as_ref()).is_err());
    }

    #[test]
    fn derive_cipher_different_salts_yield_different_keys() {
        let salt1 = [1u8; SALT_LEN];
        let salt2 = [2u8; SALT_LEN];
        let cipher1 = derive_cipher("same-password", &salt1).unwrap();
        let cipher2 = derive_cipher("same-password", &salt2).unwrap();

        let nonce = aes_gcm::Nonce::from_slice(&[0u8; NONCE_LEN]);
        let plaintext = b"secret data";

        let ct1 = cipher1.encrypt(nonce, plaintext.as_ref()).unwrap();
        assert!(cipher2.decrypt(nonce, ct1.as_ref()).is_err());
    }

    // -----------------------------------------------------------------------
    // Credential
    // -----------------------------------------------------------------------

    #[test]
    fn credential_to_cli_account() {
        let account = aptos_sdk::account::Ed25519Account::generate();
        let hex = hex::encode(account.private_key().to_bytes());
        let cred = Credential {
            alias: "test".to_string(),
            key_type: KeyType::Ed25519,
            private_key_hex: hex.clone(),
        };
        let cli = cred.to_cli_account().unwrap();
        assert_eq!(cli.address(), account.address());
    }

    #[test]
    fn credential_private_key_hex_accessor() {
        let cred = Credential {
            alias: "test".to_string(),
            key_type: KeyType::Ed25519,
            private_key_hex: "deadbeef".to_string(),
        };
        assert_eq!(cred.private_key_hex(), "deadbeef");
    }

    // -----------------------------------------------------------------------
    // VaultFile serialization
    // -----------------------------------------------------------------------

    #[test]
    fn vault_file_round_trip() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "alice".to_string(),
            VaultEntry {
                key_type: "ed25519".to_string(),
                nonce: B64.encode([0u8; NONCE_LEN]),
                ciphertext: B64.encode(b"encrypted_data"),
            },
        );

        let file = VaultFile {
            version: VAULT_VERSION,
            salt: B64.encode([0u8; SALT_LEN]),
            entries,
        };

        let json = serde_json::to_string(&file).unwrap();
        let parsed: VaultFile = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, VAULT_VERSION);
        assert!(parsed.entries.contains_key("alice"));
        assert_eq!(parsed.entries["alice"].key_type, "ed25519");
    }

    // -----------------------------------------------------------------------
    // Vault default_path
    // -----------------------------------------------------------------------

    #[test]
    fn vault_default_path_ends_with_vault_json() {
        let path = Vault::default_path().unwrap();
        assert!(path.ends_with("vault.json"));
        assert!(path.to_string_lossy().contains(".aptos"));
        assert!(path.to_string_lossy().contains("credentials"));
    }
}
