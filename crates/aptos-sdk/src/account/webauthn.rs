// Module docs reference many WebAuthn / RustCrypto identifiers that clippy's
// pedantic `doc_markdown` lint flags even when they are intentionally rendered
// as prose (e.g. "Aptos networks", "clientDataJSON", "RustCrypto"). Backticking
// every occurrence harms readability without improving safety, so allow the
// lint for this module only.
#![allow(clippy::doc_markdown)]

//! WebAuthn / Passkey account implementation.
//!
//! This module provides [`WebAuthnAccount`], an account type that signs
//! Aptos transactions using a `secp256r1` / P-256 key but wraps the
//! signature in the WebAuthn `PartialAuthenticatorAssertionResponse`
//! envelope that the on-chain `AnySignature::WebAuthn` variant expects.
//!
//! # Why this exists
//!
//! On current Aptos networks (devnet, testnet, mainnet), the
//! `AnySignature` enum stored inside `AccountAuthenticator::SingleKey` /
//! `MultiKey` has variant index `2` reserved for **WebAuthn** -- not for
//! bare `secp256r1` ECDSA signatures. A transaction signed by the historical
//! [`super::Secp256r1Account`] is therefore rejected by the chain even
//! though the signature itself is mathematically correct, because the
//! chain interprets variant `2` as a `PartialAuthenticatorAssertionResponse`
//! and the bare 64-byte ECDSA signature does not parse as one.
//!
//! `WebAuthnAccount` produces the correct envelope:
//!
//! 1. The `challenge` the chain expects is `SHA3-256(signing_message(raw_txn))`.
//!    We compute it from the message passed into `Account::sign`.
//! 2. We construct a minimal but valid `clientDataJSON` that carries this
//!    challenge as a base64url (no-pad) string and a configurable
//!    `origin` field.
//! 3. We construct a 37-byte synthetic `authenticatorData`
//!    (`rpIdHash || flags || signCount`). The chain does not enforce a
//!    specific `rpIdHash` so we hash a developer-configurable `rp_id` into
//!    32 bytes; defaults are deterministic.
//! 4. We sign the binary concatenation
//!    `authenticatorData || SHA-256(clientDataJSON)` with the
//!    `secp256r1` key. The `k256` / `p256` stack hashes that buffer with
//!    SHA-256 internally, exactly mirroring how the chain verifies via
//!    `signature::Verifier::verify`.
//! 5. We BCS-serialize the resulting
//!    `PartialAuthenticatorAssertionResponse` and emit it as the
//!    `AnySignature::WebAuthn` payload.
//!
//! The result is a fully self-contained synthetic-Passkey account that
//! produces transactions a live Aptos node will accept and execute.
//!
//! # Example
//!
//! ```rust,no_run
//! use aptos_sdk::account::{Account, WebAuthnAccount};
//!
//! let account = WebAuthnAccount::generate();
//! // Use `account` anywhere an `&dyn Account` / `impl Account` is required.
//! println!("WebAuthn account address: {}", account.address());
//! ```

use crate::account::account::{Account, AuthenticationKey};
use crate::crypto::multi_key::uleb128_encode;
use crate::crypto::{
    SINGLE_KEY_SCHEME, Secp256r1PrivateKey, Secp256r1PublicKey, derive_authentication_key,
    sha2_256, sha3_256,
};
use crate::error::AptosResult;
use crate::types::AccountAddress;
use std::fmt;

/// Default WebAuthn relying-party identifier baked into the synthetic
/// `authenticator_data.rpIdHash` field. The on-chain verifier does not
/// enforce a specific value, so any deterministic 32-byte hash is fine.
pub const DEFAULT_WEBAUTHN_RP_ID: &str = "aptos-rust-sdk";

/// Default WebAuthn `origin` field baked into the synthetic
/// `client_data_json.origin` value. Like `rp_id`, the on-chain verifier
/// does not enforce a specific value.
pub const DEFAULT_WEBAUTHN_ORIGIN: &str = "https://aptos-rust-sdk.local";

/// On-chain BCS variant tag for `AnySignature::WebAuthn`.
const ANY_SIGNATURE_WEBAUTHN_TAG: u8 = 0x02;

/// On-chain BCS variant tag for `AssertionSignature::Secp256r1Ecdsa` (the
/// only variant currently defined). Used inside
/// `PartialAuthenticatorAssertionResponse.signature`.
const ASSERTION_SIGNATURE_SECP256R1_TAG: u8 = 0x00;

/// WebAuthn `AuthenticatorData` flags byte (UP | UV = User Present and
/// User Verified). The chain does not enforce a specific flag combination,
/// so we always assert both, since our software-only signer "presents the
/// user" by definition every time `sign` is called.
const AUTHENTICATOR_DATA_FLAGS: u8 = 0x05;

/// Length of an Aptos secp256r1 signature in bytes (`r || s`).
const SECP256R1_SIGNATURE_LENGTH: usize = 64;

/// A WebAuthn / Passkey-style account.
///
/// Wraps a [`Secp256r1PrivateKey`] but produces transaction signatures in
/// the on-chain `AnySignature::WebAuthn` format. See the module-level
/// docs for the precise wire format.
#[derive(Clone)]
pub struct WebAuthnAccount {
    private_key: Secp256r1PrivateKey,
    public_key: Secp256r1PublicKey,
    address: AccountAddress,
    rp_id_hash: [u8; 32],
    origin: String,
}

impl WebAuthnAccount {
    /// Generates a new random WebAuthn account using the default
    /// RP-ID and origin (see [`DEFAULT_WEBAUTHN_RP_ID`] /
    /// [`DEFAULT_WEBAUTHN_ORIGIN`]).
    #[must_use]
    pub fn generate() -> Self {
        Self::from_private_key(Secp256r1PrivateKey::generate())
    }

    /// Creates a WebAuthn account from an existing P-256 private key,
    /// using the default RP-ID and origin.
    #[must_use]
    pub fn from_private_key(private_key: Secp256r1PrivateKey) -> Self {
        Self::from_parts(private_key, DEFAULT_WEBAUTHN_RP_ID, DEFAULT_WEBAUTHN_ORIGIN)
    }

    /// Creates a WebAuthn account from a private key and explicit
    /// RP-ID / origin strings.
    ///
    /// The on-chain verifier does not enforce particular values for these
    /// fields, but if you are interoperating with a relying party that
    /// records the `rpIdHash` / `origin` for off-chain auditing you may
    /// wish to specify them.
    #[must_use]
    pub fn from_parts(private_key: Secp256r1PrivateKey, rp_id: &str, origin: &str) -> Self {
        let public_key = private_key.public_key();
        let address = public_key.to_address();
        let rp_id_hash = sha2_256(rp_id.as_bytes());
        Self {
            private_key,
            public_key,
            address,
            rp_id_hash,
            origin: origin.to_owned(),
        }
    }

    /// Creates a WebAuthn account from private-key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not a valid 32-byte P-256 scalar.
    pub fn from_private_key_bytes(bytes: &[u8]) -> AptosResult<Self> {
        let private_key = Secp256r1PrivateKey::from_bytes(bytes)?;
        Ok(Self::from_private_key(private_key))
    }

    /// Returns the account address (the on-chain authentication key).
    #[must_use]
    pub fn address(&self) -> AccountAddress {
        self.address
    }

    /// Returns the underlying P-256 public key.
    #[must_use]
    pub fn public_key(&self) -> &Secp256r1PublicKey {
        &self.public_key
    }

    /// Returns a reference to the underlying P-256 private key.
    #[must_use]
    pub fn private_key(&self) -> &Secp256r1PrivateKey {
        &self.private_key
    }

    /// Builds the synthetic 37-byte `authenticatorData` blob the WebAuthn
    /// envelope expects: `rpIdHash(32) || flags(1) || signCount(4 BE)`.
    fn build_authenticator_data(&self) -> [u8; 37] {
        let mut out = [0u8; 37];
        out[..32].copy_from_slice(&self.rp_id_hash);
        out[32] = AUTHENTICATOR_DATA_FLAGS;
        // signCount = 0 in big-endian. The chain doesn't track counters so a
        // fixed zero is fine.
        out[33..37].copy_from_slice(&[0u8; 4]);
        out
    }

    /// Builds the `clientDataJSON` byte string the WebAuthn envelope expects.
    fn build_client_data_json(&self, challenge_b64url: &str) -> Vec<u8> {
        // The exact JSON encoding doesn't matter as long as `serde_json` can
        // parse it and `challenge` is the SHA3-256-of-signing-message in
        // base64url-no-pad form. We construct a minimal string by hand to
        // avoid pulling serde_json into the WebAuthn signing path. Origin
        // strings produced by `WebAuthnAccount::from_parts` are reflected
        // verbatim, but we still escape backslashes and double quotes
        // defensively in case the caller passed unusual input.
        let mut out = String::with_capacity(128 + challenge_b64url.len() + self.origin.len());
        out.push_str(r#"{"type":"webauthn.get","challenge":""#);
        out.push_str(challenge_b64url);
        out.push_str(r#"","origin":""#);
        Self::push_json_escaped(&mut out, &self.origin);
        out.push_str(r#"","crossOrigin":false}"#);
        out.into_bytes()
    }

    fn push_json_escaped(dst: &mut String, src: &str) {
        use std::fmt::Write as _;
        for ch in src.chars() {
            match ch {
                '"' => dst.push_str("\\\""),
                '\\' => dst.push_str("\\\\"),
                c if (c as u32) < 0x20 => {
                    // ASCII control char. Emit \u00XX form. write! into String
                    // never fails.
                    let _ = write!(dst, "\\u{:04x}", c as u32);
                }
                c => dst.push(c),
            }
        }
    }
}

impl Account for WebAuthnAccount {
    fn address(&self) -> AccountAddress {
        self.address
    }

    fn authentication_key(&self) -> AuthenticationKey {
        // Address derivation is identical to `Secp256r1Account`: the chain
        // canonicalises through `AnyPublicKey::Secp256r1Ecdsa` (variant 2)
        // with the 65-byte SEC1 uncompressed encoding.
        let uncompressed = self.public_key.to_uncompressed_bytes();
        let mut bcs_bytes = Vec::with_capacity(1 + 1 + uncompressed.len());
        bcs_bytes.push(0x02); // AnyPublicKey::Secp256r1Ecdsa
        bcs_bytes.push(65); // ULEB128(65)
        bcs_bytes.extend_from_slice(&uncompressed);
        let key = derive_authentication_key(&bcs_bytes, SINGLE_KEY_SCHEME);
        AuthenticationKey::new(key)
    }

    fn sign(&self, message: &[u8]) -> AptosResult<Vec<u8>> {
        // Step 1: challenge = SHA3-256(signing_message(raw_txn)).
        // `message` here is `signing_message(raw_txn)`; `Aptos::build_transaction`
        // and `sign_transaction` produce that buffer.
        let challenge = sha3_256(message);
        let challenge_b64 = base64url_no_pad(&challenge);

        // Step 2: build the WebAuthn envelope.
        let authenticator_data = self.build_authenticator_data();
        let client_data_json = self.build_client_data_json(&challenge_b64);

        // Step 3: verification_data = authenticator_data || SHA-256(clientDataJSON)
        let client_data_hash = sha2_256(&client_data_json);
        let mut verification_data =
            Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
        verification_data.extend_from_slice(&authenticator_data);
        verification_data.extend_from_slice(&client_data_hash);

        // Step 4: sign verification_data with secp256r1. p256's Signer::sign
        // hashes with SHA-256 internally, so the resulting signature is over
        // SHA-256(verification_data), matching the chain's verifier
        // (`p256::ecdsa::VerifyingKey::verify(verification_data, sig)`).
        let signature = self.private_key.sign(&verification_data);
        let sig_bytes = signature.to_bytes();
        debug_assert_eq!(sig_bytes.len(), SECP256R1_SIGNATURE_LENGTH);

        // Step 5: BCS-encode the PartialAuthenticatorAssertionResponse.
        //
        //   variant tag = 0x00 (AssertionSignature::Secp256r1Ecdsa)
        //   secp256r1_ecdsa::Signature BCS = ULEB128(64) || 64 sig bytes
        //   authenticator_data Vec<u8> = ULEB128(37) || 37 bytes
        //   client_data_json Vec<u8>  = ULEB128(len) || bytes
        let mut paar = Vec::with_capacity(
            1 + 1
                + SECP256R1_SIGNATURE_LENGTH
                + 1
                + authenticator_data.len()
                + 2
                + client_data_json.len(),
        );
        paar.push(ASSERTION_SIGNATURE_SECP256R1_TAG);
        paar.extend(uleb128_encode(SECP256R1_SIGNATURE_LENGTH));
        paar.extend_from_slice(&sig_bytes);
        paar.extend(uleb128_encode(authenticator_data.len()));
        paar.extend_from_slice(&authenticator_data);
        paar.extend(uleb128_encode(client_data_json.len()));
        paar.extend_from_slice(&client_data_json);

        // Step 6: wrap as AnySignature::WebAuthn (variant tag 2 in the on-chain
        // AnySignature enum). The on-chain layout is
        //   `AnySignature::WebAuthn { signature: PartialAuthenticatorAssertionResponse }`
        // which BCS-serializes as `variant_tag(1) || BCS(PAAR fields inlined)`.
        // PartialAuthenticatorAssertionResponse is a *struct*, so its fields
        // appear directly after the variant tag with no outer length prefix.
        let mut out = Vec::with_capacity(1 + paar.len());
        out.push(ANY_SIGNATURE_WEBAUTHN_TAG);
        out.extend_from_slice(&paar);
        Ok(out)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        // BCS-serialized `AnyPublicKey::Secp256r1Ecdsa`
        // (variant=2, ULEB128(65), 65 bytes SEC1 uncompressed).
        let uncompressed = self.public_key.to_uncompressed_bytes();
        let mut out = Vec::with_capacity(1 + 1 + uncompressed.len());
        out.push(0x02);
        out.push(65);
        out.extend_from_slice(&uncompressed);
        out
    }

    fn signature_scheme(&self) -> u8 {
        SINGLE_KEY_SCHEME
    }
}

impl fmt::Debug for WebAuthnAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SECURITY: intentionally omit `private_key`.
        f.debug_struct("WebAuthnAccount")
            .field("address", &self.address)
            .field("public_key", &self.public_key)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// Base64url (RFC 4648 §5) without padding. Pure ASCII output.
fn base64url_no_pad(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let b0 = input[i];
        let b1 = input[i + 1];
        let b2 = input[i + 2];
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        out.push(ALPHABET[(b2 & 0x3f) as usize] as char);
        i += 3;
    }
    match input.len() - i {
        1 => {
            let b0 = input[i];
            out.push(ALPHABET[(b0 >> 2) as usize] as char);
            out.push(ALPHABET[((b0 & 0x03) << 4) as usize] as char);
        }
        2 => {
            let b0 = input[i];
            let b1 = input[i + 1];
            out.push(ALPHABET[(b0 >> 2) as usize] as char);
            out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            out.push(ALPHABET[((b1 & 0x0f) << 2) as usize] as char);
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;

    #[test]
    fn test_base64url_known_values() {
        // RFC 4648 examples (no padding) plus the "f" sequence.
        assert_eq!(base64url_no_pad(b""), "");
        assert_eq!(base64url_no_pad(b"f"), "Zg");
        assert_eq!(base64url_no_pad(b"fo"), "Zm8");
        assert_eq!(base64url_no_pad(b"foo"), "Zm9v");
        assert_eq!(base64url_no_pad(b"foob"), "Zm9vYg");
        assert_eq!(base64url_no_pad(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url_no_pad(b"foobar"), "Zm9vYmFy");
        // Distinguishing - and _ from + and / (base64 vs base64url).
        // 0xFB is `1111_1011`, with one byte of input we get the high-6
        // bits `111110 = 62` (the 63rd alphabet char => '-' in url-safe).
        let one_byte_fb = base64url_no_pad(&[0xFBu8]);
        assert!(one_byte_fb.starts_with('-'));
    }

    #[test]
    fn test_webauthn_account_generate_deterministic_address() {
        let key = Secp256r1PrivateKey::from_bytes(&[7u8; 32]).unwrap();
        let a = WebAuthnAccount::from_private_key(key.clone());
        let b = WebAuthnAccount::from_private_key(key);
        assert_eq!(a.address(), b.address());
        assert!(!a.address().is_zero());
    }

    #[test]
    fn test_webauthn_account_address_matches_secp256r1() {
        // A WebAuthn account uses the same `AnyPublicKey::Secp256r1Ecdsa`
        // variant for auth-key derivation as a Secp256r1Account, so the
        // derived addresses must match exactly for the same private key.
        #![allow(deprecated)]
        let key = Secp256r1PrivateKey::from_bytes(&[42u8; 32]).unwrap();
        let webauthn = WebAuthnAccount::from_private_key(key.clone());
        let plain = super::super::Secp256r1Account::from_private_key(key);
        assert_eq!(webauthn.address(), plain.address());
    }

    #[test]
    fn test_webauthn_account_signature_envelope_shape() {
        let account =
            WebAuthnAccount::from_private_key(Secp256r1PrivateKey::from_bytes(&[1u8; 32]).unwrap());
        let signing_message = b"signing message under test";
        let signed = account.sign(signing_message).unwrap();

        // Outer wrapper: AnySignature::WebAuthn = variant 2, then the
        // PartialAuthenticatorAssertionResponse struct's fields inlined
        // (no outer length prefix -- BCS only adds length prefixes for
        // dynamically-sized fields, not for typed struct fields of enum
        // variants).
        assert_eq!(signed[0], 0x02, "AnySignature variant must be WebAuthn (2)");

        // Inner paar starts immediately after the variant byte:
        //   variant 0 (Secp256r1Ecdsa), ULEB128(64), 64 sig bytes,
        //   ULEB128(37) (authenticator_data), 37 bytes,
        //   ULEB128(len), client_data_json bytes.
        let paar = &signed[1..];
        assert_eq!(
            paar[0], 0x00,
            "AssertionSignature variant must be Secp256r1Ecdsa (0)"
        );
        assert_eq!(paar[1], 64, "secp256r1 signature length prefix must be 64");
        let auth_data_prefix = paar[1 + 1 + 64];
        assert_eq!(
            auth_data_prefix, 37,
            "authenticator_data length prefix must be 37"
        );
        let auth_data_start = 1 + 1 + 64 + 1;
        assert_eq!(
            paar[auth_data_start + 32],
            AUTHENTICATOR_DATA_FLAGS,
            "flags byte must indicate UP|UV"
        );
    }

    #[test]
    fn test_webauthn_client_data_json_contains_challenge() {
        let account =
            WebAuthnAccount::from_private_key(Secp256r1PrivateKey::from_bytes(&[3u8; 32]).unwrap());
        let signing_message = b"another signing message";
        let signed = account.sign(signing_message).unwrap();

        // Skip the AnySignature variant byte to find the PAAR struct fields.
        let paar = &signed[1..];

        // Skip AssertionSignature::Secp256r1Ecdsa header (1 + 1 + 64) and
        // authenticator_data (1 + 37) to reach the client_data_json field.
        let mut off = 1 + 1 + 64 + 1 + 37;
        let (client_len, client_prefix_len) = decode_uleb128(&paar[off..]);
        off += client_prefix_len;
        let client_json = &paar[off..off + client_len];
        let s = std::str::from_utf8(client_json).expect("client_data_json must be UTF-8");

        // Expected challenge is SHA3-256(signing_message) base64url-no-pad.
        let expected_challenge = base64url_no_pad(&sha3_256(signing_message));
        assert!(
            s.contains(&format!("\"challenge\":\"{expected_challenge}\"")),
            "client_data_json must embed the challenge: {s}"
        );
        assert!(s.contains(r#""type":"webauthn.get""#));
        assert!(s.contains(r#""origin":""#));
        assert!(s.contains(r#""crossOrigin":false"#));
    }

    /// Tiny in-test ULEB128 decoder so we don't have to plumb the
    /// `crate::crypto::multi_key::uleb128_decode` private helper through
    /// this module's tests.
    fn decode_uleb128(bytes: &[u8]) -> (usize, usize) {
        let mut value: usize = 0;
        let mut shift = 0;
        let mut i = 0;
        loop {
            let b = bytes[i];
            value |= ((b & 0x7F) as usize) << shift;
            i += 1;
            if (b & 0x80) == 0 {
                break;
            }
            shift += 7;
        }
        (value, i)
    }
}
