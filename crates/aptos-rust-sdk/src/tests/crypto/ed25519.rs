use aptos_rust_sdk_types::crypto::ed25519::private_key::Ed25519PrivateKey;
use aptos_rust_sdk_types::crypto::ed25519::public_key::Ed25519PublicKey;
use aptos_rust_sdk_types::crypto::ed25519::signature::{
    check_signature_canonical, Ed25519Signature,
};
use aptos_rust_sdk_types::crypto::traits::{PrivateKey, PublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::str::FromStr;

fn random_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn verify_valid_key(key: Ed25519PrivateKey) {
    let public_key = key.public_key();

    let bytes = [0, 1, 2, 3, 4, 5];
    let signature = key.sign(&bytes);
    public_key
        .verify(&bytes, &signature)
        .expect("Must verify with derived public key");
}

#[test]
fn test_signature() {
    let key = Ed25519PrivateKey::from(random_key());
    verify_valid_key(key)
}

#[test]
fn test_load_private_key_bytes() {
    let signing_key = random_key();
    let key = Ed25519PrivateKey::from(signing_key.to_scalar_bytes());
    verify_valid_key(key)
}

#[test]
fn test_load_private_key_hex() {
    let signing_key = random_key();
    let str = format!("0x{}", hex::encode(&signing_key.to_scalar_bytes()));
    let key = Ed25519PrivateKey::from_str(&str).expect("Should be valid key");
    verify_valid_key(key)
}

#[test]
fn test_private_key_output_hidden() {
    let key = Ed25519PrivateKey::from(random_key());
    let debug = format!("{:?}", key);
    let display = format!("{}", key);
    assert_eq!(debug, display, "Debug and display should be the same");
    assert_eq!(
        "REDACTED_PRIVATE_KEY", &display,
        "Display should not show private key"
    );
}

#[test]
fn test_public_key_output() {
    let signing_key = random_key();
    let verifying_key = VerifyingKey::from(&signing_key);
    let key = Ed25519PrivateKey::from(signing_key);
    let public_key = key.public_key();
    let debug = format!("{:?}", public_key);
    let display = format!("{}", public_key);
    assert_eq!(debug, display, "Debug and display should be the same");
    assert_eq!(
        format!("0x{}", hex::encode(verifying_key.to_bytes())),
        display,
        "Display should match verifying key bytes"
    );
}

#[test]
fn test_public_key_load() {
    let signing_key = random_key();
    let verifying_key = VerifyingKey::from(&signing_key);
    let key = Ed25519PrivateKey::from(signing_key);

    let bytes = [0, 1, 2, 3, 4, 5];
    let signature = key.sign(&bytes);
    let public_key = Ed25519PublicKey::try_from(&verifying_key.to_bytes()).unwrap();
    public_key.verify(&bytes, &signature).unwrap();
}

#[test]
fn test_signature_malleability() {
    use aptos_rust_sdk_types::crypto::ed25519::signature::non_canonical_signature;
    let non_canonical = non_canonical_signature();
    assert!(!check_signature_canonical(&non_canonical));

    Ed25519Signature::try_from(non_canonical).expect_err("Must be a non-canonical signature");
}
