use libsecp256k1::SecretKey;
use rand::rngs::OsRng;
use std::str::FromStr;
use aptos_rust_sdk_types::crypto::secp256k1::private_key::Secp256k1PrivateKey;
use aptos_rust_sdk_types::crypto::traits::{PrivateKey, PublicKey};

fn random_key() -> SecretKey {
    SecretKey::random(&mut OsRng)
}

fn verify_valid_key(key: Secp256k1PrivateKey) {
    let public_key = key.public_key();

    let bytes = [0, 1, 2, 3, 4, 5];
    let signature = key.sign(&bytes);
    public_key
        .verify(&bytes, &signature)
        .expect("Must verify with derived public key");
}

#[test]
fn test_signature() {
    let key = Secp256k1PrivateKey::from(random_key());
    verify_valid_key(key)
}

#[test]
fn test_load_private_key_bytes() {
    let signing_key = random_key();
    let key = Secp256k1PrivateKey::try_from(&signing_key.serialize()).unwrap();
    verify_valid_key(key)
}

#[test]
fn test_load_private_key_hex() {
    let signing_key = random_key();
    let str = format!("0x{}", hex::encode(&&signing_key.serialize()));
    let key = Secp256k1PrivateKey::from_str(&str).expect("Should be valid key");
    verify_valid_key(key)
}

#[test]
fn test_private_key_output_hidden() {
    let key = Secp256k1PrivateKey::from(random_key());
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
    let verifying_key = libsecp256k1::PublicKey::from_secret_key(&signing_key);
    let key = Secp256k1PrivateKey::from(signing_key);
    let public_key = key.public_key();
    let debug = format!("{:?}", public_key);
    let display = format!("{}", public_key);
    assert_eq!(debug, display, "Debug and display should be the same");
    assert_eq!(
        format!("0x{}", hex::encode(verifying_key.serialize())),
        display,
        "Display should match verifying key bytes"
    );
}
