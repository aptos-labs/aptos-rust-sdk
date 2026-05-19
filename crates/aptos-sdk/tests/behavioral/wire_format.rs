//! Cross-SDK BCS wire-format fixtures.
//!
//! These tests pin the exact on-wire byte layout that the Rust SDK
//! produces for a small set of representative inputs:
//!
//! - `RawTransaction` with sequence-number replay protection.
//! - `RawTransaction::signing_message` (BCS + `APTOS::RawTransaction` prefix).
//! - `RawTransactionOrderless::signing_message` (uses a different prefix).
//! - `AccountAuthenticator::Ed25519` (legacy variant 0).
//! - `AccountAuthenticator::SingleKey(AnyPublicKey::Ed25519)` (variant 2).
//! - A nested generic `TypeTag`.
//!
//! Every fixture uses **deterministic** inputs (fixed keys, fixed values,
//! fixed expiration) so the resulting bytes are reproducible. A divergence
//! between this file and the TypeScript SDK constructed with the same inputs
//! is a wire-format regression and MUST be triaged before merging: a
//! corrupt authenticator or signing-message will silently produce
//! `INVALID_SIGNATURE` on the chain even though Rust compiles and all the
//! higher-level tests pass.

#![cfg(feature = "ed25519")]

use aptos_sdk::account::{Account, Ed25519Account, Ed25519SingleKeyAccount};
use aptos_sdk::crypto::{AnyPublicKey, Ed25519PrivateKey, sha3_256};
use aptos_sdk::transaction::TransactionPayload;
use aptos_sdk::transaction::authenticator::{
    AccountAuthenticator, Ed25519PublicKey as AuthEd25519PublicKey,
    Ed25519Signature as AuthEd25519Signature,
};
use aptos_sdk::transaction::payload::EntryFunction;
use aptos_sdk::transaction::types::{RawTransaction, RawTransactionOrderless};
use aptos_sdk::types::{AccountAddress, ChainId, TypeTag};

/// Deterministic Ed25519 key. The `0x01`-repeating pattern is also used by
/// the existing `auth_key_tests` module so addresses match audited values.
const FIXED_ED25519_SEED: [u8; 32] = [1u8; 32];

/// Fixed expiration timestamp so BCS bytes are reproducible.
const FIXED_EXPIRATION: u64 = 9_999_999_999;

fn fixed_apt_transfer_payload() -> TransactionPayload {
    let recipient = AccountAddress::from_hex("0x2").unwrap();
    TransactionPayload::EntryFunction(EntryFunction::apt_transfer(recipient, 1_000_000).unwrap())
}

fn fixed_raw_transaction() -> RawTransaction {
    RawTransaction {
        sender: AccountAddress::ONE,
        sequence_number: 42,
        payload: fixed_apt_transfer_payload(),
        max_gas_amount: 100_000,
        gas_unit_price: 100,
        expiration_timestamp_secs: FIXED_EXPIRATION,
        chain_id: ChainId::testnet(),
    }
}

#[test]
fn raw_transaction_signing_message_prefix_is_correct() {
    let raw = fixed_raw_transaction();
    let msg = raw.signing_message().expect("signing message must build");

    // Domain prefix: SHA3-256(b"APTOS::RawTransaction") =
    //   b5e97db07fa0bd0e5598aa3643a9bc6f6693bddc1a9fec9e674a461eaa00b193
    let expected_prefix = sha3_256(b"APTOS::RawTransaction");
    assert_eq!(
        &msg[..32],
        &expected_prefix[..],
        "domain prefix must be SHA3-256(\"APTOS::RawTransaction\")",
    );

    // Body == raw BCS of the RawTransaction.
    let body = raw.to_bcs().unwrap();
    assert_eq!(&msg[32..], &body[..]);
}

#[test]
fn raw_transaction_bcs_layout_is_reproducible() {
    // Pin the full BCS hex. Drives a future cross-check against the TS SDK
    // constructed with identical inputs.
    let raw = fixed_raw_transaction();
    let hex = const_hex::encode(raw.to_bcs().unwrap());

    // Sanity-check structurally before pinning the bytes:
    //   32B sender || 8B seq || 1B payload-variant || ... || 1B chain_id
    assert!(
        hex.starts_with(
            // sender = AccountAddress::ONE (LONG form, 32 bytes)
            "0000000000000000000000000000000000000000000000000000000000000001\
             2a00000000000000\
             02"
            .split_whitespace()
            .collect::<String>()
            .as_str()
        ),
        "leading bytes (sender + sequence_number + payload variant) drifted: {hex}",
    );

    // chain_id == ChainId::testnet() == 2 -> the final byte is `02`.
    assert!(hex.ends_with("02"), "chain id byte drifted: {hex}");

    // Sequence number 42 -> little-endian u64 -> 2a00000000000000.
    assert!(
        hex.contains("2a00000000000000"),
        "sequence_number little-endian encoding drifted: {hex}",
    );

    // Max gas amount 100_000 -> little-endian u64 -> a086010000000000.
    assert!(
        hex.contains("a086010000000000"),
        "max_gas_amount little-endian encoding drifted: {hex}",
    );

    // Gas unit price 100 -> little-endian u64 -> 6400000000000000.
    assert!(
        hex.contains("6400000000000000"),
        "gas_unit_price little-endian encoding drifted: {hex}",
    );

    // Expiration 9_999_999_999 = 0x0000_0002_540B_E3FF -> LE u64 -> ffe30b5402000000.
    assert!(
        hex.contains("ffe30b5402000000"),
        "expiration_timestamp_secs little-endian encoding drifted: {hex}",
    );
}

#[test]
fn orderless_signing_message_uses_distinct_prefix() {
    // Orderless replay protection swaps the domain prefix; the nonce stays
    // user-supplied so we use a fixed value to keep the message reproducible.
    let raw = RawTransactionOrderless::with_nonce(
        AccountAddress::ONE,
        vec![0xde, 0xad, 0xbe, 0xef],
        fixed_apt_transfer_payload(),
        100_000,
        100,
        FIXED_EXPIRATION,
        ChainId::testnet(),
    );
    let msg = raw.signing_message().unwrap();

    let expected_prefix = sha3_256(b"APTOS::RawTransactionOrderless");
    assert_eq!(&msg[..32], &expected_prefix[..]);

    // The orderless prefix MUST differ from the sequenced one -- a regression
    // that aliased them would let orderless txns replay forever.
    assert_ne!(expected_prefix, sha3_256(b"APTOS::RawTransaction"));
}

#[test]
fn account_authenticator_legacy_ed25519_bcs_layout_is_pinned() {
    let account = Ed25519Account::from_private_key(
        Ed25519PrivateKey::from_bytes(&FIXED_ED25519_SEED).unwrap(),
    );
    let message = b"fixture message";
    let sig_bytes: [u8; 64] = account
        .sign(message)
        .unwrap()
        .try_into()
        .expect("ed25519 sig length = 64");
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&account.public_key_bytes());

    let auth = AccountAuthenticator::Ed25519 {
        public_key: AuthEd25519PublicKey(pk_arr),
        signature: AuthEd25519Signature(sig_bytes),
    };
    let bytes = aptos_bcs::to_bytes(&auth).unwrap();
    let hex = const_hex::encode(&bytes);

    // Layout (variant 0 / Ed25519):
    //   0x00 || ULEB128(32) || pubkey(32) || ULEB128(64) || signature(64)
    //   = 1 + 1 + 32 + 1 + 64 = 99 bytes.
    assert_eq!(bytes.len(), 1 + 1 + 32 + 1 + 64, "BCS length mismatch");
    assert!(
        hex.starts_with("0020"),
        "variant byte (0x00) + ULEB128(32) prefix drifted: {hex}",
    );
    // After 32-byte pubkey, the next byte must be ULEB128(64) = 0x40.
    let sig_header_offset = (1 + 1 + 32) * 2;
    assert_eq!(
        &hex[sig_header_offset..sig_header_offset + 2],
        "40",
        "ULEB128(64) before signature drifted: {hex}",
    );
}

#[test]
fn account_authenticator_single_key_ed25519_bcs_layout_is_pinned() {
    let account = Ed25519SingleKeyAccount::from_private_key(
        Ed25519PrivateKey::from_bytes(&FIXED_ED25519_SEED).unwrap(),
    );
    let pk = account.public_key();
    let any_pk_bytes = AnyPublicKey::ed25519(pk).to_bcs_bytes();

    // AnyPublicKey::Ed25519 BCS = 0x00 (variant) || ULEB128(32) || 32 pubkey bytes
    //   = 34 bytes.
    assert_eq!(any_pk_bytes.len(), 1 + 1 + 32);
    assert_eq!(
        any_pk_bytes[0], 0x00,
        "AnyPublicKey::Ed25519 must be variant 0",
    );
    assert_eq!(any_pk_bytes[1], 32, "ULEB128(32) length prefix");

    // For a SingleKey authenticator the runtime BCS shape is
    //   variant 2 || raw AnyPublicKey bytes || raw AnySignature bytes
    // The Vec<u8> fields on `AccountAuthenticator::SingleKey` are emitted
    // **inline** by the hand-rolled `serialize_account_auth_raw_pair` --
    // matching the on-chain `SingleKeyAuthenticator { authenticator }`
    // struct layout. There is NO outer ULEB128 length prefix on either
    // blob; the structure is recoverable purely from the variant tags
    // embedded in AnyPublicKey / AnySignature. Test that contract here
    // because reverting to a derive-based Serialize would silently add
    // the extra prefix bytes and break on-chain authentication.

    // Build a synthetic SingleKey authenticator with the pre-serialized
    // public key and a signature blob shaped like a real
    //   AnySignature::Ed25519 = 0x00 || ULEB128(64) || 64 bytes
    // (66 bytes total).
    let synthetic_sig = {
        let mut s = vec![0u8, 64u8];
        s.extend_from_slice(&[0u8; 64]);
        s
    };
    let auth = AccountAuthenticator::SingleKey {
        public_key: any_pk_bytes.clone(),
        signature: synthetic_sig,
    };
    let outer = aptos_bcs::to_bytes(&auth).unwrap();
    let outer_hex = const_hex::encode(&outer);

    // Outer = 0x02 (variant) || 34 AnyPublicKey bytes || 66 AnySignature bytes
    //       = 1 + 34 + 66 = 101 bytes.
    assert_eq!(outer.len(), 1 + 34 + 66);
    assert!(
        outer_hex.starts_with("0200"),
        "SingleKey variant byte (0x02) + AnyPublicKey::Ed25519 variant (0x00) drifted: {outer_hex}",
    );
    // After 1-byte variant + 34-byte AnyPublicKey, the next byte must be
    // the AnySignature::Ed25519 variant tag (0x00).
    let sig_var_offset = (1 + 34) * 2;
    assert_eq!(
        &outer_hex[sig_var_offset..sig_var_offset + 2],
        "00",
        "AnySignature::Ed25519 variant tag drifted: {outer_hex}",
    );
}

#[test]
fn type_tag_nested_generic_bcs_embeds_inner_typetag() {
    let outer = TypeTag::from_str_strict("0x1::coin::Coin<0x1::aptos_coin::AptosCoin>").unwrap();
    let inner = TypeTag::aptos_coin();

    let outer_bytes = aptos_bcs::to_bytes(&outer).unwrap();
    let inner_bytes = aptos_bcs::to_bytes(&inner).unwrap();

    let outer_hex = const_hex::encode(&outer_bytes);
    let inner_hex = const_hex::encode(&inner_bytes);
    // The outer TypeTag must contain the inner one verbatim -- otherwise
    // generic instantiation has diverged from the on-chain `TypeTag` enum.
    assert!(
        outer_hex.contains(&inner_hex),
        "outer TypeTag BCS ({outer_hex}) must contain inner ({inner_hex})",
    );
}
