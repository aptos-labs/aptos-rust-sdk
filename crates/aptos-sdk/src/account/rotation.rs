//! Authentication-key rotation.
//!
//! Rotating an account's authentication key to a new key pair requires proving
//! ownership of *both* the current key and the new key. This is done by signing
//! a [`RotationProofChallenge`] with each key and submitting both signatures to
//! `0x1::account::rotate_authentication_key`.
//!
//! Use [`build_rotate_auth_key_payload`] to construct the signed payload, or the
//! higher-level `Aptos::rotate_auth_key` helper which also fetches the sequence
//! number and submits the transaction.
//!
//! # On-wire format
//!
//! The challenge is BCS-serialized and includes a fixed domain prefix
//! (`0x1::account::RotationProofChallenge`) so it cannot be replayed as any
//! other signed message. The layout is pinned to Aptos core:
//!
//! ```text
//! account_address: address   // 0x1
//! module_name:     String    // "account"
//! struct_name:     String    // "RotationProofChallenge"
//! sequence_number: u64
//! originator:      address    // the account being rotated
//! current_auth_key:address    // current authentication key, as an address
//! new_public_key:  vector<u8> // new public key bytes
//! ```

use crate::account::Account;
use crate::error::AptosResult;
use crate::transaction::{InputEntryFunctionData, TransactionPayload};
use crate::types::AccountAddress;
use serde::{Deserialize, Serialize};

/// The challenge signed (by both the current and new keys) to authorize an
/// authentication-key rotation.
///
/// The field order and the leading domain fields (`account_address`,
/// `module_name`, `struct_name`) are part of the BCS-serialized bytes and must
/// match `0x1::account::RotationProofChallenge` exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationProofChallenge {
    /// Address of the module defining the challenge (`0x1`).
    pub account_address: AccountAddress,
    /// Module name (`"account"`).
    pub module_name: String,
    /// Struct name (`"RotationProofChallenge"`).
    pub struct_name: String,
    /// The current sequence number of the account being rotated.
    pub sequence_number: u64,
    /// The account whose key is being rotated.
    pub originator: AccountAddress,
    /// The account's current authentication key, as an address.
    pub current_auth_key: AccountAddress,
    /// The new public key bytes to rotate to.
    #[serde(with = "serde_bytes")]
    pub new_public_key: Vec<u8>,
}

impl RotationProofChallenge {
    /// Builds the challenge for rotating `originator` (with the given
    /// `sequence_number` and `current_auth_key`) to `new_public_key`.
    pub fn new(
        sequence_number: u64,
        originator: AccountAddress,
        current_auth_key: AccountAddress,
        new_public_key: Vec<u8>,
    ) -> Self {
        Self {
            account_address: AccountAddress::ONE,
            module_name: "account".to_string(),
            struct_name: "RotationProofChallenge".to_string(),
            sequence_number,
            originator,
            current_auth_key,
            new_public_key,
        }
    }

    /// Serializes the challenge to its BCS bytes (the message that both keys
    /// sign).
    ///
    /// # Errors
    ///
    /// Returns an error if BCS serialization fails.
    pub fn to_bcs(&self) -> AptosResult<Vec<u8>> {
        aptos_bcs::to_bytes(self).map_err(crate::error::AptosError::bcs)
    }
}

/// Builds a signed `0x1::account::rotate_authentication_key` payload that
/// rotates `current`'s authentication key to `new_account`'s key.
///
/// Both accounts sign a [`RotationProofChallenge`]: `current` proves it controls
/// the account today, and `new_account` proves it controls the key being rotated
/// to (preventing an attacker from pointing an account at a key they don't own).
///
/// `sequence_number` must be the account's current sequence number.
///
/// # Scheme support
///
/// This targets the classic rotation path, which supports Ed25519
/// (scheme `0`) and MultiEd25519 (scheme `1`) keys for both the source and
/// destination. `current` and `new_account`'s
/// [`signature_scheme`](Account::signature_scheme) /
/// [`public_key_bytes`](Account::public_key_bytes) are forwarded verbatim.
///
/// # Errors
///
/// Returns an error if either signature cannot be produced, the challenge cannot
/// be BCS-serialized, or the payload cannot be built.
pub fn build_rotate_auth_key_payload<A: Account, B: Account>(
    current: &A,
    new_account: &B,
    sequence_number: u64,
) -> AptosResult<TransactionPayload> {
    let challenge = RotationProofChallenge::new(
        sequence_number,
        current.address(),
        current.authentication_key().into(),
        new_account.public_key_bytes(),
    );
    let message = challenge.to_bcs()?;

    // `cap_rotate_key`: current key signs the challenge (proves current control).
    let cap_rotate_key = current.sign(&message)?;
    // `cap_update_table`: new key signs the challenge (proves ownership of the
    // key being rotated to).
    let cap_update_table = new_account.sign(&message)?;

    InputEntryFunctionData::rotate_authentication_key(
        current.signature_scheme(),
        current.public_key_bytes(),
        new_account.signature_scheme(),
        new_account.public_key_bytes(),
        cap_rotate_key,
        cap_update_table,
    )
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use crate::account::Ed25519Account;
    use crate::crypto::{Ed25519PublicKey, Ed25519Signature};
    use crate::transaction::TransactionPayload;

    #[test]
    fn challenge_sets_domain_fields() {
        let challenge =
            RotationProofChallenge::new(7, AccountAddress::ONE, AccountAddress::ONE, vec![1, 2, 3]);
        assert_eq!(challenge.account_address, AccountAddress::ONE);
        assert_eq!(challenge.module_name, "account");
        assert_eq!(challenge.struct_name, "RotationProofChallenge");
        assert_eq!(challenge.sequence_number, 7);
    }

    #[test]
    fn challenge_bcs_layout_is_pinned() {
        // 0x1 originator/auth-key keep the fixture compact and deterministic.
        let challenge = RotationProofChallenge::new(
            0,
            AccountAddress::ONE,
            AccountAddress::ONE,
            vec![0xaa, 0xbb],
        );
        let hex = const_hex::encode(challenge.to_bcs().unwrap());

        // Domain prefix, built from parts:
        //   account_address 0x1 (32B) || "account" (len 07 + bytes) ||
        //   "RotationProofChallenge" (len 16 + bytes)
        let mut expected_prefix = Vec::new();
        expected_prefix.extend_from_slice(AccountAddress::ONE.as_bytes());
        expected_prefix.push(7);
        expected_prefix.extend_from_slice(b"account");
        expected_prefix.push(22);
        expected_prefix.extend_from_slice(b"RotationProofChallenge");
        assert!(
            hex.starts_with(&const_hex::encode(&expected_prefix)),
            "challenge domain-prefix BCS drifted: {hex}",
        );

        // Trailer: sequence_number 0 (8B) || originator 0x1 (32B) ||
        // current_auth_key 0x1 (32B) || new_public_key vec (len 02 + aabb).
        assert!(
            hex.ends_with("02aabb"),
            "new_public_key encoding drifted: {hex}"
        );
    }

    #[test]
    fn rotate_payload_signs_challenge_with_both_keys() {
        let current = Ed25519Account::generate();
        let new_account = Ed25519Account::generate();

        let payload = build_rotate_auth_key_payload(&current, &new_account, 5).unwrap();
        let TransactionPayload::EntryFunction(ef) = payload else {
            panic!("expected entry function");
        };
        assert_eq!(ef.module.name.as_str(), "account");
        assert_eq!(ef.function, "rotate_authentication_key");
        assert_eq!(ef.args.len(), 6);

        // Reconstruct the exact challenge and verify both signatures over it.
        let challenge = RotationProofChallenge::new(
            5,
            current.address(),
            current.authentication_key().into(),
            new_account.public_key_bytes(),
        );
        let message = challenge.to_bcs().unwrap();

        // args: [from_scheme, from_pk, to_scheme, to_pk, cap_rotate_key, cap_update_table]
        // Each is individually BCS-encoded; scheme is a u8, keys/sigs are byte vectors.
        let from_scheme: u8 = aptos_bcs::from_bytes(&ef.args[0]).unwrap();
        let to_scheme: u8 = aptos_bcs::from_bytes(&ef.args[2]).unwrap();
        assert_eq!(from_scheme, 0, "ed25519 scheme");
        assert_eq!(to_scheme, 0, "ed25519 scheme");

        let cap_rotate_key: Vec<u8> = aptos_bcs::from_bytes(&ef.args[4]).unwrap();
        let cap_update_table: Vec<u8> = aptos_bcs::from_bytes(&ef.args[5]).unwrap();

        let current_pk = Ed25519PublicKey::from_bytes(&current.public_key_bytes()).unwrap();
        let new_pk = Ed25519PublicKey::from_bytes(&new_account.public_key_bytes()).unwrap();

        current_pk
            .verify(
                &message,
                &Ed25519Signature::from_bytes(&cap_rotate_key).unwrap(),
            )
            .expect("current key must sign the challenge");
        new_pk
            .verify(
                &message,
                &Ed25519Signature::from_bytes(&cap_update_table).unwrap(),
            )
            .expect("new key must sign the challenge");

        // Cross-check: the new key must NOT verify the current key's signature.
        assert!(
            new_pk
                .verify(
                    &message,
                    &Ed25519Signature::from_bytes(&cap_rotate_key).unwrap()
                )
                .is_err(),
        );
    }
}
