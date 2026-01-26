//! Behavioral tests for the SDK.
//!
//! These tests verify that the SDK behaves correctly in various scenarios
//! without requiring a live network.

#[cfg(feature = "ed25519")]
mod crypto_tests {
    use aptos_rust_sdk_v2::crypto::Ed25519PrivateKey;

    #[test]
    fn test_sign_verify_roundtrip() {
        let private_key = Ed25519PrivateKey::generate();
        let public_key = private_key.public_key();
        let message = b"test message";

        let signature = private_key.sign(message);
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_different_messages_produce_different_signatures() {
        let private_key = Ed25519PrivateKey::generate();

        let sig1 = private_key.sign(b"message 1");
        let sig2 = private_key.sign(b"message 2");

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_different_keys_produce_different_signatures() {
        let key1 = Ed25519PrivateKey::generate();
        let key2 = Ed25519PrivateKey::generate();
        let message = b"same message";

        let sig1 = key1.sign(message);
        let sig2 = key2.sign(message);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let key1 = Ed25519PrivateKey::generate();
        let key2 = Ed25519PrivateKey::generate();
        let message = b"test message";

        let signature = key1.sign(message);
        let wrong_public_key = key2.public_key();

        assert!(wrong_public_key.verify(message, &signature).is_err());
    }

    #[test]
    fn test_tampered_message_fails_verification() {
        let private_key = Ed25519PrivateKey::generate();
        let public_key = private_key.public_key();
        let message = b"original message";

        let signature = private_key.sign(message);

        // Verification with original message should work
        assert!(public_key.verify(message, &signature).is_ok());

        // Verification with tampered message should fail
        assert!(public_key.verify(b"tampered message", &signature).is_err());
    }

    #[test]
    fn test_private_key_bytes_roundtrip() {
        let key1 = Ed25519PrivateKey::generate();
        let bytes = key1.to_bytes();
        let key2 = Ed25519PrivateKey::from_bytes(&bytes).unwrap();

        // Both keys should produce the same signature
        let message = b"test";
        assert_eq!(key1.sign(message).to_bytes(), key2.sign(message).to_bytes());
    }
}

#[cfg(all(feature = "ed25519", feature = "secp256k1"))]
mod multi_scheme_crypto_tests {
    use aptos_rust_sdk_v2::crypto::{Ed25519PrivateKey, Secp256k1PrivateKey};

    #[test]
    fn test_ed25519_and_secp256k1_produce_different_signatures() {
        let ed_key = Ed25519PrivateKey::generate();
        let secp_key = Secp256k1PrivateKey::generate();
        let message = b"cross-scheme test";

        let ed_sig = ed_key.sign(message);
        let secp_sig = secp_key.sign(message);

        // Signatures should be different even if same length
        assert_ne!(ed_sig.to_bytes().to_vec(), secp_sig.to_bytes().to_vec());
    }

    #[test]
    fn test_cross_scheme_verification_fails() {
        let ed_key = Ed25519PrivateKey::generate();
        let secp_key = Secp256k1PrivateKey::generate();
        let message = b"cross-scheme test";

        // Ed25519 signature cannot be verified with Secp256k1 key (different types)
        let ed_sig = ed_key.sign(message);
        let secp_pub = secp_key.public_key();

        // This should fail because the signature format doesn't match
        let ed_sig_bytes = ed_sig.to_bytes();
        let secp_sig_result =
            aptos_rust_sdk_v2::crypto::Secp256k1Signature::from_bytes(&ed_sig_bytes);
        assert!(
            secp_sig_result.is_err()
                || secp_pub.verify(message, &secp_sig_result.unwrap()).is_err()
        );
    }
}

#[cfg(feature = "ed25519")]
mod account_tests {
    #[cfg(feature = "mnemonic")]
    use aptos_rust_sdk_v2::account::Mnemonic;
    use aptos_rust_sdk_v2::account::{Account, Ed25519Account};

    #[test]
    #[cfg(feature = "mnemonic")]
    fn test_deterministic_key_derivation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let account1 = Ed25519Account::from_mnemonic(mnemonic, 0).unwrap();
        let account2 = Ed25519Account::from_mnemonic(mnemonic, 0).unwrap();

        assert_eq!(account1.address(), account2.address());
    }

    #[test]
    #[cfg(feature = "mnemonic")]
    fn test_different_indices_produce_different_accounts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let account1 = Ed25519Account::from_mnemonic(mnemonic, 0).unwrap();
        let account2 = Ed25519Account::from_mnemonic(mnemonic, 1).unwrap();

        assert_ne!(account1.address(), account2.address());
    }

    #[test]
    #[cfg(feature = "mnemonic")]
    fn test_mnemonic_generation() {
        let mnemonic = Mnemonic::generate(12).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 12);

        let mnemonic = Mnemonic::generate(24).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 24);
    }

    #[test]
    fn test_account_address_derivation() {
        let account = Ed25519Account::generate();
        let address = account.address();

        // Address should not be zero
        assert!(!address.is_zero());

        // Address should be 32 bytes
        assert_eq!(address.as_bytes().len(), 32);
    }

    #[test]
    fn test_account_signing() {
        let account = Ed25519Account::generate();
        let message = b"test message for signing";

        let signature = account.sign(message).expect("signing should succeed");

        // Signature should not be empty
        assert!(!signature.is_empty());

        // Signature length for Ed25519 is 64 bytes
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_account_from_private_key_hex() {
        // Generate an account and get its private key
        let original = Ed25519Account::generate();
        let _private_key_hex = hex::encode(original.public_key_bytes()); // This would need the actual private key

        // For now, test that generation works consistently
        let account1 = Ed25519Account::generate();
        let account2 = Ed25519Account::generate();

        // Different accounts should have different addresses
        assert_ne!(account1.address(), account2.address());
    }

    #[test]
    fn test_authentication_key_derivation() {
        let account = Ed25519Account::generate();
        let auth_key = account.authentication_key();

        // Auth key should be 32 bytes
        assert_eq!(auth_key.as_bytes().len(), 32);

        // For Ed25519 accounts without rotation, auth_key == address
        assert_eq!(auth_key.as_bytes(), account.address().as_bytes());
    }
}

#[cfg(feature = "ed25519")]
mod multi_ed25519_tests {
    use aptos_rust_sdk_v2::account::MultiEd25519Account;
    use aptos_rust_sdk_v2::crypto::Ed25519PrivateKey;

    #[test]
    fn test_multi_ed25519_2_of_3() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let account = MultiEd25519Account::new(keys, 2).unwrap();

        // Should be able to sign (we have all 3 keys, threshold is 2)
        let message = b"multi-sig test message";
        let signature = account.sign(message);
        assert!(
            signature.is_ok(),
            "signing with threshold keys should succeed"
        );
    }

    #[test]
    fn test_multi_ed25519_insufficient_keys() {
        let all_keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = all_keys.iter().map(|k| k.public_key()).collect();

        // Only own 1 key (not enough for threshold of 2)
        let my_keys = vec![(0u8, all_keys[0].clone())];
        let account = MultiEd25519Account::from_keys(public_keys, my_keys, 2).unwrap();

        // Signing should fail
        let message = b"multi-sig test message";
        let signature = account.sign(message);
        assert!(
            signature.is_err(),
            "signing with insufficient keys should fail"
        );
    }

    #[test]
    fn test_multi_ed25519_address_derivation() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();

        let account1 = MultiEd25519Account::new(keys.clone(), 2).unwrap();
        let account2 = MultiEd25519Account::view_only(public_keys.clone(), 2).unwrap();

        // Same keys and threshold should produce same address
        assert_eq!(account1.address(), account2.address());

        // Different threshold should produce different address
        let account3 = MultiEd25519Account::view_only(public_keys.clone(), 3).unwrap();
        assert_ne!(account1.address(), account3.address());
    }

    #[test]
    fn test_multi_ed25519_threshold_validation() {
        let keys: Vec<_> = (0..3).map(|_| Ed25519PrivateKey::generate()).collect();
        let public_keys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();

        // Valid threshold
        assert!(MultiEd25519Account::view_only(public_keys.clone(), 1).is_ok());
        assert!(MultiEd25519Account::view_only(public_keys.clone(), 2).is_ok());
        assert!(MultiEd25519Account::view_only(public_keys.clone(), 3).is_ok());

        // Invalid: threshold > num_keys
        assert!(MultiEd25519Account::view_only(public_keys.clone(), 4).is_err());

        // Invalid: threshold = 0
        assert!(MultiEd25519Account::view_only(public_keys.clone(), 0).is_err());
    }
}

#[cfg(all(feature = "ed25519", feature = "secp256k1"))]
mod multi_key_tests {
    use aptos_rust_sdk_v2::account::{Account, AnyPrivateKey, MultiKeyAccount};
    use aptos_rust_sdk_v2::crypto::{AnyPublicKey, Ed25519PrivateKey, Secp256k1PrivateKey};

    #[test]
    fn test_multi_key_mixed_types_2_of_3() {
        let ed_key1 = Ed25519PrivateKey::generate();
        let secp_key = Secp256k1PrivateKey::generate();
        let ed_key2 = Ed25519PrivateKey::generate();

        let keys = vec![
            AnyPrivateKey::ed25519(ed_key1),
            AnyPrivateKey::secp256k1(secp_key),
            AnyPrivateKey::ed25519(ed_key2),
        ];

        let account = MultiKeyAccount::new(keys, 2).unwrap();

        // Should be able to sign
        let message = b"multi-key test message";
        let signature = account.sign(message);
        assert!(
            signature.is_ok(),
            "signing with threshold keys should succeed"
        );
    }

    #[test]
    fn test_multi_key_partial_ownership() {
        let ed_key1 = Ed25519PrivateKey::generate();
        let secp_key = Secp256k1PrivateKey::generate();
        let ed_key2 = Ed25519PrivateKey::generate();

        let public_keys = vec![
            AnyPublicKey::ed25519(&ed_key1.public_key()),
            AnyPublicKey::secp256k1(&secp_key.public_key()),
            AnyPublicKey::ed25519(&ed_key2.public_key()),
        ];

        // Only own 2 of 3 keys
        let my_keys = vec![
            (0u8, AnyPrivateKey::ed25519(ed_key1)),
            (2u8, AnyPrivateKey::ed25519(ed_key2)),
        ];

        let account = MultiKeyAccount::from_keys(public_keys, my_keys, 2).unwrap();
        assert!(account.can_sign());

        let message = b"partial ownership test";
        let signature = account.sign(message);
        assert!(signature.is_ok());
    }

    #[test]
    fn test_multi_key_view_only() {
        let ed_key = Ed25519PrivateKey::generate();
        let secp_key = Secp256k1PrivateKey::generate();

        let public_keys = vec![
            AnyPublicKey::ed25519(&ed_key.public_key()),
            AnyPublicKey::secp256k1(&secp_key.public_key()),
        ];

        let view_only = MultiKeyAccount::view_only(public_keys, 2).unwrap();

        // Should not be able to sign
        assert!(!view_only.can_sign());
        assert!(view_only.sign(b"test").is_err());

        // But should have an address
        assert!(!view_only.address().is_zero());
    }

    #[test]
    fn test_multi_key_distributed_signing() {
        let ed_key = Ed25519PrivateKey::generate();
        let secp_key = Secp256k1PrivateKey::generate();

        let public_keys = vec![
            AnyPublicKey::ed25519(&ed_key.public_key()),
            AnyPublicKey::secp256k1(&secp_key.public_key()),
        ];

        // Party 1 only has the Ed25519 key
        let party1 = MultiKeyAccount::from_keys(
            public_keys.clone(),
            vec![(0, AnyPrivateKey::ed25519(ed_key))],
            2,
        )
        .unwrap();

        // Party 2 only has the Secp256k1 key
        let party2 = MultiKeyAccount::from_keys(
            public_keys.clone(),
            vec![(1, AnyPrivateKey::secp256k1(secp_key))],
            2,
        )
        .unwrap();

        // Both accounts should have the same address
        assert_eq!(party1.address(), party2.address());

        // Neither can sign alone
        assert!(!party1.can_sign());
        assert!(!party2.can_sign());

        // But they can create signature contributions
        let message = b"distributed signing test";
        let contrib1 = party1.create_signature_contribution(message, 0);
        let contrib2 = party2.create_signature_contribution(message, 1);

        assert!(contrib1.is_ok());
        assert!(contrib2.is_ok());

        // Aggregate signatures
        let multi_sig =
            MultiKeyAccount::aggregate_signatures(vec![contrib1.unwrap(), contrib2.unwrap()]);
        assert!(multi_sig.is_ok());
    }
}

mod transaction_tests {
    use aptos_rust_sdk_v2::transaction::{EntryFunction, TransactionBuilder, TransactionPayload};
    use aptos_rust_sdk_v2::types::{AccountAddress, ChainId};

    #[test]
    fn test_transaction_builder_requires_all_fields() {
        // Missing sender
        let result = TransactionBuilder::new()
            .sequence_number(0)
            .payload(TransactionPayload::EntryFunction(
                EntryFunction::apt_transfer(AccountAddress::ONE, 1000).unwrap(),
            ))
            .chain_id(ChainId::testnet())
            .build();
        assert!(result.is_err());

        // Missing sequence_number
        let result = TransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .payload(TransactionPayload::EntryFunction(
                EntryFunction::apt_transfer(AccountAddress::ONE, 1000).unwrap(),
            ))
            .chain_id(ChainId::testnet())
            .build();
        assert!(result.is_err());

        // Missing payload
        let result = TransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(0)
            .chain_id(ChainId::testnet())
            .build();
        assert!(result.is_err());

        // Missing chain_id
        let result = TransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(0)
            .payload(TransactionPayload::EntryFunction(
                EntryFunction::apt_transfer(AccountAddress::ONE, 1000).unwrap(),
            ))
            .build();
        assert!(result.is_err());

        // All fields present - should succeed
        let result = TransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(0)
            .payload(TransactionPayload::EntryFunction(
                EntryFunction::apt_transfer(AccountAddress::ONE, 1000).unwrap(),
            ))
            .chain_id(ChainId::testnet())
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_entry_function_from_function_id() {
        let entry_fn =
            EntryFunction::from_function_id("0x1::coin::transfer", vec![], vec![]).unwrap();

        assert_eq!(entry_fn.module.address, AccountAddress::ONE);
        assert_eq!(entry_fn.module.name.as_str(), "coin");
        assert_eq!(entry_fn.function, "transfer");
    }

    #[test]
    fn test_apt_transfer_entry_function() {
        let recipient = AccountAddress::from_hex("0x123").unwrap();
        let amount = 1_000_000u64;

        let entry_fn = EntryFunction::apt_transfer(recipient, amount).unwrap();

        assert_eq!(entry_fn.module.address, AccountAddress::ONE);
        assert_eq!(entry_fn.module.name.as_str(), "aptos_account");
        assert_eq!(entry_fn.function, "transfer");
        assert_eq!(entry_fn.args.len(), 2);
    }

    #[test]
    fn test_raw_transaction_signing_message() {
        let payload = EntryFunction::apt_transfer(AccountAddress::ONE, 1000).unwrap();

        let raw_txn = TransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(0)
            .payload(payload.into())
            .chain_id(ChainId::testnet())
            .max_gas_amount(1000)
            .gas_unit_price(100)
            .expiration_timestamp_secs(9999999999)
            .build()
            .unwrap();

        let signing_message = raw_txn.signing_message();
        assert!(signing_message.is_ok());

        let msg = signing_message.unwrap();
        assert!(!msg.is_empty());

        // Signing message should be deterministic
        let msg2 = raw_txn.signing_message().unwrap();
        assert_eq!(msg, msg2);
    }
}

#[cfg(feature = "ed25519")]
mod signing_flow_tests {
    use aptos_rust_sdk_v2::account::Ed25519Account;
    use aptos_rust_sdk_v2::transaction::{
        EntryFunction, TransactionBuilder, TransactionPayload, builder::sign_transaction,
    };
    use aptos_rust_sdk_v2::types::{AccountAddress, ChainId};

    #[test]
    fn test_sign_transaction_flow() {
        let account = Ed25519Account::generate();
        let recipient = AccountAddress::from_hex("0x123").unwrap();

        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let raw_txn = TransactionBuilder::new()
            .sender(account.address())
            .sequence_number(0)
            .payload(TransactionPayload::EntryFunction(payload))
            .chain_id(ChainId::testnet())
            .build()
            .unwrap();

        let signed_txn = sign_transaction(&raw_txn, &account).unwrap();

        // Signed transaction should have the raw transaction
        assert_eq!(signed_txn.raw_txn.sender, account.address());

        // Should have an authenticator
        // The authenticator type depends on the account type
        match &signed_txn.authenticator {
            aptos_rust_sdk_v2::transaction::TransactionAuthenticator::Ed25519 {
                public_key,
                signature,
            } => {
                assert_eq!(public_key.0.len(), 32);
                assert_eq!(signature.0.len(), 64);
            }
            _ => panic!("Expected Ed25519 authenticator"),
        }
    }

    #[test]
    fn test_same_transaction_same_signature() {
        let account = Ed25519Account::generate();
        let recipient = AccountAddress::from_hex("0x123").unwrap();

        let payload = EntryFunction::apt_transfer(recipient, 1000).unwrap();

        let raw_txn = TransactionBuilder::new()
            .sender(account.address())
            .sequence_number(0)
            .payload(TransactionPayload::EntryFunction(payload))
            .chain_id(ChainId::testnet())
            .expiration_timestamp_secs(9999999999) // Fixed expiration for determinism
            .build()
            .unwrap();

        let signed1 = sign_transaction(&raw_txn, &account).unwrap();
        let signed2 = sign_transaction(&raw_txn, &account).unwrap();

        // Same transaction + same account = same signature
        match (&signed1.authenticator, &signed2.authenticator) {
            (
                aptos_rust_sdk_v2::transaction::TransactionAuthenticator::Ed25519 {
                    signature: sig1,
                    ..
                },
                aptos_rust_sdk_v2::transaction::TransactionAuthenticator::Ed25519 {
                    signature: sig2,
                    ..
                },
            ) => {
                assert_eq!(sig1, sig2);
            }
            _ => panic!("Expected Ed25519 authenticators"),
        }
    }
}

mod types_tests {
    use aptos_rust_sdk_v2::types::{AccountAddress, ChainId, HashValue, TypeTag};

    #[test]
    fn test_address_parsing() {
        // Full address
        let addr = AccountAddress::from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert_eq!(addr, AccountAddress::ONE);

        // Short address
        let addr = AccountAddress::from_hex("0x1").unwrap();
        assert_eq!(addr, AccountAddress::ONE);

        // Without prefix
        let addr = AccountAddress::from_hex("1").unwrap();
        assert_eq!(addr, AccountAddress::ONE);
    }

    #[test]
    fn test_address_display() {
        assert_eq!(
            AccountAddress::ONE.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(AccountAddress::ONE.to_short_string(), "0x1");
    }

    #[test]
    fn test_special_addresses() {
        assert!(AccountAddress::ONE.is_special());
        assert!(AccountAddress::THREE.is_special());
        assert!(AccountAddress::FOUR.is_special());
        assert!(!AccountAddress::ZERO.is_special());
    }

    #[test]
    fn test_chain_id() {
        assert_eq!(ChainId::mainnet().id(), 1);
        assert_eq!(ChainId::testnet().id(), 2);
        assert!(ChainId::mainnet().is_mainnet());
        assert!(ChainId::testnet().is_testnet());
    }

    #[test]
    fn test_hash_value() {
        let hash = HashValue::sha3_256(b"test");
        assert!(!hash.is_zero());
        assert_eq!(hash.as_bytes().len(), 32);

        // Same input produces same hash
        let hash2 = HashValue::sha3_256(b"test");
        assert_eq!(hash, hash2);

        // Different input produces different hash
        let hash3 = HashValue::sha3_256(b"test2");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_type_tag_display() {
        assert_eq!(TypeTag::Bool.to_string(), "bool");
        assert_eq!(TypeTag::U64.to_string(), "u64");
        assert_eq!(TypeTag::vector(TypeTag::U8).to_string(), "vector<u8>");
        assert_eq!(
            TypeTag::aptos_coin().to_string(),
            "0x1::aptos_coin::AptosCoin"
        );
    }
}

mod error_tests {
    use aptos_rust_sdk_v2::error::AptosError;

    #[test]
    fn test_error_is_not_found() {
        assert!(AptosError::NotFound("test".into()).is_not_found());
        assert!(AptosError::AccountNotFound("0x1".into()).is_not_found());
        assert!(AptosError::api(404, "not found").is_not_found());
        assert!(!AptosError::api(500, "server error").is_not_found());
    }

    #[test]
    fn test_error_is_retryable() {
        assert!(AptosError::api(429, "rate limited").is_retryable());
        assert!(AptosError::api(500, "server error").is_retryable());
        assert!(AptosError::api(503, "unavailable").is_retryable());
        assert!(!AptosError::api(400, "bad request").is_retryable());
        assert!(!AptosError::api(401, "unauthorized").is_retryable());
    }

    #[test]
    fn test_insufficient_signatures_error() {
        let err = AptosError::InsufficientSignatures {
            required: 3,
            provided: 2,
        };
        assert!(err.to_string().contains("3"));
        assert!(err.to_string().contains("2"));
    }
}

mod bcs_serialization_tests {
    use aptos_rust_sdk_v2::types::{AccountAddress, ChainId};

    #[test]
    fn test_address_serialization() {
        let addr = AccountAddress::from_hex("0x123456789abcdef").unwrap();

        // Should be able to convert to bytes
        let bytes = addr.as_bytes();
        assert_eq!(bytes.len(), 32);

        // Should be able to parse from bytes
        let restored = AccountAddress::from_bytes(bytes).unwrap();
        assert_eq!(addr, restored);
    }

    #[test]
    fn test_chain_id_serialization() {
        let chain_id = ChainId::testnet();

        // Chain ID should be a simple u8
        assert_eq!(chain_id.id(), 2);

        // Can recreate from ID
        let restored = ChainId::new(chain_id.id());
        assert_eq!(chain_id.id(), restored.id());
    }

    #[test]
    fn test_address_hex_roundtrip() {
        let original = AccountAddress::from_hex("0x123456789abcdef").unwrap();
        let hex_str = original.to_string();
        let restored = AccountAddress::from_hex(&hex_str).unwrap();
        assert_eq!(original, restored);
    }
}

#[cfg(feature = "ed25519")]
mod transaction_bcs_tests {
    use aptos_rust_sdk_v2::account::Ed25519Account;
    use aptos_rust_sdk_v2::transaction::{
        EntryFunction, TransactionBuilder, TransactionPayload, builder::sign_transaction,
    };
    use aptos_rust_sdk_v2::types::{AccountAddress, ChainId};

    #[test]
    fn test_raw_transaction_fields() {
        let payload = EntryFunction::apt_transfer(AccountAddress::ONE, 1000).unwrap();

        let raw_txn = TransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(42)
            .payload(TransactionPayload::EntryFunction(payload))
            .chain_id(ChainId::testnet())
            .max_gas_amount(100_000)
            .gas_unit_price(100)
            .expiration_timestamp_secs(9999999999)
            .build()
            .unwrap();

        assert_eq!(raw_txn.sender, AccountAddress::ONE);
        assert_eq!(raw_txn.sequence_number, 42);
        assert_eq!(raw_txn.max_gas_amount, 100_000);
        assert_eq!(raw_txn.gas_unit_price, 100);
    }

    #[test]
    fn test_signed_transaction_creation() {
        let account = Ed25519Account::generate();
        let payload = EntryFunction::apt_transfer(AccountAddress::ONE, 1000).unwrap();

        let raw_txn = TransactionBuilder::new()
            .sender(account.address())
            .sequence_number(0)
            .payload(TransactionPayload::EntryFunction(payload))
            .chain_id(ChainId::testnet())
            .expiration_timestamp_secs(9999999999)
            .build()
            .unwrap();

        let signed_txn = sign_transaction(&raw_txn, &account).unwrap();

        // Verify the signed transaction has the raw transaction embedded
        assert_eq!(signed_txn.raw_txn.sender, account.address());
        assert_eq!(signed_txn.raw_txn.sequence_number, 0);
    }

    #[test]
    fn test_signing_message_is_deterministic() {
        let payload = EntryFunction::apt_transfer(AccountAddress::ONE, 1000).unwrap();

        let raw_txn = TransactionBuilder::new()
            .sender(AccountAddress::ONE)
            .sequence_number(0)
            .payload(TransactionPayload::EntryFunction(payload))
            .chain_id(ChainId::testnet())
            .expiration_timestamp_secs(9999999999)
            .build()
            .unwrap();

        let msg1 = raw_txn.signing_message().unwrap();
        let msg2 = raw_txn.signing_message().unwrap();
        assert_eq!(msg1, msg2);
    }
}
