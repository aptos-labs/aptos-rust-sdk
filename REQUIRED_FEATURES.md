# SDK Required features

This doc goes into the required features for an SDK, and what they should support.

## Binary Canonical Serialization (BCS)

It should support serialization and deserialization of:
- [ ] unsigned integers u8, u16, u32, u64, u128, u256
- [ ] signed integers i8, i16, i32, i64, i128, i256
- [ ] booleans bool
- [ ] vectors
- [ ] tuples
- [ ] fixed length vectors (and addresses)

Serialization should be provided as the native way for the language of the SDK.  More details of the specification can be found [here](https://github.com/aptos-labs/bcs)

## Transaction Signing

Transactions should be able to be signed and authorized with the following key types:
- [ ] Ed25519 (standalone) - `TransactionAuthenticator::Ed25519` (variant 0)
- [ ] MultiEd25519 - `TransactionAuthenticator::MultiEd25519` (variant 1)
- [ ] Ed25519 (Single Key) - `TransactionAuthenticator::SingleSender` > `AccountAuthenticator::SingleKey` > `AnyPublicKey::Ed25519` (variant 0)
- [ ] Secp256k1 (Single Key) - `TransactionAuthenticator::SingleSender` > `AccountAuthenticator::SingleKey` > `AnyPublicKey::Secp256k1Ecdsa` (variant 1)
- [ ] Secp256r1 (Single Key) - `TransactionAuthenticator::SingleSender` > `AccountAuthenticator::SingleKey` > `AnyPublicKey::Secp256r1Ecdsa` (variant 2)
- [ ] MultiKey - `TransactionAuthenticator::SingleSender` > `AccountAuthenticator::MultiKey` (variant 3)
- [ ] (Optional) Keyless - `TransactionAuthenticator::SingleSender` > `AccountAuthenticator::SingleKey` > `AnyPublicKey::Keyless` (variant 3)

### Transaction Signing Process

1. Build a `RawTransaction` with BCS serialization:
   ```
   RawTransaction {
     sender: AccountAddress (32 bytes)
     sequence_number: u64 (little-endian)
     payload: TransactionPayload (enum)
     max_gas_amount: u64 (little-endian)
     gas_unit_price: u64 (little-endian)
     expiration_timestamp_secs: u64 (little-endian)
     chain_id: ChainId (1 byte)
   }
   ```

2. Create signing message: `signing_message = SHA3-256_prefix || BCS(RawTransaction)`
   - The prefix is: `b5e97db07fa0bd0e5598aa3643a9bc6f6693bddc1a9fec9e674a461eaa00b193` (SHA3-256 of "APTOS::RawTransaction")

3. Sign the signing message with the appropriate key type

4. Create `SignedTransaction` = `RawTransaction + TransactionAuthenticator`

### TransactionAuthenticator Enum Variants

| Variant | Index | Description |
|---------|-------|-------------|
| Ed25519 | 0 | Single Ed25519 signature (97 bytes: 1 + 32 + 64) |
| MultiEd25519 | 1 | K-of-N Ed25519 multisig |
| MultiAgent | 2 | Multiple independent signers |
| FeePayer | 3 | Sponsored transaction |
| SingleSender | 4 | Modern unified format (recommended) |

### AccountAuthenticator Enum Variants (for SingleSender)

| Variant | Index | Description |
|---------|-------|-------------|
| Ed25519 | 0 | Legacy Ed25519 |
| MultiEd25519 | 1 | Legacy multi-Ed25519 |
| SingleKey | 2 | Modern single-key (supports multiple algorithms) |
| MultiKey | 3 | Modern multi-key (supports heterogeneous keys) |
| NoAccountAuthenticator | 4 | No authentication |
| Abstract | 5 | Abstract authentication |

### AnyPublicKey Enum Variants

| Variant | Index | Key Size |
|---------|-------|----------|
| Ed25519 | 0 | 32 bytes |
| Secp256k1Ecdsa | 1 | 65 bytes (uncompressed) |
| Secp256r1Ecdsa | 2 | 65 bytes (uncompressed) |
| Keyless | 3 | Variable |
| FederatedKeyless | 4 | Variable |

### AnySignature Enum Variants

| Variant | Index | Signature Size |
|---------|-------|----------------|
| Ed25519 | 0 | 64 bytes |
| Secp256k1Ecdsa | 1 | 64 bytes (r \|\| s) |
| WebAuthn | 2 | Variable |
| Keyless | 3 | Variable |

## Authentication Keys

Authentication keys must be able to be created for accounts that use:
- [ ] Ed25519 (standalone): `auth_key = SHA3-256(public_key || 0x00)` (scheme_id = 0)
- [ ] MultiEd25519: `auth_key = SHA3-256(serialized_multi_public_key || 0x01)` (scheme_id = 1)
- [ ] Ed25519 (Single Key): `auth_key = SHA3-256(BCS(AnyPublicKey::Ed25519) || 0x02)` (scheme_id = 2)
- [ ] Secp256k1 (Single Key): `auth_key = SHA3-256(BCS(AnyPublicKey::Secp256k1) || 0x02)` (scheme_id = 2)
- [ ] Secp256r1 (Single Key): `auth_key = SHA3-256(BCS(AnyPublicKey::Secp256r1) || 0x02)` (scheme_id = 2)
- [ ] MultiKey: `auth_key = SHA3-256(BCS(MultiKey) || 0x03)` (scheme_id = 3)
- [ ] (Optional) Keyless: `auth_key = SHA3-256(BCS(AnyPublicKey::Keyless) || 0x02)` (scheme_id = 2)

**Important**: The same key using different authenticator formats (e.g., Ed25519 standalone vs SingleKey(Ed25519)) will produce **different addresses** due to different scheme IDs.

### BCS Serialization Notes for Authentication Keys

- For SingleKey authentication, `BCS(AnyPublicKey)` includes the variant index:
  - Ed25519: `0x00 || public_key_bytes (32 bytes)`
  - Secp256k1: `0x01 || public_key_bytes (65 bytes)`
  - Secp256r1: `0x02 || public_key_bytes (65 bytes)`

- For MultiKey authentication:
  ```
  MultiKey {
    public_keys: Vec<AnyPublicKey>  // ULEB128 length + each serialized AnyPublicKey
    signatures_required: u8
  }
  ```

- For MultiEd25519 (legacy format, no length prefix):
  ```
  public_key_bytes = pk0 (32) || pk1 (32) || ... || pkN (32) || threshold (1)
  ```

## Key Types

Must support the following key types
- [ ] Ed25519 - 32-byte public key, 64-byte signature (EdDSA over Curve25519)
- [ ] Secp256k1 - 65-byte uncompressed public key (04 || x || y), 64-byte signature (r || s)
- [ ] Secp256r1 - 65-byte uncompressed public key (04 || x || y), WebAuthn signatures

All keys must support reading and outputting in AIP-80 format.

## Transaction Types

Transactions must be able to use the following replay protectors (not at the same time)
- [ ] Sequence Number - u64 field in RawTransaction, must equal on-chain sequence number
- [ ] Orderless (hash for 60s)

Transactions also must support the following types:
- [ ] Standard (Single sender) - Uses `TransactionAuthenticator::Ed25519` or `TransactionAuthenticator::SingleSender`
- [ ] Multiagent - Uses `TransactionAuthenticator::MultiAgent` (variant 2)
- [ ] Multisig - Uses `TransactionPayload::Multisig` (variant 3)
- [ ] Fee Payer (Sponsored) - Uses `TransactionAuthenticator::FeePayer` (variant 3)
- [ ] Multiagent fee payer - Combines MultiAgent and FeePayer patterns

### TransactionPayload Enum Variants

| Variant | Index | Description |
|---------|-------|-------------|
| Script | 0 | Execute a Move script |
| ModuleBundle | 1 | **Deprecated** - Do not use |
| EntryFunction | 2 | Call an entry function (most common) |
| Multisig | 3 | Execute via multisig account |

### EntryFunction Payload Structure

```
EntryFunction {
  module: ModuleId {
    address: AccountAddress (32 bytes)
    name: Identifier (ULEB128 length + UTF-8 bytes)
  }
  function: Identifier (ULEB128 length + UTF-8 bytes)
  ty_args: Vec<TypeTag> (ULEB128 length + each TypeTag)
  args: Vec<Vec<u8>> (ULEB128 length + each BCS-encoded argument)
}
```

### MultiEd25519 Signature Format (Legacy)

```
MultiEd25519Signature {
  signatures: sig0 (64) || sig1 (64) || ... || sigM (64)  // No length prefix
  bitmap: 4 bytes (bits indicate which keys signed, MSB first per byte)
}
```

### MultiKey Signature Format

```
MultiKeyAuthenticator {
  public_keys: MultiKey {
    public_keys: Vec<AnyPublicKey>
    signatures_required: u8
  }
  signatures: Vec<AnySignature>  // Ordered by key index
  signatures_bitmap: BitVec {
    num_bits: u16 (little-endian)
    bytes: Vec<u8>  // Packed bits, bit 0 = MSB of first byte
  }
}
```

Transactions are signed by BCS serializing the transaction payload.

## Account Addresses

Must support account addresses that are
- [ ] Parsable from string (hex format with or without 0x prefix)
- [ ] Outputs in AIP-40 format (LONG format: 64 hex characters with 0x prefix, lowercase, no trimming of leading zeros)

### Account Address Format

- Fixed 32 bytes (256 bits)
- Derived from the authentication key (which is the full 32-byte SHA3-256 hash)
- Special addresses: `0x1` (framework), `0x0` (VM), etc. should be left-padded with zeros

## References

- [Transaction Formats Specification](https://github.com/aptos-labs/aptos-core/tree/b5003a2266590e70669740044e1fe4c3d5aca955/specifications/transaction-formats)
- [BCS Specification](https://github.com/aptos-labs/bcs)
- [AIP-40: Account Address Standard](https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-40.md)
- [AIP-80: Key Format Standard](https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-80.md)
