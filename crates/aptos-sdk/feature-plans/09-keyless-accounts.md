# Keyless Accounts (AIP-61) — Re-implementation Guide

## Status: ❌ Removed — awaiting correct re-implementation

Support for keyless accounts that use OpenID Connect (OIDC) authentication
instead of a user-held private key.

## Why the previous implementation was removed

An earlier `keyless` feature shipped in this SDK and was **removed in its
entirety** because it was chain-incompatible on every axis — it could never have
produced a transaction the Aptos chain would accept, and it derived addresses
that no keyless account actually has. The specific defects were:

1. **Wrong auth-key scheme byte.** It defined `KEYLESS_SCHEME = 5` and derived
   addresses with it. aptos-core has no auth-key scheme `5`; scheme `5` is
   `Abstraction`. Keyless does **not** have a dedicated scheme byte.
2. **Wrong authenticator variant tag.** It added a top-level
   `AccountAuthenticator::Keyless` variant with BCS tag `5`. The chain parses
   tag `5` as `Abstraction`, so the authenticator would deserialize into the
   wrong variant.
3. **Wrong address derivation.** It computed
   `SHA3-256(H(iss) || H(aud) || H(sub) || pepper || 0x05)`, which is not the
   AIP-61 derivation and does not match aptos-core / the TS SDK.
4. **Wrong on-chain signature struct.** Its `KeylessSignature`
   (`{ephemeral_public_key, ephemeral_signature, proof}`) does not match the
   on-chain struct.
5. **Wrong ephemeral nonce.** It used 16 random bytes as the nonce instead of
   the Poseidon commitment the Aptos prover expects.
6. **Wrong service API shapes.** Its pepper/prover request and response bodies
   (`{jwt}` / `{jwt, ephemeral_public_key, nonce, pepper}`) do not match the
   real Aptos pepper and prover service schemas.

Critically, **no wire-format pin test and no address-derivation vector test**
existed, which is why the broken version shipped undetected. See the
`### Removed` entry in `crates/aptos-sdk/CHANGELOG.md`.

The removal deliberately kept the protocol-level `AnyPublicKey::Keyless` tag
(variant `3`) in `crypto::multi_key.rs`, because it is a real aptos-core
`AnyPublicKey` enum tag that MultiKey parsing must recognise; it is not part of
the removed feature.

## Goals

1. Support Google, Apple, and other OIDC providers.
2. Produce transactions the Aptos chain accepts (AIP-61 compliant).
3. Derive addresses that match aptos-core and the TypeScript SDK exactly.

## Non-Goals

- Running an OIDC provider (use existing providers).
- Storing user credentials (handled by the OIDC flow).
- Supporting non-OIDC authentication.

---

## Correct design (what a re-implementation MUST do)

The following requirements are derived from the audit of the removed code and
from AIP-61. They are load-bearing — get any of them wrong and transactions are
rejected on-chain or addresses do not match.

### Auth-key scheme

Keyless uses the **SingleKey** scheme (scheme byte `2`), **NOT** a dedicated
scheme byte. There is no scheme `5` in aptos-core (`5` is `Abstraction`).

### Authenticator encoding

A keyless signature rides **inside `AccountAuthenticator::SingleKey`
(variant tag 2)** as `AnyPublicKey::Keyless` (variant `3`) +
`AnySignature::Keyless` (variant `3`). It must **NOT** be a top-level
`AccountAuthenticator::Keyless` variant. (The old code used tag `5`, which the
chain parses as `Abstraction`.)

So the full nesting for a keyless-signed transaction is:

```
TransactionAuthenticator::SingleSender
  └─ AccountAuthenticator::SingleKey            (variant 2)
       ├─ AnyPublicKey::Keyless                 (variant 3)
       └─ AnySignature::Keyless                 (variant 3)
```

### Address derivation

```
auth_key = SHA3-256( BCS(AnyPublicKey::Keyless{ iss_val, idc }) || 0x02 )
```

- `0x02` is the SingleKey scheme suffix.
- `idc` is the **identifier commitment**: a Poseidon-BN254 commitment over
  pepper / aud / uid. It is **NOT** `SHA3-256(...)` of those fields.
- This replaces the removed code's incorrect
  `SHA3-256(H(iss) || H(aud) || H(sub) || pepper || 0x05)`.

### On-chain `KeylessSignature` struct

The on-chain struct fields are:

- `cert: EphemeralCertificate`
- `jwt_header_json: String`
- `exp_date_secs: u64`
- `ephemeral_pubkey`
- `ephemeral_signature`

The old struct (`{ephemeral_public_key, ephemeral_signature, proof}`) was wrong.

### Ephemeral nonce

The ephemeral nonce must be the **Poseidon commitment of
`(epk, exp_date, blinder)`** expected by the Aptos prover — **NOT** 16 random
bytes.

### Pepper / prover service APIs

Request and response bodies must match the real Aptos pepper and prover service
schemas — fields like `jwt_b64`, `epk`, `epk_blinder`, `exp_date_secs`,
`exp_horizon_secs`, `uid_key` — **not** the old `{jwt}` /
`{jwt, ephemeral_public_key, nonce, pepper}` shapes.

---

## Authentication flow

```
1. Generate ephemeral key pair (epk) + blinder; compute the Poseidon nonce.
         ↓
2. Redirect to the OIDC provider with that nonce embedded.
         ↓
3. User authenticates, provider returns a JWT bound to the nonce.
         ↓
4. Send the JWT (as jwt_b64) to the Pepper Service → get the pepper.
         ↓
5. Send JWT + epk + epk_blinder + exp_date_secs + exp_horizon_secs + uid_key
   to the Prover Service → get the ZK proof / EphemeralCertificate.
         ↓
6. Assemble AnyPublicKey::Keyless{iss_val, idc} and the on-chain
   KeylessSignature; derive the address via the SingleKey scheme.
         ↓
7. Sign the transaction's signing message with the ephemeral key and wrap it
   as SingleSender > SingleKey > (AnyPublicKey::Keyless, AnySignature::Keyless).
```

---

## Testing requirement (mandatory before this feature can be considered correct)

The absence of these tests is precisely why the broken version shipped. A
re-implementation **MUST** add:

1. A **wire-format pin test** for the SingleKey-wrapped keyless authenticator —
   byte-for-byte, in the same style as
   `test_single_key_single_sender_bcs_wire_format` in
   `src/transaction/authenticator.rs` — asserting the exact BCS bytes of
   `SingleSender > SingleKey > (AnyPublicKey::Keyless, AnySignature::Keyless)`.
2. An **address-derivation test against a known vector** from aptos-core or the
   TypeScript SDK, asserting the derived address equals the published value for
   a fixed `(iss, aud, uid, pepper, blinder)` input.

Neither test may merely print values; both must assert. Do not enable the
feature (or re-add it to `full`) until both pass.

---

## Security considerations

1. **Ephemeral key expiry.** Keys should expire (bounded by `exp_horizon_secs`).
2. **JWT validation.** Verify the JWT signature and claims before deriving.
3. **Pepper privacy.** Never expose or log pepper values.
4. **Proof freshness.** Proofs have limited validity tied to `exp_date_secs`.

---

## Dependencies (expected)

- Ed25519 crypto module (ephemeral key).
- HTTP client (`reqwest`) for pepper / prover services.
- A JWT parsing library.
- A Poseidon-BN254 implementation (for the nonce and identifier commitment) and
  Groth16 proof handling — the pieces the removed code lacked.
