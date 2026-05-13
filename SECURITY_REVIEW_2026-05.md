# Aptos Rust SDK -- Security Review (2026-05)

This review supplements [`SECURITY_AUDIT.md`](./SECURITY_AUDIT.md) (Feb 2026)
with new findings and assessments produced during the May 2026 full-SDK
audit. The Feb 2026 audit covered 22 findings, all of which were either
remediated or knowingly deferred (F-21 fuzz targets). The work in this
review specifically looks at:

1. Whether any of those previously-remediated findings have regressed.
2. Whether the audit's correctness fixes introduced new vulnerabilities.
3. New issues uncovered while exercising the SDK end-to-end against devnet.

The full code-correctness story is in
[`AUDIT_SUMMARY_2026-05.md`](./AUDIT_SUMMARY_2026-05.md); this document
focuses strictly on security-relevant items.

---

## Scope of this review

* **Crate under review:** `aptos-sdk` v0.4.1, `aptos-sdk-macros` v0.2.1.
* **Method:** Manual diff review of every change in the audit branch,
  plus targeted re-execution of the pre-existing security regression
  tests, plus deliberate inspection of new attack surface introduced
  by the audit (custom BCS serialisation, faucet looping, devnet
  auto-resolution of chain ID).
* **Out of scope:** smart-contract logic deployed via the SDK; the
  underlying cryptographic primitives (k256, p256, ed25519-dalek, blst);
  the fullnode and indexer APIs themselves.

---

## Executive summary

**No new high-severity issues introduced.** Three new low-severity items
are tracked below (S-23 through S-25). The high-impact correctness fixes
in the May audit (`AccountAuthenticator` custom Serialize, secp256k1
SHA-3-256 alignment, multi-key bitmap MSB-first) are pure correctness fixes:
they bring the SDK into agreement with the chain's authoritative
implementation and *increase* security by removing several "fail-open"
behaviours where invalid signatures, invalid auth keys, or unparseable
authenticators silently succeeded in unit tests but were rejected on the
live chain.

**All Feb-2026 high-and-critical fixes still hold.** The pedantic-clippy
gate, `#![forbid(unsafe_code)]`, response-body bound checks, URL scheme
validation, low-S enforcement, and `zeroize`-on-drop private-key handling
are all intact and verified by passing tests.

---

## Pass 1 -- Regression check against the Feb 2026 findings

| ID | Description | Still fixed? | Notes |
|----|-------------|--------------|-------|
| F-01 | Path traversal via `abi.name` in codegen | yes | `aptos-sdk-macros` and `codegen/build_helper.rs` unchanged in this audit |
| F-02 | `view_bcs` unbounded body | yes | `read_response_bounded` still in use |
| F-03 | Chunked-encoding bypass | yes | unchanged |
| F-04 | Codegen doc-string injection | yes | unchanged |
| F-05 | `format_ident!` panic on bad ABI | yes | unchanged |
| F-06 | Codegen `.unwrap()` on BCS | yes | unchanged |
| F-07 | Codegen serde rename injection | yes | unchanged |
| F-08 | `with_url` SSRF | yes | `validate_url_scheme` calls intact |
| F-09 | Sensitive pattern list | yes | unchanged |
| F-10 | Display leakage docs | yes | unchanged |
| F-11 | Mnemonic entropy zeroize | yes | unchanged |
| F-12 | MoveSourceParser size limit | yes | unchanged |
| F-13 | Codegen invalid module names | yes | unchanged |
| F-14 | 10 MB default max response | yes | unchanged |
| F-15 | Lock poisoning | yes | unchanged (and `chain_id` is now atomic anyway) |
| F-16 | ECDSA high-S in `from_bytes` | **strengthened** | secp256k1/secp256r1 `from_bytes` and `verify` still reject high-S; see S-25 |
| F-17 | Error-body unbounded reads | yes | unchanged |
| F-18 | Sponsored expiration doubled | yes | unchanged |
| F-19 | `aptos_contract_file!` symlinks | yes | unchanged |
| F-20 | Example prints private key | partial | the example printout is unchanged; see S-23 |
| F-21 | Fuzz targets missing | **still deferred** | see S-24 |
| F-22 | Stale doc reference | yes | unchanged |

No regressions detected.

---

## Pass 2 -- Targeted review of audit changes

### A. Custom `Serialize` for `AccountAuthenticator`

The May audit replaces `#[derive(Serialize)]` on `AccountAuthenticator` with
a hand-written impl that emits the public_key/signature byte runs **without
the ULEB128 length prefix** for the `SingleKey`, `MultiKey`, and `Keyless`
variants. The Ed25519 and MultiEd25519 variants are unchanged.

**Security implications considered:**

* **Buffer truncation / over-read.** The custom impl uses
  `Serializer::serialize_tuple(bytes.len())`. `aptos_bcs::ser` implements
  `serialize_tuple` as a no-prefix sequence of element writes; the length is
  used only to bound iteration. There is no path by which the inner-byte
  loop reads past `bytes.len()`.

* **Length confusion / wrong-length acceptance.** Because the outer
  framing is gone for these variants, callers MUST provide
  `public_key`/`signature` whose bytes are *already* BCS-encoded as
  `AnyPublicKey` / `AnySignature` / `MultiKeyPublicKey` / `MultiKeySignature`.
  This is exactly what `Account::public_key_bytes` and
  `Account::sign` now produce; the call sites are private to the SDK
  (`builder::sign_transaction` and friends) so the invariant is locally
  enforceable. Downstream code that hand-builds these structs by hand
  *could* pass raw, unframed bytes and the chain would reject the
  transaction with a deserialization error. That is the same failure mode
  the SDK had before the fix, just shifted from "always-broken" to
  "broken only if you bypass the safe API"; net security exposure is
  unchanged or improved.

* **`Deserialize` impl.** The hand-rolled `Deserialize` uses a private
  `Compat` enum with the legacy `Vec<u8>` fields. This is used **only for
  round-tripping the SDK's own representation back into Rust** -- e.g. in
  the existing unit tests. The SDK never deserialises foreign on-wire bytes
  into `AccountAuthenticator`; that happens on the node side. There is
  therefore no risk of accepting a malformed on-wire authenticator via
  this path.

**Conclusion:** no new security exposure.

### B. `Aptos::fund_account` loop

The audit changed `fund_account` to call the faucet repeatedly until the
on-chain balance has grown by the requested amount, capped at 16 attempts.

**Security implications considered:**

* **DoS amplification against the faucet.** A malicious caller could in
  theory request, e.g., `u64::MAX` octas and trigger 16 faucet calls. The
  pre-existing per-call faucet retry (max 3 retries) and the SDK-side cap
  of 16 attempts means at most ~48 outbound HTTP requests per
  `fund_account()` call. Each devnet faucet call is also explicitly
  rate-limited server-side (we observed `429 Request rejected by 1 checkers`
  even from a single client). The amplification factor is bounded and far
  less than what a determined attacker could already achieve by calling
  `FaucetClient::fund` themselves.

* **Resource leak on early-exit failure.** If a faucet call partially
  succeeds (returns hashes) but `wait_for_transaction` errors out for any
  of them, the loop returns an error and the already-accumulated hashes
  are discarded. This is a UX nuisance, not a security issue: any funds
  already minted onto the address remain on-chain and can be observed via
  the public ledger.

* **Pre-existing-balance read.** `fund_account` reads
  `get_balance(address)` before looping. A long-running attacker that
  watches the address could in principle interleave a (much larger)
  withdrawal between our pre-read and our first faucet call, causing us to
  request more octas than we expected. This is purely a developer-tool
  ergonomic concern, not a security boundary: the caller is funding their
  own test account from a public faucet.

**Conclusion:** no new security exposure.

### C. Devnet chain-ID auto-resolution

`Network::Devnet.chain_id()` now returns `0` and the live chain ID is
fetched on first use via `Aptos::ensure_chain_id`.

**Security implications considered:**

* **Cross-chain replay.** This change *narrows* the attack surface: with
  the previous hardcoded value (165), the SDK would sign devnet
  transactions with a chain ID the chain didn't accept. The new behaviour
  binds the signed transaction to the actual chain the SDK is configured
  to talk to, exactly as desired.

* **Trusting the fullnode for chain ID.** A compromised fullnode could
  return a misleading chain ID and cause the SDK to sign for a different
  chain than the developer intended. This is the same threat model as
  trusting the fullnode for sequence numbers, balances, and gas prices
  (see SECURITY_AUDIT.md "Implicit Threat Model"). The mitigation remains
  the same: if you need to bind to a specific chain ID, set it explicitly
  via `AptosConfig::custom(url).with_chain_id(...)` or use
  `AptosConfig::mainnet()`/`::testnet()` which return ChainId immediately
  without a network round-trip.

**Conclusion:** no new security exposure; modestly improves chain-binding
correctness for devnet users.

### D. `Aptos::simulate` builds a zero-signature SignedTransaction

The audit replaces the previous `sign_transaction(&raw_txn, account)` call
inside `Aptos::simulate` with a manually constructed `SignedTransaction`
whose authenticator carries the real public key and a 64-byte zero
signature.

**Security implications considered:**

* **No private-key exposure.** The function no longer invokes
  `account.sign(...)`; the private key is not touched during simulation.
  This is *strictly safer* than the prior behaviour, which produced a real
  signature over a transaction the caller never intended to submit.

* **The simulator accepts the resulting bytes.** The simulator endpoint
  is explicitly defined to allow zero-signed transactions for gas
  estimation; that is precisely the scenario we exercise. There is no
  scenario in which the chain accepts the simulated bytes as a *real*
  transaction because the signature is all-zero.

**Conclusion:** modest *improvement* in attack surface (key material no
longer flows through the gas-estimation path).

### E. ECDSA signing alignment with the chain (`secp256k1` SHA-3-256)

The audit changed `Secp256k1PrivateKey::sign` to hash the message with
`SHA3-256` and call `PrehashSigner::sign_prehash` instead of the SHA-256
double-hash via `Signer::sign`.

**Security implications considered:**

* **Cross-protocol signature reuse.** This change makes the signature
  bind to `SHA3-256(signing_message)`, which is the Aptos signing message
  hash. Because the signing message itself starts with
  `SHA3-256("APTOS::RawTransaction")`, the signature is domain-separated
  from any other ECDSA-over-SHA-256 protocol (e.g., Ethereum, Bitcoin,
  generic EIP-191) the same key might be used in. The previous
  double-SHA-256 was domain-separated from those protocols *by accident*;
  the new behaviour is domain-separated *by construction*.

* **Cross-key reuse within Aptos.** A signature for the same signing
  message with the same key is still unique on the chain; the change
  only affects how the SDK computes the digest. Low-S normalization is
  preserved.

**Conclusion:** modest *improvement* in domain separation.

---

## Pass 3 -- New findings

### S-23: Example program prints private key (recurrence of F-20) [INFO]

**File:** `crates/aptos-sdk/examples/account_management.rs:70-72`

Unchanged from the Feb 2026 audit. The example deliberately prints the
private key in hex to demonstrate the API surface, and is clearly labeled
as demonstration code, but a developer might copy-paste this pattern into
production.

**Recommendation:** This audit did not touch the example, so the original
recommendation stands -- add a `eprintln!("[DEMO ONLY] ...")` prefix and a
clear comment explaining why this code must never be replicated in
production.

### S-24: Fuzz targets still missing (recurrence of F-21) [INFO]

The May audit added BCS wire-format unit tests
(`test_account_authenticator_single_key_bcs_wire_format`,
`test_multi_key_authenticator_bcs_wire_format`) that pin the expected
on-wire layout. These are deterministic and catch regressions but do not
explore the malformed-input space. The `fuzzing` feature flag still pulls
in `proptest`, `proptest-derive`, and `arbitrary` but no actual targets
exist.

**Recommendation (unchanged):** Implement fuzz targets for at minimum:

* `BCS(SignedTransaction)` / `BCS(AccountAuthenticator)` -- exercise
  parser robustness with random inputs.
* `MultiKeyPublicKey::from_bytes`, `MultiKeySignature::from_bytes` --
  ensure the bitmap/length checks are tight.
* `MultiEd25519Signature::from_bytes` -- same.
* `AnyPublicKey::to_bcs_bytes` round-trip identity for arbitrary input
  shapes.

### S-25: ECDSA signature verification path coverage [LOW]

The May audit added `PrehashVerifier`-based verification but the on-chain
contract is slightly stricter than the SDK in one respect:
`aptos-crypto::secp256r1_ecdsa::Signature::check_s_malleability` checks
S strictly less than `n/2`. The SDK rejects `normalize_s().is_some()`,
which is equivalent for any well-formed signature but does not
distinguish "S == ORDER_HALF" (which `check_s_malleability` rejects with
`CanonicalRepresentationError`) from "S == 0" or other edge cases.

The k256 / p256 crates already reject `s == 0` at the Signature
construction level (the type uses `NonZeroScalar`), so `s == 0` cannot
flow through the SDK at all. `S == ORDER_HALF` is rejected by both
`normalize_s` (returns `Some` because we strictly require `s < n/2`,
matching the chain check). So the practical behaviour matches.

**Recommendation:** add a regression unit test in
`crypto/secp256r1.rs::tests` that constructs a signature with
`S == ORDER_HALF` and asserts that `verify` rejects it, locking down the
parity with the chain for any future refactor of the malleability check.

### Not findings, but worth noting

* The audit's `fund_account` loop reads the on-chain balance using the
  same fullnode that the SDK is otherwise configured against. A malicious
  fullnode could in theory under-report the balance and cause the loop to
  keep funding indefinitely up to the 16-attempt cap. The cap bounds the
  damage; the malicious node is also already trusted for sequence numbers
  and gas prices in the same `Aptos` instance, so this is not a new
  trust boundary.

* `AnyPublicKey::secp256k1` / `::secp256r1` now use 65-byte SEC1
  uncompressed encoding. The 64-byte `to_raw_bytes` accessor is still
  exposed for callers that want to interoperate with
  `aptos-stdlib::secp256k1::ecdsa_raw_public_key_from_64_bytes`. There is
  no scenario where mixing the two formats causes a security boundary
  violation, but the documentation now makes the intent explicit.

---

## Summary table

| Severity | Pre-existing | New (May 2026) | Remediated in May 2026 |
|----------|--------------|----------------|------------------------|
| Critical | 1 (F-01)     | 0              | 1 (F-01 already fixed) |
| High     | 3 (F-02..04) | 0              | 3 already fixed        |
| Medium   | 10           | 0              | all already fixed      |
| Low      | 5            | 1 (S-25)       | F-16 strengthened      |
| Info     | 3 (F-20..22) | 2 (S-23, S-24) | F-22 fixed             |

**Overall posture:** the SDK's security posture is unchanged or modestly
*improved* by the May audit. The new findings (S-23, S-24, S-25) are
either recurrences of previously-deferred items or low-impact hardening
opportunities. There is no known vulnerability in the SDK that could
allow key theft, transaction forgery, replay against an unintended
chain, or denial of service beyond what was already documented in
SECURITY_AUDIT.md.
