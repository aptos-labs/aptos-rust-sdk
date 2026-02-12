# Aptos Rust SDK -- Security Audit Report

**Date:** 2026-02-09
**Scope:** Full SDK (`aptos-sdk` v0.3.0, `aptos-sdk-macros` v0.1.0)
**Method:** 3-pass audit (automated surface scan, deep manual review, design-level assessment)
**Status:** All findings remediated (21 of 22 fixed; F-21 deferred as large effort). Response body reads now use incremental streaming with size limits (`read_response_bounded`) to prevent OOM from chunked transfer-encoding.

---

## Executive Summary

The Aptos Rust SDK demonstrates strong security fundamentals: `unsafe` code is forbidden at the crate level, all cryptographic operations delegate to well-audited libraries, private keys use `#[zeroize(drop)]` with `[REDACTED]` Debug output, and TLS certificate validation is enabled by default. No critical vulnerabilities that would allow key theft or transaction forgery were found.

The audit identified **22 findings** across 4 severity levels. **All findings have been remediated** except F-21 (fuzz targets), which requires significant new infrastructure and has been deferred.

**Finding Summary:**

| Severity | Count | Fixed |
|----------|-------|-------|
| Critical | 1     | 1     |
| High     | 3     | 3     |
| Medium   | 10    | 10    |
| Low      | 5     | 5     |
| Info     | 3     | 2 (F-21 deferred) |

---

## Pass 1: Automated Surface Scan Results

### 1a. Dependency Audit

**Status: CLEAN**

- `cargo audit`: 0 vulnerabilities in 334 crate dependencies.
- All crypto crates are current: `ed25519-dalek 2.2.0`, `k256 0.13.4`, `p256 0.13.2`, `blst 0.3.16`, `sha2 0.10.9`, `sha3 0.10.8`, `jsonwebtoken 10.3.0`.
- No yanked crates.

### 1b. Static Analysis

**Status: CLEAN with observations**

- `cargo clippy --all-features -D warnings`: 0 warnings.
- `#![forbid(unsafe_code)]` confirmed in `crates/aptos-sdk/src/lib.rs:58`.
- No `todo!()` or `unimplemented!()` in production code.
- 4 `unreachable!()` in `account/multi_key.rs` (guarded by feature flags -- acceptable).
- Production `expect()` calls cataloged:
  - 5 lock-poisoning expects in `aptos.rs` and `batch.rs` (standard Rust pattern).
  - 10 hardcoded URL parses in `config.rs` (static strings -- safe).
  - 1 BLS key generation in `bls12381.rs:52` (internal invariant).
  - 1 mnemonic validation in `mnemonic.rs:100` (post-validation invariant).

### 1c. Feature Flag Isolation

**Status: CLEAN**

All 8 optional features compile cleanly in isolation: `ed25519`, `secp256k1`, `secp256r1`, `bls`, `mnemonic`, `keyless`, `indexer`, `faucet`. Also compiles with `--no-default-features` and `--all-features`.

---

## Pass 2: Deep Manual Review Findings

### F-01: Path traversal via `abi.name` in codegen build helper [CRITICAL]

**File:** `crates/aptos-sdk/src/codegen/build_helper.rs:168-172`

**Issue:** The generated output filename uses `abi.name` directly from untrusted ABI JSON:

```rust
let output_filename = format!("{}.rs", abi.name);
let output_path = output_dir.join(&output_filename);
fs::write(&output_path, &code)?;
```

A malicious ABI with `"name": "../../../tmp/evil"` writes outside the intended output directory.

**Impact:** Arbitrary file write during build-time code generation.

**Recommendation:** Validate `abi.name` against `^[a-zA-Z_][a-zA-Z0-9_]*$` and/or verify the canonicalized output path starts with the output directory.

---

### F-02: Unbounded response body in `view_bcs` [HIGH]

**File:** `crates/aptos-sdk/src/api/fullnode.rs:561`

**Issue:** `view_bcs` reads the entire response body with no size check:

```rust
let bytes = response.bytes().await?;
```

Unlike other API methods that go through `handle_response_static` (which checks Content-Length), `view_bcs` has its own response handling path that skips this check entirely.

**Impact:** A malicious or compromised fullnode can force unbounded memory allocation, causing OOM.

**Recommendation:** Add a Content-Length check before `response.bytes()` or use bounded reads:

```rust
let bytes = response.bytes().await?;
if bytes.len() > max_response_size {
    return Err(AptosError::api(status.as_u16(), "response too large"));
}
```

---

### F-03: Content-Length check bypass via chunked encoding [HIGH]

**File:** `crates/aptos-sdk/src/api/fullnode.rs:701-712`

**Issue:** `handle_response_static` only checks `response.content_length()`. When the server uses chunked transfer encoding (no Content-Length header), `content_length()` returns `None` and the check is skipped. `response.json()` then reads the entire body with no limit.

**Impact:** A server can bypass the size check by omitting Content-Length, causing memory exhaustion.

**Recommendation:** After reading the body, enforce size limits. Consider reading bytes first with a streaming limit, then deserializing:

```rust
let bytes = response.bytes().await?;
if bytes.len() > max_response_size {
    return Err(AptosError::api(status, "response too large"));
}
let data: T = serde_json::from_slice(&bytes)?;
```

---

### F-04: Doc-string code injection in codegen generator [HIGH]

**File:** `crates/aptos-sdk/src/codegen/generator.rs:433-435, 381-383`

**Issue:** ABI-derived strings are written directly into `writeln!` output. Strings containing newlines can escape doc comments and inject arbitrary Rust code. For example, a struct field type `u64\n\npub malicious: u64,` would produce a valid additional struct field.

**Impact:** Code injection in generated Rust source during build time. Requires a crafted ABI file.

**Recommendation:** Sanitize all ABI-derived strings before embedding in generated code: strip/escape newlines, `{`, `}`, and `"` characters.

---

### F-05: `format_ident!` panic on invalid ABI identifiers in proc macros [MEDIUM]

**File:** `crates/aptos-sdk-macros/src/codegen.rs:121, 129, 170, 186, 262-263`

**Issue:** `format_ident!` is called with ABI-derived names. If the ABI contains names with invalid Rust identifier characters (e.g., `0x1::coin::Coin`, newlines, Unicode), `proc_macro2::Ident::new` panics with an ICE-like error.

**Recommendation:** Validate that ABI names are valid Rust identifiers before calling `format_ident!`, or return a clear compile error.

---

### F-06: Generated code uses `.unwrap()` for BCS serialization [MEDIUM]

**File:** `crates/aptos-sdk/src/codegen/types.rs:181-197`

**Issue:** The `to_bcs_arg` function generates code that calls `aptos_bcs::to_bytes(&x).unwrap()`. If serialization fails at runtime (unlikely but possible with unexpected types), the generated code panics instead of returning an error.

**Recommendation:** Generate `.map_err(|e| AptosError::Bcs(e.to_string()))?` instead of `.unwrap()`.

---

### F-07: `serde(rename)` string injection in codegen [MEDIUM]

**File:** `crates/aptos-sdk/src/codegen/generator.rs:439`

**Issue:** `field.name` from ABI JSON is interpolated directly into a `#[serde(rename = "...")]` attribute. If the name contains `"` or `\`, the generated attribute becomes syntactically invalid or malformed.

**Recommendation:** Escape `"` and `\` in field names, or validate that names contain only safe characters.

---

### F-08: `IndexerClient::with_url` and `FaucetClient::with_url` bypass URL scheme validation [MEDIUM]

**File:** `crates/aptos-sdk/src/api/indexer.rs:137-145`, `crates/aptos-sdk/src/api/faucet.rs:104-112`

**Issue:** Both `with_url()` convenience constructors accept arbitrary URLs without calling `validate_url_scheme()`. This allows `file://`, `gopher://`, or other dangerous schemes.

**Recommendation:** Add `validate_url_scheme()` calls to both `with_url()` methods.

---

### F-09: Error sanitization pattern list is incomplete [MEDIUM]

**File:** `crates/aptos-sdk/src/error.rs:160-168`

**Issue:** `SENSITIVE_PATTERNS` only covers 7 patterns. Missing patterns that could appear in error messages: `token`, `jwt`, `credential`, `api_key`, `apikey`, `access_token`, `refresh_token`, `pepper`.

**Recommendation:** Expand the pattern list to cover common secret patterns.

---

### F-10: `Display`/`to_string()` on errors can leak sensitive data [MEDIUM]

**File:** `crates/aptos-sdk/src/error.rs` (multiple variants)

**Issue:** `sanitized_message()` is opt-in. Callers who use `Display`/`to_string()` (the default in `?` propagation and logging) may inadvertently include private keys, mnemonics, or JWTs in log output. Variants like `InvalidPrivateKey`, `InvalidMnemonic`, `InvalidJwt` carry detail strings in their Display.

**Recommendation:** Consider making sanitization the default in `Display`, or at minimum add prominent documentation warning callers to use `sanitized_message()` for any logging.

---

### F-11: Entropy and seed material not zeroized in mnemonic derivation [MEDIUM]

**File:** `crates/aptos-sdk/src/account/mnemonic.rs`

**Issue:** In `Mnemonic::generate()`, the 16-byte entropy buffer is not explicitly zeroized before being dropped. Similarly, in `derive_ed25519_from_seed()`, the intermediate seed bytes and HMAC outputs are not zeroized. While Rust's stack variables are dropped, they are not zeroed -- the data remains in memory until overwritten.

**Recommendation:** Use `zeroize::Zeroizing` wrappers for entropy, seed, and intermediate key material:

```rust
let mut entropy = zeroize::Zeroizing::new([0u8; 16]);
OsRng.fill_bytes(entropy.as_mut());
```

---

### F-12: MoveSourceParser has no input size limit [MEDIUM]

**File:** `crates/aptos-sdk/src/codegen/move_parser.rs:90`

**Issue:** `let lines: Vec<&str> = source.lines().collect()` loads the entire Move source into memory with no size limit. A very large file can cause high memory usage.

**Recommendation:** Add a maximum input size check before parsing.

---

### F-13: Invalid module names in `generate_mod_file` [MEDIUM]

**File:** `crates/aptos-sdk/src/codegen/build_helper.rs:362-371`

**Issue:** Module names from `abi.name` are emitted directly as `pub mod {name};` without validation. Invalid characters can produce uncompileable or dangerous `mod.rs` content.

**Recommendation:** Validate module names match `^[a-zA-Z_][a-zA-Z0-9_]*$`.

---

### F-14: 100 MB default max response size is excessive [MEDIUM]

**File:** `crates/aptos-sdk/src/config.rs:64`

**Issue:** `DEFAULT_MAX_RESPONSE_SIZE` is 100 MB. Normal Aptos API responses are typically under 1 MB. A compromised node could force 100 MB allocations per request.

**Recommendation:** Lower the default to 10 MB with documentation explaining how to increase it for specific use cases.

---

### F-15: Lock poisoning propagates panics across threads [LOW]

**File:** `crates/aptos-sdk/src/aptos.rs:171-222`, `crates/aptos-sdk/src/transaction/batch.rs:544-553`

**Issue:** `chain_id.read().expect("chain_id lock poisoned")` will panic if any thread previously panicked while holding the lock. This converts a single-thread panic into a cascading failure.

**Recommendation:** Consider using `lock().unwrap_or_else(|e| e.into_inner())` to recover from poisoned locks, or document this behavior.

---

### F-16: `from_bytes` for ECDSA signatures may accept high-S values [LOW]

**File:** `crates/aptos-sdk/src/crypto/secp256k1.rs`, `crates/aptos-sdk/src/crypto/secp256r1.rs`

**Issue:** While signing always produces low-S signatures (preventing malleability), `Signature::from_bytes()` may accept high-S signatures from external sources. If verified signatures are used for identity purposes, this could allow signature malleability.

**Impact:** Low -- the Aptos blockchain itself enforces low-S, so this is only relevant for off-chain signature verification.

**Recommendation:** Consider normalizing or rejecting high-S signatures in `from_bytes()`.

---

### F-17: Error paths use unbounded `text()` and `json()` reads [LOW]

**File:** `crates/aptos-sdk/src/api/fullnode.rs:551, 769`

**Issue:** Error response bodies are read with `response.text().await.unwrap_or_default()` and `response.json().await.unwrap_or_default()` with no size limit. A malicious server could send a very large error body.

**Recommendation:** Truncate error body reads to a reasonable limit (e.g., 8 KB).

---

### F-18: Sponsored transaction default expiration doubled [LOW]

**File:** `crates/aptos-sdk/src/transaction/sponsored.rs` (~line 221-222)

**Issue:** `DEFAULT_EXPIRATION_SECONDS` appears to be applied twice in some code paths, resulting in a 20-minute expiration window instead of 10 minutes. Longer expiration windows increase replay risk.

**Recommendation:** Review and normalize expiration handling to ensure single application.

---

### F-19: `aptos_contract_file!` follows symlinks [LOW]

**File:** `crates/aptos-sdk-macros/src/lib.rs:146-147`

**Issue:** `std::fs::read_to_string` follows symlinks. A symlink under the project directory could cause reading of files outside the project.

**Impact:** Low -- the path is developer-controlled in the macro invocation.

**Recommendation:** For defense in depth, canonicalize the path and verify it remains under `CARGO_MANIFEST_DIR`.

---

### F-20: Private key printed in example code [INFO]

**File:** `crates/aptos-sdk/examples/account_management.rs:70-72`

```rust
let pk_hex = hex::encode(pk_bytes);
println!("Private key (hex): {}", pk_hex);
```

**Issue:** While clearly labeled as demonstration code, users may copy this pattern into production code.

**Recommendation:** Add a more prominent warning comment, or use `eprintln!("[DEMO ONLY] ...")` to make it clear this should never be replicated.

---

### F-21: Fuzzing infrastructure exists but has zero fuzz targets [INFO]

**Issue:** The `fuzzing` feature flag enables `proptest`, `proptest-derive`, and `arbitrary` dependencies, but no actual fuzz targets or property-based tests exist in the codebase.

**Recommendation:** Implement fuzz targets for high-risk parsing code:
- BCS deserialization of transactions and authenticators
- `AccountAddress::from_hex()` and `AccountAddress::from_bytes()`
- `TypeTag::from_str_strict()` and `EntryFunctionId::from_str_strict()`
- `MultiKeySignature::from_bytes()` and `MultiEd25519Signature::from_bytes()`
- ABI JSON parsing in codegen

---

### F-22: `specifications/tests/` directory referenced in docs but missing [INFO]

**Issue:** `CLAUDE.md` references "Behavioral specification tests in `specifications/tests/rust/`" but this directory does not exist.

**Recommendation:** Remove the stale reference or create the directory.

---

## Pass 3: Design-Level Assessment

### 3a. Implicit Threat Model

The SDK operates with the following trust boundaries:

| Actor | Trust Level | Notes |
|-------|------------|-------|
| SDK user (developer) | Fully trusted | Controls all inputs, keys, configuration |
| Fullnode API | Partially trusted | Responses used for gas estimation, sequence numbers, balances |
| Indexer API | Partially trusted | GraphQL responses for queries |
| Faucet API | Partially trusted | Only used on testnets |
| ABI providers | Trusted at build time | ABI files used for code generation |
| Move contracts | Untrusted | Executed on-chain, SDK just submits |

**Trust boundary violations identified:**
1. Fullnode responses are used to set gas prices and sequence numbers without validation beyond JSON parsing. A malicious fullnode could return inflated gas prices.
2. ABI files are treated as fully trusted for code generation but may come from untrusted sources (F-01, F-04, F-07).
3. `with_url()` constructors bypass URL validation (F-08).

### 3b. Missing Hardening

1. **Response body streaming** -- All response reads now use `read_response_bounded()` which pre-checks `Content-Length` and reads incrementally via `response.chunk()`, aborting early if the size limit is exceeded. Error body reads are also bounded. (Addresses F-02, F-03, F-17)
2. **Constant-time operations** -- Signature verification delegates to underlying crates (ed25519-dalek, k256, p256) which use constant-time comparison. The SDK itself does not perform any custom constant-time operations, which is correct.
3. **Fuzz testing** -- Infrastructure exists but is unused (F-21).
4. **Side-channel resistance** -- Signing operations use library implementations with side-channel resistance. Non-security-critical operations (address parsing, ABI processing) are not constant-time, which is acceptable.

### 3c. Positive Security Properties

The SDK demonstrates several strong security practices:

1. `#![forbid(unsafe_code)]` -- Prevents all unsafe Rust at the crate level.
2. `#[zeroize(drop)]` on all private key types with `[REDACTED]` Debug output.
3. Domain-separated signing with `sha3_256(b"APTOS::RawTransaction")` prefix.
4. BCS deterministic serialization prevents transaction malleability.
5. TLS enabled by default with no opt-out in the public API.
6. URL scheme validation blocks SSRF via dangerous protocols.
7. ECDSA low-S enforcement prevents signature malleability.
8. Error sanitization system with sensitive pattern redaction.
9. Retry logic with exponential backoff, jitter, and bounded max delay.
10. `checked_add` for sequence number arithmetic in batch transactions.

### 3d. Security Test Coverage Gaps

| Area | Current State | Recommendation |
|------|--------------|----------------|
| API response handling | 1 test in fullnode.rs | Add tests for oversized responses, missing Content-Length, chunked encoding |
| BCS deserialization | No malformed-input tests | Add tests with truncated, oversized, and corrupted BCS payloads |
| Authenticator parsing | No negative tests | Add tests with wrong-length keys, tampered signature bytes |
| Codegen with malicious ABI | No security tests | Add tests with path traversal, newlines, special chars in ABI names |
| Error leakage | Sanitization tested | Add tests verifying Display does not leak key material |
| Fuzz targets | 0 targets | Implement for parsers and deserializers |

---

## Remediation Roadmap

### Immediate (Critical/High)

| ID | Finding | Effort |
|----|---------|--------|
| F-01 | Validate `abi.name` in build_helper.rs | Small |
| F-02 | Add size check to `view_bcs` response | Small |
| F-03 | Use bounded body reads in `handle_response_static` | Medium |
| F-04 | Sanitize ABI strings in code generator | Medium |

### Short-term (Medium)

| ID | Finding | Effort |
|----|---------|--------|
| F-05 | Validate identifiers before `format_ident!` | Small |
| F-06 | Replace `.unwrap()` with error handling in generated code | Small |
| F-07 | Escape serde rename strings | Small |
| F-08 | Add `validate_url_scheme()` to `with_url()` methods | Small |
| F-09 | Expand sensitive pattern list | Small |
| F-10 | Document or default sanitized Display | Medium |
| F-11 | Zeroize entropy/seed in mnemonic derivation | Small |
| F-12 | Add input size limit to MoveSourceParser | Small |
| F-13 | Validate module names in generate_mod_file | Small |
| F-14 | Lower default max response size to 10 MB | Small |

### Long-term (Low/Info)

| ID | Finding | Effort |
|----|---------|--------|
| F-15 | Handle lock poisoning gracefully | Small |
| F-16 | Normalize/reject high-S signatures in from_bytes | Small |
| F-17 | Truncate error body reads | Small |
| F-18 | Fix sponsored transaction expiration | Small |
| F-19 | Canonicalize macro file paths | Small |
| F-20 | Improve example warnings | Small |
| F-21 | Implement fuzz targets | Large |
| F-22 | Fix stale doc reference | Trivial |
