# Aptos Rust SDK

> **Status:** work in progress. The current implementation primarily covers REST client plumbing, API type definitions, and Ed25519-based signing helpers. Several verification paths (e.g. multi-sig authenticators) are still marked `unimplemented!()`.

## Workspace Layout
- `crates/aptos-rust-sdk` – async REST client surface for fullnodes (`AptosFullnodeClient`) plus builders and response helpers.
- `crates/aptos-rust-sdk-types` – API types, serialization helpers, and Move value utilities consumed by the client.
- `crates/examples` – runnable binaries and async tests that demonstrate view functions, type parsing, and transaction workflows.

## Prerequisites
- Rust toolchain 1.85.0 (tracked in `rust-toolchain.toml`).
- Access to an Aptos fullnode REST endpoint (mainnet/testnet/devnet/localnet URLs are pre-configured in `AptosNetwork`).

```
cargo build
cargo test --package aptos-rust-sdk -- --nocapture
cargo test --package examples -- --nocapture # requires network access unless SKIP_NETWORK_TESTS=1
```

## Consuming the Crates
The crates are not published to crates.io (`publish = false`), so depend on the sources directly:

```toml
[dependencies]
aptos-rust-sdk = { git = "https://github.com/aptos-labs/aptos-rust-sdk", package = "aptos-rust-sdk" , branch = "main"}
aptos-rust-sdk-types = { git = "https://github.com/aptos-labs/aptos-rust-sdk", package = "aptos-rust-sdk-types" , branch = "main"}
```

When working inside this workspace, use the shared dependency definitions from `[workspace.dependencies]`.

## Building a Client
`AptosFullnodeClient` is constructed via the builder API:

```rust
use aptos_rust_sdk::client::builder::AptosClientBuilder;
use aptos_rust_sdk::client::config::AptosNetwork;

let client = AptosClientBuilder::new(AptosNetwork::testnet())
    .timeout(std::time::Duration::from_secs(10))
    .build();
let state = client.get_state().await?; // ledger metadata
```

The builder automatically adds the `x-aptos-client` header and supports optional API key injection through the `X_API_KEY` environment variable.

## Reading On-Chain Data
Common read paths are wrapped on the client:
- `get_state()` returns `State` decoded from ledger headers.
- `get_account_resources(address)` fetches account resources as JSON.
- `get_account_balance(address, asset_type)` hits the REST balance endpoint.
- `view_function(request)` issues `POST /v1/view` with typed Move arguments (`ViewRequest`).

See `view_function_example.rs` for end-to-end usage, including helper patterns and known limitations of the REST API (struct type arguments work reliably; vectors and primitive type arguments often fail).

## Constructing and Submitting Transactions
`crates/examples/src/lib.rs` demonstrates three transaction flows.

### Single-Signer Entry Function
1. Derive the sender address from an `AuthenticationKey`.
2. Fetch the sequence number via `get_account_resources`.
3. Build a `TransactionPayload::EntryFunction` with module/function identifiers and BCS-encoded arguments.
4. Create `RawTransaction::new(...)` with gas settings, expiration, and `ChainId`.
5. Sign `raw_txn.generate_signing_message()` with an `Ed25519PrivateKey` and wrap it using `TransactionAuthenticator::ed25519`.
6. Submit or simulate with `AptosFullnodeClient::submit_transaction` / `simulate_transaction`.

```rust
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use aptos_rust_sdk::client::builder::AptosClientBuilder;
use aptos_rust_sdk::client::config::AptosNetwork;
use aptos_rust_sdk_types::api_types::transaction::{
    EntryFunction, GenerateSigningMessage, RawTransaction, SignedTransaction, TransactionPayload,
};
use aptos_rust_sdk_types::api_types::transaction_authenticator::{
    AccountAuthenticator, AuthenticationKey, TransactionAuthenticator,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = AptosClientBuilder::new(AptosNetwork::testnet()).build();
    let state = client.get_state().await?;

    let seed_bytes = hex::decode("4aeeeb3f286caa91984d4a16d424786c7aa26947050b00e84ab7033f2aab0c2d")?;
    let key = Ed25519PrivateKey::try_from(seed_bytes.as_slice())?;
    let sender = AuthenticationKey::ed25519(&Ed25519PublicKey::from(&key)).account_address();

    let resources = client
        .get_account_resources(sender.to_string())
        .await?
        .into_inner();
    let sequence_number = resources
        .iter()
        .find(|r| r.type_ == "0x1::account::Account")
        .and_then(|r| r.data.get("sequence_number"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing sequence number"))?
        .parse::<u64>()?;

    let payload = TransactionPayload::EntryFunction(EntryFunction::new(
        aptos_rust_sdk_types::api_types::module_id::ModuleId::new(
            aptos_rust_sdk_types::api_types::address::AccountAddress::ONE,
            "aptos_account".to_string(),
        ),
        "transfer".to_string(),
        vec![],
        vec![
            aptos_rust_sdk_types::api_types::address::AccountAddress::ONE.to_vec(),
            1u64.to_le_bytes().to_vec(),
        ],
    ));

    let raw_txn = RawTransaction::new(
        sender,
        sequence_number,
        payload,
        11,                         // max_gas_amount
        100,                        // gas_unit_price
        state.timestamp_usecs / 1_000_000 + 600, // expiration timestamp (secs)
        aptos_rust_sdk_types::api_types::chain_id::ChainId::Testnet,
    );

    let signature = key.sign_message(&raw_txn.generate_signing_message()?);
    let signed = SignedTransaction::new(
        raw_txn,
        TransactionAuthenticator::ed25519(Ed25519PublicKey::from(&key), signature),
    );

    // Optional: simulate before submission
    client
        .simulate_transaction(SignedTransaction::new(
            signed.raw_txn().clone(),
            TransactionAuthenticator::single_sender(AccountAuthenticator::no_authenticator()),
        ))
        .await?;

    let response = client.submit_transaction(signed).await?;
    println!("submitted: {:?}", response.into_inner());
    Ok(())
}
```

### Fee Payer Flow
Use `RawTransactionWithData::new_multi_agent_with_fee_payer` to generate the signing message shared by the primary sender and the fee payer. Attach authenticators with `TransactionAuthenticator::fee_payer`, providing:
- the sender’s `AccountAuthenticator`
- any secondary signer authenticators
- the fee payer address and authenticator

### Multi-Agent Flow
`RawTransactionWithData::new_multi_agent` collects the base transaction and secondary signer addresses. Each participant signs the shared message. Construct the final authenticator with `TransactionAuthenticator::MultiAgent` and submit.

## Examples
- `cargo test -p examples --lib` runs async integration tests under `crates/examples/src/lib.rs` exercising the flows above.
- `cargo run -p examples --bin view_function_example` prints the view-function walkthrough.
- `cargo run -p examples --bin type_parsing_example` demonstrates Move type parsing utilities.

## Limitations and TODOs
- README reflects the current WIP status: transaction submission helpers exist but server-side behaviour can change rapidly, and the crate does not expose high-level wallet abstractions yet.
- Multi-sig verification paths (`TransactionAuthenticator::verify`, `AccountAuthenticator::verify`) are stubbed with `unimplemented!()`.
- View function support mirrors REST API constraints; vector type arguments and certain primitive type arguments are unreliable.
- Indexer client support is not implemented (`crates/aptos-rust-sdk/src/client/indexer.rs`).

Contributions and bug reports are welcome while the SDK stabilizes.
