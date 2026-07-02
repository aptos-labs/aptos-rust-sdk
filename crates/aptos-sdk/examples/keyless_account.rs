//! Example: Keyless (OIDC) account creation and transaction signing
//!
//! This example demonstrates how to:
//! 1. Generate an ephemeral key pair (embed its nonce in your IdP OAuth URL)
//! 2. Persist the ephemeral key across the OAuth redirect
//! 3. Derive a [`KeylessAccount`] from an OIDC JWT using Aptos pepper / prover services
//! 4. Query account state and sign a transfer transaction
//!
//! # Prerequisites
//!
//! - Enable the `keyless` feature (see `Cargo.toml` below).
//! - Register an OAuth client with your identity provider and configure the
//!   Aptos [Keyless integration guide](https://aptos.dev/build/guides/aptos-keyless/integration-guide).
//! - Obtain a JWT by completing the OAuth redirect. The JWT must include the
//!   `nonce` claim matching the ephemeral key generated in step 1.
//!
//! # Running
//!
//! **Step 1** — generate and persist an ephemeral key (note the nonce and storage path):
//!
//! ```text
//! cargo run --example keyless_account --features "keyless,ed25519,faucet"
//! ```
//!
//! Complete the IdP login using the printed nonce, then **step 2** — derive the account:
//!
//! ```text
//! APTOS_KEYLESS_JWT="eyJ..." \
//!   cargo run --example keyless_account --features "keyless,ed25519,faucet"
//! ```
//!
//! The second run reloads the ephemeral key from the same storage file so the JWT
//! nonce matches. Override the path with `APTOS_KEYLESS_EPK_FILE` if needed.

use aptos_sdk::{
    Aptos, AptosConfig,
    account::{Account, EphemeralKeyPair, HttpPepperService, HttpProverService, KeylessAccount},
    config::Network,
    transaction::EntryFunction,
};
use std::path::{Path, PathBuf};
use url::Url;

const EPK_FILE_ENV: &str = "APTOS_KEYLESS_EPK_FILE";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Keyless Account Example ===\n");

    let storage_path = ephemeral_storage_path();
    let ephemeral = load_or_create_ephemeral(&storage_path)?;

    println!("--- Ephemeral key ---");
    println!("Nonce:        {}", ephemeral.nonce());
    println!("Storage file: {}", storage_path.display());
    if ephemeral.is_expired() {
        anyhow::bail!(
            "Stored ephemeral key has expired. Delete {} and re-run step 1.",
            storage_path.display()
        );
    }

    let jwt = match std::env::var("APTOS_KEYLESS_JWT") {
        Ok(token) if !token.is_empty() => token,
        _ => {
            print_setup_instructions(ephemeral.nonce(), &storage_path);
            return Ok(());
        }
    };

    // Connect to devnet and wire up Aptos-hosted pepper / prover services.
    let aptos = Aptos::new(AptosConfig::devnet())?;
    println!(
        "\nConnected to devnet (chain_id: {})",
        aptos.chain_id().id()
    );

    let pepper_url = Network::Devnet
        .pepper_url()
        .expect("devnet has a default pepper URL");
    let prover_url = Network::Devnet
        .prover_url()
        .expect("devnet has a default prover URL");

    let pepper_service = HttpPepperService::new(Url::parse(pepper_url)?);
    let prover_service = HttpProverService::new(Url::parse(prover_url)?);

    println!("Pepper service: {pepper_url}");
    println!("Prover service: {prover_url}");

    println!("\n--- Deriving KeylessAccount ---");
    let account =
        KeylessAccount::from_jwt(&jwt, ephemeral, &pepper_service, &prover_service).await?;

    println!("Address:  {}", account.address());
    println!("Issuer:   {}", account.issuer());
    println!("Audience: {}", account.audience());
    println!("User ID:  {}", account.user_id());
    println!("Valid:    {}", account.is_valid());

    let balance = aptos.get_balance(account.address()).await?;
    println!("\n--- Account state ---");
    println!(
        "Balance: {} octas ({} APT)",
        balance,
        balance as f64 / 100_000_000.0
    );

    if balance == 0 {
        println!(
            "\nAccount has zero balance. Fund it from another wallet, then re-run with \
             APTOS_KEYLESS_JWT set."
        );
        return Ok(());
    }

    let recipient = aptos_sdk::types::AccountAddress::from_hex("0x1")?;
    let transfer_amount = 1_000u64; // 0.000001 APT — minimal smoke-test transfer
    let payload = EntryFunction::apt_transfer(recipient, transfer_amount)?;

    println!("\n--- Submitting transfer ---");
    let committed = aptos
        .sign_submit_and_wait(&account, payload.into(), None)
        .await?;
    let success = committed
        .data
        .get("success")
        .and_then(serde_json::Value::as_bool);
    println!("Success: {success:?}");

    Ok(())
}

fn ephemeral_storage_path() -> PathBuf {
    std::env::var(EPK_FILE_ENV).map_or_else(
        |_| std::env::temp_dir().join("aptos-sdk-keyless-ephemeral.json"),
        PathBuf::from,
    )
}

fn load_or_create_ephemeral(path: &Path) -> anyhow::Result<EphemeralKeyPair> {
    if path.exists() {
        return EphemeralKeyPair::load_from_file(path)
            .map_err(|e| anyhow::anyhow!("failed to restore ephemeral key: {e}"));
    }

    let ephemeral = EphemeralKeyPair::generate(3600);
    ephemeral
        .save_to_file(path)
        .map_err(|e| anyhow::anyhow!("failed to persist ephemeral key: {e}"))?;
    Ok(ephemeral)
}

fn print_setup_instructions(nonce: &str, storage_path: &Path) {
    println!("\n--- Next: complete OAuth ---");
    println!("No JWT found. After signing in with your IdP, re-run with APTOS_KEYLESS_JWT.");
    println!();
    println!("Quick checklist:");
    println!("  1. Register an OAuth client with your IdP (Google, Apple, etc.).");
    println!("  2. Start the login redirect with nonce = {nonce}");
    println!("     (see https://aptos.dev/build/guides/aptos-keyless/integration-guide)");
    println!("  3. Extract the id_token from the callback URL fragment.");
    println!(
        "  4. Re-run without deleting {} so the same ephemeral key is restored:",
        storage_path.display()
    );
    println!("       APTOS_KEYLESS_JWT=\"<id_token>\" \\");
    println!("         cargo run --example keyless_account --features \"keyless,ed25519,faucet\"");
}
