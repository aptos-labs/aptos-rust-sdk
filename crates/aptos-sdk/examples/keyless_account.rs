//! Example: Keyless (OIDC) account creation and transaction signing
//!
//! This example demonstrates how to:
//! 1. Generate an ephemeral key pair (embed its nonce in your IdP OAuth URL)
//! 2. Derive a [`KeylessAccount`] from an OIDC JWT using Aptos pepper / prover services
//! 3. Query account state and sign a transfer transaction
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
//! ```text
//! # After your app receives an ID token from the IdP:
//! APTOS_KEYLESS_JWT="eyJ..." \
//!   cargo run --example keyless_account --features "keyless,ed25519,faucet"
//! ```
//!
//! Without `APTOS_KEYLESS_JWT`, the example prints setup instructions and
//! demonstrates ephemeral key generation only.

use aptos_sdk::{
    Aptos, AptosConfig,
    account::{Account, EphemeralKeyPair, HttpPepperService, HttpProverService, KeylessAccount},
    config::Network,
    transaction::EntryFunction,
};
use url::Url;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Keyless Account Example ===\n");

    // Step 1: Generate an ephemeral key *before* redirecting the user to your IdP.
    // The nonce must appear in the OAuth `nonce` parameter so it is embedded in the JWT.
    let ephemeral = EphemeralKeyPair::generate(3600);
    println!("--- Ephemeral key (use in IdP login URL) ---");
    println!("Nonce:   {}", ephemeral.nonce());
    println!("Expires: in 3600 seconds");

    let jwt = match std::env::var("APTOS_KEYLESS_JWT") {
        Ok(token) if !token.is_empty() => token,
        _ => {
            print_setup_instructions(ephemeral.nonce());
            return Ok(());
        }
    };

    // Step 2: Connect to devnet and wire up Aptos-hosted pepper / prover services.
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

    // Step 3: Derive the keyless account from the JWT.
    println!("\n--- Deriving KeylessAccount ---");
    let account =
        KeylessAccount::from_jwt(&jwt, ephemeral, &pepper_service, &prover_service).await?;

    println!("Address:  {}", account.address());
    println!("Issuer:   {}", account.issuer());
    println!("Audience: {}", account.audience());
    println!("User ID:  {}", account.user_id());
    println!("Valid:    {}", account.is_valid());

    // Step 4: Query on-chain state.
    let balance = aptos.get_balance(account.address()).await?;
    println!("\n--- Account state ---");
    println!(
        "Balance: {} octas ({} APT)",
        balance,
        balance as f64 / 100_000_000.0
    );

    if balance == 0 {
        println!(
            "\nAccount has zero balance. Fund it from another wallet or use the devnet faucet \
             if your address is eligible, then re-run this example."
        );
        return Ok(());
    }

    // Step 5: Sign, submit, and wait for a small transfer.
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

fn print_setup_instructions(nonce: &str) {
    println!("\n--- Setup required ---");
    println!("No JWT found. Set APTOS_KEYLESS_JWT to an OIDC ID token to continue.");
    println!();
    println!("Quick checklist:");
    println!("  1. Register an OAuth client with your IdP (Google, Apple, etc.).");
    println!("  2. Start the login redirect with nonce = {nonce}");
    println!("     (see https://aptos.dev/build/guides/aptos-keyless/integration-guide)");
    println!("  3. Extract the id_token from the callback URL fragment.");
    println!("  4. Re-run:");
    println!("       APTOS_KEYLESS_JWT=\"<id_token>\" \\");
    println!("         cargo run --example keyless_account --features \"keyless,ed25519,faucet\"");
}
