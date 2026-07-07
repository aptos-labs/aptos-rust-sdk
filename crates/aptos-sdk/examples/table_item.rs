//! Example: Reading a Move table item
//!
//! Table state is not addressable as a normal account resource, so the fullnode
//! exposes a dedicated `POST /tables/{handle}/item` endpoint. This example:
//! 1. Reads a resource that contains a `Table` (the on-chain governance voting
//!    forum) to obtain the table's `handle`
//! 2. Reads an item from that table with `Aptos::get_table_item`
//!
//! The pattern is always the same: get a table `handle` from some resource
//! field, then call `get_table_item(handle, key_type, value_type, key)`.
//!
//! Run with: `cargo run --example table_item --features ed25519`

use aptos_sdk::{Aptos, AptosConfig, types::AccountAddress};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Read real data from mainnet.
    let aptos = Aptos::new(AptosConfig::mainnet())?;
    println!("Connected to mainnet");

    // The governance voting forum stores proposals in a `Table<u64, Proposal>`.
    let forum_type = "0x1::voting::VotingForum<0x1::governance_proposal::GovernanceProposal>";
    let forum = aptos
        .fullnode()
        .get_account_resource(AccountAddress::ONE, forum_type)
        .await?;

    // The table handle lives in the `proposals` field.
    let handle = forum.data.data["proposals"]["handle"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("could not find proposals table handle"))?
        .to_string();
    println!("Proposals table handle: {handle}");

    // Read proposal #0 from the table. Keys/values are given by their Move type;
    // a `u64` key is passed as a JSON string.
    let proposal = aptos
        .get_table_item(
            &handle,
            "u64",
            "0x1::voting::Proposal<0x1::governance_proposal::GovernanceProposal>",
            serde_json::json!("0"),
        )
        .await?;

    println!("Proposal #0:");
    println!(
        "  proposer: {}",
        proposal
            .get("proposer")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>")
    );
    println!(
        "  creation_time_secs: {}",
        proposal
            .get("creation_time_secs")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>")
    );

    Ok(())
}
