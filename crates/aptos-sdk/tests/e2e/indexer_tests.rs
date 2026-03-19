use super::*;
use aptos_sdk::account::Ed25519Account;

/// Helper: Get the current ledger version for indexer sync.
async fn current_version(aptos: &Aptos) -> u64 {
    aptos
        .ledger_info()
        .await
        .expect("failed to get ledger info")
        .version()
        .expect("failed to parse version")
}

#[tokio::test]
#[ignore]
async fn e2e_indexer_get_fungible_asset_balances() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let account = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    let version = current_version(&aptos).await;
    wait_for_indexer(&aptos, version).await;

    let indexer = aptos.indexer().expect("indexer not configured");
    let balances = indexer
        .get_fungible_asset_balances(account.address())
        .await
        .expect("failed to get fungible asset balances");

    println!("Fungible asset balances: {}", balances.len());
    // Should have at least APT
    assert!(
        !balances.is_empty(),
        "funded account should have fungible asset balances"
    );
    for b in &balances {
        println!("  asset: {}, amount: {}", b.asset_type, b.amount);
    }
}

#[tokio::test]
#[ignore]
async fn e2e_indexer_get_account_transactions() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();
    aptos
        .transfer_apt(&sender, recipient.address(), 1_000_000)
        .await
        .expect("failed to transfer");

    let version = current_version(&aptos).await;
    wait_for_indexer(&aptos, version).await;

    let indexer = aptos.indexer().expect("indexer not configured");
    let txns = indexer
        .get_account_transactions(sender.address(), Some(10))
        .await
        .expect("failed to get transactions");

    println!("Account transactions: {}", txns.len());
    assert!(!txns.is_empty(), "should have at least one transaction");
}

#[tokio::test]
#[ignore]
async fn e2e_indexer_get_coin_balances() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let account = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    let version = current_version(&aptos).await;
    wait_for_indexer(&aptos, version).await;

    let indexer = aptos.indexer().expect("indexer not configured");
    let balances = indexer
        .get_coin_balances(account.address())
        .await
        .expect("failed to get coin balances");

    println!("Coin balances: {}", balances.len());
    // Funded account should have APT in the legacy coin module
    for b in &balances {
        println!("  coin: {}, amount: {}", b.coin_type, b.amount);
    }
}

#[tokio::test]
#[ignore]
async fn e2e_indexer_get_coin_activities() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");

    let recipient = Ed25519Account::generate();
    aptos
        .transfer_apt(&sender, recipient.address(), 1_000_000)
        .await
        .expect("failed to transfer");

    let version = current_version(&aptos).await;
    wait_for_indexer(&aptos, version).await;

    let indexer = aptos.indexer().expect("indexer not configured");
    let activities = indexer
        .get_coin_activities(sender.address(), Some(10))
        .await
        .expect("failed to get coin activities");

    println!("Coin activities: {}", activities.len());
    for a in &activities {
        println!(
            "  type: {}, amount: {:?}, coin: {}",
            a.activity_type, a.amount, a.coin_type
        );
    }
}

#[tokio::test]
#[ignore]
async fn e2e_indexer_get_events_by_type() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    // Ensure there's at least one transaction to generate events
    let sender = aptos
        .create_funded_account(200_000_000)
        .await
        .expect("failed to create sender");
    let recipient = Ed25519Account::generate();
    aptos
        .transfer_apt(&sender, recipient.address(), 1_000)
        .await
        .expect("failed to transfer");

    let version = current_version(&aptos).await;
    wait_for_indexer(&aptos, version).await;

    let indexer = aptos.indexer().expect("indexer not configured");

    // Query for coin deposit events
    let events = indexer
        .get_events_by_type("0x1::coin::DepositEvent", Some(10))
        .await;

    match events {
        Ok(e) => {
            println!("DepositEvent events: {}", e.len());
            for ev in &e {
                println!(
                    "  seq: {}, type: {}, version: {:?}",
                    ev.sequence_number, ev.event_type, ev.transaction_version
                );
            }
        }
        Err(e) => {
            // DepositEvent may not exist on newer chains using v2 events
            println!("Event type query result: {}", e);
        }
    }
}

#[tokio::test]
#[ignore]
async fn e2e_indexer_get_processor_status() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let indexer = aptos.indexer().expect("indexer not configured");
    let statuses = indexer
        .get_processor_status()
        .await
        .expect("failed to get processor status");

    assert!(
        !statuses.is_empty(),
        "should have at least one processor status"
    );
    for s in &statuses {
        println!(
            "Processor: {}, version: {}, updated: {:?}",
            s.processor, s.last_success_version, s.last_updated
        );
    }
}

#[tokio::test]
#[ignore]
async fn e2e_indexer_check_indexer_lag() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let ledger_version = current_version(&aptos).await;

    // Wait for indexer to catch up
    wait_for_indexer(&aptos, ledger_version.saturating_sub(100)).await;

    let indexer = aptos.indexer().expect("indexer not configured");

    // Allow generous lag for localnet
    let healthy = indexer
        .check_indexer_lag(ledger_version, 1000)
        .await
        .expect("failed to check lag");

    println!(
        "Indexer lag check (ref={}, max_lag=1000): healthy={}",
        ledger_version, healthy
    );
    assert!(healthy, "indexer should be within 1000 versions of ledger");
}

#[tokio::test]
#[ignore]
async fn e2e_indexer_get_account_tokens_paginated() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let account = aptos
        .create_funded_account(100_000_000)
        .await
        .expect("failed to create account");

    let version = current_version(&aptos).await;
    wait_for_indexer(&aptos, version).await;

    let indexer = aptos.indexer().expect("indexer not configured");
    let page = indexer
        .get_account_tokens_paginated(account.address(), None)
        .await
        .expect("failed to get tokens paginated");

    // New account likely has no tokens, but the query should succeed
    println!(
        "Tokens: {}, has_more: {}, total: {:?}",
        page.items.len(),
        page.has_more,
        page.total_count
    );
    assert!(!page.has_more, "new account shouldn't have more tokens");
}

#[tokio::test]
#[ignore]
async fn e2e_indexer_raw_graphql_query() {
    let config = get_test_config();
    let aptos = Aptos::new(config).expect("failed to create client");

    let indexer = aptos.indexer().expect("indexer not configured");

    // Raw query: get the current processor status (a simple query that always works)
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct Status {
        processor: String,
        last_success_version: u64,
    }

    #[derive(serde::Deserialize)]
    struct Response {
        processor_status: Vec<Status>,
    }

    let result: Response = indexer
        .query(
            r"query { processor_status { processor last_success_version } }",
            None,
        )
        .await
        .expect("failed to execute raw query");

    assert!(
        !result.processor_status.is_empty(),
        "raw query should return data"
    );
    println!(
        "Raw query returned {} processor statuses",
        result.processor_status.len()
    );
}
