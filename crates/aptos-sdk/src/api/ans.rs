//! Aptos Names Service (ANS) client -- **scaffold / not yet implemented**.
//!
//! This module exists so `AGENTS.md` can stop referencing a missing file,
//! and so future work can land in one obvious place. **Nothing here issues
//! a network call yet.**
//!
//! # Scope when implemented
//!
//! At minimum we want:
//!
//! - `lookup(name)` -- resolve a `.apt` / sub-domain string into an
//!   [`AccountAddress`].
//! - `reverse_lookup(address)` -- find the primary name registered to an
//!   address, if any.
//!
//! At extension time:
//!
//! - Register / renew flows (entry-function builders against the on-chain
//!   ANS contract -- requires pinned contract addresses per network and a
//!   plan for how the SDK should pick them).
//! - Sub-domain queries.
//!
//! # Why not implemented yet
//!
//! The TS SDK's ANS module hard-codes contract addresses per network and
//! relies on the indexer for some lookups. Mirroring that 1:1 without
//! making network-specific decisions visible to callers needs design
//! work that's tracked separately from the May-2026 audit follow-ups. See
//! `AUDIT_SUMMARY_2026-05.md` and the audit follow-up commits for context.

use crate::api::FullnodeClient;
use crate::error::{AptosError, AptosResult};
use crate::types::AccountAddress;

/// Skeleton client for Aptos Names Service.
///
/// All methods currently return
/// [`AptosError::Internal`]
/// so callers fail fast rather than silently accepting placeholder values.
#[derive(Debug, Clone)]
pub struct AnsClient {
    #[allow(dead_code)] // wired up when lookups land
    fullnode: FullnodeClient,
}

impl AnsClient {
    /// Constructs a new ANS client bound to a given fullnode.
    #[must_use]
    pub fn new(fullnode: FullnodeClient) -> Self {
        Self { fullnode }
    }

    /// Resolves an ANS name (e.g. `"alice.apt"`) to its registered
    /// [`AccountAddress`].
    ///
    /// # Errors
    ///
    /// Currently always returns [`AptosError::Internal`]; the lookup is
    /// scheduled but not yet wired up. Track progress against the audit
    /// follow-up issue cited in this module's docs.
    pub async fn lookup(&self, _name: &str) -> AptosResult<AccountAddress> {
        Err(AptosError::Internal(
            "ANS lookup is not yet implemented in the Rust SDK (tracked as an audit \
             follow-up); use the on-chain `0x...::router::get_address` view \
             function directly for now"
                .to_string(),
        ))
    }

    /// Finds the primary ANS name registered to a given address, if any.
    ///
    /// # Errors
    ///
    /// Currently always returns [`AptosError::Internal`]; the reverse
    /// lookup is scheduled but not yet wired up.
    pub async fn reverse_lookup(&self, _address: AccountAddress) -> AptosResult<Option<String>> {
        Err(AptosError::Internal(
            "ANS reverse lookup is not yet implemented in the Rust SDK \
             (tracked as an audit follow-up)"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AptosConfig;

    #[tokio::test]
    async fn lookup_is_unsupported() {
        let fullnode = FullnodeClient::new(AptosConfig::testnet()).unwrap();
        let ans = AnsClient::new(fullnode);
        let err = ans.lookup("alice.apt").await.unwrap_err();
        assert!(matches!(err, AptosError::Internal(_)));
    }

    #[tokio::test]
    async fn reverse_lookup_is_unsupported() {
        let fullnode = FullnodeClient::new(AptosConfig::testnet()).unwrap();
        let ans = AnsClient::new(fullnode);
        let err = ans.reverse_lookup(AccountAddress::ONE).await.unwrap_err();
        assert!(matches!(err, AptosError::Internal(_)));
    }
}
