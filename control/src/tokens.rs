//! Short-lived launch tokens. At agent launch the orchestrator mints a token bound to
//! an agent id with a TTL; the agent presents it to the proxy, which resolves it back
//! to the agent. The token is an opaque capability honored only by halter — it is
//! useless against the real upstream — and is revocable at any time.
//!
//! Time is passed in explicitly (`now_ms`) so minting, expiry, and resolution are all
//! deterministically testable; the binary supplies the wall clock via [`crate::now_ms`].

use models::control::MintResponse;
use parking_lot::RwLock;
use std::collections::HashMap;
use uuid::Uuid;

struct Entry {
    agent: String,
    expires_at_ms: u64,
}

/// The in-memory token table. Opaque tokens map to `(agent, expiry)`.
#[derive(Default)]
pub struct Tokens {
    entries: RwLock<HashMap<String, Entry>>,
}

impl Tokens {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a fresh token for `agent` valid for `ttl_seconds` from `now_ms`.
    pub fn mint(&self, agent: impl Into<String>, ttl_seconds: u64, now_ms: u64) -> MintResponse {
        let agent = agent.into();
        // Two v4 UUIDs concatenated: ~244 bits of entropy, unguessable.
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let expires_at_ms = now_ms.saturating_add(ttl_seconds.saturating_mul(1000));
        self.entries.write().insert(
            token.clone(),
            Entry {
                agent: agent.clone(),
                expires_at_ms,
            },
        );
        MintResponse {
            token,
            agent,
            expires_at_ms,
        }
    }

    /// Resolve a token to its agent id, or `None` if unknown or expired at `now_ms`.
    pub fn resolve(&self, token: &str, now_ms: u64) -> Option<String> {
        let entries = self.entries.read();
        let entry = entries.get(token)?;
        if entry.expires_at_ms <= now_ms {
            return None;
        }
        Some(entry.agent.clone())
    }

    /// Revoke a token immediately. Returns whether a token was removed.
    pub fn revoke(&self, token: &str) -> bool {
        self.entries.write().remove(token).is_some()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn mint_then_resolve_within_ttl() {
        let tokens = Tokens::new();
        let minted = tokens.mint("agent-1", 60, 1_000);
        assert_eq!(minted.agent, "agent-1");
        assert_eq!(
            tokens.resolve(&minted.token, 1_000).as_deref(),
            Some("agent-1")
        );
        // Just before expiry.
        assert_eq!(
            tokens.resolve(&minted.token, 60_999).as_deref(),
            Some("agent-1")
        );
    }

    #[test]
    fn token_expires() {
        let tokens = Tokens::new();
        let minted = tokens.mint("agent-1", 60, 1_000);
        // At/after expiry (1000 + 60_000).
        assert!(tokens.resolve(&minted.token, 61_000).is_none());
    }

    #[test]
    fn unknown_token_resolves_none() {
        let tokens = Tokens::new();
        assert!(tokens.resolve("bogus", 1).is_none());
    }

    #[test]
    fn revoke_invalidates() {
        let tokens = Tokens::new();
        let minted = tokens.mint("agent-1", 60, 0);
        assert!(tokens.revoke(&minted.token));
        assert!(tokens.resolve(&minted.token, 1).is_none());
        assert!(!tokens.revoke(&minted.token));
    }
}
