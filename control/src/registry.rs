//! The agent → policy registry. Implements the Option-3 model: an agent's standing
//! authorization policy is a property of its identity, registered once and reused for
//! every launch.

use models::policy::Policy;
use parking_lot::RwLock;
use std::collections::HashMap;

/// Maps an agent id to its standing [`Policy`]. In-memory and seeded at startup from
/// config; a future backing store implements the same surface.
#[derive(Default)]
pub struct Registry {
    agents: RwLock<HashMap<String, Policy>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or replace an agent's standing policy.
    pub fn register(&self, agent: impl Into<String>, policy: Policy) {
        self.agents.write().insert(agent.into(), policy);
    }

    /// The agent's policy, or `None` if the agent is unknown (a fail-closed signal: an
    /// authenticated agent with no policy is denied).
    pub fn policy(&self, agent: &str) -> Option<Policy> {
        self.agents.read().get(agent).cloned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn register_then_fetch() {
        let reg = Registry::new();
        assert!(reg.policy("a").is_none());
        reg.register("a", Policy { rules: vec![] });
        assert!(reg.policy("a").is_some());
    }
}
