//! halter server configuration. This is application/storage config — hand-written and
//! deliberately *not* a fluorite type — so it can evolve independently of the wire
//! protocol. It seeds the control plane (agents → policies, credential vault) and the
//! gateway route at startup.

use models::policy::Policy;
use serde::Deserialize;
use std::collections::HashMap;

/// Top-level server config, loaded from JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Address the agent-facing reverse proxy listens on, e.g. `127.0.0.1:9090`.
    pub proxy_addr: String,
    /// Address the operator/orchestrator admin API listens on, e.g. `127.0.0.1:9091`.
    pub admin_addr: String,
    /// The upstream HTTPS services halter will proxy to (the allowlist). Routed by Host.
    pub services: Vec<ServiceConfig>,
    /// Logical credential id → real secret. Provisioned out of band; never exposed to
    /// agents.
    #[serde(default)]
    pub credentials: HashMap<String, String>,
    /// Agents and their standing policies (Option 3).
    #[serde(default)]
    pub agents: Vec<AgentConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    /// Logical service name; becomes `Action.target` and what policy rules scope to.
    pub name: String,
    /// Host pattern matched against the request `Host`: exact, `*.suffix`, or `*`.
    pub host: String,
    /// Upstream base URL, e.g. `https://api.github.com`.
    pub upstream_base: String,
    /// Normalization flavor: "github" or "generic" (default).
    #[serde(default)]
    pub flavor: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    pub id: String,
    pub policy: Policy,
}

impl Config {
    /// Load and parse a config file.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read config {}: {e}", path.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("parse config {}: {e}", path.display()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_config() {
        let json = r#"{
            "proxy_addr": "127.0.0.1:9090",
            "admin_addr": "127.0.0.1:9091",
            "services": [
                { "name": "github", "host": "api.github.com", "upstream_base": "https://api.github.com", "flavor": "github" }
            ],
            "credentials": { "github-app": "secret" },
            "agents": [
                { "id": "agent-1", "policy": { "rules": [
                    { "effect": "Allow",
                      "matches": { "targets": [], "verbs": ["Read"], "resources": [], "conditions": [] },
                      "grantCredentials": ["github-app"] }
                ] } }
            ]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.proxy_addr, "127.0.0.1:9090");
        assert_eq!(cfg.agents.len(), 1);
        assert_eq!(cfg.agents[0].policy.rules.len(), 1);
        assert_eq!(
            cfg.credentials.get("github-app").map(String::as_str),
            Some("secret")
        );
    }
}
