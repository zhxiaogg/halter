//! halter server configuration. This is application/storage config — hand-written and
//! deliberately *not* a fluorite type — so it can evolve independently of the wire
//! protocol. It seeds the gateway's service allowlist (with each service's outbound auth
//! stance) and the credential vault at startup. There are no agents: tokens are minted
//! per-policy via the admin API.

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
    /// consumers.
    #[serde(default)]
    pub credentials: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    /// Logical instance name; becomes `Action.target` and what policy rules scope to.
    pub name: String,
    /// Host pattern matched against the request `Host`: exact, `*.suffix`, or `*`.
    pub host: String,
    /// Upstream base URL, e.g. `https://api.github.com`.
    pub upstream_base: String,
    /// Normalization flavor: "github" or "generic" (default).
    #[serde(default)]
    pub flavor: Option<String>,
    /// Consumer-facing address the agent points its tool at to reach this service through
    /// halter (surfaced in the provision doc). Optional.
    #[serde(default)]
    pub consumer_address: Option<String>,
    /// Wire protocol for extraction: "rest" (default), "aws-query", or "aws-json".
    #[serde(default)]
    pub protocol: Option<String>,
    /// Optional path template capturing named segments into fields, e.g. `/{bucket}/{key+}`.
    #[serde(default)]
    pub path_template: Option<String>,
    /// What halter does with upstream auth on allow: `"passthrough"` (default) forwards
    /// the consumer's own credential; `{ "bearer": "<cred-id>" }` injects it as a Bearer
    /// token; `{ "header": { "name": "X-API-Key", "credential": "<cred-id>" } }` injects
    /// it as a custom header.
    #[serde(default)]
    pub outbound: OutboundConfig,
}

/// The configured outbound auth stance for a service (see [`ServiceConfig::outbound`]).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundConfig {
    /// Forward the consumer's own credential unchanged (filter-only).
    #[default]
    Passthrough,
    /// Inject the named vault credential as `Authorization: Bearer <secret>`.
    Bearer(String),
    /// Inject the named vault credential as a custom header.
    Header { name: String, credential: String },
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
                { "name": "github", "host": "api.github.com", "upstream_base": "https://api.github.com",
                  "flavor": "github", "outbound": { "bearer": "github-app" } },
                { "name": "openai", "host": "api.openai.com", "upstream_base": "https://api.openai.com",
                  "flavor": "generic", "outbound": "passthrough" },
                { "name": "keyed", "host": "api.keyed.com", "upstream_base": "https://api.keyed.com",
                  "outbound": { "header": { "name": "X-API-Key", "credential": "keyed-key" } } }
            ],
            "credentials": { "github-app": "secret" }
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.proxy_addr, "127.0.0.1:9090");
        assert_eq!(cfg.services.len(), 3);
        assert!(matches!(
            cfg.services[0].outbound,
            OutboundConfig::Bearer(ref id) if id == "github-app"
        ));
        assert!(matches!(
            cfg.services[1].outbound,
            OutboundConfig::Passthrough
        ));
        assert!(matches!(
            cfg.services[2].outbound,
            OutboundConfig::Header { ref name, ref credential }
                if name == "X-API-Key" && credential == "keyed-key"
        ));
        assert_eq!(
            cfg.credentials.get("github-app").map(String::as_str),
            Some("secret")
        );
    }

    #[test]
    fn outbound_defaults_to_passthrough() {
        let json = r#"{
            "proxy_addr": "127.0.0.1:9090",
            "admin_addr": "127.0.0.1:9091",
            "services": [
                { "name": "svc", "host": "*", "upstream_base": "https://up.example" }
            ]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert!(matches!(
            cfg.services[0].outbound,
            OutboundConfig::Passthrough
        ));
    }
}
