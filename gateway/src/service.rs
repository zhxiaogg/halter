//! Service routing. halter forwards to any number of configured upstream HTTPS services,
//! chosen by the request's `Host` header. The configured set is an allowlist: a request
//! whose host matches no service is denied (fail closed). Each service names how its
//! requests are normalized into an `Action` (its [`Flavor`]).

/// How a service's requests are normalized into an `Action`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavor {
    /// GitHub-aware resource parsing (repo/pull_request/issue kinds).
    Github,
    /// Path-based generic parsing — works for any HTTP/JSON or SSE service.
    Generic,
}

/// The wire protocol that decides *where the operation lives* in a request — the only
/// real branch in extraction. `Rest` (the default) reads the HTTP method + path; the AWS
/// RPC protocols read the operation from the body/header (the path is constant).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Protocol {
    /// Operation = HTTP method + URL path (RESTful: GitHub, k8s, S3, most APIs).
    #[default]
    Rest,
    /// AWS query protocol: `Action=<Op>` in a form-encoded body (EC2, IAM, …).
    AwsQuery,
    /// AWS JSON protocol: `X-Amz-Target: <svc>.<Op>` header (DynamoDB, …).
    AwsJson,
}

impl Protocol {
    /// Parse a protocol name; unknown/absent values default to [`Protocol::Rest`].
    pub fn parse(name: Option<&str>) -> Self {
        match name {
            Some(n) if n.eq_ignore_ascii_case("aws-query") => Protocol::AwsQuery,
            Some(n) if n.eq_ignore_ascii_case("aws-json") => Protocol::AwsJson,
            _ => Protocol::Rest,
        }
    }
}

/// Per-service normalization config — how a raw request becomes an `Action`. Grouped so
/// extraction knobs can grow without touching every `Service` site. Defaults to plain
/// RESTful method+path extraction (Tier 0).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extract {
    /// The wire protocol (operation location).
    pub protocol: Protocol,
    /// Optional path template capturing named segments into `fields`, e.g.
    /// `/{bucket}/{key}`. `None` = no capture (Tier 0 path glob).
    pub path_template: Option<String>,
}

impl Flavor {
    /// Parse a flavor name; unknown/absent values default to [`Flavor::Generic`].
    pub fn parse(name: Option<&str>) -> Self {
        match name {
            Some(n) if n.eq_ignore_ascii_case("github") => Flavor::Github,
            _ => Flavor::Generic,
        }
    }

    /// The canonical lowercase flavor name (the inverse of [`Flavor::parse`]).
    pub fn name(self) -> &'static str {
        match self {
            Flavor::Github => "github",
            Flavor::Generic => "generic",
        }
    }
}

/// What halter does with upstream auth when a request is allowed — a closed mechanism
/// library, selected per service instance. This is the **hybrid** stance: filter-only by
/// default (`Passthrough`), credential-hiding via one of the inject mechanisms. The
/// credential is a property of the service instance, never named in policy. (SigV4 — a
/// request *transform* rather than a header set — is added as its own arm later.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outbound {
    /// Forward the consumer's own credential unchanged (filter-only).
    Passthrough,
    /// Inject the vault credential as `Authorization: Bearer <secret>`.
    Bearer { credential: String },
    /// Inject the vault credential as a custom header `<name>: <secret>` (e.g.
    /// `X-API-Key`).
    Header { name: String, credential: String },
}

impl Outbound {
    /// The vault credential id this stance injects, if any (`None` for passthrough).
    pub fn credential_id(&self) -> Option<&str> {
        match self {
            Outbound::Passthrough => None,
            Outbound::Bearer { credential } | Outbound::Header { credential, .. } => {
                Some(credential)
            }
        }
    }
}

/// One configured upstream service instance.
#[derive(Clone, Debug)]
pub struct Service {
    /// Logical instance name; becomes `Action.target` and what policy rules scope to.
    pub name: String,
    /// Host pattern matched against the request `Host` header: an exact host, a
    /// `*.suffix` wildcard, or `*` (catch-all).
    pub host: String,
    /// Upstream base URL without a trailing slash, e.g. `https://api.github.com`.
    pub upstream_base: String,
    /// How requests to this service are normalized.
    pub flavor: Flavor,
    /// What halter does with upstream auth on allow.
    pub outbound: Outbound,
    /// Consumer-facing address the agent points its tool at to reach this service
    /// through halter (the provision doc surfaces this). Empty if not configured.
    pub address: String,
    /// How requests are normalized into an `Action` (protocol + field extraction).
    pub extract: Extract,
}

/// Routes an inbound request to a service by its `Host`. First match wins, so put more
/// specific patterns before catch-alls.
pub struct ServiceRouter {
    services: Vec<Service>,
}

impl ServiceRouter {
    pub fn new(services: Vec<Service>) -> Self {
        Self { services }
    }

    /// The service whose host pattern matches `host`, or `None` (→ deny).
    pub fn route(&self, host: &str) -> Option<&Service> {
        let host = normalize_host(host);
        self.services.iter().find(|s| host_matches(&s.host, &host))
    }

    /// All configured services (used to project a provision doc).
    pub fn services(&self) -> &[Service] {
        &self.services
    }
}

/// Lowercase and strip a trailing `:port` for matching.
fn normalize_host(host: &str) -> String {
    let host = host.trim().to_ascii_lowercase();
    match host.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            h.to_string()
        }
        _ => host,
    }
}

/// Match a (lowercased, port-stripped) host against a pattern: `*` matches anything,
/// `*.suffix` matches `suffix` and any subdomain of it, otherwise an exact match.
fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    pattern == host
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn svc(name: &str, host: &str) -> Service {
        Service {
            name: name.into(),
            host: host.into(),
            upstream_base: format!("https://{name}.example"),
            flavor: Flavor::Generic,
            outbound: Outbound::Passthrough,
            address: String::new(),
            extract: Extract::default(),
        }
    }

    #[test]
    fn routes_by_exact_host_and_strips_port() {
        let r = ServiceRouter::new(vec![svc("github", "api.github.com")]);
        assert_eq!(
            r.route("api.github.com").map(|s| s.name.as_str()),
            Some("github")
        );
        assert_eq!(
            r.route("api.github.com:443").map(|s| s.name.as_str()),
            Some("github")
        );
        assert!(r.route("api.openai.com").is_none());
    }

    #[test]
    fn wildcard_suffix_and_catch_all() {
        let r = ServiceRouter::new(vec![svc("oai", "*.openai.com"), svc("any", "*")]);
        assert_eq!(
            r.route("api.openai.com").map(|s| s.name.as_str()),
            Some("oai")
        );
        assert_eq!(r.route("openai.com").map(|s| s.name.as_str()), Some("oai"));
        // Falls through to catch-all.
        assert_eq!(r.route("example.org").map(|s| s.name.as_str()), Some("any"));
    }

    #[test]
    fn first_match_wins() {
        let r = ServiceRouter::new(vec![svc("specific", "api.github.com"), svc("catch", "*")]);
        assert_eq!(
            r.route("api.github.com").map(|s| s.name.as_str()),
            Some("specific")
        );
    }

    #[test]
    fn flavor_parse_defaults_generic() {
        assert_eq!(Flavor::parse(Some("github")), Flavor::Github);
        assert_eq!(Flavor::parse(Some("GitHub")), Flavor::Github);
        assert_eq!(Flavor::parse(Some("rest")), Flavor::Generic);
        assert_eq!(Flavor::parse(None), Flavor::Generic);
    }
}
