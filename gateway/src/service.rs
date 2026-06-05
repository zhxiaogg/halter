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

impl Flavor {
    /// Parse a flavor name; unknown/absent values default to [`Flavor::Generic`].
    pub fn parse(name: Option<&str>) -> Self {
        match name {
            Some(n) if n.eq_ignore_ascii_case("github") => Flavor::Github,
            _ => Flavor::Generic,
        }
    }
}

/// One configured upstream service.
#[derive(Clone, Debug)]
pub struct Service {
    /// Logical name; becomes `Action.target` and what policy rules scope to.
    pub name: String,
    /// Host pattern matched against the request `Host` header: an exact host, a
    /// `*.suffix` wildcard, or `*` (catch-all).
    pub host: String,
    /// Upstream base URL without a trailing slash, e.g. `https://api.github.com`.
    pub upstream_base: String,
    /// How requests to this service are normalized.
    pub flavor: Flavor,
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
