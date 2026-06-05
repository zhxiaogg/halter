//! The gateway core: the transport-agnostic decision + enforcement path.
//!
//! [`Gateway::handle`] takes a normalized [`ProxyRequest`], authenticates the halter
//! token, resolves the agent's policy, normalizes the request into an `Action`, calls
//! the pure [`policy::decide`], records an audit event, and returns an [`Outcome`] —
//! either a [`ForwardPlan`] (with the real credential injected and the agent's token
//! stripped) or a [`Rejection`]. It performs no network I/O itself; the server module
//! executes the forward. Keeping this layer free of HTTP plumbing makes the whole
//! decision path deterministically testable.

use crate::normalize;
use crate::service::{Service, ServiceRouter};
use control::{ControlPlane, now_ms};
use models::action::Action;
use models::audit::{AuditEvent, Decision};
use models::verdict::{DenyReason, Obligation, Verdict};
use std::sync::Arc;

/// A normalized inbound request, independent of any HTTP library.
pub struct ProxyRequest {
    pub method: http::Method,
    /// Request path including the leading `/`, e.g. `/repos/o/r/pulls`.
    pub path: String,
    /// Raw query string without the `?`, possibly empty.
    pub query: String,
    pub headers: http::HeaderMap,
    pub body: bytes::Bytes,
}

/// What the data plane should do with a request.
pub enum Outcome {
    /// Forward upstream after applying the plan (credential injected, token stripped).
    Forward(ForwardPlan),
    /// Reject without contacting the upstream.
    Reject(Rejection),
}

/// A concrete upstream request to execute.
pub struct ForwardPlan {
    pub url: String,
    pub method: http::Method,
    pub headers: http::HeaderMap,
    pub body: bytes::Bytes,
}

/// A denied request, ready to render as an HTTP error.
pub struct Rejection {
    pub status: http::StatusCode,
    pub reason: DenyReason,
    pub message: String,
}

/// A source of wall-clock time, injectable for tests.
type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The data-plane decision engine. Holds the control plane and the service routing
/// table (any number of configured upstream HTTPS services).
pub struct Gateway {
    control: Arc<ControlPlane>,
    router: ServiceRouter,
    clock: Clock,
}

impl Gateway {
    /// Build a gateway over `control` routing to `router`'s services, using the wall
    /// clock.
    pub fn new(control: Arc<ControlPlane>, router: ServiceRouter) -> Self {
        Self {
            control,
            router,
            clock: Arc::new(now_ms),
        }
    }

    /// Build a gateway with an injected clock (tests).
    pub fn with_clock(control: Arc<ControlPlane>, router: ServiceRouter, clock: Clock) -> Self {
        Self {
            control,
            router,
            clock,
        }
    }

    /// Mint a launch token for `agent`, or `None` if the agent has no registered policy.
    /// This is the control-plane verb the orchestrator calls at launch.
    pub fn mint(&self, agent: &str, ttl_seconds: u64) -> Option<models::control::MintResponse> {
        self.control.registry.policy(agent)?;
        Some(self.control.tokens.mint(agent, ttl_seconds, (self.clock)()))
    }

    /// Authenticate, authorize, and (on allow) plan the upstream forward.
    pub fn handle(&self, req: ProxyRequest) -> Outcome {
        let now = (self.clock)();

        let Some(token) = extract_token(&req.headers) else {
            return reject(
                http::StatusCode::UNAUTHORIZED,
                DenyReason::Unauthenticated,
                "missing halter token",
            );
        };
        let Some(agent) = self.control.tokens.resolve(&token, now) else {
            return reject(
                http::StatusCode::UNAUTHORIZED,
                DenyReason::Unauthenticated,
                "unknown or expired halter token",
            );
        };

        // Route to a configured service by the request Host. An unmatched host is denied
        // (fail closed) — halter only forwards to its allowlist.
        let host = extract_host(&req.headers).unwrap_or_default();
        let Some(service) = self.router.route(&host).cloned() else {
            self.audit_raw(&agent, &host, Decision::Deny, "no service for host", now);
            return reject(
                http::StatusCode::NOT_FOUND,
                DenyReason::UnknownTarget,
                "no service configured for this host",
            );
        };

        let action = normalize::normalize(&agent, &service, &req);

        let Some(policy) = self.control.registry.policy(&agent) else {
            self.audit(&action, Decision::Deny, "no policy registered", now);
            return reject(
                http::StatusCode::FORBIDDEN,
                DenyReason::NoPolicy,
                "agent has no policy",
            );
        };

        match policy::decide(&action, &policy) {
            Verdict::Deny(d) => {
                self.audit(&action, Decision::Deny, &format!("{:?}", d.reason), now);
                reject(http::StatusCode::FORBIDDEN, d.reason, "denied by policy")
            }
            Verdict::Allow(a) => self.plan_forward(&service, &action, &a.obligations, req, now),
        }
    }

    /// Build the upstream forward plan, resolving credential obligations against the
    /// vault. A missing credential fails closed (the agent must never proceed without
    /// the substitution that hides the real secret).
    fn plan_forward(
        &self,
        service: &Service,
        action: &Action,
        obligations: &[Obligation],
        req: ProxyRequest,
        now: u64,
    ) -> Outcome {
        let mut headers = sanitize_headers(&req.headers);
        let mut injected: Vec<String> = Vec::new();

        for obligation in obligations {
            match obligation {
                Obligation::InjectCredential(o) => {
                    let id = &o.credential.id;
                    let Some(secret) = self.control.credentials.resolve(id) else {
                        self.audit(
                            action,
                            Decision::Deny,
                            &format!("credential '{id}' not configured"),
                            now,
                        );
                        return reject(
                            http::StatusCode::BAD_GATEWAY,
                            DenyReason::NotAllowed,
                            "required credential is not configured",
                        );
                    };
                    match http::HeaderValue::from_str(&format!("Bearer {}", secret.expose())) {
                        Ok(value) => {
                            headers.insert(http::header::AUTHORIZATION, value);
                            injected.push(id.clone());
                        }
                        Err(_) => {
                            self.audit(action, Decision::Deny, "credential not header-safe", now);
                            return reject(
                                http::StatusCode::BAD_GATEWAY,
                                DenyReason::NotAllowed,
                                "credential is not header-safe",
                            );
                        }
                    }
                }
            }
        }

        let detail = if injected.is_empty() {
            "allowed (no credential)".to_string()
        } else {
            format!("allowed; injected [{}]", injected.join(", "))
        };
        self.audit(action, Decision::Allow, &detail, now);

        Outcome::Forward(ForwardPlan {
            url: upstream_url(&service.upstream_base, &req.path, &req.query),
            method: req.method,
            headers,
            body: req.body,
        })
    }

    fn audit(&self, action: &Action, decision: Decision, detail: &str, now: u64) {
        self.control.audit.record(AuditEvent {
            at_ms: now,
            agent: action.agent.clone(),
            action: action.clone(),
            decision,
            detail: detail.to_string(),
        });
    }

    /// Audit a decision made before an `Action` exists (e.g. an unroutable host). The
    /// recorded action carries the raw host so the event is still attributable.
    fn audit_raw(&self, agent: &str, host: &str, decision: Decision, detail: &str, now: u64) {
        let action = Action::of(
            agent,
            "<unrouted>",
            models::action::Verb::Read,
            models::action::Resource::of(host, "host"),
        );
        self.audit(&action, decision, detail, now);
    }
}

/// Join an upstream base with the request path and optional query.
fn upstream_url(base: &str, path: &str, query: &str) -> String {
    let base = base.trim_end_matches('/');
    if query.is_empty() {
        format!("{base}{path}")
    } else {
        format!("{base}{path}?{query}")
    }
}

/// Extract the `Host` header value.
fn extract_host(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn reject(status: http::StatusCode, reason: DenyReason, message: &str) -> Outcome {
    Outcome::Reject(Rejection {
        status,
        reason,
        message: message.to_string(),
    })
}

/// Extract the bearer token from the `Authorization` header, accepting both
/// `Bearer <t>` and GitHub's `token <t>` schemes (case-insensitive scheme).
fn extract_token(headers: &http::HeaderMap) -> Option<String> {
    let raw = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, value) = raw.split_once(' ')?;
    let scheme = scheme.to_ascii_lowercase();
    if (scheme == "bearer" || scheme == "token") && !value.is_empty() {
        Some(value.trim().to_string())
    } else {
        None
    }
}

/// Copy request headers for the upstream, dropping the agent's `Authorization` (the
/// real credential is injected instead), the inbound `Host` and `Content-Length`
/// (recomputed by the client), and hop-by-hop headers.
fn sanitize_headers(headers: &http::HeaderMap) -> http::HeaderMap {
    let mut out = http::HeaderMap::new();
    for (name, value) in headers {
        if is_dropped_header(name) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn is_dropped_header(name: &http::HeaderName) -> bool {
    const HOP_BY_HOP: [&str; 8] = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ];
    let n = name.as_str().to_ascii_lowercase();
    n == "authorization" || n == "host" || n == "content-length" || HOP_BY_HOP.contains(&n.as_str())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::service::{Flavor, Service, ServiceRouter};
    use control::{InMemoryAudit, Secret};
    use models::policy::{Effect, Match, Policy, Rule};

    /// A control plane wired with an in-memory audit sink we can inspect, plus a seeded
    /// credential. Returns the plane, the audit handle, and the credential handle.
    fn test_control() -> (
        Arc<ControlPlane>,
        Arc<InMemoryAudit>,
        Arc<control::InMemoryCredentials>,
    ) {
        let creds = Arc::new(control::InMemoryCredentials::new());
        creds.insert("github-app", Secret::new("real-secret-token"));
        let audit = Arc::new(InMemoryAudit::new());
        let plane = ControlPlane::new(creds.clone(), audit.clone());
        (Arc::new(plane), audit, creds)
    }

    /// A catch-all GitHub-flavored service pointing at the real API base.
    fn router() -> ServiceRouter {
        ServiceRouter::new(vec![Service {
            name: "github".into(),
            host: "*".into(),
            upstream_base: "https://api.github.com".into(),
            flavor: Flavor::Github,
        }])
    }

    fn allow_all_with_cred() -> Policy {
        Policy {
            rules: vec![Rule {
                effect: Effect::Allow,
                matches: Match {
                    targets: vec![],
                    verbs: vec![],
                    resources: vec![],
                    conditions: vec![],
                },
                grant_credentials: vec!["github-app".into()],
            }],
        }
    }

    fn bearer(token: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    }

    fn get(headers: http::HeaderMap, path: &str) -> ProxyRequest {
        ProxyRequest {
            method: http::Method::GET,
            path: path.into(),
            query: String::new(),
            headers,
            body: bytes::Bytes::new(),
        }
    }

    fn fixed_clock(t: u64) -> Clock {
        Arc::new(move || t)
    }

    #[test]
    fn missing_token_is_unauthorized() {
        let (control, _audit, _) = test_control();
        let gw = Gateway::new(control, router());
        match gw.handle(get(http::HeaderMap::new(), "/repos/o/r")) {
            Outcome::Reject(r) => {
                assert_eq!(r.status, http::StatusCode::UNAUTHORIZED);
                assert_eq!(r.reason, DenyReason::Unauthenticated);
            }
            Outcome::Forward(_) => panic!("expected reject"),
        }
    }

    #[test]
    fn unknown_token_is_unauthorized() {
        let (control, _a, _) = test_control();
        let gw = Gateway::new(control, router());
        match gw.handle(get(bearer("not-a-real-token"), "/repos/o/r")) {
            Outcome::Reject(r) => assert_eq!(r.reason, DenyReason::Unauthenticated),
            Outcome::Forward(_) => panic!("expected reject"),
        }
    }

    #[test]
    fn allowed_request_injects_credential_and_strips_agent_token() {
        let (control, audit, _) = test_control();
        control.registry.register("agent-1", allow_all_with_cred());
        let gw = Gateway::with_clock(control.clone(), router(), fixed_clock(1_000));
        let minted = gw.mint("agent-1", 60).unwrap();

        match gw.handle(get(bearer(&minted.token), "/repos/octocat/hello")) {
            Outcome::Forward(plan) => {
                assert_eq!(plan.url, "https://api.github.com/repos/octocat/hello");
                let auth = plan
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .unwrap()
                    .to_str()
                    .unwrap();
                // The agent's token is gone; the real secret is in its place.
                assert_eq!(auth, "Bearer real-secret-token");
                assert!(!auth.contains(&minted.token));
            }
            Outcome::Reject(_) => panic!("expected forward"),
        }
        let events = audit.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].decision, Decision::Allow);
    }

    #[test]
    fn expired_token_is_unauthorized() {
        let (control, _a, _) = test_control();
        control.registry.register("agent-1", allow_all_with_cred());
        // Mint at t=1000 with 60s TTL → expires at 61_000.
        let gw_mint = Gateway::with_clock(control.clone(), router(), fixed_clock(1_000));
        let minted = gw_mint.mint("agent-1", 60).unwrap();
        // Handle at t=61_000 (expired).
        let gw = Gateway::with_clock(control, router(), fixed_clock(61_000));
        match gw.handle(get(bearer(&minted.token), "/repos/o/r")) {
            Outcome::Reject(r) => assert_eq!(r.reason, DenyReason::Unauthenticated),
            Outcome::Forward(_) => panic!("expected reject"),
        }
    }

    #[test]
    fn denied_request_is_forbidden_and_audited() {
        let (control, audit, _) = test_control();
        // Policy allows only reads; a DELETE falls through to default-deny.
        control.registry.register(
            "agent-1",
            Policy {
                rules: vec![Rule {
                    effect: Effect::Allow,
                    matches: Match {
                        targets: vec![],
                        verbs: vec![models::action::Verb::Read],
                        resources: vec![],
                        conditions: vec![],
                    },
                    grant_credentials: vec!["github-app".into()],
                }],
            },
        );
        let gw = Gateway::with_clock(control, router(), fixed_clock(1_000));
        let minted = gw.mint("agent-1", 60).unwrap();
        let del = ProxyRequest {
            method: http::Method::DELETE,
            path: "/repos/o/r".into(),
            query: String::new(),
            headers: bearer(&minted.token),
            body: bytes::Bytes::new(),
        };
        match gw.handle(del) {
            Outcome::Reject(r) => {
                assert_eq!(r.status, http::StatusCode::FORBIDDEN);
                assert_eq!(r.reason, DenyReason::NotAllowed);
            }
            Outcome::Forward(_) => panic!("expected reject"),
        }
        assert_eq!(audit.events()[0].decision, Decision::Deny);
    }

    #[test]
    fn authenticated_agent_without_policy_is_forbidden() {
        let (control, _a, _) = test_control();
        // Register so mint succeeds, then the policy lookup at handle time still finds
        // a policy — so to exercise NoPolicy we mint a token then remove via a fresh
        // control without the agent. Simpler: mint manually against tokens table.
        let now = 1_000;
        let minted = control.tokens.mint("ghost", 60, now);
        let gw = Gateway::with_clock(control, router(), fixed_clock(now));
        match gw.handle(get(bearer(&minted.token), "/repos/o/r")) {
            Outcome::Reject(r) => assert_eq!(r.reason, DenyReason::NoPolicy),
            Outcome::Forward(_) => panic!("expected reject"),
        }
    }

    #[test]
    fn mint_unknown_agent_returns_none() {
        let (control, _a, _) = test_control();
        let gw = Gateway::new(control, router());
        assert!(gw.mint("nobody", 60).is_none());
    }

    #[test]
    fn extract_token_accepts_both_schemes() {
        let mut h = http::HeaderMap::new();
        h.insert(http::header::AUTHORIZATION, "token abc".parse().unwrap());
        assert_eq!(extract_token(&h).as_deref(), Some("abc"));
        h.insert(http::header::AUTHORIZATION, "Bearer xyz".parse().unwrap());
        assert_eq!(extract_token(&h).as_deref(), Some("xyz"));
    }
}
