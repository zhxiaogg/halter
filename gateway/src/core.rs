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
use crate::service::{Outbound, Service, ServiceRouter};
use control::{ControlPlane, now_ms};
use models::action::Action;
use models::audit::{AuditEvent, Decision};
use models::verdict::{DenyReason, Verdict};
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

    /// Mint a launch token bound to `policy`. This is the control-plane verb the
    /// orchestrator calls at launch. Any valid policy mints a token — there is no agent
    /// identity (multi-tenant caller-authorization, when added, gates this earlier).
    pub fn mint(
        &self,
        policy: models::policy::Policy,
        ttl_seconds: u64,
    ) -> models::control::MintResponse {
        self.control
            .tokens
            .mint(policy, ttl_seconds, (self.clock)())
    }

    /// Authenticate, authorize, and (on allow) plan the upstream forward.
    pub fn handle(&self, req: ProxyRequest) -> Outcome {
        let now = (self.clock)();

        let Some((token, source)) = extract_auth(&req.headers) else {
            return reject(
                http::StatusCode::UNAUTHORIZED,
                DenyReason::Unauthenticated,
                "missing halter token",
            );
        };
        // The token resolves directly to its bound policy — no agent indirection.
        let Some(policy) = self.control.tokens.resolve(&token, now) else {
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
            self.audit_raw(&host, Decision::Deny, "no service for host", now);
            return reject(
                http::StatusCode::NOT_FOUND,
                DenyReason::UnknownTarget,
                "no service configured for this host",
            );
        };

        let action = normalize::normalize(&service, &req);

        match policy::decide(&action, &policy) {
            Verdict::Deny(d) => {
                self.audit(&action, Decision::Deny, &format!("{:?}", d.reason), now);
                reject(http::StatusCode::FORBIDDEN, d.reason, "denied by policy")
            }
            // On allow the outbound credential is the matched service's property, not the
            // policy's — the engine's allow is bare.
            Verdict::Allow(_) => self.plan_forward(&service, &action, req, source, now),
        }
    }

    /// Build the upstream forward plan according to the matched service's outbound
    /// stance. `Passthrough` forwards the consumer's own credential (preserved by
    /// `sanitize_headers` when the halter token arrived via `X-Halter-Token`); `Inject`
    /// swaps in the target's real credential from the vault. A missing credential fails
    /// closed.
    fn plan_forward(
        &self,
        service: &Service,
        action: &Action,
        req: ProxyRequest,
        source: AuthSource,
        now: u64,
    ) -> Outcome {
        let mut headers = sanitize_headers(&req.headers, source);

        let detail = match &service.outbound {
            Outbound::Passthrough => "allowed (passthrough)".to_string(),
            Outbound::Inject { credential } => {
                let Some(secret) = self.control.credentials.resolve(credential) else {
                    self.audit(
                        action,
                        Decision::Deny,
                        &format!("credential '{credential}' not configured"),
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
                format!("allowed; injected [{credential}]")
            }
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
            action: action.clone(),
            decision,
            detail: detail.to_string(),
        });
    }

    /// Audit a decision made before a routed `Action` exists (e.g. an unroutable host).
    /// The recorded action carries the raw host as its target so the event is still
    /// attributable.
    fn audit_raw(&self, host: &str, decision: Decision, detail: &str, now: u64) {
        let action = Action::of(
            "<unrouted>",
            models::action::Verb::crud(models::action::CrudKind::Read),
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

/// The dedicated header a consumer uses to present its halter token *without* consuming
/// the `Authorization` slot — so a filter-only (passthrough) consumer can carry its own
/// upstream credential in `Authorization` at the same time.
const HALTER_TOKEN_HEADER: &str = "x-halter-token";

/// Where the halter token was found. This decides whether `Authorization` belongs to
/// halter (and must be stripped) or to the consumer (and must be preserved for
/// passthrough).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AuthSource {
    /// The token came from the dedicated `X-Halter-Token` header; `Authorization` (if
    /// any) is the consumer's own upstream credential.
    HalterHeader,
    /// The token came from `Authorization` itself (e.g. `gh`/`kubectl`, which have only
    /// one auth slot); `Authorization` is the halter token and must not be forwarded.
    Authorization,
}

/// Extract the halter token and where it came from. `X-Halter-Token` is preferred (it
/// frees `Authorization` for passthrough); otherwise fall back to `Authorization`,
/// accepting both `Bearer <t>` and GitHub's `token <t>` schemes.
fn extract_auth(headers: &http::HeaderMap) -> Option<(String, AuthSource)> {
    if let Some(v) = headers
        .get(HALTER_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        let v = v.trim();
        if !v.is_empty() {
            return Some((v.to_string(), AuthSource::HalterHeader));
        }
    }
    let raw = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, value) = raw.split_once(' ')?;
    let scheme = scheme.to_ascii_lowercase();
    if (scheme == "bearer" || scheme == "token") && !value.trim().is_empty() {
        Some((value.trim().to_string(), AuthSource::Authorization))
    } else {
        None
    }
}

/// Copy request headers for the upstream, always dropping the `X-Halter-Token` header,
/// the inbound `Host` and `Content-Length` (recomputed by the client), and hop-by-hop
/// headers. `Authorization` is dropped only when it carried the halter token
/// (`source == Authorization`); under `HalterHeader` it is the consumer's own credential
/// and is preserved for passthrough.
fn sanitize_headers(headers: &http::HeaderMap, source: AuthSource) -> http::HeaderMap {
    let mut out = http::HeaderMap::new();
    for (name, value) in headers {
        if is_dropped_header(name, source) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn is_dropped_header(name: &http::HeaderName, source: AuthSource) -> bool {
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
    if n == HALTER_TOKEN_HEADER || n == "host" || n == "content-length" {
        return true;
    }
    if n == "authorization" {
        return source == AuthSource::Authorization;
    }
    HOP_BY_HOP.contains(&n.as_str())
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

    /// A catch-all GitHub-flavored service that injects the `github-app` credential.
    fn router() -> ServiceRouter {
        ServiceRouter::new(vec![Service {
            name: "github".into(),
            host: "*".into(),
            upstream_base: "https://api.github.com".into(),
            flavor: Flavor::Github,
            outbound: Outbound::Inject {
                credential: "github-app".into(),
            },
        }])
    }

    /// A catch-all generic service that forwards the consumer's own credential.
    fn router_passthrough() -> ServiceRouter {
        ServiceRouter::new(vec![Service {
            name: "svc".into(),
            host: "*".into(),
            upstream_base: "https://up.example".into(),
            flavor: Flavor::Generic,
            outbound: Outbound::Passthrough,
        }])
    }

    fn allow_all() -> Policy {
        Policy {
            rules: vec![Rule {
                effect: Effect::Allow,
                matches: Match {
                    targets: vec![],
                    verbs: vec![],
                    resources: vec![],
                    conditions: vec![],
                },
            }],
        }
    }

    fn read_only() -> Policy {
        Policy {
            rules: vec![Rule {
                effect: Effect::Allow,
                matches: Match {
                    targets: vec![],
                    verbs: vec![models::action::Verb::crud(models::action::CrudKind::Read)],
                    resources: vec![],
                    conditions: vec![],
                },
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

    /// Headers with the halter token in `X-Halter-Token` and the consumer's own
    /// credential in `Authorization` (the passthrough shape).
    fn halter_header_with_own_cred(token: &str, own_cred: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(
            HALTER_TOKEN_HEADER,
            http::HeaderValue::from_str(token).unwrap(),
        );
        h.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(own_cred).unwrap(),
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
    fn allowed_request_injects_targets_credential() {
        let (control, audit, _) = test_control();
        let gw = Gateway::with_clock(control.clone(), router(), fixed_clock(1_000));
        let minted = gw.mint(allow_all(), 60);

        match gw.handle(get(bearer(&minted.token), "/repos/octocat/hello")) {
            Outcome::Forward(plan) => {
                assert_eq!(plan.url, "https://api.github.com/repos/octocat/hello");
                let auth = plan
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .unwrap()
                    .to_str()
                    .unwrap();
                // The consumer's token is gone; the target's real secret is in its place.
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
    fn passthrough_with_token_in_authorization_forwards_no_credential() {
        let (control, _audit, _) = test_control();
        let gw = Gateway::with_clock(control.clone(), router_passthrough(), fixed_clock(1_000));
        let minted = gw.mint(allow_all(), 60);
        // The consumer put the halter token in Authorization and carries no separate
        // upstream credential → it is stripped, nothing replaces it.
        match gw.handle(get(bearer(&minted.token), "/x")) {
            Outcome::Forward(plan) => {
                assert!(plan.headers.get(http::header::AUTHORIZATION).is_none());
            }
            Outcome::Reject(_) => panic!("expected forward"),
        }
    }

    #[test]
    fn passthrough_preserves_consumers_own_credential() {
        let (control, _audit, _) = test_control();
        let gw = Gateway::with_clock(control.clone(), router_passthrough(), fixed_clock(1_000));
        let minted = gw.mint(allow_all(), 60);
        // The halter token rides X-Halter-Token; the consumer's own credential in
        // Authorization is forwarded untouched (the real filter-only behaviour).
        let headers = halter_header_with_own_cred(&minted.token, "Bearer consumer-own-key");
        let req = ProxyRequest {
            method: http::Method::GET,
            path: "/x".into(),
            query: String::new(),
            headers,
            body: bytes::Bytes::new(),
        };
        match gw.handle(req) {
            Outcome::Forward(plan) => {
                assert_eq!(
                    plan.headers
                        .get(http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok()),
                    Some("Bearer consumer-own-key")
                );
                // The halter token header is not forwarded.
                assert!(plan.headers.get(HALTER_TOKEN_HEADER).is_none());
            }
            Outcome::Reject(_) => panic!("expected forward"),
        }
    }

    #[test]
    fn inject_overrides_consumers_own_credential() {
        let (control, _audit, _) = test_control();
        let gw = Gateway::with_clock(control.clone(), router(), fixed_clock(1_000));
        let minted = gw.mint(allow_all(), 60);
        // Even if the consumer presents its own credential, inject replaces it with the
        // target's real secret.
        let headers = halter_header_with_own_cred(&minted.token, "Bearer consumer-own-key");
        let req = ProxyRequest {
            method: http::Method::GET,
            path: "/repos/o/r".into(),
            query: String::new(),
            headers,
            body: bytes::Bytes::new(),
        };
        match gw.handle(req) {
            Outcome::Forward(plan) => {
                assert_eq!(
                    plan.headers
                        .get(http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok()),
                    Some("Bearer real-secret-token")
                );
            }
            Outcome::Reject(_) => panic!("expected forward"),
        }
    }

    #[test]
    fn expired_token_is_unauthorized() {
        let (control, _a, _) = test_control();
        // Mint at t=1000 with 60s TTL → expires at 61_000.
        let gw_mint = Gateway::with_clock(control.clone(), router(), fixed_clock(1_000));
        let minted = gw_mint.mint(allow_all(), 60);
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
        let gw = Gateway::with_clock(control, router(), fixed_clock(1_000));
        let minted = gw.mint(read_only(), 60);
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
    fn extract_auth_prefers_halter_header_then_authorization() {
        let mut h = http::HeaderMap::new();
        h.insert(http::header::AUTHORIZATION, "token abc".parse().unwrap());
        assert_eq!(
            extract_auth(&h),
            Some(("abc".to_string(), AuthSource::Authorization))
        );
        h.insert(http::header::AUTHORIZATION, "Bearer xyz".parse().unwrap());
        assert_eq!(
            extract_auth(&h),
            Some(("xyz".to_string(), AuthSource::Authorization))
        );
        // X-Halter-Token wins over Authorization.
        h.insert(HALTER_TOKEN_HEADER, "tok-123".parse().unwrap());
        assert_eq!(
            extract_auth(&h),
            Some(("tok-123".to_string(), AuthSource::HalterHeader))
        );
    }
}
