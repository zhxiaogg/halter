//! e2e tests for transport + routing capabilities that the per-use-case suite doesn't
//! exercise: SSE streaming relay and fail-closed Host routing. (Per-service injection and
//! AWS-query action gating live in `use_cases.rs`.)

use gateway::{Extract, Flavor, Outbound, Service};
use models::policy::Policy;
use tests::{start_halter_services, start_mock_upstream};

fn allow_all() -> Policy {
    serde_json::from_str(
        r#"{ "rules": [ { "effect": "Allow",
            "matches": { "targets": [], "verbs": [], "resources": [], "conditions": [] } } ] }"#,
    )
    .expect("valid policy")
}

fn service(name: &str, host: &str, flavor: Flavor, credential: &str, upstream: &str) -> Service {
    Service {
        name: name.into(),
        host: host.into(),
        upstream_base: upstream.into(),
        flavor,
        outbound: Outbound::Bearer {
            credential: credential.into(),
        },
        address: String::new(),
        extract: Extract::default(),
    }
}

/// SSE transport: an event-stream response is relayed through halter with its
/// `text/event-stream` content type and full payload intact.
#[tokio::test]
async fn sse_stream_is_relayed() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter_services(vec![service(
        "events",
        "*",
        Flavor::Generic,
        "svc-key",
        &upstream.base_url,
    )])
    .await;
    halter.add_credential("svc-key", "real");
    let token = halter.mint_token(&allow_all(), 3600).await;

    let resp = reqwest::Client::new()
        .get(format!("{}/v1/stream", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("data: one"));
    assert!(body.contains("data: three"));
}

/// Fail closed: a request whose Host matches no configured service is denied and never
/// forwarded — even with a valid token and an allow-all policy.
#[tokio::test]
async fn unrouted_host_is_denied() {
    let upstream = start_mock_upstream().await;
    // Only "api.github.com" is configured; the test client's Host (127.0.0.1) won't match.
    let halter = start_halter_services(vec![service(
        "github",
        "api.github.com",
        Flavor::Github,
        "github-app",
        &upstream.base_url,
    )])
    .await;
    halter.add_credential("github-app", "real");
    let token = halter.mint_token(&allow_all(), 3600).await;

    let resp = reqwest::Client::new()
        .get(format!("{}/repos/o/r", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert!(
        !upstream.was_called(),
        "unrouted host must not be forwarded"
    );
}
