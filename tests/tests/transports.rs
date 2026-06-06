//! e2e tests for the generalized capabilities: any HTTPS service (Host-routed,
//! fail-closed allowlist) and any transport (HTTP request/response and SSE streaming).

use gateway::{Extract, Flavor, Outbound, Protocol, Service};
use models::policy::Policy;
use tests::{start_halter_services, start_mock_upstream};

fn allow_all() -> Policy {
    serde_json::from_str(
        r#"{ "rules": [ { "effect": "Allow",
            "matches": { "targets": [], "verbs": [], "resources": [], "conditions": [] } } ] }"#,
    )
    .expect("valid policy")
}

/// RPC extraction: an AWS-query service distinguishes `DescribeInstances` (read) from
/// `TerminateInstances` (destroy) — both `POST /` — so policy gates them apart.
#[tokio::test]
async fn aws_query_action_is_gated() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter_services(vec![Service {
        name: "ec2".into(),
        host: "*".into(),
        upstream_base: upstream.base_url.clone(),
        flavor: Flavor::Generic,
        outbound: Outbound::Bearer {
            credential: "aws".into(),
        },
        address: String::new(),
        extract: Extract {
            protocol: Protocol::AwsQuery,
            path_template: None,
        },
    }])
    .await;
    halter.add_credential("aws", "real");
    // Allow only DescribeInstances (a named action verb).
    let policy: Policy = serde_json::from_str(
        r#"{ "rules": [ { "effect": "Allow", "matches": {
            "targets": [], "resources": [], "conditions": [],
            "verbs": [ { "type": "Action", "value": { "id": "DescribeInstances" } } ] } } ] }"#,
    )
    .expect("valid policy");
    let token = halter.mint_token(&policy, 3600).await;
    let client = reqwest::Client::new();

    let ok = client
        .post(format!("{}/", halter.proxy_url))
        .bearer_auth(&token)
        .body("Action=DescribeInstances&Version=2016-11-15")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    let denied = client
        .post(format!("{}/", halter.proxy_url))
        .bearer_auth(&token)
        .body("Action=TerminateInstances&InstanceId=i-1")
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    // Only the allowed read was forwarded.
    assert_eq!(upstream.requests().len(), 1);
}

/// A generic (non-GitHub) service: halter proxies any HTTPS API, injecting that
/// service's credential.
#[tokio::test]
async fn generic_service_is_proxied_with_its_credential() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter_services(vec![Service {
        name: "openai".into(),
        host: "*".into(),
        upstream_base: upstream.base_url.clone(),
        flavor: Flavor::Generic,
        outbound: Outbound::Bearer {
            credential: "openai-key".into(),
        },
        address: String::new(),
        extract: Extract::default(),
    }])
    .await;
    halter.add_credential("openai-key", "sk-real-key");
    let token = halter.mint_token(&allow_all(), 3600).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", halter.proxy_url))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "model": "gpt" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let got = upstream.requests();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].path, "/v1/chat/completions");
    assert_eq!(got[0].authorization.as_deref(), Some("Bearer sk-real-key"));
}

/// SSE transport: an event-stream response is relayed through halter with its
/// `text/event-stream` content type and full payload intact.
#[tokio::test]
async fn sse_stream_is_relayed() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter_services(vec![Service {
        name: "events".into(),
        host: "*".into(),
        upstream_base: upstream.base_url.clone(),
        flavor: Flavor::Generic,
        outbound: Outbound::Bearer {
            credential: "svc-key".into(),
        },
        address: String::new(),
        extract: Extract::default(),
    }])
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
    // Only "api.github.com" is configured; the test client's Host won't match it.
    let halter = start_halter_services(vec![Service {
        name: "github".into(),
        host: "api.github.com".into(),
        upstream_base: upstream.base_url.clone(),
        flavor: Flavor::Github,
        outbound: Outbound::Bearer {
            credential: "github-app".into(),
        },
        address: String::new(),
        extract: Extract::default(),
    }])
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
