//! Full-stack e2e tests: a real halter server (reverse proxy + admin API) in front of a
//! mock GitHub upstream, driven over HTTP exactly as a sandboxed agent's `gh`/`git`
//! would drive it. Each test asserts one user story end to end.

use models::policy::Policy;
use tests::{start_halter, start_mock_upstream};

fn policy_from(json: &str) -> Policy {
    serde_json::from_str(json).expect("valid policy json")
}

/// Allow only reads. The target's credential is injected by the service config, not the
/// policy. (`verb` is the open tagged union — a CRUD verb here.)
const READ_ONLY: &str = r#"{
    "rules": [
        { "effect": "Allow",
          "matches": {
              "targets": [],
              "verbs": [ { "type": "Crud", "value": { "kind": "Read" } } ],
              "resources": [], "conditions": []
          } }
    ]
}"#;

/// Allow opening PRs only against base branch "develop".
const PR_TO_DEVELOP_ONLY: &str = r#"{
    "rules": [
        { "effect": "Allow",
          "matches": {
              "targets": [],
              "verbs": [ { "type": "Crud", "value": { "kind": "Create" } } ],
              "resources": ["repos/*/*/pulls"],
              "conditions": [ { "type": "Equals", "value": { "field": "base", "value": "develop" } } ]
          } }
    ]
}"#;

/// User story: a scoped agent reads a repo; halter swaps its token for the real
/// credential, which the agent never sees.
#[tokio::test]
async fn allowed_read_injects_real_credential() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter(&upstream.base_url).await;
    halter.add_credential("github-app", "real-secret-token");
    let token = halter.mint_token(&policy_from(READ_ONLY), 3600).await;

    let resp = reqwest::Client::new()
        .get(format!("{}/repos/octocat/hello", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let got = upstream.requests();
    assert_eq!(got.len(), 1, "upstream should be called exactly once");
    assert_eq!(got[0].path, "/repos/octocat/hello");
    // The real secret reached the upstream; the agent's halter token did not.
    assert_eq!(
        got[0].authorization.as_deref(),
        Some("Bearer real-secret-token")
    );
    assert!(!got[0].authorization.as_deref().unwrap().contains(&token));
}

/// User story: a read-only agent's write is denied inline and never reaches GitHub.
#[tokio::test]
async fn denied_write_never_reaches_upstream() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter(&upstream.base_url).await;
    halter.add_credential("github-app", "real-secret-token");
    let token = halter.mint_token(&policy_from(READ_ONLY), 3600).await;

    let resp = reqwest::Client::new()
        .delete(format!("{}/repos/octocat/hello", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert!(
        !upstream.was_called(),
        "denied request must not be forwarded"
    );
}

/// User story: finer-than-native control — PRs allowed only against an approved base.
#[tokio::test]
async fn pr_create_gated_by_base_branch() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter(&upstream.base_url).await;
    halter.add_credential("github-app", "real-secret-token");
    let token = halter
        .mint_token(&policy_from(PR_TO_DEVELOP_ONLY), 3600)
        .await;
    let client = reqwest::Client::new();

    // Allowed: base = develop.
    let ok = client
        .post(format!("{}/repos/octocat/hello/pulls", halter.proxy_url))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "base": "develop", "title": "feature" }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // Denied: base = main.
    let denied = client
        .post(format!("{}/repos/octocat/hello/pulls", halter.proxy_url))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "base": "main", "title": "sneaky" }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);

    // Only the allowed PR was forwarded.
    let got = upstream.requests();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].method, "POST");
    assert_eq!(got[0].path, "/repos/octocat/hello/pulls");
}

/// User story: an unauthenticated or invalid token is rejected before any forwarding.
#[tokio::test]
async fn missing_or_invalid_token_is_unauthorized() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter(&upstream.base_url).await;
    halter.add_credential("github-app", "real-secret-token");
    let client = reqwest::Client::new();

    let no_auth = client
        .get(format!("{}/repos/octocat/hello", halter.proxy_url))
        .send()
        .await
        .unwrap();
    assert_eq!(no_auth.status(), 401);

    let bad_auth = client
        .get(format!("{}/repos/octocat/hello", halter.proxy_url))
        .bearer_auth("not-a-real-token")
        .send()
        .await
        .unwrap();
    assert_eq!(bad_auth.status(), 401);

    assert!(!upstream.was_called());
}

/// User story: any structurally valid policy mints a token (no agent identity).
#[tokio::test]
async fn admin_mint_accepts_any_valid_policy() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter(&upstream.base_url).await;
    let resp = halter.mint(&policy_from(READ_ONLY), 3600).await;
    assert!(resp.status().is_success());
    let value: serde_json::Value = resp.json().await.unwrap();
    assert!(value["token"].as_str().is_some());
}

/// User story: every decision is journaled — allow and deny alike.
#[tokio::test]
async fn decisions_are_audited() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter(&upstream.base_url).await;
    halter.add_credential("github-app", "real-secret-token");
    let token = halter.mint_token(&policy_from(READ_ONLY), 3600).await;
    let client = reqwest::Client::new();

    client
        .get(format!("{}/repos/octocat/hello", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    client
        .delete(format!("{}/repos/octocat/hello", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    let events = halter.audit.events();
    assert_eq!(events.len(), 2, "one audit record per decision");
    assert_eq!(events[0].decision, models::audit::Decision::Allow);
    assert_eq!(events[1].decision, models::audit::Decision::Deny);
}
