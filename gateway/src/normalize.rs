//! Request → [`Action`] normalization. This is the protocol adapter: it turns a raw
//! HTTP request into the engine's protocol-agnostic `Action`. Normalization is generic
//! by default (any HTTP/JSON or SSE service); a service can opt into a richer [`Flavor`]
//! (e.g. GitHub) for nicer resource kinds. A future K8s/Envoy adapter is a sibling here.

use crate::core::ProxyRequest;
use crate::service::{Flavor, Service};
use models::action::{Action, Resource, Verb};
use serde_json::{Map, Value};

/// Normalize a request to `service` into an `Action` for `agent`.
pub fn normalize(agent: &str, service: &Service, req: &ProxyRequest) -> Action {
    let verb = verb_for(&req.method);
    let path = req.path.trim_start_matches('/');
    let resource = match service.flavor {
        Flavor::Github => github_resource(path),
        Flavor::Generic => generic_resource(path),
    };
    let fields = merge_fields(&req.query, &req.body);
    Action::of(agent, service.name.clone(), verb, resource).with_fields(fields)
}

/// Map an HTTP method to a coarse [`Verb`]. Unknown/odd methods map to `Read`, the
/// least-privileged verb, so they cannot accidentally satisfy a write rule.
fn verb_for(method: &http::Method) -> Verb {
    match *method {
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS => Verb::Read,
        http::Method::POST => Verb::Create,
        http::Method::PUT | http::Method::PATCH => Verb::Update,
        http::Method::DELETE => Verb::Delete,
        _ => Verb::Read,
    }
}

/// Generic resource: the full path as the canonical id, with the first path segment as
/// a coarse `kind`. Works for any service.
fn generic_resource(path: &str) -> Resource {
    if path.is_empty() {
        return Resource::of("", "root");
    }
    let kind = path.split('/').next().unwrap_or("other");
    Resource::of(path, kind)
}

/// GitHub-aware resource parsing (the `github` flavor).
fn github_resource(path: &str) -> Resource {
    if path.is_empty() {
        return Resource::of("", "root");
    }
    let segments: Vec<&str> = path.split('/').collect();
    let kind = match segments.as_slice() {
        ["repos", _owner, _repo] => "repo",
        ["repos", _owner, _repo, collection, ..] => github_collection_kind(collection),
        [first, ..] => first,
        [] => "other",
    };
    Resource::of(path, kind)
}

fn github_collection_kind(collection: &str) -> &'static str {
    match collection {
        "pulls" => "pull_request",
        "issues" => "issue",
        "contents" => "contents",
        "git" => "git",
        "actions" => "actions",
        "hooks" => "hook",
        _ => "repo_subresource",
    }
}

/// Merge query-string params and a JSON body into one flat `fields` object for
/// conditional rules. Body keys win over query keys. A non-JSON or non-object body
/// contributes nothing (its bytes still pass through untouched when forwarded).
fn merge_fields(query: &str, body: &[u8]) -> Value {
    let mut map = Map::new();
    for (k, v) in parse_query(query) {
        map.insert(k, Value::String(v));
    }
    if let Ok(Value::Object(obj)) = serde_json::from_slice::<Value>(body) {
        for (k, v) in obj {
            map.insert(k, v);
        }
    }
    Value::Object(map)
}

/// Minimal `a=b&c=d` parser. Values are taken verbatim (no percent-decoding in v1);
/// missing `=` yields an empty value.
fn parse_query(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return vec![];
    }
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (pair.to_string(), String::new()),
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::HeaderMap;

    fn service(name: &str, flavor: Flavor) -> Service {
        Service {
            name: name.into(),
            host: "*".into(),
            upstream_base: "https://upstream.example".into(),
            flavor,
        }
    }

    fn req(method: http::Method, path: &str, query: &str, body: &str) -> ProxyRequest {
        ProxyRequest {
            method,
            path: path.to_string(),
            query: query.to_string(),
            headers: HeaderMap::new(),
            body: Bytes::from(body.to_string()),
        }
    }

    #[test]
    fn github_flavor_parses_pull_request() {
        let r = req(
            http::Method::POST,
            "/repos/octocat/hello/pulls",
            "",
            r#"{"base":"main","title":"x"}"#,
        );
        let a = normalize("agent-1", &service("github", Flavor::Github), &r);
        assert_eq!(a.target, "github");
        assert_eq!(a.verb, Verb::Create);
        assert_eq!(a.resource.path, "repos/octocat/hello/pulls");
        assert_eq!(a.resource.kind, "pull_request");
        assert_eq!(
            a.fields,
            serde_json::json!({ "base": "main", "title": "x" })
        );
    }

    #[test]
    fn generic_flavor_uses_first_segment_kind() {
        let a = normalize(
            "a",
            &service("openai", Flavor::Generic),
            &req(
                http::Method::POST,
                "/v1/chat/completions",
                "",
                r#"{"model":"gpt"}"#,
            ),
        );
        assert_eq!(a.target, "openai");
        assert_eq!(a.verb, Verb::Create);
        assert_eq!(a.resource.path, "v1/chat/completions");
        assert_eq!(a.resource.kind, "v1");
        assert_eq!(a.fields, serde_json::json!({ "model": "gpt" }));
    }

    #[test]
    fn verbs_map_from_methods() {
        assert_eq!(verb_for(&http::Method::DELETE), Verb::Delete);
        assert_eq!(verb_for(&http::Method::PATCH), Verb::Update);
        assert_eq!(verb_for(&http::Method::HEAD), Verb::Read);
    }

    #[test]
    fn body_overrides_query_fields() {
        let a = normalize(
            "a",
            &service("svc", Flavor::Generic),
            &req(
                http::Method::POST,
                "/x",
                "base=main",
                r#"{"base":"develop"}"#,
            ),
        );
        assert_eq!(a.fields, serde_json::json!({ "base": "develop" }));
    }

    #[test]
    fn non_json_body_is_ignored_for_fields() {
        let a = normalize(
            "a",
            &service("svc", Flavor::Generic),
            &req(http::Method::POST, "/x", "", "not json"),
        );
        assert_eq!(a.fields, serde_json::json!({}));
    }
}
