//! The HTTP data plane: an axum reverse proxy that drives [`Gateway`], plus a small
//! admin API for minting tokens.
//!
//! halter runs as a reverse proxy, not a transparent MITM: the agent is configured to
//! address halter directly and the sandbox (nono/Seatbelt/Landlock + netns) guarantees
//! halter is the *only* reachable destination, so the agent cannot bypass it. That lets
//! us avoid TLS interception and CA distribution entirely while preserving the core
//! invariant — the agent presents its halter token, never the real credential.

use crate::core::{ForwardPlan, Gateway, Outcome, ProxyRequest, Rejection};
use axum::Router;
use axum::body::Body;
use axum::extract::{Json, State};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use http::StatusCode;
use models::control::MintRequest;
use std::sync::Arc;

/// Maximum request body halter will buffer (25 MiB). Larger requests are rejected.
const MAX_BODY: usize = 25 * 1024 * 1024;

/// Shared state for both routers: the decision engine and the outbound HTTP client.
pub struct ServerState {
    gateway: Gateway,
    client: reqwest::Client,
}

impl ServerState {
    pub fn new(gateway: Gateway) -> Self {
        Self {
            gateway,
            client: reqwest::Client::new(),
        }
    }
}

/// The proxy router: every method and path is captured and run through the gateway.
pub fn proxy_router(state: Arc<ServerState>) -> Router {
    Router::new().fallback(proxy_handler).with_state(state)
}

/// The admin router: `POST /mint` issues a launch token for a registered agent. Bind
/// this on a separate, localhost-only listener — it is operator/orchestrator surface,
/// not agent surface.
pub fn admin_router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/mint", post(mint_handler))
        .with_state(state)
}

/// Serve both routers until shutdown: the proxy on `proxy_addr`, the admin API on
/// `admin_addr`.
pub async fn serve(
    proxy_addr: std::net::SocketAddr,
    admin_addr: std::net::SocketAddr,
    gateway: Gateway,
) -> std::io::Result<()> {
    let state = Arc::new(ServerState::new(gateway));
    let proxy_listener = tokio::net::TcpListener::bind(proxy_addr).await?;
    let admin_listener = tokio::net::TcpListener::bind(admin_addr).await?;
    tracing::info!(%proxy_addr, %admin_addr, "halter listening");

    let proxy = axum::serve(proxy_listener, proxy_router(state.clone()));
    let admin = axum::serve(admin_listener, admin_router(state));
    tokio::try_join!(async move { proxy.await }, async move { admin.await },)?;
    Ok(())
}

async fn proxy_handler(
    State(state): State<Arc<ServerState>>,
    request: axum::extract::Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };
    let proxy_req = ProxyRequest {
        method: parts.method,
        path: parts.uri.path().to_string(),
        query: parts.uri.query().unwrap_or_default().to_string(),
        headers: parts.headers,
        body,
    };
    match state.gateway.handle(proxy_req) {
        Outcome::Reject(rejection) => rejection_response(&rejection),
        Outcome::Forward(plan) => forward(&state.client, plan).await,
    }
}

async fn mint_handler(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<MintRequest>,
) -> Response {
    match state.gateway.mint(&req.agent, req.ttl_seconds) {
        Some(response) => (StatusCode::OK, Json(response)).into_response(),
        None => error_response(StatusCode::NOT_FOUND, "unknown agent"),
    }
}

/// Execute the planned upstream request and relay the response back to the agent.
///
/// The response body is **streamed**, never buffered, so Server-Sent Events, chunked
/// responses, and long-polls flow through halter transparently. (The request body is
/// buffered earlier because policy conditions may inspect it; responses have no such
/// need.)
async fn forward(client: &reqwest::Client, plan: ForwardPlan) -> Response {
    let mut builder = client.request(plan.method, &plan.url).headers(plan.headers);
    if !plan.body.is_empty() {
        builder = builder.body(plan.body);
    }
    let upstream = match builder.send().await {
        Ok(resp) => resp,
        Err(e) => return error_response(StatusCode::BAD_GATEWAY, &format!("upstream error: {e}")),
    };

    let status = upstream.status();
    let headers = filter_response_headers(upstream.headers());
    let body = Body::from_stream(upstream.bytes_stream());

    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

/// Copy upstream response headers, dropping hop-by-hop and length/encoding headers that
/// the server layer recomputes.
fn filter_response_headers(headers: &http::HeaderMap) -> http::HeaderMap {
    let mut out = http::HeaderMap::new();
    for (name, value) in headers {
        let n = name.as_str().to_ascii_lowercase();
        if matches!(
            n.as_str(),
            "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "content-length"
                | "te"
                | "trailers"
                | "upgrade"
        ) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn rejection_response(rejection: &Rejection) -> Response {
    let body = serde_json::json!({
        "error": rejection.message,
        "reason": format!("{:?}", rejection.reason),
    })
    .to_string();
    (
        rejection.status,
        [(http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

fn error_response(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({ "error": message }).to_string();
    (
        status,
        [(http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}
