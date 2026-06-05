//! halter data plane — the reverse proxy that enforces policy decisions.
//!
//! - [`github`] normalizes an HTTP request into the engine's `Action` (the protocol
//!   adapter; a second target would add a sibling module).
//! - [`core`] is the transport-agnostic decision + enforcement path ([`Gateway`]).
//! - [`server`] is the axum HTTP surface and the outbound forwarder.

pub mod core;
pub mod github;
pub mod server;

pub use core::{ForwardPlan, Gateway, Outcome, ProxyRequest, Rejection, Route};
pub use server::{ServerState, admin_router, proxy_router, serve};
