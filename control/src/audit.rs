//! The audit sink. Every decision halter makes — allow or deny — is recorded. The
//! trait lets the data plane stay oblivious to where records go; v1 ships an in-memory
//! sink (used by tests and introspection) and a `tracing` sink for operations.

use models::audit::AuditEvent;
use parking_lot::RwLock;

/// Receives one immutable [`AuditEvent`] per decision. Implementations must be cheap
/// and non-blocking; the data plane records on the request path.
pub trait AuditSink: Send + Sync {
    fn record(&self, event: AuditEvent);
}

/// Collects events in memory. Used by tests and for local introspection.
#[derive(Default)]
pub struct InMemoryAudit {
    events: RwLock<Vec<AuditEvent>>,
}

impl InMemoryAudit {
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot copy of all recorded events, oldest first.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.read().clone()
    }
}

impl AuditSink for InMemoryAudit {
    fn record(&self, event: AuditEvent) {
        self.events.write().push(event);
    }
}

/// Emits each event as a structured `tracing` record.
#[derive(Default)]
pub struct TracingAudit;

impl AuditSink for TracingAudit {
    fn record(&self, event: AuditEvent) {
        tracing::info!(
            agent = %event.agent,
            decision = ?event.decision,
            resource = %event.action.resource.path,
            verb = ?event.action.verb,
            detail = %event.detail,
            "halter decision"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use models::action::{Action, Resource, Verb};
    use models::audit::Decision;

    #[test]
    fn in_memory_audit_collects_in_order() {
        let sink = InMemoryAudit::new();
        for (i, decision) in [Decision::Allow, Decision::Deny].into_iter().enumerate() {
            sink.record(AuditEvent {
                at_ms: i as u64,
                agent: "a".into(),
                action: Action::of("a", "github", Verb::Read, Resource::of("repos/o/r", "repo")),
                decision,
                detail: String::new(),
            });
        }
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].decision, Decision::Allow);
        assert_eq!(events[1].decision, Decision::Deny);
    }
}
