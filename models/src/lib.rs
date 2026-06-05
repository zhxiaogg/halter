//! Generated protocol/contract types for halter (see `fluorite/*.fl`).
//!
//! Each module is generated from the like-named schema package. Hand-written
//! convenience constructors live here, never in the schemas.

#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod action {
    include!(concat!(env!("OUT_DIR"), "/action/mod.rs"));
}

#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod policy {
    include!(concat!(env!("OUT_DIR"), "/policy/mod.rs"));
}

#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod verdict {
    include!(concat!(env!("OUT_DIR"), "/verdict/mod.rs"));
}

#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod audit {
    include!(concat!(env!("OUT_DIR"), "/audit/mod.rs"));
}

#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod control {
    include!(concat!(env!("OUT_DIR"), "/control/mod.rs"));
}

/// An empty `fields` JSON object — the default when a request carries no query or body
/// attributes relevant to conditional rules.
pub fn empty_fields() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

impl action::Action {
    /// Ergonomic constructor with an empty `fields` object (the generated `new` requires
    /// every field, including `fields`, positionally).
    pub fn of(
        agent: impl Into<String>,
        target: action::Target,
        verb: action::Verb,
        resource: action::Resource,
    ) -> Self {
        Self {
            agent: agent.into(),
            target,
            verb,
            resource,
            fields: empty_fields(),
        }
    }

    /// Set the request `fields` (merged query + body) used by conditional rules.
    #[must_use]
    pub fn with_fields(mut self, fields: serde_json::Value) -> Self {
        self.fields = fields;
        self
    }
}

impl action::Resource {
    /// Ergonomic constructor accepting anything `Into<String>` (the generated `new`
    /// takes `String` positionally).
    pub fn of(path: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind: kind.into(),
        }
    }
}

impl verdict::Verdict {
    /// Whether this verdict permits the action.
    pub fn is_allow(&self) -> bool {
        matches!(self, verdict::Verdict::Allow(_))
    }

    /// Allow with the given credential-injection obligations.
    pub fn allow(credentials: Vec<verdict::CredentialRef>) -> Self {
        verdict::Verdict::Allow(verdict::AllowVerdict {
            obligations: credentials
                .into_iter()
                .map(|credential| {
                    verdict::Obligation::InjectCredential(verdict::InjectCredentialObligation {
                        credential,
                    })
                })
                .collect(),
        })
    }

    /// Deny with the given reason.
    pub fn deny(reason: verdict::DenyReason) -> Self {
        verdict::Verdict::Deny(verdict::DenyVerdict { reason })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::action::{Action, Resource, Target, Verb};
    use super::verdict::{CredentialRef, DenyReason, Verdict};

    #[test]
    fn action_round_trips_through_json() {
        let action = Action::of(
            "agent-1",
            Target::Github,
            Verb::Create,
            Resource::of("repos/octocat/hello/pulls", "pull_request"),
        )
        .with_fields(serde_json::json!({ "base": "main" }));
        let json = serde_json::to_string(&action).unwrap();
        let back: Action = serde_json::from_str(&json).unwrap();
        assert_eq!(action, back);
    }

    #[test]
    fn verdict_helpers_build_expected_variants() {
        let allow = Verdict::allow(vec![CredentialRef { id: "gh".into() }]);
        assert!(allow.is_allow());

        let deny = Verdict::deny(DenyReason::NotAllowed);
        assert!(!deny.is_allow());
    }
}
