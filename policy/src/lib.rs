//! The halter policy engine — the reusable decision core.
//!
//! Its entire public surface is one pure function, [`decide`]: given a normalized
//! [`Action`] and an agent's [`Policy`], it returns a [`Verdict`]. No I/O, no HTTP, no
//! async, no awareness that a proxy exists. That narrowness is the point: any data
//! plane (the bundled reverse proxy today, an Envoy `ext_authz` adapter tomorrow) can
//! reuse it by translating its request into an `Action` and enforcing the `Verdict`.
//!
//! Semantics: rules are evaluated top-to-bottom, **first match wins**, and if no rule
//! matches the action is **denied** (fail closed). An `Allow` rule's
//! `grant_credentials` become credential-injection obligations the data plane fulfills.

use models::action::{Action, Verb};
use models::policy::{Condition, Effect, Match, Policy, Rule};
use models::verdict::{CredentialRef, DenyReason, Verdict};
use serde_json::Value;

/// Decide whether `action` is permitted under `policy`.
///
/// Pure and total: every action yields either `Allow` (with obligations) or `Deny`
/// (with a reason). The default, when no rule matches, is `Deny(NotAllowed)`.
pub fn decide(action: &Action, policy: &Policy) -> Verdict {
    for rule in &policy.rules {
        if rule_matches(rule, action) {
            return verdict_for(rule);
        }
    }
    Verdict::deny(DenyReason::NotAllowed)
}

/// Build the verdict a matched rule produces.
fn verdict_for(rule: &Rule) -> Verdict {
    match rule.effect {
        Effect::Allow => Verdict::allow(
            rule.grant_credentials
                .iter()
                .map(|id| CredentialRef { id: id.clone() })
                .collect(),
        ),
        Effect::Deny => Verdict::deny(DenyReason::ExplicitDeny),
    }
}

/// Whether every facet of a rule's `matches` holds for the action. Empty lists mean
/// "any", so an all-empty `Match` matches every action.
fn rule_matches(rule: &Rule, action: &Action) -> bool {
    let m: &Match = &rule.matches;
    target_matches(&m.targets, &action.target)
        && verb_matches(&m.verbs, &action.verb)
        && resource_matches(&m.resources, &action.resource.path)
        && m.conditions
            .iter()
            .all(|c| condition_holds(c, &action.fields))
}

fn target_matches(targets: &[String], target: &str) -> bool {
    targets.is_empty() || targets.iter().any(|t| t == target)
}

fn verb_matches(verbs: &[Verb], verb: &Verb) -> bool {
    verbs.is_empty() || verbs.contains(verb)
}

fn resource_matches(patterns: &[String], path: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|p| glob_matches(p, path))
}

/// Segment-wise glob over a slash-joined resource path. `*` matches exactly one
/// segment; `**` matches any number of segments (including zero) and is normally the
/// trailing segment. Both pattern and path are compared by their `/`-split segments.
fn glob_matches(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let seg: Vec<&str> = path.split('/').collect();
    segments_match(&pat, &seg)
}

fn segments_match(pat: &[&str], seg: &[&str]) -> bool {
    match pat.split_first() {
        None => seg.is_empty(),
        Some((&"**", rest)) => {
            // `**` consumes zero-or-more segments: succeed if `rest` matches any suffix.
            (0..=seg.len()).any(|i| segments_match(rest, &seg[i..]))
        }
        Some((&head, rest)) => match seg.split_first() {
            None => false,
            Some((&shead, srest)) => (head == "*" || head == shead) && segments_match(rest, srest),
        },
    }
}

/// Whether a single field condition holds against the action's `fields` JSON object.
fn condition_holds(condition: &Condition, fields: &Value) -> bool {
    match condition {
        Condition::Equals(c) => lookup(fields, &c.field) == Some(&c.value),
        Condition::OneOf(c) => lookup(fields, &c.field).is_some_and(|v| c.values.contains(v)),
        Condition::Exists(c) => lookup(fields, &c.field).is_some_and(|v| !v.is_null()),
    }
}

/// Resolve a dotted path (e.g. `"head.ref"`) into a JSON object. Returns `None` if any
/// segment is missing or a non-object is traversed.
fn lookup<'a>(fields: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = fields;
    for seg in path.split('.') {
        cur = cur.as_object()?.get(seg)?;
    }
    Some(cur)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use models::action::{Action, Resource, Verb};
    use models::policy::{
        Condition, Effect, EqualsCondition, ExistsCondition, Match, OneOfCondition, Policy, Rule,
    };
    use models::verdict::{DenyReason, Verdict};

    fn empty_match() -> Match {
        Match {
            targets: vec![],
            verbs: vec![],
            resources: vec![],
            conditions: vec![],
        }
    }

    fn allow(matches: Match, creds: &[&str]) -> Rule {
        Rule {
            effect: Effect::Allow,
            matches,
            grant_credentials: creds.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn deny(matches: Match) -> Rule {
        Rule {
            effect: Effect::Deny,
            matches,
            grant_credentials: vec![],
        }
    }

    fn pr_create() -> Action {
        Action::of(
            "agent-1",
            "github",
            Verb::Create,
            Resource::of("repos/octocat/hello/pulls", "pull_request"),
        )
    }

    #[test]
    fn empty_policy_denies_default() {
        let v = decide(&pr_create(), &Policy { rules: vec![] });
        assert!(matches!(
            v,
            Verdict::Deny(d) if d.reason == DenyReason::NotAllowed
        ));
    }

    #[test]
    fn matching_allow_rule_grants_with_credentials() {
        let policy = Policy {
            rules: vec![allow(
                Match {
                    verbs: vec![Verb::Create],
                    resources: vec!["repos/octocat/*/pulls".into()],
                    ..empty_match()
                },
                &["github-app"],
            )],
        };
        let v = decide(&pr_create(), &policy);
        match v {
            Verdict::Allow(a) => {
                assert_eq!(a.obligations.len(), 1);
            }
            Verdict::Deny(_) => panic!("expected allow"),
        }
    }

    #[test]
    fn first_match_wins_deny_before_allow() {
        let policy = Policy {
            rules: vec![
                deny(Match {
                    verbs: vec![Verb::Create],
                    ..empty_match()
                }),
                allow(empty_match(), &["github-app"]),
            ],
        };
        let v = decide(&pr_create(), &policy);
        assert!(matches!(
            v,
            Verdict::Deny(d) if d.reason == DenyReason::ExplicitDeny
        ));
    }

    #[test]
    fn read_only_agent_denied_create() {
        // Allow only reads; a create falls through to default-deny.
        let policy = Policy {
            rules: vec![allow(
                Match {
                    verbs: vec![Verb::Read],
                    ..empty_match()
                },
                &["github-app"],
            )],
        };
        let read = Action::of(
            "agent-1",
            "github",
            Verb::Read,
            Resource::of("repos/octocat/hello", "repo"),
        );
        assert!(decide(&read, &policy).is_allow());
        assert!(!decide(&pr_create(), &policy).is_allow());
    }

    #[test]
    fn condition_gates_on_field_value() {
        // May open PRs, but only against base "develop".
        let policy = Policy {
            rules: vec![allow(
                Match {
                    verbs: vec![Verb::Create],
                    resources: vec!["repos/*/*/pulls".into()],
                    conditions: vec![Condition::Equals(EqualsCondition {
                        field: "base".into(),
                        value: serde_json::json!("develop"),
                    })],
                    ..empty_match()
                },
                &["github-app"],
            )],
        };
        let to_develop = pr_create().with_fields(serde_json::json!({ "base": "develop" }));
        let to_main = pr_create().with_fields(serde_json::json!({ "base": "main" }));
        assert!(decide(&to_develop, &policy).is_allow());
        assert!(!decide(&to_main, &policy).is_allow());
    }

    #[test]
    fn one_of_and_exists_conditions() {
        let policy = Policy {
            rules: vec![allow(
                Match {
                    conditions: vec![
                        Condition::OneOf(OneOfCondition {
                            field: "base".into(),
                            values: vec![
                                serde_json::json!("develop"),
                                serde_json::json!("staging"),
                            ],
                        }),
                        Condition::Exists(ExistsCondition {
                            field: "title".into(),
                        }),
                    ],
                    ..empty_match()
                },
                &["github-app"],
            )],
        };
        let ok = pr_create().with_fields(serde_json::json!({ "base": "staging", "title": "x" }));
        let no_title = pr_create().with_fields(serde_json::json!({ "base": "staging" }));
        let bad_base = pr_create().with_fields(serde_json::json!({ "base": "main", "title": "x" }));
        assert!(decide(&ok, &policy).is_allow());
        assert!(!decide(&no_title, &policy).is_allow());
        assert!(!decide(&bad_base, &policy).is_allow());
    }

    #[test]
    fn glob_double_star_matches_remainder() {
        assert!(glob_matches(
            "repos/octocat/**",
            "repos/octocat/hello/pulls/1"
        ));
        assert!(glob_matches("repos/*/*/pulls", "repos/a/b/pulls"));
        assert!(!glob_matches("repos/*/*/pulls", "repos/a/b/issues"));
        assert!(!glob_matches("repos/*/pulls", "repos/a/b/pulls"));
        assert!(glob_matches("repos/octocat/**", "repos/octocat"));
    }

    #[test]
    fn dotted_field_lookup() {
        let fields = serde_json::json!({ "head": { "ref": "feature" } });
        assert_eq!(
            lookup(&fields, "head.ref"),
            Some(&serde_json::json!("feature"))
        );
        assert_eq!(lookup(&fields, "head.sha"), None);
        assert_eq!(lookup(&fields, "missing"), None);
    }
}
