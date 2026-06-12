//! Pluggable normalization flavors. A flavor owns how a request path becomes a
//! [`Resource`] and publishes its [`Catalog`] — the machine-readable vocabulary policy
//! tooling (discovery, lint, the web UI) works from. Built-in flavors live here and
//! register in [`registry`]; adding one = a new impl + one registry line.
//!
//! Catalog/normalizer agreement is enforced by invariant tests rather than shared
//! interpretation code: every catalog operation is walked through the flavor's real
//! [`Flavor::resource`] and the method→verb mapping, so the published vocabulary cannot
//! drift from what the data plane actually produces.

mod generic;
mod github;
mod k8s;

pub use generic::GenericFlavor;
pub use github::GithubFlavor;
pub use k8s::K8sFlavor;

use hackamore_models::action::Resource;
use hackamore_models::catalog::Catalog;

/// How one service flavor turns request paths into resources, plus its published
/// vocabulary. `Debug` is a supertrait so [`crate::service::Service`] can keep
/// `#[derive(Debug)]`.
pub trait Flavor: Send + Sync + std::fmt::Debug {
    /// The canonical lowercase flavor name (what config's `"flavor"` field says).
    fn name(&self) -> &'static str;
    /// The flavor's operation vocabulary (empty = raw/undocumented).
    fn catalog(&self) -> &Catalog;
    /// Derive the resource (canonical path + kind) for a request path.
    fn resource(&self, path: &str) -> Resource;
}

pub static GENERIC: GenericFlavor = GenericFlavor;
pub static GITHUB: GithubFlavor = GithubFlavor;
pub static K8S: K8sFlavor = K8sFlavor;

static REGISTRY: [&dyn Flavor; 3] = [&GITHUB, &K8S, &GENERIC];

/// Every built-in flavor, in `catalog list` display order.
pub fn registry() -> &'static [&'static dyn Flavor] {
    &REGISTRY
}

/// Look up a flavor by its canonical name (case-insensitive).
pub fn by_name(name: &str) -> Option<&'static dyn Flavor> {
    registry()
        .iter()
        .copied()
        .find(|f| f.name().eq_ignore_ascii_case(name))
}

/// Resolve a config flavor name. Absent = generic; an unknown name is an error (fail
/// closed: a typo must not silently downgrade to generic parsing).
pub fn resolve(name: Option<&str>) -> Result<&'static dyn Flavor, UnknownFlavor> {
    match name {
        None => Ok(&GENERIC),
        Some(n) => by_name(n).ok_or_else(|| UnknownFlavor(n.to_string())),
    }
}

/// A config named a flavor no registered impl claims.
#[derive(Debug, PartialEq, Eq)]
pub struct UnknownFlavor(pub String);

impl std::fmt::Display for UnknownFlavor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let known: Vec<&str> = registry().iter().map(|f| f.name()).collect();
        write!(
            f,
            "unknown flavor '{}' (known: {})",
            self.0,
            known.join(", ")
        )
    }
}

impl std::error::Error for UnknownFlavor {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn by_name_is_case_insensitive() {
        assert_eq!(by_name("github").map(|f| f.name()), Some("github"));
        assert_eq!(by_name("GitHub").map(|f| f.name()), Some("github"));
        assert_eq!(by_name("k8s").map(|f| f.name()), Some("k8s"));
        assert!(by_name("nope").is_none());
    }

    #[test]
    fn resolve_defaults_absent_to_generic_and_fails_closed_on_unknown() {
        assert_eq!(resolve(None).map(|f| f.name()), Ok("generic"));
        assert_eq!(resolve(Some("github")).map(|f| f.name()), Ok("github"));
        let err = resolve(Some("rest")).map(|f| f.name()).unwrap_err();
        assert_eq!(err, UnknownFlavor("rest".to_string()));
        // The message lists what would have been accepted.
        assert!(err.to_string().contains("github"));
        assert!(err.to_string().contains("generic"));
    }

    #[test]
    fn registry_names_are_unique() {
        let names: std::collections::BTreeSet<&str> = registry().iter().map(|f| f.name()).collect();
        assert_eq!(names.len(), registry().len());
    }
}
