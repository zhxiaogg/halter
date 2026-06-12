//! Kubernetes-aware resource parsing (the `k8s` flavor): namespace + resource kind.

use super::Flavor;
use hackamore_models::action::Resource;
use hackamore_models::catalog::Catalog;
use std::sync::OnceLock;

/// Kubernetes-aware resource parsing (namespace + resource kind).
#[derive(Debug)]
pub struct K8sFlavor;

impl Flavor for K8sFlavor {
    fn name(&self) -> &'static str {
        "k8s"
    }

    fn catalog(&self) -> &Catalog {
        static CATALOG: OnceLock<Catalog> = OnceLock::new();
        CATALOG.get_or_init(|| Catalog::of("k8s", vec![]))
    }

    fn resource(&self, path: &str) -> Resource {
        k8s_resource(path)
    }
}

/// Kubernetes-aware resource parsing: the resource kind is the collection after the
/// namespace name (`…/namespaces/dev/pods` → `pods`), else the last path segment.
fn k8s_resource(path: &str) -> Resource {
    if path.is_empty() {
        return Resource::of("", "root");
    }
    let segs: Vec<&str> = path.split('/').collect();
    let kind = segs
        .iter()
        .position(|s| *s == "namespaces")
        .and_then(|i| segs.get(i + 2))
        .or_else(|| segs.last())
        .copied()
        .unwrap_or("resource");
    Resource::of(path, kind)
}
