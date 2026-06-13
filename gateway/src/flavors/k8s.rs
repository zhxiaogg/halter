//! Kubernetes-aware resource parsing (the `k8s` flavor): namespace + resource kind.

use super::Flavor;
use hackamore_models::action::{CrudKind, Resource, Verb};
use hackamore_models::catalog::{Catalog, HttpMethod, Operation};
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
        CATALOG.get_or_init(k8s_catalog)
    }

    fn resource(&self, path: &str) -> Resource {
        k8s_resource(path)
    }
}

/// The curated Kubernetes vocabulary: common namespaced core/apps operations. The kind
/// vocabulary is open-ended (CRDs); these document the shape policies match against —
/// kind = the collection segment after the namespace. Pinned to the normalizer by the
/// invariant tests in [`super`].
fn k8s_catalog() -> Catalog {
    let read = Verb::crud(CrudKind::Read);
    let create = Verb::crud(CrudKind::Create);
    let delete = Verb::crud(CrudKind::Delete);
    let ops = vec![
        Operation::of(
            "pods.list",
            read.clone(),
            HttpMethod::Get,
            "api/v1/namespaces/{namespace}/pods",
            "pods",
            "List pods in a namespace",
        ),
        Operation::of(
            "pods.get",
            read.clone(),
            HttpMethod::Get,
            "api/v1/namespaces/{namespace}/pods/{name}",
            "pods",
            "Read one pod",
        ),
        Operation::of(
            "pods.logs",
            read.clone(),
            HttpMethod::Get,
            "api/v1/namespaces/{namespace}/pods/{name}/log",
            "pods",
            "Read pod logs",
        ),
        Operation::of(
            "pods.delete",
            delete.clone(),
            HttpMethod::Delete,
            "api/v1/namespaces/{namespace}/pods/{name}",
            "pods",
            "Delete a pod",
        ),
        Operation::of(
            "deployments.list",
            read.clone(),
            HttpMethod::Get,
            "apis/apps/v1/namespaces/{namespace}/deployments",
            "deployments",
            "List deployments in a namespace",
        ),
        Operation::of(
            "deployments.get",
            read.clone(),
            HttpMethod::Get,
            "apis/apps/v1/namespaces/{namespace}/deployments/{name}",
            "deployments",
            "Read one deployment",
        ),
        Operation::of(
            "deployments.create",
            create,
            HttpMethod::Post,
            "apis/apps/v1/namespaces/{namespace}/deployments",
            "deployments",
            "Create a deployment",
        ),
        Operation::of(
            "deployments.delete",
            delete,
            HttpMethod::Delete,
            "apis/apps/v1/namespaces/{namespace}/deployments/{name}",
            "deployments",
            "Delete a deployment",
        ),
        Operation::of(
            "secrets.get",
            read,
            HttpMethod::Get,
            "api/v1/namespaces/{namespace}/secrets/{name}",
            "secrets",
            "Read one secret",
        ),
    ];
    Catalog::of("k8s", ops)
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
