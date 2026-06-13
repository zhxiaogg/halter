//! The default flavor: path-based generic parsing that works for any HTTP/JSON or SSE
//! service. Raw (empty) catalog — there is no service-specific vocabulary to publish.

use super::Flavor;
use hackamore_models::action::Resource;
use hackamore_models::catalog::Catalog;
use std::sync::OnceLock;

/// Path-based generic parsing — works for any service.
#[derive(Debug)]
pub struct GenericFlavor;

impl Flavor for GenericFlavor {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn catalog(&self) -> &Catalog {
        static CATALOG: OnceLock<Catalog> = OnceLock::new();
        CATALOG.get_or_init(|| Catalog::of("generic", vec![]))
    }

    fn resource(&self, path: &str) -> Resource {
        generic_resource(path)
    }
}

/// Generic resource: the full path as the canonical id, with the first path segment as
/// a coarse `kind`. Works for any service.
pub(super) fn generic_resource(path: &str) -> Resource {
    if path.is_empty() {
        return Resource::of("", "root");
    }
    let kind = path.split('/').next().unwrap_or("other");
    Resource::of(path, kind)
}
