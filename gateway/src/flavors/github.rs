//! GitHub-aware resource parsing (the `github` flavor): repo/pull_request/issue kinds.

use super::Flavor;
use hackamore_models::action::Resource;
use hackamore_models::catalog::Catalog;
use std::sync::OnceLock;

/// GitHub-aware resource parsing (repo/pull_request/issue kinds).
#[derive(Debug)]
pub struct GithubFlavor;

impl Flavor for GithubFlavor {
    fn name(&self) -> &'static str {
        "github"
    }

    fn catalog(&self) -> &Catalog {
        static CATALOG: OnceLock<Catalog> = OnceLock::new();
        CATALOG.get_or_init(|| Catalog::of("github", vec![]))
    }

    fn resource(&self, path: &str) -> Resource {
        github_resource(path)
    }
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
