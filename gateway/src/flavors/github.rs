//! GitHub-aware resource parsing (the `github` flavor): repo/pull_request/issue kinds.

use super::Flavor;
use hackamore_models::action::{CrudKind, Resource, Verb};
use hackamore_models::catalog::{Catalog, FieldSource, FieldSpec, HttpMethod, Operation};
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
        CATALOG.get_or_init(github_catalog)
    }

    fn resource(&self, path: &str) -> Resource {
        github_resource(path)
    }
}

/// A documented body field.
fn body(name: &str, summary: &str) -> FieldSpec {
    FieldSpec::of(name, FieldSource::Body, summary)
}

/// A documented query-string field.
fn query(name: &str, summary: &str) -> FieldSpec {
    FieldSpec::of(name, FieldSource::Query, summary)
}

/// The curated GitHub vocabulary: the operations agents most commonly need policies
/// about, with the fields conditional rules can constrain. Kinds and verbs are pinned to
/// the normalizer by the invariant tests in [`super`].
fn github_catalog() -> Catalog {
    let read = Verb::crud(CrudKind::Read);
    let create = Verb::crud(CrudKind::Create);
    let update = Verb::crud(CrudKind::Update);
    let delete = Verb::crud(CrudKind::Delete);
    let ops = vec![
        Operation::of(
            "repo.get",
            read.clone(),
            HttpMethod::Get,
            "repos/{owner}/{repo}",
            "repo",
            "Read repository metadata",
        ),
        Operation::of(
            "pulls.list",
            read.clone(),
            HttpMethod::Get,
            "repos/{owner}/{repo}/pulls",
            "pull_request",
            "List pull requests",
        )
        .with_fields(vec![
            query("state", "filter: open/closed/all"),
            query("base", "filter by base branch"),
            query("head", "filter by head ref"),
        ]),
        Operation::of(
            "pulls.create",
            create.clone(),
            HttpMethod::Post,
            "repos/{owner}/{repo}/pulls",
            "pull_request",
            "Open a pull request",
        )
        .with_fields(vec![
            body("title", "PR title"),
            body("head", "branch the changes come from"),
            body("base", "branch the changes go into"),
            body("body", "PR description"),
            body("draft", "open as a draft PR"),
        ]),
        Operation::of(
            "pulls.get",
            read.clone(),
            HttpMethod::Get,
            "repos/{owner}/{repo}/pulls/{number}",
            "pull_request",
            "Read one pull request",
        ),
        Operation::of(
            "pulls.update",
            update.clone(),
            HttpMethod::Patch,
            "repos/{owner}/{repo}/pulls/{number}",
            "pull_request",
            "Edit a pull request",
        )
        .with_fields(vec![
            body("title", "new title"),
            body("body", "new description"),
            body("state", "open or closed"),
            body("base", "new base branch"),
        ]),
        Operation::of(
            "pulls.merge",
            update.clone(),
            HttpMethod::Put,
            "repos/{owner}/{repo}/pulls/{number}/merge",
            "pull_request",
            "Merge a pull request",
        )
        .with_fields(vec![
            body("merge_method", "merge/squash/rebase"),
            body("commit_title", "merge commit title"),
        ]),
        Operation::of(
            "issues.list",
            read.clone(),
            HttpMethod::Get,
            "repos/{owner}/{repo}/issues",
            "issue",
            "List issues",
        )
        .with_fields(vec![
            query("state", "filter: open/closed/all"),
            query("labels", "comma-separated label filter"),
        ]),
        Operation::of(
            "issues.create",
            create.clone(),
            HttpMethod::Post,
            "repos/{owner}/{repo}/issues",
            "issue",
            "Open an issue",
        )
        .with_fields(vec![
            body("title", "issue title"),
            body("body", "issue description"),
            body("labels", "labels to apply"),
            body("assignees", "logins to assign"),
        ]),
        Operation::of(
            "issues.get",
            read.clone(),
            HttpMethod::Get,
            "repos/{owner}/{repo}/issues/{number}",
            "issue",
            "Read one issue",
        ),
        Operation::of(
            "issues.update",
            update.clone(),
            HttpMethod::Patch,
            "repos/{owner}/{repo}/issues/{number}",
            "issue",
            "Edit an issue",
        )
        .with_fields(vec![
            body("title", "new title"),
            body("body", "new description"),
            body("state", "open or closed"),
        ]),
        Operation::of(
            "issues.comment",
            create.clone(),
            HttpMethod::Post,
            "repos/{owner}/{repo}/issues/{number}/comments",
            "issue",
            "Comment on an issue or PR",
        )
        .with_fields(vec![body("body", "comment text")]),
        Operation::of(
            "contents.get",
            read.clone(),
            HttpMethod::Get,
            "repos/{owner}/{repo}/contents/{path+}",
            "contents",
            "Read a file or directory listing",
        )
        .with_fields(vec![query("ref", "branch/tag/SHA to read at")]),
        Operation::of(
            "contents.put",
            update.clone(),
            HttpMethod::Put,
            "repos/{owner}/{repo}/contents/{path+}",
            "contents",
            "Create or update a file (PUT normalizes to Update)",
        )
        .with_fields(vec![
            body("message", "commit message"),
            body("content", "base64 file content"),
            body("branch", "target branch"),
            body("sha", "blob SHA being replaced (updates)"),
        ]),
        Operation::of(
            "contents.delete",
            delete.clone(),
            HttpMethod::Delete,
            "repos/{owner}/{repo}/contents/{path+}",
            "contents",
            "Delete a file",
        )
        .with_fields(vec![
            body("message", "commit message"),
            body("sha", "blob SHA being deleted"),
            body("branch", "target branch"),
        ]),
        Operation::of(
            "git.create_ref",
            create,
            HttpMethod::Post,
            "repos/{owner}/{repo}/git/refs",
            "git",
            "Create a branch or tag ref",
        )
        .with_fields(vec![
            body("ref", "fully qualified ref, e.g. refs/heads/x"),
            body("sha", "commit SHA the ref points at"),
        ]),
        Operation::of(
            "git.get_ref",
            read.clone(),
            HttpMethod::Get,
            "repos/{owner}/{repo}/git/ref/{ref+}",
            "git",
            "Read a single ref",
        ),
        Operation::of(
            "actions.list_runs",
            read.clone(),
            HttpMethod::Get,
            "repos/{owner}/{repo}/actions/runs",
            "actions",
            "List workflow runs",
        ),
        Operation::of(
            "hooks.list",
            read,
            HttpMethod::Get,
            "repos/{owner}/{repo}/hooks",
            "hook",
            "List repository webhooks",
        ),
        Operation::of(
            "hooks.create",
            Verb::crud(CrudKind::Create),
            HttpMethod::Post,
            "repos/{owner}/{repo}/hooks",
            "hook",
            "Create a repository webhook",
        )
        .with_fields(vec![
            body("config", "webhook config (url, secret, …)"),
            body("events", "events to deliver"),
            body("active", "whether deliveries are enabled"),
        ]),
    ];
    Catalog::of("github", ops)
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
