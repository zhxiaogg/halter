//! Human/JSON rendering for the discovery + validation commands (`hackamore catalog
//! list`, `hackamore policy lint`, `hackamore policy test`). Pure string-building so it
//! unit-tests without a terminal.

use hackamore_models::action::{Action, Verb};
use hackamore_models::catalog::Catalog;
use hackamore_models::lint::Finding;
use hackamore_models::verdict::Verdict;
use hackamore_policy::Trace;

/// Render catalogs as an aligned human table, one section per flavor. Raw flavors
/// (empty catalogs) say so instead of printing an empty table.
pub fn catalogs_human(catalogs: &[Catalog]) -> String {
    let mut out = String::new();
    for catalog in catalogs {
        if !out.is_empty() {
            out.push('\n');
        }
        if catalog.operations.is_empty() {
            out.push_str(&format!("flavor: {}\n", catalog.flavor));
            out.push_str(
                "  (raw: no catalog — paths normalize generically; policies use path globs)\n",
            );
            continue;
        }
        out.push_str(&format!(
            "flavor: {} ({} operations)\n",
            catalog.flavor,
            catalog.operations.len()
        ));
        let header = ["OPERATION", "VERB", "ROUTE", "KIND", "FIELDS"];
        let rows: Vec<[String; 5]> = catalog
            .operations
            .iter()
            .map(|op| {
                [
                    op.id.clone(),
                    verb_display(&op.verb),
                    format!("{} {}", op.route.method.as_str(), op.route.path_template),
                    op.resource_kind.clone(),
                    op.fields
                        .iter()
                        .map(|f| f.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                ]
            })
            .collect();
        // Pad each of the first four columns to its widest cell; FIELDS runs ragged.
        let width = |i: usize| {
            rows.iter()
                .map(|r| r[i].len())
                .chain(std::iter::once(header[i].len()))
                .max()
                .unwrap_or(0)
        };
        let widths = [width(0), width(1), width(2), width(3)];
        let line = |cells: [&str; 5]| {
            format!(
                "  {:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {}\n",
                cells[0],
                cells[1],
                cells[2],
                cells[3],
                cells[4],
                w0 = widths[0],
                w1 = widths[1],
                w2 = widths[2],
                w3 = widths[3],
            )
            .trim_end()
            .to_string()
                + "\n"
        };
        out.push_str(&line(header));
        for row in &rows {
            out.push_str(&line([&row[0], &row[1], &row[2], &row[3], &row[4]]));
        }
    }
    out
}

/// Render catalogs as pretty JSON (the same shape the admin `GET /catalogs` endpoint
/// will serve).
pub fn catalogs_json(catalogs: &[Catalog]) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(catalogs)
}

/// The terse verb spelling (the same vocabulary `Verb::parse` accepts): CRUD verbs by
/// kind name, named actions by id.
fn verb_display(verb: &Verb) -> String {
    match verb {
        Verb::Crud(crud) => format!("{:?}", crud.kind),
        Verb::Action(named) => named.id.clone(),
    }
}

/// Render lint findings, one line each (`error rule 1: …` / `warning rule 0: …`), with
/// a one-line tally. Empty findings render the all-clear line.
pub fn findings_human(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "ok: no findings\n".to_string();
    }
    let mut out = String::new();
    for f in findings {
        let severity = if f.is_error() { "error" } else { "warning" };
        out.push_str(&format!(
            "{severity} rule {}: {}\n",
            f.rule_index, f.message
        ));
    }
    let errors = findings.iter().filter(|f| f.is_error()).count();
    out.push_str(&format!(
        "{} error(s), {} warning(s)\n",
        errors,
        findings.len() - errors
    ));
    out
}

/// Render a `policy test` result: the normalized action, then the traced decision.
pub fn trace_human(action: &Action, trace: &Trace) -> Result<String, serde_json::Error> {
    let decision = match (&trace.verdict, trace.matched_rule) {
        (Verdict::Allow(_), Some(rule)) => format!("Allow (rule {rule})"),
        // The engine only allows via a matched rule; this arm is unreachable but total.
        (Verdict::Allow(_), None) => "Allow".to_string(),
        (Verdict::Deny(d), Some(rule)) => format!("Deny {:?} (rule {rule})", d.reason),
        (Verdict::Deny(d), None) => format!("Deny {:?} (no rule matched)", d.reason),
    };
    Ok(format!(
        "action: {}\ndecision: {decision}\n",
        serde_json::to_string_pretty(action)?
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use hackamore_models::action::CrudKind;
    use hackamore_models::catalog::{FieldSource, FieldSpec, HttpMethod, Operation};

    fn sample() -> Vec<Catalog> {
        vec![
            Catalog::of(
                "github",
                vec![
                    Operation::of(
                        "pulls.create",
                        Verb::crud(CrudKind::Create),
                        HttpMethod::Post,
                        "repos/{owner}/{repo}/pulls",
                        "pull_request",
                        "Open a pull request",
                    )
                    .with_fields(vec![
                        FieldSpec::of("base", FieldSource::Body, "target branch"),
                        FieldSpec::of("head", FieldSource::Body, "source branch"),
                    ]),
                    Operation::of(
                        "repo.get",
                        Verb::crud(CrudKind::Read),
                        HttpMethod::Get,
                        "repos/{owner}/{repo}",
                        "repo",
                        "Read repository metadata",
                    ),
                ],
            ),
            Catalog::of("generic", vec![]),
        ]
    }

    #[test]
    fn human_table_aligns_columns_and_marks_raw_flavors() {
        let text = catalogs_human(&sample());
        assert_eq!(
            text,
            "\
flavor: github (2 operations)
  OPERATION     VERB    ROUTE                            KIND          FIELDS
  pulls.create  Create  POST repos/{owner}/{repo}/pulls  pull_request  base, head
  repo.get      Read    GET repos/{owner}/{repo}         repo

flavor: generic
  (raw: no catalog — paths normalize generically; policies use path globs)
"
        );
    }

    #[test]
    fn json_round_trips() {
        let json = catalogs_json(&sample()).unwrap();
        let back: Vec<Catalog> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sample());
    }

    #[test]
    fn findings_render_with_tally_and_all_clear() {
        assert_eq!(findings_human(&[]), "ok: no findings\n");
        let text = findings_human(&[
            Finding::error(1, "glob '/x' can never match"),
            Finding::warning(2, "field 'bsae' is not documented"),
        ]);
        assert_eq!(
            text,
            "error rule 1: glob '/x' can never match\n\
             warning rule 2: field 'bsae' is not documented\n\
             1 error(s), 1 warning(s)\n"
        );
    }

    #[test]
    fn trace_renders_decision_lines() {
        use hackamore_models::action::{CrudKind, Resource};
        use hackamore_models::verdict::DenyReason;
        let action = Action::of(
            "github",
            Verb::crud(CrudKind::Create),
            Resource::of("repos/o/r/pulls", "pull_request"),
        );
        let allowed = Trace {
            verdict: Verdict::allow(vec![]),
            matched_rule: Some(0),
        };
        let text = trace_human(&action, &allowed).unwrap();
        assert!(text.starts_with("action: {"));
        assert!(text.ends_with("decision: Allow (rule 0)\n"));

        let fallthrough = Trace {
            verdict: Verdict::deny(DenyReason::NotAllowed),
            matched_rule: None,
        };
        let text = trace_human(&action, &fallthrough).unwrap();
        assert!(text.ends_with("decision: Deny NotAllowed (no rule matched)\n"));
    }
}
