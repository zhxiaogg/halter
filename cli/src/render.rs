//! Human/JSON rendering for `hackamore catalog list`. Pure string-building so it
//! unit-tests without a terminal.

use hackamore_models::action::Verb;
use hackamore_models::catalog::Catalog;

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
}
