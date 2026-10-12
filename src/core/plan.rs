//! The B3 work-item plan: a flat JSON list with `after` edges, validated by closed enums —
//! deliberately not a DSL (`reports/06-phase2-requirements.md:43-48`,
//! `reports/13-phase2-design-b3.md` § 2).
//!
//! A plan is orchestration data the conductor drives, never instructions: each `work` item
//! becomes an ordinary run through the same policy chokepoint as any delegate, and each `human`
//! item mints a `GateKind::Plan` gate the socket alone can resolve (S2). Validation here covers
//! the plan's own shape — ids, edges, acyclicity, bounds, kind/field coherence. Task-field
//! bounds (id charset, description length, ≥1 acceptance) stay at the doors, exactly where
//! `delegate` enforces them, so the two entry points cannot drift apart.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::core::types::Task;

/// The only plan format this build understands.
pub const PLAN_VERSION: u32 = 1;

/// The item ceiling. Small on purpose: a plan is a short brief the human can read whole, not a
/// program — and every item is a full run with its own budget and gates.
pub const MAX_PLAN_ITEMS: usize = 20;

/// Bounds shared with task ids: 1–64 of `[A-Za-z0-9._-]`.
const MAX_ITEM_ID_CHARS: usize = 64;

/// A `human` item's summary — same ceiling as a gate summary line's clamp.
const MAX_HUMAN_SUMMARY_CHARS: usize = 4_000;

/// What one item is. Closed: an unattested kind fails to deserialize at the door.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum PlanItemKind {
    /// A task the conductor delegates as an ordinary run: build → (verify) → (review) → gate.
    Work,
    /// A stop for a person: mints a `plan` gate on the container run and waits for the socket.
    Human,
}

/// One item. A struct with a `kind` discriminant rather than a tagged enum so
/// `deny_unknown_fields` keeps working (serde cannot deny unknown fields on internally tagged
/// enums); [`validate_plan`] enforces the kind/field coherence a tagged enum would have given.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanItem {
    pub id: String,
    pub kind: PlanItemKind,
    /// Required for `work`, forbidden for `human`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<Task>,
    /// Required for `human`, forbidden for `work`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Item ids that must be `done` before this one starts. Empty means "start immediately" —
    /// two items with no edges between them are the parallel fanout.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub after: Vec<String>,
    /// `work` only: per-item override of the team's captured verify switch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<bool>,
    /// `work` only: per-item override of the team's captured review switch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<bool>,
}

/// The plan document, as submitted through a door and echoed verbatim in `plan.created`.
///
/// Like [`crate::core::team::Team`], not `deny_unknown_fields` at the top level: the `version`
/// gate is what refuses a format from the future. Items are strict — they are the surface a
/// typo would otherwise silently change.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub version: u32,
    pub name: String,
    pub items: Vec<PlanItem>,
}

/// Why a plan (or one of its items) was refused. Closed set, one code per rule.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PlanIssueCode {
    UnsupportedVersion,
    NoItems,
    TooManyItems,
    BadItemId,
    DuplicateItemId,
    UnknownAfter,
    SelfAfter,
    Cycle,
    MissingTask,
    MissingSummary,
    FieldNotAllowed,
}

impl PlanIssueCode {
    /// The wire spelling, identical to what `serde` emits. Exhaustive: a new code must be named.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PlanIssueCode::UnsupportedVersion => "unsupported_version",
            PlanIssueCode::NoItems => "no_items",
            PlanIssueCode::TooManyItems => "too_many_items",
            PlanIssueCode::BadItemId => "bad_item_id",
            PlanIssueCode::DuplicateItemId => "duplicate_item_id",
            PlanIssueCode::UnknownAfter => "unknown_after",
            PlanIssueCode::SelfAfter => "self_after",
            PlanIssueCode::Cycle => "cycle",
            PlanIssueCode::MissingTask => "missing_task",
            PlanIssueCode::MissingSummary => "missing_summary",
            PlanIssueCode::FieldNotAllowed => "field_not_allowed",
        }
    }
}

impl fmt::Display for PlanIssueCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One thing wrong with the plan, named per item so a door refusal teaches the exact row.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PlanIssue {
    /// The item's id, or `""` for a document-level issue (version, item count).
    pub item: String,
    pub code: PlanIssueCode,
    pub detail: String,
}

/// Checks the plan's shape: version, bounds, id rules, kind/field coherence, edge resolution and
/// acyclicity (Kahn). Every failing rule is reported, not just the first.
///
/// # Errors
/// The issues, when any rule fails.
pub fn validate_plan(plan: &Plan) -> Result<(), Vec<PlanIssue>> {
    let mut issues = Vec::new();
    let doc = |code, detail: String| PlanIssue {
        item: String::new(),
        code,
        detail,
    };

    if plan.version > PLAN_VERSION {
        issues.push(doc(
            PlanIssueCode::UnsupportedVersion,
            format!(
                "plan version {} is newer than this build's {PLAN_VERSION}",
                plan.version
            ),
        ));
    }
    if plan.items.is_empty() {
        issues.push(doc(
            PlanIssueCode::NoItems,
            "a plan needs at least one item".to_string(),
        ));
    }
    if plan.items.len() > MAX_PLAN_ITEMS {
        issues.push(doc(
            PlanIssueCode::TooManyItems,
            format!(
                "{} items; a plan may carry at most {MAX_PLAN_ITEMS}",
                plan.items.len()
            ),
        ));
    }

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for item in &plan.items {
        let issue = |code, detail: String| PlanIssue {
            item: item.id.clone(),
            code,
            detail,
        };
        if item.id.is_empty()
            || item.id.chars().count() > MAX_ITEM_ID_CHARS
            || !item
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            issues.push(issue(
                PlanIssueCode::BadItemId,
                format!("item ids are 1-{MAX_ITEM_ID_CHARS} of [A-Za-z0-9._-]"),
            ));
        }
        if !seen.insert(item.id.as_str()) {
            issues.push(issue(
                PlanIssueCode::DuplicateItemId,
                "another item already uses this id".to_string(),
            ));
        }
        match item.kind {
            PlanItemKind::Work => {
                if item.task.is_none() {
                    issues.push(issue(
                        PlanIssueCode::MissingTask,
                        "a work item carries the task it delegates".to_string(),
                    ));
                }
                if item.summary.is_some() {
                    issues.push(issue(
                        PlanIssueCode::FieldNotAllowed,
                        "`summary` belongs to human items".to_string(),
                    ));
                }
            }
            PlanItemKind::Human => {
                if item
                    .summary
                    .as_ref()
                    .is_none_or(|s| s.is_empty() || s.chars().count() > MAX_HUMAN_SUMMARY_CHARS)
                {
                    issues.push(issue(
                        PlanIssueCode::MissingSummary,
                        format!(
                            "a human item carries a 1-{MAX_HUMAN_SUMMARY_CHARS} character summary"
                        ),
                    ));
                }
                if item.task.is_some() || item.verify.is_some() || item.review.is_some() {
                    issues.push(issue(
                        PlanIssueCode::FieldNotAllowed,
                        "`task`/`verify`/`review` belong to work items".to_string(),
                    ));
                }
            }
        }
    }

    for item in &plan.items {
        for edge in &item.after {
            if edge == &item.id {
                issues.push(PlanIssue {
                    item: item.id.clone(),
                    code: PlanIssueCode::SelfAfter,
                    detail: "an item cannot come after itself".to_string(),
                });
            } else if !seen.contains(edge.as_str()) {
                issues.push(PlanIssue {
                    item: item.id.clone(),
                    code: PlanIssueCode::UnknownAfter,
                    detail: format!("`after` names `{edge}`, which is not an item in this plan"),
                });
            }
        }
    }

    // Kahn over the ids that resolved; unresolved edges were already reported above and cycles
    // are only meaningful over real nodes.
    if issues.is_empty() {
        let mut indegree: BTreeMap<&str, usize> = plan
            .items
            .iter()
            .map(|item| (item.id.as_str(), item.after.len()))
            .collect();
        let mut ready: Vec<&str> = indegree
            .iter()
            .filter(|(_, degree)| **degree == 0)
            .map(|(id, _)| *id)
            .collect();
        let mut settled = 0_usize;
        while let Some(done) = ready.pop() {
            settled += 1;
            for item in &plan.items {
                if item.after.iter().any(|edge| edge == done) {
                    let degree = indegree
                        .get_mut(item.id.as_str())
                        .expect("every item has an indegree");
                    *degree -= 1;
                    if *degree == 0 {
                        ready.push(item.id.as_str());
                    }
                }
            }
        }
        if settled != plan.items.len() {
            issues.push(PlanIssue {
                item: String::new(),
                code: PlanIssueCode::Cycle,
                detail: "the `after` edges form a cycle; a plan is a DAG".to_string(),
            });
        }
    }

    if issues.is_empty() {
        Ok(())
    } else {
        Err(issues)
    }
}

/// Where one item stands, as `plan.item` records it. Closed; the conductor is the only writer.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PlanItemStatus {
    Pending,
    Started,
    Done,
    Blocked,
    Skipped,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str) -> Task {
        Task {
            id: id.to_string(),
            title: "t".to_string(),
            description: "a description".to_string(),
            files: vec![],
            acceptance: vec!["done".to_string()],
        }
    }

    fn work(id: &str, after: &[&str]) -> PlanItem {
        PlanItem {
            id: id.to_string(),
            kind: PlanItemKind::Work,
            task: Some(task(id)),
            summary: None,
            after: after.iter().map(|s| (*s).to_string()).collect(),
            verify: None,
            review: None,
        }
    }

    fn plan(items: Vec<PlanItem>) -> Plan {
        Plan {
            version: PLAN_VERSION,
            name: "p".to_string(),
            items,
        }
    }

    #[test]
    fn a_sequence_and_a_fanout_validate() {
        validate_plan(&plan(vec![
            work("a", &[]),
            work("b", &["a"]),
            work("c", &["a"]),
            PlanItem {
                id: "sign".to_string(),
                kind: PlanItemKind::Human,
                task: None,
                summary: Some("look at b and c together".to_string()),
                after: vec!["b".to_string(), "c".to_string()],
                verify: None,
                review: None,
            },
        ]))
        .expect("a DAG plan validates");
    }

    #[test]
    fn every_issue_code_is_produced_and_spelled() {
        let issues = validate_plan(&Plan {
            version: PLAN_VERSION + 1,
            name: "p".to_string(),
            items: vec![],
        })
        .expect_err("refused");
        assert_eq!(
            issues.iter().map(|i| i.code.as_str()).collect::<Vec<_>>(),
            ["unsupported_version", "no_items"]
        );

        let mut too_many = plan((0..21).map(|n| work(&format!("i{n}"), &[])).collect());
        let issues = validate_plan(&too_many).expect_err("refused");
        assert_eq!(issues[0].code.as_str(), "too_many_items");
        too_many.items.truncate(2);

        let mut bad = plan(vec![work("ok", &[]), work("bad id!", &[])]);
        bad.items[1].after = vec!["bad id!".to_string()];
        let issues = validate_plan(&bad).expect_err("refused");
        assert_eq!(issues[0].code, PlanIssueCode::BadItemId);
        assert_eq!(issues[1].code, PlanIssueCode::SelfAfter);

        let issues =
            validate_plan(&plan(vec![work("a", &[]), work("a", &[])])).expect_err("refused");
        assert_eq!(issues[0].code, PlanIssueCode::DuplicateItemId);

        let issues = validate_plan(&plan(vec![work("a", &["ghost"])])).expect_err("refused");
        assert_eq!(issues[0].code, PlanIssueCode::UnknownAfter);

        let issues =
            validate_plan(&plan(vec![work("a", &["b"]), work("b", &["a"])])).expect_err("cycle");
        assert_eq!(issues[0].code, PlanIssueCode::Cycle);

        let mut wrong = plan(vec![work("a", &[])]);
        wrong.items[0].task = None;
        wrong.items[0].summary = Some("prose".to_string());
        let issues = validate_plan(&wrong).expect_err("refused");
        assert_eq!(
            issues.iter().map(|i| i.code).collect::<Vec<_>>(),
            [PlanIssueCode::MissingTask, PlanIssueCode::FieldNotAllowed]
        );

        let human_wrong = plan(vec![PlanItem {
            id: "h".to_string(),
            kind: PlanItemKind::Human,
            task: Some(task("h")),
            summary: None,
            after: vec![],
            verify: Some(true),
            review: None,
        }]);
        let issues = validate_plan(&human_wrong).expect_err("refused");
        assert_eq!(
            issues.iter().map(|i| i.code).collect::<Vec<_>>(),
            [
                PlanIssueCode::MissingSummary,
                PlanIssueCode::FieldNotAllowed
            ]
        );

        // Every code has a producer above; the spellings are pinned for the wire in one place.
        assert_eq!(
            [
                PlanIssueCode::UnsupportedVersion,
                PlanIssueCode::NoItems,
                PlanIssueCode::TooManyItems,
                PlanIssueCode::BadItemId,
                PlanIssueCode::DuplicateItemId,
                PlanIssueCode::UnknownAfter,
                PlanIssueCode::SelfAfter,
                PlanIssueCode::Cycle,
                PlanIssueCode::MissingTask,
                PlanIssueCode::MissingSummary,
                PlanIssueCode::FieldNotAllowed,
            ]
            .map(PlanIssueCode::as_str),
            [
                "unsupported_version",
                "no_items",
                "too_many_items",
                "bad_item_id",
                "duplicate_item_id",
                "unknown_after",
                "self_after",
                "cycle",
                "missing_task",
                "missing_summary",
                "field_not_allowed",
            ]
        );
    }

    #[test]
    fn an_unknown_item_key_is_refused_at_deserialization() {
        let err = serde_json::from_value::<PlanItem>(serde_json::json!({
            "id": "a", "kind": "work", "task": task("a"), "retries": 3
        }))
        .expect_err("deny_unknown_fields holds");
        assert!(err.to_string().contains("retries"), "{err}");
    }
}
