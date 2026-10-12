//! T12: `schemas/*.json` — drift guard, `jsonschema` compilation, fixture validation
//! (`reports/03-design.md` § Test Strategy, row `schemas/`).
//!
//! `schemars` is the source of truth for the three checked-in documents; each one is
//! `schema_for!(T)` run once through `strip_dollar_schema` (V7). These tests assert the files on
//! disk still equal what the types generate, that they compile as JSON Schema, and that the
//! captured provider output validates (or fails to) against them exactly as the loop expects.
//!
//! ## Regenerating `schemas/*.json`
//!
//! The generator is `gen_schemas` below — an `#[ignore]`d test rather than a `src/bin/` helper, so
//! the writer and the drift guard share one code path and no throwaway target ships in the crate:
//!
//! ```text
//! cargo test --test schemas gen_schemas -- --ignored
//! ```
//!
//! Run it after changing `BuildResult`, `ReviewVerdict` or `HandoffEnvelope`, then commit the
//! regenerated files; `checked_in_schemas_match_the_generated_ones` fails until you do.

use std::fs;
use std::path::{Path, PathBuf};

use agent_control_plane::core::types::{
    require_all_properties, strip_dollar_schema, BuildResult, HandoffEnvelope, ReviewVerdict,
    Severity, VerifyReport,
};
use schemars::schema_for;
use serde_json::{json, Value};

const BUILD_RESULT: &str = "schemas/build-result.json";
const REVIEW_VERDICT: &str = "schemas/review-verdict.json";
const HANDOFF_ENVELOPE: &str = "schemas/handoff-envelope.json";
const VERIFY_REPORT: &str = "schemas/verify-report.json";

const DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";

const REGENERATE: &str = "regenerate with `cargo test --test schemas gen_schemas -- --ignored`";

/// A well-formed `diffHash` (Rev 25): every synthetic verdict below carries one, so each test fails
/// for the reason it names rather than for the missing required key.
const A_DIFF_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Every checked-in schema paired with the document its type generates, `$schema` already stripped.
fn generated() -> Vec<(&'static str, Value)> {
    vec![
        (
            BUILD_RESULT,
            // Worker result schemas additionally pass `require_all_properties` (OpenAI strict
            // mode, live gate 2026-08-27); the handoff envelope is lead-facing and does not.
            require_all_properties(strip_dollar_schema(
                serde_json::to_value(schema_for!(BuildResult)).expect("BuildResult schema"),
            )),
        ),
        (
            REVIEW_VERDICT,
            require_all_properties(strip_dollar_schema(
                serde_json::to_value(schema_for!(ReviewVerdict)).expect("ReviewVerdict schema"),
            )),
        ),
        (
            VERIFY_REPORT,
            require_all_properties(strip_dollar_schema(
                serde_json::to_value(schema_for!(VerifyReport)).expect("VerifyReport schema"),
            )),
        ),
        (
            HANDOFF_ENVELOPE,
            strip_dollar_schema(
                serde_json::to_value(schema_for!(HandoffEnvelope)).expect("HandoffEnvelope schema"),
            ),
        ),
    ]
}

fn checked_in(rel: &str) -> Value {
    let path = repo_path(rel);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err} — {REGENERATE}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("{} is not valid JSON: {err}", path.display()))
}

fn validator_for(rel: &str) -> jsonschema::Validator {
    let schema = checked_in(rel);
    jsonschema::validator_for(&schema).unwrap_or_else(|err| panic!("{rel} does not compile: {err}"))
}

fn jsonl(rel: &str) -> Vec<Value> {
    let path = repo_path(rel);
    let text =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|err| panic!("{rel}: bad JSONL line: {err}"))
        })
        .collect()
}

/// The `structured_output` Claude reports on the final `result` line of a transcript.
fn claude_structured_output(rel: &str) -> Value {
    jsonl(rel)
        .into_iter()
        .filter(|line| line["type"] == "result")
        .map(|mut line| line["structured_output"].take())
        .next_back()
        .unwrap_or_else(|| panic!("{rel} has no result line"))
}

/// The reviewer's final message: Codex reports it as the `text` of an `agent_message` item, and
/// the adapter parses that string as JSON before validating it.
fn codex_agent_message(rel: &str) -> Value {
    let text = jsonl(rel)
        .into_iter()
        .filter(|line| line["type"] == "item.completed" && line["item"]["type"] == "agent_message")
        .map(|line| {
            line["item"]["text"]
                .as_str()
                .expect("agent_message text is a string")
                .to_owned()
        })
        .next_back()
        .unwrap_or_else(|| panic!("{rel} has no agent_message item"));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("{rel}: agent_message is not a JSON document: {err}"))
}

/// The one-off generator (see the module comment). `#[ignore]`d: it writes into the repo.
#[test]
#[ignore = "generator — writes schemas/*.json; run with --ignored"]
fn gen_schemas() {
    for (rel, schema) in generated() {
        let path = repo_path(rel);
        fs::create_dir_all(path.parent().expect("schemas/ has a parent"))
            .unwrap_or_else(|err| panic!("create {}: {err}", path.display()));
        let mut text = serde_json::to_string_pretty(&schema).expect("pretty-print schema");
        text.push('\n');
        fs::write(&path, text).unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
    }
}

#[test]
fn checked_in_schemas_match_the_generated_ones() {
    for (rel, schema) in generated() {
        assert_eq!(
            checked_in(rel),
            schema,
            "{rel} has drifted from the type it is generated from — {REGENERATE}"
        );
    }
}

#[test]
fn checked_in_schemas_carry_no_dollar_schema_key() {
    for (rel, _) in generated() {
        let doc = checked_in(rel);
        assert!(
            doc.get("$schema").is_none(),
            "{rel} still carries $schema — claude --json-schema rejects that document (V7)"
        );
    }
}

#[test]
fn worker_output_schemas_are_closed_at_the_root() {
    for rel in [BUILD_RESULT, REVIEW_VERDICT, VERIFY_REPORT] {
        let doc = checked_in(rel);
        assert_eq!(doc["type"], "object", "{rel} must describe an object");
        assert_eq!(
            doc["additionalProperties"],
            Value::Bool(false),
            "{rel} must reject unknown keys at the root"
        );
        // OpenAI strict mode (live gate 2026-08-27): `required` must list EVERY property. This
        // is what catches a dropped `require_all_properties` in `generated()` — both sides of
        // the drift test move together, so only an independent assertion can see it.
        let mut required: Vec<&str> = doc["required"]
            .as_array()
            .unwrap_or_else(|| panic!("{rel} must carry a root `required` list"))
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let mut properties: Vec<&str> = doc["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{rel} must carry root `properties`"))
            .keys()
            .map(String::as_str)
            .collect();
        required.sort_unstable();
        properties.sort_unstable();
        assert_eq!(
            required, properties,
            "{rel}: `required` must list every property (OpenAI strict)"
        );
    }
}

#[test]
fn checked_in_schemas_are_valid_draft_2020_12() {
    for (rel, _) in generated() {
        let mut doc = checked_in(rel);
        doc.as_object_mut()
            .expect("a schema document is a JSON object")
            .insert("$schema".into(), DRAFT_2020_12.into());
        if let Err(err) = jsonschema::meta::validate(&doc) {
            panic!("{rel} is not a valid draft 2020-12 schema: {err}");
        }
    }
}

#[test]
fn strip_dollar_schema_removes_only_the_top_level_key() {
    let stripped = strip_dollar_schema(json!({
        "$schema": DRAFT_2020_12,
        "type": "object",
        "$defs": { "Severity": { "$schema": DRAFT_2020_12, "type": "string" } },
        "properties": { "severity": { "$ref": "#/$defs/Severity" } }
    }));
    assert!(stripped.get("$schema").is_none());
    assert_eq!(stripped["$defs"]["Severity"]["$schema"], DRAFT_2020_12);
    assert_eq!(
        stripped["properties"]["severity"]["$ref"],
        "#/$defs/Severity"
    );

    let untouched = json!({ "type": "object" });
    assert_eq!(strip_dollar_schema(untouched.clone()), untouched);

    let not_an_object = json!(["$schema"]);
    assert_eq!(strip_dollar_schema(not_an_object.clone()), not_an_object);
}

#[test]
fn build_result_schema_accepts_the_captured_builder_output() {
    let validator = validator_for(BUILD_RESULT);
    let good = claude_structured_output("fixtures/jsonl/claude/pass-1.jsonl");
    assert_eq!(good["status"], "succeeded");
    if let Err(err) = validator.validate(&good) {
        panic!("pass-1.jsonl structured_output must validate: {err}");
    }
    let parsed: BuildResult =
        serde_json::from_value(good).expect("the same document deserializes into BuildResult");
    assert_eq!(parsed.files_changed, ["src/adder.ts"]);
}

#[test]
fn build_result_schema_rejects_the_captured_invalid_output() {
    let validator = validator_for(BUILD_RESULT);
    let bad = claude_structured_output("fixtures/jsonl/claude/invalid-1.jsonl");
    assert!(
        !validator.is_valid(&bad),
        "invalid-1.jsonl structured_output {bad} must not validate"
    );
    assert!(serde_json::from_value::<BuildResult>(bad).is_err());
}

#[test]
fn review_verdict_schema_accepts_every_captured_review() {
    let validator = validator_for(REVIEW_VERDICT);
    // Every reviewer transcript a fake can replay, not just the two the loop reads first:
    // `fixtures/jsonl/README.md` § Invariants requires all of them to stay valid.
    for (rel, verdict) in [
        ("fixtures/jsonl/codex/review-pass-1.jsonl", "PASS"),
        ("fixtures/jsonl/codex/review-pass-2.jsonl", "PASS"),
        ("fixtures/jsonl/codex/review-fail-1.jsonl", "FAIL"),
        ("fixtures/jsonl/codex/split_line-1.jsonl", "PASS"),
    ] {
        let message = codex_agent_message(rel);
        assert_eq!(
            message["verdict"], verdict,
            "{rel} carries the wrong verdict"
        );
        if let Err(err) = validator.validate(&message) {
            panic!("{rel} agent_message must validate: {err}");
        }
        let parsed: ReviewVerdict = serde_json::from_value(message)
            .unwrap_or_else(|err| panic!("{rel} deserializes into ReviewVerdict: {err}"));
        assert_eq!(parsed.diff_hash.len(), 64, "{rel} echoes a sha256 (Rev 25)");
        if verdict == "FAIL" {
            assert!(
                parsed
                    .findings
                    .iter()
                    .any(|finding| finding.severity == Severity::Blocking),
                "{rel}: a FAIL must say what blocks"
            );
        }
    }
}

#[test]
fn verify_report_schema_accepts_a_minimal_pass_and_rejects_drift() {
    let validator = validator_for(VERIFY_REPORT);
    let good = json!({
        "status": "pass",
        "summary": "cargo test: 12 passed",
        "commands": ["cargo test"],
        "failures": [],
        "diffHash": A_DIFF_HASH
    });
    if let Err(err) = validator.validate(&good) {
        panic!("a minimal pass report must validate: {err}");
    }
    let parsed: VerifyReport =
        serde_json::from_value(good).expect("the same document deserializes into VerifyReport");
    assert_eq!(parsed.commands, ["cargo test"]);

    // Closed at the root (deny_unknown_fields + additionalProperties:false).
    assert!(
        !validator.is_valid(&json!({
            "status": "pass", "summary": "ok", "commands": [], "failures": [],
            "diffHash": A_DIFF_HASH, "note": "smuggled"
        })),
        "an unknown key must not validate"
    );
    assert!(
        serde_json::from_value::<VerifyReport>(json!({
            "status": "pass", "summary": "ok", "commands": [], "failures": [],
            "diffHash": A_DIFF_HASH, "note": "smuggled"
        }))
        .is_err(),
        "serde must refuse the unknown key too"
    );

    // The status set is closed and kebab-case; the hash echo is required and hex-bound.
    assert!(!validator.is_valid(&json!({
        "status": "PASS", "summary": "ok", "commands": [], "failures": [], "diffHash": A_DIFF_HASH
    })));
    assert!(validator.is_valid(&json!({
        "status": "nothing-to-run", "summary": "no build or test command found",
        "commands": [], "failures": [], "diffHash": A_DIFF_HASH
    })));
    assert!(!validator.is_valid(&json!({
        "status": "pass", "summary": "ok", "commands": [], "failures": [], "diffHash": "beef"
    })));
    assert!(!validator.is_valid(&json!({
        "status": "fail", "summary": "x", "commands": [],
        "failures": ["y".repeat(1001)], "diffHash": A_DIFF_HASH
    })));
}

/// C1 (T68): the argv-selected codex fixtures are schema-bound like every other worker
/// document — the builder's agent_message validates as a build-result, the verifier's as a
/// verify-report. Without this, an edit to either fixture only surfaces as an opaque
/// invalid_output deep inside the e2e.
#[test]
fn codex_build_and_verify_fixtures_validate_against_their_schemas() {
    let build = codex_agent_message("fixtures/jsonl/codex/build-pass-1.jsonl");
    let build_validator = validator_for(BUILD_RESULT);
    if let Err(err) = build_validator.validate(&build) {
        panic!("build-pass-1's agent_message must be a valid build-result: {err}");
    }
    let parsed: BuildResult = serde_json::from_value(build).expect("deserializes into BuildResult");
    assert_eq!(parsed.files_changed, ["src/adder.ts"]);
    assert!(
        parsed.summary.contains("workspace-write"),
        "the summary's workspace-write phrase is LOAD-BEARING: quoted into the reviewer prompt \
         it regression-guards the chokepoint against substring-scanning untrusted text (T68)"
    );

    let verify = codex_agent_message("fixtures/jsonl/codex/verify-pass-1.jsonl");
    let verify_validator = validator_for(VERIFY_REPORT);
    if let Err(err) = verify_validator.validate(&verify) {
        panic!("verify-pass-1's agent_message must be a valid verify-report: {err}");
    }
}

#[test]
fn review_verdict_schema_rejects_a_lowercase_verdict() {
    let validator = validator_for(REVIEW_VERDICT);
    assert!(
        !validator.is_valid(&json!({
            "verdict": "pass", "findings": [], "diffHash": A_DIFF_HASH
        })),
        "the verdict casing is closed — the fixtures say PASS/FAIL"
    );
}

/// Rev 25: a verdict that does not echo the frozen diff's hash can never open an integrate gate,
/// and the schema is the first thing that says so.
#[test]
fn review_verdict_schema_requires_a_hex_diff_hash() {
    let validator = validator_for(REVIEW_VERDICT);
    assert!(
        validator.is_valid(&json!({
            "verdict": "PASS", "findings": [], "diffHash": A_DIFF_HASH
        })),
        "a 64-hex diffHash is what the reviewer is asked for"
    );
    for missing_or_malformed in [
        json!({ "verdict": "PASS", "findings": [] }),
        json!({ "verdict": "PASS", "findings": [], "diffHash": "" }),
        json!({ "verdict": "PASS", "findings": [], "diffHash": "not-a-hash" }),
        // uppercase hex, and one character short: both are drift, not a hash we handed out
        json!({ "verdict": "PASS", "findings": [], "diffHash": A_DIFF_HASH.to_uppercase() }),
        json!({ "verdict": "PASS", "findings": [], "diffHash": &A_DIFF_HASH[..63] }),
    ] {
        assert!(
            !validator.is_valid(&missing_or_malformed),
            "{missing_or_malformed} must not validate"
        );
    }
}

#[test]
fn review_verdict_schema_rejects_an_unbounded_finding() {
    let validator = validator_for(REVIEW_VERDICT);
    let overlong = json!({
        "verdict": "FAIL",
        "findings": [{ "severity": "blocking", "problem": "x".repeat(4001) }],
        "diffHash": A_DIFF_HASH
    });
    assert!(
        !validator.is_valid(&overlong),
        "every string in review-verdict.json is maxLength-bounded"
    );
    // Every finding key is required since the OpenAI-strict pass (live gate, 2026-08-27);
    // optionality is expressed as explicit nulls.
    let at_the_bound = json!({
        "verdict": "FAIL",
        "findings": [{
            "severity": "blocking", "problem": "x".repeat(4000),
            "file": null, "line": null, "fix": null
        }],
        "diffHash": A_DIFF_HASH
    });
    assert!(validator.is_valid(&at_the_bound), "4 000 chars is allowed");
    let missing_keys = json!({
        "verdict": "FAIL",
        "findings": [{ "severity": "blocking", "problem": "x" }],
        "diffHash": A_DIFF_HASH
    });
    assert!(
        !validator.is_valid(&missing_keys),
        "OpenAI strict mode: every finding key must be present (null for absent)"
    );
}
