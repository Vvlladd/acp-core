//! T17: `src/providers/codex.rs` — argv snapshot, `parse_line` over the recorded transcripts and
//! `extract_result` (`reports/03-design.md` § Test Strategy, row `providers/codex.rs`).
//!
//! Every transcript is **read from `fixtures/jsonl/codex/` at runtime**, never pasted in here, so a
//! fixture edit that changes a shape the parser depends on fails these tests instead of silently
//! diverging from what the fake CLI replays.
//!
//! The adapter is pure — it opens no file and spawns nothing — so the argv tests use fixed absolute
//! paths (the same `/tmp/acp-fixture-*` placeholders the fixtures use) rather than temp dirs, and
//! the resulting argv is asserted as a literal snapshot: its order is load-bearing, and a snapshot
//! is the only assertion that catches a reordering.
//!
//! `preflight` is deliberately not exercised here: both of its branches depend on process-global
//! `PATH`, and the design assigns that coverage to the loop tests, which reproduce `missing_bin` by
//! prepending an empty directory to `PATH` (`fixtures/jsonl/README.md` § "Scenario → fixture map").

use std::fs;
use std::path::{Path, PathBuf};

use agent_control_plane::core::types::{
    ErrorCode, ProviderName, RoleName, RoleSpec, SandboxMode, SchemaName, TokenUsage,
};
use agent_control_plane::providers::codex::CodexAdapter;
use agent_control_plane::providers::{
    base_env, NormalizedEvent, ProviderAdapter, RawResult, ResultCtx, SandboxSpec, SpawnPlan,
    SpawnRequest,
};
use serde_json::{json, Value};

const MODEL: &str = "gpt-5.5";
const PROMPT: &str = "Review the frozen diff at /tmp/acp-fixture-state/diffs/att-0001.patch.";
const ROLE_PROMPT: &str = "Review the frozen diff. Output only the JSON verdict.";

/// The builder worktree a reviewer runs in — Codex never receives `-C`, so this is the child's cwd.
const CWD: &str = "/tmp/acp-fixture-worktree";
const ATTEMPT_DIR: &str = "/tmp/acp-fixture-state/attempts/att-0001";
const STATE_DIR: &str = "/tmp/acp-fixture-state";
const OUTPUT_SCHEMA: &str = "/tmp/acp-fixture-state/attempts/att-0001/output-schema.json";
const LAST_MESSAGE: &str = "/tmp/acp-fixture-state/attempts/att-0001/last-message.txt";

/// `review-pass-1.jsonl`'s `thread_id`, and the one `turn-failed-1.jsonl` reports before failing.
const PASS_THREAD_ID: &str = "01a02001-0001-7001-8001-000000000001";
const FAILED_THREAD_ID: &str = "01a02004-0004-7004-8004-000000000004";

/// Every checked-in Codex transcript. `fixtures/jsonl/README.md` § Invariants: each starts with a
/// `thread.started` line.
const TRANSCRIPTS: [&str; 7] = [
    "review-pass-1.jsonl",
    "review-pass-2.jsonl",
    "review-fail-1.jsonl",
    "turn-failed-1.jsonl",
    "split_line-1.jsonl",
    "build-pass-1.jsonl",
    "verify-pass-1.jsonl",
];

// ---------------------------------------------------------------------------
// Fixtures and request construction
// ---------------------------------------------------------------------------

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn fixture(name: &str) -> String {
    let path = repo_path("fixtures/jsonl/codex").join(name);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn parse_all(transcript: &str) -> Vec<NormalizedEvent> {
    transcript
        .lines()
        .flat_map(|line| CodexAdapter.parse_line(line))
        .collect()
}

fn events(name: &str) -> Vec<NormalizedEvent> {
    parse_all(&fixture(name))
}

/// The last `agent_message.text` of a transcript — exactly what the real CLI writes to `-o`, and
/// therefore what the supervisor hands back as [`ResultCtx::last_message`].
fn last_agent_message(transcript: &str) -> String {
    transcript
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["item"]["type"] == "agent_message")
        .filter_map(|event| event["item"]["text"].as_str().map(str::to_string))
        .next_back()
        .expect("fixture carries an agent_message")
}

/// The reviewer as `roles/roles.json` declares it (design § Security).
fn reviewer() -> RoleSpec {
    RoleSpec {
        role: RoleName::Reviewer,
        provider: ProviderName::Codex,
        models: vec![MODEL.to_string()],
        default_model: MODEL.to_string(),
        writes: false,
        prompt_file: Some("prompts/reviewer-worker.md".to_string()),
        prompt_sha256: None,
        description: None,
        tools: None,
        sandbox_mode: Some(SandboxMode::ReadOnly),
        max_turns: 12,
        spawn_budget_usd: 2.0,
        result_schema: SchemaName::ReviewVerdict,
        allowed_delegations: Vec::new(),
    }
}

/// The real `$schema`-stripped `review-verdict` document (V7) — the artifact the adapter declares
/// in `write_files`.
fn schema_document() -> Value {
    let path = repo_path("schemas/review-verdict.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).expect("review-verdict.json is JSON")
}

fn request<'a>(
    role: &'a RoleSpec,
    schema: &'a Value,
    role_prompt: &'a str,
    session_id: Option<&'a str>,
) -> SpawnRequest<'a> {
    SpawnRequest {
        role,
        model: MODEL,
        prompt: PROMPT,
        role_prompt,
        cwd: Path::new(CWD),
        attempt_dir: Path::new(ATTEMPT_DIR),
        state_dir: Path::new(STATE_DIR),
        lead_run_id: None,
        schema: ("review-verdict", schema),
        max_turns: role.max_turns,
        spawn_budget_usd: role.spawn_budget_usd,
        // A reviewer never writes, so there is no worktree to hand a sandbox spec for.
        sandbox: None,
        session_id,
        effort: None,
    }
}

fn fresh_plan(role_prompt: &str) -> SpawnPlan {
    let role = reviewer();
    let schema = schema_document();
    CodexAdapter.build_fresh(&request(&role, &schema, role_prompt, None))
}

/// The same request with a `SandboxSpec` attached — what the loop builds for a codex writer or
/// verifier once `sandboxes_writes(Codex)` flips (C1).
fn sandboxed_request<'a>(
    role: &'a RoleSpec,
    schema: &'a Value,
    session_id: Option<&'a str>,
) -> SpawnRequest<'a> {
    SpawnRequest {
        sandbox: Some(SandboxSpec {
            worktree: Path::new(CWD),
        }),
        ..request(role, schema, ROLE_PROMPT, session_id)
    }
}

fn resume_plan(session_id: &str) -> SpawnPlan {
    let role = reviewer();
    let schema = schema_document();
    CodexAdapter.build_resume(&request(&role, &schema, ROLE_PROMPT, Some(session_id)))
}

fn strs(argv: &[String]) -> Vec<&str> {
    argv.iter().map(String::as_str).collect()
}

fn result_of(events: &[NormalizedEvent], last_message: Option<&str>) -> RawResult {
    CodexAdapter.extract_result(&ResultCtx {
        events,
        exit_code: Some(0),
        signal: None,
        last_message,
        stderr_head: None,
    })
}

// ---------------------------------------------------------------------------
// argv
// ---------------------------------------------------------------------------

#[test]
fn fresh_argv_matches_the_design_exactly() {
    let plan = fresh_plan(ROLE_PROMPT);

    assert_eq!(
        plan.file,
        PathBuf::from("codex"),
        "bare name, resolved on PATH"
    );
    assert_eq!(plan.cwd, Path::new(CWD), "cwd is the worktree, never `-C`");
    assert_eq!(
        plan.env,
        base_env(),
        "the adapter adds nothing to the worker env"
    );
    assert_eq!(
        strs(&plan.argv),
        vec![
            "exec",
            "--json",
            "--strict-config",
            "--ignore-user-config",
            "-m",
            MODEL,
            "-s",
            "read-only",
            "-c",
            r#"approval_policy="never""#,
            "-c",
            r#"sandbox_mode="read-only""#,
            "-c",
            "mcp_servers={}",
            "-c",
            r#"model_reasoning_effort="medium""#,
            "-c",
            r#"developer_instructions="Review the frozen diff. Output only the JSON verdict.""#,
            "--output-schema",
            OUTPUT_SCHEMA,
            "-o",
            LAST_MESSAGE,
            PROMPT,
        ],
    );
}

#[test]
fn resume_argv_matches_the_design_exactly() {
    let plan = resume_plan(PASS_THREAD_ID);

    assert_eq!(
        plan.cwd,
        Path::new(CWD),
        "a thread resumes from its own cwd (C3)"
    );
    assert_eq!(
        strs(&plan.argv),
        vec![
            "exec",
            "resume",
            "--json",
            "--strict-config",
            "--ignore-user-config",
            "-m",
            MODEL,
            "-c",
            r#"approval_policy="never""#,
            "-c",
            r#"sandbox_mode="read-only""#,
            "-c",
            "mcp_servers={}",
            "-c",
            r#"developer_instructions="Review the frozen diff. Output only the JSON verdict.""#,
            "--output-schema",
            OUTPUT_SCHEMA,
            "-o",
            LAST_MESSAGE,
            PASS_THREAD_ID,
            PROMPT,
        ],
    );
}

#[test]
fn resume_argv_carries_no_sandbox_cd_or_prompt_flag() {
    let argv = resume_plan(PASS_THREAD_ID).argv;
    let tokens = strs(&argv);

    // `codex exec resume` rejects all three (`reports/02-exploration.md` § Codex).
    for denied in ["-s", "--sandbox", "-C", "--cd", "-p", "--profile"] {
        assert!(
            !tokens.contains(&denied),
            "resume argv must not contain {denied}: {tokens:?}"
        );
    }
    // The sandbox still travels — as config, which resume does accept.
    for required in [
        r#"approval_policy="never""#,
        r#"sandbox_mode="read-only""#,
        "mcp_servers={}",
    ] {
        assert!(
            tokens.contains(&required),
            "resume argv must contain -c {required}: {tokens:?}"
        );
    }
    assert!(
        tokens
            .iter()
            .any(|token| token.starts_with(r#"developer_instructions=""#)),
        "resume repeats the role body, quoted: {tokens:?}"
    );
}

#[test]
fn the_prompt_is_the_trailing_positional_on_both_paths() {
    assert_eq!(
        fresh_plan(ROLE_PROMPT).argv.last().map(String::as_str),
        Some(PROMPT)
    );

    // Resume takes `<threadId> <PROMPT>`, in that order.
    let resume = resume_plan(PASS_THREAD_ID).argv;
    let tail = strs(&resume[resume.len() - 2..]);
    assert_eq!(tail, vec![PASS_THREAD_ID, PROMPT]);
}

#[test]
fn both_plans_write_exactly_one_output_schema_file() {
    let schema = schema_document();
    for (label, plan) in [
        ("fresh", fresh_plan(ROLE_PROMPT)),
        ("resume", resume_plan(PASS_THREAD_ID)),
    ] {
        assert_eq!(plan.write_files.len(), 1, "{label}: one file, the schema");
        let (path, body) = &plan.write_files[0];
        assert_eq!(path, Path::new(OUTPUT_SCHEMA), "{label}");
        assert!(
            strs(&plan.argv).contains(&OUTPUT_SCHEMA),
            "{label}: the written file is the one `--output-schema` names"
        );

        let written: Value = serde_json::from_str(body).expect("write_files body is JSON");
        assert_eq!(
            written, schema,
            "{label}: the document is passed through verbatim"
        );
        assert!(
            written.get("$schema").is_none(),
            "{label}: the post-processed schema carries no $schema key (V7)"
        );
    }
}

#[test]
fn developer_instructions_round_trips_a_prompt_full_of_quotes_and_newlines() {
    // A role body is a markdown file: it has newlines, quotes and backslashes, and none of them may
    // break out of the single argv element `-c developer_instructions=…` occupies.
    const TRICKY: &str = "Line one\n\"quoted\" and a backslash \\ and a tab\there\n";
    let argv = fresh_plan(TRICKY).argv;

    let assignment = argv
        .iter()
        .find(|token| token.starts_with("developer_instructions="))
        .expect("developer_instructions is in the argv");
    let literal = assignment
        .strip_prefix("developer_instructions=")
        .expect("prefix checked above");
    assert!(
        !literal.contains('\n'),
        "the quoted body must stay on one argv element: {literal:?}"
    );
    let decoded: String = serde_json::from_str(literal).expect("a JSON string literal");
    assert_eq!(decoded, TRICKY, "the body survives quoting unchanged");
}

// ---------------------------------------------------------------------------
// parse_line
// ---------------------------------------------------------------------------

#[test]
fn thread_started_yields_the_one_session_event() {
    let sessions: Vec<String> = events("review-pass-1.jsonl")
        .into_iter()
        .filter_map(|event| match event {
            NormalizedEvent::Session { session_id } => Some(session_id),
            _ => None,
        })
        .collect();
    assert_eq!(sessions, vec![PASS_THREAD_ID.to_string()]);
}

#[test]
fn turn_completed_usage_carries_all_four_token_counts() {
    let usage: Vec<NormalizedEvent> = events("review-pass-1.jsonl")
        .into_iter()
        .filter(|event| matches!(event, NormalizedEvent::Usage { .. }))
        .collect();

    // The four counts on `review-pass-1.jsonl`'s last line, verbatim. Codex reports no dollar
    // figure, so cost stays `None` and is computed later from the rate table.
    assert_eq!(
        usage,
        vec![NormalizedEvent::Usage {
            tokens: TokenUsage {
                input: 18432,
                cached_input: 16128,
                output: 142,
                reasoning: Some(64),
            },
            cost_usd: None,
        }]
    );
}

#[test]
fn the_deprecation_error_item_is_a_phase_not_a_failure() {
    let transcript = fixture("review-pass-1.jsonl");
    let deprecation = transcript.lines().nth(1).expect("fixture line 2");
    let message = serde_json::from_str::<Value>(deprecation).expect("line 2 is JSON")["item"]
        ["message"]
        .as_str()
        .expect("fixture drift: line 2 is no longer the deprecation `error` item")
        .to_string();

    assert_eq!(
        CodexAdapter.parse_line(deprecation),
        vec![NormalizedEvent::Phase {
            phase: "error".to_string(),
            note: Some(message),
        }],
        "an `item.completed` whose item.type is `error` is a config warning, not a failure"
    );
}

#[test]
fn a_passing_transcript_yields_no_final_and_no_error_event() {
    // The strong form of the rule above: the whole PASS transcript — deprecation item included —
    // contains nothing the supervisor could read as a failure.
    for name in [
        "review-pass-1.jsonl",
        "review-pass-2.jsonl",
        "review-fail-1.jsonl",
    ] {
        for event in events(name) {
            assert!(
                !matches!(
                    event,
                    NormalizedEvent::Final { .. } | NormalizedEvent::Error { .. }
                ),
                "{name} produced {event:?}; a completed turn never fails, whatever the verdict"
            );
        }
    }
}

#[test]
fn turn_failed_yields_a_failed_final() {
    let transcript = fixture("turn-failed-1.jsonl");
    let message = transcript
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|event| event["type"] == "turn.failed")
        .expect("fixture ends with turn.failed")["error"]["message"]
        .as_str()
        .expect("turn.failed carries error.message")
        .to_string();

    let finals: Vec<NormalizedEvent> = parse_all(&transcript)
        .into_iter()
        .filter(|event| matches!(event, NormalizedEvent::Final { .. }))
        .collect();
    assert_eq!(
        finals,
        vec![NormalizedEvent::Final {
            ok: false,
            text: Some(message),
            structured: None,
            stop_reason: Some("turn.failed".to_string()),
            cost_usd: None,
            tokens: None,
            error_code: Some(ErrorCode::ProviderError),
        }]
    );
}

#[test]
fn every_transcript_starts_with_a_session_and_emits_bounded_normalized_events() {
    for name in TRANSCRIPTS {
        let transcript = fixture(name);
        for (index, line) in transcript.lines().enumerate() {
            let parsed = CodexAdapter.parse_line(line);
            let raw: Value = serde_json::from_str(line).unwrap();
            let count = if raw["type"]=="turn.completed" || (raw["type"]=="item.completed"
                && raw["item"]["type"]=="agent_message") { 2 } else { 1 };
            assert_eq!(parsed.len(), count, "{name} line {}: {line}", index + 1);
            if index == 0 {
                assert_eq!(
                    parsed[0],
                    NormalizedEvent::Session {
                        session_id: serde_json::from_str::<Value>(line).expect("JSON")["thread_id"]
                            .as_str()
                            .expect("line 1 carries a thread_id")
                            .to_string(),
                    },
                    "{name}: line 1 is always thread.started"
                );
            }
        }
    }
}

#[test]
fn blank_and_malformed_lines_parse_to_nothing() {
    // Worker output is data, never instructions: nothing here may panic or invent an event.
    for line in [
        "",
        "   ",
        "not json at all",
        "{",
        "[]",
        "null",
        r#"{"no_type":1}"#,
        r#"{"type":42}"#,
        r#"{"type":"thread.started"}"#,
        r#"{"type":"item.completed"}"#,
        r#"{"type":"session.configured"}"#,
    ] {
        assert!(
            CodexAdapter.parse_line(line).is_empty(),
            "expected no event from {line:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// extract_result
// ---------------------------------------------------------------------------

#[test]
fn a_completed_turn_takes_its_result_from_the_output_file() {
    let transcript = fixture("review-pass-1.jsonl");
    let last_message = last_agent_message(&transcript);
    let result = result_of(&parse_all(&transcript), Some(&last_message));

    assert!(result.ok, "turn.completed seen and no turn.failed");
    assert_eq!(result.session_id.as_deref(), Some(PASS_THREAD_ID));
    assert_eq!(result.text.as_deref(), Some(last_message.as_str()));
    assert_eq!(
        result.structured,
        // Rev 25: every reviewer fixture echoes the frozen diff's hash
        // (`fixtures/jsonl/README.md` § Placeholder).
        Some(json!({
            "verdict": "PASS",
            "findings": [],
            "diffHash": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
        }))
    );
    assert_eq!(result.error_code, None);
}

#[test]
fn a_completed_turn_with_no_output_file_reports_nothing_structured() {
    // Codex exited 0 having finished its turn but never wrote `-o`. The adapter reports success
    // with no document; the supervisor's schema check is what turns that into `invalid_output`.
    let result = result_of(&events("review-pass-1.jsonl"), None);

    assert!(result.ok);
    assert_eq!(result.session_id.as_deref(), Some(PASS_THREAD_ID));
    assert_eq!(result.text, None);
    assert_eq!(result.structured, None);
}

#[test]
fn a_failed_turn_still_reports_its_thread_id() {
    // 17b: the thread exists, so the attempt is resumable even though it failed.
    let result = result_of(&events("turn-failed-1.jsonl"), None);

    assert!(!result.ok);
    assert_eq!(result.session_id.as_deref(), Some(FAILED_THREAD_ID));
    assert_eq!(result.error_code, Some(ErrorCode::ProviderError));
    assert!(
        result.text.is_some(),
        "the turn.failed message is carried through"
    );
}

#[test]
fn a_stream_that_stops_after_the_thread_id_is_not_a_success() {
    // The `hang` shape: `thread.started` and then nothing. A session exists (17b), but no turn ever
    // completed, so the adapter must not report success.
    let first_line = fixture("review-pass-1.jsonl")
        .lines()
        .next()
        .expect("fixture line 1")
        .to_string();
    let result = result_of(&CodexAdapter.parse_line(&first_line), None);

    assert!(!result.ok);
    assert_eq!(result.session_id.as_deref(), Some(PASS_THREAD_ID));
    assert_eq!(
        result.error_code, None,
        "classifying this is the caller's job"
    );
}

#[test]
fn extract_result_without_a_session_reports_no_session() {
    // The `no_session` scenario: the process died with zero stdout lines, so no thread id exists.
    // Naming that `no_session` is the supervisor's job — the adapter only reports the absence, and
    // above all does not panic looking for a session that was never there.
    let empty = result_of(&[], None);
    assert_eq!(empty, RawResult::default());
    assert!(!empty.ok);
    assert_eq!(empty.session_id, None);

    // Same verdict with noise on the stream and a `-o` body on disk: no thread.started, no session.
    let noise = [NormalizedEvent::Phase {
        phase: "turn.started".to_string(),
        note: None,
    }];
    let stray = result_of(&noise, Some(r#"{"verdict":"PASS","findings":[]}"#));
    assert!(!stray.ok);
    assert_eq!(stray.session_id, None);
}

// ---------------------------------------------------------------------------
// C1: the workspace-write shapes (T66) — measured plan, research § 2 items 1-6
// ---------------------------------------------------------------------------

#[test]
fn sandboxed_fresh_argv_matches_the_measured_plan_exactly() {
    let role = reviewer();
    let schema = schema_document();
    let plan = CodexAdapter.build_fresh(&sandboxed_request(&role, &schema, None));
    assert_eq!(
        plan.cwd,
        Path::new(CWD),
        "cwd pins the writable root, never `-C`"
    );
    assert_eq!(
        strs(&plan.argv),
        vec![
            "exec",
            "--json",
            "--strict-config",
            "--ignore-user-config",
            "-m",
            MODEL,
            "-s",
            "workspace-write",
            "-c",
            r#"approval_policy="never""#,
            "-c",
            r#"sandbox_mode="workspace-write""#,
            "-c",
            "sandbox_workspace_write.exclude_slash_tmp=true",
            "-c",
            "sandbox_workspace_write.exclude_tmpdir_env_var=true",
            "-c",
            "sandbox_workspace_write.writable_roots=[]",
            "-c",
            "mcp_servers={}",
            "-c",
            r#"model_reasoning_effort="medium""#,
            "-c",
            r#"developer_instructions="Review the frozen diff. Output only the JSON verdict.""#,
            "--output-schema",
            OUTPUT_SCHEMA,
            "-o",
            LAST_MESSAGE,
            PROMPT,
        ],
    );
}

#[test]
fn sandboxed_resume_argv_matches_the_measured_plan_exactly() {
    let role = reviewer();
    let schema = schema_document();
    let plan = CodexAdapter.build_resume(&sandboxed_request(&role, &schema, Some(PASS_THREAD_ID)));
    // The one path where `-s` must be ABSENT and the thread id must sit between the flags and
    // the trailing prompt — order is load-bearing, so the pin is the full vector.
    assert_eq!(
        strs(&plan.argv),
        vec![
            "exec",
            "resume",
            "--json",
            "--strict-config",
            "--ignore-user-config",
            "-m",
            MODEL,
            "-c",
            r#"approval_policy="never""#,
            "-c",
            r#"sandbox_mode="workspace-write""#,
            "-c",
            "sandbox_workspace_write.exclude_slash_tmp=true",
            "-c",
            "sandbox_workspace_write.exclude_tmpdir_env_var=true",
            "-c",
            "sandbox_workspace_write.writable_roots=[]",
            "-c",
            "mcp_servers={}",
            "-c",
            r#"developer_instructions="Review the frozen diff. Output only the JSON verdict.""#,
            "--output-schema",
            OUTPUT_SCHEMA,
            "-o",
            LAST_MESSAGE,
            PASS_THREAD_ID,
            PROMPT,
        ],
    );
}

#[test]
fn lead_profile_is_closed_on_fresh_and_resume_and_binds_its_owner() {
    use agent_control_plane::core::supervisor::{assert_safe_argv, ArgvCtx};
    use agent_control_plane::core::types::RunId;
    use agent_control_plane::core::team::Effort;
    let mut role = reviewer();
    role.role = RoleName::Lead;
    role.result_schema = SchemaName::FreeText;
    let schema = json!({});
    let run = RunId::new_v4();
    for session in [None, Some(PASS_THREAD_ID)] {
        let mut req = request(&role, &schema, ROLE_PROMPT, session);
        req.lead_run_id = Some(run);
        req.effort = Some(Effort::High);
        let mut plan = if session.is_some() { CodexAdapter.build_resume(&req) }
            else { CodexAdapter.build_fresh(&req) };
        plan.file = env!("CARGO_BIN_EXE_fake-codex").into();
        let ctx = ArgvCtx { role: RoleName::Lead, lead_run_id: Some(run), worktree: req.cwd,
            provider: ProviderName::Codex, sandboxed: false, state_dir: req.state_dir,
            prompt_index: Some(plan.argv.len()-1) };
        assert_safe_argv(plan.clone(), &ctx).expect("the complete restricted lead profile");
        assert_eq!(plan.required_version.as_deref(), Some("codex-cli 0.153.0"));
        assert!(!plan.argv.iter().any(|s| s == "--output-schema"));
        let catalog: Value = serde_json::from_str(&plan.write_files[0].1).unwrap();
        assert!(catalog["models"][0]["apply_patch_tool_type"].is_null());
        assert_eq!(catalog["models"][0]["shell_type"], "disabled");
        assert!(plan.argv.iter().any(|s| s == "model_reasoning_effort=\"high\""));
        let config = plan.argv.iter().find(|s| s.starts_with("mcp_servers=")).unwrap();
        assert!(config.contains("required=true"));
        assert!(config.contains("default_tools_approval_mode=\"prompt\""));
        assert_eq!(config.matches("approval_mode=\"approve\"").count(), 9);
        assert!(config.contains(&run.to_string()));
        for mutation in 0..7 {
            let mut bad = plan.clone();
            match mutation {
                0 => bad.required_version = None,
                1 => bad.argv.iter_mut().filter(|s| s.starts_with("features.shell_tool=")).for_each(|s| *s="features.shell_tool=true".into()),
                2 => bad.write_files[0].1 = bad.write_files[0].1.replace("\"disabled\"", "\"shell_command\""),
                3 => bad.argv.iter_mut().filter(|s| s.starts_with("mcp_servers=")).for_each(|s| *s=s.replace("required=true", "required=false")),
                4 => bad.argv.insert(2, "--enable=shell_tool".into()),
                5 => bad.write_files.push((Path::new(STATE_DIR).join("other.json"), "{}".into())),
                _ => bad.cwd = "/tmp/another-repo".into(),
            }
            let changed = ArgvCtx { prompt_index: Some(bad.argv.len()-1), ..ctx };
            assert!(assert_safe_argv(bad, &changed).is_err(), "mutation {mutation} was accepted");
        }
        let foreign = ArgvCtx { lead_run_id: Some(RunId::new_v4()), ..ctx };
        assert!(assert_safe_argv(plan, &foreign).is_err());
    }
}

#[test]
fn codex_assistant_messages_emit_once_when_complete_and_are_utf8_bounded() {
    let text = "é".repeat(4000);
    let started = json!({"type":"item.started", "item":{"type":"agent_message", "text":text}});
    assert!(!CodexAdapter.parse_line(&started.to_string()).iter()
        .any(|e| matches!(e, NormalizedEvent::Message { .. })));
    let completed = json!({"type":"item.completed", "item":{"type":"agent_message", "text":text}});
    let parsed = CodexAdapter.parse_line(&completed.to_string());
    let messages: Vec<_> = parsed.iter().filter_map(|e| match e {
        NormalizedEvent::Message { text, .. } => Some(text), _ => None }).collect();
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().all(|text| text.len() <= 4096));
    assert_eq!(messages.iter().map(|text| text.as_str()).collect::<String>(), text);
}
