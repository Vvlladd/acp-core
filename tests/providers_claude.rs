//! T15: `providers/claude.rs` — argv snapshots, stream parsing, result extraction
//! (`reports/03-design.md` § Test Strategy, row `providers/claude.rs`).
//!
//! Two halves, both token-free:
//!
//! * **argv**, asserted structurally rather than as one opaque string, because each property is a
//!   separate safety claim: the prompt sits immediately after `-p` so no variadic flag can swallow
//!   it, a writing role always carries the sandbox `--settings` (V4), the inline `--agents` role
//!   carries the prompt body verbatim (V3), the `--json-schema` document has no top-level
//!   `$schema` (V7), no denied flag appears, and nothing positional follows the variadics.
//! * **the stream**, replayed from the captured fixtures under `fixtures/jsonl/claude/`. They are
//!   read from disk (not `include_str!`) so a fixture edit is caught by the next test run rather
//!   than by the next rebuild.

use std::path::{Path, PathBuf};

use agent_control_plane::core::types::{
    ErrorCode, ProviderName, RoleName, RoleSpec, RunId, SandboxMode, SchemaName,
};
use agent_control_plane::providers::claude::ClaudeAdapter;
use agent_control_plane::providers::{
    NormalizedEvent, ProviderAdapter, ResultCtx, SandboxSpec, SpawnRequest,
};
use serde_json::Value;

mod common;

/// `assert_safe_argv`'s ceiling (design, § Exact argv: "argv + env asserted ≤ `MAX_ARGV_BYTES`").
/// Duplicated rather than imported: `core::policy` is a separate task, and this test must fail if
/// the adapter ever grows past the limit regardless of what the policy module ends up naming it.
const MAX_ARGV_BYTES: usize = 200_000;

/// The design's prompt-body ceiling (`MAX_PROMPT_BYTES`), used for the worst-case argv size test.
const MAX_PROMPT_BYTES: usize = 100_000;

const SONNET: &str = "claude-sonnet-4-5";
const OPUS: &str = "claude-opus-4-1";

const SESSION_ID: &str = "aaaaaaaa-1111-4a11-8a11-aaaaaaaaaaaa";

const TOOLS: [&str; 6] = ["Bash", "Read", "Edit", "Write", "Glob", "Grep"];
const LEAD_TOOLS: [&str; 9] = [
    "mcp__acp__delegate",
    "mcp__acp__submit_plan",
    "mcp__acp__audit_existing",
    "mcp__acp__send_message",
    "mcp__acp__await_result",
    "mcp__acp__get_status",
    "mcp__acp__cancel",
    "mcp__acp__request_human_gate",
    "mcp__acp__resolve_gate",
];

/// Flags that must never reach a worker (`core::policy::DENIED_ARGV`). Spot-checked here — T21
/// asserts the full list against `assert_safe_argv`, which is where the enforcement lives.
const DENIED_ARGV_SPOT_CHECK: [&str; 4] = [
    "--plugin-dir",
    "--dangerously-skip-permissions",
    "--add-dir",
    "-C",
];

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// Owns everything a [`SpawnRequest`] borrows, so a test can hand out requests that differ only in
/// model and session id.
struct Fixture {
    role: RoleSpec,
    schema: Value,
    cwd: PathBuf,
    attempt_dir: PathBuf,
    state_dir: PathBuf,
    worktree: PathBuf,
    prompt: String,
    role_prompt: String,
    /// `None` for every fixture but a test that explicitly asserts `ACP_LEAD_RUN_ID` (T84): a lead
    /// spawn always carries one in practice, but the default here matches every other role, which
    /// never does.
    lead_run_id: Option<RunId>,
}

impl Fixture {
    /// A writing role: gets a worktree and therefore the mandatory sandbox `--settings` (V4).
    fn builder() -> Self {
        Self {
            role: role_spec(RoleName::Builder, true),
            schema: checked_in_schema(),
            cwd: PathBuf::from("/tmp/acp-fixture-worktree"),
            attempt_dir: PathBuf::from("/tmp/acp-fixture-state/attempt-1"),
            state_dir: PathBuf::from("/tmp/acp-fixture-state"),
            worktree: PathBuf::from("/tmp/acp-fixture-worktree"),
            prompt: "Add src/adder.ts exporting add(a, b).".to_string(),
            role_prompt: "You are a builder worker.\nNever commit.\n".to_string(),
            lead_run_id: None,
        }
    }

    /// A read-only role. The shipped reviewer runs on Codex; what matters here is `writes: false`,
    /// which is the only thing that may drop the sandbox flag.
    fn read_only() -> Self {
        Self {
            role: role_spec(RoleName::Reviewer, false),
            ..Self::builder()
        }
    }

    fn lead() -> Self {
        let mut role = role_spec(RoleName::Lead, false);
        role.default_model = "haiku".to_string();
        role.max_turns = 100;
        role.spawn_budget_usd = 2.0;
        role.tools = Some(LEAD_TOOLS.iter().map(|tool| (*tool).to_string()).collect());
        Self {
            role,
            cwd: PathBuf::from("/tmp/acp-fixture-repo"),
            worktree: PathBuf::from("/tmp/acp-fixture-repo"),
            prompt: "Please inspect the current work and coordinate a fix.".to_string(),
            role_prompt: "You are the ACP lead. Only a human approves gates.\n".to_string(),
            ..Self::builder()
        }
    }

    fn request(&self) -> SpawnRequest<'_> {
        SpawnRequest {
            role: &self.role,
            model: SONNET,
            prompt: &self.prompt,
            role_prompt: &self.role_prompt,
            cwd: &self.cwd,
            attempt_dir: &self.attempt_dir,
            state_dir: &self.state_dir,
            lead_run_id: self.lead_run_id,
            schema: ("build-result", &self.schema),
            max_turns: self.role.max_turns,
            spawn_budget_usd: self.role.spawn_budget_usd,
            // A read-only role is spawned without a sandbox spec: nothing may be written, so there
            // is no worktree to allow.
            sandbox: self.role.requires_sandbox().then_some(SandboxSpec {
                worktree: &self.worktree,
            }),
            session_id: None,
            effort: None,
        }
    }

    fn fresh(&self, model: &str) -> Vec<String> {
        ClaudeAdapter
            .build_fresh(&SpawnRequest {
                model,
                ..self.request()
            })
            .argv
    }

    fn resume(&self, model: &str) -> Vec<String> {
        ClaudeAdapter
            .build_resume(&SpawnRequest {
                model,
                session_id: Some(SESSION_ID),
                ..self.request()
            })
            .argv
    }
}

fn role_spec(role: RoleName, writes: bool) -> RoleSpec {
    RoleSpec {
        role,
        provider: ProviderName::Claude,
        models: vec![SONNET.to_string(), OPUS.to_string()],
        default_model: SONNET.to_string(),
        writes,
        prompt_file: Some("prompts/builder-worker.md".to_string()),
        prompt_sha256: None,
        description: Some("Implements one task in its own worktree.".to_string()),
        tools: Some(TOOLS.iter().map(|tool| (*tool).to_string()).collect()),
        sandbox_mode: Some(if writes {
            SandboxMode::WorkspaceWrite
        } else {
            SandboxMode::ReadOnly
        }),
        max_turns: 12,
        spawn_budget_usd: 2.5,
        result_schema: SchemaName::BuildResult,
        allowed_delegations: Vec::new(),
    }
}

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// The real post-processed artifact the supervisor passes in (design, § `schemas/`).
fn checked_in_schema() -> Value {
    let text = std::fs::read_to_string(repo_path("schemas/build-result.json"))
        .expect("schemas/build-result.json is checked in");
    serde_json::from_str(&text).expect("build-result.json is valid JSON")
}

fn fixture_lines(name: &str) -> Vec<String> {
    let path = repo_path(&format!("fixtures/jsonl/claude/{name}.jsonl"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
        .lines()
        .map(str::to_string)
        .collect()
}

/// Every event the adapter produces for one fixture, in stream order.
fn parse_fixture(name: &str) -> Vec<NormalizedEvent> {
    fixture_lines(name)
        .iter()
        .flat_map(|line| ClaudeAdapter.parse_line(line))
        .collect()
}

// ---------------------------------------------------------------------------
// argv helpers
// ---------------------------------------------------------------------------

fn index_of(argv: &[String], flag: &str) -> usize {
    argv.iter()
        .position(|token| token == flag)
        .unwrap_or_else(|| panic!("{flag} missing from argv: {argv:?}"))
}

/// The single token after `flag`.
fn flag_value<'a>(argv: &'a [String], flag: &str) -> &'a str {
    &argv[index_of(argv, flag) + 1]
}

/// Every token after `flag` up to the next `-`-prefixed one — a variadic flag's whole list.
fn flag_values<'a>(argv: &'a [String], flag: &str) -> Vec<&'a str> {
    argv[index_of(argv, flag) + 1..]
        .iter()
        .take_while(|token| !token.starts_with('-'))
        .map(String::as_str)
        .collect()
}

fn json_flag(argv: &[String], flag: &str) -> Value {
    serde_json::from_str(flag_value(argv, flag))
        .unwrap_or_else(|err| panic!("{flag} value is not JSON: {err}"))
}

/// The argv with every inline-JSON token replaced by `<json>`, so flag *order* can be asserted as
/// one readable snapshot without depending on JSON key ordering (the payloads get their own
/// assertions below).
fn skeleton(argv: &[String]) -> Vec<String> {
    argv.iter()
        .map(|token| {
            if token.starts_with('{') {
                "<json>".to_string()
            } else {
                token.clone()
            }
        })
        .collect()
}

/// The design's flag order (§ Exact argv), with `<json>` where an inline document sits.
fn expected_skeleton(
    prompt: &str,
    model: &str,
    resume: Option<&str>,
    sandbox: bool,
) -> Vec<String> {
    let mut expected = vec!["-p".to_string(), prompt.to_string()];
    if let Some(session_id) = resume {
        expected.extend(["--resume".to_string(), session_id.to_string()]);
    }
    expected.extend([
        "--model".to_string(),
        model.to_string(),
        "--setting-sources".to_string(),
        "project".to_string(),
        "--agents".to_string(),
        "<json>".to_string(),
        "--agent".to_string(),
        if sandbox { "builder" } else { "reviewer" }.to_string(),
    ]);
    if sandbox {
        expected.extend(["--settings".to_string(), "<json>".to_string()]);
    }
    expected.extend([
        "--output-format".to_string(),
        "stream-json".to_string(),
        "--verbose".to_string(),
        "--json-schema".to_string(),
        "<json>".to_string(),
        "--max-turns".to_string(),
        "12".to_string(),
        "--max-budget-usd".to_string(),
        "2.5".to_string(),
        "--permission-mode".to_string(),
        "acceptEdits".to_string(),
        "--allowedTools".to_string(),
    ]);
    expected.extend(TOOLS.iter().map(|tool| (*tool).to_string()));
    expected.push("--disallowedTools".to_string());
    expected.extend(
        [
            "Bash(git commit:*)",
            "Bash(git push:*)",
            "Bash(git reset:*)",
            "Bash(git add:*)",
        ]
        .iter()
        .map(|tool| (*tool).to_string()),
    );
    expected.extend([
        "--strict-mcp-config".to_string(),
        "--mcp-config".to_string(),
        "<json>".to_string(),
    ]);
    expected
}

/// Everything that must hold of a builder argv whatever the model and whether it is a resume.
fn assert_builder_argv(fixture: &Fixture, argv: &[String], model: &str) {
    // The prompt is the token immediately after `-p` — index 2 of the command line, counting
    // `claude` as index 0 (`SpawnPlan.file` holds the program).
    assert_eq!(argv[0], "-p", "argv must start with -p: {argv:?}");
    assert_eq!(argv[1], fixture.prompt, "prompt must follow -p directly");
    assert_eq!(flag_value(argv, "--model"), model);
    assert_eq!(flag_value(argv, "--setting-sources"), "project");
    assert_eq!(flag_value(argv, "--permission-mode"), "acceptEdits");
    assert_eq!(flag_value(argv, "--max-turns"), "12");
    assert_eq!(flag_value(argv, "--max-budget-usd"), "2.5");
    assert_eq!(flag_value(argv, "--agent"), "builder");
    assert_eq!(flag_values(argv, "--allowedTools"), TOOLS);
    assert_eq!(
        flag_values(argv, "--disallowedTools"),
        [
            "Bash(git commit:*)",
            "Bash(git push:*)",
            "Bash(git reset:*)",
            "Bash(git add:*)"
        ]
    );
    assert!(argv.iter().any(|token| token == "--strict-mcp-config"));
    assert_eq!(
        json_flag(argv, "--mcp-config"),
        serde_json::json!({"mcpServers": {}})
    );

    // V3: the role travels inline, with the prompt body verbatim.
    let agents = json_flag(argv, "--agents");
    let agent = &agents["builder"];
    assert_eq!(
        agent["prompt"].as_str(),
        Some(fixture.role_prompt.as_str()),
        "--agents must carry the role prompt body byte for byte"
    );
    assert_eq!(agent["model"].as_str(), Some(model));
    assert_eq!(
        agent["description"].as_str(),
        fixture.role.description.as_deref()
    );
    assert_eq!(
        agent["tools"],
        serde_json::json!(TOOLS),
        "the inline role may not widen the tool allowlist"
    );

    // V4: the kernel sandbox, scoped to this worktree and nothing else.
    let settings = json_flag(argv, "--settings");
    let sandbox = &settings["sandbox"];
    assert_eq!(sandbox["enabled"], Value::Bool(true));
    assert_eq!(sandbox["autoAllowBashIfSandboxed"], Value::Bool(true));
    assert_eq!(
        sandbox["filesystem"]["denyWrite"],
        serde_json::json!(["~/"])
    );
    assert_eq!(
        sandbox["filesystem"]["allowWrite"],
        serde_json::json!([fixture.worktree.display().to_string()]),
        "allowWrite must be exactly the assigned worktree"
    );
    assert!(
        fixture.worktree.is_absolute(),
        "the sandbox path must be absolute"
    );

    // V7: `claude --json-schema` rejects a document carrying a top-level `$schema`.
    let schema = json_flag(argv, "--json-schema");
    assert!(
        schema.get("$schema").is_none(),
        "--json-schema payload must have no top-level $schema key"
    );
    assert!(
        schema.get("$defs").is_some(),
        "the rest of the schema document must survive intact"
    );

    for denied in DENIED_ARGV_SPOT_CHECK {
        assert!(
            !argv.iter().any(|token| token == denied),
            "denied flag {denied} present in argv"
        );
    }

    // Variadics last: after the first one, every token belongs to a flag's list — in particular
    // the prompt never reappears where `--mcp-config` would swallow it.
    let first_variadic = index_of(argv, "--allowedTools");
    assert!(
        !argv[first_variadic..]
            .iter()
            .any(|token| token == &fixture.prompt),
        "nothing positional may follow the variadic flags"
    );
    assert_eq!(
        argv.last().map(String::as_str),
        Some(r#"{"mcpServers":{}}"#),
        "the last token must be a flag value, not a positional"
    );
    assert_eq!(argv[argv.len() - 2], "--mcp-config");
}

// ---------------------------------------------------------------------------
// argv: fresh + resume × sonnet + opus
// ---------------------------------------------------------------------------

#[test]
fn fresh_sonnet_argv_matches_the_design_shape() {
    let fixture = Fixture::builder();
    let argv = fixture.fresh(SONNET);
    assert_eq!(
        skeleton(&argv),
        expected_skeleton(&fixture.prompt, SONNET, None, true)
    );
    assert_builder_argv(&fixture, &argv, SONNET);
}

#[test]
fn fresh_opus_argv_matches_the_design_shape() {
    let fixture = Fixture::builder();
    let argv = fixture.fresh(OPUS);
    assert_eq!(
        skeleton(&argv),
        expected_skeleton(&fixture.prompt, OPUS, None, true)
    );
    assert_builder_argv(&fixture, &argv, OPUS);
}

#[test]
fn resume_sonnet_argv_repeats_the_fresh_flags() {
    let fixture = Fixture::builder();
    let argv = fixture.resume(SONNET);
    assert_eq!(
        skeleton(&argv),
        expected_skeleton(&fixture.prompt, SONNET, Some(SESSION_ID), true)
    );
    assert_builder_argv(&fixture, &argv, SONNET);
    // The prompt still comes first; `--resume` follows it (V1 — resume repeats every fresh flag,
    // including `--agent`, because `--resume` restores the transcript and nothing else).
    assert_eq!(argv[1], fixture.prompt);
    assert_eq!(argv[2], "--resume");
    assert_eq!(argv[3], SESSION_ID);
    assert_eq!(flag_value(&argv, "--agent"), "builder");
}

#[test]
fn resume_opus_argv_repeats_the_fresh_flags() {
    let fixture = Fixture::builder();
    let argv = fixture.resume(OPUS);
    assert_eq!(
        skeleton(&argv),
        expected_skeleton(&fixture.prompt, OPUS, Some(SESSION_ID), true)
    );
    assert_builder_argv(&fixture, &argv, OPUS);
    assert_eq!(flag_value(&argv, "--resume"), SESSION_ID);
}

#[test]
fn fresh_and_resume_differ_only_by_the_resume_pair() {
    let fixture = Fixture::builder();
    let fresh = fixture.fresh(SONNET);
    let mut resume = fixture.resume(SONNET);
    assert_eq!(
        resume.drain(2..4).collect::<Vec<_>>(),
        ["--resume", SESSION_ID]
    );
    assert_eq!(resume, fresh, "resume must repeat the fresh flag set (V1)");
}

#[test]
fn a_read_only_role_gets_no_sandbox_settings() {
    let fixture = Fixture::read_only();
    let argv = fixture.fresh(SONNET);
    assert_eq!(
        skeleton(&argv),
        expected_skeleton(&fixture.prompt, SONNET, None, false)
    );
    assert!(
        !argv.iter().any(|token| token == "--settings"),
        "a role that writes nothing needs no writable path"
    );
    assert_eq!(flag_value(&argv, "--agent"), "reviewer");
    assert!(json_flag(&argv, "--agents").get("reviewer").is_some());
}

#[test]
fn a_lead_uses_only_the_local_proxy_without_a_sandbox_or_result_schema() {
    let fixture = Fixture::lead();
    let plan = ClaudeAdapter.build_fresh(&fixture.request());
    let argv = &plan.argv;

    assert_eq!(plan.cwd, fixture.cwd, "the lead runs at the repo root");
    assert_eq!(ClaudeAdapter.prompt_index(&plan), Some(1));
    assert_eq!(flag_value(argv, "--agent"), "lead");
    assert_eq!(flag_value(argv, "--max-turns"), "100");
    assert_eq!(flag_value(argv, "--max-budget-usd"), "2");
    assert!(!argv.iter().any(|token| token == "--settings"));
    assert!(!argv.iter().any(|token| token == "--json-schema"));
    assert_eq!(flag_values(argv, "--allowedTools"), LEAD_TOOLS);
    assert_eq!(
        flag_values(argv, "--disallowedTools"),
        [
            "Bash(git commit:*)",
            "Bash(git push:*)",
            "Bash(git reset:*)",
            "Bash(git add:*)"
        ]
    );

    let agents = json_flag(argv, "--agents");
    assert_eq!(agents["lead"]["tools"], serde_json::json!(LEAD_TOOLS));
    assert_eq!(
        agents["lead"]["prompt"].as_str(),
        Some(fixture.role_prompt.as_str())
    );

    let config = json_flag(argv, "--mcp-config");
    let acp = &config["mcpServers"]["acp"];
    assert_eq!(
        acp["command"],
        serde_json::json!(std::env::current_exe().expect("current executable"))
    );
    assert_eq!(
        acp["args"],
        serde_json::json!(["mcp-proxy", "--repo", fixture.cwd])
    );
    // The proxy child inherits claude's scrubbed environment, so the daemon's state dir must ride
    // in the config's env block or the proxy resolves the *default* state dir and misses the
    // socket. Keyed (not whole-object) so a concurrently-guarded `ACP_ROLES_FILE` test cannot
    // race this one; the exact shape is pinned under the env guard below.
    assert_eq!(
        acp["env"]["ACP_STATE_DIR"],
        serde_json::json!("/tmp/acp-fixture-state")
    );
    assert_eq!(
        config["mcpServers"].as_object().map(serde_json::Map::len),
        Some(1),
        "no project-authored MCP server joins the proxy"
    );
}

#[test]
fn the_lead_mcp_env_hands_the_proxy_exactly_the_paths_the_scrubbed_env_drops() {
    common::with_exclusive_env(|| async {
        let fixture = Fixture::lead();
        let previous = std::env::var_os("ACP_ROLES_FILE");
        std::env::remove_var("ACP_ROLES_FILE");
        let env_of =
            |argv: &[String]| json_flag(argv, "--mcp-config")["mcpServers"]["acp"]["env"].clone();

        // Without a roles override the block carries the state dir alone: nothing else from the
        // daemon's environment may leak into the proxy child.
        assert_eq!(
            env_of(&fixture.fresh(SONNET)),
            serde_json::json!({ "ACP_STATE_DIR": "/tmp/acp-fixture-state" })
        );

        // With one, the proxy gets the same roles file the daemon's own startup read — and still
        // nothing more.
        std::env::set_var("ACP_ROLES_FILE", "/tmp/acp-fixture-roles.json");
        let env = env_of(&fixture.fresh(SONNET));

        // A *relative* override is absolutized against the daemon's cwd before it travels: the
        // proxy child would otherwise resolve it from claude's cwd and fail closed to zero tools.
        std::env::set_var("ACP_ROLES_FILE", "relative/roles.json");
        let env_relative = env_of(&fixture.fresh(SONNET));
        let codex = agent_control_plane::providers::codex::CodexAdapter.build_fresh(&SpawnRequest {
            model: "gpt-5.5", ..fixture.request()
        });
        let codex_mcp = codex.argv.iter().find(|v| v.starts_with("mcp_servers=")).unwrap().clone();

        match previous {
            Some(value) => std::env::set_var("ACP_ROLES_FILE", value),
            None => std::env::remove_var("ACP_ROLES_FILE"),
        }
        assert_eq!(
            env,
            serde_json::json!({
                "ACP_STATE_DIR": "/tmp/acp-fixture-state",
                "ACP_ROLES_FILE": "/tmp/acp-fixture-roles.json",
            })
        );
        assert!(codex_mcp.contains(&format!("ACP_ROLES_FILE={}", serde_json::json!(
            std::env::current_dir().unwrap().join("relative/roles.json")))));
        assert_eq!(
            env_relative["ACP_ROLES_FILE"],
            serde_json::json!(std::env::current_dir()
                .expect("test cwd")
                .join("relative/roles.json"))
        );
    });
}

/// T84: `spawn_lead` threads the minted lead run into `ACP_LEAD_RUN_ID`, alongside
/// `ACP_STATE_DIR`, so `acp mcp-proxy` can later attest this lead's own `delegate`/`plan.start`
/// calls. Worker roles never carry a `lead_run_id` at all — the field stays absent, not merely
/// empty, exactly like the daemon's other lead-only env entries.
#[test]
fn a_lead_run_id_rides_alongside_the_state_dir_in_the_proxy_env() {
    let mut fixture = Fixture::lead();
    let run: RunId = "11111111-1111-4111-8111-111111111111"
        .parse()
        .expect("fixture run id");
    fixture.lead_run_id = Some(run);
    let argv = fixture.fresh(SONNET);
    let env = json_flag(&argv, "--mcp-config")["mcpServers"]["acp"]["env"].clone();
    assert_eq!(env["ACP_LEAD_RUN_ID"], serde_json::json!(run));
    assert_eq!(env["ACP_STATE_DIR"], serde_json::json!("/tmp/acp-fixture-state"));

    // A worker's request never sets `lead_run_id`; `--mcp-config` for one is `{"mcpServers":{}}`
    // regardless (V2), but the field itself must not silently start leaking into that shape.
    let worker = Fixture::builder();
    assert_eq!(worker.lead_run_id, None);
}

#[test]
fn a_role_without_a_description_or_tools_still_produces_a_usable_inline_role() {
    let mut fixture = Fixture::builder();
    fixture.role.description = None;
    fixture.role.tools = None;
    let argv = fixture.fresh(SONNET);

    let agent = json_flag(&argv, "--agents")["builder"].clone();
    assert_eq!(agent["description"].as_str(), Some("builder worker"));
    assert_eq!(agent["tools"], serde_json::json!(TOOLS));
}

#[test]
fn a_schema_that_still_carries_dollar_schema_is_stripped_before_it_reaches_the_cli() {
    // Defence in depth: the supervisor passes the post-processed artifact (V7), but `claude`
    // *rejects* the document outright if the key survives, so the adapter strips it again.
    let mut fixture = Fixture::builder();
    fixture.schema["$schema"] =
        Value::String("https://json-schema.org/draft/2020-12/schema".into());
    let argv = fixture.fresh(SONNET);

    let schema = json_flag(&argv, "--json-schema");
    assert!(schema.get("$schema").is_none());
    assert_eq!(schema["title"], fixture.schema["title"]);
}

#[test]
fn the_spawn_plan_carries_the_program_cwd_and_scrubbed_env() {
    let fixture = Fixture::builder();
    let plan = ClaudeAdapter.build_fresh(&fixture.request());

    assert_eq!(plan.file, PathBuf::from("claude"));
    assert_eq!(plan.cwd, fixture.cwd);
    assert!(
        plan.write_files.is_empty(),
        "Claude takes its role and schema inline — nothing to write"
    );
    assert!(!plan.env.keys().any(|key| key.starts_with("ACP_")));
    assert_eq!(
        plan.env.get("GIT_CONFIG_VALUE_0").map(String::as_str),
        Some("")
    );
}

#[test]
fn a_worst_case_prompt_stays_under_the_argv_ceiling() {
    // The largest argv the design permits: a role prompt at `MAX_PROMPT_BYTES` (the body is what
    // dominates, since it travels inline in `--agents`) plus a full-size task prompt.
    let mut fixture = Fixture::builder();
    fixture.role_prompt = "R".repeat(90_000);
    fixture.prompt = "P".repeat(4_096);
    let plan = ClaudeAdapter.build_fresh(&fixture.request());

    assert!(fixture.role_prompt.len() < MAX_PROMPT_BYTES);
    // `execve` counts argv *and* env against `ARG_MAX`, and so does `assert_safe_argv`; each entry
    // costs its bytes plus a NUL, and each env entry an `=` as well.
    let argv_bytes: usize = plan.argv.iter().map(|token| token.len() + 1).sum();
    let env_bytes: usize = plan
        .env
        .iter()
        .map(|(key, value)| key.len() + value.len() + 2)
        .sum();
    assert!(
        argv_bytes + env_bytes < MAX_ARGV_BYTES,
        "argv+env {} bytes exceeds the {MAX_ARGV_BYTES}-byte ceiling",
        argv_bytes + env_bytes
    );
    // The prompt body still arrives whole — no truncation to fit.
    assert_eq!(
        json_flag(&plan.argv, "--agents")["builder"]["prompt"]
            .as_str()
            .map(str::len),
        Some(90_000)
    );
}

// ---------------------------------------------------------------------------
// parse_line
// ---------------------------------------------------------------------------

#[test]
fn pass_fixture_yields_exactly_one_session_and_a_successful_final() {
    let lines = fixture_lines("pass-1");
    let events = parse_fixture("pass-1");

    let sessions: Vec<&String> = events
        .iter()
        .filter_map(|event| match event {
            NormalizedEvent::Session { session_id } => Some(session_id),
            _ => None,
        })
        .collect();
    let expected_session: Value = serde_json::from_str(&lines[0]).expect("init line is JSON");
    assert_eq!(sessions.len(), 1, "only `system/init` starts a session");
    assert_eq!(
        sessions[0].as_str(),
        expected_session["session_id"].as_str().expect("session_id")
    );

    // The terminal line carries the usage figures and the outcome, in that order.
    let terminal = ClaudeAdapter.parse_line(lines.last().expect("fixture is not empty"));
    assert!(matches!(
        terminal.as_slice(),
        [
            NormalizedEvent::Usage { .. },
            NormalizedEvent::Final { ok: true, .. }
        ]
    ));
    let NormalizedEvent::Final {
        structured,
        stop_reason,
        cost_usd,
        error_code,
        ..
    } = &terminal[1]
    else {
        panic!("expected a Final event, got {terminal:?}");
    };
    assert_eq!(
        structured.as_ref().map(|s| s["status"].clone()),
        Some(Value::String("succeeded".into()))
    );
    assert_eq!(stop_reason.as_deref(), Some("completed"));
    assert!(cost_usd.unwrap_or_default() > 0.0);
    assert_eq!(*error_code, None);
}

#[test]
fn usage_maps_cache_reads_to_cached_input() {
    let lines = fixture_lines("pass-1");
    let terminal = ClaudeAdapter.parse_line(lines.last().expect("fixture is not empty"));
    let NormalizedEvent::Usage { tokens, cost_usd } = &terminal[0] else {
        panic!("expected a Usage event, got {terminal:?}");
    };

    // From the captured `result.usage`: 42 fresh + 8455 written to cache, 32147 read back.
    assert_eq!(tokens.input, 42 + 8455);
    assert_eq!(tokens.cached_input, 32_147);
    assert_eq!(tokens.output, 1_083);
    assert_eq!(tokens.reasoning, None);
    assert_eq!(*cost_usd, Some(0.0262357));
}

#[test]
fn assistant_lines_become_tool_use_and_text_phases() {
    let events = parse_fixture("pass-1");
    let phases: Vec<(&str, Option<&str>)> = events
        .iter()
        .filter_map(|event| match event {
            NormalizedEvent::Phase { phase, note } => Some((phase.as_str(), note.as_deref())),
            _ => None,
        })
        .collect();

    // The fixture writes one file, then reports its result as text; `thinking` blocks and tool
    // results are not progress the lead can act on and produce nothing.
    assert_eq!(phases, [("tool_use", Some("Write")), ("text", None)]);

    let messages: Vec<&str> = events
        .iter()
        .filter_map(|event| match event {
            NormalizedEvent::Message { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        messages.len(),
        1,
        "the fixture has one assistant text block"
    );
    assert!(messages[0].contains("Added src/adder.ts"));
}

#[test]
fn assistant_messages_preserve_long_unicode_prose_in_bounded_parts() {
    let prose = format!("{}éTAIL", "a".repeat(4_095));
    let line = serde_json::json!({
        "type": "assistant",
        "message": {"content": [{"type": "text", "text": prose}]}
    }).to_string();
    let events = ClaudeAdapter.parse_line(&line);
    let parts: Vec<_> = events.iter().filter_map(|event| match event {
        NormalizedEvent::Message { text, part } => Some((text, part)), _ => None,
    }).collect();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts.iter().map(|(text, _)| text.as_str()).collect::<String>(), prose);
    for (index, (text, part)) in parts.iter().enumerate() {
        assert!(text.len() <= 4096);
        let part = part.expect("assembly metadata");
        assert_eq!(part.index, index as u32);
        assert_eq!(part.count, 2);
        assert!(!part.truncated);
    }
}

#[test]
fn one_assistant_line_materializes_at_most_501_messages_and_one_phase() {
    let content: Vec<Value> = (0..10_000)
        .map(|i| serde_json::json!({"type": "text", "text": format!("block {i}")}))
        .collect();
    let line = serde_json::json!({
        "type": "assistant",
        "message": {"content": content}
    })
    .to_string();
    let events = ClaudeAdapter.parse_line(&line);

    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, NormalizedEvent::Message { .. }))
            .count(),
        501
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, NormalizedEvent::Phase { .. }))
            .count(),
        1,
        "only the final coalescible phase is retained"
    );
}

#[test]
fn the_max_turns_fixture_is_a_failed_final_carrying_the_max_turns_code() {
    let lines = fixture_lines("max_turns-1");
    let terminal = ClaudeAdapter.parse_line(lines.last().expect("fixture is not empty"));

    let NormalizedEvent::Final {
        ok,
        error_code,
        stop_reason,
        structured,
        ..
    } = &terminal[1]
    else {
        panic!("expected a Final event, got {terminal:?}");
    };
    assert!(!*ok, "`is_error: true` is a failed attempt");
    assert_eq!(*error_code, Some(ErrorCode::MaxTurns));
    assert_eq!(stop_reason.as_deref(), Some("max_turns"));
    assert_eq!(
        *structured, None,
        "a max-turns run produced no result document"
    );
}

#[test]
fn an_invalid_output_run_is_still_a_successful_final() {
    // `invalid-1` ends cleanly with a document that does not match the schema. Classifying that as
    // `invalid_output` is the caller's job — the adapter only reports what Claude said.
    let lines = fixture_lines("invalid-1");
    let terminal = ClaudeAdapter.parse_line(lines.last().expect("fixture is not empty"));

    let NormalizedEvent::Final {
        ok,
        structured,
        error_code,
        ..
    } = &terminal[1]
    else {
        panic!("expected a Final event, got {terminal:?}");
    };
    assert!(*ok);
    assert_eq!(*error_code, None);
    assert!(
        structured.as_ref().expect("structured_output")["status"]
            != Value::String("succeeded".into())
    );
}

#[test]
fn garbage_blank_and_non_object_lines_parse_to_nothing() {
    for line in [
        "not json{",
        "",
        "   ",
        "{\"type\":\"system\"",
        "42",
        "[1,2,3]",
        "{\"type\":\"user\",\"message\":{}}",
        "{\"type\":\"system\",\"subtype\":\"init\"}",
    ] {
        assert!(
            ClaudeAdapter.parse_line(line).is_empty(),
            "line {line:?} must yield no events and must not panic"
        );
    }
}

// ---------------------------------------------------------------------------
// extract_result
// ---------------------------------------------------------------------------

#[test]
fn extract_result_reports_the_last_final_and_the_session() {
    let events = parse_fixture("pass-1");
    let result = ClaudeAdapter.extract_result(&ResultCtx {
        events: &events,
        exit_code: Some(0),
        signal: None,
        last_message: None,
        stderr_head: None,
    });

    assert!(result.ok);
    assert_eq!(result.session_id.as_deref(), Some(SESSION_ID));
    assert_eq!(result.error_code, None);
    assert_eq!(
        result.structured.expect("structured_output")["filesChanged"],
        serde_json::json!(["src/adder.ts"])
    );
    assert!(result
        .text
        .expect("result text")
        .contains("\"status\":\"succeeded\""));
}

#[test]
fn extract_result_carries_the_error_code_of_a_failed_attempt() {
    let events = parse_fixture("max_turns-1");
    let result = ClaudeAdapter.extract_result(&ResultCtx {
        events: &events,
        exit_code: Some(1),
        signal: None,
        last_message: None,
        stderr_head: None,
    });

    assert!(!result.ok);
    assert_eq!(result.error_code, Some(ErrorCode::MaxTurns));
    assert_eq!(
        result.session_id.as_deref(),
        Some("cccccccc-3333-4c33-8c33-cccccccccccc")
    );
}

#[test]
fn a_stream_without_a_final_is_not_ok_but_still_reports_its_session() {
    // A worker killed mid-attempt: the session id is what tells the loop it can resume rather than
    // start over (`no_session` is the case where even this is absent).
    let events: Vec<NormalizedEvent> = ClaudeAdapter.parse_line(&fixture_lines("pass-1")[0]);
    let result = ClaudeAdapter.extract_result(&ResultCtx {
        events: &events,
        exit_code: None,
        signal: Some("SIGKILL"),
        last_message: None,
        stderr_head: None,
    });

    assert!(!result.ok);
    assert_eq!(result.session_id.as_deref(), Some(SESSION_ID));
    assert_eq!(result.text, None);
    assert_eq!(result.structured, None);

    let empty = ClaudeAdapter.extract_result(&ResultCtx {
        events: &[],
        exit_code: Some(1),
        signal: None,
        last_message: None,
        stderr_head: None,
    });
    assert!(!empty.ok);
    assert_eq!(empty.session_id, None);
}

/// Live-gate regression (2026-08-27): when the worker runs as a named agent
/// (`--agents … --agent <role>`), claude 2.1.221 omits `structured_output` from the result event
/// and the un-enforced model may fence its JSON. The adapter falls back to parsing the final text;
/// the supervisor's own schema validation stays the gate.
#[test]
fn a_result_without_structured_output_falls_back_to_the_fenced_final_text() {
    let line = r#"{"type":"result","subtype":"success","is_error":false,"usage":{},"total_cost_usd":0.01,"result":"```json\n{\"status\":\"succeeded\",\"filesChanged\":[],\"summary\":\"PONG\"}\n```"}"#;
    let events: Vec<NormalizedEvent> = ClaudeAdapter.parse_line(line);
    let structured = events
        .iter()
        .find_map(|event| match event {
            NormalizedEvent::Final { structured, .. } => Some(structured.clone()),
            _ => None,
        })
        .expect("a Final event");
    assert_eq!(
        structured
            .as_ref()
            .and_then(|value| value.get("summary"))
            .and_then(|value| value.as_str()),
        Some("PONG"),
        "the fenced final text is parsed when structured_output is absent"
    );

    // Prose with no document stays unstructured — the fallback parses, it does not invent.
    let prose = r#"{"type":"result","subtype":"success","is_error":false,"usage":{},"result":"I finished the task."}"#;
    let events: Vec<NormalizedEvent> = ClaudeAdapter.parse_line(prose);
    let structured = events
        .iter()
        .find_map(|event| match event {
            NormalizedEvent::Final { structured, .. } => Some(structured.clone()),
            _ => None,
        })
        .expect("a Final event");
    assert!(structured.is_none());
}

/// Live-gate regression (2026-08-30): a real haiku verifier led its correct report with a
/// sentence of prose before an UNFENCED trailing document. The fallback extracts the trailing
/// object — nested braces, a `{` inside the prose, and prose containing `}` all fall out of the
/// walk-from-the-last-brace parse — while extraction stays short of acceptance: the schema
/// validator remains the gate.
#[test]
fn a_result_with_prose_before_an_unfenced_document_extracts_the_trailing_object() {
    let structured_of = |line: &str| {
        ClaudeAdapter
            .parse_line(line)
            .iter()
            .find_map(|event| match event {
                NormalizedEvent::Final { structured, .. } => Some(structured.clone()),
                _ => None,
            })
            .expect("a Final event")
    };
    let result_line = |text: &str| {
        serde_json::json!({
            "type": "result", "subtype": "success", "is_error": false,
            "usage": {}, "total_cost_usd": 0.01, "result": text
        })
        .to_string()
    };

    // The exact live shape: explanation, then the bare document (with nested structure).
    let live = result_line(
        "Per my instructions, when a repository declares no build or test command, I report \
         status `nothing-to-run`.\n{\n  \"status\": \"nothing-to-run\",\n  \"summary\": \"no \
         build declared\",\n  \"commands\": [],\n  \"failures\": [],\n  \"diffHash\": \"abc\"\n}",
    );
    let structured = structured_of(&live).expect("the trailing document is extracted");
    assert_eq!(
        structured.get("status").and_then(|v| v.as_str()),
        Some("nothing-to-run")
    );

    // Prose that itself contains braces before the real document: the last balanced object wins.
    let braces = result_line(
        "I looked at {config} blocks first.\n{\"status\":\"pass\",\"nested\":{\"deep\":true}}",
    );
    let structured = structured_of(&braces).expect("extracted despite braces in the prose");
    assert_eq!(
        structured.pointer("/nested/deep"),
        Some(&serde_json::Value::Bool(true))
    );

    // Text that merely ENDS with a } but holds no parseable document stays unstructured.
    let junk = result_line("unbalanced { thing }");
    assert!(structured_of(&junk).is_none());

    // A BARE document followed by trailing prose does NOT extract: without a fence there is no
    // document marker, and grabbing a mid-text object would accept messages the prompt forbids
    // twice over.
    let midtext = result_line("{\"status\":\"pass\"} — and let me add some thoughts.");
    assert!(structured_of(&midtext).is_none());

    // Live round 2 (2026-08-30): prose, then a ```json fence — the exact real-verifier shape.
    // The fence is an explicit marker, so it extracts even mid-text.
    let prose_then_fence = result_line(concat!(
        "Based on my examination:\n\n1. **No manifests found**\n\n",
        "```json\n{\"status\":\"nothing-to-run\",\"commands\":[]}\n```"
    ));
    let structured = structured_of(&prose_then_fence).expect("the fenced document is extracted");
    assert_eq!(
        structured.get("status").and_then(|v| v.as_str()),
        Some("nothing-to-run")
    );

    // An earlier non-JSON fence (a quoted code snippet) is skipped; the LAST parseable fenced
    // object wins even with trailing prose after it.
    let two_fences = result_line(concat!(
        "The file contains:\n```typescript\nexport function add() {}\n```\n",
        "and my report:\n```json\n{\"status\":\"pass\"}\n```\nDone."
    ));
    let structured = structured_of(&two_fences).expect("the json fence wins over the ts fence");
    assert_eq!(
        structured.get("status").and_then(|v| v.as_str()),
        Some("pass")
    );

    // The ORDER is pinned (review, 2026-08-30): a message-final bare document beats an earlier
    // fenced object — a template the model echoed from its own prompt must not win over the
    // real report at the end.
    let template_then_real = result_line(
        "The format is:\n```json\n{\"status\":\"TEMPLATE\"}\n```\nMy report:\n{\"status\":\"pass\",\"real\":true}",
    );
    let structured = structured_of(&template_then_real).expect("the trailing document wins");
    assert_eq!(structured.get("real"), Some(&serde_json::Value::Bool(true)));

    // A stray ``` in the prose must not hide the real fenced report (no parity assumption).
    let stray_fence = result_line(
        "A ``` marks a fence, by the way.\n```json\n{\"status\":\"pass\",\"stray\":true}\n```",
    );
    let structured = structured_of(&stray_fence).expect("parity-free fence walk");
    assert_eq!(
        structured.get("stray"),
        Some(&serde_json::Value::Bool(true))
    );
}
