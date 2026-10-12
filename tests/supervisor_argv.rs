//! T23: `core::supervisor::assert_safe_argv` — the S5 chokepoint — plus a real detached spawn
//! (`reports/03-design.md` § Test Strategy, row `core/supervisor.rs`, argv-safety half).
//!
//! Plans come from the **real adapters** wherever possible: a hand-written argv would only prove
//! that the checker rejects what this file made up, whereas `ClaudeAdapter::build_fresh` &c are
//! what production feeds it. Each negative case therefore starts from a plan that passes and
//! breaks exactly one thing, which is also what makes the *order* of the five checks observable.
//!
//! One convention this file pins down, because getting it wrong is silent: **`SpawnPlan.argv`
//! excludes the program name.** The program is `SpawnPlan.file`, as `Command::args` expects, so
//! Claude's plan begins `["-p", <prompt>, …]` — the prompt is `argv[1]` here, and index 2 of the
//! command line the design writes out with `claude` at index 0. `spawn_detached` therefore passes
//! `plan.argv` **in full**; the record line the fake writes is asserted against it below, so a
//! future `argv[1..]` slice fails here rather than in a live run.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_control_plane::core::policy::{PolicyCode, DENIED_ARGV, MAX_ARGV_BYTES};
use agent_control_plane::core::supervisor::{assert_safe_argv, spawn_detached, ArgvCtx};
use agent_control_plane::core::types::{ProviderName, RoleName, RoleSpec, SandboxMode, SchemaName};
use agent_control_plane::providers::claude::ClaudeAdapter;
use agent_control_plane::providers::codex::CodexAdapter;
use agent_control_plane::providers::{ProviderAdapter, SandboxSpec, SpawnPlan, SpawnRequest};
use nix::sys::signal::{killpg, Signal};
use nix::unistd::{getpgid, Pid};
use serde_json::{json, Value};
use tempfile::TempDir;

const CLAUDE_MODEL: &str = "claude-sonnet-4-5";
const CODEX_MODEL: &str = "gpt-5.5";
const CLAUDE_SESSION: &str = "aaaaaaaa-1111-4a11-8a11-aaaaaaaaaaaa";
const CODEX_THREAD: &str = "01930f4a-0000-7000-8000-000000000001";

/// The four role × session shapes the design's test row names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Combo {
    BuilderFresh,
    BuilderResume,
    ReviewerFresh,
    ReviewerResume,
}

const ALL_COMBOS: [Combo; 4] = [
    Combo::BuilderFresh,
    Combo::BuilderResume,
    Combo::ReviewerFresh,
    Combo::ReviewerResume,
];

impl Combo {
    /// Only a builder writes, and only a writing role must carry the sandbox settings (V4).
    fn writes(self) -> bool {
        matches!(self, Combo::BuilderFresh | Combo::BuilderResume)
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// Owns the temp dirs every plan and every check borrows: a real `$ACP_STATE_DIR` with a real
/// attempt dir under it, and a real git worktree. Real directories matter — `assert_safe_argv`
/// canonicalizes, and on macOS a `/var/…` temp dir is really `/private/var/…`.
struct Fixture {
    state_dir: TempDir,
    repo: TempDir,
    elsewhere: TempDir,
    /// `claude`/`codex` symlinks to the fake bins. Every plan's `PATH` points here, so
    /// `assert_safe_argv` resolves the *fakes* and no test depends on a real CLI being installed.
    bins: TempDir,
    attempt_dir: PathBuf,
    builder: RoleSpec,
    reviewer: RoleSpec,
    build_schema: Value,
    review_schema: Value,
    prompt: String,
    role_prompt: String,
}

impl Fixture {
    fn new() -> Self {
        let state_dir = common::temp_state_dir();
        let attempt_dir = state_dir.path().join("runs/2f0d5f1e/attempts/9d2b7c40");
        std::fs::create_dir_all(&attempt_dir).expect("create the attempt dir");
        Self {
            state_dir,
            repo: common::temp_git_repo(),
            elsewhere: tempfile::tempdir().expect("a directory the worker may not write to"),
            bins: common::fixture_bin_dir(),
            attempt_dir,
            builder: role_spec(RoleName::Builder, ProviderName::Claude, true),
            reviewer: role_spec(RoleName::Reviewer, ProviderName::Codex, false),
            build_schema: checked_in_schema("build-result.json"),
            review_schema: checked_in_schema("review-verdict.json"),
            prompt: "Add src/adder.ts exporting add(a, b).".to_string(),
            role_prompt: "You are a builder worker. Never commit; the control plane does.\n"
                .to_string(),
        }
    }

    fn worktree(&self) -> &Path {
        self.repo.path()
    }

    fn ctx(&self, sandboxed: bool) -> ArgvCtx<'_> {
        self.ctx_for(ProviderName::Claude, sandboxed)
    }

    /// C1: the sandbox check is provider-shaped, so codex-plan tests pass the codex provider.
    fn ctx_for(&self, provider: ProviderName, sandboxed: bool) -> ArgvCtx<'_> {
        ArgvCtx {
            role: agent_control_plane::core::types::RoleName::Builder,
            lead_run_id: None,
            worktree: self.repo.path(),
            provider,
            sandboxed,
            state_dir: self.state_dir.path(),
            prompt_index: None,
        }
    }

    fn ctx_with_prompt(&self, sandboxed: bool, prompt_index: usize) -> ArgvCtx<'_> {
        ArgvCtx {
            prompt_index: Some(prompt_index),
            ..self.ctx(sandboxed)
        }
    }

    /// The plan the real adapter builds for one combination.
    fn plan(&self, combo: Combo) -> SpawnPlan {
        let builder = combo.writes();
        let role = if builder {
            &self.builder
        } else {
            &self.reviewer
        };
        let schema = if builder {
            ("build-result", &self.build_schema)
        } else {
            ("review-verdict", &self.review_schema)
        };
        let session = match combo {
            Combo::BuilderResume => Some(CLAUDE_SESSION),
            Combo::ReviewerResume => Some(CODEX_THREAD),
            _ => None,
        };
        let req = SpawnRequest {
            role,
            model: if builder { CLAUDE_MODEL } else { CODEX_MODEL },
            prompt: &self.prompt,
            role_prompt: &self.role_prompt,
            // The reviewer runs read-only in the builder's worktree — never `-C`, always the cwd.
            cwd: self.repo.path(),
            attempt_dir: &self.attempt_dir,
            state_dir: self.state_dir.path(),
            lead_run_id: None,
            schema,
            max_turns: 12,
            spawn_budget_usd: 2.5,
            sandbox: builder.then_some(SandboxSpec {
                worktree: self.repo.path(),
            }),
            session_id: session,
            effort: None,
        };
        let mut plan = match (builder, session.is_some()) {
            (true, false) => ClaudeAdapter.build_fresh(&req),
            (true, true) => ClaudeAdapter.build_resume(&req),
            (false, false) => CodexAdapter.build_fresh(&req),
            (false, true) => CodexAdapter.build_resume(&req),
        };
        // `file` stays the bare `claude`/`codex` the adapter built — production's shape — and the
        // plan's own `PATH` is what `assert_safe_argv` resolves it against.
        plan.env
            .insert("PATH".to_string(), common::prepend_path(self.bins.path()));
        plan
    }

    /// The absolute fake the plan's `PATH` must resolve to.
    fn fake(&self, name: &str) -> PathBuf {
        common::fixture_bin(&self.bins, name)
    }
}

fn role_spec(role: RoleName, provider: ProviderName, writes: bool) -> RoleSpec {
    RoleSpec {
        role,
        provider,
        models: vec![CLAUDE_MODEL.to_string(), CODEX_MODEL.to_string()],
        default_model: if writes {
            CLAUDE_MODEL.to_string()
        } else {
            CODEX_MODEL.to_string()
        },
        writes,
        prompt_file: None,
        prompt_sha256: None,
        description: Some("Implements one task in its own worktree.".to_string()),
        tools: None,
        sandbox_mode: Some(if writes {
            SandboxMode::WorkspaceWrite
        } else {
            SandboxMode::ReadOnly
        }),
        max_turns: 12,
        spawn_budget_usd: 2.5,
        result_schema: if writes {
            SchemaName::BuildResult
        } else {
            SchemaName::ReviewVerdict
        },
        allowed_delegations: Vec::new(),
    }
}

/// The real post-processed artifact the supervisor passes in (design, § `schemas/`).
fn checked_in_schema(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("schemas")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&text).expect("a checked-in schema is valid JSON")
}

// ---------------------------------------------------------------------------
// Plan surgery
// ---------------------------------------------------------------------------

fn with_token(mut plan: SpawnPlan, token: &str) -> SpawnPlan {
    plan.argv.push(token.to_string());
    plan
}

/// Drops `flag` and the value that follows it.
fn without_flag(mut plan: SpawnPlan, flag: &str) -> SpawnPlan {
    let at = index_of(&plan.argv, flag);
    plan.argv.drain(at..=at + 1);
    plan
}

fn replace_flag_value(mut plan: SpawnPlan, flag: &str, value: String) -> SpawnPlan {
    let at = index_of(&plan.argv, flag);
    plan.argv[at + 1] = value;
    plan
}

fn index_of(argv: &[String], flag: &str) -> usize {
    argv.iter()
        .position(|token| token == flag)
        .unwrap_or_else(|| panic!("{flag} missing from argv: {argv:?}"))
}

fn adapter_prompt_index(combo: Combo, plan: &SpawnPlan) -> usize {
    let index = if combo.writes() {
        ClaudeAdapter.prompt_index(plan)
    } else {
        CodexAdapter.prompt_index(plan)
    };
    index.unwrap_or_else(|| {
        panic!(
            "{combo:?} adapter did not declare its prompt: {:?}",
            plan.argv
        )
    })
}

fn expected_prompt_index(combo: Combo, plan: &SpawnPlan) -> usize {
    if combo.writes() {
        1
    } else {
        plan.argv
            .len()
            .checked_sub(1)
            .expect("a Codex plan has a trailing prompt")
    }
}

/// A sandbox `--settings` document with the two knobs the check reads made explicit.
fn settings(enabled: bool, allow_write: &[&Path]) -> String {
    let allow: Vec<String> = allow_write
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    json!({
        "sandbox": {
            "enabled": enabled,
            "autoAllowBashIfSandboxed": true,
            "filesystem": { "denyWrite": ["~/"], "allowWrite": allow }
        }
    })
    .to_string()
}

/// The code a plan is rejected with, or a panic naming what was expected.
fn rejection(plan: SpawnPlan, ctx: &ArgvCtx<'_>, what: &str) -> PolicyCode {
    match assert_safe_argv(plan, ctx) {
        Ok(_) => panic!("{what} was accepted, but must be rejected"),
        Err(err) => err.code,
    }
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

#[test]
fn every_role_and_session_combination_is_accepted_as_the_adapter_built_it() {
    let fx = Fixture::new();
    for combo in ALL_COMBOS {
        let plan = fx.plan(combo);
        let argv = plan.argv.clone();
        let checked = assert_safe_argv(plan, &fx.ctx(combo.writes()))
            .unwrap_or_else(|err| panic!("{combo:?} must pass, got {err}"));
        // The chokepoint validates the argv, it never rewrites it…
        assert_eq!(checked.plan().argv, argv, "{combo:?}");
        // …but it does resolve the program, so no PATH search is left for spawn time.
        let expected = fx.fake(if combo.writes() { "claude" } else { "codex" });
        assert_eq!(checked.plan().file, expected, "{combo:?}");
    }
}

#[test]
fn a_read_only_role_carries_no_sandbox_settings_and_still_passes() {
    let fx = Fixture::new();
    for combo in [Combo::ReviewerFresh, Combo::ReviewerResume] {
        let plan = fx.plan(combo);
        assert!(
            !plan.argv.iter().any(|token| token == "--settings"),
            "{combo:?} is read-only: there is no worktree to allow"
        );
        assert!(assert_safe_argv(plan, &fx.ctx(false)).is_ok(), "{combo:?}");
    }
}

// ---------------------------------------------------------------------------
// Check 1 — the deny-list
// ---------------------------------------------------------------------------

#[test]
fn every_adapter_declares_the_prompt_token_it_actually_built() {
    let fx = Fixture::new();
    for combo in ALL_COMBOS {
        let mut plan = fx.plan(combo);
        let expected = expected_prompt_index(combo, &plan);
        assert_eq!(adapter_prompt_index(combo, &plan), expected, "{combo:?}");
        assert_eq!(plan.argv[expected], fx.prompt, "{combo:?}");

        // The declaration is a position in the adapter's layout, not a heuristic over any argv
        // token's content. A later check owns malformed-token rejection.
        plan.argv[0] = "not-the-adapter-subcommand".to_string();
        assert_eq!(adapter_prompt_index(combo, &plan), expected, "{combo:?}");
    }
}

#[test]
fn every_denied_flag_is_rejected_in_every_combination() {
    let fx = Fixture::new();
    assert_eq!(
        DENIED_ARGV.len(),
        10,
        "the design fixes ten denied tokens; a new one needs a case here"
    );
    for denied in DENIED_ARGV {
        for combo in ALL_COMBOS {
            let original = fx.plan(combo);
            let prompt_index = expected_prompt_index(combo, &original);
            // Replace every existing non-prompt token in turn, then append one more. The prompt is
            // the only position the context exempts; no adjacent or later token inherits it.
            for token_index in 0..=original.argv.len() {
                if token_index == prompt_index {
                    continue;
                }
                let mut plan = original.clone();
                if token_index == plan.argv.len() {
                    plan.argv.push((*denied).to_string());
                } else {
                    plan.argv[token_index] = (*denied).to_string();
                }
                let what = format!("{denied} at argv[{token_index}]");
                assert_eq!(
                    rejection(
                        plan,
                        &fx.ctx_with_prompt(combo.writes(), prompt_index),
                        &what
                    ),
                    PolicyCode::UnsafeArgv,
                    "{denied} at argv[{token_index}] in a {combo:?} plan"
                );
            }
        }
    }
}

#[test]
fn adapter_declared_prompts_may_contain_denied_flag_text() {
    let fx = Fixture::new();
    let chat_text =
        "run make -C build; explain --cd; quote --dangerously-skip-permissions without using it";

    for combo in ALL_COMBOS {
        let mut plan = fx.plan(combo);
        let expected = expected_prompt_index(combo, &plan);
        plan.argv[expected] = chat_text.to_string();
        let prompt_index = adapter_prompt_index(combo, &plan);
        assert!(
            assert_safe_argv(plan, &fx.ctx_with_prompt(combo.writes(), prompt_index)).is_ok(),
            "{combo:?} prompt text must be exempt only at the adapter-declared position"
        );
    }
}

#[test]
fn an_adapter_declared_prompt_starting_with_a_dash_is_rejected() {
    let fx = Fixture::new();
    for combo in ALL_COMBOS {
        let mut plan = fx.plan(combo);
        let expected = expected_prompt_index(combo, &plan);
        plan.argv[expected] = "-human-text-that-looks-like-a-flag".to_string();
        let prompt_index = adapter_prompt_index(combo, &plan);
        assert_eq!(
            rejection(
                plan,
                &fx.ctx_with_prompt(combo.writes(), prompt_index),
                "a leading-dash prompt"
            ),
            PolicyCode::UnsafeArgv,
            "{combo:?}"
        );
    }
}

#[test]
fn a_denied_flag_hidden_inside_a_larger_token_is_rejected() {
    let fx = Fixture::new();
    // `contains`, not `==`: both of these are a single argv token that smuggles an escape.
    for smuggled in [
        r#"--settings={"permissions":{"defaultMode":"bypassPermissions"}}"#,
        "--add-dir=/etc",
    ] {
        let plan = with_token(fx.plan(Combo::BuilderFresh), smuggled);
        assert_eq!(
            rejection(plan, &fx.ctx(true), smuggled),
            PolicyCode::UnsafeArgv
        );
    }
}

// ---------------------------------------------------------------------------
// Check 2 — the mandatory kernel sandbox (V4)
// ---------------------------------------------------------------------------

#[test]
fn a_writing_role_without_settings_is_sandbox_missing() {
    let fx = Fixture::new();
    for combo in [Combo::BuilderFresh, Combo::BuilderResume] {
        let plan = without_flag(fx.plan(combo), "--settings");
        assert_eq!(
            rejection(plan, &fx.ctx(true), "a builder with no --settings"),
            PolicyCode::SandboxMissing,
            "{combo:?}"
        );
    }
}

/// B1 (T62): the chokepoint keys on `sandboxed`, not on writer-hood — a read-only-shaped plan
/// (the exact argv a reviewer gets, no `--settings` at all) under a sandboxed context must be
/// refused. This is the direct guard for T64's verifier, which is sandboxed without being a
/// writer; `ArgvCtx` no longer even carries writer status, so this cannot regress silently.
#[test]
fn a_sandboxed_non_writer_without_the_settings_is_sandbox_missing() {
    let fx = Fixture::new();
    assert_eq!(
        rejection(
            fx.plan(Combo::ReviewerFresh),
            &fx.ctx(true),
            "a sandboxed non-writer with no --settings"
        ),
        PolicyCode::SandboxMissing
    );
}

#[test]
fn a_writing_role_whose_sandbox_is_disabled_is_sandbox_missing() {
    let fx = Fixture::new();
    let plan = replace_flag_value(
        fx.plan(Combo::BuilderFresh),
        "--settings",
        settings(false, &[fx.worktree()]),
    );
    assert_eq!(
        rejection(plan, &fx.ctx(true), "sandbox.enabled=false"),
        PolicyCode::SandboxMissing
    );
}

#[test]
fn a_writing_role_allowed_to_write_elsewhere_is_sandbox_missing() {
    let fx = Fixture::new();
    // A different directory entirely…
    let wrong = replace_flag_value(
        fx.plan(Combo::BuilderFresh),
        "--settings",
        settings(true, &[fx.elsewhere.path()]),
    );
    assert_eq!(
        rejection(wrong, &fx.ctx(true), "allowWrite naming another directory"),
        PolicyCode::SandboxMissing
    );
    // …and its own worktree *plus* one more: a second writable root is still a second one.
    let widened = replace_flag_value(
        fx.plan(Combo::BuilderFresh),
        "--settings",
        settings(true, &[fx.worktree(), fx.elsewhere.path()]),
    );
    assert_eq!(
        rejection(widened, &fx.ctx(true), "a widened allowWrite list"),
        PolicyCode::SandboxMissing
    );
}

// ---------------------------------------------------------------------------
// Check 3 — paths stay inside the attempt dir and the worktree
// ---------------------------------------------------------------------------

#[test]
fn an_argv_path_outside_the_attempt_dir_and_worktree_is_unsafe_argv() {
    let fx = Fixture::new();
    let outside = fx.elsewhere.path().join("last-message.txt");
    let plan = replace_flag_value(
        fx.plan(Combo::ReviewerFresh),
        "-o",
        outside.display().to_string(),
    );
    assert_eq!(
        rejection(plan, &fx.ctx(false), "an -o file outside both roots"),
        PolicyCode::UnsafeArgv
    );
}

#[test]
fn a_traversal_out_of_the_attempt_dir_is_resolved_and_rejected() {
    let fx = Fixture::new();
    let escape = fx
        .attempt_dir
        .join("../../../../../../etc/acp-owned.json")
        .display()
        .to_string();
    let plan = replace_flag_value(fx.plan(Combo::ReviewerFresh), "--output-schema", escape);
    assert_eq!(
        rejection(
            plan,
            &fx.ctx(false),
            "a `..` traversal out of the state dir"
        ),
        PolicyCode::UnsafeArgv
    );
}

#[test]
fn the_attempt_dir_files_the_adapter_names_are_inside_the_state_dir() {
    let fx = Fixture::new();
    let plan = fx.plan(Combo::ReviewerFresh);
    for flag in ["--output-schema", "-o"] {
        let value = &plan.argv[index_of(&plan.argv, flag) + 1];
        assert!(
            Path::new(value).starts_with(&fx.attempt_dir),
            "{flag} must name a file in the attempt dir, got {value}"
        );
    }
    assert!(assert_safe_argv(plan, &fx.ctx(false)).is_ok());
}

#[test]
fn a_write_files_destination_outside_both_roots_is_unsafe_argv() {
    let fx = Fixture::new();
    // argv is untouched and perfectly fine; the reach is the file `spawn_detached` would create,
    // with the daemon's privileges rather than the worker's sandboxed ones.
    let mut plan = fx.plan(Combo::ReviewerFresh);
    plan.write_files[0].0 = fx.elsewhere.path().join("output-schema.json");
    assert_eq!(
        rejection(
            plan,
            &fx.ctx(false),
            "a write_files path outside both roots"
        ),
        PolicyCode::UnsafeArgv
    );

    let mut plan = fx.plan(Combo::ReviewerFresh);
    plan.write_files[0].0 = fx.attempt_dir.join("../../../../../../etc/acp-owned.json");
    assert_eq!(
        rejection(plan, &fx.ctx(false), "a write_files traversal"),
        PolicyCode::UnsafeArgv
    );
}

// ---------------------------------------------------------------------------
// Check 4 — argv + env size
// ---------------------------------------------------------------------------

#[test]
fn an_argv_over_the_ceiling_is_argv_too_large() {
    let fx = Fixture::new();
    // 250 KB in one token: no denied substring, not a path, so checks 1-3 pass and 4 is what fires.
    let huge = "a".repeat(250_000);
    assert!(huge.len() > MAX_ARGV_BYTES);
    let plan = with_token(fx.plan(Combo::BuilderFresh), &huge);
    assert_eq!(
        rejection(plan, &fx.ctx(true), "a 250 KB argv token"),
        PolicyCode::ArgvTooLarge
    );
}

#[test]
fn the_environment_counts_towards_the_ceiling_too() {
    let fx = Fixture::new();
    // `execve` counts argv and env against one `ARG_MAX`, so a huge *value* must fail the same way
    // — and under an allowlisted key, so it is check 4 and not check 5 that rejects it.
    let mut plan = fx.plan(Combo::BuilderFresh);
    plan.env.insert("LANG".to_string(), "b".repeat(250_000));
    assert_eq!(
        rejection(plan, &fx.ctx(true), "a 250 KB env value"),
        PolicyCode::ArgvTooLarge
    );
}

// ---------------------------------------------------------------------------
// Check 5 — the worker environment
// ---------------------------------------------------------------------------

#[test]
fn an_env_key_outside_the_allowlist_is_unsafe_env() {
    let fx = Fixture::new();
    for key in [
        "ACP_STATE_DIR",
        "ACP_SOCKET",
        "AWS_SECRET_ACCESS_KEY",
        "SSH_AUTH_SOCK",
    ] {
        let mut plan = fx.plan(Combo::BuilderFresh);
        plan.env.insert(key.to_string(), "x".to_string());
        assert_eq!(
            rejection(plan, &fx.ctx(true), key),
            PolicyCode::UnsafeEnv,
            "{key} must not reach a worker"
        );
    }
}

#[test]
fn acp_fake_keys_are_the_one_pass_through() {
    let fx = Fixture::new();
    let mut plan = fx.plan(Combo::BuilderFresh);
    plan.env
        .insert("ACP_FAKE_SCENARIO".to_string(), "pass".to_string());
    plan.env
        .insert("ACP_FAKE_DELAY_MS".to_string(), "5".to_string());
    assert!(
        assert_safe_argv(plan, &fx.ctx(true)).is_ok(),
        "ACP_FAKE_* is a fixed prefix allowlist (design, § Worker environment)"
    );
}

#[test]
fn an_env_value_carrying_the_state_dir_is_unsafe_env() {
    let fx = Fixture::new();
    // The pass-through is a prefix allowlist, not a hole: a worker that learned $ACP_STATE_DIR
    // would know where the socket that approves its own gate lives.
    let mut plan = fx.plan(Combo::BuilderFresh);
    plan.env.insert(
        "ACP_FAKE_RECORD".to_string(),
        fx.state_dir
            .path()
            .join("record.jsonl")
            .display()
            .to_string(),
    );
    assert_eq!(
        rejection(
            plan,
            &fx.ctx(true),
            "an ACP_FAKE_* value under the state dir"
        ),
        PolicyCode::UnsafeEnv
    );

    // …and the same directory spelled the way `TMPDIR` reaches it is still the same directory.
    let mut plan = fx.plan(Combo::BuilderFresh);
    plan.env.insert(
        "HOME".to_string(),
        fx.state_dir
            .path()
            .canonicalize()
            .expect("canonicalize the state dir")
            .display()
            .to_string(),
    );
    assert_eq!(
        rejection(plan, &fx.ctx(true), "the canonical state dir in HOME"),
        PolicyCode::UnsafeEnv
    );
}

// ---------------------------------------------------------------------------
// The program itself
// ---------------------------------------------------------------------------

#[test]
fn the_checked_plans_path_keeps_only_absolute_entries() {
    let fx = Fixture::new();
    let mut plan = fx.plan(Combo::BuilderFresh);
    plan.env.insert(
        "PATH".to_string(),
        format!(".:{}::relative/bin", fx.bins.path().display()),
    );
    let checked =
        assert_safe_argv(plan, &fx.ctx(true)).expect("a relative entry is dropped, not fatal");
    assert_eq!(
        checked.plan().env.get("PATH").map(String::as_str),
        Some(fx.bins.path().display().to_string().as_str()),
        "`.` and an empty entry both mean the worker's own worktree"
    );
}

#[test]
fn a_provider_that_answers_only_to_a_relative_path_entry_is_unsafe_argv() {
    let fx = Fixture::new();
    // The planted binary is reachable — but only through `.`, which is the worktree.
    plant_executable(fx.worktree(), "claude", "#!/bin/sh\n: > PLANTED\n");
    let mut plan = fx.plan(Combo::BuilderFresh);
    plan.env
        .insert("PATH".to_string(), ".:relative/bin".to_string());
    assert_eq!(
        rejection(plan, &fx.ctx(true), "a provider found only through `.`"),
        PolicyCode::UnsafeArgv
    );
}

#[test]
fn a_relative_program_path_is_unsafe_argv() {
    let fx = Fixture::new();
    plant_executable(fx.worktree(), "claude", "#!/bin/sh\n: > PLANTED\n");
    let mut plan = fx.plan(Combo::BuilderFresh);
    plan.file = PathBuf::from("./claude");
    assert_eq!(
        rejection(plan, &fx.ctx(true), "a relative program path"),
        PolicyCode::UnsafeArgv
    );
}

#[test]
fn a_provider_inside_the_worktree_is_unsafe_argv_however_it_is_named() {
    let fx = Fixture::new();
    let planted = plant_executable(fx.worktree(), "claude", "#!/bin/sh\n: > PLANTED\n");

    // Named absolutely…
    let mut plan = fx.plan(Combo::BuilderFresh);
    plan.file = planted;
    assert_eq!(
        rejection(
            plan,
            &fx.ctx(true),
            "an absolute program inside the worktree"
        ),
        PolicyCode::UnsafeArgv
    );

    // …and found through an absolute PATH entry that happens to be the worktree.
    let mut plan = fx.plan(Combo::BuilderFresh);
    plan.env.insert(
        "PATH".to_string(),
        format!("{}:{}", fx.worktree().display(), fx.bins.path().display()),
    );
    assert_eq!(
        rejection(plan, &fx.ctx(true), "the worktree as a PATH entry"),
        PolicyCode::UnsafeArgv
    );
}

#[tokio::test]
async fn a_provider_planted_in_the_worktree_is_never_executed() {
    let fx = Fixture::new();
    // The attack: the worker drops an executable named `claude` in the directory it writes to, and
    // waits for the control plane — whose cwd for the spawn *is* that directory — to run it.
    plant_executable(fx.worktree(), "claude", "#!/bin/sh\n: > PLANTED\n");
    let marker = fx.worktree().join("PLANTED");
    let record = fx.repo.path().join("record.jsonl");

    let mut plan = fx.plan(Combo::BuilderFresh);
    // `.` first, exactly as a careless PATH would have it; the real bin dir is absolute and later.
    plan.env.insert(
        "PATH".to_string(),
        format!(".:{}", fx.bins.path().display()),
    );
    plan.env
        .insert("ACP_FAKE_SCENARIO".to_string(), "pass".to_string());
    plan.env
        .insert("ACP_FAKE_RECORD".to_string(), record.display().to_string());

    let checked = assert_safe_argv(plan, &fx.ctx(true)).expect("the absolute entry still resolves");
    assert_eq!(
        checked.plan().file,
        fx.fake("claude"),
        "the `.` entry must not win the lookup"
    );

    let mut spawned = spawn_detached(checked, fx.attempt_dir.clone())
        .await
        .expect("spawn the resolved provider");
    let status = spawned.child.wait().await.expect("wait for the provider");
    assert!(
        status.success(),
        "the real fake ran, got {status}; its stderr was {:?}",
        read(&fx.attempt_dir.join("stderr.log"))
    );
    assert!(
        !marker.exists(),
        "the planted `claude` was executed — {} exists",
        marker.display()
    );
    assert!(record.exists(), "the fake provider is what ran");
}

#[test]
fn a_symlinked_provider_planted_in_the_worktree_is_rejected_and_never_runs() {
    let fx = Fixture::new();
    // The dodge: `<worktree>/codex -> /bin/sh`. Follow the final symlink and the target is a
    // blameless system binary — but a Codex argv opens with the token `exec`, so `sh` would read a
    // script by that name out of its current directory, which is the worktree the worker writes to.
    std::os::unix::fs::symlink("/bin/sh", fx.worktree().join("codex")).expect("plant the symlink");
    plant_executable(fx.worktree(), "exec", "#!/bin/sh\n: > PLANTED\n");
    let marker = fx.worktree().join("PLANTED");

    // Found through the worktree as an absolute PATH entry…
    let mut plan = fx.plan(Combo::ReviewerFresh);
    plan.env.insert(
        "PATH".to_string(),
        format!("{}:{}", fx.worktree().display(), fx.bins.path().display()),
    );
    assert_eq!(
        rejection(plan, &fx.ctx(false), "a symlinked provider in the worktree"),
        PolicyCode::UnsafeArgv
    );

    // …and named absolutely.
    let mut plan = fx.plan(Combo::ReviewerFresh);
    plan.file = fx.worktree().join("codex");
    assert_eq!(
        rejection(plan, &fx.ctx(false), "an absolute symlink in the worktree"),
        PolicyCode::UnsafeArgv
    );

    // Rejected means never spawned: nothing under the worktree ran.
    assert!(
        !marker.exists(),
        "the worker's `exec` script ran — {} exists",
        marker.display()
    );
}

#[test]
fn a_symlinked_provider_outside_the_worktree_is_still_welcome() {
    let fx = Fixture::new();
    // How a real CLI is installed: `/opt/homebrew/bin/claude -> ../Cellar/…`. The fixture bin dir
    // is exactly that shape, so the happy-path tests already depend on this — asserted once here so
    // a future tightening of the symlink rule fails loudly rather than in production.
    let resolved = fx.fake("claude");
    assert!(
        std::fs::symlink_metadata(&resolved)
            .expect("the fixture provider exists")
            .file_type()
            .is_symlink(),
        "the fixture CLI is reached through a symlink"
    );
    let checked =
        assert_safe_argv(fx.plan(Combo::BuilderFresh), &fx.ctx(true)).expect("a symlink elsewhere");
    assert_eq!(checked.plan().file, resolved);
}

/// Writes an executable file — a worker planting a program in its own worktree.
fn plant_executable(dir: &Path, name: &str, script: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, script).expect("write the planted program");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod +x");
    path
}

// ---------------------------------------------------------------------------
// Order
// ---------------------------------------------------------------------------

#[test]
fn a_plan_that_fails_several_checks_reports_the_first_one() {
    let fx = Fixture::new();

    // Denied token (1) + no sandbox (2) + oversized (4) + bad env (5) → the denied token.
    let mut worst = with_token(
        without_flag(fx.plan(Combo::BuilderFresh), "--settings"),
        "--dangerously-skip-permissions",
    );
    worst.argv.push("a".repeat(250_000));
    worst
        .env
        .insert("ACP_STATE_DIR".to_string(), "x".to_string());
    assert_eq!(
        rejection(worst, &fx.ctx(true), "a plan failing checks 1, 2, 4 and 5"),
        PolicyCode::UnsafeArgv
    );

    // No sandbox (2) + bad env (5) → the sandbox.
    let mut no_sandbox = without_flag(fx.plan(Combo::BuilderFresh), "--settings");
    no_sandbox
        .env
        .insert("ACP_STATE_DIR".to_string(), "x".to_string());
    assert_eq!(
        rejection(no_sandbox, &fx.ctx(true), "a plan failing checks 2 and 5"),
        PolicyCode::SandboxMissing
    );

    // Oversized (4) + bad env (5) → the size.
    let mut oversized = with_token(fx.plan(Combo::BuilderFresh), &"a".repeat(250_000));
    oversized
        .env
        .insert("ACP_STATE_DIR".to_string(), "x".to_string());
    assert_eq!(
        rejection(oversized, &fx.ctx(true), "a plan failing checks 4 and 5"),
        PolicyCode::ArgvTooLarge
    );
}

// ---------------------------------------------------------------------------
// spawn_detached
// ---------------------------------------------------------------------------

#[tokio::test]
async fn spawn_detached_writes_the_attempt_inputs_and_runs_the_fake_claude() {
    let fx = Fixture::new();
    // The record file lives in the worktree, never under the state dir: its path travels in the
    // environment, and check 5 forbids the state dir doing that.
    let record = fx.repo.path().join("record.jsonl");

    let mut plan = fx.plan(Combo::BuilderFresh);
    plan.env
        .insert("ACP_FAKE_SCENARIO".to_string(), "pass".to_string());
    plan.env
        .insert("ACP_FAKE_RECORD".to_string(), record.display().to_string());
    let argv = plan.argv.clone();

    let checked = assert_safe_argv(plan, &fx.ctx(true)).expect("a real builder plan is safe");
    let mut spawned = spawn_detached(checked, fx.attempt_dir.clone())
        .await
        .expect("spawn the fake provider");
    assert_eq!(
        spawned.pgid, spawned.pid,
        "a detached child leads its group"
    );
    assert!(
        !spawned.start_time.is_empty(),
        "`ps -o lstart=` recorded a start time"
    );
    let status = spawned.child.wait().await.expect("wait for the fake");
    assert!(
        status.success(),
        "the `pass` scenario exits 0, got {status}; the fake's stderr was {:?}",
        read(&fx.attempt_dir.join("stderr.log"))
    );

    // The attempt's inputs, on disk before the spawn (design, § On-disk layout).
    let recorded: Vec<String> =
        serde_json::from_str(&read(&fx.attempt_dir.join("argv.json"))).expect("argv.json is JSON");
    assert_eq!(recorded, argv);
    assert_eq!(read(&fx.attempt_dir.join("prompt.txt")), fx.prompt);
    assert!(
        !read(&fx.attempt_dir.join("stdout.jsonl")).is_empty(),
        "the provider's stream was captured"
    );
    assert!(fx.attempt_dir.join("stderr.log").exists());

    // What the child actually received. `argv` here is the whole plan vector: the program is
    // `plan.file`, so slicing `argv[1..]` would have dropped `-p` and fed the prompt as a flag.
    let line: Value = serde_json::from_str(read(&record).trim()).expect("the record line is JSON");
    assert_eq!(line["argv"], json!(argv));
    // The fake reports `current_dir()`, which is the worktree with every symlink resolved — on
    // macOS a temp dir's `/var/…` really is `/private/var/…`.
    assert_eq!(
        line["cwd"],
        json!(fx
            .repo
            .path()
            .canonicalize()
            .expect("canonicalize the worktree")
            .display()
            .to_string())
    );
    // The env scrub reached the child: only the two `ACP_FAKE_*` keys survived (T25 covers the
    // rest of the allowlist against the same record).
    assert_eq!(
        line["envSubset"]["acpEnvKeys"],
        json!(["ACP_FAKE_RECORD", "ACP_FAKE_SCENARIO"])
    );
}

#[tokio::test]
async fn spawn_detached_writes_the_plans_input_files_for_the_fake_codex() {
    let fx = Fixture::new();
    let mut plan = fx.plan(Combo::ReviewerFresh);
    plan.env
        .insert("ACP_FAKE_SCENARIO".to_string(), "pass".to_string());
    assert_eq!(plan.write_files.len(), 1, "codex needs its schema on disk");

    let checked = assert_safe_argv(plan, &fx.ctx(false)).expect("a real reviewer plan is safe");
    let mut spawned = spawn_detached(checked, fx.attempt_dir.clone())
        .await
        .expect("spawn the fake provider");
    let status = spawned.child.wait().await.expect("wait for the fake");
    assert!(
        status.success(),
        "the `pass` scenario exits 0, got {status}; the fake's stderr was {:?}",
        read(&fx.attempt_dir.join("stderr.log"))
    );

    // `SpawnPlan.write_files` — the schema document the CLI opens by path (adapters stay pure).
    let schema: Value = serde_json::from_str(&read(&fx.attempt_dir.join("output-schema.json")))
        .expect("output-schema.json is JSON");
    assert_eq!(schema, fx.review_schema);
    // Written by the child into the attempt dir, i.e. the `-o` path survived the argv check intact.
    assert!(fx.attempt_dir.join("last-message.txt").exists());
}

#[tokio::test]
async fn a_detached_worker_leads_its_own_process_group_and_dies_to_killpg() {
    let fx = Fixture::new();
    let mut plan = fx.plan(Combo::BuilderFresh);
    // `hang` writes one line and then sleeps until it is signalled.
    plan.env
        .insert("ACP_FAKE_SCENARIO".to_string(), "hang".to_string());

    let checked = assert_safe_argv(plan, &fx.ctx(true)).expect("a real builder plan is safe");
    let mut spawned = spawn_detached(checked, fx.attempt_dir.clone())
        .await
        .expect("spawn the fake provider");
    let pid = Pid::from_raw(spawned.pid);

    // It is running: the first line of its stream has landed.
    let stdout = fx.attempt_dir.join("stdout.jsonl");
    let running = wait_until(Duration::from_secs(10), || {
        std::fs::metadata(&stdout).map(|m| m.len()).unwrap_or(0) > 0
    })
    .await;
    assert!(
        running,
        "the fake never wrote its first line; its stderr was {:?}",
        read(&fx.attempt_dir.join("stderr.log"))
    );

    // `process_group(0)`: its own group, and *not* the test runner's — which is the whole reason
    // the timeout ladder may `killpg` at all.
    let group = getpgid(Some(pid)).expect("getpgid of the child");
    assert_eq!(group, pid, "the child leads its own process group");
    assert_ne!(
        group,
        getpgid(None).expect("getpgid of this process"),
        "signalling that group must not signal the test runner"
    );

    killpg(group, Signal::SIGKILL).expect("killpg the worker's group");
    let status = tokio::time::timeout(Duration::from_secs(10), spawned.child.wait())
        .await
        .expect("the killed worker exits")
        .expect("wait for the worker");
    assert!(!status.success());
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(Signal::SIGKILL as i32),
        "the worker died to the signal sent to its group"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// Polls `ready` on a 25 ms tick — the same tick the design injects into supervisor tests.
async fn wait_until(limit: Duration, ready: impl Fn() -> bool) -> bool {
    let deadline = std::time::Instant::now() + limit;
    while std::time::Instant::now() < deadline {
        if ready() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    ready()
}

// ---------------------------------------------------------------------------
// Check 2, the codex arm (C1/T67) — the measured workspace-write shape, item by item
// ---------------------------------------------------------------------------

/// The real adapter's sandboxed plans, fresh and resumed — built exactly as the loop builds them.
impl Fixture {
    fn codex_sandboxed_plan(&self, resume: bool) -> SpawnPlan {
        let req = SpawnRequest {
            role: &self.reviewer,
            model: CODEX_MODEL,
            prompt: &self.prompt,
            role_prompt: &self.role_prompt,
            cwd: self.repo.path(),
            attempt_dir: &self.attempt_dir,
            state_dir: self.state_dir.path(),
            lead_run_id: None,
            schema: ("review-verdict", &self.review_schema),
            max_turns: 12,
            spawn_budget_usd: 2.5,
            sandbox: Some(SandboxSpec {
                worktree: self.repo.path(),
            }),
            session_id: resume.then_some(CODEX_THREAD),
            effort: None,
        };
        let mut plan = if resume {
            CodexAdapter.build_resume(&req)
        } else {
            CodexAdapter.build_fresh(&req)
        };
        plan.env
            .insert("PATH".to_string(), common::prepend_path(self.bins.path()));
        plan
    }
}

#[test]
fn a_sandboxed_codex_plan_passes_on_both_paths() {
    let fx = Fixture::new();
    for resume in [false, true] {
        assert_safe_argv(
            fx.codex_sandboxed_plan(resume),
            &fx.ctx_for(ProviderName::Codex, true),
        )
        .unwrap_or_else(|err| {
            panic!("the adapter's own sandboxed plan passes (resume={resume}): {err:?}")
        });
    }
}

/// Every confinement item is individually load-bearing: strip one, and the refusal names it.
#[test]
fn stripping_any_codex_confinement_item_is_sandbox_missing_and_names_it() {
    let fx = Fixture::new();
    for (token, hint) in [
        (r#"sandbox_mode="workspace-write""#, "sandbox_mode"),
        (
            "sandbox_workspace_write.exclude_slash_tmp=true",
            "exclude_slash_tmp",
        ),
        (
            "sandbox_workspace_write.exclude_tmpdir_env_var=true",
            "exclude_tmpdir_env_var",
        ),
        (
            "sandbox_workspace_write.writable_roots=[]",
            "writable_roots",
        ),
    ] {
        let mut plan = fx.codex_sandboxed_plan(false);
        let at = plan
            .argv
            .iter()
            .position(|t| t == token)
            .unwrap_or_else(|| panic!("{token} is in the adapter's plan"));
        // Drop the `-c` and its value together.
        plan.argv.drain(at - 1..=at);
        let err = assert_safe_argv(plan, &fx.ctx_for(ProviderName::Codex, true))
            .expect_err("a stripped confinement item must refuse");
        assert_eq!(err.code, PolicyCode::SandboxMissing, "{token}");
        assert!(
            err.reason.contains(hint),
            "the refusal names the missing item ({hint}): {}",
            err.reason
        );
    }

    // `--ignore-user-config` is a bare flag, not a `-c` pair.
    let mut plan = fx.codex_sandboxed_plan(false);
    let at = plan
        .argv
        .iter()
        .position(|t| t == "--ignore-user-config")
        .expect("in the plan");
    plan.argv.remove(at);
    let err = assert_safe_argv(plan, &fx.ctx_for(ProviderName::Codex, true))
        .expect_err("without --ignore-user-config the user's config could widen the seatbelt");
    assert_eq!(err.code, PolicyCode::SandboxMissing);
    assert!(err.reason.contains("ignore-user-config"), "{}", err.reason);
}

/// The cwd IS the writable root: a sandboxed codex plan whose cwd is not the worktree is refused
/// even with every flag present.
#[test]
fn a_sandboxed_codex_plan_with_a_foreign_cwd_is_sandbox_missing() {
    let fx = Fixture::new();
    let mut plan = fx.codex_sandboxed_plan(false);
    plan.cwd = fx.elsewhere.path().to_path_buf();
    let err = assert_safe_argv(plan, &fx.ctx_for(ProviderName::Codex, true))
        .expect_err("cwd pins the writable root");
    assert_eq!(err.code, PolicyCode::SandboxMissing);
    assert!(err.reason.contains("cwd"), "{}", err.reason);
}

/// The false-positive class that BLOCKED THE LOOP live during T68: worker-authored free text
/// (a build summary quoted into the reviewer's prompt) legitimately says "workspace-write", and
/// the confused-plan check must be flag-position-aware, never a substring scan. A read-only
/// codex plan whose PROMPT contains the phrase passes.
#[test]
fn a_read_only_codex_plan_whose_prompt_mentions_workspace_write_passes() {
    let fx = Fixture::new();
    let mut plan = fx.plan(Combo::ReviewerFresh);
    let last = plan.argv.len() - 1;
    plan.argv[last] = format!(
        "{} The builder reported: added the file under the codex workspace-write seatbelt.",
        plan.argv[last]
    );
    assert_safe_argv(plan, &fx.ctx_for(ProviderName::Codex, false))
        .expect("free text saying workspace-write is not a workspace-write plan");
}

/// The confused-plan refusal: a read-only codex context must never accept workspace-write
/// tokens — a mislabeled context cannot widen a seatbelt.
#[test]
fn a_read_only_codex_plan_carrying_workspace_write_is_refused() {
    let fx = Fixture::new();
    let plan = fx.codex_sandboxed_plan(false);
    let err = assert_safe_argv(plan, &fx.ctx_for(ProviderName::Codex, false))
        .expect_err("workspace-write tokens under a read-only context are a confused plan");
    assert_eq!(err.code, PolicyCode::SandboxMissing);
}

/// A `-s` that names anything but workspace-write on a sandboxed plan is refused, even with the
/// `-c` pair present — the two spellings must agree.
#[test]
fn a_sandboxed_codex_plan_with_a_disagreeing_dash_s_is_refused() {
    let fx = Fixture::new();
    let mut plan = fx.codex_sandboxed_plan(false);
    let at = plan.argv.iter().position(|t| t == "-s").expect("-s");
    plan.argv[at + 1] = "read-only".to_string();
    let err = assert_safe_argv(plan, &fx.ctx_for(ProviderName::Codex, true))
        .expect_err("-s and -c sandbox_mode must agree");
    assert_eq!(err.code, PolicyCode::SandboxMissing);
}
