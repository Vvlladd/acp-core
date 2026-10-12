//! Codex adapter: `codex exec --strict-config`, `-c mcp_servers={}`, thread events.
//! Implemented in T16 (`reports/03-design.md` § `src/providers`).
//!
//! Rules this module exists to enforce (design, § "Exact argv (order is load-bearing)"):
//!
//! - **The prompt is the trailing positional.** `codex exec` takes the prompt last, and
//!   `codex exec resume` takes `<threadId> <PROMPT>` in that order. Every flag therefore has to be
//!   emitted before it, and none of them may be variadic.
//! - **Resume carries no `-s`, no `-C`, no `-p`.** `codex exec resume` rejects those flags
//!   (`reports/02-exploration.md` § "Codex `codex exec --json …`"), so the sandbox travels as
//!   `-c sandbox_mode=<mode>` alone and the cwd travels as the child's actual working
//!   directory — never `-C`, on either path, because a resumed thread must run from the cwd it
//!   started in (C3). Since C1 the mode is `workspace-write` for a sandboxed role (writer or
//!   verifier), with the measured confinement keys, and `read-only` otherwise.
//!   `--ignore-user-config` now travels on BOTH paths; `codex exec --help` proves it for fresh,
//!   and `live_codex_pong_and_resume` is the resume-acceptance proof — it MUST be re-run before
//!   C1 ships (no `codex exec resume --help` capture exists in the repo).
//! - **`-c mcp_servers={}`** on both paths: a worker inherits no MCP server, so it can never reach
//!   this control plane's own tools (C1 — Codex launches MCP servers *outside* its seatbelt).
//! - The role body travels **inline** as `-c developer_instructions=<quoted>`; the result schema
//!   travels as a **file** the supervisor writes from [`SpawnPlan::write_files`], because adapters
//!   are pure and never touch the filesystem.
//!
//! The parser's one non-obvious rule: an `item.completed` whose `item.type` is `error` is a
//! **config-deprecation warning**, present in every real capture (`fixtures/jsonl/README.md`
//! § `codex/`). It is a phase, never a `Final` and never a [`NormalizedEvent::Error`] — the only
//! line that fails a turn is `turn.failed`.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{
    base_env, find_on_path, NormalizedEvent, ProviderAdapter, RawResult, ResultCtx, SpawnPlan,
    SpawnRequest,
};
use crate::core::team::Effort;
use crate::core::types::{AttemptError, ErrorCode, ProviderName, TokenUsage};

#[path = "codex_lead.rs"]
pub(crate) mod lead;

/// The program name. Bare, not absolute: `PATH` resolution happens at spawn time, against the same
/// `PATH` [`ProviderAdapter::preflight`] searches.
const PROGRAM: &str = "codex";

/// The sandbox mode of one Codex attempt, as both `-s <mode>` (fresh only) and
/// `-c sandbox_mode=<mode>` — a projection of the request (C1): `workspace-write` when the
/// caller attached a [`SandboxSpec`], `read-only` otherwise. Both modes are seatbelt-enforced
/// (`docs/research/2026-08-28-phase2-daemon.md` § 2 — measured verdict table), and
/// `assert_safe_argv`'s codex arm asserts the emitted shape.
///
/// [`SandboxSpec`]: super::SandboxSpec
fn sandbox_mode(req: &SpawnRequest<'_>) -> &'static str {
    if req.sandbox.is_some() {
        "workspace-write"
    } else {
        "read-only"
    }
}

/// The codex-cli version the workspace-write seatbelt verdict table was measured against
/// (`docs/research/2026-08-28-phase2-daemon.md` § 2: worktree ALLOW; both `.git`s, `$HOME`,
/// `~/.acp`, the socket and the network DENY; residual `$CODEX_HOME/memories` ALLOW). A codex
/// upgrade can silently change any row, so `doctor` warns when the installed version differs.
pub const SANDBOX_VERIFIED_VERSION: &str = "0.132.0";

/// Never ask a human mid-turn: an unattended worker has no one to answer the prompt, and the
/// sandbox — not an approval dialog — is what bounds it.
const APPROVAL_POLICY: &str = "never";

/// `-c model_reasoning_effort=` for a fresh thread when the team named none. Absent from the resume
/// argv (design, § "Exact argv"): a resumed thread keeps the effort it was started with.
const REASONING_EFFORT: &str = "medium";

/// What `codex` writes to stderr when it cannot authenticate, matched case-insensitively and
/// anywhere in the head of `stderr.log` (design, § Error Handling → `provider_unauthenticated`).
///
/// **The contract is `src/bin/fake-codex.rs`'s `auth_fail` scenario**, which reproduces the shape
/// of the real 401 captured on 2026-08-22: `ERROR: 401 Unauthorized · run \`codex login\`` followed
/// by `stream error: {"error":{"type":"authentication_error","message":"missing or expired
/// credentials in CODEX_HOME/auth.json"}}`. The real CLI also words the second half
/// `Not logged in: run \`codex login\``, which the first entry below covers.
const AUTH_SIGNATURES: [&str; 3] = ["codex login", "authentication_error", "401 unauthorized"];

/// Written into the attempt dir by the supervisor and passed as `--output-schema`.
const OUTPUT_SCHEMA_FILE: &str = "output-schema.json";

/// `-o <attemptDir>/last-message.txt`: Codex writes only the final `agent_message` there, which is
/// the schema-conformant document [`ProviderAdapter::extract_result`] reads back through
/// [`ResultCtx::last_message`].
const LAST_MESSAGE_FILE: &str = "last-message.txt";

/// Longest worker-authored string a [`NormalizedEvent::Phase`] note carries into the event log. A
/// `command_execution` command is written by the model and can be an arbitrarily long heredoc; the
/// note exists to say *what the worker is doing*, not to archive it.
const MAX_NOTE_BYTES: usize = 512;

/// The `codex` CLI, reduced to argv construction and line parsing.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CodexAdapter;

impl CodexAdapter {
    /// The flags shared by `exec` and `exec resume`, in the design's order — everything between the
    /// subcommand and the trailing positionals.
    ///
    /// `sandbox` and `reasoning` are the only two differences between the two argv shapes: `-s` is
    /// rejected by `exec resume`, and the design's resume line carries no `model_reasoning_effort`.
    fn shared_argv(req: &SpawnRequest<'_>, sandbox: bool, reasoning: bool) -> Vec<String> {
        let mode = sandbox_mode(req);
        let mut argv = vec![
            "--json".to_string(),
            "--strict-config".to_string(),
            // C1: the user's own `~/.codex/config.toml` must not steer a worker —
            // `sandbox_workspace_write.writable_roots` set there would silently WIDEN the
            // seatbelt (measured), and `--strict-config` only rejects unknown keys, not that.
            // On every spawn, both paths, both modes; auth still uses `CODEX_HOME`.
            "--ignore-user-config".to_string(),
            "-m".to_string(),
            req.model.to_string(),
        ];
        if sandbox {
            argv.push("-s".to_string());
            argv.push(mode.to_string());
        }
        push_quoted(&mut argv, "approval_policy", APPROVAL_POLICY);
        push_quoted(&mut argv, "sandbox_mode", mode);
        if req.sandbox.is_some() {
            // C1's measured confinement set (research § 2, items 2-3): both default temp roots
            // excluded (typed bools), and the widening lever pinned to an explicit empty list so
            // an inherited value can never add a writable root. The worktree itself is pinned by
            // cwd — codex derives the writable root from the child's working directory, never
            // from `-C` (which the denied-argv list refuses anyway).
            push_raw(
                &mut argv,
                "sandbox_workspace_write.exclude_slash_tmp",
                "true",
            );
            push_raw(
                &mut argv,
                "sandbox_workspace_write.exclude_tmpdir_env_var",
                "true",
            );
            push_raw(&mut argv, "sandbox_workspace_write.writable_roots", "[]");
        }
        // A bare `{}` — an empty inline table, not a quoted string, or `--strict-config` rejects it.
        push_raw(&mut argv, "mcp_servers", "{}");
        if reasoning {
            // The team's effort when it named one, the configured constant otherwise (Rev 26).
            // Both spellings come out of a closed allowlist — `Effort` is an enum and
            // `validate_team` checks it against `providers.codex.efforts` **and** the model's own
            // `modelEfforts` list (Rev 28) — so nothing a human wrote in `team.json` reaches this
            // argv position unchecked. That validation is the only per-model bound on a worker:
            // unlike the lead (`lead::check_plan`), this adapter re-checks nothing itself, and a
            // recorded `{model, effort}` pair replays as recorded (T88) even if the catalog later
            // narrows that model — the API, not the sandbox, is what would then refuse it.
            let effort = req.effort.map_or(REASONING_EFFORT, Effort::as_str);
            push_quoted(&mut argv, "model_reasoning_effort", effort);
        }
        push_quoted(&mut argv, "developer_instructions", req.role_prompt);
        argv.push("--output-schema".to_string());
        argv.push(path_arg(&req.attempt_dir.join(OUTPUT_SCHEMA_FILE)));
        argv.push("-o".to_string());
        argv.push(path_arg(&req.attempt_dir.join(LAST_MESSAGE_FILE)));
        argv
    }

    /// Wraps a finished argv in the plan both paths share: bare program, the request's cwd (never
    /// `-C`), the worker env allowlist, and the one file the CLI needs on disk.
    fn plan(req: &SpawnRequest<'_>, argv: Vec<String>) -> SpawnPlan {
        SpawnPlan {
            required_version: None,
            file: PathBuf::from(PROGRAM),
            argv,
            cwd: req.cwd.to_path_buf(),
            env: base_env(),
            write_files: vec![(
                req.attempt_dir.join(OUTPUT_SCHEMA_FILE),
                // `Display for Value` is compact JSON and cannot fail, so the pure adapter needs no
                // `Result` here. The document is already `$schema`-stripped by the caller (V7).
                req.schema.1.to_string(),
            )],
        }
    }
}

impl ProviderAdapter for CodexAdapter {
    fn name(&self) -> ProviderName {
        ProviderName::Codex
    }

    fn build_fresh(&self, req: &SpawnRequest<'_>) -> SpawnPlan {
        if req.role.role == crate::core::types::RoleName::Lead { return lead::plan(req, false); }
        let mut argv = vec!["exec".to_string()];
        argv.extend(Self::shared_argv(req, true, true));
        argv.push(req.prompt.to_string());
        Self::plan(req, argv)
    }

    fn build_resume(&self, req: &SpawnRequest<'_>) -> SpawnPlan {
        if req.role.role == crate::core::types::RoleName::Lead { return lead::plan(req, true); }
        let thread_id = req
            .session_id
            .expect("build_resume requires SpawnRequest::session_id (design § src/providers)");
        let mut argv = vec!["exec".to_string(), "resume".to_string()];
        argv.extend(Self::shared_argv(req, false, false));
        argv.push(thread_id.to_string());
        argv.push(req.prompt.to_string());
        Self::plan(req, argv)
    }

    fn prompt_index(&self, plan: &SpawnPlan) -> Option<usize> {
        plan.argv.len().checked_sub(1)
    }

    fn preflight(&self, req: &SpawnRequest<'_>) -> Option<AttemptError> {
        if find_on_path(PROGRAM).is_none() {
            return Some(AttemptError {
                code: ErrorCode::ProviderMissing,
                message: format!("`{PROGRAM}` was not found on PATH"),
            });
        }
        // Resume only: `codex exec resume` has no `-C`, so the thread's recorded cwd has to still
        // be there for the child to start in it (C3).
        if req.session_id.is_some() && !req.cwd.is_dir() {
            return Some(AttemptError {
                code: ErrorCode::ResumeTargetMissing,
                message: format!("resume cwd no longer exists: {}", req.cwd.display()),
            });
        }
        None
    }

    fn parse_line(&self, line: &str) -> Vec<NormalizedEvent> {
        let Ok(value) = serde_json::from_str::<Value>(line.trim()) else {
            return Vec::new();
        };
        let Some(kind) = value.get("type").and_then(Value::as_str) else {
            return Vec::new();
        };
        match kind {
            // Line 1 of every transcript. Its absence is what the supervisor classifies as
            // `no_session`; see `extract_result`.
            "thread.started" => str_field(&value, "thread_id")
                .map(|thread_id| NormalizedEvent::Session {
                    session_id: thread_id.to_string(),
                })
                .into_iter()
                .collect(),
            "turn.started" => vec![NormalizedEvent::Phase {
                phase: kind.to_string(),
                note: None,
            }],
            // Both edges of an item report the same phase — "what the worker is doing" — including
            // the `error` item, which is the config-deprecation warning every real capture carries
            // (see the module comment). Misreading it as a failure would fail every attempt.
            "item.started" | "item.completed" => {
                let mut events: Vec<_> = item_phase(&value).into_iter().collect();
                if kind == "item.completed" && value["item"]["type"] == "agent_message" {
                    if let Some(text) = value["item"]["text"].as_str() {
                        events.extend(super::message_parts(text, 0));
                    }
                }
                events
            },
            // Usage and explicit terminal evidence are separate: the supervisor needs the latter
            // after reattachment, while the final result is still read from the output file.
            "turn.completed" => vec![usage_event(&value), NormalizedEvent::Completed],
            "turn.failed" => vec![NormalizedEvent::Final {
                ok: false,
                text: Some(
                    value
                        .get("error")
                        .and_then(|error| str_field(error, "message"))
                        .unwrap_or("codex reported turn.failed with no error message")
                        .to_string(),
                ),
                structured: None,
                stop_reason: Some(kind.to_string()),
                cost_usd: None,
                tokens: None,
                error_code: Some(ErrorCode::ProviderError),
            }],
            // A top-level `error` line: the API call behind the turn failed. Not fatal by itself —
            // Codex may retry, and when it does not the `turn.failed` line above is what ends the
            // attempt. Killing the child here would pre-empt the CLI's own recovery.
            "error" => str_field(&value, "message")
                .map(|message| NormalizedEvent::Error {
                    message: message.to_string(),
                    fatal: false,
                })
                .into_iter()
                .collect(),
            _ => Vec::new(),
        }
    }

    fn extract_result(&self, ctx: &ResultCtx<'_>) -> RawResult {
        // Checked before anything on the stream, because there is nothing on the stream: a CLI that
        // could not log in exits non-zero without emitting `thread.started`, so the only trace is
        // the signature it left on stderr. Reporting it is what separates an environment failure a
        // human must fix (17a, no strike) from `no_session`, which is strikeable (§ Error Handling).
        if super::is_auth_failure(ctx, &AUTH_SIGNATURES) {
            return RawResult {
                ok: false,
                error_code: Some(ErrorCode::ProviderUnauthenticated),
                ..RawResult::default()
            };
        }
        let session_id = ctx.events.iter().rev().find_map(|event| match event {
            NormalizedEvent::Session { session_id } => Some(session_id.clone()),
            _ => None,
        });
        // No `thread.started` was ever parsed, so no thread exists to resume. Reporting the absence
        // is this function's job; calling it `no_session` (and deciding the attempt is not
        // resumable) is the supervisor's — design, § Error Handling.
        let Some(session_id) = session_id else {
            return RawResult::default();
        };

        // A failed Final is authoritative; Completed records success separately from the output file.
        if let Some(NormalizedEvent::Final {
            ok,
            text,
            structured,
            error_code,
            ..
        }) = ctx
            .events
            .iter()
            .rev()
            .find(|event| matches!(event, NormalizedEvent::Final { .. }))
        {
            return RawResult {
                ok: *ok,
                text: text.clone(),
                structured: structured.clone(),
                error_code: *error_code,
                session_id: Some(session_id),
            };
        }

        // Codex's stream has no verdict field — nothing here corresponds to Claude's
        // `result.is_error` — so success is exactly "a `turn.completed` was seen and no
        // `turn.failed` was". The result text is the `-o` file the CLI was told to write its final
        // message to; an empty or missing one leaves `structured` unset, and the supervisor's
        // schema check turns that into `invalid_output`.
        let turn_completed = ctx
            .events
            .iter()
            .any(|event| matches!(event, NormalizedEvent::Completed));
        let body = ctx
            .last_message
            .map(str::trim)
            .filter(|body| !body.is_empty());
        RawResult {
            ok: turn_completed,
            text: body.map(str::to_string),
            structured: body.and_then(|body| serde_json::from_str::<Value>(body).ok()),
            error_code: None,
            session_id: Some(session_id),
        }
    }
}

/// Pushes `-c <key>=<value>` as the two argv elements Codex expects, with `value` written verbatim
/// — for a value that is TOML syntax (`{}`) rather than a string.
fn push_raw(argv: &mut Vec<String>, key: &str, value: &str) {
    argv.push("-c".to_string());
    argv.push(format!("{key}={value}"));
}

/// Pushes `-c <key>="<value>"`, quoting the value as a JSON string literal — which is also a valid
/// TOML basic string, so a role prompt full of quotes, backslashes and newlines survives
/// `--strict-config` intact.
fn push_quoted(argv: &mut Vec<String>, key: &str, value: &str) {
    push_raw(argv, key, &Value::String(value.to_string()).to_string());
}

/// A path as an argv element. Attempt-dir paths are control-plane-built and UTF-8 in practice; a
/// lossy conversion keeps the pure adapter free of a `Result` it could never act on.
fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// `item.started` / `item.completed` → the phase named by `item.type`, annotated with the item's
/// own one-line descriptor (`command` for a `command_execution`, `message` for an `error`). An
/// `agent_message` gets no note: its text is the result, and it travels through the `-o` file.
fn item_phase(value: &Value) -> Option<NormalizedEvent> {
    let item = value.get("item")?;
    let phase = str_field(item, "type")?;
    let note = ["command", "message"]
        .iter()
        .find_map(|key| str_field(item, key))
        .map(truncate_note);
    Some(NormalizedEvent::Phase {
        phase: phase.to_string(),
        note,
    })
}

/// `turn.completed` → the four token counts, verbatim. Codex reports no dollar figure, so cost is
/// computed later from `roles.json`'s rate table (`CostSource::RateTable`), never guessed here.
fn usage_event(value: &Value) -> NormalizedEvent {
    let usage = value.get("usage");
    let count = |key: &str| {
        usage
            .and_then(|usage| usage.get(key))
            .and_then(Value::as_u64)
    };
    NormalizedEvent::Usage {
        tokens: TokenUsage {
            input: count("input_tokens").unwrap_or(0),
            cached_input: count("cached_input_tokens").unwrap_or(0),
            output: count("output_tokens").unwrap_or(0),
            reasoning: count("reasoning_output_tokens"),
        },
        cost_usd: None,
    }
}

/// Caps a phase note at [`MAX_NOTE_BYTES`], cutting on a char boundary so a multi-byte character is
/// never split, and marking the cut so a human reading the log knows there was more.
fn truncate_note(note: &str) -> String {
    if note.len() <= MAX_NOTE_BYTES {
        return note.to_string();
    }
    let mut end = MAX_NOTE_BYTES;
    while end > 0 && !note.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &note[..end])
}
