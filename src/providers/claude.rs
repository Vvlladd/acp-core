//! Claude Code adapter: inline `--agents` role, kernel sandbox settings, cwd-scoped `--resume`.
//! Implemented in T14 (`reports/03-design.md` § `src/providers`).
//!
//! Everything provider-specific about Claude lives here: the argv shape verified in Phase 2, the
//! `--output-format stream-json` line grammar, and the mapping from a `result` line to a terminal
//! result. The adapter is pure — it reads a [`SpawnRequest`] and returns a [`SpawnPlan`]; the
//! supervisor spawns, and `assert_safe_argv` is the thing that *enforces* what is built here.
//!
//! Three properties of the argv are load-bearing (design, § Exact argv — "order is load-bearing"):
//!
//! 1. **The prompt is the token immediately after `-p`.** `--mcp-config`, `--allowedTools` and
//!    `--disallowedTools` are variadic, so a positional anywhere after them would be swallowed as
//!    another list element. The prompt goes first and the variadics go last, with the plan's final
//!    token always a flag *value* — never a positional.
//! 2. **The role is injected inline** via `--agents` (V3), so no file has to exist in the worktree
//!    and a worker cannot edit its own role definition mid-run.
//! 3. **A writing role always carries the sandbox `--settings`** (V4): `allowWrite` is exactly its
//!    own worktree and `denyWrite` is `~/`, which is the kernel-level reason a builder cannot
//!    reach `$ACP_STATE_DIR` (and therefore cannot approve its own gate).
//!
//! `SpawnPlan.argv` holds the arguments only — the program is [`SpawnPlan::file`], as
//! `Command::args` expects — so the prompt sits at `argv[1]`, i.e. index 2 of the command line the
//! design writes out with `claude` at index 0.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::core::types::{
    strip_dollar_schema, AttemptError, ErrorCode, ProviderName, RoleName, RoleSpec, RunId,
    TokenUsage,
};

use super::{NormalizedEvent, ProviderAdapter, RawResult, ResultCtx, SpawnPlan, SpawnRequest};

/// The program name; resolved against `PATH` by the supervisor and by `preflight`.
const PROGRAM: &str = "claude";

/// One provider line cannot make the parser allocate without bound. The 501st candidate is enough
/// for the supervisor to emit its one attempt-level truncation marker.
const MAX_MESSAGES_PER_LINE: usize = 501;

/// The tool allowlist — the same list in `--allowedTools` and in the inline `--agents` role, so a
/// role cannot widen what the CLI itself permits (design, § Exact argv).
const TOOLS: [&str; 6] = ["Bash", "Read", "Edit", "Write", "Glob", "Grep"];

/// What `claude` writes to stderr when it cannot authenticate, matched case-insensitively and
/// anywhere in the head of `stderr.log` (design, § Error Handling → `provider_unauthenticated`).
///
/// **The contract is `src/bin/fake-claude.rs`'s `auth_fail` scenario**, which reproduces the shape
/// of the real 401 captured on 2026-08-22: a login hint followed by the API error body —
/// `authentication required - run /login` and
/// `API Error: 401 {"type":"error","error":{"type":"authentication_error",…}}`. The real CLI has
/// also been seen to word it `Invalid API key · Please run /login` and
/// `OAuth token has expired · Please run /login`; every one of those carries `/login`, and the API
/// body carries `authentication_error`, so the two entries below cover the family without matching
/// an ordinary turn that merely mentions a key.
const AUTH_SIGNATURES: [&str; 3] = ["/login", "authentication_error", "invalid api key"];

/// Bash forms a worker may never run: only the control plane commits, and only after a human gate.
/// This is defence in depth over the sandbox — `git reset` is denied too, because a worker that
/// rewinds its own worktree destroys the pre-attempt sha the loop diffs against, and `git add`
/// because the index belongs to the approval path: an index a worker left dirty is the one state an
/// integrate commit refuses to build on (round-4 review, finding 4). The supervisor clears one
/// anyway at the end of the attempt; this stops it being made in the first place.
const DISALLOWED_TOOLS: [&str; 4] = [
    "Bash(git commit:*)",
    "Bash(git push:*)",
    "Bash(git reset:*)",
    "Bash(git add:*)",
];

/// The Claude Code CLI, reduced to argv construction and line parsing.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ClaudeAdapter;

impl ProviderAdapter for ClaudeAdapter {
    fn name(&self) -> ProviderName {
        ProviderName::Claude
    }

    fn build_fresh(&self, req: &SpawnRequest<'_>) -> SpawnPlan {
        plan(req, &[])
    }

    fn build_resume(&self, req: &SpawnRequest<'_>) -> SpawnPlan {
        // Resume repeats the full fresh flag set (V1): `--resume` restores the transcript, not the
        // role, the sandbox or the output schema. `session_id` is part of the method's contract —
        // a caller that reaches here without one has a bug the supervisor cannot paper over.
        let session_id = req
            .session_id
            .expect("build_resume requires req.session_id (design, § Exact argv: Claude resume)");
        plan(req, &["--resume".to_string(), session_id.to_string()])
    }

    fn prompt_index(&self, _plan: &SpawnPlan) -> Option<usize> {
        Some(1)
    }

    fn preflight(&self, req: &SpawnRequest<'_>) -> Option<AttemptError> {
        if super::find_on_path(PROGRAM).is_none() {
            return Some(AttemptError {
                code: ErrorCode::ProviderMissing,
                message: format!(
                    "`{PROGRAM}` was not found on PATH — install Claude Code and re-run `acp doctor`"
                ),
            });
        }
        // `--resume` is cwd-scoped (C3): the transcript lives under a key derived from the cwd the
        // session started in, so a resume from a worktree that has since been removed silently
        // starts a *new* session instead of failing. Catch it before the spawn.
        if req.session_id.is_some() && !req.cwd.exists() {
            return Some(AttemptError {
                code: ErrorCode::ResumeTargetMissing,
                message: format!(
                    "cannot resume: the session's working directory {} no longer exists",
                    req.cwd.display()
                ),
            });
        }
        None
    }

    fn parse_line(&self, line: &str) -> Vec<NormalizedEvent> {
        // Worker output is data, never instructions — and never a reason to panic. A blank line, a
        // partial line the supervisor mis-split, or outright garbage all map to "no events".
        let Ok(value) = serde_json::from_str::<Value>(line.trim()) else {
            return Vec::new();
        };
        match str_at(&value, "type") {
            Some("system") if str_at(&value, "subtype") == Some("init") => {
                match str_at(&value, "session_id") {
                    Some(session_id) => vec![NormalizedEvent::Session {
                        session_id: session_id.to_string(),
                    }],
                    None => Vec::new(),
                }
            }
            Some("assistant") => parse_assistant(&value),
            Some("result") => parse_result(&value),
            // `user` (tool results), `rate_limit_event`, hook and thinking-token notices: real
            // stream traffic that carries no progress the lead can act on.
            _ => Vec::new(),
        }
    }

    fn extract_result(&self, ctx: &ResultCtx<'_>) -> RawResult {
        // `ctx.last_message` stays unused: Claude reports its final message inline on the stream
        // (`result.result`), so no `-o` file exists. `exit_code`/`signal` are the caller's to
        // classify — an adapter reports what the provider said, not what it means.
        //
        // The one exception is authentication, and it is an exception the design names: a CLI that
        // could not log in writes its signature to stderr and exits non-zero before a single
        // stream line, so nothing on the stream can report it and `super::is_auth_failure` is the
        // only place it can be seen (§ Error Handling).
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
        let last_final = ctx.events.iter().rev().find_map(|event| match event {
            NormalizedEvent::Final {
                ok,
                text,
                structured,
                error_code,
                ..
            } => Some((*ok, text, structured, *error_code)),
            _ => None,
        });
        match last_final {
            Some((ok, text, structured, error_code)) => RawResult {
                ok,
                text: text.clone(),
                structured: structured.clone(),
                error_code,
                session_id,
            },
            // No terminal line: the process died mid-stream. `session_id` still travels, because
            // whether one exists is exactly what separates a resumable failure from `no_session`.
            None => RawResult {
                ok: false,
                session_id,
                ..RawResult::default()
            },
        }
    }
}

/// The one argv builder, shared by fresh and resume: `extra` is spliced in directly after the
/// prompt so both shapes are identical apart from `--resume <sessionId>` (V1).
fn plan(req: &SpawnRequest<'_>, extra: &[String]) -> SpawnPlan {
    let mut argv = vec!["-p".to_string(), req.prompt.to_string()];
    argv.extend_from_slice(extra);
    argv.extend([
        "--model".to_string(),
        req.model.to_string(),
        // Project settings only: no user-level `~/.claude/settings.json` and no enterprise policy
        // file, so what the worker runs under is entirely what this argv says.
        "--setting-sources".to_string(),
        "project".to_string(),
        "--agents".to_string(),
        agents_json(req.role, req.role_prompt, req.model),
        "--agent".to_string(),
        role_key(req.role.role).to_string(),
    ]);
    // V4: mandatory for a sandboxed role (a writer, or the B1 verifier working in the builder's
    // worktree). The caller says so by attaching a `SandboxSpec`; a sandboxed role that arrives
    // without one is a caller bug, and omitting the flag is the fail-closed answer —
    // `assert_safe_argv` rejects the plan with `SandboxMissing` rather than the worker running
    // unsandboxed.
    if let Some(sandbox) = req.sandbox {
        argv.extend([
            "--settings".to_string(),
            settings_json(&sandbox.worktree.display().to_string()),
        ]);
    }
    argv.extend([
        "--output-format".to_string(),
        "stream-json".to_string(),
        "--verbose".to_string(),
    ]);
    // A conversational lead has no terminal result schema in v1. Its assistant text is retained
    // as ordinary untrusted output, while builder/reviewer structured results keep the existing
    // post-processed schema contract.
    if req.role.role != RoleName::Lead {
        argv.extend([
            "--json-schema".to_string(),
            // The schema arrives post-processed (V7); stripping again is idempotent and keeps the
            // guarantee local, because `claude` rejects a top-level `$schema`.
            json_token(&strip_dollar_schema(req.schema.1.clone())),
        ]);
    }
    argv.extend([
        "--max-turns".to_string(),
        req.max_turns.to_string(),
        "--max-budget-usd".to_string(),
        req.spawn_budget_usd.to_string(),
        "--permission-mode".to_string(),
        "acceptEdits".to_string(),
    ]);
    // Variadic flags last (design, § Exact argv). Nothing positional may follow them, so the final
    // token of every plan is a flag value.
    argv.push("--allowedTools".to_string());
    argv.extend(role_tools(req.role));
    argv.push("--disallowedTools".to_string());
    argv.extend(DISALLOWED_TOOLS.iter().map(|tool| (*tool).to_string()));
    let mcp_config = if req.role.role == RoleName::Lead {
        lead_mcp_config(req.cwd, req.state_dir, req.lead_run_id)
    } else {
        // Workers must not be able to reach the control plane they run under (V2).
        json_token(&json!({ "mcpServers": {} }))
    };
    argv.extend([
        "--strict-mcp-config".to_string(),
        "--mcp-config".to_string(),
        mcp_config,
    ]);

    SpawnPlan {
        required_version: None,
        file: PathBuf::from(PROGRAM),
        argv,
        cwd: req.cwd.to_path_buf(),
        env: super::base_env(),
        // Claude needs nothing on disk: the role and the schema both travel inline.
        write_files: Vec::new(),
    }
}

/// The inline role definition (V3). `description`/`tools` fall back to what the CLI would otherwise
/// be given, so a role config that omits them still spawns a usable worker.
fn agents_json(role: &RoleSpec, role_prompt: &str, model: &str) -> String {
    let key = role_key(role.role);
    let description = role
        .description
        .clone()
        .unwrap_or_else(|| format!("{key} worker"));
    let tools = role_tools(role);
    json_token(&json!({
        key: {
            "description": description,
            "prompt": role_prompt,
            "tools": tools,
            "model": model,
        }
    }))
}

fn role_tools(role: &RoleSpec) -> Vec<String> {
    if role.role == RoleName::Security {
        return ["Read", "Glob", "Grep"].into_iter().map(String::from).collect();
    }
    role.tools
        .clone()
        .unwrap_or_else(|| TOOLS.iter().map(|tool| (*tool).to_string()).collect())
}

/// The spawned lead reaches the daemon only through its socket-backed stdio proxy. Both paths are
/// adapter-owned facts: no task, prompt, team file or tool call can choose either executable.
///
/// The `env` block exists because the proxy child inherits claude's environment, and claude runs
/// under the scrubbed worker allowlist: `ACP_STATE_DIR` and `ACP_ROLES_FILE` never survive it.
/// Without an explicit `ACP_STATE_DIR` the proxy would fall back to the repo-derived *default*
/// state dir and miss the socket whenever the daemon serves from a custom one. Both values are
/// daemon-owned facts (the state dir travels on the request; the roles override is the daemon's
/// own environment — the same variable its startup `load_roles` read), scoped to the MCP child
/// alone: the lead's shell tools still see neither.
///
/// `lead_run_id` is the same daemon-owned-fact shape as `state_dir` (T84): the minted run this
/// spawn *is*, threaded in as `ACP_LEAD_RUN_ID` so `acp mcp-proxy` can later attach `callerRunId`
/// to this lead's own `delegate`/`plan.start` calls. Always `Some` in practice — `plan()` only
/// takes this branch for `RoleName::Lead`, and every lead spawn mints a run before it gets here —
/// but the adapter stays honest about the type rather than asserting it.
fn lead_mcp_config(repo_root: &Path, state_dir: &Path, lead_run_id: Option<RunId>) -> String {
    let Some(command) = std::env::current_exe()
        .ok()
        .filter(|path| path.is_absolute())
    else {
        // The pure adapter cannot return an I/O error. Empty is fail-closed: the lead gets no ACP
        // server rather than a command from PATH or provider-authored input.
        return json_token(&json!({ "mcpServers": {} }));
    };
    let mut env = serde_json::Map::new();
    env.insert("ACP_STATE_DIR".to_string(), json!(state_dir));
    if let Some(lead_run_id) = lead_run_id {
        env.insert("ACP_LEAD_RUN_ID".to_string(), json!(lead_run_id));
    }
    if let Some(absolute) = super::proxy_roles_file() {
        env.insert("ACP_ROLES_FILE".to_string(), json!(absolute));
    }

    json_token(&json!({
        "mcpServers": {
            "acp": {
                "command": command,
                "args": ["mcp-proxy", "--repo", repo_root],
                "env": env,
            }
        }
    }))
}

/// The kernel sandbox settings for a writing role (V4): the worker may write to its own worktree
/// and nowhere else — `~/` (which holds `$ACP_STATE_DIR` and the socket) is denied outright.
fn settings_json(worktree: &str) -> String {
    json_token(&json!({
        "sandbox": {
            "enabled": true,
            "autoAllowBashIfSandboxed": true,
            "filesystem": {
                "denyWrite": ["~/"],
                "allowWrite": [worktree],
            }
        }
    }))
}

/// Serializes an inline JSON argv token. Serializing a `Value` cannot fail, but the fallback keeps
/// the adapter panic-free rather than trusting that reasoning at run time.
fn json_token(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
}

/// The wire name of a role — the `--agents` key and the `--agent` value. Matches the `lowercase`
/// serde rename on [`RoleName`]; spelled out rather than round-tripped through `serde_json` so no
/// argv token depends on a fallible conversion.
fn role_key(role: RoleName) -> &'static str {
    match role {
        RoleName::Lead => "lead",
        RoleName::Builder => "builder",
        RoleName::Reviewer => "reviewer",
        RoleName::Verifier => "verifier",
        RoleName::Security => "security",
    }
}

/// One `assistant` line → one [`NormalizedEvent::Phase`] per actionable content block and one
/// uncoalesced [`NormalizedEvent::Message`] for every text block. `thinking` blocks are skipped.
fn parse_assistant(value: &Value) -> Vec<NormalizedEvent> {
    let Some(blocks) = value.pointer("/message/content").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut phase = None;
    let mut messages = Vec::new();
    for (block_index, block) in blocks.iter().enumerate() {
        match str_at(block, "type") {
            Some("tool_use") => {
                phase = Some(NormalizedEvent::Phase {
                    phase: "tool_use".to_string(),
                    // The tool name comes from the closed set the CLI was given; the tool *input* is
                    // worker-authored text and stays out of the event log.
                    note: str_at(block, "name").map(str::to_string),
                })
            }
            Some("text") => {
                // Keep the existing coarse progress phase for status consumers; the prose itself
                // is a separate event so the supervisor can bypass phase coalescing for leads.
                phase = Some(NormalizedEvent::Phase {
                    phase: "text".to_string(),
                    note: None,
                });
                if messages.len() < MAX_MESSAGES_PER_LINE {
                    if let Some(text) = str_at(block, "text") {
                        messages.extend(super::message_parts(text, block_index as u32)
                            .into_iter().take(MAX_MESSAGES_PER_LINE - messages.len()));
                    }
                }
            }
            _ => {}
        }
    }
    phase.into_iter().chain(messages).collect()
}

/// The terminal `result` line → the usage figures and the final outcome.
fn parse_result(value: &Value) -> Vec<NormalizedEvent> {
    let tokens = token_usage(value.get("usage"));
    let cost_usd = value.get("total_cost_usd").and_then(Value::as_f64);
    let subtype = str_at(value, "subtype");
    vec![
        NormalizedEvent::Usage { tokens, cost_usd },
        NormalizedEvent::Final {
            // `is_error` is Claude's own verdict; an absent flag means the run ended cleanly.
            ok: !value
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            text: str_at(value, "result").map(str::to_string),
            structured: value
                .get("structured_output")
                .filter(|structured| !structured.is_null())
                .cloned()
                // Live-gate fallback (2026-08-27): when the worker runs as a named agent
                // (`--agents … --agent <role>`), claude 2.1.221 omits `structured_output` from the
                // result event even though `--json-schema` was accepted, and the un-enforced model
                // may fence its JSON. The CLI's validation was only ever advisory — the supervisor
                // re-validates `structured` against the role schema either way — so parsing the
                // final text is a fallback, not a trust change.
                .or_else(|| str_at(value, "result").and_then(parse_fenced_json)),
            // `terminal_reason` answers "why did the attempt end" ("completed", "max_turns"); the
            // top-level `stop_reason` describes only the last assistant message, so it is not the
            // field the loop wants. `subtype` is the fallback — it is always present.
            stop_reason: str_at(value, "terminal_reason")
                .or(subtype)
                .map(str::to_string),
            cost_usd,
            tokens: Some(tokens),
            // The one failure Claude names precisely enough to act on; every other `is_error` is
            // classified by the caller from the exit code and the terminal-state table.
            error_code: (subtype == Some("error_max_turns")).then_some(ErrorCode::MaxTurns),
        },
    ]
}

/// The final text as JSON, tolerating one surrounding markdown fence — and, failing that, prose
/// **before** an unfenced trailing document (live gate, 2026-08-30: a real haiku verifier led
/// its correct `nothing-to-run` report with a sentence of explanation, exactly what the prompt
/// forbids and exactly what models keep doing). Returns `None` for anything that does not
/// parse — the caller records an absent structured result and the schema validator (not this
/// function) decides what that means for the attempt.
fn parse_fenced_json(text: &str) -> Option<Value> {
    let trimmed = text.trim();
    let body = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .and_then(|rest| rest.strip_suffix("```"))
        .map(str::trim)
        .unwrap_or(trimmed);
    if let Ok(parsed) = serde_json::from_str::<Value>(body) {
        if parsed.is_object() {
            return Some(parsed);
        }
    }
    // Trailing-object FIRST (review, 2026-08-30): the message-final document is the better
    // prior for "the answer" — a fence-first order would let a template the model echoed from
    // its own prompt beat the real report at the end. Both live shapes still route correctly:
    // the prose+fence message ends in ``` so the trailing rule declines and the fence rule
    // fires; the prose+bare message has no fences.
    parse_trailing_object(trimmed).or_else(|| parse_last_fenced_object(trimmed))
}

/// The last fenced JSON block anywhere in the text (live gate, 2026-08-30 round 2: the real
/// verifier wrote numbered prose and THEN a ```json fence — the whole-text fence strip only
/// handles a message that IS one fence). Segments between ``` delimiters are walked from the
/// last toward the first, so an earlier non-JSON fence (a quoted code snippet) is skipped
/// naturally. The fence is an explicit document marker, so trailing prose after it does not
/// disqualify — unlike the bare trailing-object rule below.
fn parse_last_fenced_object(text: &str) -> Option<Value> {
    let segments: Vec<&str> = text.split("```").collect();
    if segments.len() < 3 {
        return None;
    }
    // Every segment is a candidate, walked last-to-first — parity ("odd = inside a fence") is
    // deliberately NOT assumed, because one stray ``` in the prose flips it and would hide the
    // real report (review, 2026-08-30). A prose segment essentially never parses as an object;
    // one that does still faces the schema gate.
    segments.iter().rev().take(16).find_map(|body| {
        let body = body.trim_start();
        // Strip a fence language tag: the whole first line, when it holds no `{` of its own
        // (covers json, jsonc, JSON, `json title=…`), never the document's opening brace.
        let body = match body.split_once('\n') {
            Some((first, rest)) if !first.contains('{') => rest,
            _ => body,
        };
        serde_json::from_str::<Value>(body.trim())
            .ok()
            .filter(Value::is_object)
    })
}

/// The trailing JSON object of a prose-then-document final message. Candidate starts are the
/// `{` positions walked from the **last** toward the first: the parse of `text[start..]`
/// succeeds exactly when `start` opens one complete document that runs to the end of the text,
/// so nested braces and `{` inside the prose fall out naturally. Bounded (64 candidates) so a
/// pathological brace-storm costs nothing; extraction is still not acceptance — the schema
/// validator remains the gate, so a wrong grab fails closed.
fn parse_trailing_object(text: &str) -> Option<Value> {
    if !text.ends_with('}') {
        return None;
    }
    text.char_indices()
        .filter(|(_, c)| *c == '{')
        .map(|(at, _)| at)
        .rev()
        .take(64)
        .find_map(|at| {
            serde_json::from_str::<Value>(&text[at..])
                .ok()
                .filter(Value::is_object)
        })
}

/// Claude's `usage` block → the provider-neutral [`TokenUsage`]. Cache *creation* tokens are fresh
/// input that happened to be written to the cache, so they count as `input`; only cache *reads*
/// are `cached_input`. Claude reports no reasoning tokens.
fn token_usage(usage: Option<&Value>) -> TokenUsage {
    let count = |key: &str| {
        usage
            .and_then(|usage| usage.get(key))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    TokenUsage {
        input: count("input_tokens").saturating_add(count("cache_creation_input_tokens")),
        cached_input: count("cache_read_input_tokens"),
        output: count("output_tokens"),
        reasoning: None,
    }
}

/// `value[key]` as a `&str`, or `None` if the key is missing or is not a string.
fn str_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}
