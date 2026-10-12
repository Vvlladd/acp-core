//! The `ProviderAdapter` contract: argv construction, event mapping and resume shape, kept free of
//! any core knowledge. Implemented in T13 (`reports/03-design.md` § `src/providers`).
//!
//! Adapters are **pure**: `build_fresh`/`build_resume` return a [`SpawnPlan`] describing the process
//! to start and the files it needs; the supervisor writes those files and spawns the child. Nothing
//! here touches runs, gates, strikes or policy, and no method is `async` (design, § `src/providers`:
//! the trait has no async methods) — which is why `async-trait` is deliberately absent from the
//! dependency set.

pub mod claude;
pub mod codex;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::core::team::Effort;
use crate::core::types::{AttemptError, ErrorCode, ProviderName, RoleSpec, RunId, TokenUsage};

// ---------------------------------------------------------------------------
// Spawn description
// ---------------------------------------------------------------------------

/// Everything the supervisor needs to start one provider process.
///
/// `file` is the bare program name (`"claude"` / `"codex"`), **not** an absolute path:
/// `tokio::process::Command` resolves it against `PATH` at spawn time, which is the same lookup
/// [`ProviderAdapter::preflight`] performs when it checks "binary on PATH" via [`find_on_path`].
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SpawnPlan {
    /// Optional exact CLI version required by a measured tool profile. Checked off the actor
    /// mailbox against the resolved executable before the provider can begin a model turn.
    pub required_version: Option<String>,
    pub file: PathBuf,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    /// Files the CLI expects on disk (e.g. Codex's `--output-schema`), written by the supervisor
    /// before the spawn so adapters stay pure.
    pub write_files: Vec<(PathBuf, String)>,
}

/// The absolute worktree a writing role may write to — Claude's kernel sandbox `allowWrite` (V4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SandboxSpec<'a> {
    pub worktree: &'a Path,
}

/// One request to build a spawn plan. Borrowed throughout: adapters never own control-plane state.
#[derive(Clone, Copy, Debug)]
pub struct SpawnRequest<'a> {
    pub role: &'a RoleSpec,
    pub model: &'a str,
    pub prompt: &'a str,
    pub role_prompt: &'a str,
    pub cwd: &'a Path,
    pub attempt_dir: &'a Path,
    /// The daemon's own state directory. A spawned **lead** needs it inside its `--mcp-config`
    /// `env` block: the `acp mcp-proxy` child that claude launches runs under the scrubbed worker
    /// environment, so without an explicit `ACP_STATE_DIR` it would fall back to the *default*
    /// state dir and miss the socket whenever the daemon serves from a custom one. Workers never
    /// see it — their MCP config is empty (V2).
    pub state_dir: &'a Path,
    /// The run this spawn *is*, when it is a lead (T84). Threaded into the `acp mcp-proxy` child's
    /// `ACP_LEAD_RUN_ID` so the daemon can later attest a `delegate`/`plan.start` the lead's own MCP
    /// calls make came from this run — worker spawns never fill this in, and get no such env entry.
    pub lead_run_id: Option<RunId>,
    /// `(schema name, post-processed schema document)` — the `$schema`-stripped artifact (V7).
    pub schema: (&'a str, &'a Value),
    pub max_turns: u32,
    pub spawn_budget_usd: f64,
    /// `Some` for a writing role, `None` for a read-only one.
    pub sandbox: Option<SandboxSpec<'a>>,
    /// Required by [`ProviderAdapter::build_resume`], ignored by `build_fresh`.
    pub session_id: Option<&'a str>,
    /// The reasoning effort the team assigned this role (Rev 26), or `None` to leave the adapter on
    /// its own configured constant. Codex spends it as `-c model_reasoning_effort=`; claude has no
    /// such knob and ignores it. A **resume** never carries one: a thread keeps the effort it was
    /// started with.
    pub effort: Option<Effort>,
}

// ---------------------------------------------------------------------------
// Normalized event stream
// ---------------------------------------------------------------------------

/// The provider-neutral shape every CLI's JSONL line is mapped to. One raw line may map to zero
/// events (blank lines, garbage, provider-specific noise) or to several.
#[derive(Clone, PartialEq, Debug)]
pub enum NormalizedEvent {
    Session {
        session_id: String,
    },
    Phase {
        phase: String,
        note: Option<String>,
    },
    /// One assistant prose block. The adapter byte-caps it; the supervisor decides whether the
    /// attempt's role is allowed to publish it and enforces the per-attempt event cap.
    Message {
        text: String,
        part: Option<crate::core::types::MessagePart>,
    },
    Usage {
        tokens: TokenUsage,
        cost_usd: Option<f64>,
    },
    /// A successful provider turn ended; its result may live in a separate output file.
    /// Unlike usage, this is explicit terminal evidence for restart recovery.
    Completed,
    Final {
        ok: bool,
        text: Option<String>,
        structured: Option<Value>,
        stop_reason: Option<String>,
        cost_usd: Option<f64>,
        tokens: Option<TokenUsage>,
        error_code: Option<ErrorCode>,
    },
    Error {
        message: String,
        fatal: bool,
    },
}

// ---------------------------------------------------------------------------
// Result extraction
// ---------------------------------------------------------------------------

/// What [`ProviderAdapter::extract_result`] sees: the events parsed from the attempt's stdout and
/// how the process ended. `last_message` carries the body of the file a provider was told to write
/// its final message to (Codex's `-o <attemptDir>/last-message.txt`); it is `None` for providers
/// that report the final message inline on the stream.
///
/// `stderr_head` is the **head** of `<attemptDir>/stderr.log`, capped at
/// [`STDERR_HEAD_BYTES`](crate::core::supervisor::STDERR_HEAD_BYTES) — the same untrusted-head
/// discipline `last_message` and `HandoffEnvelope::head` follow. It exists for exactly one
/// decision: an authentication failure writes its signature there and nowhere else, and the design
/// makes that an *environment* failure rather than a bad turn (§ Error Handling:
/// `provider_unauthenticated` = "auth signature + non-zero exit before any event"). Nothing else
/// may read it: stderr is provider-authored text, so [`is_auth_failure`] is the only rule allowed
/// to look, and only alongside two facts the control plane observed itself.
#[derive(Clone, Copy, Debug)]
pub struct ResultCtx<'a> {
    pub events: &'a [NormalizedEvent],
    pub exit_code: Option<i32>,
    pub signal: Option<&'a str>,
    pub last_message: Option<&'a str>,
    pub stderr_head: Option<&'a str>,
}

/// The provider's own view of how an attempt ended. Classification into an `AttemptStatus` (and any
/// schema validation of `structured`) is the caller's job, not the adapter's.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct RawResult {
    pub ok: bool,
    pub text: Option<String>,
    pub structured: Option<Value>,
    pub error_code: Option<ErrorCode>,
    pub session_id: Option<String>,
}

// ---------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------

/// One provider CLI, reduced to argv construction and line parsing.
///
/// Implementations must be pure and panic-free: `parse_line` returns `[]` for a blank or malformed
/// line rather than failing, because worker output is data, never instructions.
pub trait ProviderAdapter: Send + Sync {
    fn name(&self) -> ProviderName;
    fn build_fresh(&self, req: &SpawnRequest<'_>) -> SpawnPlan;
    /// `req.session_id` is required here — resume runs from the cwd the session started in (C3).
    fn build_resume(&self, req: &SpawnRequest<'_>) -> SpawnPlan;
    /// The one argv position at which this adapter placed caller-authored prompt text.
    ///
    /// The spawn chokepoint exempts only this position from denied-substring scanning. Keeping the
    /// declaration on the adapter makes the exemption positional and provider-owned rather than a
    /// content heuristic in core policy.
    fn prompt_index(&self, plan: &SpawnPlan) -> Option<usize>;
    /// Cheap pre-spawn checks only: binary on `PATH`, resume cwd still exists.
    fn preflight(&self, req: &SpawnRequest<'_>) -> Option<AttemptError>;
    fn parse_line(&self, line: &str) -> Vec<NormalizedEvent>;
    fn extract_result(&self, ctx: &ResultCtx<'_>) -> RawResult;
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Did this attempt end the way an **unauthenticated** CLI ends?
///
/// The design's terminal-state table spells the rule out (§ Error Handling): `spawn_failed` with
/// `provider_unauthenticated` is reached by an "auth signature + non-zero exit **before any
/// event**". All three conditions are required here, and two of the three are facts the control
/// plane observed rather than text a provider wrote:
///
/// * a non-zero exit — an unknown exit (a re-attached attempt has no `Child` to read one from)
///   is never enough;
/// * **no session was ever established** — a 401 met halfway through a turn is a failed turn,
///   which is strikeable and resumable, not a machine a human has to go and log into;
/// * one of `signatures` somewhere in the head of stderr, matched case-insensitively.
///
/// The signature list is each adapter's own, because the two CLIs word it differently. Getting it
/// wrong is safe in one direction only: a missed signature costs a strike and a repair round that
/// fails identically, while a false positive would block a run that a repair could have rescued —
/// so the two structural conditions are what carry the decision, and the string only confirms it.
#[must_use]
pub fn is_auth_failure(ctx: &ResultCtx<'_>, signatures: &[&str]) -> bool {
    if !matches!(ctx.exit_code, Some(code) if code != 0) {
        return false;
    }
    if ctx
        .events
        .iter()
        .any(|event| matches!(event, NormalizedEvent::Session { .. }))
    {
        return false;
    }
    let Some(stderr) = ctx.stderr_head else {
        return false;
    };
    let stderr = stderr.to_ascii_lowercase();
    signatures
        .iter()
        .any(|signature| stderr.contains(&signature.to_ascii_lowercase()))
}

/// The env keys a worker inherits from this process (design, § Worker environment).
// USER/LOGNAME joined the list at the live gate (2026-08-26): the real `claude` CLI resolves its
// Keychain credentials through them, and without them every real worker reports "Not logged in"
// while the fakes pass. Both are identity, not secrets, and the peer is the same uid anyway.
const INHERITED_ENV_KEYS: [&str; 6] = ["PATH", "HOME", "TMPDIR", "LANG", "USER", "LOGNAME"];

/// The fixed prefix the design lets through on top of [`INHERITED_ENV_KEYS`] (§ Worker
/// environment). It is an **allowlisted prefix, not a mode flag**: nothing turns it on, and in
/// production no key wearing it is ever set, so the rule is a no-op there.
///
/// Debug builds only — see [`base_env`] for why the gate is `debug_assertions`.
#[cfg(debug_assertions)]
const ACP_FAKE_PREFIX: &str = "ACP_FAKE_";

/// The worker environment shared by every adapter (design, § Worker environment).
///
/// Exactly `{PATH, HOME, TMPDIR, LANG, USER, LOGNAME}` — those of them that are set in this process — plus the
/// three `GIT_CONFIG_*` keys that neutralize `remote.origin.url`, so a worker that runs `git push`
/// pushes nowhere (C4/V5). Everything else is dropped, so a worker can never learn `ACP_STATE_DIR`
/// or the socket path.
///
/// **Plus the [`ACP_FAKE_PREFIX`] pass-through, in a debug build only**: every `ACP_FAKE_*` key set
/// in the daemon's own environment is copied verbatim. The design names it as part of the worker
/// environment — "Builder env = exactly `{PATH, HOME, TMPDIR, LANG, USER, LOGNAME}` ∪ `GIT_CONFIG_{COUNT,KEY_0,
/// VALUE_0}` ∪ **`ACP_FAKE_*`**" — and it is what lets an integration test drive the fake CLIs
/// *through the real loop*, with the argv and the environment a worker is started with being the
/// production ones and nothing about the spawn path special-cased for a test.
///
/// It widens nothing. `assert_safe_argv`'s check 5 already accepts exactly this prefix and rejects
/// any forwarded value containing the state-dir path, so a pass-through key can never hand a worker
/// the socket that approves its own gate; and a real `claude`/`codex` ignores the keys.
///
/// The gate is `cfg(debug_assertions)` rather than `cfg(test)` for the same reason
/// `ACP_TEST_GIT_TIMEOUT_MS` is (`workspace::git::git_op_timeout`): an integration test links the
/// library compiled *without* `cfg(test)`, so `cfg(test)` would leave the pass-through dead exactly
/// where it is needed. `cargo build --release` compiles the loop out entirely, so the shipped `acp`
/// binary has no environment-driven way to put anything extra into a worker's environment.
pub fn base_env() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for key in INHERITED_ENV_KEYS {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.to_string(), value);
        }
    }
    #[cfg(debug_assertions)]
    for (key, value) in std::env::vars() {
        if key.starts_with(ACP_FAKE_PREFIX) {
            env.insert(key, value);
        }
    }
    env.insert("GIT_CONFIG_COUNT".to_string(), "1".to_string());
    env.insert(
        "GIT_CONFIG_KEY_0".to_string(),
        "remote.origin.url".to_string(),
    );
    env.insert("GIT_CONFIG_VALUE_0".to_string(), String::new());
    env
}

/// Whether this provider can confine a **writing** worker to its own worktree.
///
/// This is the one place that knowledge lives. Claude's plan is the mandatory
/// `--settings {"sandbox":{…,"allowWrite":[<worktree>],"denyWrite":["~/"]}}`; Codex's (C1) is
/// the measured `workspace-write` seatbelt — `-s workspace-write` +
/// `-c sandbox_mode="workspace-write"` + both temp-root excludes + an explicit empty
/// `writable_roots` + `--ignore-user-config`, with the worktree pinned by cwd — asserted item
/// by item at the spawn chokepoint (`check_codex_sandbox_shape`, V4). Named residuals, accepted
/// rather than hidden: `$CODEX_HOME/memories` stays writable (a cross-attempt channel between
/// codex workers), and project-local codex config in a hostile repo is not covered by
/// `--ignore-user-config`. This is deliberately NOT parity with Claude's `allowWrite ==
/// [worktree]`; the verdict table is version-pinned (`SANDBOX_VERIFIED_VERSION`) and `doctor`
/// warns on drift.
#[must_use]
pub const fn sandboxes_writes(provider: ProviderName) -> bool {
    match provider {
        ProviderName::Claude => true,
        ProviderName::Codex => true,
    }
}

/// Resolve `name` against `PATH` for `preflight`'s "binary on PATH" check, returning the absolute
/// path so the supervisor can spawn the resolved program rather than re-running the search.
///
/// Hand-rolled because the dependency set is fixed and `which` is not in it; both adapters call it
/// so the lookup exists once. Symlinks are followed (`fs::metadata`), which is what lets a test
/// point `claude`/`codex` at the fake bins.
///
/// **Only absolute `PATH` entries are searched.** An empty entry means "the current directory" to
/// `execvp`, and a worker process is started with its own worktree as the current directory, so
/// honouring an empty (or `.`, or any relative) entry would let a worker plant an executable named
/// `claude` and have the control plane launch it. `workspace::git` applies the same rule to `git`.
pub fn find_on_path(name: &str) -> Option<PathBuf> {
    search_path(&std::env::var_os("PATH")?, name)
}

/// [`find_on_path`] against an explicit `PATH` value, so the rule above is directly testable.
fn search_path(path_env: &OsStr, name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    for dir in std::env::split_paths(path_env) {
        if !dir.is_absolute() {
            continue;
        }
        let candidate = dir.join(name);
        let Ok(meta) = std::fs::metadata(&candidate) else {
            continue;
        };
        if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
            return Some(candidate);
        }
    }
    None
}


const MESSAGE_PART_BYTES: usize = 4 * 1024;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Preserve conversational prose in small wire events. The supervisor's existing 500-event
/// attempt budget still bounds durable text at 2 MiB. Worker handoff heads keep their own 4 KiB
/// cap. A block beyond 64 KiB carries an explicit notice, including on older clients.
fn message_parts(text: &str, block: u32) -> Vec<NormalizedEvent> {
    use crate::core::types::MessagePart;
    if text.len() <= MESSAGE_PART_BYTES {
        return vec![NormalizedEvent::Message { text: text.to_owned(), part: None }];
    }
    let truncated = text.len() > MAX_MESSAGE_BYTES;
    let bounded;
    let text = if truncated {
        const NOTICE: &str = "\n\n[Response shortened at 64 KiB; full output remains in the attempt log.]";
        let mut end = MAX_MESSAGE_BYTES - NOTICE.len();
        while !text.is_char_boundary(end) { end -= 1; }
        bounded = format!("{}{NOTICE}", &text[..end]);
        bounded.as_str()
    } else { text };
    let mut remaining = text;
    let mut parts = Vec::new();
    while !remaining.is_empty() {
        let mut end = remaining.len().min(MESSAGE_PART_BYTES);
        while !remaining.is_char_boundary(end) { end -= 1; }
        parts.push(remaining[..end].to_owned());
        remaining = &remaining[end..];
    }
    let count = parts.len() as u32;
    parts.into_iter().enumerate().map(|(index, text)| NormalizedEvent::Message {
        text, part: Some(MessagePart { block, index: index as u32, count, truncated }),
    }).collect()
}


/// Preserve a daemon-selected roles override when the MCP child runs from the repository root.
fn proxy_roles_file() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("ACP_ROLES_FILE").filter(|v| !v.is_empty())?;
    std::path::absolute(std::path::PathBuf::from(path)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_prose_has_a_visible_limit_and_stays_within_both_budgets() {
        let parts = message_parts(&"🦀".repeat(30_000), 7);
        let mut joined = String::new();
        assert!(parts.len() <= 17);
        for (index, event) in parts.iter().enumerate() {
            let NormalizedEvent::Message { text, part: Some(part) } = event else { panic!("part") };
            assert!(text.len() <= MESSAGE_PART_BYTES);
            assert_eq!(part.index, index as u32);
            assert_eq!(part.count, parts.len() as u32);
            assert_eq!(part.block, 7);
            assert!(part.truncated);
            joined.push_str(text);
        }
        assert!(joined.len() <= MAX_MESSAGE_BYTES);
        assert!(joined.contains("Response shortened at 64 KiB"));
    }

    #[test]
    fn base_env_is_exactly_the_allowlist_plus_git_config_and_the_acp_fake_prefix() {
        let env = base_env();
        for key in env.keys() {
            assert!(
                INHERITED_ENV_KEYS.contains(&key.as_str())
                    || key == "GIT_CONFIG_COUNT"
                    || key == "GIT_CONFIG_KEY_0"
                    || key == "GIT_CONFIG_VALUE_0"
                    || key.starts_with("ACP_FAKE_"),
                "unexpected key in worker env: {key}"
            );
        }
        // PATH is always set for a process cargo spawns; the other three are optional.
        assert!(env.contains_key("PATH"));
        assert_eq!(env.get("GIT_CONFIG_COUNT").map(String::as_str), Some("1"));
        assert_eq!(
            env.get("GIT_CONFIG_KEY_0").map(String::as_str),
            Some("remote.origin.url")
        );
        assert_eq!(env.get("GIT_CONFIG_VALUE_0").map(String::as_str), Some(""));
        // Every *other* `ACP_*` key stays out: a worker must never learn `ACP_STATE_DIR`.
        assert!(
            !env.keys()
                .any(|k| k.starts_with("ACP_") && !k.starts_with("ACP_FAKE_")),
            "an ACP_ key outside the fake prefix reached the worker env: {env:?}"
        );
    }

    /// The design's fixed-prefix pass-through (§ Worker environment): an `ACP_FAKE_*` key set in
    /// the daemon's environment reaches the worker, and a neighbouring `ACP_*` key does not.
    ///
    /// The two keys are named uniquely so this can mutate the process environment without
    /// disturbing any other test in this binary: the assertions above only ask about the prefix as
    /// a class, never about a particular key.
    #[test]
    fn the_acp_fake_prefix_passes_through_and_nothing_else_acp_does() {
        const PASSED: &str = "ACP_FAKE_BASE_ENV_PROBE";
        const DROPPED: &str = "ACP_BASE_ENV_PROBE_NOT_FAKE";

        std::env::set_var(PASSED, "scenario");
        std::env::set_var(DROPPED, "secret");
        let env = base_env();
        std::env::remove_var(PASSED);
        std::env::remove_var(DROPPED);

        assert_eq!(env.get(PASSED).map(String::as_str), Some("scenario"));
        assert_eq!(env.get(DROPPED), None);
    }

    #[test]
    fn find_on_path_finds_an_executable_and_misses_a_plain_file() {
        assert!(find_on_path("sh").is_some(), "sh must be on PATH");
        assert!(find_on_path("acp-definitely-not-a-real-binary").is_none());
    }

    #[test]
    fn only_absolute_path_entries_are_searched() {
        use std::os::unix::fs::PermissionsExt;

        // A worker's worktree, with an executable named like a provider CLI planted in it.
        let planted = tempfile::tempdir().expect("tempdir");
        let bin = planted.path().join("claude");
        std::fs::write(&bin, "#!/bin/sh\nexit 0\n").expect("write");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        // Empty, `.` and relative entries are all "the current directory" or worse: never searched.
        assert_eq!(search_path(OsStr::new(":.:relative/bin"), "claude"), None);
        assert_eq!(search_path(OsStr::new(""), "claude"), None);

        // The same directory named absolutely is searched normally.
        let absolute = format!(":.:{}", planted.path().display());
        assert_eq!(
            search_path(OsStr::new(&absolute), "claude").as_deref(),
            Some(bin.as_path())
        );
    }
}
