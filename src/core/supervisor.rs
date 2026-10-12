//! Process supervision: spawning, streaming, liveness, reattach, cancellation and timeouts.
//! Implemented in T22/T24 (`reports/03-design.md` § `src/core/supervisor.rs`).
//!
//! T22 is the **spawn chokepoint**: [`assert_safe_argv`] and [`spawn_detached`]. The tailer, the
//! liveness probe, the timeout ladder and reattach are T24.
//!
//! Two properties of this half are load-bearing:
//!
//! 1. **S5 is compiler-enforced.** [`spawn_detached`] takes a [`CheckedPlan`], whose single field
//!    is private and whose only constructor is [`assert_safe_argv`]. No caller outside this module
//!    can build one, so "every spawn was argv-checked" is a fact the type system carries rather
//!    than a convention a future task could forget (design, § `src/core/supervisor.rs`).
//! 2. **The child is detached, not owned.** `process_group(0)` puts it in its own process group, so
//!    the timeout ladder can `killpg` the whole tree — a worker's own `Bash` children included —
//!    without ever signalling the control plane itself, and `kill_on_drop(false)` means a daemon
//!    restart leaves running workers alive to be re-attached rather than reaped by a `Drop`.
//!
//! **Must NOT know**: which provider it runs, git, gates, strikes (design). Everything
//! provider-shaped in here is read out of the [`SpawnPlan`] an adapter built.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use globset::GlobSet;
use nix::errno::Errno;
use nix::sys::signal::{kill, killpg, Signal};
use nix::unistd::Pid;
use serde_json::Value;
use thiserror::Error;
use tokio::process::Command;
use tokio::sync::{mpsc, Mutex, OwnedMutexGuard};
use tokio::task::JoinHandle;

use crate::core::policy::{PolicyCode, PolicyError, DENIED_ARGV, MAX_ARGV_BYTES};
use crate::core::registry::{self, Registry, RegistryError};
use crate::core::types::{
    AgentId, Attempt, AttemptError, AttemptId, AttemptKind, AttemptStatus, CancelBy, CostSource,
    ErrorCode, Event, EventPayload, MessageRole, PolicyViolation, ProviderName, Rate, RoleName,
    RunId, SchemaName, TokenUsage, ViolationKind,
};
use crate::providers::{NormalizedEvent, ProviderAdapter, RawResult, ResultCtx, SpawnPlan};
use crate::workspace::git;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The only environment keys a worker may be handed, beyond the [`ACP_FAKE_PREFIX`] pass-through
/// (design, § Worker environment). Exactly what [`crate::providers::base_env`] builds — asserted
/// here rather than trusted, because the supervisor spawns whatever plan it is given.
const ENV_ALLOWLIST: [&str; 9] = [
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    // USER/LOGNAME: the real claude CLI resolves its Keychain credentials through them; without
    // them every real worker reports "Not logged in" (found at the live gate, 2026-08-26).
    "USER",
    "LOGNAME",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_0",
    "GIT_CONFIG_VALUE_0",
];

/// The one prefix that passes the env allowlist: it is what lets an integration test drive the
/// fake CLIs *through the real supervisor*. A fixed prefix allowlist, not a mode flag — in
/// production nothing sets these and the rule is a no-op (design, § Worker environment).
const ACP_FAKE_PREFIX: &str = "ACP_FAKE_";

/// Longest argv token [`assert_safe_argv`] will treat as a filesystem path. macOS's `PATH_MAX` is
/// 1024; anything past this ceiling cannot name a file the kernel could open, so it is rejected
/// rather than resolved — which also bounds the number of `stat` calls one oversized token can
/// cost, since the size check runs *after* the path check.
const MAX_PATH_BYTES: usize = 4096;

/// `<attemptDir>/argv.json` — the argv the child was given (design, § On-disk layout).
const ARGV_FILE: &str = "argv.json";

/// `<attemptDir>/prompt.txt` — the prompt token, when the argv shape identifies one.
const PROMPT_FILE: &str = "prompt.txt";

/// `<attemptDir>/stdout.jsonl` — the provider's event stream, tailed by `Supervisor::tick` (T24).
const STDOUT_FILE: &str = "stdout.jsonl";

/// `<attemptDir>/stderr.log` — everything the provider wrote to stderr.
const STDERR_FILE: &str = "stderr.log";

/// The start-time probe. Absolute, like every other program this crate spawns: a worker's worktree
/// is a child's cwd, so a `PATH` search could be answered by a file the worker planted.
const PS_BIN: &str = "/bin/ps";

// ---------------------------------------------------------------------------
// The chokepoint
// ---------------------------------------------------------------------------

/// A [`SpawnPlan`] that has passed [`assert_safe_argv`].
///
/// **The field is private and there is no other constructor.** That is the whole point: outside
/// this module a `CheckedPlan` cannot be forged, so calling [`spawn_detached`] on an unchecked plan
/// is a compile error rather than a review finding (design, § `src/core/supervisor.rs`: "S5 is
/// compiler-enforced").
///
/// Two invariants hold of the plan inside, beyond the five checks: its `file` is an **absolute,
/// resolved program** (never a name `spawn_detached` would have to look up while sitting in a
/// worker's worktree), and its `PATH` holds absolute entries only.
#[derive(Debug)]
pub struct CheckedPlan(SpawnPlan);

impl CheckedPlan {
    /// Read-only access to the plan that passed. Handing out a `&SpawnPlan` cannot forge a
    /// `CheckedPlan` — the wrapper stays unconstructible — so the chokepoint is intact.
    #[must_use]
    pub fn plan(&self) -> &SpawnPlan {
        &self.0
    }
}

/// What a plan is checked *against*: the worktree it may write in, whether it writes at all, the
/// whether the plan must carry the kernel sandbox, the state dir it may name in argv but never in
/// its environment, and the one prompt position the provider adapter declared.
///
/// `state_dir` rather than the attempt dir because every attempt dir is
/// `$ACP_STATE_DIR/runs/<runId>/attempts/<attemptId>` (design, § On-disk layout) — containment in
/// the state dir is what this context can express, and the attempt dir is the only part of it an
/// adapter ever names (Codex's `--output-schema` and `-o` files).
#[derive(Clone, Copy, Debug)]
pub struct ArgvCtx<'a> {
    pub role: RoleName,
    pub lead_run_id: Option<RunId>,
    pub worktree: &'a Path,
    /// Which provider built this plan — the sandbox check is provider-shaped (C1): Claude
    /// carries a `--settings` policy document to inspect; Codex has none, so its arm asserts
    /// the measured workspace-write argv shape instead.
    pub provider: ProviderName,
    /// Whether this plan must carry the provider's kernel sandbox confined to `worktree` —
    /// [`RoleSpec::requires_sandbox`]: writers, and the verifier, which builds and runs tests in
    /// the *builder's* worktree without being a writer (B1). Writer accounting stays elsewhere.
    ///
    /// [`RoleSpec::requires_sandbox`]: crate::core::types::RoleSpec::requires_sandbox
    pub sandboxed: bool,
    pub state_dir: &'a Path,
    /// The adapter-declared prompt token in [`SpawnPlan::argv`]. Only this position is exempt from
    /// denied-substring scanning, and it is still refused when it begins with `-` so the provider
    /// CLI cannot parse human-authored text as a flag.
    pub prompt_index: Option<usize>,
}

/// The single gate every spawn passes through, in this exact order (design,
/// § `src/core/supervisor.rs`):
///
/// 1. **No denied token** — no argv token except the adapter-declared prompt contains any
///    [`DENIED_ARGV`] entry ([`PolicyCode::UnsafeArgv`]). The prompt must not begin with `-`.
///    `contains`, not `==`, so `--add-dir=/etc` and a `--settings` document with
///    `"defaultMode":"bypassPermissions"` are both caught.
/// 2. **Sandbox present for a sandboxed role** (writers and the verifier, B1), provider-shaped
///    (C1): for Claude, some `--settings` token's JSON has `sandbox.enabled == true` and
///    `sandbox.filesystem.allowWrite == [<ctx.worktree>]`, as one absolute path (V4); for
///    Codex, the measured workspace-write argv shape item by item, with the writable root
///    pinned by `cwd == worktree` (`check_codex_sandbox_shape`). Otherwise
///    [`PolicyCode::SandboxMissing`]: a builder or verifier never runs unsandboxed, and never
///    with a wider writable set than the worktree it works in.
/// 3. **Paths stay home** — every argv token that *is* a filesystem path, and every
///    [`SpawnPlan::write_files`] destination `spawn_detached` will create, resolves inside
///    `ctx.state_dir` or `ctx.worktree` ([`PolicyCode::UnsafeArgv`]).
/// 4. **Size** — argv plus environment ≤ [`MAX_ARGV_BYTES`] ([`PolicyCode::ArgvTooLarge`]);
///    `execve` counts both against `ARG_MAX`, so an unbounded prompt must fail as a policy
///    rejection we can explain, not as `E2BIG`.
/// 5. **Environment** — every key is in [`ENV_ALLOWLIST`] or starts with [`ACP_FAKE_PREFIX`] and no
///    value anywhere contains the state dir's path ([`PolicyCode::UnsafeEnv`]) — a worker that
///    learned `$ACP_STATE_DIR` could find the socket that approves its own gate — after which
///    `PATH` is reduced to its absolute entries.
///
/// The order is the contract: a plan that fails several checks is reported by the *first* one, so
/// the rejection a human reads names the most specific defect rather than whichever check happened
/// to run first.
///
/// Only then is the program itself resolved to an absolute path, against that sanitized `PATH`
/// ([`resolve_program`]). A checked plan therefore never leaves a `PATH` search to be performed at
/// spawn time, when the process's current directory is the worktree the worker writes to: an empty,
/// `.` or otherwise relative `PATH` entry means "the current directory" to `execvp`, so a worker
/// that dropped an executable named `claude` in its worktree would otherwise have the control plane
/// launch it. `workspace::git` applies the same rule to `git`.
///
/// # Errors
/// One of `UnsafeArgv`, `SandboxMissing`, `ArgvTooLarge`, `UnsafeEnv`.
pub fn assert_safe_argv(
    mut plan: SpawnPlan,
    ctx: &ArgvCtx<'_>,
) -> Result<CheckedPlan, PolicyError> {
    check_denied_tokens(&plan, ctx)?;
    check_sandbox(&plan, ctx)?;
    check_paths(&plan, ctx)?;
    check_size(&plan)?;
    check_env(&mut plan, ctx)?;
    plan.file = resolve_program(&plan, ctx)?;
    Ok(CheckedPlan(plan))
}

/// Check 1: the deny-list.
fn check_denied_tokens(plan: &SpawnPlan, ctx: &ArgvCtx<'_>) -> Result<(), PolicyError> {
    if let Some(prompt_index) = ctx.prompt_index {
        let prompt = plan.argv.get(prompt_index).ok_or_else(|| {
            PolicyError::new(
                PolicyCode::UnsafeArgv,
                "the adapter-declared prompt index is outside argv",
            )
            .with_detail(serde_json::json!({ "promptIndex": prompt_index }))
        })?;
        if prompt.starts_with('-') {
            return Err(PolicyError::new(
                PolicyCode::UnsafeArgv,
                "the prompt must not begin with `-`",
            )
            .with_detail(serde_json::json!({ "promptIndex": prompt_index })));
        }
    }

    for (index, token) in plan.argv.iter().enumerate() {
        if ctx.prompt_index == Some(index) {
            continue;
        }
        if let Some(denied) = DENIED_ARGV.iter().find(|denied| token.contains(**denied)) {
            return Err(PolicyError::new(
                PolicyCode::UnsafeArgv,
                format!("argv carries the denied flag `{denied}`"),
            )
            .with_detail(serde_json::json!({ "denied": denied })));
        }
    }
    Ok(())
}

/// Check 2: V4, the kernel sandbox a sandboxed role (a writer, or the B1 verifier) may not run
/// without. Provider-shaped (C1): Claude's arm inspects the `--settings` policy document; the
/// codex arm asserts the measured workspace-write **argv shape** — codex computes its writable
/// set from the flags and the child's cwd, so the shape and the cwd ARE the policy
/// (`docs/research/2026-08-28-phase2-daemon.md` § 2, items 1-6).
fn check_sandbox(plan: &SpawnPlan, ctx: &ArgvCtx<'_>) -> Result<(), PolicyError> {
    if ctx.role == RoleName::Lead && ctx.provider == ProviderName::Codex {
        crate::providers::codex::lead::check_plan(plan, ctx.worktree, ctx.state_dir, ctx.lead_run_id)?;
    }
    if !ctx.sandboxed {
        // Defence-in-depth: a read-only codex plan carrying the workspace-write MODE is a
        // confused plan — refuse it rather than let a mislabeled context widen a seatbelt.
        // Flag-position-aware on purpose, never a substring scan: worker-authored free text
        // (a build summary quoted into a reviewer prompt) may legitimately SAY
        // "workspace-write", and only the `-s` value or a whole `-c` pair can BE the mode —
        // the same lesson as the T53 prompt exemption.
        if ctx.provider == ProviderName::Codex {
            let confused = plan
                .argv
                .iter()
                .zip(plan.argv.iter().skip(1))
                .any(|(flag, value)| {
                    ((flag == "-s" || flag == "--sandbox") && value == "workspace-write")
                        || ((flag == "-c" || flag == "--config")
                            && value == r#"sandbox_mode="workspace-write""#)
                });
            if confused {
                return Err(PolicyError::new(
                    PolicyCode::SandboxMissing,
                    "a read-only codex plan must not carry the workspace-write sandbox mode",
                ));
            }
        }
        return Ok(());
    }
    match ctx.provider {
        ProviderName::Claude => {
            let satisfied = plan
                .argv
                .iter()
                .zip(plan.argv.iter().skip(1))
                .filter(|(flag, _)| *flag == "--settings")
                .any(|(_, settings)| sandbox_confines_writes_to(settings, ctx.worktree));
            if satisfied {
                return Ok(());
            }
            Err(PolicyError::new(
                PolicyCode::SandboxMissing,
                "a sandboxed role must carry --settings with sandbox.enabled=true and \
                 sandbox.filesystem.allowWrite = [the worktree it works in]",
            )
            .with_detail(serde_json::json!({ "worktree": ctx.worktree })))
        }
        ProviderName::Codex => check_codex_sandbox_shape(plan, ctx),
    }
}

/// The measured codex confinement set, asserted item by item so a refusal names what is missing.
/// `-s workspace-write` is fresh-only (`exec resume` rejects `-s`), so the mode is asserted via
/// the `-c sandbox_mode` pair that travels on both paths; when `-s` IS present its value must
/// agree. The cwd is what pins the writable root, so it must resolve to the worktree.
fn check_codex_sandbox_shape(plan: &SpawnPlan, ctx: &ArgvCtx<'_>) -> Result<(), PolicyError> {
    let missing = |what: &str| {
        Err(PolicyError::new(
            PolicyCode::SandboxMissing,
            format!("a sandboxed codex plan is missing its confinement: {what}"),
        )
        .with_detail(serde_json::json!({ "worktree": ctx.worktree })))
    };
    let has = |token: &str| plan.argv.iter().any(|t| t == token);
    let has_config = |pair: &str| {
        plan.argv
            .iter()
            .zip(plan.argv.iter().skip(1))
            .any(|(flag, value)| (flag == "-c" || flag == "--config") && value == pair)
    };
    if let Some(at) = plan.argv.iter().position(|t| t == "-s" || t == "--sandbox") {
        if plan.argv.get(at + 1).map(String::as_str) != Some("workspace-write") {
            return missing(
                "the sandbox flag (-s/--sandbox) must name workspace-write when present",
            );
        }
    }
    if !has_config(r#"sandbox_mode="workspace-write""#) {
        return missing(r#"-c sandbox_mode="workspace-write""#);
    }
    if !has_config("sandbox_workspace_write.exclude_slash_tmp=true") {
        return missing("-c sandbox_workspace_write.exclude_slash_tmp=true");
    }
    if !has_config("sandbox_workspace_write.exclude_tmpdir_env_var=true") {
        return missing("-c sandbox_workspace_write.exclude_tmpdir_env_var=true");
    }
    if !has_config("sandbox_workspace_write.writable_roots=[]") {
        return missing("-c sandbox_workspace_write.writable_roots=[] (explicit — an inherited value must not widen)");
    }
    if !has("--ignore-user-config") {
        return missing("--ignore-user-config (the user's config.toml can widen writable_roots)");
    }
    if resolve(&plan.cwd) != resolve(ctx.worktree) {
        return missing("cwd == the worktree (cwd is what pins the writable root)");
    }
    Ok(())
}

/// Whether one `--settings` document enables the sandbox and confines writes to exactly `worktree`.
///
/// `allowWrite` must be a **single** absolute path resolving to the worktree: a second entry is a
/// second writable root, which is precisely what the check exists to forbid.
fn sandbox_confines_writes_to(settings: &str, worktree: &Path) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(settings) else {
        return false;
    };
    if value.pointer("/sandbox/enabled") != Some(&Value::Bool(true)) {
        return false;
    }
    let Some(allow) = value
        .pointer("/sandbox/filesystem/allowWrite")
        .and_then(Value::as_array)
    else {
        return false;
    };
    let [Value::String(only)] = allow.as_slice() else {
        return false;
    };
    let allowed = Path::new(only);
    allowed.is_absolute() && resolve(allowed) == resolve(worktree)
}

/// Check 3: every path the plan reaches for — in argv, or as a file `spawn_detached` will write —
/// lies inside the state dir or the worktree.
///
/// argv *tokens* are checked, not their contents: a token that embeds a path in prose or JSON is not
/// a path the CLI will open, and the two documents that do embed one — the sandbox `--settings` and
/// the inline `--agents` role — are covered by check 2 and by the kernel sandbox itself.
///
/// [`SpawnPlan::write_files`] is checked for the opposite reason: those paths are opened for
/// *writing*, by this process, before the spawn — with the daemon's privileges rather than the
/// worker's sandboxed ones — so an adapter (or a future caller) that named `~/.zshrc` there would
/// otherwise have the control plane overwrite it.
fn check_paths(plan: &SpawnPlan, ctx: &ArgvCtx<'_>) -> Result<(), PolicyError> {
    let roots = [ctx.state_dir, ctx.worktree].map(resolve);
    if ctx.role == RoleName::Lead && ctx.provider == ProviderName::Codex
        && plan.write_files.iter().any(|(path, _)| !resolve(path).starts_with(&roots[0])) {
        return Err(PolicyError::new(PolicyCode::UnsafeArgv,
            "Codex lead profile files must stay in the private state directory"));
    }
    let in_argv = plan
        .argv
        .iter()
        .filter_map(|token| path_candidate(token))
        .map(|token| ("argv", Path::new(token)));
    let to_write = plan
        .write_files
        .iter()
        .map(|(path, _)| ("write_files", path.as_path()));
    for (what, candidate) in in_argv.chain(to_write) {
        let inside = candidate.as_os_str().len() <= MAX_PATH_BYTES && {
            let resolved = resolve(candidate);
            roots.iter().any(|root| resolved.starts_with(root))
        };
        if !inside {
            return Err(PolicyError::new(
                PolicyCode::UnsafeArgv,
                format!("{what} names a path outside the attempt dir and the worktree"),
            )
            .with_detail(serde_json::json!({
                "path": truncate(&candidate.display().to_string()),
                "stateDir": ctx.state_dir,
                "worktree": ctx.worktree,
            })));
        }
    }
    Ok(())
}

/// The filesystem path a token *is*, if any: the token itself when it is absolute, or the value of
/// a `--flag=/absolute/path` (which is how a path reaches a CLI without occupying its own token).
///
/// A relative token is not a path candidate: `execve` resolves it against the child's cwd, which is
/// the worktree or the attempt dir by construction.
fn path_candidate(token: &str) -> Option<&str> {
    if token.starts_with('/') {
        return Some(token);
    }
    if !token.starts_with('-') {
        return None;
    }
    token
        .split_once('=')
        .map(|(_, value)| value)
        .filter(|value| value.starts_with('/'))
}

/// Check 4: `execve` counts argv **and** env against `ARG_MAX`, so both are summed here.
///
/// The program name is not counted: it is a bare `claude`/`codex` (or an absolute path to one),
/// bytes that cannot plausibly close a 200 KB gap against a 1 MiB limit.
fn check_size(plan: &SpawnPlan) -> Result<(), PolicyError> {
    let argv_bytes: usize = plan.argv.iter().map(String::len).sum();
    let env_bytes: usize = plan.env.iter().map(|(k, v)| k.len() + v.len()).sum();
    let total = argv_bytes + env_bytes;
    if total > MAX_ARGV_BYTES {
        return Err(PolicyError::new(
            PolicyCode::ArgvTooLarge,
            format!("argv + env is {total} bytes, over the {MAX_ARGV_BYTES} byte ceiling"),
        )
        .with_detail(serde_json::json!({
            "argvBytes": argv_bytes,
            "envBytes": env_bytes,
            "maxBytes": MAX_ARGV_BYTES,
        })));
    }
    Ok(())
}

/// Check 5: the env allowlist, the state dir that may not travel in it, and the `PATH` sanitization
/// that has to happen before the program can be resolved.
fn check_env(plan: &mut SpawnPlan, ctx: &ArgvCtx<'_>) -> Result<(), PolicyError> {
    for key in plan.env.keys() {
        if !ENV_ALLOWLIST.contains(&key.as_str()) && !key.starts_with(ACP_FAKE_PREFIX) {
            return Err(PolicyError::new(
                PolicyCode::UnsafeEnv,
                format!(
                    "environment key `{}` is not in the worker allowlist",
                    truncate(key)
                ),
            )
            .with_detail(serde_json::json!({ "allowed": ENV_ALLOWLIST })));
        }
    }
    // Both spellings of the state dir: a `/var/…` path and the `/private/var/…` it canonicalizes
    // to on macOS name the same directory, and either would tell a worker where the socket is.
    let mut spellings = vec![ctx.state_dir.display().to_string()];
    let canonical = resolve(ctx.state_dir).display().to_string();
    if !spellings.contains(&canonical) {
        spellings.push(canonical);
    }
    for (key, value) in &plan.env {
        for spelling in spellings.iter().filter(|s| !s.is_empty()) {
            if value.contains(spelling.as_str()) {
                return Err(PolicyError::new(
                    PolicyCode::UnsafeEnv,
                    format!("environment value `{key}` leaks the state dir path to the worker"),
                )
                .with_detail(serde_json::json!({ "key": key })));
            }
        }
    }
    sanitize_path(&mut plan.env);
    Ok(())
}

/// Reduces the worker's `PATH` to its absolute entries, in place.
///
/// Sanitized rather than rejected, because a developer's own `PATH` legitimately carries relative
/// entries (`node_modules/.bin`, a trailing colon) and [`crate::providers::base_env`] copies it
/// verbatim — a rejection would make every real spawn on such a machine fail. `workspace::git`
/// sanitizes the `git` child's `PATH` the same way and for the same reason.
///
/// The key is **removed** when nothing absolute survives: an empty `PATH` value means "the current
/// directory" to some `execvp` implementations, which is the very thing being prevented, whereas an
/// absent one leaves the child with the system default.
fn sanitize_path(env: &mut BTreeMap<String, String>) {
    let Some(path) = env.get("PATH") else {
        return;
    };
    match sanitize_path_value(path) {
        Some(kept) => env.insert("PATH".to_string(), kept),
        None => env.remove("PATH"),
    };
}

/// The absolute entries of a `PATH` value, re-joined — or `None` when there are none, or when an
/// entry cannot be re-joined losslessly (a directory whose name contains `:`), which fails closed.
fn sanitize_path_value(path: &str) -> Option<String> {
    let kept: Vec<PathBuf> = std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .collect();
    if kept.is_empty() {
        return None;
    }
    std::env::join_paths(kept).ok()?.into_string().ok()
}

/// The program a checked plan will actually execute: an absolute path, resolved here rather than by
/// `execvp` at spawn time.
///
/// Two shapes are accepted:
///
/// * an **absolute** `file`, taken as given (what a caller supplies when it has already resolved
///   the binary);
/// * a **bare name**, looked up in **the plan's own `PATH`** — which check 5 has just reduced to
///   its absolute entries — applying the same rule as [`crate::providers::find_on_path`].
///
/// The plan's `PATH` and nothing else: `env_clear().envs(&plan.env)` makes it the value the child
/// itself would search, and resolving against *this process's* environment instead would let a
/// provider installed on the daemon's `PATH` silently answer for a plan whose own `PATH` offered
/// nothing legitimate. A plan that carries no `PATH` therefore cannot resolve a bare name at all,
/// which is the fail-closed answer: `preflight` reports a missing provider long before this.
///
/// A relative path with separators (`./claude`, `bin/claude`) is rejected outright, and whatever
/// survives is put through [`reject_worktree_program`].
///
/// # Errors
/// [`PolicyCode::UnsafeArgv`] — the plan cannot be spawned safely, which is the same class of
/// defect as a denied flag.
fn resolve_program(plan: &SpawnPlan, ctx: &ArgvCtx<'_>) -> Result<PathBuf, PolicyError> {
    let file = plan.file.as_path();
    let resolved = if file.is_absolute() {
        file.to_path_buf()
    } else if file.components().count() == 1 {
        let name = file
            .to_str()
            .ok_or_else(|| unsafe_program("the provider binary name is not valid UTF-8", file))?;
        let path = plan.env.get("PATH").ok_or_else(|| {
            unsafe_program(
                "the worker environment has no absolute PATH entry to resolve the provider against",
                file,
            )
        })?;
        find_on_absolute_entries(OsStr::new(path), name).ok_or_else(|| {
            unsafe_program(
                "the provider binary is not on an absolute PATH entry of the worker environment",
                file,
            )
        })?
    } else {
        return Err(unsafe_program(
            "a relative program path would be resolved against the worker's own worktree",
            file,
        ));
    };

    reject_worktree_program(&resolved, ctx)?;
    Ok(resolved)
}

/// Refuses a program the worker could have put there, judged by **where the candidate is**, not by
/// what it eventually points at.
///
/// Following the final symlink first is the bug this function exists to avoid: a worker that creates
/// `<worktree>/codex -> /bin/sh` hands the checker a canonical target (`/bin/sh`) that is beyond
/// reproach, and the spawn then runs `sh` with the plan's argv — whose first token, for Codex, is
/// `exec`, so `sh` reads a script named `exec` out of its current directory, which is the worktree.
/// The binary's *location* is therefore the thing to judge, and the final component is deliberately
/// not followed: the parent is canonicalized (so `/var` vs `/private/var`, and any symlinked parent
/// directory, resolve to one spelling) and the file name is re-joined onto it.
///
/// Three spellings of the candidate are tested against two spellings of the worktree, because each
/// catches a different dodge: the lexical path catches a symlinked *intermediate* directory that
/// canonicalization would follow out of the worktree, the canonicalized-parent form catches a
/// worktree reached under another name, and the fully resolved target catches the reverse trick — a
/// symlink *outside* the worktree pointing back into it.
///
/// A symlink is named separately in the rejection: it is the deliberate shape of the attack, and a
/// human reading `audit.jsonl` should not have to guess. Symlinks elsewhere stay welcome —
/// Homebrew's `/opt/homebrew/bin/claude -> ../Cellar/…` is how the real CLI is usually installed,
/// and the fake CLIs are reached the same way in tests.
///
/// # Errors
/// [`PolicyCode::UnsafeArgv`].
fn reject_worktree_program(candidate: &Path, ctx: &ArgvCtx<'_>) -> Result<(), PolicyError> {
    let roots = [normalize(ctx.worktree), resolve(ctx.worktree)];
    let located = match (candidate.parent(), candidate.file_name()) {
        (Some(parent), Some(name)) => resolve(parent).join(name),
        _ => resolve(candidate),
    };
    let spellings = [normalize(candidate), located, resolve(candidate)];
    if !spellings
        .iter()
        .any(|spelling| roots.iter().any(|root| spelling.starts_with(root)))
    {
        return Ok(());
    }
    let is_symlink = std::fs::symlink_metadata(candidate)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false);
    Err(unsafe_program(
        if is_symlink {
            "the provider binary is a symlink planted in the worktree the worker writes to"
        } else {
            "the provider binary lies inside the worktree the worker writes to"
        },
        candidate,
    ))
}

fn unsafe_program(reason: &str, file: &Path) -> PolicyError {
    PolicyError::new(PolicyCode::UnsafeArgv, reason.to_string()).with_detail(serde_json::json!({
        "program": truncate(&file.display().to_string()),
    }))
}

/// [`crate::providers::find_on_path`]'s rule — absolute `PATH` entries only, executable regular
/// files only — applied to an explicit `PATH` value instead of this process's.
///
/// `providers` owns the process-wide lookup and cannot express this one without exposing its
/// internals; the rule is duplicated here rather than weakened, and both are covered by tests that
/// plant an executable reachable only through a relative entry. The absolute-entry filter is
/// redundant after [`sanitize_path`] and kept anyway: this function must be safe on any `PATH`.
///
/// Symlinks are followed here on purpose (`metadata`, not `symlink_metadata`) — that is how a real
/// CLI is usually installed. Whether the *candidate* is somewhere a worker could have planted it is
/// [`reject_worktree_program`]'s question, asked of whatever this returns.
fn find_on_absolute_entries(path_env: &OsStr, name: &str) -> Option<PathBuf> {
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

// ---------------------------------------------------------------------------
// Spawn
// ---------------------------------------------------------------------------

/// A child the supervisor started but does not own the lifetime of.
///
/// `pgid == pid` because [`spawn_detached`] calls `process_group(0)`: the child leads its own
/// group, which is what makes `killpg` reach a worker's own `Bash` children and nothing else.
/// `start_time` is the `ps -o lstart=` string, kept **verbatim** — it is compared as a string
/// across daemon restarts, so its formatting is part of the recorded identity of the process, not a
/// value to re-derive (design, § Process model: "Liveness probe").
#[derive(Debug)]
pub struct SpawnedProc {
    pub pid: i32,
    pub pgid: i32,
    pub start_time: String,
    /// The argv as spawned, for `attempt.started{argv}`.
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    /// The owned handle. Its presence is what tells T24's `signal_group` that this attempt cannot
    /// have suffered pid reuse and needs no re-probe before it signals; a re-attached attempt has
    /// no `SpawnedProc` at all.
    pub child: tokio::process::Child,
}

/// Everything that can go wrong between a checked plan and a running child.
///
/// None of these are policy rejections — the plan already passed [`assert_safe_argv`] — so they map
/// to `attempt.finished{spawn_failed}` (design, § Error Handling), not to an `audit.jsonl` line.
#[derive(Debug, Error)]
pub enum SpawnError {
    #[error("{op} {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not start `{program}`: {source}")]
    Exec {
        program: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("`{program}` exited before its pid could be recorded")]
    NoPid { program: PathBuf },
}

/// Writes the attempt's inputs to disk, then starts the provider **detached**.
///
/// On disk before the spawn (design, § On-disk layout): `argv.json` (the plan's argv verbatim — the
/// program itself is [`SpawnPlan::file`]), `prompt.txt` when [`prompt_token`] can identify one, and
/// every [`SpawnPlan::write_files`] entry (Codex's `--output-schema` document). `stdout.jsonl` and
/// `stderr.log` are opened for **append**, so a re-attached attempt's tail keeps its byte offsets.
///
/// The child's argv is `plan.argv` in full. `SpawnPlan.argv` holds the *arguments only* — the
/// program is `plan.file`, as `Command::args` expects (T14/T16: Claude's plan starts `["-p",
/// <prompt>, …]`, so the prompt is `argv[1]` here and index 2 of the command line the design writes
/// out with `claude` at index 0). The design's sketch of this call spells it `args(&argv[1..])`,
/// which assumed argv[0] was the program; passing that slice would drop Claude's `-p` and feed the
/// prompt as a flag.
///
/// `env_clear().envs(&plan.env)` is the second half of the env scrub: the child gets exactly the
/// allowlist check 5 verified and nothing this process inherited. `plan.file` is the **absolute**
/// program [`assert_safe_argv`] resolved, so no `PATH` search happens here — this process's current
/// directory is about to be a worker's worktree.
///
/// # Errors
/// [`SpawnError::Io`] if an input file or a stdio file cannot be written, [`SpawnError::Exec`] if
/// the program cannot be started (a missing CLI is `ENOENT` here), [`SpawnError::NoPid`] if the
/// child is already reaped before its pid can be read.
pub async fn spawn_detached(p: CheckedPlan, dir: PathBuf) -> Result<SpawnedProc, SpawnError> {
    let plan = p.0;
    check_required_version(&plan).await?;

    create_dir("create attempt dir", &dir).await?;
    let argv_json = serde_json::to_vec_pretty(&plan.argv).unwrap_or_else(|_| b"[]".to_vec());
    write_file("write argv.json", &dir.join(ARGV_FILE), &argv_json).await?;
    if let Some(prompt) = prompt_token(&plan.argv) {
        write_file(
            "write prompt.txt",
            &dir.join(PROMPT_FILE),
            prompt.as_bytes(),
        )
        .await?;
    }
    for (path, body) in &plan.write_files {
        if let Some(parent) = path.parent() {
            create_dir("create input dir", parent).await?;
        }
        write_file("write plan input", path, body.as_bytes()).await?;
    }

    let stdout = open_append(&dir.join(STDOUT_FILE)).await?;
    let stderr = open_append(&dir.join(STDERR_FILE)).await?;

    let mut command = Command::new(&plan.file);
    command
        .args(&plan.argv)
        .current_dir(&plan.cwd)
        .env_clear()
        .envs(&plan.env)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        // Its own process group: the timeout ladder signals the group, never this process's own.
        // `libc::setsid`/`pre_exec` would do the same thing in an `unsafe` block that runs between
        // `fork` and `exec`; this is the safe spelling of it (design, Revision log: "no `setsid`").
        .process_group(0)
        // A dropped handle must not kill a worker: after a daemon restart the supervisor re-attaches
        // to processes it no longer owns, so ownership is deliberately not lifetime-scoped.
        .kill_on_drop(false);

    let child = command.spawn().map_err(|source| SpawnError::Exec {
        program: plan.file.clone(),
        source,
    })?;
    let pid = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .ok_or_else(|| SpawnError::NoPid {
            program: plan.file.clone(),
        })?;
    let start_time = ps_start_time(pid).await.unwrap_or_default();

    Ok(SpawnedProc {
        pid,
        pgid: pid,
        start_time,
        argv: plan.argv,
        cwd: plan.cwd,
        child,
    })
}

/// Owns an unreaped process-group leader throughout probe cleanup. No PID from persisted state
/// is used: WNOWAIT retains this child's identity until its descendants have been signalled.
struct VersionProbe {
    child: tokio::process::Child,
    group: Option<Pid>,
}

impl VersionProbe {
    fn kill_group(&mut self) {
        if let Some(group) = self.group.take() { let _ = killpg(group, Signal::SIGKILL); }
    }
}
impl Drop for VersionProbe {
    fn drop(&mut self) { self.kill_group(); }
}

/// Poll the owned child without reaping it. This retains a zombie as a PID/PGID identity anchor
/// while descendants are killed; signalling a reaped PID could hit an unrelated reused group.
async fn version_child_exited(pid: Pid) -> io::Result<()> {
    loop {
        // SAFETY: zero is a valid initial siginfo_t; waitid writes only within that allocation.
        // The PID belongs to our still-owned, never-waited Child. WNOHANG never blocks the actor
        // runtime thread, and WNOWAIT deliberately leaves the exit available for Child::wait.
        let exited = {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe { libc::waitid(libc::P_PID, pid.as_raw() as libc::id_t,
                &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) };
            if result == -1 { return Err(io::Error::last_os_error()); }
            // SAFETY: successful waitid with WEXITED initializes the child identity fields.
            unsafe { info.si_pid() != 0 }
        };
        if exited { return Ok(()); }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Bounded compatibility check off the actor, using the already-resolved executable and scrubbed
/// environment. Timeout, oversized output and cancelled futures kill the entire owned group.
async fn check_required_version(plan: &SpawnPlan) -> Result<(), SpawnError> {
    use tokio::io::AsyncReadExt;
    let Some(expected) = &plan.required_version else { return Ok(()); };
    let result = async {
        let mut child = Command::new(&plan.file).arg("--version").current_dir(&plan.cwd)
            .env_clear().envs(&plan.env).stdin(Stdio::null()).stdout(Stdio::piped())
            .stderr(Stdio::null()).process_group(0).kill_on_drop(true).spawn()?;
        let stdout = child.stdout.take().ok_or_else(|| io::Error::other("version probe has no stdout"))?;
        let pid = child.id().and_then(|p| i32::try_from(p).ok())
            .ok_or_else(|| io::Error::other("version probe has no pid"))?;
        let mut probe = VersionProbe { child, group: Some(Pid::from_raw(pid)) };
        let mut bytes = Vec::new();
        let read = async {
            stdout.take(513).read_to_end(&mut bytes).await?;
            if bytes.len()>512 { return Err(io::Error::other("version output exceeds 512 bytes")); }
            Ok::<_,io::Error>(())
        };
        let checked = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(read, version_child_exited(Pid::from_raw(pid)))?;
            Ok::<_,io::Error>(())
        }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut,"CLI version probe exceeded five seconds"))
            .and_then(|r| r);
        probe.kill_group();
        let status = tokio::time::timeout(Duration::from_secs(2), probe.child.wait()).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "version probe cleanup exceeded two seconds"))??;
        checked?;
        let actual = String::from_utf8_lossy(&bytes);
        if !status.success() || actual.trim()!=expected {
            return Err(io::Error::other(format!("this lead profile requires {expected}; installed version differs")));
        }
        Ok::<_,io::Error>(())
    }.await;
    result.map_err(|source| SpawnError::Exec { program: plan.file.clone(), source })
}

/// The prompt token of a plan, when the argv shape identifies one beyond doubt.
///
/// Two shapes, both provider-neutral: the token after `-p` (Claude's fresh and resume argv), or the
/// final token when the one before it is not a flag (Codex ends `… -o <file> [<threadId>] <PROMPT>`;
/// Claude's plan always ends on a flag *value*, so it never matches this branch). Anything else
/// yields `None` and no `prompt.txt` is written — a missing convenience file is better than one
/// naming the wrong token.
fn prompt_token(argv: &[String]) -> Option<&str> {
    if let Some(index) = argv.iter().position(|token| token == "-p") {
        return argv.get(index + 1).map(String::as_str);
    }
    match argv {
        [.., before, last] if !before.starts_with('-') => Some(last),
        _ => None,
    }
}

/// `ps -o lstart= -p <pid>`, trimmed. `None` when the process is already gone — a scenario that
/// exits instantly is a normal attempt outcome, not a spawn failure, so the caller records an empty
/// start time and lets the liveness probe report the exit.
async fn ps_start_time(pid: i32) -> Option<String> {
    let output = Command::new(PS_BIN)
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .await
        .ok()?;
    parse_lstart(&output.stdout)
}

/// The one place `ps -o lstart=` output becomes a start-time string, so T24's `ProcessProbe` and
/// the value recorded at spawn cannot drift apart.
fn parse_lstart(raw: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(raw).trim().to_string();
    (!text.is_empty()).then_some(text)
}

async fn create_dir(op: &'static str, path: &Path) -> Result<(), SpawnError> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|source| SpawnError::Io {
            op,
            path: path.to_path_buf(),
            source,
        })
}

async fn write_file(op: &'static str, path: &Path, body: &[u8]) -> Result<(), SpawnError> {
    tokio::fs::write(path, body)
        .await
        .map_err(|source| SpawnError::Io {
            op,
            path: path.to_path_buf(),
            source,
        })
}

/// Opens one of the attempt's log files for append and hands back the `std` file `Stdio` needs.
async fn open_append(path: &Path) -> Result<std::fs::File, SpawnError> {
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .map_err(|source| SpawnError::Io {
            op: "open attempt log",
            path: path.to_path_buf(),
            source,
        })?;
    Ok(file.into_std().await)
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// A path reduced to one canonical spelling for comparison: `.`/`..` resolved lexically, then the
/// longest ancestor that exists canonicalized and the rest re-joined.
///
/// Both halves are needed. Canonicalizing alone fails for a file the spawn is about to *create*
/// (`<attemptDir>/output-schema.json`); lexical normalization alone would call a `/var/…` temp dir
/// and the `/private/var/…` it really is two different places on macOS. Iterative rather than
/// recursive so an absurdly long token cannot exhaust the stack.
fn resolve(path: &Path) -> PathBuf {
    let lexical = normalize(path);
    let mut trailing: Vec<&std::ffi::OsStr> = Vec::new();
    let mut cursor: &Path = &lexical;
    loop {
        if let Ok(real) = cursor.canonicalize() {
            let mut out = real;
            out.extend(trailing.iter().rev());
            return out;
        }
        match (cursor.parent(), cursor.file_name()) {
            (Some(parent), Some(name)) => {
                trailing.push(name);
                cursor = parent;
            }
            _ => return lexical,
        }
    }
}

/// Lexical normalization: drops `.`, pops a component for `..` (without ever climbing past the
/// root), and leaves everything else alone. Purely textual — it touches no filesystem, which is
/// what makes it safe to run on an argv token that may name nothing at all.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    // A relative path may legitimately start above itself; an absolute one may not,
                    // and `pop` already refuses to climb past `/`.
                    if !out.has_root() {
                        out.push("..");
                    }
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Caps a caller- or worker-influenced string before it is echoed into a rejection that lands in
/// `audit.jsonl`. Cuts on a char boundary.
fn truncate(s: &str) -> String {
    const LIMIT: usize = 120;
    match s.char_indices().nth(LIMIT) {
        Some((cut, _)) => format!("{}…", &s[..cut]),
        None => s.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Liveness
// ---------------------------------------------------------------------------

/// Is the process we recorded still the process running under that pid?
///
/// Two questions, deliberately asked together: `kill(pid, None)` answers "does this pid exist", and
/// the `lstart` string answers "is it still *ours*". A pid on macOS wraps around in the tens of
/// thousands, so a daemon that was down for a while can find a stranger's process wearing the pid
/// it recorded — and `signal_group` would otherwise `killpg` it (design, § Process model:
/// "Signalling a process we do not own is guarded").
///
/// The trait exists so tests can inject a probe and so `libproc` can replace `ps` later without
/// touching the supervisor; `ps` is what the design picked, because the recorded start time is
/// compared **as a string** across restarts and therefore needs one stable serialization.
pub trait ProcessProbe: Send + Sync {
    fn is_alive(&self, pid: i32, start_time: &str) -> bool;
    fn start_time(&self, pid: i32) -> Option<String>;
}

/// The production probe: `kill(pid, 0)` plus `ps -o lstart= -p <pid>`.
///
/// Blocking, and deliberately so — one `fork` per tick per **re-attached** attempt (≤ 2 concurrent
/// by `limits.maxConcurrentAttempts`), which is cheaper than the machinery to await it. An attempt
/// the supervisor still owns a [`SpawnedProc::child`] for never reaches this: `try_wait` answers
/// for it, and a pid we have not reaped cannot be recycled.
#[derive(Clone, Copy, Debug, Default)]
pub struct PsProbe;

impl ProcessProbe for PsProbe {
    fn is_alive(&self, pid: i32, start_time: &str) -> bool {
        // `0` is "every process in my own group" and negatives are group ids: neither is ever a
        // pid we recorded, and both would be catastrophic to signal, so they are never alive.
        if pid <= 0 {
            return false;
        }
        match kill(Pid::from_raw(pid), None) {
            Ok(()) => {}
            // The pid exists but belongs to another user — still alive; `lstart` decides identity.
            Err(Errno::EPERM) => {}
            Err(_) => return false,
        }
        // An empty recorded start time (the spawn's `ps` failed) can never match, so the attempt is
        // treated as dead rather than signalled on an unverified pid — the fail-closed direction.
        self.start_time(pid)
            .is_some_and(|actual| actual == start_time)
    }

    fn start_time(&self, pid: i32) -> Option<String> {
        if pid <= 0 {
            return None;
        }
        let output = std::process::Command::new(PS_BIN)
            .args(["-o", "lstart=", "-p", &pid.to_string()])
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        parse_lstart(&output.stdout)
    }
}

// ---------------------------------------------------------------------------
// Signalling
// ---------------------------------------------------------------------------

/// What one `killpg` did. `Gone` is not a failure: the ladder fires SIGTERM and then SIGKILL at a
/// process group that is normally already dead, so `ESRCH` is the expected answer and the ladder is
/// idempotent because of it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignalOutcome {
    Sent,
    /// `ESRCH` — no such process group.
    Gone,
    /// A re-attached attempt whose pid no longer carries the recorded `lstart`. **Nothing was
    /// signalled**; the attempt is `lost` (design, Revision 24).
    Mismatch,
    /// The kernel refused (`EPERM`), or the recorded pgid is not a group we may name. Nothing sent.
    Refused,
}

/// Who to signal, and whether we still own the process.
#[derive(Clone, Debug)]
struct SignalTarget {
    pid: i32,
    pgid: i32,
    start_time: String,
    /// True while a [`tokio::process::Child`] for this pid is alive in this process: the kernel
    /// cannot recycle an unreaped pid, so no re-probe is needed (and none is possible — a probe
    /// would see our own zombie).
    owned: bool,
}

/// Remembers that a signal was refused because the pid is no longer the process we recorded.
/// Every `signal_target` call site funnels through here, so no rung of the ladder can drop it.
fn record_mismatch(lost: &AtomicBool, outcome: SignalOutcome) {
    if outcome == SignalOutcome::Mismatch {
        lost.store(true, Ordering::SeqCst);
    }
}

fn record_cancel_signal(lost: &AtomicBool, refused: &AtomicBool, outcome: SignalOutcome) {
    record_mismatch(lost, outcome);
    if outcome == SignalOutcome::Refused { refused.store(true, Ordering::SeqCst); }
}

/// The **only** `killpg` in the crate (design, § `src/core/supervisor.rs`).
///
/// For a re-attached attempt the pid + `lstart` check is re-run *immediately* before the signal, so
/// a recycled pgid belonging to an unrelated process can never be signalled. The check cannot be
/// hoisted: any gap between deciding and signalling is the race it exists to close.
fn signal_target(probe: &dyn ProcessProbe, target: &SignalTarget, sig: Signal) -> SignalOutcome {
    // `killpg(0)` means "my own process group" — the control plane and its own children. A
    // recorded pgid of 0 or less is a bug or a corrupted log, never something to signal.
    if target.pgid <= 0 {
        return SignalOutcome::Refused;
    }
    if !target.owned && !probe.is_alive(target.pid, &target.start_time) {
        return SignalOutcome::Mismatch;
    }
    match killpg(Pid::from_raw(target.pgid), sig) {
        Ok(()) => SignalOutcome::Sent,
        Err(Errno::ESRCH) => SignalOutcome::Gone,
        Err(_) => SignalOutcome::Refused,
    }
}

// ---------------------------------------------------------------------------
// The supervisor
// ---------------------------------------------------------------------------

/// How long a process group has between SIGTERM and SIGKILL (design, § Error Handling: "SIGTERM →
/// 5 s → SIGKILL"). Fixed rather than configurable: it is the worker's chance to flush its own
/// transcript, and shortening it silently would lose the tail of a timed-out attempt.
const KILL_GRACE: Duration = Duration::from_secs(5);

/// The grace period between the two rungs on the **fatal** shutdown path.
///
/// Shorter than [`KILL_GRACE`] on purpose. The normal ladder can afford five seconds because it
/// runs detached while the daemon keeps serving; this one is awaited by the actor's very last turn,
/// during which nothing is answered and nothing can be recorded. Two seconds is long enough for a
/// worker that handles SIGTERM to finish and short enough that a broken daemon exits promptly.
const FATAL_KILL_GRACE: Duration = Duration::from_secs(2);

/// How long the fatal path waits for a signalled process to actually disappear before giving up on
/// it and saying so. Bounded because a daemon that cannot exit is a worse failure than one that
/// exits having logged which pid it could not account for.
const FATAL_REAP_WAIT: Duration = Duration::from_secs(2);

/// `<attemptDir>/result.txt` — the worker's final free text, the attempt's `resultPath`.
const RESULT_TEXT_FILE: &str = "result.txt";

/// `<attemptDir>/result.json` — the structured output, written only when it validates.
const RESULT_JSON_FILE: &str = "result.json";

/// `<attemptDir>/last-message.txt` — Codex's `-o` file. Read **after** the process exits: the CLI
/// writes it when the stream ends, so reading it earlier reads nothing.
const LAST_MESSAGE_FILE: &str = "last-message.txt";

/// `<runDir>/diffs/<attemptId>.patch` — the frozen diff handed to the reviewer.
const DIFFS_DIR: &str = "diffs";

/// Most bytes of `<attemptDir>/stderr.log` handed to [`ProviderAdapter::extract_result`] as
/// [`ResultCtx::stderr_head`].
///
/// A **head**, and a small one, for the same reason `HandoffEnvelope::head` is: stderr is
/// provider-authored text of unbounded length, and the one decision that reads it — an
/// authentication signature, which a CLI prints before it does anything else — is always in the
/// first few lines. The whole file stays on disk at `stderrPath` for a human.
pub const STDERR_HEAD_BYTES: usize = 4 * 1024;

/// Regular assistant messages retained for one lead attempt. The first later block produces one
/// marker; every block after that is discarded.
const MAX_AGENT_MESSAGES: usize = 500;
const MESSAGE_TRUNCATION_MARKER: &str = "[assistant message stream truncated after 500 events]";

/// Everything the supervisor must know about one attempt beyond the process itself.
///
/// The design's field list ends at `writes`. The five that follow it are what the finalize path
/// this module owns cannot do without: it validates the worker's output (`schema`/`schema_name`),
/// matches the changed files against the run's denylist (`denylist`), prices a turn the provider
/// did not price itself (`rate`), and records the attempt's spawn budget in `attempt.started`
/// (`spawn_budget_usd`). Each arrives as an already-prepared value — a compiled [`GlobSet`], a
/// post-processed schema document, a price card — so the supervisor still knows nothing about
/// roles, providers or configuration, which is the boundary the design actually draws.
pub struct AttemptContext {
    pub run: RunId,
    pub agent: AgentId,
    pub attempt: AttemptId,
    /// `$ACP_STATE_DIR/runs/<runId>/attempts/<attemptId>` (design, § On-disk layout).
    pub dir: PathBuf,
    pub adapter: Arc<dyn ProviderAdapter>,
    pub timeout: Duration,
    pub pre_sha: String,
    pub kind: AttemptKind,
    /// Needed at the tailer boundary: only a lead may publish assistant prose.
    pub role: RoleName,
    pub worktree: PathBuf,
    /// The supervisor's one mutex for `worktree`. The exact `Arc` also goes to integrate commits,
    /// so finalization after a fresh spawn, resume, or daemon reattach cannot race approval.
    pub worktree_lock: Arc<Mutex<()>>,
    pub writes: bool,
    /// The post-processed (`$schema`-stripped) document the worker's structured output must
    /// validate against — the same artifact the CLI was handed (V7).
    pub schema: Arc<Value>,
    pub schema_name: SchemaName,
    /// The run's `denylistGlobs`, compiled once by the caller.
    pub denylist: Arc<GlobSet>,
    pub spawn_budget_usd: f64,
    /// The model's price card, for `attempt.usage` when the provider reports no cost of its own.
    pub rate: Option<Rate>,
    /// The provider session already recorded for this attempt (`agent.session` →
    /// `AgentHandle.session_id`), or `None` for a fresh spawn.
    ///
    /// It exists for [`Supervisor::reattach`]: a resumed tail starts *after* the `system/init` /
    /// `thread.started` line, so without it `extract_result` would be handed a stream with no
    /// session in it — which Codex's adapter reads as "no thread exists" and returns an empty
    /// result for, and which the terminal-state table reads as `no_session`. Seeding it makes the
    /// resumed stream look exactly like the one the first supervisor saw.
    pub session_id: Option<String>,
}

/// What the supervisor posts back to the actor's mailbox.
///
/// The first two are **wake-ups, not truth**: they only say "look now" a little sooner than the
/// tick would have, so a dropped or full mailbox costs a round of latency and never correctness.
/// The supervisor names its own type because it must compile before the actor does; T33's
/// `Command` enum carries the same three cases and forwards them verbatim.
///
/// [`SupervisorSignal::FinalizeReady`] is different, and is the one signal that **must** be
/// delivered: it carries the only copy of a finished attempt's terminal events. Its sender awaits
/// capacity rather than using `try_send`, because dropping it would strand the attempt `running`
/// forever (Codex review of T33, finding 1).
#[derive(Clone, PartialEq, Debug)]
pub enum SupervisorSignal {
    /// The process was reaped. **The log is not yet whole** when this arrives — `attempt.finished`
    /// and everything around it lands with the `FinalizeReady` that follows.
    AttemptExited {
        attempt: AttemptId,
        exit_code: Option<i32>,
        signal: Option<String>,
    },
    AttemptTimeout {
        attempt: AttemptId,
    },
    /// The git and filesystem half of finalizing `attempt` has finished, off the actor. The report
    /// is plain data; applying it is [`Supervisor::apply_finalize`], which only appends.
    FinalizeReady {
        attempt: AttemptId,
        report: Box<FinalizeReport>,
    },
}

/// Everything `cancel` can refuse to do.
#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("attempt {0} is not running")]
    NotRunning(AttemptId),
    #[error("the operating system refused the stop signal for attempt {0}")]
    SignalRefused(AttemptId),
}

/// Tails, times out and finalizes every running attempt.
///
/// It owns no `Registry`: every method that appends takes `&mut Registry` from the actor, which is
/// the single writer of the event log (design, § `src/core/registry.rs`).
pub struct Supervisor {
    tick: Duration,
    probe: Arc<dyn ProcessProbe>,
    tx: mpsc::Sender<SupervisorSignal>,
    running: HashMap<AttemptId, Running>,
    /// Attempts whose [`FinalizeReport`] has been applied **in full**. `policy.violation` and
    /// `diff.frozen` are not deduplicated by the reducer (only `attempt.usage`/`result`/`finished`
    /// are, by C2), so a report that reached the actor twice would duplicate them. One report is
    /// produced per attempt and this is the guard that it is applied once.
    ///
    /// An attempt lands here only once its terminal `attempt.finished` is durably appended — never
    /// before (Codex review of T33, round 2, finding 1).
    finalized: HashSet<AttemptId>,
    /// Reports whose append failed part-way. They are retried on every tick; until one succeeds the
    /// attempt is still `running` in the projection and the events that end it exist nowhere but
    /// here, so dropping one would strand the attempt forever.
    pending_finalize: HashMap<AttemptId, PendingFinalize>,
    finalizing: HashSet<AttemptId>,
    /// One mutex per recorded worktree path. Both attempt contexts and integrate helpers obtain
    /// their `Arc` here, including after restart, so there is no second invisible lock pool.
    worktree_locks: HashMap<PathBuf, Arc<Mutex<()>>>,
}

impl Supervisor {
    #[must_use]
    pub fn new(
        tick: Duration,
        probe: Arc<dyn ProcessProbe>,
        tx: mpsc::Sender<SupervisorSignal>,
    ) -> Self {
        Self {
            tick,
            probe,
            tx,
            running: HashMap::new(),
            finalized: HashSet::new(),
            pending_finalize: HashMap::new(),
            finalizing: HashSet::new(),
            worktree_locks: HashMap::new(),
        }
    }

    /// The single source of the mutex that serializes git writes in one worktree.
    ///
    /// Keyed by the recorded path rather than a canonicalized one: every producer carries the
    /// same recorded path, and this is process-local serialization rather than a filesystem lock.
    pub fn worktree_lock(&mut self, worktree: &Path) -> Arc<Mutex<()>> {
        Arc::clone(
            self.worktree_locks
                .entry(worktree.to_path_buf())
                .or_default(),
        )
    }

    /// The interval the actor should call [`Supervisor::tick`] at — 2 s in production, 25 ms in
    /// tests (design: "`tick_ms` is injectable").
    #[must_use]
    pub fn tick_interval(&self) -> Duration {
        self.tick
    }

    #[must_use]
    pub fn is_running(&self, id: &AttemptId) -> bool {
        self.running.contains_key(id)
    }

    /// Live ownership is authoritative even if `attempt.started` could not be appended.
    #[must_use]
    pub fn active_attempts(&self) -> Vec<(AttemptId, RunId)> {
        self.running.iter().map(|(id, running)| (*id, running.ctx.run)).collect()
    }

    #[must_use]
    pub fn cancellation_signal_refused(&self, id: &AttemptId) -> bool {
        self.running.get(id).is_some_and(|running| running.cancel_refused.load(Ordering::SeqCst))
    }

    /// Bytes of `stdout.jsonl` consumed as **complete** lines. The unterminated tail after it is
    /// buffered in memory and is deliberately not counted (C6) — exposed so a test can assert the
    /// offset stopped at the last `\n`.
    #[must_use]
    pub fn byte_offset(&self, id: &AttemptId) -> Option<u64> {
        self.running.get(id).map(|run| run.offset)
    }

    /// Takes ownership of a freshly spawned child: records `attempt.started`, arms the deadline and
    /// starts tailing.
    ///
    /// Returns the attempt as the registry projects it. If the log write itself failed the same
    /// record is returned unprojected — the attempt is still supervised, because a worker process
    /// exists either way and abandoning it would leak it.
    pub fn adopt(&mut self, p: SpawnedProc, ctx: AttemptContext, reg: &mut Registry) -> Attempt {
        let SpawnedProc {
            pid,
            pgid,
            start_time,
            argv,
            cwd,
            child,
        } = p;
        let started_at = emit(
            reg,
            &ctx.run,
            EventPayload::AttemptStarted {
                attempt_id: ctx.attempt,
                agent_id: ctx.agent,
                attempt_kind: ctx.kind,
                dir: ctx.dir.clone(),
                argv,
                cwd,
                pid,
                pgid,
                start_time: start_time.clone(),
                pre_sha: ctx.pre_sha.clone(),
                timeout_sec: ctx.timeout.as_secs(),
                spawn_budget_usd: ctx.spawn_budget_usd,
            },
        )
        .map_or_else(registry::now_rfc3339, |event| event.base.ts.clone());

        let attempt = reg
            .attempt(&ctx.attempt)
            .cloned()
            .unwrap_or_else(|| attempt_record(&ctx, pid, pgid, &start_time, &started_at));
        let timeout = ctx.timeout;
        let mut running = Running::new(ctx, pid, pgid, start_time, Some(child), Instant::now());
        self.arm_deadline(&mut running, timeout);
        self.running.insert(attempt.attempt_id, running);
        attempt
    }

    /// Resumes supervision of an attempt this process did not start — the restart path.
    ///
    /// Three things are restored (design, § Process model: "Re-attach"):
    ///
    /// * the tail position, from `Attempt.src_line` — which the reducer already maintains as the
    ///   max `srcLine` over *all* tailer-derived events (`agent.progress`, `agent.message`,
    ///   `agent.session`, `attempt.usage`, `attempt.result`), so re-deriving it by scanning the log would recompute
    ///   the projection the registry hands us. `stdout.jsonl` is re-opened and that many complete
    ///   lines are skipped; re-parsing the few lines after the last event-producing one is harmless
    ///   (C2 makes terminal-attempt events reducer no-ops);
    /// * the deadline, re-armed from `started_at + timeout_sec` so a worker that outlived the
    ///   control plane is still bounded by its original timeout — an already-expired one fires
    ///   immediately;
    /// * the durable lead-message count, so a daemon restart cannot reset the per-attempt cap;
    /// * nothing else: there is no `Child`, so this attempt's liveness is the pid + `lstart` probe
    ///   and its `exitCode` stays `null`.
    ///
    /// The design spells the second parameter `adapter: Arc<dyn ProviderAdapter>`. It is the
    /// [`AttemptContext`] here instead, because `Attempt` carries neither the worktree, the writes
    /// flag, the result schema nor the denylist the finalize path needs, and `ctx.adapter` is the
    /// adapter the design asked for.
    pub fn reattach(&mut self, a: &Attempt, ctx: AttemptContext, reg: &Registry) {
        let (Some(pid), Some(pgid)) = (a.pid, a.pgid) else {
            tracing::warn!(attempt = %a.attempt_id, "re-attach skipped: the attempt records no pid");
            return;
        };
        let elapsed = elapsed_since(&a.started_at);
        let started = Instant::now()
            .checked_sub(elapsed)
            .unwrap_or_else(Instant::now);
        let mut running = Running::new(
            ctx,
            pid,
            pgid,
            a.start_time.clone().unwrap_or_default(),
            None,
            started,
        );
        let (offset, src_line) = resume_offset(&a.dir.join(STDOUT_FILE), a.src_line);
        running.offset = offset;
        running.src_line = src_line;
        running.resumed_from = src_line;
        let prior_messages = reg.agent_message_count(&a.run_id, &a.attempt_id);
        (running.message_events, running.message_marker_emitted) =
            restored_message_limit(prior_messages);
        let remaining = Duration::from_secs(a.timeout_sec).saturating_sub(elapsed);
        self.arm_deadline(&mut running, remaining);
        self.running.insert(a.attempt_id, running);
    }

    /// Requests a cancellation: records it, sends SIGTERM now and schedules the SIGKILL.
    ///
    /// It does not await the grace period — the ladder is a detached task, so a cancel is one
    /// mailbox turn and not five seconds of a blocked actor. The terminal `attempt.finished` is
    /// appended by the tick that observes the process die, so a cancellation of a worker that
    /// ignores SIGTERM still resolves, five seconds later, on SIGKILL.
    ///
    /// The design's signature omits `reg`; appending `attempt.cancel_requested` needs it, and
    /// `adopt`/`tick` are handed the registry the same way.
    ///
    /// # Errors
    /// [`SupervisorError::NotRunning`] if the attempt already finished (or was never adopted) —
    /// which the caller may treat as success, since the process is gone either way.
    pub async fn cancel(
        &mut self,
        id: &AttemptId,
        by: CancelBy,
        reg: &mut Registry,
    ) -> Result<(), SupervisorError> {
        let Some(run) = self.running.get_mut(id) else {
            return Err(SupervisorError::NotRunning(*id));
        };
        run.cancel_by = Some(by);
        let run_id = run.ctx.run;
        let target = run.target();
        let lost = Arc::clone(&run.lost);
        let refused = Arc::clone(&run.cancel_refused);
        if let Some(ladder) = run.ladder.take() {
            // A cancellation supersedes the timeout ladder: one ladder per attempt, always the
            // latest, so an aborted deadline can never fire at a pid the kernel has since reused.
            ladder.abort();
        }
        emit(
            reg,
            &run_id,
            EventPayload::AttemptCancelRequested {
                attempt_id: *id,
                by,
            },
        );
        // A cancellation of a process we can no longer identify signals nothing and cancels
        // nothing: the attempt is `lost`, and saying "cancelled" would claim we ended something we
        // never touched.
        let outcome = signal_target(&*self.probe, &target, Signal::SIGTERM);
        record_cancel_signal(&lost, &refused, outcome);
        let handle = self.spawn_kill(target, lost, refused);
        if let Some(run) = self.running.get_mut(id) {
            run.ladder = Some(handle);
        }
        if outcome == SignalOutcome::Refused { return Err(SupervisorError::SignalRefused(*id)); }
        Ok(())
    }

    /// One pass over every running attempt: tail, coalesce, liveness, and finalize whatever ended.
    pub async fn tick(&mut self, reg: &mut Registry) {
        let ids: Vec<AttemptId> = self.running.keys().copied().collect();
        for id in ids {
            self.tick_attempt(id, reg).await;
        }
    }

    /// The design's `signal_group`: the guarded path to `killpg` for an attempt the caller holds
    /// the [`Attempt`] record of. `Mismatch` means nothing was signalled and the attempt is `lost`.
    #[must_use]
    pub fn signal_group(&self, a: &Attempt, sig: Signal) -> SignalOutcome {
        let running = self.running.get(&a.attempt_id);
        let target = SignalTarget {
            pid: a.pid.unwrap_or(0),
            pgid: a.pgid.unwrap_or(0),
            start_time: a.start_time.clone().unwrap_or_default(),
            owned: running.is_some_and(|run| run.child.is_some()),
        };
        let outcome = signal_target(&*self.probe, &target, sig);
        if let Some(run) = running {
            // `&self` is enough to record it: the flag is shared, which is what lets the design's
            // "no-ops and records `attempt.finished{lost}`" happen on the next tick.
            record_mismatch(&run.lost, outcome);
        }
        outcome
    }

    async fn tick_attempt(&mut self, id: AttemptId, reg: &mut Registry) {
        let probe = Arc::clone(&self.probe);
        let Some(run) = self.running.get_mut(&id) else {
            return;
        };

        // `drain_stdout` has already advanced the in-memory file offset by the time it returns a
        // batch. If an append failed, retry that exact batch before reading any later provider
        // line; otherwise a later progress event could commit a cursor past the missing message.
        if !run.retry_pending_batch(reg) {
            return;
        }
        let batch = run.drain_stdout(false).await;
        if !run.emit_or_park(reg, batch, 0) {
            return;
        }

        // The deadline task cannot append (it holds no registry), so the record the Error Handling
        // table calls for — `attempt.cancel_requested{by:timeout}` — is written by the first tick
        // that observes the flag it set.
        if run.timed_out.load(Ordering::SeqCst) && !run.timeout_announced {
            run.timeout_announced = true;
            let run_id = run.ctx.run;
            emit(
                reg,
                &run_id,
                EventPayload::AttemptCancelRequested {
                    attempt_id: id,
                    by: CancelBy::Timeout,
                },
            );
        }

        let Some(exit) = run.poll_exit(&*probe).await else {
            return;
        };
        let _ = self.tx.try_send(SupervisorSignal::AttemptExited {
            attempt: id,
            exit_code: exit.exit_code,
            signal: exit.signal.clone(),
        });
        let run = self.running.remove(&id).expect("borrowed above");
        // Everything from here on is git and file I/O, so it runs off the actor (decision 11 —
        // Codex review of T33, finding 1). `tick` returns now; the terminal events arrive with
        // `SupervisorSignal::FinalizeReady`.
        self.spawn_finalize(run, exit);
    }

    /// Runs the git + filesystem half of finalizing an exited attempt in a helper task and posts
    /// the resulting [`FinalizeReport`] back through [`SupervisorSignal::FinalizeReady`].
    ///
    /// Bounded by [`GIT_OP_TIMEOUT`](crate::workspace::git::GIT_OP_TIMEOUT) exactly like the
    /// actor's other helpers. A helper that runs out of time still produces a report — a
    /// fail-closed `escalate` — because an attempt whose workspace could not be read is precisely
    /// the case the design blocks the run for, and silently leaving it `running` would strand it.
    fn spawn_finalize(&mut self, mut run: Running, exit: ExitInfo) {
        self.finalizing.insert(run.ctx.attempt);
        if let Some(ladder) = run.ladder.take() {
            // The pid is reaped by now; a ladder that fired after this would name a free pid.
            ladder.abort();
        }
        let attempt = run.ctx.attempt;
        let fallback = FinalizeFallback::capture(&run, &exit);
        let tx = self.tx.clone();
        tokio::spawn(async move {
            // Waiting behind an approval is ordinary serialization, not a workspace failure and
            // never a worker violation. Acquire outside the finalize timeout; once acquired, the
            // owned guard lives through every inspection/remediation/freeze until the report is
            // complete (or the bounded finalize future is dropped).
            let serialized = if run.ctx.writes {
                Some(Arc::clone(&run.ctx.worktree_lock).lock_owned().await)
            } else {
                None
            };
            let report = match tokio::time::timeout(
                git::GIT_OP_TIMEOUT,
                finalize_prepare(run, exit, serialized),
            )
            .await
            {
                Ok(report) => report,
                Err(_elapsed) => fallback.timed_out(),
            };
            // `send`, not `try_send`: this carries the only copy of the attempt's terminal events.
            let _ = tx
                .send(SupervisorSignal::FinalizeReady {
                    attempt,
                    report: Box::new(report),
                })
                .await;
        });
    }

    /// Applies a [`FinalizeReport`] — the actor's `Command::FinalizeReady` turn.
    ///
    /// Nothing here is I/O beyond the log itself: every decision was made in the helper, so this is
    /// `Registry::append` in the design's order and nothing else.
    ///
    /// **Failure is not final.** An append that fails leaves the report parked in
    /// `pending_finalize` and the attempt *unmarked*, so the next tick retries it. The alternative,
    /// which this replaced, was to mark the attempt finalized up front and let `emit` swallow the
    /// error: a half-written report then left an attempt `running` in the log with its
    /// `attempt.finished` nowhere, its `Running` already dropped, and the only copy of its terminal
    /// events discarded as a duplicate (Codex review of T33, round 2, finding 1).
    ///
    /// # Errors
    /// [`RegistryError`] from the append that failed. The caller does not have to act on it — the
    /// retry is automatic — but it is returned rather than logged so a caller that wants to count
    /// failures can.
    pub fn apply_finalize(
        &mut self,
        report: FinalizeReport,
        reg: &mut Registry,
    ) -> Result<(), RegistryError> {
        if self.finalized.contains(&report.attempt) {
            tracing::debug!(attempt = %report.attempt, "finalize report already applied");
            return Ok(());
        }
        let attempt = report.attempt;
        let pending = self
            .pending_finalize
            .entry(attempt)
            .or_insert(PendingFinalize {
                report,
                next: 0,
                failures: 0,
            });
        Self::drain_pending(pending, reg)?;
        self.pending_finalize.remove(&attempt);
        self.finalizing.remove(&attempt);
        self.finalized.insert(attempt);
        Ok(())
    }

    /// Retries every parked finalize report and surfaces a transcript batch that exhausted the
    /// same append budget. Called once per tick by the actor.
    ///
    /// # Errors
    /// [`FinalizeStalled`] when one report or tailer batch has used up
    /// [`MAX_FINALIZE_ATTEMPTS`]. The event log is the only durable truth, so a log that cannot be
    /// written is not a run-level problem to record — recording is the thing that is broken. The
    /// actor treats it as fatal: it stops, and every door then answers `CoreError::Unavailable`
    /// (design, § Error Handling — "`serve` exits non-zero rather than serving stale state").
    pub fn retry_finalize(&mut self, reg: &mut Registry) -> Result<(), FinalizeStalled> {
        let stalled_batch = self.running.iter().find_map(|(attempt, run)| {
            run.pending_batch
                .as_ref()
                .filter(|pending| pending.failures >= MAX_FINALIZE_ATTEMPTS)
                .map(|pending| (*attempt, pending.failures))
        });
        if let Some((attempt, failures)) = stalled_batch {
            let pending = self
                .running
                .get_mut(&attempt)
                .and_then(|run| run.pending_batch.take())
                .expect("the stalled transcript batch still exists");
            return Err(FinalizeStalled {
                attempt,
                failures,
                source: pending.last_error,
            });
        }

        let ids: Vec<AttemptId> = self.pending_finalize.keys().copied().collect();
        for attempt in ids {
            let Some(pending) = self.pending_finalize.get_mut(&attempt) else {
                continue;
            };
            match Self::drain_pending(pending, reg) {
                Ok(()) => {
                    self.pending_finalize.remove(&attempt);
                    self.finalizing.remove(&attempt);
                    self.finalized.insert(attempt);
                    tracing::info!(%attempt, "a parked finalize report was applied on retry");
                }
                Err(err) => {
                    let failures = pending.failures;
                    tracing::warn!(%attempt, failures, %err, "appending a finalize report failed");
                    if failures >= MAX_FINALIZE_ATTEMPTS {
                        return Err(FinalizeStalled {
                            attempt,
                            failures,
                            source: err,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Appends what is left of a parked report, advancing `next` past every event that lands.
    ///
    /// `next` makes an in-process retry exact; [`already_recorded`] makes it *safe* even when it is
    /// not — a report re-delivered from index 0, or resumed after the log grew underneath it, still
    /// cannot duplicate an event the projection already holds.
    fn drain_pending(
        pending: &mut PendingFinalize,
        reg: &mut Registry,
    ) -> Result<(), RegistryError> {
        let run = pending.report.run;
        while pending.next < pending.report.events.len() {
            let payload = &pending.report.events[pending.next];
            // Several text blocks may be byte-identical and share one source line. Their ordinal
            // inside the report is therefore the only retry key the fixed wire shape permits.
            let occurrence = pending.report.events[..pending.next]
                .iter()
                .filter(|prior| *prior == payload)
                .count()
                + 1;
            if !already_recorded(reg, &run, payload, occurrence) {
                reg.append(&run, payload.clone()).inspect_err(|_| {
                    pending.failures += 1;
                })?;
            }
            pending.next += 1;
        }
        Ok(())
    }

    /// Ends every live worker and does not return until they are gone.
    ///
    /// Best effort, and **appends nothing** — it takes no `Registry`, which is the compile-time
    /// half of that promise. It is called on one path only: the actor stopping because the event
    /// log is unwritable.
    ///
    /// That exception is worth stating against the design, because the design says the opposite
    /// for the *normal* exit: "Exit path (C3) … Workers survive; a restart re-attaches", and
    /// `kill_on_drop` stays `false` and `.process_group(0)` exists precisely so "a `serve` restart
    /// never kills a worker". Surviving is safe there because the log records what each worker was
    /// doing and a restart picks it back up. Neither holds once the log cannot be written: nothing
    /// more can be recorded about these processes, so a restart could not re-attach them, and they
    /// would go on holding worktrees, spending budget and editing files with nobody watching. So
    /// the normal cancellation path is left exactly as C3 specifies, and only the fatal path
    /// signals (Codex review of T33, round 3).
    ///
    /// **The whole ladder is awaited here.** Scheduling the SIGKILL rung in a detached task — which
    /// is right for the timeout ladder, whose daemon keeps running — is wrong on this path: the
    /// actor returns immediately afterwards, and a runtime that shuts down before the grace period
    /// elapses drops that task, so a worker that ignores SIGTERM outlives the daemon anyway (Codex
    /// review of T33, round 4). So: SIGTERM to every group, one [`FATAL_KILL_GRACE`], SIGKILL to
    /// whatever is left, then reap.
    ///
    /// Every signal goes through the same guarded chokepoint as the ladder, and the second rung
    /// **re-probes** before firing: an attempt whose pid no longer carries its recorded `lstart` is
    /// skipped, never signalled, so a recycled pid belonging to a stranger is not killed on the way
    /// out.
    ///
    /// Returns the attempts that were signalled.
    pub async fn abandon_all(&mut self) -> Vec<AttemptId> {
        // Drained first: the loop below needs `&self.probe`, and holding the map's iterator across
        // that would borrow `self` twice.
        let live: Vec<Abandoning> = self
            .running
            .drain()
            .map(|(attempt, mut run)| Abandoning {
                attempt,
                target: run.target(),
                lost: Arc::clone(&run.lost),
                ladder: run.ladder.take(),
                child: run.child.take(),
            })
            .collect();

        // Rung one, to everything at once, so the grace period is spent once rather than per worker.
        let mut signalled: Vec<Abandoning> = Vec::new();
        for mut entry in live {
            if let Some(ladder) = entry.ladder.take() {
                // The pid is about to be signalled by us; a ladder firing later would name a pid
                // the kernel may have handed to somebody else.
                ladder.abort();
            }
            let outcome = signal_target(&*self.probe, &entry.target, Signal::SIGTERM);
            record_mismatch(&entry.lost, outcome);
            if outcome == SignalOutcome::Mismatch {
                tracing::warn!(attempt = %entry.attempt, pid = entry.target.pid,
                    "not signalled: the pid is no longer ours");
                continue;
            }
            signalled.push(entry);
        }
        if signalled.is_empty() {
            return Vec::new();
        }

        tokio::time::sleep(FATAL_KILL_GRACE).await;

        // Rung two. `ESRCH` is the expected answer for a worker that took the first rung, and it is
        // not a failure — that is what makes the ladder idempotent.
        for entry in &signalled {
            let outcome = signal_target(&*self.probe, &entry.target, Signal::SIGKILL);
            record_mismatch(&entry.lost, outcome);
        }

        let mut abandoned = Vec::new();
        for mut entry in signalled {
            match entry.child.take() {
                // Ours: `wait` both confirms it is gone and reaps it, so it does not linger as a
                // zombie waiting for a runtime that is about to stop.
                Some(mut child) => {
                    if tokio::time::timeout(FATAL_REAP_WAIT, child.wait())
                        .await
                        .is_err()
                    {
                        tracing::error!(attempt = %entry.attempt, pid = entry.target.pid,
                            "did not exit after SIGKILL");
                        continue;
                    }
                }
                // Re-attached: not our child, so there is nothing to reap and the probe is the
                // only way to ask.
                None => {
                    if !wait_until_gone(&*self.probe, &entry.target).await {
                        tracing::error!(attempt = %entry.attempt, pid = entry.target.pid,
                            "a re-attached worker is still alive after SIGKILL");
                        continue;
                    }
                }
            }
            abandoned.push(entry.attempt);
        }
        abandoned
    }

    /// Has this attempt's report been applied in full?
    #[must_use]
    pub fn is_finalized(&self, attempt: &AttemptId) -> bool {
        self.finalized.contains(attempt)
    }

    /// Finalization helpers and unapplied reports. A process may be reaped before its report
    /// arrives; that whole interval remains activity even if attempt.started was not projected.
    #[must_use]
    pub fn pending_finalize_count(&self) -> usize {
        self.finalizing.len() + self.pending_finalize.keys().filter(|id| !self.finalizing.contains(id)).count()
    }

    /// The timeout half of the ladder, as a detached task: sleep to the deadline, flag it, wake the
    /// actor, SIGTERM the group, wait the grace, SIGKILL it. `ESRCH` is ignored throughout, so the
    /// task is idempotent with respect to a worker that dies on its own in between.
    fn arm_deadline(&self, running: &mut Running, delay: Duration) {
        let target = running.target();
        let probe = Arc::clone(&self.probe);
        let tx = self.tx.clone();
        let flag = Arc::clone(&running.timed_out);
        let lost = Arc::clone(&running.lost);
        let attempt = running.ctx.attempt;
        if let Some(previous) = running.ladder.take() {
            previous.abort();
        }
        running.ladder = Some(tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            flag.store(true, Ordering::SeqCst);
            let _ = tx.try_send(SupervisorSignal::AttemptTimeout { attempt });
            // A rung that could not be delivered because the pid is somebody else's does not make
            // the attempt a timeout: it makes it `lost`, and the flag is how the tick learns that.
            record_mismatch(&lost, signal_target(&*probe, &target, Signal::SIGTERM));
            tokio::time::sleep(KILL_GRACE).await;
            record_mismatch(&lost, signal_target(&*probe, &target, Signal::SIGKILL));
        }));
    }

    /// The second half of the ladder on its own, for a cancellation whose SIGTERM has already gone.
    fn spawn_kill(&self, target: SignalTarget, lost: Arc<AtomicBool>, refused: Arc<AtomicBool>) -> JoinHandle<()> {
        let probe = Arc::clone(&self.probe);
        tokio::spawn(async move {
            tokio::time::sleep(KILL_GRACE).await;
            record_cancel_signal(&lost, &refused, signal_target(&*probe, &target, Signal::SIGKILL));
        })
    }
}

fn restored_message_limit(prior_messages: usize) -> (usize, bool) {
    (
        prior_messages.min(MAX_AGENT_MESSAGES),
        prior_messages > MAX_AGENT_MESSAGES,
    )
}

// ---------------------------------------------------------------------------
// One running attempt
// ---------------------------------------------------------------------------

/// The supervisor's private per-attempt state: the tail position, the parsed stream so far, and the
/// handles that end it.
struct Running {
    ctx: AttemptContext,
    pid: i32,
    pgid: i32,
    start_time: String,
    /// `None` for a re-attached attempt — the process is not this one's child, so its liveness is
    /// the pid + `lstart` probe and no exit code is knowable.
    child: Option<tokio::process::Child>,
    /// Bytes of `stdout.jsonl` consumed as complete lines; advances only to the last `\n` (C6).
    offset: u64,
    /// The unterminated tail read past `offset`, kept until its `\n` arrives.
    partial: Vec<u8>,
    /// 1-based index of the last complete line parsed.
    src_line: u64,
    /// Every normalized event parsed so far — what `extract_result` is handed at the end.
    events: Vec<NormalizedEvent>,
    session: Option<String>,
    /// The `src_line` the tail resumed *after* — 0 whenever this supervisor watched the attempt
    /// from its first byte, which is what makes "no session line was ever seen" evidence.
    resumed_from: u64,
    usage: Option<UsageLine>,
    saw_final: bool,
    started: Instant,
    timed_out: Arc<AtomicBool>,
    timeout_announced: bool,
    /// Set the moment any signal attempt comes back [`SignalOutcome::Mismatch`]: the pid this
    /// attempt records is no longer carrying the `lstart` it was spawned with, so **nothing was
    /// signalled** and the process this supervisor was watching is unaccounted for.
    ///
    /// An `Arc<AtomicBool>` rather than a `bool` because the two writers are a detached ladder task
    /// and `signal_group(&self)`, neither of which holds `&mut Running` (design, Revision 24).
    lost: Arc<AtomicBool>,
    /// Both rungs retain a refusal for lifecycle status without confusing it with lost identity.
    cancel_refused: Arc<AtomicBool>,
    cancel_by: Option<CancelBy>,
    ladder: Option<JoinHandle<()>>,
    message_events: usize,
    message_marker_emitted: bool,
    /// A transcript batch whose durable append stopped partway through. The offset already points
    /// beyond it, so this is the only in-process copy and must land before stdout advances again.
    pending_batch: Option<PendingBatch>,
}

/// The last `attempt.usage` figures seen on the stream, held until the attempt ends: cost accrues
/// per line, and the design appends exactly one usage event per attempt, on the drain.
struct UsageLine {
    src_line: u64,
    tokens: TokenUsage,
    cost_usd: Option<f64>,
}

/// What one tick parsed that turns into events: the session id, if it appeared, and the **last**
/// phase line, because a tick emits at most one coalesced `agent.progress`.
#[derive(Default)]
struct Batch {
    session: Option<(u64, String)>,
    phase: Option<(u64, String, Option<String>)>,
    /// Unlike `phase`, messages are never coalesced. The attempt-wide cap bounds this vector.
    messages: Vec<(u64, String, Option<crate::core::types::MessagePart>)>,
}

struct PendingBatch {
    batch: Batch,
    failures: u32,
    last_error: RegistryError,
}

/// How a process ended. `exit_code == None` with `owned == false` is a re-attached attempt that
/// simply stopped existing — the transcript is the only evidence of what happened to it.
#[derive(Clone, Debug)]
struct ExitInfo {
    exit_code: Option<i32>,
    signal: Option<String>,
    owned: bool,
}

impl Running {
    fn new(
        ctx: AttemptContext,
        pid: i32,
        pgid: i32,
        start_time: String,
        child: Option<tokio::process::Child>,
        started: Instant,
    ) -> Self {
        // A known session id is replayed into the parsed stream as the `system/init` line would
        // have produced it, so every adapter sees the session its result belongs to.
        let session = ctx.session_id.clone();
        let events = session
            .clone()
            .map(|session_id| NormalizedEvent::Session { session_id })
            .into_iter()
            .collect();
        Self {
            ctx,
            pid,
            pgid,
            start_time,
            child,
            offset: 0,
            partial: Vec::new(),
            src_line: 0,
            events,
            session,
            resumed_from: 0,
            usage: None,
            saw_final: false,
            started,
            timed_out: Arc::new(AtomicBool::new(false)),
            timeout_announced: false,
            lost: Arc::new(AtomicBool::new(false)),
            cancel_refused: Arc::new(AtomicBool::new(false)),
            cancel_by: None,
            ladder: None,
            message_events: 0,
            message_marker_emitted: false,
            pending_batch: None,
        }
    }

    fn target(&self) -> SignalTarget {
        SignalTarget {
            pid: self.pid,
            pgid: self.pgid,
            start_time: self.start_time.clone(),
            owned: self.child.is_some(),
        }
    }

    /// Reads whatever `stdout.jsonl` has grown by and parses the **complete** lines out of it.
    ///
    /// C6, the property this whole method exists for: the read starts at `offset + partial.len()`,
    /// everything up to the last `\n` is parsed and charged to `offset`, and the bytes after it
    /// stay in `partial` — so a provider that flushes half a JSON object (which the real CLIs do,
    /// under load) neither yields a garbage event nor loses the line when its other half lands on
    /// the next tick.
    ///
    /// `flush_tail` is the drain after the process has exited: no `\n` is ever coming, so an
    /// unterminated final line is parsed as-is rather than discarded.
    async fn drain_stdout(&mut self, flush_tail: bool) -> Batch {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};

        let mut batch = Batch::default();
        let path = self.ctx.dir.join(STDOUT_FILE);
        // Absent until the child's first write — not an error, just nothing to read yet.
        let Ok(mut file) = tokio::fs::File::open(&path).await else {
            return batch;
        };
        let from = self.offset + self.partial.len() as u64;
        if file.seek(std::io::SeekFrom::Start(from)).await.is_err() {
            return batch;
        }
        let mut fresh = Vec::new();
        if let Err(err) = file.read_to_end(&mut fresh).await {
            tracing::warn!(path = %path.display(), %err, "reading the attempt transcript failed");
            return batch;
        }
        self.partial.extend_from_slice(&fresh);

        if let Some(last) = self.partial.iter().rposition(|byte| *byte == b'\n') {
            let rest = self.partial.split_off(last + 1);
            let complete = std::mem::replace(&mut self.partial, rest);
            self.offset += complete.len() as u64;
            // `split_inclusive` keeps one element per line, so a blank line still costs a
            // `src_line` and the 1-based numbering stays the file's own.
            let adapter = Arc::clone(&self.ctx.adapter);
            for line in complete.split_inclusive(|byte| *byte == b'\n') {
                self.consume_line(&adapter, line, &mut batch);
            }
        }

        if flush_tail && !self.partial.is_empty() {
            let tail = std::mem::take(&mut self.partial);
            self.offset += tail.len() as u64;
            let adapter = Arc::clone(&self.ctx.adapter);
            self.consume_line(&adapter, &tail, &mut batch);
        }
        batch
    }

    /// One raw line → zero or more normalized events. Worker output is data: a line that parses to
    /// nothing (blank, garbage, provider noise) still advances `src_line`, because `src_line` names
    /// a position in the file and not a position in the event stream.
    fn consume_line(&mut self, adapter: &Arc<dyn ProviderAdapter>, raw: &[u8], batch: &mut Batch) {
        self.src_line += 1;
        let src_line = self.src_line;
        let text = String::from_utf8_lossy(raw);
        for event in adapter.parse_line(text.trim_end_matches('\n')) {
            let mut retain_for_result = true;
            match &event {
                NormalizedEvent::Session { session_id } => {
                    batch.session = Some((src_line, session_id.clone()));
                }
                NormalizedEvent::Phase { phase, note } => {
                    batch.phase = Some((src_line, phase.clone(), note.clone()));
                }
                NormalizedEvent::Message { text, part } => {
                    // Prose is not input to `extract_result`, so never retain it for the lifetime
                    // of the process. Leads publish through this bounded path; worker prose dies
                    // here without entering the durable event log.
                    retain_for_result = false;
                    if self.ctx.role == RoleName::Lead
                        && batch.messages.len() < MAX_AGENT_MESSAGES + 1
                    {
                        batch.messages.push((src_line, text.clone(), *part));
                    }
                }
                NormalizedEvent::Usage { tokens, cost_usd } => {
                    self.usage = Some(UsageLine {
                        src_line,
                        tokens: *tokens,
                        cost_usd: *cost_usd,
                    });
                }
                NormalizedEvent::Final { .. } | NormalizedEvent::Completed => self.saw_final = true,
                NormalizedEvent::Error { .. } => {}
            }
            if retain_for_result {
                self.events.push(event);
            }
        }
    }

    /// The payloads one drained batch produces: at most one `agent.session` per attempt and at
    /// most one `agent.progress` per tick (design: "emit at most one coalesced
    /// `agent.progress{srcLine, phase}` per tick").
    ///
    /// Separated from the append so the final drain — which happens in the finalize helper, off
    /// the actor — can produce its events without holding a `Registry`.
    fn batch_events(&mut self, batch: &Batch) -> Vec<EventPayload> {
        let mut events = Vec::new();
        if let Some((src_line, session_id)) = &batch.session {
            if self.session.as_deref() != Some(session_id.as_str()) {
                self.session = Some(session_id.clone());
                events.push(EventPayload::AgentSession {
                    agent_id: self.ctx.agent,
                    attempt_id: self.ctx.attempt,
                    session_id: session_id.clone(),
                    src_line: *src_line,
                });
            }
        }
        for (src_line, text, part) in &batch.messages {
            if self.message_events < MAX_AGENT_MESSAGES {
                self.message_events += 1;
                events.push(EventPayload::AgentMessage {
                    attempt_id: self.ctx.attempt,
                    src_line: *src_line,
                    role: MessageRole::Assistant,
                    text: text.clone(),
                    part: *part,
                });
            } else if !self.message_marker_emitted {
                self.message_marker_emitted = true;
                events.push(EventPayload::AgentMessage {
                    attempt_id: self.ctx.attempt,
                    src_line: *src_line,
                    role: MessageRole::Assistant,
                    text: MESSAGE_TRUNCATION_MARKER.to_string(),
                    part: None,
                });
            }
        }
        if let Some((src_line, phase, note)) = &batch.phase {
            events.push(EventPayload::AgentProgress {
                attempt_id: self.ctx.attempt,
                src_line: *src_line,
                phase: phase.clone(),
                note: note.clone(),
            });
        }
        events
    }

    /// [`Running::batch_events`], appended — the tailing path, which does hold a `Registry`.
    fn emit_or_park(&mut self, reg: &mut Registry, batch: Batch, failures: u32) -> bool {
        match self.emit_batch(reg, &batch) {
            Ok(()) => true,
            Err(err) => {
                let failures = failures + 1;
                tracing::warn!(
                    attempt = %self.ctx.attempt,
                    failures,
                    %err,
                    "appending a transcript batch failed"
                );
                self.pending_batch = Some(PendingBatch {
                    batch,
                    failures,
                    last_error: err,
                });
                false
            }
        }
    }

    fn retry_pending_batch(&mut self, reg: &mut Registry) -> bool {
        let Some(pending) = self.pending_batch.take() else {
            return true;
        };
        self.emit_or_park(reg, pending.batch, pending.failures)
    }

    fn emit_batch(&mut self, reg: &mut Registry, batch: &Batch) -> Result<(), RegistryError> {
        let run_id = self.ctx.run;
        if let Some((src_line, session_id)) = &batch.session {
            if self.session.as_deref() != Some(session_id.as_str()) {
                reg.append(
                    &run_id,
                    EventPayload::AgentSession {
                        agent_id: self.ctx.agent,
                        attempt_id: self.ctx.attempt,
                        session_id: session_id.clone(),
                        src_line: *src_line,
                    },
                )?;
                self.session = Some(session_id.clone());
            }
        }
        for (index, (src_line, text, part)) in batch.messages.iter().enumerate() {
            let payload = EventPayload::AgentMessage {
                attempt_id: self.ctx.attempt,
                src_line: *src_line,
                role: MessageRole::Assistant,
                text: text.clone(),
                part: *part,
            };
            let occurrence = batch.messages[..index]
                .iter()
                .filter(|(prior_line, prior_text, prior_part)| prior_line == src_line && prior_text == text && prior_part == part)
                .count()
                + 1;
            if reg.has_payload_occurrence(&run_id, &payload, occurrence) {
                continue;
            }
            if self.message_events < MAX_AGENT_MESSAGES {
                reg.append(&run_id, payload)?;
                self.message_events += 1;
            } else if !self.message_marker_emitted {
                let marker = EventPayload::AgentMessage {
                    attempt_id: self.ctx.attempt,
                    src_line: *src_line,
                    role: MessageRole::Assistant,
                    text: MESSAGE_TRUNCATION_MARKER.to_string(),
                    part: None,
                };
                reg.append(&run_id, marker)?;
                self.message_marker_emitted = true;
            }
        }
        // This is the line-level cursor commit: it lands only after every retained message block
        // from the drained batch is durable. A restart may replay blocks, which the occurrence
        // check above removes, but it can never skip a partially emitted provider line.
        if let Some((src_line, phase, note)) = &batch.phase {
            reg.append(
                &run_id,
                EventPayload::AgentProgress {
                    attempt_id: self.ctx.attempt,
                    src_line: *src_line,
                    phase: phase.clone(),
                    note: note.clone(),
                },
            )?;
        }
        Ok(())
    }

    /// Has it ended? `try_wait` for a child we own (which also reaps it), the pid + `lstart` probe
    /// for one we do not.
    ///
    /// For a re-attached attempt this is also where **identity** is decided, not just liveness. A
    /// pid that is alive under a *different* `lstart` is somebody else's process: nothing of ours
    /// can be signalled and the attempt is `lost`, and the flag is stored **here** — in the same
    /// pass that will classify the attempt — rather than being left to the ladder task. The ladder
    /// records it too, but it publishes `timed_out` before its (blocking) guarded probe returns, so
    /// a tick that ran in between would otherwise classify an attempt nothing was ever signalled
    /// for as a `timeout`.
    async fn poll_exit(&mut self, probe: &dyn ProcessProbe) -> Option<ExitInfo> {
        match self.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(Some(status)) => Some(ExitInfo::from_status(&status)),
                Ok(None) => None,
                // The child is unwaitable (already reaped elsewhere): treat it as gone rather than
                // supervising a process we can never hear about again.
                Err(err) => {
                    tracing::warn!(pid = self.pid, %err, "try_wait failed");
                    Some(ExitInfo::vanished())
                }
            },
            None => {
                if probe.is_alive(self.pid, &self.start_time) {
                    return None;
                }
                // Alive, but not ours: `is_alive` collapses "gone" and "recycled" into one `false`,
                // so the second question is asked explicitly.
                if probe
                    .start_time(self.pid)
                    .is_some_and(|actual| actual != self.start_time)
                {
                    self.lost.store(true, Ordering::SeqCst);
                }
                Some(ExitInfo::vanished())
            }
        }
    }
}

impl ExitInfo {
    fn from_status(status: &std::process::ExitStatus) -> Self {
        use std::os::unix::process::ExitStatusExt;
        Self {
            exit_code: status.code(),
            signal: status
                .signal()
                .and_then(|number| Signal::try_from(number).ok())
                .map(|signal| signal.as_str().to_string()),
            owned: true,
        }
    }

    /// A process that stopped existing: no code, no signal, no `Child` to ask.
    fn vanished() -> Self {
        Self {
            exit_code: None,
            signal: None,
            owned: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Finalize
// ---------------------------------------------------------------------------

/// Everything [`finalize_prepare`] learned, as **plain data**: the ordered events that end an
/// attempt, and nothing that owns a file, a process or a `Registry`.
///
/// It exists because the git and filesystem work that produces those events may not happen inside
/// a mailbox turn (decision 11 — "the actor never awaits unbounded I/O"). Before the Codex review
/// of T33, `Supervisor::tick` finalized inline: a wedged `git status` in one run's worktree stalled
/// `get_status`, `cancel` and every gate resolution for up to `GIT_OP_TIMEOUT`. Now the report is
/// built off the actor and applied by [`Supervisor::apply_finalize`], which only appends.
///
/// The event list is ordered exactly as the design's Data Flow requires — usage → violations →
/// result → `attempt.finished` → `diff.frozen` — so applying it is a loop and there is no second
/// place where that order could drift.
#[derive(Clone, PartialEq, Debug)]
pub struct FinalizeReport {
    run: RunId,
    attempt: AttemptId,
    status: AttemptStatus,
    events: Vec<EventPayload>,
}

impl FinalizeReport {
    #[must_use]
    pub fn attempt(&self) -> AttemptId {
        self.attempt
    }

    #[must_use]
    pub fn run(&self) -> RunId {
        self.run
    }

    /// The terminal status the events carry — for a caller's log line, and for tests.
    #[must_use]
    pub fn status(&self) -> AttemptStatus {
        self.status
    }

    /// The events, in the order they must be appended.
    #[must_use]
    pub fn events(&self) -> &[EventPayload] {
        &self.events
    }
}

/// How many times a tailer batch or finalize report may be appended before the actor gives up on
/// the log — **the first attempt plus its retries**, so a budget of 5 means one initial append and
/// four ticks' worth of retries.
///
/// Small on purpose: the failures this guards against are `ENOSPC`, a read-only filesystem and a
/// state dir somebody deleted underneath a running daemon. None of them clear up on their own in a
/// few seconds, so retrying for a minute would only delay the honest answer.
pub const MAX_FINALIZE_ATTEMPTS: u32 = 5;

/// One live attempt lifted out of `running`, so [`Supervisor::abandon_all`] can signal it without
/// borrowing `self` through the map's iterator at the same time.
struct Abandoning {
    attempt: AttemptId,
    target: SignalTarget,
    lost: Arc<AtomicBool>,
    ladder: Option<JoinHandle<()>>,
    /// Kept rather than dropped: it is what lets the fatal path *reap* the worker after the second
    /// rung instead of leaving a zombie for the runtime to collect at some later point it may
    /// never reach. A re-attached attempt has none, and is polled instead.
    child: Option<tokio::process::Child>,
}

/// A [`FinalizeReport`] waiting to be appended, and how far it got.
struct PendingFinalize {
    report: FinalizeReport,
    /// Index of the first event of `report` that is not yet durable.
    next: usize,
    failures: u32,
}

/// The event log could not be written, [`MAX_FINALIZE_ATTEMPTS`] times over, for one attempt.
///
/// Fatal by construction: the design calls `events.jsonl` "the only durable truth", so a daemon
/// that cannot append has nothing truthful left to say and must stop rather than keep answering
/// from a projection the disk does not agree with.
#[derive(Debug, Error)]
#[error("attempt {attempt}: the event log is unwritable after {failures} tries: {source}")]
pub struct FinalizeStalled {
    pub attempt: AttemptId,
    pub failures: u32,
    #[source]
    pub source: RegistryError,
}

/// Does the projection already hold this event?
///
/// The retry path's second guard. C2 makes `attempt.usage`, `attempt.result` and `attempt.finished`
/// *reducer* no-ops when re-applied, which protects the projection but still writes a duplicate
/// line; `policy.violation` and `diff.frozen` are not deduplicated at all and would genuinely
/// double. So every kind a finalize report can carry is checked here against the state the log
/// already produced, and only what is genuinely missing is appended.
fn already_recorded(
    reg: &Registry,
    run: &RunId,
    payload: &EventPayload,
    occurrence: usize,
) -> bool {
    match payload {
        EventPayload::AgentSession {
            agent_id,
            session_id,
            ..
        } => reg
            .agent(agent_id)
            .is_some_and(|agent| agent.session_id.as_deref() == Some(session_id.as_str())),
        EventPayload::AgentProgress {
            attempt_id,
            src_line,
            ..
        } => reg
            .attempt(attempt_id)
            .is_some_and(|attempt| attempt.src_line >= *src_line),
        EventPayload::AgentMessage { .. } => reg.has_payload_occurrence(run, payload, occurrence),
        // Presence, never price. `cost_usd > 0.0` was the first cut and it was wrong: a model with
        // no rate card estimates to exactly 0.0, so a re-delivered report duplicated the usage line
        // for every unpriced attempt (Codex review of T33, round 3). `tokens` is `None` until a
        // usage event is folded in and `Some` forever after, which is the fact being asked about.
        EventPayload::AttemptUsage {
            attempt_id,
            src_line,
            ..
        } => reg
            .attempt(attempt_id)
            .is_some_and(|attempt| attempt.tokens.is_some() && attempt.src_line >= *src_line),
        EventPayload::AttemptResult { attempt_id, .. } => reg
            .attempt(attempt_id)
            .is_some_and(|attempt| attempt.result_path.is_some()),
        EventPayload::PolicyViolated {
            attempt_id: Some(attempt_id),
            violation,
            ..
        } => reg
            .attempt(attempt_id)
            .is_some_and(|attempt| attempt.violations.contains(violation)),
        EventPayload::DiffFrozen { attempt_id, .. } => reg
            .attempt(attempt_id)
            .is_some_and(|attempt| attempt.diff_path.is_some()),
        EventPayload::AttemptFinished { attempt_id, .. } => reg
            .attempt(attempt_id)
            .is_some_and(|attempt| attempt.status != AttemptStatus::Running),
        // Nothing else reaches a finalize report; anything that did would be appended, which is the
        // safe direction for a kind whose duplicate the reducer tolerates.
        _ => false,
    }
}

/// Polls until `target`'s pid stops carrying its recorded `lstart`, or [`FATAL_REAP_WAIT`] passes.
///
/// Only for a re-attached attempt: it is not our child, so there is no `wait` to call and the
/// liveness probe is the only question available.
async fn wait_until_gone(probe: &dyn ProcessProbe, target: &SignalTarget) -> bool {
    let deadline = Instant::now() + FATAL_REAP_WAIT;
    while probe.is_alive(target.pid, &target.start_time) {
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    true
}

/// The handful of facts a finalize that ran out of time still has to report.
///
/// Captured **before** the helper takes ownership of the `Running`, because a timed-out helper's
/// future is dropped and everything inside it goes with it.
struct FinalizeFallback {
    run: RunId,
    attempt: AttemptId,
    exit_code: Option<i32>,
    signal: Option<String>,
    started: Instant,
}

impl FinalizeFallback {
    fn capture(run: &Running, exit: &ExitInfo) -> Self {
        Self {
            run: run.ctx.run,
            attempt: run.ctx.attempt,
            exit_code: exit.exit_code,
            signal: exit.signal.clone(),
            started: run.started,
        }
    }

    /// **Fail closed.** A finalize that could not complete verified nothing, so the attempt
    /// escalates: the run blocks, no reviewer starts and nobody is struck for what the control
    /// plane could not read — the same treatment a git failure inside `finalize_prepare` gets.
    fn timed_out(self) -> FinalizeReport {
        let duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        FinalizeReport {
            run: self.run,
            attempt: self.attempt,
            status: AttemptStatus::Escalate,
            events: vec![EventPayload::AttemptFinished {
                attempt_id: self.attempt,
                status: AttemptStatus::Escalate,
                exit_code: self.exit_code,
                signal: self.signal,
                post_sha: None,
                duration_ms,
                error: Some(workspace_failure(
                    "finalizing",
                    format!(
                        "the finalize helper exceeded GIT_OP_TIMEOUT ({}s)",
                        git::GIT_OP_TIMEOUT.as_secs()
                    ),
                )),
            }],
        }
    }
}

/// Everything between "the process ended" and `attempt.finished`, in the design's order (§ Data
/// Flow, steps 9-13): drain → `attempt.usage` → `postSha` → denylist → result → terminal event →
/// `diff.frozen`.
///
/// **This is the I/O half and it never touches the `Registry`.** It runs in the helper task
/// [`Supervisor::spawn_finalize`] starts, so the git calls, the transcript drain, the result write
/// and the frozen diff all happen off the actor; what comes back is a [`FinalizeReport`] the actor
/// applies with nothing but appends (Codex review of T33, finding 1).
///
/// One ordering subtlety, from Rev 25: the frozen diff is computed **before** `attempt.finished`
/// even though its event is appended after. An empty diff turns a `succeeded` into
/// `invalid_output{no_changed_files}`, and `reduce` keeps the *first* terminal status it sees (C2),
/// so appending `succeeded` first and correcting it afterwards would leave the projection saying
/// `succeeded` forever. Building the whole ordered list before any of it is appended makes that
/// structural rather than a comment.
async fn finalize_prepare(
    mut run: Running,
    exit: ExitInfo,
    _worktree_guard: Option<OwnedMutexGuard<()>>,
) -> FinalizeReport {
    let mut events: Vec<EventPayload> = Vec::new();
    // Whatever the process wrote between the last tick and its exit, plus any final line it never
    // terminated with a newline.
    let batch = run.drain_stdout(true).await;
    events.extend(run.batch_events(&batch));

    let run_id = run.ctx.run;
    let attempt_id = run.ctx.attempt;
    let duration_ms = u64::try_from(run.started.elapsed().as_millis()).unwrap_or(u64::MAX);

    if let Some(usage) = run.usage.take() {
        let (cost_usd, source) = match usage.cost_usd {
            Some(cost) => (cost, CostSource::Provider),
            None => (
                estimate_cost(run.ctx.rate.as_ref(), &usage.tokens),
                CostSource::RateTable,
            ),
        };
        events.push(EventPayload::AttemptUsage {
            attempt_id,
            src_line: usage.src_line,
            cost_usd,
            tokens: usage.tokens,
            source,
        });
    }

    // Only a writing role can have moved HEAD or touched a denied path, and a read-only reviewer
    // runs *in the builder's worktree* — asking git about its changes there would report the
    // builder's work and escalate the wrong attempt.
    let mut post_sha = None;
    let mut denied: Vec<String> = Vec::new();
    // The first git failure of this finalize, if any. It is what makes the whole path **fail
    // closed**: every check below is an enforcement step, so a step that could not run means the
    // attempt was never verified — and an unverified attempt may not be `succeeded`.
    let mut workspace_error: Option<String> = None;
    if run.ctx.writes {
        match git::head_sha(&run.ctx.worktree).await {
            Ok(sha) => post_sha = Some(sha),
            // Without HEAD there is no way to tell whether the worker committed, so the
            // `worker_committed` rule silently would not have been enforced.
            Err(err) => record_git_failure(&mut workspace_error, "reading HEAD", &err, attempt_id),
        }
        if let Some(sha) = post_sha.clone().filter(|sha| *sha != run.ctx.pre_sha) {
            // The commit is undone but its content is kept: the reset moves HEAD and the index
            // back to `preSha` and leaves every file on disk alone, so the diff still holds the
            // work and the worktree is left in the state an approval can later commit from.
            let reset = git::reset_mixed(&run.ctx.worktree, &run.ctx.pre_sha).await;
            if let Err(err) = &reset {
                // The worker's commit is still in the branch: the reset is the enforcement, and it
                // did not happen.
                record_git_failure(&mut workspace_error, "resetting HEAD", err, attempt_id);
            }
            events.push(violation(
                attempt_id,
                run.ctx.agent,
                PolicyViolation {
                    kind: ViolationKind::WorkerCommitted,
                    // The detail is evidence a human reads, so it says what actually happened
                    // rather than what was attempted.
                    detail: if reset.is_ok() {
                        "the worker committed; HEAD was reset to the attempt's preSha and the \
                             changes kept in the worktree"
                    } else {
                        "the worker committed and the reset to the attempt's preSha failed: \
                             the commit is still in the branch"
                    }
                    .to_string(),
                    files: None,
                    pre_sha: Some(run.ctx.pre_sha.clone()),
                    post_sha: Some(sha),
                },
            ));
        } else if post_sha.is_some() {
            // The same rule from the other side. A worker that ran `git add` and never committed
            // leaves HEAD alone and the index dirty — and a dirty index is the one state
            // `gates::run_commit` refuses to commit on top of, so nothing here would have cleared it
            // and the run's own approval could never go through (round-4 review, finding 4). The
            // remediation is the one above with nothing to undo: `reset --mixed` to `preSha`
            // unstages and leaves every byte on disk where the worker left it.
            match git::index_is_clean(&run.ctx.worktree).await {
                Ok(true) => {}
                Ok(false) => {
                    let reset = git::reset_mixed(&run.ctx.worktree, &run.ctx.pre_sha).await;
                    if let Err(err) = &reset {
                        record_git_failure(
                            &mut workspace_error,
                            "unstaging the index",
                            err,
                            attempt_id,
                        );
                    }
                    events.push(violation(
                        attempt_id,
                        run.ctx.agent,
                        PolicyViolation {
                            kind: ViolationKind::WorkerStaged,
                            detail: if reset.is_ok() {
                                "the worker staged changes without committing; the index was reset \
                                 to the attempt's preSha and the changes kept in the worktree"
                            } else {
                                "the worker staged changes without committing and the reset to the \
                                 attempt's preSha failed: the index is still dirty and an approval \
                                 will refuse to commit in this worktree"
                            }
                            .to_string(),
                            files: None,
                            pre_sha: Some(run.ctx.pre_sha.clone()),
                            post_sha: post_sha.clone(),
                        },
                    ));
                }
                // The index was never checked, so it was never cleared: an approval may be wedged
                // and nobody would know why.
                Err(err) => {
                    record_git_failure(&mut workspace_error, "checking the index", &err, attempt_id)
                }
            }
        }
        match git::changed_files(&run.ctx.worktree).await {
            Ok(changed) => {
                let paths: Vec<String> = changed.into_iter().map(|file| file.path).collect();
                denied = git::match_denylist(&paths, &run.ctx.denylist)
                    .into_iter()
                    .map(|hit| hit.path)
                    .collect();
            }
            // An empty changed-file set here would read as "nothing denied" — the denylist would be
            // skipped rather than enforced, which is the one thing it may never be.
            Err(err) => record_git_failure(
                &mut workspace_error,
                "listing the changed files",
                &err,
                attempt_id,
            ),
        }
    }

    // A denylist hit ends the attempt here: no result extraction, no reviewer, a human decides
    // (design, § Data Flow step 11 — "No reviewer, no strike").
    if !denied.is_empty() {
        events.push(violation(
            attempt_id,
            run.ctx.agent,
            PolicyViolation {
                kind: ViolationKind::DenylistHit,
                detail: "the attempt changed files the run's denylist forbids".to_string(),
                files: Some(denied),
                pre_sha: Some(run.ctx.pre_sha.clone()),
                post_sha: post_sha.clone(),
            },
        ));
        events.push(EventPayload::AttemptFinished {
            attempt_id,
            status: AttemptStatus::Escalate,
            exit_code: exit.exit_code,
            signal: exit.signal.clone(),
            post_sha,
            duration_ms,
            // The gate is a denylist gate either way — the violation above says so — but if a
            // git call also failed, the human must be told the worktree is unverified rather
            // than being shown a clean `escalate` with no error at all.
            error: workspace_error
                .take()
                .map(|message| workspace_failure("denylist_hit", message)),
        });
        return FinalizeReport {
            run: run_id,
            attempt: attempt_id,
            status: AttemptStatus::Escalate,
            events,
        };
    }

    // Codex writes its final message to the `-o` file when the stream ends, so this read happens
    // after the exit and never before it.
    let last_message = tokio::fs::read_to_string(run.ctx.dir.join(LAST_MESSAGE_FILE))
        .await
        .ok();
    // The same is true of stderr, and for the same reason it is read at all: an authentication
    // failure leaves nothing on the stream, so its signature is only ever here.
    let stderr_head = read_head(&run.ctx.dir.join(STDERR_FILE), STDERR_HEAD_BYTES).await;
    let raw = run.ctx.adapter.extract_result(&ResultCtx {
        events: &run.events,
        exit_code: exit.exit_code,
        signal: exit.signal.as_deref(),
        last_message: last_message.as_deref(),
        stderr_head: stderr_head.as_deref(),
    });
    // Free text (the lead's contract) is validated against nothing and carries no structured
    // artifact into the log: a fenced JSON block in a reply is prose, not a deliverable.
    let free_text = run.ctx.schema_name == SchemaName::FreeText;
    let structured_valid = !free_text
        && raw
            .structured
            .as_ref()
            .is_some_and(|structured| validates(&run.ctx.schema, structured));
    // A spawned lead is a conversational session, not a worker returning a typed artifact. It has
    // no CLI `--json-schema`; its final free text is still written and logged below, but absence of
    // structured output is explicitly accepted for this one closed role only.
    let output_accepted = run.ctx.role == RoleName::Lead || structured_valid;

    if raw.text.is_some() || raw.structured.is_some() {
        let result_path = write_result(&run.ctx.dir, &raw, structured_valid).await;
        events.push(EventPayload::AttemptResult {
            attempt_id,
            src_line: run.src_line,
            result_path,
            schema: schema_key(run.ctx.schema_name).to_string(),
            structured_valid,
            structured: if free_text {
                None
            } else {
                raw.structured.clone()
            },
        });
    }

    let (mut status, mut error) = classify(&run, &exit, &raw, output_accepted);

    // Rev 25: a builder that succeeded and changed nothing has produced nothing to review.
    let mut frozen = None;
    if status == AttemptStatus::Succeeded && run.ctx.writes {
        let path = diff_path(&run.ctx.dir, &attempt_id);
        match git::frozen_diff(&run.ctx.worktree, &path).await {
            Ok(stat) if stat.files.is_empty() => {
                status = AttemptStatus::InvalidOutput;
                error = Some(AttemptError {
                    code: ErrorCode::NoChangedFiles,
                    message: "the attempt reported success but changed no files".to_string(),
                });
            }
            Ok(stat) => {
                // `frozen_diff` hashes the exact bounded bytes as it writes them, so there is no
                // second whole-file read and the event is bound to the artifact produced above.
                let diff_hash = stat.diff_hash.clone();
                frozen = Some((stat, diff_hash, path));
            }
            Err(err) => {
                record_git_failure(&mut workspace_error, "freezing the diff", &err, attempt_id);
            }
        }
    }

    // **Fail closed.** A writing attempt is only `succeeded` when every enforcement step ran and a
    // hashed diff exists; otherwise it escalates, which is the terminal state whose recovery is
    // "block the run, start no reviewer, strike nobody" — the worker is not at fault, and a human
    // has to look at a worktree the control plane could not read (design, § Error Handling: git
    // faults are audited and block the affected run).
    //
    // This is not only about a success. `failed`, `invalid_output`, `timeout` and `no_session` are
    // all **strikeable**: reporting one of them while a git call silently failed would strike the
    // worker for our own blindness and send the loop into a repair round against a worktree nobody
    // has verified. So an unverified workspace outranks them all, and the original classification
    // survives in the message.
    if run.ctx.writes {
        if let Some(message) = workspace_error.take() {
            let failure = workspace_failure(status_key(status), message);
            match status {
                // A human already decided this attempt's fate, and a `lost` one is never resumed:
                // neither state strikes anybody or advances the loop, so the status stands and the
                // git failure rides along on the error rather than being invented into an escalate.
                AttemptStatus::Cancelled | AttemptStatus::Lost => error = Some(failure),
                _ => {
                    status = AttemptStatus::Escalate;
                    error = Some(failure);
                }
            }
        } else if status == AttemptStatus::Succeeded && frozen.is_none() {
            status = AttemptStatus::Escalate;
            error = Some(AttemptError {
                code: ErrorCode::WorkspaceError,
                message: "no frozen diff was produced for a writing attempt".to_string(),
            });
        }
    }

    // An untracked symlink is a deliberate probe for a file the kernel sandbox denies the worker
    // (`git::frozen_diff` names it but never reads through it). The review still runs — the diff
    // renders it as a mode 120000 entry, and the hash covers what the reviewer actually sees.
    if let Some((stat, _, _)) = &frozen {
        if !stat.symlinks.is_empty() {
            events.push(violation(
                attempt_id,
                run.ctx.agent,
                PolicyViolation {
                    kind: ViolationKind::SymlinkPlanted,
                    detail: "the worktree holds untracked symlinks; the diff names them and \
                                 never read through them"
                        .to_string(),
                    files: Some(stat.symlinks.clone()),
                    pre_sha: Some(run.ctx.pre_sha.clone()),
                    post_sha: post_sha.clone(),
                },
            ));
        }
    }

    events.push(EventPayload::AttemptFinished {
        attempt_id,
        status,
        exit_code: exit.exit_code,
        signal: exit.signal.clone(),
        post_sha,
        duration_ms,
        error,
    });

    // Only a succeeded attempt hands a diff to a reviewer, so an escalated one never advertises
    // one — the loop keys the review off `diff.frozen`.
    if let Some((stat, diff_hash, path)) = frozen.filter(|_| status == AttemptStatus::Succeeded) {
        events.push(EventPayload::DiffFrozen {
            attempt_id,
            diff_path: path,
            diff_hash,
            files: stat.files,
            added: stat.added,
            deleted: stat.deleted,
        });
    }

    FinalizeReport {
        run: run_id,
        attempt: attempt_id,
        status,
        events,
    }
}

/// The terminal-state table (design, § Error Handling), in the order its rows must be read: an
/// unidentifiable process outranks everything (we cannot claim to have ended what we never
/// signalled), an explicit cancellation outranks a timeout, a timeout outranks whatever the
/// transcript says, and only then does the transcript decide.
fn classify(
    run: &Running,
    exit: &ExitInfo,
    raw: &RawResult,
    structured_valid: bool,
) -> (AttemptStatus, Option<AttemptError>) {
    // A pid that stopped matching its recorded `lstart` was never signalled, so neither the
    // cancellation nor the deadline below actually reached anything: the honest terminal state is
    // `lost`, which is also the one the loop never auto-resumes (design, Revision 24).
    if run.lost.load(Ordering::SeqCst) {
        return (AttemptStatus::Lost, None);
    }
    if matches!(run.cancel_by, Some(CancelBy::Lead | CancelBy::Cli)) {
        return (AttemptStatus::Cancelled, None);
    }
    if run.timed_out.load(Ordering::SeqCst) {
        return (AttemptStatus::Timeout, None);
    }
    // A re-attached attempt whose process disappeared without ever producing a final line: nothing
    // can say how it ended, so it is never auto-resumed.
    if !exit.owned && !run.saw_final {
        return (AttemptStatus::Lost, None);
    }
    // **Above `no_session`, deliberately.** An unauthenticated CLI never emits `system/init`
    // either, so both rows describe the same observation — and the recovery they name is opposite:
    // `no_session` strikes the lineage and retries in a fresh session (17c), while an environment
    // failure strikes nobody and blocks the run until a human logs in (17a). Guessing wrong costs
    // three spawns that fail identically, so the more specific row is read first (design,
    // § Error Handling: `spawn_failed` ← "`provider_unauthenticated` (auth signature + non-zero
    // exit before any event)").
    if raw.error_code == Some(ErrorCode::ProviderUnauthenticated) {
        return (
            AttemptStatus::SpawnFailed,
            Some(AttemptError {
                code: ErrorCode::ProviderUnauthenticated,
                message: "the provider CLI is not authenticated — log in and re-run `acp doctor`"
                    .to_string(),
            }),
        );
    }
    // "Died before `system/init`" is a claim only a supervisor that watched the first line may
    // make; a resumed tail starts past it, and the session it recorded before the restart is what
    // `ctx.session_id` carries back in.
    if raw.session_id.is_none() && run.resumed_from == 0 {
        return (AttemptStatus::NoSession, None);
    }
    if let Some(code) = raw.error_code {
        return (
            AttemptStatus::Failed,
            Some(AttemptError {
                code,
                message: raw
                    .text
                    .clone()
                    .unwrap_or_else(|| "the provider reported a failed turn".to_string()),
            }),
        );
    }
    if !raw.ok || matches!(exit.exit_code, Some(code) if code != 0) {
        return (
            AttemptStatus::Failed,
            Some(AttemptError {
                code: ErrorCode::ProviderError,
                message: raw
                    .text
                    .clone()
                    .unwrap_or_else(|| "the attempt ended without a successful result".to_string()),
            }),
        );
    }
    if !structured_valid {
        return (
            AttemptStatus::InvalidOutput,
            Some(AttemptError {
                code: ErrorCode::SchemaInvalid,
                message: "the final message is missing or does not validate against the role's \
                          result schema"
                    .to_string(),
            }),
        );
    }
    (AttemptStatus::Succeeded, None)
}

/// At most `max` bytes from the front of `path`, cut back to a UTF-8 char boundary.
///
/// Bounded on purpose — via `take`, so at most `max + 3` bytes are ever read: a worker controls
/// how much it writes to stderr, and this runs on every finalize. A missing or unreadable file is `None` — nothing here is worth failing an attempt
/// over, and every caller treats the absence as "no signature".
async fn read_head(path: &Path, max: usize) -> Option<String> {
    // `take` bounds the read itself — `tokio::fs::read` would load the whole worker-controlled
    // file just to keep 4 KiB of it (review finding). Three bytes of slack keep a codepoint split
    // exactly at `max` visible to the boundary walk-back below.
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path).await.ok()?;
    let mut bytes = Vec::with_capacity(max.saturating_add(3).min(64 * 1024));
    file.take(max as u64 + 3)
        .read_to_end(&mut bytes)
        .await
        .ok()?;
    let mut end = bytes.len().min(max);
    // Only a cut needs moving; a whole file is already on a boundary — and `bytes[end]` would be
    // out of bounds. `from_utf8_lossy` would replace a split codepoint with U+FFFD rather than
    // dropping it, which is harmless but makes the head a different string than the file's prefix.
    if end < bytes.len() {
        while end > 0 && (bytes[end] & 0b1100_0000) == 0b1000_0000 {
            end -= 1;
        }
    }
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

/// `<attemptDir>/result.txt` (always) and `<attemptDir>/result.json` (only when the structured
/// output validated), per the design's on-disk layout. The returned path is the attempt's
/// `resultPath` — the free text, which is what a human and a repair prompt read.
async fn write_result(dir: &Path, raw: &RawResult, structured_valid: bool) -> PathBuf {
    let text_path = dir.join(RESULT_TEXT_FILE);
    let text = raw.text.clone().unwrap_or_default();
    if let Err(err) = tokio::fs::write(&text_path, text.as_bytes()).await {
        tracing::error!(path = %text_path.display(), %err, "writing result.txt failed");
    }
    if structured_valid {
        if let Some(structured) = &raw.structured {
            let path = dir.join(RESULT_JSON_FILE);
            let body = serde_json::to_vec_pretty(structured).unwrap_or_else(|_| b"{}".to_vec());
            if let Err(err) = tokio::fs::write(&path, body).await {
                tracing::error!(path = %path.display(), %err, "writing result.json failed");
            }
        }
    }
    text_path
}

/// Does the worker's structured output satisfy the role's schema? A schema that does not compile is
/// treated as "nothing validates": the alternative is accepting unvalidated output, and the
/// checked-in schemas are compile-tested (T12), so this can only be a caller bug.
fn validates(schema: &Value, instance: &Value) -> bool {
    match jsonschema::validator_for(schema) {
        Ok(validator) => validator.is_valid(instance),
        Err(err) => {
            tracing::error!(%err, "the role's result schema does not compile");
            false
        }
    }
}

/// `<runDir>/diffs/<attemptId>.patch`, derived from the attempt dir — which the design fixes as
/// `<runDir>/attempts/<attemptId>` (§ On-disk layout). A dir shallower than that (only a caller
/// that ignored the layout can produce one) keeps its diffs beside itself rather than escaping.
fn diff_path(attempt_dir: &Path, attempt: &AttemptId) -> PathBuf {
    let run_dir = attempt_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(attempt_dir);
    run_dir
        .join(DIFFS_DIR)
        .join(format!("{}.patch", attempt.as_uuid()))
}

/// What a turn cost according to our own rate table, when the provider reported no cost of its own
/// — the arithmetic of `roles::loader::estimate_cost_usd`, over the one price card this attempt
/// needs. An unpriced model costs 0: the rate table is an estimate for the human, never the thing
/// that authorises a spawn.
fn estimate_cost(rate: Option<&Rate>, tokens: &TokenUsage) -> f64 {
    let Some(rate) = rate else {
        return 0.0;
    };
    (tokens.input as f64 / 1e6) * rate.input_per_m_tok_usd
        + (tokens.cached_input as f64 / 1e6) * rate.cached_input_per_m_tok_usd
        + (tokens.output as f64 / 1e6) * rate.output_per_m_tok_usd
}

/// The terminal error a failed enforcement step produces. The original classification is kept in
/// the message — "what it would have been, had we been able to check" is exactly what a human
/// reading a blocked run needs.
fn workspace_failure(after: &str, message: String) -> AttemptError {
    AttemptError {
        code: ErrorCode::WorkspaceError,
        message: format!("workspace unverified after {after}: {message}"),
    }
}

/// The wire name of a terminal status, for the message above. Spelled out for the same reason
/// [`schema_key`] is: an event field never depends on a fallible conversion.
fn status_key(status: AttemptStatus) -> &'static str {
    match status {
        AttemptStatus::Running => "running",
        AttemptStatus::Succeeded => "succeeded",
        AttemptStatus::Failed => "failed",
        AttemptStatus::InvalidOutput => "invalid_output",
        AttemptStatus::Timeout => "timeout",
        AttemptStatus::Cancelled => "cancelled",
        AttemptStatus::Lost => "lost",
        AttemptStatus::SpawnFailed => "spawn_failed",
        AttemptStatus::NoSession => "no_session",
        AttemptStatus::Escalate => "escalate",
    }
}

/// The wire name of a schema — `attempt.result.schema`. Spelled out rather than round-tripped
/// through serde so an event field never depends on a fallible conversion.
fn schema_key(name: SchemaName) -> &'static str {
    match name {
        SchemaName::BuildResult => "build-result",
        SchemaName::ReviewVerdict => "review-verdict",
        SchemaName::VerifyReport => "verify-report",
        SchemaName::FreeText => "free-text",
    }
}

fn violation(attempt: AttemptId, agent: AgentId, violation: PolicyViolation) -> EventPayload {
    EventPayload::PolicyViolated {
        attempt_id: Some(attempt),
        agent_id: Some(agent),
        violation,
    }
}

/// Records the **first** git failure of a finalize and logs it. First rather than last because it
/// is the one that explains the rest: a worktree whose `rev-parse` failed will fail every call
/// after it, and the human wants the original cause.
///
/// A git fault never stops an attempt from reaching a terminal state (design, § Error Handling:
/// git faults "never block the actor") — it changes *which* terminal state it reaches.
fn record_git_failure(
    slot: &mut Option<String>,
    op: &str,
    err: &git::GitError,
    attempt: AttemptId,
) {
    tracing::error!(attempt = %attempt, %err, "{op} failed");
    slot.get_or_insert_with(|| format!("{op} failed: {err}"));
}

/// Appends one event, or logs the write failure and carries on. A registry that cannot write is
/// already fatal for the run; losing the attempt's remaining events on top of it is not an
/// improvement, and the actor's own error path (T33) is what surfaces it.
fn emit(reg: &mut Registry, run: &RunId, payload: EventPayload) -> Option<Arc<Event>> {
    match reg.append(run, payload) {
        Ok(event) => Some(event),
        Err(err) => {
            tracing::error!(run = %run, %err, "appending an event failed");
            None
        }
    }
}

/// The `Attempt` `reduce` builds from `attempt.started` — reconstructed here only for the case
/// where that append failed, so `adopt` can still hand its caller the attempt it is supervising.
fn attempt_record(
    ctx: &AttemptContext,
    pid: i32,
    pgid: i32,
    start_time: &str,
    started_at: &str,
) -> Attempt {
    Attempt {
        attempt_id: ctx.attempt,
        agent_id: ctx.agent,
        run_id: ctx.run,
        kind: ctx.kind,
        dir: ctx.dir.clone(),
        pid: Some(pid),
        pgid: Some(pgid),
        start_time: Some(start_time.to_string()),
        status: AttemptStatus::Running,
        error: None,
        started_at: started_at.to_string(),
        finished_at: None,
        pre_sha: ctx.pre_sha.clone(),
        post_sha: None,
        exit_code: None,
        signal: None,
        cost_usd: 0.0,
        tokens: None,
        src_line: 0,
        byte_offset: 0,
        timeout_sec: ctx.timeout.as_secs(),
        spawn_budget_usd: ctx.spawn_budget_usd,
        result_path: None,
        structured_valid: None,
        structured: None,
        violations: Vec::new(),
        diff_path: None,
    }
}

// ---------------------------------------------------------------------------
// Re-attach helpers
// ---------------------------------------------------------------------------

/// Where the tailer resumes: the byte just past the `last_src_line`th `\n` of `stdout.jsonl`, and
/// the number of lines that actually exist (a log truncated by a crash has fewer).
///
/// Complete lines only — a file whose last line has no newline resumes before that line, which is
/// C6 again across a restart.
fn resume_offset(path: &Path, last_src_line: u64) -> (u64, u64) {
    // Nothing was consumed, so nothing is skipped — and the loop below, which only ever stops *on*
    // a newline it counted, would otherwise run to the end of the file.
    if last_src_line == 0 {
        return (0, 0);
    }
    let Ok(bytes) = std::fs::read(path) else {
        return (0, 0);
    };
    let mut lines = 0;
    let mut offset = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            lines += 1;
            offset = index as u64 + 1;
            if lines == last_src_line {
                break;
            }
        }
    }
    (offset, lines.min(last_src_line))
}

/// How long ago an RFC 3339 timestamp this crate wrote was — what re-arms a deadline across a
/// restart. An unparseable or future timestamp yields zero, so a deadline is re-armed for its full
/// length rather than fired immediately on a clock that moved backwards.
fn elapsed_since(ts: &str) -> Duration {
    let Some(then) = unix_millis_from_rfc3339(ts) else {
        return Duration::ZERO;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as i128);
    Duration::from_millis(u64::try_from((now - then).max(0)).unwrap_or(0))
}

/// `2026-08-22T09:41:07.412Z` → milliseconds since the epoch. The inverse of
/// `registry::now_rfc3339`, and only of that: the format is fixed-width, this crate is the only
/// writer of these strings, and the design's dependency set has no date crate.
fn unix_millis_from_rfc3339(ts: &str) -> Option<i128> {
    let bytes = ts.as_bytes();
    if bytes.len() < 20 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    let field = |from: usize, to: usize| ts.get(from..to)?.parse::<i64>().ok();
    let year = field(0, 4)?;
    let month = field(5, 7)?;
    let day = field(8, 10)?;
    let hour = field(11, 13)?;
    let minute = field(14, 16)?;
    let second = field(17, 19)?;
    let millis = if bytes.get(19) == Some(&b'.') {
        field(20, 23).unwrap_or(0)
    } else {
        0
    };
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    Some(i128::from(secs) * 1000 + i128::from(millis))
}

/// `(year, month, day)` → days since 1970-01-01. Howard Hinnant's `days_from_civil`, the exact
/// inverse of the `civil_from_days` `registry::now_rfc3339` renders with.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400; // [0, 399]
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1; // [0, 365]
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{LineageId, Origin, ProviderName, RoleName, Task};

    #[tokio::test]
    async fn version_probes_clean_up_descendants_on_success_overflow_timeout_and_cancellation() {
        use std::os::unix::fs::PermissionsExt;
        for mode in ["success", "overflow", "timeout", "cancel"] {
            let dir = tempfile::tempdir().unwrap();
            let script = dir.path().join("version-wrapper");
            let ending = match mode {
                "success" => "printf 'measured\\n'\nexit 0\n".into(),
                "overflow" => format!("printf '{}'\nwait\n", "x".repeat(514)),
                _ => "wait\n".into(),
            };
            std::fs::write(&script, format!("#!/bin/sh\n/bin/sleep 30 >/dev/null 2>&1 &\nprintf '%s' \"$!\" > child.pid\n{ending}")).unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
            let plan = SpawnPlan { required_version: Some("measured".into()), file: script,
                argv: vec![], cwd: dir.path().into(), env: Default::default(), write_files: vec![] };
            let task = tokio::spawn(async move { check_required_version(&plan).await });
            let pid_file = dir.path().join("child.pid");
            let deadline = Instant::now()+Duration::from_secs(3);
            let pid = loop {
                if let Ok(pid) = std::fs::read_to_string(&pid_file).unwrap_or_default().parse::<i32>() { break pid; }
                assert!(Instant::now()<deadline, "probe did not start");
                tokio::time::sleep(Duration::from_millis(10)).await;
            };
            if mode=="cancel" { task.abort(); assert!(task.await.unwrap_err().is_cancelled()); }
            else { assert_eq!(task.await.unwrap().is_ok(), mode=="success", "{mode}"); }
            let deadline = Instant::now()+Duration::from_secs(3);
            loop {
                let output = Command::new(PS_BIN).args(["-o", "stat=", "-p", &pid.to_string()])
                    .output().await.unwrap();
                let state = String::from_utf8_lossy(&output.stdout);
                // A reparented zombie is already dead; launchd/init owns its eventual reap.
                if state.trim().is_empty() || state.trim().starts_with('Z') { break; }
                assert!(Instant::now()<deadline, "{mode} left descendant {pid}: {state}");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    /// A registry holding one run, one agent and one started attempt — the state a finalize report
    /// is applied on top of.
    fn seeded(dir: &std::path::Path) -> (Registry, RunId, AgentId, AttemptId) {
        let mut reg = Registry::open(dir).expect("open registry");
        let run = RunId::new_v4();
        let agent = AgentId::new_v4();
        let attempt = AttemptId::new_v4();
        reg.append(
            &run,
            EventPayload::RunCreated {
                execution: None,
                repo_root: dir.join("repo"),
                state_dir: dir.to_path_buf(),
                base_ref: "main".into(),
                base_sha: "0".repeat(40),
                task: Task {
                    id: "T33".into(),
                    title: "finalize".into(),
                    description: "apply a report".into(),
                    files: vec![],
                    acceptance: vec![],
                },
                version: 1,
                lead: None,
                team_name: None,
                steps: None,
            },
        )
        .expect("run.created");
        reg.append(
            &run,
            EventPayload::AgentCreated {
                agent_id: agent,
                role: RoleName::Builder,
                provider: ProviderName::Claude,
                model: "sonnet".into(),
                lineage_id: Some(LineageId::new_v4()),
                depth: 1,
                parent_agent_id: None,
                origin: Origin::Lead,
                writes: true,
                cwd: dir.join("repo"),
                worktree: Some(dir.join("repo")),
            },
        )
        .expect("agent.created");
        reg.append(
            &run,
            EventPayload::AttemptStarted {
                attempt_id: attempt,
                agent_id: agent,
                attempt_kind: AttemptKind::Fresh,
                dir: dir.join("attempt"),
                argv: vec!["claude".into()],
                cwd: dir.join("repo"),
                pid: 4242,
                pgid: 4242,
                start_time: "Sat Aug 23 00:00:00 2026".into(),
                pre_sha: "0".repeat(40),
                timeout_sec: 900,
                spawn_budget_usd: 2.0,
            },
        )
        .expect("attempt.started");
        (reg, run, agent, attempt)
    }

    fn report_for(
        run: RunId,
        agent: AgentId,
        attempt: AttemptId,
        dir: &std::path::Path,
    ) -> FinalizeReport {
        FinalizeReport {
            run,
            attempt,
            status: AttemptStatus::Succeeded,
            events: vec![
                EventPayload::AgentSession {
                    agent_id: agent,
                    attempt_id: attempt,
                    session_id: "sess-1".into(),
                    src_line: 1,
                },
                // Identical blocks on one provider line are two events, not a set. Retry
                // deduplication must retain both once and still reject a redelivery.
                EventPayload::AgentMessage {
                    attempt_id: attempt,
                    src_line: 2,
                    role: MessageRole::Assistant,
                    text: "same block".into(),
                    part: None,
                },
                EventPayload::AgentMessage {
                    attempt_id: attempt,
                    src_line: 2,
                    role: MessageRole::Assistant,
                    text: "same block".into(),
                    part: None,
                },
                // Zero-cost on purpose: a model with no rate card prices every turn at exactly
                // 0.0, and that must not read as "no usage was recorded" on a retry.
                EventPayload::AttemptUsage {
                    attempt_id: attempt,
                    src_line: 3,
                    cost_usd: 0.0,
                    tokens: TokenUsage {
                        input: 120,
                        cached_input: 0,
                        output: 40,
                        reasoning: None,
                    },
                    source: CostSource::RateTable,
                },
                EventPayload::AttemptResult {
                    attempt_id: attempt,
                    src_line: 4,
                    result_path: dir.join("result.txt"),
                    schema: "build-result".into(),
                    structured_valid: true,
                    structured: None,
                },
                violation(
                    attempt,
                    agent,
                    PolicyViolation {
                        kind: ViolationKind::WorkerCommitted,
                        detail: "the worker committed".into(),
                        files: None,
                        pre_sha: Some("0".repeat(40)),
                        post_sha: Some("1".repeat(40)),
                    },
                ),
                EventPayload::AttemptFinished {
                    attempt_id: attempt,
                    status: AttemptStatus::Succeeded,
                    exit_code: Some(0),
                    signal: None,
                    post_sha: Some("0".repeat(40)),
                    duration_ms: 12,
                    error: None,
                },
                EventPayload::DiffFrozen {
                    attempt_id: attempt,
                    diff_path: dir.join("d.patch"),
                    diff_hash: "abc".into(),
                    files: vec!["src/adder.ts".into()],
                    added: 3,
                    deleted: 0,
                },
            ],
        }
    }

    fn supervisor_for_test() -> Supervisor {
        let (tx, rx) = mpsc::channel(8);
        std::mem::forget(rx);
        Supervisor::new(Duration::from_millis(25), Arc::new(PsProbe), tx)
    }

    #[tokio::test]
    async fn cancellation_retains_refused_signals_and_unprojected_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = Registry::open(dir.path()).unwrap();
        let mut supervisor = supervisor_for_test();
        let run = RunId::new_v4();
        let attempt = AttemptId::new_v4();
        let ctx = AttemptContext {
            run, agent: AgentId::new_v4(), attempt, dir: dir.path().join("attempt"),
            adapter: Arc::new(crate::providers::claude::ClaudeAdapter), timeout: Duration::from_secs(60),
            pre_sha: "0".repeat(40), kind: AttemptKind::Fresh, role: RoleName::Lead,
            worktree: dir.path().join("repo"), worktree_lock: Arc::new(Mutex::new(())),
            writes: false, schema: Arc::new(Value::Null), schema_name: SchemaName::FreeText,
            denylist: Arc::new(globset::GlobSetBuilder::new().build().unwrap()),
            spawn_budget_usd: 1.0, rate: None, session_id: None,
        };
        // A pgid of zero is deterministically refused before any kernel signal or process probe.
        supervisor.running.insert(attempt, Running::new(ctx, 0, 0, String::new(), None, Instant::now()));
        assert!(registry.state().attempts.is_empty());
        assert_eq!(supervisor.active_attempts(), vec![(attempt, run)]);
        assert!(matches!(supervisor.cancel(&attempt, CancelBy::Cli, &mut registry).await,
            Err(SupervisorError::SignalRefused(id)) if id == attempt));
        assert!(supervisor.cancellation_signal_refused(&attempt));
        assert!(supervisor.is_running(&attempt), "signal refusal must not abandon supervision");
        let running = supervisor.running.get_mut(&attempt).unwrap();
        running.ladder.take().unwrap().abort();
        running.cancel_refused.store(false, Ordering::SeqCst);
        // Drive the production final-rung helper with the same deterministically invalid target.
        let refused = Arc::clone(&running.cancel_refused);
        let lost = Arc::clone(&running.lost);
        let target = running.target();
        supervisor.spawn_kill(target, lost, refused).await.unwrap();
        assert!(supervisor.cancellation_signal_refused(&attempt));
        assert!(supervisor.is_running(&attempt));

        let (mailbox, _commands) = crate::core::channel();
        let mut core = crate::core::Core::new(registry, supervisor,
            crate::roles::loader::load_roles(None).unwrap(), dir.path().join("repo"),
            dir.path().to_path_buf(), mailbox);
        let signal = tokio_util::sync::CancellationToken::new();
        core.lifecycle.configure(true, signal.clone());
        core.lifecycle.request(crate::core::lifecycle::Request::Stop {
            mode: crate::core::lifecycle::StopMode::WhenIdle,
        }, vec![], Instant::now()).unwrap();
        assert!(core.registry.state().attempts.is_empty());
        let busy = !core.lifecycle_busy_reasons().is_empty();
        assert!(busy, "unprojected supervisor ownership holds safe stop");
        core.lifecycle.tick(busy, Instant::now());
        assert!(!signal.is_cancelled());

        let (tx, mut reports) = mpsc::channel(8);
        core.supervisor.tx = tx;
        let mut running = core.supervisor.running.remove(&attempt).unwrap();
        running.ctx.writes = true;
        let lock = Arc::clone(&running.ctx.worktree_lock).lock_owned().await;
        core.supervisor.spawn_finalize(running, ExitInfo { exit_code: Some(0), signal: None, owned: false });
        assert!(core.supervisor.active_attempts().is_empty());
        assert_eq!(core.supervisor.pending_finalize_count(), 1);
        let busy = !core.lifecycle_busy_reasons().is_empty();
        core.lifecycle.tick(busy, Instant::now());
        assert!(!signal.is_cancelled(), "the finalization helper owns activity while blocked on its worktree lock");
        drop(lock);
        let message = tokio::time::timeout(Duration::from_secs(10), reports.recv()).await.unwrap().unwrap();
        let SupervisorSignal::FinalizeReady { report, .. } = message else { panic!("expected finalization report") };
        assert_eq!(core.supervisor.pending_finalize_count(), 1, "received is not durably applied");
        core.supervisor.apply_finalize(*report, &mut core.registry).unwrap();
        assert_eq!(core.supervisor.pending_finalize_count(), 0);
    }

    #[test]
    fn a_reattach_restores_the_attempt_wide_message_limit() {
        assert_eq!(restored_message_limit(0), (0, false));
        assert_eq!(restored_message_limit(499), (499, false));
        assert_eq!(restored_message_limit(500), (500, false));
        assert_eq!(restored_message_limit(501), (500, true));
    }

    #[test]
    fn a_replayed_partial_provider_line_keeps_each_message_exactly_once() {
        for chunked in [false, true] { check_partial_message_replay(chunked); }
    }

    fn check_partial_message_replay(chunked: bool) {
        let first_part = chunked.then_some(crate::core::types::MessagePart {
            block: 0, index: 0, count: 2, truncated: false,
        });
        let second_part = first_part.map(|part| crate::core::types::MessagePart { index: 1, ..part });
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut reg, run, agent, attempt) = seeded(dir.path());
        let first = EventPayload::AgentMessage {
            attempt_id: attempt,
            src_line: 2,
            role: MessageRole::Assistant,
            text: "first block".into(),
            part: first_part,
        };
        reg.append(&run, first)
            .expect("the first block became durable");
        assert_eq!(
            reg.attempt(&attempt).expect("attempt").src_line,
            0,
            "one block must not commit the whole provider line"
        );

        let denylist = globset::GlobSetBuilder::new()
            .build()
            .expect("empty denylist");
        let ctx = AttemptContext {
            run,
            agent,
            attempt,
            dir: dir.path().join("attempt"),
            adapter: Arc::new(crate::providers::claude::ClaudeAdapter),
            timeout: Duration::from_secs(60),
            pre_sha: "0".repeat(40),
            kind: AttemptKind::Fresh,
            role: RoleName::Lead,
            worktree: dir.path().join("repo"),
            worktree_lock: Arc::new(Mutex::new(())),
            writes: false,
            schema: Arc::new(Value::Null),
            schema_name: SchemaName::BuildResult,
            denylist: Arc::new(denylist),
            spawn_budget_usd: 1.0,
            rate: None,
            session_id: None,
        };
        let mut running = Running::new(ctx, 0, 0, String::new(), None, Instant::now());
        (running.message_events, running.message_marker_emitted) =
            restored_message_limit(reg.agent_message_count(&run, &attempt));
        let batch = Batch {
            session: None,
            phase: Some((2, "text".into(), None)),
            messages: vec![(2, "first block".into(), first_part), (2, "second block".into(), second_part)],
        };
        running
            .emit_batch(&mut reg, &batch)
            .expect("the replayed line becomes durable");

        running.emit_batch(&mut reg, &batch).expect("a second replay deduplicates");
        let messages: Vec<String> = reg
            .events(&run, None, usize::MAX)
            .iter()
            .filter_map(|event| match &event.payload {
                EventPayload::AgentMessage { text, .. } => Some(text.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(messages, ["first block", "second block"]);
        assert_eq!(
            reg.attempt(&attempt).expect("attempt").src_line,
            2,
            "the trailing progress commits the complete line"
        );
    }

    #[test]
    fn a_failed_message_batch_is_parked_before_a_later_cursor_can_land() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut reg, run, agent, attempt) = seeded(dir.path());
        reg.append(
            &run,
            EventPayload::AgentMessage {
                attempt_id: attempt,
                src_line: 2,
                role: MessageRole::Assistant,
                text: "first block".into(),
                part: None,
            },
        )
        .expect("the first block became durable");

        // Reopen without a cached append handle, then make the log reject the missing second
        // block. This is the exact partial-line failure that used to be dropped by `tick_attempt`.
        drop(reg);
        let mut reg = Registry::open(dir.path()).expect("reopen");
        let log = log_path(dir.path(), run);
        if !set_log_writable(&log, false) {
            eprintln!("skipped: the log's mode is not enforceable here");
            return;
        }

        let denylist = globset::GlobSetBuilder::new()
            .build()
            .expect("empty denylist");
        let ctx = AttemptContext {
            run,
            agent,
            attempt,
            dir: dir.path().join("attempt"),
            adapter: Arc::new(crate::providers::claude::ClaudeAdapter),
            timeout: Duration::from_secs(60),
            pre_sha: "0".repeat(40),
            kind: AttemptKind::Fresh,
            role: RoleName::Lead,
            worktree: dir.path().join("repo"),
            worktree_lock: Arc::new(Mutex::new(())),
            writes: false,
            schema: Arc::new(Value::Null),
            schema_name: SchemaName::BuildResult,
            denylist: Arc::new(denylist),
            spawn_budget_usd: 1.0,
            rate: None,
            session_id: None,
        };
        let mut running = Running::new(ctx, 0, 0, String::new(), None, Instant::now());
        (running.message_events, running.message_marker_emitted) =
            restored_message_limit(reg.agent_message_count(&run, &attempt));
        let partial_line = Batch {
            session: None,
            phase: Some((2, "text".into(), None)),
            messages: vec![(2, "first block".into(), None), (2, "second block".into(), None)],
        };

        assert!(!running.emit_or_park(&mut reg, partial_line, 0));
        assert!(
            running.pending_batch.is_some(),
            "the unread suffix is retained"
        );
        assert_eq!(
            reg.attempt(&attempt).expect("attempt").src_line,
            0,
            "the partial provider line did not commit its cursor"
        );

        assert!(set_log_writable(&log, true));
        assert!(running.retry_pending_batch(&mut reg));
        assert!(running.pending_batch.is_none());
        assert!(running.emit_or_park(
            &mut reg,
            Batch {
                session: None,
                phase: Some((3, "text".into(), None)),
                messages: vec![(3, "third block".into(), None)],
            },
            0,
        ));

        let messages: Vec<String> = reg
            .events(&run, None, usize::MAX)
            .iter()
            .filter_map(|event| match &event.payload {
                EventPayload::AgentMessage { text, .. } => Some(text.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(messages, ["first block", "second block", "third block"]);
        assert_eq!(reg.attempt(&attempt).expect("attempt").src_line, 3);
    }

    /// The reattach cap counts what the provider streamed, not what the human typed: a `user`
    /// turn (T82) shares the resumed attempt's id but is not one of its 500 assistant messages, so
    /// restoring the limit over it would cost the lead one message — and at exactly 500, hide a
    /// truncation marker that was never written.
    #[test]
    fn the_restored_message_cap_ignores_the_human_user_turn() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut reg, run, _agent, attempt) = seeded(dir.path());
        for (src_line, role, text) in [
            (0, MessageRole::User, "the human's follow-up"),
            (2, MessageRole::Assistant, "first block"),
            (2, MessageRole::Assistant, "second block"),
        ] {
            reg.append(
                &run,
                EventPayload::AgentMessage {
                    attempt_id: attempt,
                    src_line,
                    role,
                    text: text.into(),
                    part: None,
                },
            )
            .expect("the turn became durable");
        }
        assert_eq!(
            reg.agent_message_count(&run, &attempt),
            2,
            "two assistant blocks; the user turn is not counted against the cap"
        );
    }

    /// A report that reaches `apply_finalize` twice — a duplicate delivery, or a retry that resumed
    /// from index 0 — must not duplicate messages, `policy.violation` or `diff.frozen`. None is
    /// deduplicated by the reducer, so `already_recorded` is the only retry guard.
    #[test]
    fn re_applying_a_report_appends_nothing_twice() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut reg, run, agent, attempt) = seeded(dir.path());
        let report = report_for(run, agent, attempt, dir.path());
        let mut sup = supervisor_for_test();

        sup.apply_finalize(report.clone(), &mut reg)
            .expect("the first application succeeds");
        let after_first = reg.events(&run, None, usize::MAX).len();
        assert_eq!(reg.agent_message_count(&run, &attempt), 2);
        assert!(sup.is_finalized(&attempt));
        assert_eq!(sup.pending_finalize_count(), 0);

        // Force a second delivery past the `finalized` guard, which is what a report re-sent after
        // a partial failure looks like from `already_recorded`'s point of view.
        sup.finalized.remove(&attempt);
        sup.apply_finalize(report, &mut reg)
            .expect("the second application succeeds");

        assert_eq!(
            reg.events(&run, None, usize::MAX).len(),
            after_first,
            "a re-applied report must append nothing"
        );
        let attempt_record = reg.attempt(&attempt).expect("the attempt");
        assert_eq!(attempt_record.violations.len(), 1);
        assert_eq!(attempt_record.status, AttemptStatus::Succeeded);
    }

    /// An unpriced model's usage line costs exactly 0.0. That is a real usage event, and a report
    /// re-applied from index 0 must not write it twice (Codex review of T33, round 3).
    #[test]
    fn a_zero_cost_usage_line_is_recorded_and_not_re_appended() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut reg, run, agent, attempt) = seeded(dir.path());
        let report = report_for(run, agent, attempt, dir.path());
        let mut sup = supervisor_for_test();

        sup.apply_finalize(report.clone(), &mut reg)
            .expect("the first application succeeds");
        let recorded = reg.attempt(&attempt).expect("the attempt");
        assert_eq!(
            recorded.cost_usd, 0.0,
            "the fixture is deliberately unpriced"
        );
        assert!(recorded.tokens.is_some(), "but its usage *was* recorded");

        let usage_lines = |reg: &Registry| {
            reg.events(&run, None, usize::MAX)
                .iter()
                .filter(|e| matches!(&e.payload, EventPayload::AttemptUsage { .. }))
                .count()
        };
        assert_eq!(usage_lines(&reg), 1);

        sup.finalized.remove(&attempt);
        sup.apply_finalize(report, &mut reg)
            .expect("the second application succeeds");
        assert_eq!(
            usage_lines(&reg),
            1,
            "a zero-cost usage line is present, not missing"
        );
    }

    /// `<state>/runs/<runId>/events.jsonl`, the file every append goes through.
    fn log_path(dir: &std::path::Path, run: RunId) -> PathBuf {
        dir.join("runs").join(run.to_string()).join("events.jsonl")
    }

    /// Makes the log writable or not. Returns `false` when the mode cannot be enforced — running as
    /// root, where 0444 is advisory — so the caller can skip rather than assert something untrue.
    fn set_log_writable(path: &std::path::Path, writable: bool) -> bool {
        use std::os::unix::fs::PermissionsExt;

        // Safe: a read of this process's own effective uid, no arguments, no allocation.
        if unsafe { libc::geteuid() } == 0 {
            return false;
        }
        let mode = if writable { 0o600 } else { 0o444 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).is_ok()
    }

    /// An append that fails must leave the attempt **retryable**: parked, unmarked, still `running`
    /// in the projection — and a later retry must land its terminal event exactly once.
    ///
    /// The version this replaced marked the attempt finalized *before* appending and let `emit`
    /// swallow the error, so a failure here dropped the only copy of the attempt's terminal events
    /// and stranded it `running` forever (Codex review of T33, round 2, finding 1).
    #[test]
    fn a_report_whose_append_fails_is_parked_and_lands_on_retry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (reg, run, agent, attempt) = seeded(dir.path());
        // A fresh registry has no cached append handle, so the file's mode is what decides.
        drop(reg);
        let mut reg = Registry::open(dir.path()).expect("reopen");
        let log = log_path(dir.path(), run);
        if !set_log_writable(&log, false) {
            eprintln!("skipped: the log's mode is not enforceable here");
            return;
        }
        let report = report_for(run, agent, attempt, dir.path());
        let mut sup = supervisor_for_test();

        let err = sup
            .apply_finalize(report, &mut reg)
            .expect_err("the log is read-only");
        assert!(matches!(err, RegistryError::Io { .. }));
        assert_eq!(sup.pending_finalize_count(), 1, "parked, not dropped");
        assert!(!sup.is_finalized(&attempt), "and never marked done");
        assert_eq!(
            reg.attempt(&attempt).map(|a| a.status),
            Some(AttemptStatus::Running),
            "nothing terminal was recorded"
        );

        assert!(set_log_writable(&log, true));
        sup.retry_finalize(&mut reg).expect("the retry succeeds");

        assert_eq!(sup.pending_finalize_count(), 0);
        assert!(sup.is_finalized(&attempt));
        assert_eq!(
            reg.attempt(&attempt).map(|a| a.status),
            Some(AttemptStatus::Succeeded)
        );
        let finished = reg
            .events(&run, None, usize::MAX)
            .iter()
            .filter(|e| matches!(&e.payload, EventPayload::AttemptFinished { .. }))
            .count();
        assert_eq!(finished, 1, "exactly one attempt.finished");
        let frozen = reg
            .events(&run, None, usize::MAX)
            .iter()
            .filter(|e| matches!(&e.payload, EventPayload::DiffFrozen { .. }))
            .count();
        assert_eq!(frozen, 1, "exactly one diff.frozen");
    }

    /// The budget runs out and the caller is told, once — not silently forever.
    #[test]
    fn a_report_that_cannot_be_appended_stalls_after_its_budget() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (reg, run, agent, attempt) = seeded(dir.path());
        drop(reg);
        let mut reg = Registry::open(dir.path()).expect("reopen");
        let log = log_path(dir.path(), run);
        if !set_log_writable(&log, false) {
            eprintln!("skipped: the log's mode is not enforceable here");
            return;
        }
        let mut sup = supervisor_for_test();

        assert!(sup
            .apply_finalize(report_for(run, agent, attempt, dir.path()), &mut reg)
            .is_err());
        assert_eq!(sup.pending_finalize_count(), 1);

        // `apply_finalize` spent the first of the budget's attempts, so this many retries still
        // fit inside it and the one after them exhausts it.
        for _ in 0..MAX_FINALIZE_ATTEMPTS - 2 {
            assert!(
                sup.retry_finalize(&mut reg).is_ok(),
                "still inside the budget"
            );
        }
        let stalled = sup
            .retry_finalize(&mut reg)
            .expect_err("the budget is spent");
        assert_eq!(stalled.attempt, attempt);
        assert_eq!(stalled.failures, MAX_FINALIZE_ATTEMPTS);
        assert!(!sup.is_finalized(&attempt), "and it was never marked done");

        set_log_writable(&log, true);
    }

    #[test]
    fn the_prompt_is_the_token_after_dash_p() {
        let argv: Vec<String> = ["-p", "do the thing", "--model", "sonnet"]
            .iter()
            .map(|t| (*t).to_string())
            .collect();
        assert_eq!(prompt_token(&argv), Some("do the thing"));
    }

    #[test]
    fn a_trailing_positional_is_the_prompt_and_a_flag_value_is_not() {
        // Codex: `… -o <file> <PROMPT>` — the token before the prompt is a value, not a flag.
        let codex: Vec<String> = ["exec", "-o", "/tmp/last-message.txt", "review this"]
            .iter()
            .map(|t| (*t).to_string())
            .collect();
        assert_eq!(prompt_token(&codex), Some("review this"));

        // A plan whose last token is a flag's value has no identifiable prompt.
        let flagged: Vec<String> = ["--mcp-config", "{\"mcpServers\":{}}"]
            .iter()
            .map(|t| (*t).to_string())
            .collect();
        assert_eq!(prompt_token(&flagged), None);
        assert_eq!(prompt_token(&[]), None);
    }

    #[test]
    fn only_a_token_that_is_a_path_is_a_path_candidate() {
        assert_eq!(path_candidate("/etc/passwd"), Some("/etc/passwd"));
        assert_eq!(
            path_candidate("--output-schema=/tmp/s.json"),
            Some("/tmp/s.json")
        );
        // Prose and JSON that merely mention a path are not paths the CLI will open.
        assert_eq!(path_candidate("write the file at /etc/passwd"), None);
        assert_eq!(
            path_candidate("developer_instructions=\"be careful\""),
            None
        );
        assert_eq!(path_candidate("--model"), None);
    }

    #[test]
    fn normalize_resolves_traversal_without_climbing_past_the_root() {
        assert_eq!(normalize(Path::new("/a/b/../c")), Path::new("/a/c"));
        assert_eq!(normalize(Path::new("/a/../../../etc")), Path::new("/etc"));
        assert_eq!(normalize(Path::new("/a/./b/")), Path::new("/a/b"));
    }

    #[test]
    fn resolve_keeps_a_path_that_does_not_exist_yet_under_its_real_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().canonicalize().expect("canonicalize");
        let unborn = dir.path().join("attempts/a/output-schema.json");
        assert!(resolve(&unborn).starts_with(&real));
        assert!(resolve(&unborn).ends_with("output-schema.json"));
    }

    #[test]
    fn only_absolute_path_entries_survive_sanitization() {
        // `.` and the empty entry both mean "the current directory" to `execvp`, and the current
        // directory of a spawn is the worker's own worktree.
        assert_eq!(
            sanitize_path_value(".:/usr/bin::relative/bin:/bin"),
            Some("/usr/bin:/bin".to_string())
        );
        assert_eq!(sanitize_path_value(".:relative/bin"), None);
        assert_eq!(sanitize_path_value(""), None);
    }

    #[test]
    fn an_all_relative_path_is_dropped_rather_than_emptied() {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), ".:node_modules/.bin".to_string());
        sanitize_path(&mut env);
        assert!(!env.contains_key("PATH"), "an empty PATH would mean `.`");
    }

    #[test]
    fn a_pgid_that_names_our_own_group_is_never_signalled() {
        // `killpg(0, …)` is "everything in my process group" — the control plane itself. A missing
        // or corrupted pgid must therefore never reach `killpg`, whatever the probe says.
        struct AlwaysAlive;
        impl ProcessProbe for AlwaysAlive {
            fn is_alive(&self, _pid: i32, _start_time: &str) -> bool {
                true
            }
            fn start_time(&self, _pid: i32) -> Option<String> {
                Some("Sat Aug 23 03:22:01 2026".to_string())
            }
        }
        for pgid in [0, -1] {
            let target = SignalTarget {
                pid: 4242,
                pgid,
                start_time: "Sat Aug 23 03:22:01 2026".to_string(),
                owned: true,
            };
            assert_eq!(
                signal_target(&AlwaysAlive, &target, Signal::SIGKILL),
                SignalOutcome::Refused,
                "pgid {pgid}"
            );
        }
    }

    #[test]
    fn a_reattached_target_whose_start_time_moved_is_not_signalled() {
        struct Recycled;
        impl ProcessProbe for Recycled {
            fn is_alive(&self, _pid: i32, start_time: &str) -> bool {
                start_time == "Sat Aug 23 03:22:01 2026"
            }
            fn start_time(&self, _pid: i32) -> Option<String> {
                Some("Sat Aug 23 03:22:01 2026".to_string())
            }
        }
        // A pid the kernel handed to somebody else while the daemon was down. `owned` is false, so
        // the re-probe runs — and `Mismatch` means no signal was sent at all (Revision 24).
        let stranger = SignalTarget {
            pid: 4242,
            pgid: 4242,
            start_time: "Fri Aug 22 11:00:00 2026".to_string(),
            owned: false,
        };
        assert_eq!(
            signal_target(&Recycled, &stranger, Signal::SIGTERM),
            SignalOutcome::Mismatch
        );
    }

    #[test]
    fn resume_offset_stops_after_the_last_complete_line_it_was_asked_for() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stdout.jsonl");
        std::fs::write(&path, b"one\ntwo\nthree\npartial").expect("write");

        // Two lines consumed: resume at the byte after the second `\n`.
        assert_eq!(resume_offset(&path, 2), (8, 2));
        // The log is shorter than the projection claims (a crash truncated it): resume at the end
        // of the last *complete* line, never inside the unterminated tail (C6).
        assert_eq!(resume_offset(&path, 9), (14, 3));
        assert_eq!(resume_offset(&path, 0), (0, 0));
        assert_eq!(resume_offset(&dir.path().join("absent.jsonl"), 3), (0, 0));
    }

    #[test]
    fn a_timestamp_this_crate_wrote_parses_back_to_the_instant_it_named() {
        // The parser is the inverse of `registry::now_rfc3339`, and of nothing else.
        assert_eq!(
            unix_millis_from_rfc3339("1970-01-01T00:00:00.000Z"),
            Some(0)
        );
        assert_eq!(
            unix_millis_from_rfc3339("2023-11-14T22:13:20.412Z"),
            Some(1_700_000_000_412)
        );
        // The leap day a `days / 365` conversion gets wrong.
        assert_eq!(
            unix_millis_from_rfc3339("2024-02-29T00:00:00.000Z"),
            Some(1_709_164_800_000)
        );
        assert_eq!(unix_millis_from_rfc3339("not a timestamp"), None);
        // `now` is now: a deadline re-armed from it gets the full timeout, not an expired one.
        assert!(elapsed_since(&registry::now_rfc3339()) < Duration::from_secs(2));
        assert_eq!(elapsed_since("garbage"), Duration::ZERO);
    }

    #[test]
    fn lstart_is_kept_verbatim_apart_from_surrounding_space() {
        assert_eq!(
            parse_lstart(b"Sat Aug 23 03:22:01 2026\n"),
            Some("Sat Aug 23 03:22:01 2026".to_string())
        );
        assert_eq!(parse_lstart(b"   \n"), None);
        assert_eq!(parse_lstart(b""), None);
    }
}
