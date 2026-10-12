//! Fixtures shared by the integration tests that drive real processes (T23; used by T25 and the
//! loop tests that follow).
//!
//! Three rules from `NOTES.md` are encoded here so no test has to re-derive them:
//!
//! * the fake CLIs are found through `env!("CARGO_BIN_EXE_fake-claude")`, which resolves only
//!   because the fakes are `[[bin]]` targets of *this* package;
//! * a test reaches them by name (`claude`, `codex`) through a temp bin dir prepended to `PATH`,
//!   never by hard-coding a path into a plan — that is the same lookup production performs;
//! * `$ACP_STATE_DIR` and every scratch repo live in `tempfile` dirs, so a test never writes into
//!   the repo.
//!
//! Included with `mod common;` by several test binaries, each of which uses a different subset —
//! hence the crate-level `dead_code` allowance.

#![allow(dead_code)]

use std::env;
use std::future::Future;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Once, RwLock};
use std::time::{Duration, Instant};

use agent_control_plane::core::policy::{DelegateRequest, SessionSpec};
use agent_control_plane::core::registry::Registry;
use agent_control_plane::core::supervisor::{PsProbe, Supervisor};
use agent_control_plane::core::types::{
    Actor, AgentId, AgentStatus, AttemptStatus, Event, EventPayload, HandoffEnvelope, RoleName,
    RolesConfig, RunId, RunStatus, SchemaName, Task,
};
use agent_control_plane::core::{
    channel, run_actor, spawn_signal_forwarder, spawn_tick_task, AwaitOut, Command as CoreCommand,
    Core, CoreError, CoreHandle, StatusOut, StatusQuery,
};
use agent_control_plane::roles::loader::load_roles;
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde_json::Value;
use tempfile::TempDir;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// A temp directory holding `claude` and `codex` symlinks to the fake bins.
///
/// Symlinks rather than copies: `providers::find_on_path` follows them (`fs::metadata`), and a copy
/// would go stale the moment cargo rebuilt the fake.
pub fn fixture_bin_dir() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir for the fake CLI bin dir");
    for (name, target) in [
        ("claude", env!("CARGO_BIN_EXE_fake-claude")),
        ("codex", env!("CARGO_BIN_EXE_fake-codex")),
    ] {
        let link = dir.path().join(name);
        symlink(target, &link)
            .unwrap_or_else(|err| panic!("symlink {} -> {target}: {err}", link.display()));
    }
    dir
}

/// A `PATH` value with `dir` in front of this process's own.
///
/// An empty current `PATH` yields just `dir`, never `"<dir>:"` — a trailing colon is an empty entry,
/// which means "the current directory" to `execvp` and is exactly what
/// `providers::find_on_path` refuses to search.
pub fn prepend_path(dir: &Path) -> String {
    match env::var("PATH") {
        Ok(existing) if !existing.is_empty() => format!("{}:{existing}", dir.display()),
        _ => dir.display().to_string(),
    }
}

/// A temp `$ACP_STATE_DIR`. `tempfile` creates it 0700, which is the mode the design requires.
pub fn temp_state_dir() -> TempDir {
    tempfile::tempdir().expect("tempdir for $ACP_STATE_DIR")
}

/// A scratch git repo with one empty commit, so `HEAD` resolves.
///
/// `user.name`/`user.email` are set in the repo itself: a `worker_commits` scenario runs a real
/// `git commit` in here, and the daemon's own identity must not be assumed to exist.
pub fn temp_git_repo() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir for a scratch git repo");
    git(dir.path(), &["init", "--initial-branch=main"]);
    git(dir.path(), &["config", "user.name", "acp test"]);
    git(dir.path(), &["config", "user.email", "acp@example.invalid"]);
    git(
        dir.path(),
        &["commit", "--allow-empty", "-m", "initial commit"],
    );
    dir
}

fn git(cwd: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|err| panic!("run git {args:?}: {err}"));
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The `claude` (or `codex`) symlink inside a [`fixture_bin_dir`].
pub fn fixture_bin(dir: &TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

// ---------------------------------------------------------------------------
// Driving the fake CLIs through the *real* loop (T36-T38)
// ---------------------------------------------------------------------------
//
// A test that drives `core::loop` cannot hand the fake bins a plan of its own: the loop builds
// every `SpawnPlan` itself, from `providers::base_env()`, and resolves `claude`/`codex` against
// **this process's** `PATH` twice — once in `preflight` and once in `assert_safe_argv`. So the only
// two dials a loop test has are the process `PATH` and the process environment, and both are
// process-global while cargo runs a binary's tests on parallel threads.
//
// The way out is to make the per-test configuration travel on the **filesystem** instead: `PATH`
// gets one pair of wrapper scripts for the whole binary ([`install_fake_clis`]), and each wrapper
// walks up from the worker's own current directory — its worktree, which lives inside that test's
// temp repository — to the first [`FAKE_ENV_FILE`] and sources it ([`configure_fakes`]). Two tests
// with different repositories therefore configure different workers with no shared state at all,
// and nothing has to be serialized.
//
// [`with_shared_env`] / [`with_exclusive_env`] are for the handful of tests that genuinely need the
// process environment itself — `missing_bin` (which is *defined* as "not on `PATH`") and the one
// that proves the `ACP_FAKE_*` pass-through in `providers::base_env`.

/// Sourced by the wrapper CLIs, found by walking up from the worker's cwd. It lives at the root of
/// a test's temp repository, which is an ancestor of every worktree the loop creates in it and is
/// *not* inside any of them — so it can never show up in a frozen diff.
pub const FAKE_ENV_FILE: &str = ".acp-fake-env";

/// `$ACP_FAKE_STATE` for a repository: the fakes' per-scenario invocation counter. Beside
/// [`FAKE_ENV_FILE`] and outside every worktree, for the same reason.
pub const FAKE_STATE_FILE: &str = ".acp-fake-state.json";

/// Set in [`FAKE_ENV_FILE`] to a marker path: the **codex** wrapper makes the **first** reviewer
/// echo a wrong `diffHash` and every one after it echo the right one.
///
/// It is how a test reaches Rev 25's recovery half — one reviewer refused, one replacement that
/// actually decides — which no fixture can express, because the correct hash is only knowable at
/// run time. The marker is created by the first call, so the "once" is a fact on disk rather than
/// a race with the loop.
pub const FAKE_WRONG_HASH_ONCE: &str = "ACP_FAKE_WRONG_HASH_ONCE";

/// The wrong hash [`FAKE_WRONG_HASH_ONCE`] makes the first reviewer echo: 64 hex, so the verdict
/// still validates against `schemas/review-verdict.json` and what fails is the binding, not the
/// schema.
pub const WRONG_DIFF_HASH: &str =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

/// Set in [`FAKE_ENV_FILE`] to make the **codex** wrapper truncate `$ACP_FAKE_STATE` before every
/// call, so every reviewer replays the scenario's *first* transcript.
///
/// It is how a test reaches a sequence the fixture set has no name for — two consecutive review
/// `FAIL`s — without racing the loop to rewrite the counter file between reviewers
/// (`fixtures/jsonl/README.md`: `fail_then_pass` is `review-fail-1` then `review-pass-2`, chosen by
/// the counter in `$ACP_FAKE_STATE`).
pub const FAKE_RESET_STATE: &str = "ACP_FAKE_RESET_STATE";

static FAKE_CLIS: Once = Once::new();

/// Shared for tests that only read the process environment, exclusive for the ones that rewrite it.
pub static ENV_GUARD: RwLock<()> = RwLock::new(());

/// Puts wrapper `claude`/`codex` scripts on the front of this process's `PATH`, once per test
/// binary.
///
/// For the whole binary rather than per test, and that is the safety property that matters: with
/// the wrappers in front, a machine that happens to have a real `claude` or `codex` installed still
/// cannot have one started by these tests.
///
/// The wrapper dir is deliberately leaked — a spawn may resolve `claude` through it long after the
/// test that triggered the install returned.
pub fn install_fake_clis() {
    FAKE_CLIS.call_once(|| {
        let dir = tempfile::tempdir().expect("tempdir for the wrapper CLI bin dir");
        write_wrapper(
            &dir.path().join("claude"),
            env!("CARGO_BIN_EXE_fake-claude"),
            CLAUDE_EXTRA,
        );
        write_wrapper(
            &dir.path().join("codex"),
            env!("CARGO_BIN_EXE_fake-codex"),
            CODEX_EXTRA,
        );

        let original = env::var_os("PATH").unwrap_or_default();
        let mut dirs = vec![dir.keep()];
        dirs.extend(env::split_paths(&original));
        env::set_var("PATH", env::join_paths(dirs).expect("join PATH"));
    });
}

/// Points the wrappers in `repo_root` at one scenario.
///
/// Always sets `ACP_FAKE_SCENARIO` and `ACP_FAKE_STATE`; `extra` adds anything else the fakes read
/// (`ACP_FAKE_DELAY_MS`, `ACP_FAKE_DIFF_HASH`, [`FAKE_RESET_STATE`]). Call it before the first
/// `delegate` — the file is read by each worker as it starts, so a later call re-points the workers
/// that have not started yet.
pub fn configure_fakes(repo_root: &Path, scenario: &str, extra: &[(&str, &str)]) {
    let state = repo_root.join(FAKE_STATE_FILE);
    let state = state.display().to_string();
    let mut vars: Vec<(&str, &str)> = vec![
        ("ACP_FAKE_SCENARIO", scenario),
        ("ACP_FAKE_STATE", state.as_str()),
    ];
    vars.extend_from_slice(extra);

    let mut body = String::from("# written by tests/common/mod.rs — sourced by the wrapper CLIs\n");
    for (key, value) in vars {
        assert!(
            !value.contains('\'') && !value.contains('\n'),
            "{key} must be quotable in a POSIX shell assignment: {value:?}"
        );
        body.push_str(&format!("{key}='{value}'\nexport {key}\n"));
    }
    let path = repo_root.join(FAKE_ENV_FILE);
    std::fs::write(&path, body).unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
}

/// Runs one async test body on its own multi-threaded runtime, holding [`ENV_GUARD`] **shared**.
///
/// The guard is taken in sync code around `block_on` rather than inside the future, so no lock is
/// ever held across an `.await` (`clippy::await_holding_lock`).
pub fn with_shared_env<F, Fut>(body: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let _env = ENV_GUARD
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    block_on(body());
}

/// The same, **exclusive**: for a test that rewrites `PATH` or sets an `ACP_FAKE_*` key in this
/// process, neither of which any other test may observe.
pub fn with_exclusive_env<F, Fut>(body: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let _env = ENV_GUARD
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    block_on(body());
}

fn block_on<Fut: Future<Output = ()>>(fut: Fut) {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(fut);
}

/// What the **claude** wrapper does on top of sourcing [`FAKE_ENV_FILE`]: lift the `diffHash`
/// out of the prompt for a **verifier** invocation (the verifier prompt states it exactly as the
/// reviewer's does), so the fake's verify report echoes the hash of the diff the loop actually
/// froze — what a real verifier does, and what Rev 25's mirror in `branch_verify` requires.
///
/// Deliberately a **separate variable** from `ACP_FAKE_DIFF_HASH`: that one steers the *codex
/// reviewer*, and a test pinning the reviewer's wrong-hash path must not accidentally poison the
/// verify step (both wrappers source the same env file). A verify-mismatch test sets
/// `ACP_FAKE_VERIFY_HASH` instead. A builder/lead prompt contains no "diffHash is", so the
/// lifted value stays empty and harmless there.
const CLAUDE_EXTRA: &str = "\
if [ -z \"$ACP_FAKE_VERIFY_HASH\" ]; then\n\
\tACP_FAKE_VERIFY_HASH=$(printf '%s\\n' \"$@\" | sed -n 's/.*diffHash is \\([0-9a-f][0-9a-f]*\\).*/\\1/p' | head -n 1)\n\
\texport ACP_FAKE_VERIFY_HASH\n\
fi\n";

/// What the **codex** wrapper does before `exec`, on top of sourcing [`FAKE_ENV_FILE`].
///
/// Two jobs, both of which have to happen in the child because only the child knows the prompt it
/// was given:
///
/// * `ACP_FAKE_RESET_STATE` truncates the counter file, pinning every call to the scenario's first
///   transcript (see [`FAKE_RESET_STATE`]);
/// * `ACP_FAKE_WRONG_HASH_ONCE` names a marker the first call creates; while it did not exist, the
///   call echoes [`WRONG_DIFF_HASH`] instead of the real one (see [`FAKE_WRONG_HASH_ONCE`]);
/// * with no `ACP_FAKE_DIFF_HASH` configured, the hash is lifted **out of the reviewer's own
///   prompt** — `handoff::build_reviewer_prompt` states it as "The frozen diff's diffHash is
///   `<64 hex>`." — so the fake echoes the hash of the diff the loop actually froze. That is what a
///   real reviewer does, and Rev 25 requires it: a `PASS` whose `diffHash` differs is discarded. A
///   test that wants the *mismatch* path sets `ACP_FAKE_DIFF_HASH` in [`FAKE_ENV_FILE`] instead,
///   and this leaves it alone.
const CODEX_EXTRA: &str = "\
if [ -n \"$ACP_FAKE_RESET_STATE\" ] && [ -n \"$ACP_FAKE_STATE\" ]; then\n\
\tprintf '%s' '{}' > \"$ACP_FAKE_STATE\"\n\
fi\n\
if [ -n \"$ACP_FAKE_WRONG_HASH_ONCE\" ] && [ ! -e \"$ACP_FAKE_WRONG_HASH_ONCE\" ]; then\n\
\t: > \"$ACP_FAKE_WRONG_HASH_ONCE\"\n\
\tACP_FAKE_DIFF_HASH=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n\
\texport ACP_FAKE_DIFF_HASH\n\
fi\n\
if [ -z \"$ACP_FAKE_DIFF_HASH\" ]; then\n\
\tACP_FAKE_DIFF_HASH=$(printf '%s\\n' \"$@\" | sed -n 's/.*diffHash is \\([0-9a-f][0-9a-f]*\\).*/\\1/p' | head -n 1)\n\
\texport ACP_FAKE_DIFF_HASH\n\
fi\n";

/// Writes one wrapper script: source the nearest [`FAKE_ENV_FILE`] above the worker's cwd, run
/// `extra`, then `exec` the real fake with the argv the control plane built, untouched.
fn write_wrapper(path: &Path, real: &str, extra: &str) {
    let script = format!(
        "#!/bin/sh\n\
         # Per-test configuration for the fake provider CLIs (tests/common/mod.rs).\n\
         # The walk-up must be TOTAL: if the cwd was deleted under us (a dropped\n\
         # TempDir with a worker still live), `pwd -P` fails and an unguarded\n\
         # `dirname` loop spins forever at `.` forking twice per iteration\n\
         # (found as a live CPU-burning orphan in review). Bail on an empty or\n\
         # relative dir and on a dirname fixed point.\n\
         dir=$(pwd -P) || dir=\n\
         case \"$dir\" in /*) ;; *) dir= ;; esac\n\
         while [ -n \"$dir\" ]; do\n\
         \tif [ -f \"$dir/{FAKE_ENV_FILE}\" ]; then\n\
         \t\t. \"$dir/{FAKE_ENV_FILE}\"\n\
         \t\tbreak\n\
         \tfi\n\
         \tnext=$(dirname \"$dir\")\n\
         \tif [ \"$next\" = \"$dir\" ]; then\n\
         \t\tbreak\n\
         \tfi\n\
         \tdir=$next\n\
         done\n\
         {extra}exec \"{real}\" \"$@\"\n"
    );
    std::fs::write(path, script).unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|err| panic!("chmod {}: {err}", path.display()));
}

// ---------------------------------------------------------------------------
// A whole loop, wired the way production wires it (T36-T38)
// ---------------------------------------------------------------------------

/// The design's injected tick for tests ("`tick_ms` is injectable; tests use 25 ms").
pub const TICK: Duration = Duration::from_millis(25);

/// How long anything here may take before a test calls it a hang. Generous on purpose: it is a
/// failure detector, never a timing assertion.
pub const LIMIT: Duration = Duration::from_secs(60);

/// The state dir and the repository one loop test owns, plus the scenario its workers replay.
///
/// Both are `tempfile` dirs, so a test never writes into this repository, and the fake CLIs are
/// configured through [`configure_fakes`] rather than through this process's environment.
pub struct LoopWorld {
    pub state: TempDir,
    pub repo: TempDir,
}

impl LoopWorld {
    /// A state dir, a scratch repo with one empty commit, the wrapper CLIs on `PATH`, and
    /// `.acp-fake-env` pointing at `scenario`.
    pub fn new(scenario: &str, extra: &[(&str, &str)]) -> Self {
        install_fake_clis();
        let world = Self {
            state: temp_state_dir(),
            repo: temp_git_repo(),
        };
        configure_fakes(world.repo_root(), scenario, extra);
        world
    }

    pub fn state_dir(&self) -> &Path {
        self.state.path()
    }

    pub fn repo_root(&self) -> &Path {
        self.repo.path()
    }

    /// A fresh [`Registry`] over this world's state dir — the durable log, replayed from disk.
    pub fn reopen(&self) -> Registry {
        Registry::open(self.state_dir()).expect("reopen the registry")
    }

    /// Every event of `run`, read back from disk.
    pub fn events(&self, run: &RunId) -> Vec<Arc<Event>> {
        self.reopen().events(run, None, usize::MAX)
    }
}

/// Which companion tasks an actor is started with.
#[derive(Clone, Copy, Default)]
pub struct ActorOpts {
    /// Re-attach to every attempt the log still shows as `running` — the restart path.
    pub reattach: bool,
    /// Leave the tick task unspawned, so nothing at all happens until the caller sends a command.
    /// Used by the restart test, whose two snapshots must be taken over an unchanged log.
    pub no_tick: bool,
}

/// One running core: the actor task, the signal forwarder, and (unless [`ActorOpts::no_tick`]) the
/// tick task — exactly the three `main.rs` spawns.
pub struct LoopActor {
    pub handle: CoreHandle,
    pub events: broadcast::Receiver<Arc<Event>>,
    pub shutdown: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    /// Kept apart from the rest because it is the one task a stop must **not** wait for; see
    /// [`LoopActor::stop`].
    forwarder: JoinHandle<()>,
    mailbox: mpsc::Sender<CoreCommand>,
}

impl LoopActor {
    /// Starts the tick task an [`ActorOpts::no_tick`] core was deliberately built without.
    ///
    /// The restart test compares two `get_status` snapshots taken over the *same* log, so its
    /// second core must not tail, probe or sweep until the comparison is done — and then must, so
    /// the worker it re-attached to can be ended.
    pub fn start_ticking(&mut self) {
        self.tasks.push(spawn_tick_task(
            self.mailbox.clone(),
            TICK,
            self.shutdown.clone(),
        ));
    }

    /// Stops the actor and waits for it.
    ///
    /// A normal stop deliberately leaves live workers running (design, C3: "workers survive; a
    /// restart re-attaches"), so a test that started one calls [`quiesce`] **first**.
    ///
    /// The signal forwarder is aborted rather than awaited. Its receiver only closes once every
    /// `SupervisorSignal` sender is gone, and `Supervisor::arm_deadline` clones one into a detached
    /// ladder task that sleeps until the attempt's deadline — up to `attemptTimeoutSec`, which is
    /// half an hour. That is deliberate (the ladder has to be able to deliver SIGKILL after the
    /// actor is gone), so waiting on the forwarder would be waiting on a timer. With the actor
    /// stopped the forwarder has nothing left to deliver anyway.
    pub async fn stop(self) {
        self.shutdown.cancel();
        for task in self.tasks {
            let _ = tokio::time::timeout(LIMIT, task).await;
        }
        self.forwarder.abort();
    }
}

/// Wires a core over `world` and starts it.
pub fn start_actor(world: &LoopWorld, roles: Arc<RolesConfig>, opts: ActorOpts) -> LoopActor {
    let (tx, rx) = channel();
    let (sig_tx, signals) = mpsc::channel(64);
    let registry = world.reopen();
    let mut supervisor = Supervisor::new(TICK, Arc::new(PsProbe), sig_tx);
    if opts.reattach {
        reattach_running(&mut supervisor, &registry, &roles);
    }
    let core = Core::new(
        registry,
        supervisor,
        roles,
        world.repo_root().to_path_buf(),
        world.state_dir().to_path_buf(),
        tx,
    );
    let handle = core.handle();
    let events = handle.events();
    let mailbox = core.mailbox();
    let shutdown = CancellationToken::new();
    let forwarder = spawn_signal_forwarder(signals, mailbox.clone());
    let mut tasks = vec![tokio::spawn(run_actor(core, rx, shutdown.clone()))];
    if !opts.no_tick {
        tasks.push(spawn_tick_task(mailbox.clone(), TICK, shutdown.clone()));
    }
    LoopActor {
        handle,
        events,
        shutdown,
        tasks,
        forwarder,
        mailbox,
    }
}

/// The embedded roles with a shorter attempt deadline, for the scenarios that never end on their
/// own (`hang`). Cloning the config is the only way to change it: `roles.json` is embedded, and a
/// test must not depend on an external file it would then have to keep in sync.
pub fn roles_with_attempt_timeout(secs: u64) -> Arc<RolesConfig> {
    let mut cfg = (*load_roles(None).expect("the embedded roles")).clone();
    cfg.defaults.attempt_timeout_sec = secs;
    Arc::new(cfg)
}

pub fn embedded_roles() -> Arc<RolesConfig> {
    load_roles(None).expect("the embedded roles")
}

/// The **library's** restart path, applied to this world's supervisor.
///
/// It used to be re-implemented here, which meant the daemon and the tests could drift — and did:
/// `cli::serve` had no re-attach at all while these tests proved one worked. There is now one
/// implementation (`core::loop::reattach_running`), called from the same place in the same
/// sequence by `acp serve` and by [`start_actor`], so a restart test exercises the daemon's code.
fn reattach_running(supervisor: &mut Supervisor, registry: &Registry, roles: &RolesConfig) {
    agent_control_plane::core::r#loop::reattach_running(supervisor, registry, roles);
}

/// The checked-in post-processed schema a role's output is validated against (V7).
pub fn checked_in_schema(name: SchemaName) -> Value {
    let file = match name {
        SchemaName::BuildResult => "build-result.json",
        SchemaName::ReviewVerdict => "review-verdict.json",
        SchemaName::VerifyReport => "verify-report.json",
        // A lead's free text is validated against nothing: there is no document to check in.
        SchemaName::FreeText => return Value::Null,
    };
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("schemas")
        .join(file);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&text).expect("a checked-in schema is valid JSON")
}

fn compile_denylist(roles: &RolesConfig) -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    for pattern in &roles.defaults.denylist_globs {
        builder.add(Glob::new(pattern).expect("a shipped denylist glob compiles"));
    }
    builder.build().expect("the denylist compiles")
}

// ---------------------------------------------------------------------------
// Waiting — on durable events, never on a timer
// ---------------------------------------------------------------------------

/// Waits for one event on the door's own broadcast stream.
///
/// `Lagged` is skipped rather than failed: it is a property of this subscriber, not of the thing
/// under test.
pub async fn wait_for_event(
    events: &mut broadcast::Receiver<Arc<Event>>,
    what: &str,
    mut pred: impl FnMut(&Event) -> bool,
) -> Arc<Event> {
    let found = tokio::time::timeout(LIMIT, async {
        loop {
            match events.recv().await {
                Ok(event) if pred(&event) => return event,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => {
                    panic!("the event stream closed before {what}")
                }
            }
        }
    })
    .await;
    found.unwrap_or_else(|_| panic!("{what} never happened within {LIMIT:?}"))
}

/// Polls the durable log until `pred` holds, then returns the events it held for.
///
/// Reading the log rather than the broadcast stream is what makes a wait *idempotent*: a condition
/// that was already true before the caller subscribed still resolves.
pub async fn wait_for_log(
    world: &LoopWorld,
    run: &RunId,
    what: &str,
    mut pred: impl FnMut(&[Arc<Event>]) -> bool,
) -> Vec<Arc<Event>> {
    let deadline = Instant::now() + LIMIT;
    loop {
        let events = world.events(run);
        if pred(&events) {
            return events;
        }
        assert!(
            Instant::now() < deadline,
            "{what} never happened within {LIMIT:?}\nevent kinds so far: {:?}",
            events
                .iter()
                .filter_map(|e| serde_json::to_value(&e.payload).ok())
                .map(|v| {
                    let kind = v["kind"].as_str().unwrap_or("?").to_string();
                    match v.get("reason").and_then(|r| r.as_str()) {
                        Some(reason) => format!("{kind}({reason})"),
                        None => kind,
                    }
                })
                .collect::<Vec<_>>()
        );
        tokio::time::sleep(TICK).await;
    }
}

/// Polls `get_status` until `pred` holds.
pub async fn wait_for_status(
    handle: &CoreHandle,
    query: StatusQuery,
    what: &str,
    mut pred: impl FnMut(&StatusOut) -> bool,
) -> StatusOut {
    let deadline = Instant::now() + LIMIT;
    loop {
        let status = handle
            .status(query.clone())
            .await
            .unwrap_or_else(|err| panic!("get_status while waiting for {what}: {err}"));
        if pred(&status) {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "{what} never happened within {LIMIT:?}: {}",
            digest(&status)
        );
        tokio::time::sleep(TICK).await;
    }
}

/// A one-line summary of a status, for a failure message. A whole `StatusOut` carries every worker
/// argv the run has produced — tens of kilobytes of prompt, unreadable as a panic message.
fn digest(status: &StatusOut) -> String {
    let runs: Vec<String> = status
        .runs
        .iter()
        .map(|run| format!("{:?}/{:?}", run.status, run.loop_state))
        .collect();
    let attempts: Vec<String> = status
        .attempts
        .iter()
        .map(|a| format!("{:?}", a.status))
        .collect();
    format!(
        "runs [{}], attempts [{}], blockedReason {:?}",
        runs.join(", "),
        attempts.join(", "),
        status.blocked_reason
    )
}

/// Ends every worker this test started, so none outlives it.
///
/// A normal actor stop leaves live workers running on purpose, so a test that spawned one has to
/// end it itself. Cancelling is also what stops the loop from starting the *next* attempt: a
/// cancelled attempt is `Branch::None`, the one terminal state the loop deliberately does nothing
/// about.
///
/// "Quiet" is two things, not one — nothing is running **and** nothing can still start. The second
/// is what `agent.created` with no `attempt.started` means: a spawn helper is in flight, and it
/// will adopt a worker after this returns. An agent in that state whose run has stopped accepting
/// workers is not counted, because nothing will ever be started for it (`run_accepts_workers`).
pub async fn quiesce(handle: &CoreHandle) {
    let deadline = Instant::now() + LIMIT;
    let mut quiet = 0;
    while quiet < 2 {
        let Ok(status) = handle.status(StatusQuery::default()).await else {
            return; // the actor is already gone; nothing of ours can still be adopted
        };
        let live: Vec<AgentId> = status
            .attempts
            .iter()
            .filter(|a| a.status == AttemptStatus::Running)
            .map(|a| a.agent_id)
            .collect();
        let starting = status.agents.iter().any(|agent| {
            !status
                .attempts
                .iter()
                .any(|attempt| attempt.agent_id == agent.agent_id)
                && !matches!(
                    agent.process_state,
                    AgentStatus::Closed | AgentStatus::Cancelled
                )
                && status
                    .runs
                    .iter()
                    .any(|run| run.run_id == agent.run_id && run.status == RunStatus::Running)
        });
        if live.is_empty() && !starting {
            quiet += 1;
        } else {
            quiet = 0;
            for agent in live {
                let _ = handle.cancel(agent).await;
            }
        }
        assert!(
            Instant::now() < deadline,
            "workers were still running after {LIMIT:?}"
        );
        tokio::time::sleep(TICK).await;
    }
}

// ---------------------------------------------------------------------------
// Reading the log back
// ---------------------------------------------------------------------------

/// Every event of `events` whose payload matches `f`, mapped through it.
pub fn pick<T>(events: &[Arc<Event>], f: impl Fn(&EventPayload) -> Option<T>) -> Vec<T> {
    events.iter().filter_map(|e| f(&e.payload)).collect()
}

/// `<stateDir>/runs/<runId>/attempts/<attemptId>/prompt.txt` — the prompt the worker was actually
/// started with, written by `spawn_detached` from the plan's own argv.
pub fn rendered_prompt(attempt_dir: &Path) -> String {
    let path = attempt_dir.join("prompt.txt");
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// `git rev-parse HEAD` in `dir`, as the human would run it.
pub fn head_sha(dir: &Path) -> String {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(dir)
        .output()
        .unwrap_or_else(|err| panic!("git rev-parse in {}: {err}", dir.display()));
    assert!(
        out.status.success(),
        "git rev-parse in {} failed: {}",
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The files one commit touched, `git show --name-only`.
pub fn files_in_commit(dir: &Path, sha: &str) -> Vec<String> {
    let out = Command::new("git")
        .args(["show", "--name-only", "--pretty=format:", sha])
        .current_dir(dir)
        .output()
        .unwrap_or_else(|err| panic!("git show in {}: {err}", dir.display()));
    assert!(out.status.success(), "git show {sha} failed");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// One task, whose rendered prompt carries the string the stray-process check greps for
/// (`ps -eo command | grep -F 'Add src/adder.ts'`) — the same one `tests/supervisor_tick.rs` and
/// `tests/actor.rs` use, so a worker stranded by *any* suite is caught by one command.
pub fn loop_task(id: &str) -> Task {
    Task {
        id: id.to_string(),
        title: "Add src/adder.ts exporting add(a, b).".to_string(),
        description: "Add src/adder.ts exporting add(a, b).".to_string(),
        files: vec!["src/adder.ts".to_string()],
        acceptance: vec!["add(1, 2) === 3".to_string()],
    }
}

/// A fresh builder delegation for `task`.
pub fn delegate_builder(task: Task) -> DelegateRequest {
    DelegateRequest {
        run_id: None,
        role: RoleName::Builder,
        task,
        model: None,
        session: SessionSpec::Fresh,
        base_ref: None,
        worktree: None,
        steps: None,
        caller_run_id: None,
    }
}

/// The same fresh builder delegation, attested as coming from `caller_run_id` (T84) — what
/// `acp mcp-proxy` attaches to a spawned lead's own `delegate` calls.
pub fn delegate_builder_from(task: Task, caller_run_id: RunId) -> DelegateRequest {
    DelegateRequest {
        caller_run_id: Some(caller_run_id),
        ..delegate_builder(task)
    }
}

/// The human path for a gate resolution — `Actor::Socket` is the CLI and the menu-bar app.
pub fn cli_actor() -> Actor {
    Actor::Socket {
        client_name: "cli".to_string(),
    }
}

/// `await_result` as a lead polls it (design, step 8), until the agent's newest attempt is done.
///
/// Two things are tolerated on the way, both of them normal: a `Running` answer, which is what the
/// caller's own timeout produces, and a policy refusal naming an agent this state dir has not seen
/// yet — `delegate` answers **before** the worktree helper appends `agent.created`, which is the
/// whole point of the non-blocking reply.
pub async fn await_done(handle: &CoreHandle, agent: AgentId) -> Box<HandoffEnvelope> {
    let deadline = Instant::now() + LIMIT;
    loop {
        match handle.await_result(agent, TICK * 8).await {
            Ok(AwaitOut::Done { envelope }) => return envelope,
            Ok(AwaitOut::Running { .. }) => {}
            Err(CoreError::Policy(_)) => {}
            Err(err) => panic!("await_result on {agent}: {err}"),
        }
        assert!(
            Instant::now() < deadline,
            "agent {agent} never finished an attempt within {LIMIT:?}"
        );
        tokio::time::sleep(TICK).await;
    }
}
