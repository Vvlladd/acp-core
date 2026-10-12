//! T34: the core actor's two structural promises, asserted from outside the crate —
//! `reports/03-design.md` § Test Strategy, row `core/mod.rs` (actor).
//!
//! The promises are decision 10 ("the actor is one task") and decision 11 ("a mailbox turn never
//! awaits unbounded I/O"). Everything here exists to make one of them fail loudly if it stops
//! being true:
//!
//! * **A wedged git costs the mailbox nothing.** `Core::spawn_worktree_helper` is the chokepoint
//!   `delegate` reaches git through, so a `git worktree add` is stalled inside it while an
//!   *unrelated* run's `CoreHandle::status` is called twenty times. The stall is not a `sleep`: the
//!   shimmed `git` blocks until this test removes a marker file, so "the helper was still stuck"
//!   is a fact rather than a bet on a timer.
//! * **The mailbox keeps turning while a completion is outstanding.** An attempt's deadline fires
//!   while a `commit_all` helper is stuck; the proof is the *event log's own ordering* —
//!   `gate.resolving` < `attempt.cancel_requested{by:timeout}` < `gate.resolved` — which no timing
//!   assumption can fake.
//! * **No door is ever left hanging.** A parked `await_result` whose actor disappears is answered
//!   `Unavailable`; so is every `CoreHandle` method after the actor task has panicked. Each of
//!   those calls is wrapped in a `tokio::time::timeout`, so a regression that hangs fails the test
//!   instead of hanging the suite.
//! * **A door that times out and retries leaks nothing.** Twenty-five `await_result` calls that
//!   each expire and drop their receiver leave at most one dead `Waiter` for that agent.
//!
//! Three conventions this file inherits and does not re-derive (`NOTES.md`, `tests/common`):
//! `$ACP_STATE_DIR` and every repository are `tempfile` dirs so nothing is written into the repo;
//! the fake CLIs are reached by name through a temp bin dir on `PATH`; and the one worker spawned
//! here goes through the production chokepoint (`assert_safe_argv` → `spawn_detached`) and is
//! ended by the supervisor's own ladder before the test returns.
//!
//! **The git-hang scenario is driven through the helpers, not through `delegate`.**
//! `Core::spawn_worktree_helper` is the chokepoint `delegate` reaches git through, and driving it
//! directly keeps the assertion about the *mailbox* rather than about a whole delegation. T35 added
//! two more of the same shape, and this file covers both: the worktree read 17c hands to
//! `Core::spawn_porcelain_helper`, and the intents `Core::reconcile_intents` reissues after a
//! restart.

mod common;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};

use agent_control_plane::core::gates::{self, GatePayload, NewGate};
use agent_control_plane::core::policy::{DelegateRequest, SessionSpec};
use agent_control_plane::core::registry::Registry;
use agent_control_plane::core::supervisor::{
    assert_safe_argv, spawn_detached, ArgvCtx, AttemptContext, PsProbe, SpawnedProc, Supervisor,
    SupervisorSignal,
};
use agent_control_plane::core::types::{
    Actor, AgentId, AgentStatus, AttemptError, AttemptId, AttemptKind, AttemptStatus, CancelBy,
    ErrorCode, Event, EventPayload, False, GateId, GateKind, GateStatus, LineageId, LoopBranch,
    LoopState, Origin, ProviderName, ReviewFinding, RoleName, RoleSpec, RunId, RunStatus,
    SandboxMode, SchemaName, Severity, Task, Verdict, VerifyStatus,
};
use agent_control_plane::core::{
    channel, run_actor, spawn_signal_forwarder, spawn_tick_task, AwaitOut, Command, Core,
    CoreError, GateRequest, GateResolution, SendResult, StatusQuery,
};
use agent_control_plane::providers::claude::ClaudeAdapter;
use agent_control_plane::providers::{ProviderAdapter, SandboxSpec, SpawnRequest};
use agent_control_plane::roles::loader::load_roles;
use agent_control_plane::workspace::git::{self, GitError};
use globset::GlobSetBuilder;
use serde_json::Value;
use tempfile::TempDir;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

/// The design's injected tick for tests.
const TICK: Duration = Duration::from_millis(25);

/// How long anything here may take before the test calls it a hang. Generous on purpose: it is a
/// failure detector, never a timing assertion — the assertions that care about time measure it.
const LIMIT: Duration = Duration::from_secs(30);

/// The bound every "this must answer rather than hang" call is given. One second is the design's
/// own number for the git-hang row, and it is three orders of magnitude more than a mailbox turn
/// that touches nothing but the projection needs.
const ANSWER: Duration = Duration::from_secs(1);

/// How long "nothing else was issued" waits before believing it.
///
/// A helper posts its completion from a `tokio::spawn`, so an immediate `try_recv` proves nothing —
/// it races the task rather than the code under test. This is two orders of magnitude more than a
/// `spawn_detached` or a `git worktree add` on a temp dir needs to report.
const QUIET: Duration = Duration::from_millis(500);

const MODEL: &str = "claude-sonnet-4-5";

/// The prompt the fake worker is spawned with. Deliberately the same string
/// `tests/supervisor_tick.rs` uses, so `ps -eo command | grep -F 'Add src/adder.ts'` catches a
/// worker stranded by *any* suite, not just that one.
const WORKER_PROMPT: &str = "Add src/adder.ts exporting add(a, b).";

// ---------------------------------------------------------------------------
// The blocking `git` shim
// ---------------------------------------------------------------------------

/// While this file exists in a worktree, the shimmed `git` blocks in it.
const BLOCK_MARKER: &str = ".acp-block-git";

/// Written by the shim the moment it starts blocking, so a test can wait for git to be *inside*
/// the stall rather than assume it got there.
const ENTERED_MARKER: &str = ".acp-block-git.entered";

/// The shortened [`git::GIT_OP_TIMEOUT`] this binary runs under (debug builds only; see
/// `git_op_timeout`). It has to outlast the longest deliberate stall a test unblocks by hand —
/// which is ~1.3 s in [`an_attempt_timeout_is_recorded_while_a_commit_helper_is_stuck`] — and it
/// is what makes the never-unblocked stall end as `GitError::Timeout` in about four seconds
/// instead of thirty.
const GIT_TIMEOUT_MS: u64 = 4_000;

static SHIM: Once = Once::new();

/// Puts a **pass-through** `git` on the front of the process `PATH` and shortens the git timeout.
///
/// Like `tests/supervisor_tick.rs`'s shim and unlike `tests/git.rs`'s, this one needs no
/// `ENV_GUARD`: it `exec`s the real git unless the worktree it was invoked in holds
/// [`BLOCK_MARKER`], so every other git call in this binary behaves exactly as it always did.
///
/// It blocks on a *file* rather than sleeping for a fixed time, which is the whole reason the
/// concurrency assertions below are deterministic: the stall lasts precisely as long as the test
/// wants it to, and ends the moment the test says so — no margin to lose on a loaded machine, and
/// no `sleep` left running after the child is killed.
///
/// Both mutations are process-global, which is why they happen once, in a [`Once`] every test
/// enters before it reads any environment of its own. The shim directory is deliberately leaked:
/// another test may resolve `git` through it long after the one that created it returned.
fn install_blocking_git() {
    install_shims();
}

/// Puts the fake `claude`/`codex` on the front of the process `PATH`, for the whole binary.
///
/// A spawn resolves its program twice — `preflight` against this process's `PATH` and
/// `assert_safe_argv` against the plan's — so a test that lets the loop start a worker has to fix
/// the *process* environment, not just a plan. Doing it for the whole binary is also the safety
/// property that matters here: with the fakes in front, a machine that happens to have a real
/// `claude` installed still cannot have one started by these tests.
fn install_fake_clis() {
    install_shims();
}

/// **One** mutation of `PATH`, for both shims.
///
/// Two `Once`s each doing a read-modify-write of `PATH` from different tests is a lost update: the
/// second reads the value the first had not yet stored and drops its directory. So the git shim and
/// the fake CLIs go on in a single pass, and every entry point above funnels through here.
fn install_shims() {
    SHIM.call_once(|| {
        use std::os::unix::fs::PermissionsExt;

        let real = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join("git"))
            .find(|candidate| {
                std::fs::metadata(candidate)
                    .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
                    .unwrap_or(false)
            })
            .expect("a real git on PATH");

        let dir = TempDir::new().expect("shim dir");
        let shim = dir.path().join("git");
        std::fs::write(
            &shim,
            format!(
                "#!/bin/sh\n\
                 if [ -e \"./{BLOCK_MARKER}\" ]; then\n\
                 \t: > \"./{ENTERED_MARKER}\"\n\
                 \twhile [ -e \"./{BLOCK_MARKER}\" ]; do sleep 0.05; done\n\
                 fi\n\
                 exec \"{}\" \"$@\"\n",
                real.display()
            ),
        )
        .expect("write the shim");
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        // Both shim directories are deliberately leaked: a test may resolve `git` or `claude`
        // through them long after the test that created them returned.
        let original = std::env::var_os("PATH").unwrap_or_default();
        let mut dirs = vec![dir.keep(), common::fixture_bin_dir().keep()];
        dirs.extend(std::env::split_paths(&original));
        std::env::set_var("PATH", std::env::join_paths(dirs).expect("join PATH"));
        std::env::set_var("ACP_TEST_GIT_TIMEOUT_MS", GIT_TIMEOUT_MS.to_string());
    });
}

/// The next git call made in `dir` will block until [`unblock_git_in`].
fn block_git_in(dir: &Path) {
    std::fs::write(dir.join(BLOCK_MARKER), b"").expect("plant the block marker");
}

/// Releases the blocked git call and removes both markers, so the worktree is committable again.
fn unblock_git_in(dir: &Path) {
    let _ = std::fs::remove_file(dir.join(BLOCK_MARKER));
    let _ = std::fs::remove_file(dir.join(ENTERED_MARKER));
}

/// Waits until the shim reports it is *inside* the stall.
///
/// This is what turns "git is presumably slow now" into a fact, and it is the reason no assertion
/// below needs a margin: everything after this call is known to be running against a git that
/// cannot make progress.
async fn wait_until_git_blocks(dir: &Path) {
    let sentinel = dir.join(ENTERED_MARKER);
    let deadline = Instant::now() + LIMIT;
    while !sentinel.exists() {
        assert!(
            Instant::now() < deadline,
            "git never entered the blocked section in {}",
            dir.display()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

/// A core plus the two receivers `run_actor` and `spawn_signal_forwarder` are given.
///
/// The supervisor's signal receiver is handed back rather than dropped: a dropped receiver makes
/// every `try_send` fail, which is survivable by design but would strand every finalize report.
struct Wiring {
    core: Core,
    rx: mpsc::Receiver<Command>,
    signals: mpsc::Receiver<SupervisorSignal>,
}

fn wire(state: &Path, repo: &Path) -> Wiring {
    let (tx, rx) = channel();
    let (sig_tx, signals) = mpsc::channel(64);
    let core = Core::new(
        Registry::open(state).expect("open the registry"),
        Supervisor::new(TICK, Arc::new(PsProbe), sig_tx),
        load_roles(None).expect("the embedded roles"),
        repo.to_path_buf(),
        state.to_path_buf(),
        tx,
    );
    Wiring { core, rx, signals }
}

fn task(title: &str, description: &str) -> Task {
    Task {
        id: "T34".to_string(),
        title: title.to_string(),
        description: description.to_string(),
        files: vec!["tests/actor.rs".to_string()],
        acceptance: vec!["cargo test --test actor exits 0".to_string()],
    }
}

/// One run in the projection, with `repo_root` pointing at `repo`.
fn seed_run(core: &mut Core, repo: &Path, title: &str) -> RunId {
    let run = RunId::new_v4();
    core.registry
        .append(
            &run,
            EventPayload::RunCreated {
                execution: None,
                repo_root: repo.to_path_buf(),
                state_dir: core.state_dir.clone(),
                base_ref: "main".to_string(),
                base_sha: "0".repeat(40),
                task: task(title, "the actor stays answerable"),
                version: 1,
                lead: None,
                team_name: None,
                steps: None,
            },
        )
        .expect("run.created");
    run
}

/// One builder agent of `run`, so `await_result` has something it is allowed to park on.
fn seed_agent(core: &mut Core, run: &RunId, worktree: &Path) -> AgentId {
    let agent = AgentId::new_v4();
    core.registry
        .append(
            run,
            EventPayload::AgentCreated {
                agent_id: agent,
                role: RoleName::Builder,
                provider: ProviderName::Claude,
                model: MODEL.to_string(),
                lineage_id: Some(LineageId::new_v4()),
                depth: 1,
                parent_agent_id: None,
                origin: Origin::Lead,
                writes: true,
                cwd: worktree.to_path_buf(),
                worktree: Some(worktree.to_path_buf()),
            },
        )
        .expect("agent.created");
    agent
}

/// `attempt.started` + `attempt.finished` for a brand-new, already-succeeded attempt of `agent`.
fn finish_attempt(core: &mut Core, run: &RunId, agent: AgentId) -> AttemptId {
    let attempt = AttemptId::new_v4();
    core.registry
        .append(
            run,
            EventPayload::AttemptStarted {
                attempt_id: attempt,
                agent_id: agent,
                attempt_kind: AttemptKind::Fresh,
                dir: core.state_dir.join("attempt"),
                argv: vec!["claude".to_string()],
                cwd: core.repo_root.clone(),
                pid: 4242,
                pgid: 4242,
                start_time: "Sat Aug 23 00:00:00 2026".to_string(),
                pre_sha: "0".repeat(40),
                timeout_sec: 900,
                spawn_budget_usd: 2.0,
            },
        )
        .expect("attempt.started");
    core.registry
        .append(
            run,
            EventPayload::AttemptFinished {
                attempt_id: attempt,
                status: AttemptStatus::Succeeded,
                exit_code: Some(0),
                signal: None,
                post_sha: Some("0".repeat(40)),
                duration_ms: 10,
                error: None,
            },
        )
        .expect("attempt.finished");
    attempt
}

// ---------------------------------------------------------------------------
// A real worker, through the production chokepoint
// ---------------------------------------------------------------------------

fn builder_role() -> RoleSpec {
    RoleSpec {
        role: RoleName::Builder,
        provider: ProviderName::Claude,
        models: vec![MODEL.to_string()],
        default_model: MODEL.to_string(),
        writes: true,
        prompt_file: None,
        prompt_sha256: None,
        description: Some("Implements one task in its own worktree.".to_string()),
        tools: None,
        sandbox_mode: Some(SandboxMode::WorkspaceWrite),
        max_turns: 12,
        spawn_budget_usd: 2.0,
        result_schema: SchemaName::BuildResult,
        allowed_delegations: Vec::new(),
    }
}

/// The real post-processed artifact the supervisor validates worker output against (V7).
fn checked_in_schema() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("schemas")
        .join("build-result.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&text).expect("a checked-in schema is valid JSON")
}

/// Spawns the fake `claude` on the `hang` scenario — a worker that writes one line and then blocks
/// until it is signalled — through the same path production takes: the adapter's own plan, the
/// argv/env chokepoint, then `spawn_detached`.
async fn spawn_hanging_worker(
    bins: &TempDir,
    state_dir: &Path,
    worktree: &Path,
    attempt_dir: &Path,
) -> SpawnedProc {
    let schema = checked_in_schema();
    let role = builder_role();
    let prompt = WORKER_PROMPT.to_string();
    let req = SpawnRequest {
        role: &role,
        model: MODEL,
        prompt: &prompt,
        role_prompt: "You are a builder worker. Never commit; the control plane does.\n",
        cwd: worktree,
        attempt_dir,
        state_dir,
        lead_run_id: None,
        schema: ("build-result", &schema),
        max_turns: 12,
        spawn_budget_usd: 2.0,
        sandbox: Some(SandboxSpec { worktree }),
        session_id: None,
        effort: None,
    };
    let mut plan = ClaudeAdapter.build_fresh(&req);
    plan.env
        .insert("PATH".to_string(), common::prepend_path(bins.path()));
    plan.env
        .insert("ACP_FAKE_SCENARIO".to_string(), "hang".to_string());
    let prompt_index = ClaudeAdapter.prompt_index(&plan);

    let checked = assert_safe_argv(
        plan,
        &ArgvCtx {
            role: agent_control_plane::core::types::RoleName::Builder,
            lead_run_id: None,
            worktree,
            provider: ProviderName::Claude,
            sandboxed: true,
            state_dir,
            prompt_index,
        },
    )
    .expect("the adapter's own plan passes the chokepoint");
    spawn_detached(checked, attempt_dir.to_path_buf())
        .await
        .expect("spawn the fake provider")
}

fn attempt_context(
    run: RunId,
    agent: AgentId,
    attempt: AttemptId,
    dir: PathBuf,
    worktree: &Path,
    pre_sha: &str,
    timeout: Duration,
) -> AttemptContext {
    AttemptContext {
        run,
        agent,
        attempt,
        dir,
        adapter: Arc::new(ClaudeAdapter),
        timeout,
        pre_sha: pre_sha.to_string(),
        kind: AttemptKind::Fresh,
        role: RoleName::Builder,
        worktree: worktree.to_path_buf(),
        worktree_lock: Arc::new(tokio::sync::Mutex::new(())),
        writes: true,
        schema: Arc::new(checked_in_schema()),
        schema_name: SchemaName::BuildResult,
        denylist: Arc::new(
            GlobSetBuilder::new()
                .build()
                .expect("an empty denylist compiles"),
        ),
        spawn_budget_usd: 2.0,
        rate: None,
        session_id: None,
    }
}

// ---------------------------------------------------------------------------
// Reading the log back
// ---------------------------------------------------------------------------

/// The `seq` of the first event of `run` matching `pred`, read back from disk.
fn seq_of(reg: &Registry, run: &RunId, what: &str, pred: impl Fn(&Event) -> bool) -> u64 {
    reg.events(run, None, usize::MAX)
        .iter()
        .find(|event| pred(event))
        .unwrap_or_else(|| panic!("{what} is not in the log"))
        .base
        .seq
}

/// Waits for one event on the door's own broadcast stream.
///
/// `Lagged` is skipped rather than failed: it means the stream outran this receiver, which is a
/// property of the subscriber and not of the thing under test.
async fn wait_for_event(
    events: &mut broadcast::Receiver<Arc<Event>>,
    what: &str,
    mut pred: impl FnMut(&Event) -> bool,
) {
    let found = tokio::time::timeout(LIMIT, async {
        loop {
            match events.recv().await {
                Ok(event) if pred(&event) => return,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => {
                    panic!("the event stream closed before {what}")
                }
            }
        }
    })
    .await;
    assert!(found.is_ok(), "{what} never happened within {LIMIT:?}");
}

/// Calls one door and requires an answer: a hang is a failure, not a slow test.
async fn answered<T>(door: &str, call: impl Future<Output = Result<T, CoreError>>) -> T
where
    T: std::fmt::Debug,
{
    tokio::time::timeout(ANSWER, call)
        .await
        .unwrap_or_else(|_| panic!("{door} did not answer within {ANSWER:?}"))
        .unwrap_or_else(|err| panic!("{door} failed: {err}"))
}

/// The same, for a door that must report the actor is gone.
async fn unavailable<T>(door: &str, call: impl Future<Output = Result<T, CoreError>>)
where
    T: std::fmt::Debug,
{
    let out = tokio::time::timeout(ANSWER, call)
        .await
        .unwrap_or_else(|_| panic!("{door} hung after the actor was gone"));
    assert!(
        matches!(out, Err(CoreError::Unavailable)),
        "{door} answered {out:?} rather than Unavailable"
    );
}

fn cli() -> Actor {
    Actor::Socket {
        client_name: "cli".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Decision 11: a wedged git costs the mailbox nothing
// ---------------------------------------------------------------------------

/// The design's git-hang row: with `git worktree add` stalled inside the helper `delegate` reaches
/// git through, an unrelated run's `get_status` still answers in well under a second.
///
/// The stall is held open by a marker file rather than a sleep, so the two `is_finished` checks
/// around the measurement are facts: the helper had not completed before the twenty calls and had
/// not completed after them. Without decision 11 — a `delegate` that awaited `add_worktree` inside
/// its mailbox turn — the very first of those calls would have queued behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unrelated_status_answers_while_a_worktree_helper_is_stuck_in_git() {
    install_blocking_git();
    let state = common::temp_state_dir();
    let repo = common::temp_git_repo();
    let scratch = TempDir::new().expect("tempdir for the new worktree");

    let Wiring {
        mut core,
        rx,
        signals: _signals,
    } = wire(state.path(), repo.path());
    let delegating = seed_run(&mut core, repo.path(), "the run whose git is wedged");
    let unrelated = seed_run(
        &mut core,
        repo.path(),
        "the run that must still be answerable",
    );

    // Read HEAD before the block goes up, so the one stalled call is the `worktree add` itself.
    let base_sha = git::head_sha(repo.path()).await.expect("HEAD resolves");
    block_git_in(repo.path());

    let lineage = LineageId::new_v4();
    let helper = core.spawn_worktree_helper(
        lineage,
        repo.path().to_path_buf(),
        scratch.path().join("lineage-1"),
        "acp/lineage-1".to_string(),
        base_sha,
    );

    let handle = core.handle();
    let shutdown = CancellationToken::new();
    let actor = tokio::spawn(run_actor(core, rx, shutdown.clone()));

    wait_until_git_blocks(repo.path()).await;
    assert!(
        !helper.is_finished(),
        "git is inside the blocked section, so the helper cannot have finished"
    );

    // The assertion. Twenty round trips through the mailbox, while a git call the *other* run
    // depends on cannot make progress.
    let started = Instant::now();
    for _ in 0..20 {
        let status = answered(
            "status",
            handle.status(StatusQuery {
                run_id: Some(unrelated),
                agent_id: None,
                last_events: 20,
            }),
        )
        .await;
        assert_eq!(status.runs.len(), 1, "the query names one run");
        assert_eq!(status.runs[0].run_id, unrelated);
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < ANSWER,
        "the mailbox stalled behind add_worktree: 20 status turns took {elapsed:?}"
    );
    assert!(
        !helper.is_finished(),
        "the worktree helper was in flight for the whole measurement"
    );

    // And the actor is not merely answering *this* run: the wedged one is intact too, with no
    // worktree of its own, because nothing about it has completed.
    let status = answered(
        "status",
        handle.status(StatusQuery {
            run_id: Some(delegating),
            agent_id: None,
            last_events: 20,
        }),
    )
    .await;
    assert_eq!(status.runs.len(), 1);
    assert!(status.agents.is_empty(), "no agent was created: {status:?}");

    // Releasing git lets the helper finish, which is the last proof it was genuinely blocked in
    // there rather than never started.
    unblock_git_in(repo.path());
    tokio::time::timeout(LIMIT, helper)
        .await
        .expect("the worktree helper never finished once git was released")
        .expect("the worktree helper task did not panic");
    answered("status", handle.status(StatusQuery::default())).await;

    shutdown.cancel();
    actor.await.expect("the actor task stopped cleanly");
}

/// The other half of the same row: a `git worktree add` that never becomes possible ends as
/// `GitError::Timeout` — a value the actor can act on — rather than pinning the helper, and the
/// mailbox turn that applies it is instant.
///
/// This drives `spawn_worktree_helper` directly and reads the completion off the mailbox, because
/// until T35 lands `core::loop` the actor's `Delegate` arm answers `Unavailable` without ever
/// reaching git. The helper, the outcome and the turn that applies it are exactly the ones
/// `delegate` will use.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wedged_add_worktree_ends_as_a_timeout_rather_than_pinning_the_actor() {
    install_blocking_git();
    let state = common::temp_state_dir();
    let repo = common::temp_git_repo();
    let scratch = TempDir::new().expect("tempdir for the new worktree");

    let Wiring {
        mut core,
        mut rx,
        signals: _signals,
    } = wire(state.path(), repo.path());
    seed_run(&mut core, repo.path(), "the run whose git never recovers");

    let base_sha = git::head_sha(repo.path()).await.expect("HEAD resolves");
    block_git_in(repo.path());

    let lineage = LineageId::new_v4();
    let helper = core.spawn_worktree_helper(
        lineage,
        repo.path().to_path_buf(),
        scratch.path().join("lineage-1"),
        "acp/lineage-1".to_string(),
        base_sha,
    );
    wait_until_git_blocks(repo.path()).await;
    assert!(!helper.is_finished(), "git is inside the blocked section");

    // Nothing releases the block: the bound comes from `git.rs`, which kills the child and reports
    // the operation that timed out.
    let cmd = tokio::time::timeout(LIMIT, rx.recv())
        .await
        .expect("the helper never posted a completion")
        .expect("the mailbox is open");
    match &cmd {
        Command::WorktreeReady {
            lineage: got,
            result,
        } => {
            assert_eq!(*got, lineage, "the completion names the lineage it was for");
            match result {
                Err(GitError::Timeout { op, secs }) => {
                    assert_eq!(*op, "add_worktree");
                    assert_eq!(*secs, GIT_TIMEOUT_MS / 1_000);
                }
                other => panic!("a wedged add_worktree must time out, not {other:?}"),
            }
        }
        other => panic!("the worktree helper posted {other:?}"),
    }
    unblock_git_in(repo.path());
    tokio::time::timeout(LIMIT, helper)
        .await
        .expect("the worktree helper never returned")
        .expect("the worktree helper task did not panic");

    // Applying it is a mailbox turn like any other, and the actor answers the next command in the
    // same breath.
    let turn = Instant::now();
    core.handle_command(cmd).await;
    assert!(
        turn.elapsed() < ANSWER,
        "applying a failed worktree took {:?}",
        turn.elapsed()
    );
    let (tx, reply) = tokio::sync::oneshot::channel();
    core.handle_command(Command::Status {
        query: StatusQuery::default(),
        reply: tx,
    })
    .await;
    let status = reply.await.expect("the actor replied").expect("status");
    assert_eq!(status.runs.len(), 1);
}

// ---------------------------------------------------------------------------
// The mailbox keeps turning while a completion is outstanding
// ---------------------------------------------------------------------------

/// The design's second row: an attempt's deadline fires while a `commit_all` helper is stuck, and
/// the timeout is still recorded.
///
/// The proof is the event log's own ordering rather than a stopwatch. `gate.resolving` is appended
/// by the turn that hands the commit to a helper and `gate.resolved` by the turn that applies its
/// result, so an `attempt.cancel_requested{by:timeout}` whose `seq` falls *between* them can only
/// have been written by a mailbox turn taken while `CommitDone` was outstanding. The commit cannot
/// finish early — it is blocked on a marker only this test removes — so the window is real and no
/// margin is being relied on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attempt_timeout_is_recorded_while_a_commit_helper_is_stuck() {
    install_blocking_git();
    let state = common::temp_state_dir();
    // Two repositories: the attempt's worktree, where the supervisor's finalize runs real git, and
    // the gate's worktree, which is the one held hostage.
    let work = common::temp_git_repo();
    let integrate = common::temp_git_repo();
    let bins = common::fixture_bin_dir();

    let Wiring {
        mut core,
        rx,
        signals,
    } = wire(state.path(), work.path());
    let run = seed_run(&mut core, work.path(), "a timeout behind a stuck commit");
    let agent = seed_agent(&mut core, &run, work.path());

    // Something for the integrate commit to make, frozen exactly as the loop freezes it: an
    // approval re-checks the worktree against this hash before it commits, so a gate that names no
    // reviewed diff never reaches git at all (Codex review of T35, finding 1).
    std::fs::write(integrate.path().join("adder.ts"), "export const add = 1;\n")
        .expect("dirty the gate's worktree");
    let diff_path = state.path().join("diffs").join("integrate.patch");
    git::frozen_diff(integrate.path(), &diff_path)
        .await
        .expect("freeze the gate's worktree");
    let diff_hash = git::sha256_file(&diff_path)
        .await
        .expect("hash the frozen diff");
    let gate = gates::create_gate(
        &mut core.registry,
        &run,
        NewGate {
            kind: GateKind::Integrate,
            summary: "integrate lineage 1".to_string(),
            requested_by: Origin::ControlPlane,
            payload: GatePayload {
                worktree: Some(integrate.path().to_path_buf()),
                files: vec!["adder.ts".to_string()],
                diff_hash: Some(diff_hash),
                diff_path: Some(diff_path),
                pre_sha: Some(git::head_sha(integrate.path()).await.expect("HEAD")),
                spend_usd: 0.42,
                ..GatePayload::default()
            },
        },
    )
    .expect("create the integrate gate");

    // A worker that only a signal can end, with a deadline short enough to fire while the commit
    // is stuck and long enough to be comfortably after the gate starts resolving.
    let attempt = AttemptId::new_v4();
    let attempt_dir = state
        .path()
        .join("runs")
        .join(run.to_string())
        .join("attempts")
        .join(attempt.to_string());
    std::fs::create_dir_all(&attempt_dir).expect("create the attempt dir");
    let pre_sha = git::head_sha(work.path()).await.expect("HEAD resolves");
    let spawned = spawn_hanging_worker(&bins, state.path(), work.path(), &attempt_dir).await;
    core.supervisor.adopt(
        spawned,
        attempt_context(
            run,
            agent,
            attempt,
            attempt_dir,
            work.path(),
            &pre_sha,
            Duration::from_millis(1_200),
        ),
        &mut core.registry,
    );

    block_git_in(integrate.path());

    let handle = core.handle();
    let mut events = handle.events();
    let mailbox = core.mailbox();
    let shutdown = CancellationToken::new();
    let _forwarder = spawn_signal_forwarder(signals, mailbox.clone());
    let _ticks = spawn_tick_task(mailbox, TICK, shutdown.clone());
    let actor = tokio::spawn(run_actor(core, rx, shutdown.clone()));

    // The approval parks its reply behind the commit helper — it cannot answer until the commit
    // does, which is exactly the outstanding completion this test needs.
    let approving = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.resolve_gate(gate.gate_id, true, None, cli()).await })
    };

    wait_for_event(&mut events, "gate.resolving", |event| {
        matches!(&event.payload, EventPayload::GateResolving { gate_id, .. } if *gate_id == gate.gate_id)
    })
    .await;
    wait_until_git_blocks(integrate.path()).await;

    // The assertion: a wake-up the actor could only take by turning its mailbox.
    wait_for_event(
        &mut events,
        "attempt.cancel_requested{by:timeout}",
        |event| {
            matches!(
                &event.payload,
                EventPayload::AttemptCancelRequested {
                    attempt_id,
                    by: CancelBy::Timeout,
                    ..
                } if *attempt_id == attempt
            )
        },
    )
    .await;
    assert!(
        !approving.is_finished(),
        "the commit helper is still blocked, so its reply cannot have been sent"
    );

    // Releasing git lets the parked reply resolve — the gate was never abandoned, only parked.
    unblock_git_in(integrate.path());
    let resolution = tokio::time::timeout(LIMIT, approving)
        .await
        .expect("the approval never answered once git was released")
        .expect("the approving task did not panic")
        .expect("the gate resolved");
    assert!(
        matches!(resolution, GateResolution::Approved { .. }),
        "{resolution:?}"
    );

    // The worker is ended by the supervisor's own ladder before this test lets go of it.
    let deadline = Instant::now() + LIMIT;
    loop {
        let status = answered("status", handle.status(StatusQuery::default())).await;
        if status
            .attempts
            .iter()
            .any(|a| a.attempt_id == attempt && a.status != AttemptStatus::Running)
        {
            break;
        }
        assert!(Instant::now() < deadline, "the attempt never finalized");
        tokio::time::sleep(TICK).await;
    }

    shutdown.cancel();
    tokio::time::timeout(LIMIT, actor)
        .await
        .expect("the actor never stopped")
        .expect("the actor task stopped cleanly");

    // Read the log back from disk — the durable ordering, not the in-memory projection.
    let reg = Registry::open(state.path()).expect("reopen the registry");
    let resolving = seq_of(
        &reg,
        &run,
        "gate.resolving",
        |event| matches!(&event.payload, EventPayload::GateResolving { gate_id, .. } if *gate_id == gate.gate_id),
    );
    let timed_out = seq_of(
        &reg,
        &run,
        "attempt.cancel_requested{by:timeout}",
        |event| {
            matches!(
                &event.payload,
                EventPayload::AttemptCancelRequested { attempt_id, by: CancelBy::Timeout, .. }
                    if *attempt_id == attempt
            )
        },
    );
    let resolved = seq_of(&reg, &run, "gate.resolved", |event| {
        matches!(
            &event.payload,
            EventPayload::GateResolved { gate_id, status: GateStatus::Approved, .. }
                if *gate_id == gate.gate_id
        )
    });
    assert!(
        resolving < timed_out && timed_out < resolved,
        "the timeout must be recorded between the two halves of the commit: \
         gate.resolving={resolving}, attempt.cancel_requested={timed_out}, gate.resolved={resolved}"
    );
    assert_eq!(
        reg.attempt(&attempt).map(|a| a.status),
        Some(AttemptStatus::Timeout),
        "and the attempt is durably a timeout"
    );
}

// ---------------------------------------------------------------------------
// await_result: a door that times out and retries leaks nothing
// ---------------------------------------------------------------------------

/// The bound on `await_result` lives at the handle, so a caller that expires drops its receiver and
/// the actor is left holding a closed `Waiter`. Twenty-five expiries in a row must leave one, not
/// twenty-five, and a real resolution afterwards must still find its way out.
///
/// The mailbox is pumped inline here rather than by `run_actor`, for one reason: `waiter_count` is
/// a method on `Core`, and once `run_actor` owns the `Core` no test can ask it anything. Every
/// other part of the path is the production one — `CoreHandle::await_result` applies its own
/// timeout and drops its own receiver.
#[tokio::test]
async fn dropped_await_result_receivers_never_accumulate_in_the_waiters_map() {
    install_blocking_git();
    let state = common::temp_state_dir();
    let repo = common::temp_git_repo();

    let Wiring {
        mut core,
        mut rx,
        signals: _signals,
    } = wire(state.path(), repo.path());
    let run = seed_run(&mut core, repo.path(), "a door that keeps timing out");
    let agent = seed_agent(&mut core, &run, repo.path());
    let handle = core.handle();

    for _ in 0..25 {
        let call = handle.await_result(agent, Duration::from_millis(5));
        tokio::pin!(call);
        let out = loop {
            tokio::select! {
                out = &mut call => break out,
                cmd = rx.recv() => core.handle_command(cmd.expect("the mailbox is open")).await,
            }
        };
        assert!(
            matches!(
                out.expect("await_result answered"),
                AwaitOut::Running { .. }
            ),
            "an unfinished agent answers `running`, from the projection"
        );
        assert!(
            core.waiter_count(&agent) <= 1,
            "the waiters map grew to {} across repeated expiries",
            core.waiter_count(&agent)
        );
    }
    assert_eq!(
        core.waiter_count(&agent),
        1,
        "exactly one dead waiter survives, no matter how many callers gave up"
    );

    // A turn that may have changed state sweeps the last dead one away too.
    core.handle_command(Command::Tick).await;
    assert_eq!(core.waiter_count(&agent), 0);

    // And the real resolution afterwards finds no live waiter, answers, and does not panic.
    finish_attempt(&mut core, &run, agent);
    let call = handle.await_result(agent, LIMIT);
    tokio::pin!(call);
    let out = loop {
        tokio::select! {
            out = &mut call => break out,
            cmd = rx.recv() => core.handle_command(cmd.expect("the mailbox is open")).await,
        }
    };
    assert!(
        matches!(out.expect("await_result answered"), AwaitOut::Done { .. }),
        "a finished agent is answered from the projection, without parking"
    );
    assert_eq!(
        core.waiter_count(&agent),
        0,
        "and nothing was parked for it"
    );
}

// ---------------------------------------------------------------------------
// No door is ever left hanging
// ---------------------------------------------------------------------------

/// A caller parked inside `await_result` when the actor disappears is answered `Unavailable`, not
/// stranded until its own (possibly very long) timeout expires.
///
/// The parking is staged deterministically: a `biased` `select!` polls the call first, so the
/// `AwaitResult` command is provably in the mailbox before it is handled, and `waiter_count` then
/// confirms the reply really is parked. Dropping the core is what a panicking or exiting actor task
/// does to its `Waiter`s.
#[tokio::test]
async fn a_parked_await_result_is_answered_when_the_actor_disappears() {
    install_blocking_git();
    let state = common::temp_state_dir();
    let repo = common::temp_git_repo();

    let Wiring {
        mut core,
        mut rx,
        signals: _signals,
    } = wire(state.path(), repo.path());
    let run = seed_run(&mut core, repo.path(), "a parked caller");
    let agent = seed_agent(&mut core, &run, repo.path());
    let handle = core.handle();

    // A timeout no test would ever wait out: if this call falls through to it rather than being
    // answered, the bound below fails.
    let call = handle.await_result(agent, Duration::from_secs(3_600));
    tokio::pin!(call);
    tokio::select! {
        biased;
        _ = &mut call => panic!("await_result answered before the actor had seen it"),
        cmd = rx.recv() => core.handle_command(cmd.expect("the mailbox is open")).await,
    }
    assert_eq!(
        core.waiter_count(&agent),
        1,
        "the reply is parked, which is what makes the next assertion mean anything"
    );

    drop(core);
    drop(rx);

    let out = tokio::time::timeout(ANSWER, call)
        .await
        .expect("a parked await_result was stranded when the actor went away");
    assert!(
        matches!(out, Err(CoreError::Unavailable)),
        "a parked caller hears the actor is gone: {out:?}"
    );
}

/// The design's "if the actor task ever panics, every door answers `core_unavailable` rather than
/// serving stale state" — every `CoreHandle` method, each with an answer required.
///
/// `run_actor` has no reachable panic to provoke from a door (every mailbox turn is total, and T33
/// left no `todo!()` behind), so the panic is staged in a stand-in loop with the same shape: one
/// `recv`, one `handle_command`, and a task that dies without answering. What matters is what it
/// leaves behind, which is identical either way — a dropped `Receiver` — and that is what every
/// assertion below reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_door_answers_unavailable_after_the_actor_task_panics() {
    install_blocking_git();
    let state = common::temp_state_dir();
    let repo = common::temp_git_repo();

    let Wiring {
        mut core,
        mut rx,
        signals: _signals,
    } = wire(state.path(), repo.path());
    let run = seed_run(&mut core, repo.path(), "an actor that dies mid-turn");
    let agent = seed_agent(&mut core, &run, repo.path());
    let handle = core.handle();
    let mailbox = core.mailbox();

    let actor = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            assert!(
                !matches!(cmd, Command::Tick),
                "the actor task died mid-turn (staged)"
            );
            core.handle_command(cmd).await;
        }
    });

    // It served at least one command first, so a green run cannot mean "the core never started".
    let status = answered("status", handle.status(StatusQuery::default())).await;
    assert_eq!(status.runs.len(), 1);

    mailbox
        .send(Command::Tick)
        .await
        .expect("the actor is still listening");
    let died = tokio::time::timeout(LIMIT, actor)
        .await
        .expect("the actor never stopped")
        .expect_err("the actor task panicked");
    assert!(died.is_panic());
    drop(mailbox);

    assert!(handle.is_closed(), "the door knows the actor is gone");
    unavailable("status", handle.status(StatusQuery::default())).await;
    unavailable(
        "delegate",
        handle.delegate(DelegateRequest {
            run_id: Some(run),
            role: RoleName::Builder,
            task: task("nobody is home", "the actor is gone"),
            model: None,
            session: SessionSpec::Fresh,
            base_ref: None,
            worktree: None,
            steps: None,
            caller_run_id: None,
        }),
    )
    .await;
    unavailable(
        "send_message",
        handle.send_message(agent, "carry on".to_string()),
    )
    .await;
    unavailable(
        "await_result",
        handle.await_result(agent, Duration::from_secs(3_600)),
    )
    .await;
    unavailable("cancel", handle.cancel(agent)).await;
    unavailable(
        "request_gate",
        handle.request_gate(GateRequest {
            run_id: run,
            gate: NewGate {
                kind: GateKind::Escalate,
                summary: "nobody is home".to_string(),
                requested_by: Origin::ControlPlane,
                payload: GatePayload::default(),
            },
        }),
    )
    .await;
    unavailable(
        "resolve_gate",
        handle.resolve_gate(GateId::new_v4(), false, None, cli()),
    )
    .await;
}

/// A door held by a caller that never learned the actor stopped is still a closed door: the same
/// battery, after the *production* stop path rather than a panic.
#[tokio::test]
async fn every_door_answers_unavailable_after_a_clean_stop() {
    install_blocking_git();
    let state = common::temp_state_dir();
    let repo = common::temp_git_repo();

    let Wiring {
        mut core,
        rx,
        signals: _signals,
    } = wire(state.path(), repo.path());
    let run = seed_run(&mut core, repo.path(), "a clean stop");
    let agent = seed_agent(&mut core, &run, repo.path());
    let handle = core.handle();
    let shutdown = CancellationToken::new();
    let actor = tokio::spawn(run_actor(core, rx, shutdown.clone()));

    answered("status", handle.status(StatusQuery::default())).await;
    shutdown.cancel();
    tokio::time::timeout(LIMIT, actor)
        .await
        .expect("the actor never stopped")
        .expect("the actor task stopped cleanly");

    assert!(handle.is_closed());
    unavailable("status", handle.status(StatusQuery::default())).await;
    unavailable(
        "await_result",
        handle.await_result(agent, Duration::from_secs(3_600)),
    )
    .await;
    unavailable("cancel", handle.cancel(agent)).await;
}

// ---------------------------------------------------------------------------
// The loop's own helper hand-offs (T35, Codex review findings 2 and 3)
// ---------------------------------------------------------------------------

/// The lineage `agent` belongs to, given a worktree — `worktree.created` is what mints the
/// `LineageState` the loop's 17c looks the retry up by.
fn seed_lineage(core: &mut Core, run: &RunId, agent: AgentId, worktree: &Path) -> LineageId {
    let lineage = core
        .registry
        .agent(&agent)
        .expect("the agent was seeded")
        .lineage_id
        .expect("a seeded builder has a lineage");
    core.registry
        .append(
            run,
            EventPayload::WorktreeCreated {
                agent_id: agent,
                lineage_id: lineage,
                path: worktree.to_path_buf(),
                branch: "acp/lineage-1".to_string(),
                base_sha: "0".repeat(40),
            },
        )
        .expect("worktree.created");
    lineage
}

/// 17c reads the inherited worktree with `git status --porcelain`, and it reads it **off the
/// actor**: the branch appends its durable events, hands the read to a helper and returns.
///
/// The regression this pins is a mailbox turn that awaited git. Before the fix a wedged worktree
/// held the actor for the whole `GIT_OP_TIMEOUT`, so every door of every run — `get_status`,
/// `cancel`, a gate resolution — waited on one run's broken directory (Codex review of T35,
/// finding 3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wedged_worktree_read_does_not_pin_the_actor_during_a_retry() {
    install_blocking_git();
    let state = common::temp_state_dir();
    let repo = common::temp_git_repo();

    let Wiring {
        mut core,
        mut rx,
        signals: _signals,
    } = wire(state.path(), repo.path());
    let run = seed_run(&mut core, repo.path(), "a retry against a wedged worktree");
    let agent = seed_agent(&mut core, &run, repo.path());
    let lineage = seed_lineage(&mut core, &run, agent, repo.path());

    block_git_in(repo.path());

    // 17c's own call. It must not wait for git.
    let started = Instant::now();
    let result = core.retry_fresh(&lineage).await;
    let elapsed = started.elapsed();
    assert!(
        matches!(result, SendResult::Ok { .. }),
        "the retry was refused: {result:?}"
    );
    assert!(
        elapsed < ANSWER,
        "retry_fresh waited {elapsed:?} on a wedged worktree"
    );

    // The read is genuinely in flight and genuinely stuck…
    wait_until_git_blocks(repo.path()).await;

    // …and the actor answers anyway, over and over.
    for _ in 0..20 {
        let (tx, reply) = tokio::sync::oneshot::channel();
        let turn = Instant::now();
        core.handle_command(Command::Status {
            query: StatusQuery::default(),
            reply: tx,
        })
        .await;
        assert!(
            turn.elapsed() < ANSWER,
            "a status turn took {:?} behind a wedged worktree read",
            turn.elapsed()
        );
        reply.await.expect("status replied").expect("status ok");
    }

    // The branch's durable half is already on disk: the dead handle is closed and its replacement
    // is announced, both **before** the marker the loop appends.
    let closed = core.registry.agent(&agent).expect("the old agent").status;
    assert_eq!(closed, AgentStatus::Closed);
    let fresh = core
        .registry
        .run(&run)
        .expect("the run")
        .lineages
        .iter()
        .find(|l| l.lineage_id == lineage)
        .expect("the lineage")
        .agent_ids
        .len();
    assert_eq!(
        fresh, 2,
        "the retry's agent is announced before its worktree is read"
    );

    unblock_git_in(repo.path());
    let cmd = tokio::time::timeout(LIMIT, rx.recv())
        .await
        .expect("the porcelain helper never posted a completion")
        .expect("the mailbox is open");
    assert!(
        matches!(&cmd, Command::RetryFreshReady { agent: got, porcelain } if *got != agent && porcelain.is_ok()),
        "the helper posted {cmd:?}"
    );
}

/// Restart rule (a): an `agent.created` the log never got an `attempt.started` for is reissued.
///
/// This is the gap `loop.dispatched` opens. The marker is appended as the branch's last event and
/// stops it from ever running again — which is right for its durable decisions and wrong for the
/// spawn helper it hands off to, because a daemon that dies in between takes `pending_spawn` with
/// it. Without a reconciler the run sits for ever with an agent that never started (Codex review of
/// T35, finding 2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_that_never_started_is_reissued_once_on_restart() {
    install_fake_clis();
    let state = common::temp_state_dir();
    let repo = common::temp_git_repo();

    // A log that ends exactly where the crash would have: the agent is announced, nothing started.
    let agent = {
        let Wiring { mut core, .. } = wire(state.path(), repo.path());
        let run = seed_run(&mut core, repo.path(), "an agent that never started");
        let agent = seed_agent(&mut core, &run, repo.path());
        seed_lineage(&mut core, &run, agent, repo.path());
        agent
    };

    // The restart. `Core::new` reconciles, so the spawn is already in flight.
    let Wiring {
        mut core,
        mut rx,
        signals: _signals,
    } = wire(state.path(), repo.path());
    let cmd = tokio::time::timeout(LIMIT, rx.recv())
        .await
        .expect("the reissued spawn never reported")
        .expect("the mailbox is open");
    let attempt = match &cmd {
        Command::SpawnReady { attempt, result } => {
            assert!(result.is_ok(), "the reissued spawn failed: {result:?}");
            *attempt
        }
        other => panic!("the reconciler posted {other:?}"),
    };
    core.handle_command(cmd).await;

    let started = core
        .registry
        .agent(&agent)
        .expect("the agent")
        .attempt_ids
        .clone();
    assert_eq!(started, vec![attempt], "exactly one attempt was started");

    // Reconciling again changes nothing — the guard is the log, and the log now says it started.
    core.reconcile_intents();
    assert_quiet(&mut rx, "a completed intent must not be reissued").await;
    assert_eq!(
        core.registry.agent(&agent).expect("the agent").attempt_ids,
        started,
        "and no second attempt was started"
    );
    end_attempt(&mut core, agent).await;

    // …and neither does a second restart over the completed log.
    drop(core);
    let Wiring { core, mut rx, .. } = wire(state.path(), repo.path());
    assert_quiet(&mut rx, "a restart over a complete log issues nothing").await;
    drop(core);
}

/// Restart rule (b): a run whose 17d closed a lineage but never got its new worktree.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replacement_that_never_got_its_worktree_is_reissued_once_on_restart() {
    install_fake_clis();
    let state = common::temp_state_dir();
    let repo = common::temp_git_repo();

    let run = {
        let Wiring { mut core, .. } = wire(state.path(), repo.path());
        let run = seed_run(&mut core, repo.path(), "a replacement that never landed");
        let agent = seed_agent(&mut core, &run, repo.path());
        let lineage = seed_lineage(&mut core, &run, agent, repo.path());
        let attempt = finish_attempt(&mut core, &run, agent);

        // Everything 17d writes, ending with the marker that stops it being re-driven.
        for payload in [
            EventPayload::LineageClosed {
                lineage_id: lineage,
                reason: "out of strikes after 2".to_string(),
            },
            EventPayload::WorktreeRetired {
                path: repo.path().to_path_buf(),
                reason: "the lineage was closed after 2 strikes".to_string(),
                resumable: False,
            },
            EventPayload::AgentStatusChanged {
                agent_id: agent,
                status: AgentStatus::Closed,
                reason: Some("the lineage is out of strikes".to_string()),
            },
            EventPayload::LoopStateChanged {
                state: LoopState::Replacing,
                builder_agent_id: Some(agent),
                attempt_no: 2,
                strikes: 2,
            },
            EventPayload::LoopDispatched {
                attempt_id: attempt,
                branch: LoopBranch::Replace,
            },
        ] {
            core.registry.append(&run, payload).expect("append");
        }
        run
    };

    let Wiring {
        mut core,
        mut rx,
        signals: _signals,
    } = wire(state.path(), repo.path());

    // The worktree helper 17d never got to report.
    let cmd = tokio::time::timeout(LIMIT, rx.recv())
        .await
        .expect("the reissued worktree never reported")
        .expect("the mailbox is open");
    assert!(
        matches!(&cmd, Command::WorktreeReady { result, .. } if result.is_ok()),
        "the reconciler posted {cmd:?}"
    );
    core.handle_command(cmd).await;

    let lineages = core.registry.run(&run).expect("the run").lineages.len();
    assert_eq!(
        lineages, 2,
        "a second lineage was created for the replacement"
    );

    // Its spawn follows, and once it is adopted both rules are closed.
    let cmd = tokio::time::timeout(LIMIT, rx.recv())
        .await
        .expect("the replacement's spawn never reported")
        .expect("the mailbox is open");
    assert!(matches!(&cmd, Command::SpawnReady { .. }), "{cmd:?}");
    core.handle_command(cmd).await;

    let replacement = core
        .registry
        .run(&run)
        .expect("the run")
        .agent_ids
        .last()
        .copied()
        .expect("the replacement agent");
    end_attempt(&mut core, replacement).await;
    drop(core);

    let Wiring { core, mut rx, .. } = wire(state.path(), repo.path());
    assert_quiet(&mut rx, "a restart over a complete log issues nothing").await;
    drop(core);
}

/// B1 (T64 review F8, fixed in T65): a restart-reissued 17d replacement after a **verify-fail**
/// strike-out must inherit the verifier's failure lines — `abandoned_context` picks the newest of
/// {review verdict, verify FAIL report}, so a stale earlier verdict must NOT win, and an empty
/// `failures` list falls back to the report's summary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_reissued_replacement_inherits_the_verify_failure_text() {
    install_fake_clis();
    // (verdict_first, failures, expected, absent): the selection is NEWEST-of-the-two, both
    // directions — a "verify always wins" mutation must fail the third case.
    for (verdict_first, failures, expected, absent) in [
        (
            true,
            vec!["tests::adder_returns_sum".to_string()],
            "tests::adder_returns_sum",
            "a stale review finding about naming",
        ),
        // Schema-legal `fail` with no failure lines: the summary is the fallback finding.
        (true, Vec::new(), "the build broke before any test ran", ""),
        // The review verdict is the NEWER event here, so it must win over the older verify fail.
        (
            false,
            vec!["a stale verify line".to_string()],
            "a stale review finding about naming",
            "a stale verify line",
        ),
    ] {
        let state = common::temp_state_dir();
        let repo = common::temp_git_repo();

        let run = {
            let Wiring { mut core, .. } = wire(state.path(), repo.path());
            let run = seed_run(&mut core, repo.path(), "verify strike-out reissue");
            let agent = seed_agent(&mut core, &run, repo.path());
            let lineage = seed_lineage(&mut core, &run, agent, repo.path());
            let attempt = finish_attempt(&mut core, &run, agent);

            // The two candidate closers, in the order this case dictates — newest last.
            let verdict = EventPayload::ReviewVerdict {
                attempt_id: AttemptId::new_v4(),
                builder_attempt_id: attempt,
                verdict: Verdict::Fail,
                findings: vec![ReviewFinding {
                    severity: Severity::Blocking,
                    file: None,
                    line: None,
                    problem: "a stale review finding about naming".to_string(),
                    fix: None,
                }],
                diff_hash: None,
            };
            let report = EventPayload::VerifyReport {
                attempt_id: AttemptId::new_v4(),
                builder_attempt_id: attempt,
                status: VerifyStatus::Fail,
                summary: "the build broke before any test ran".to_string(),
                failures: failures.clone(),
            };
            let (first, second) = if verdict_first {
                (verdict, report)
            } else {
                (report, verdict)
            };
            for payload in [
                first,
                second,
                EventPayload::LineageClosed {
                    lineage_id: lineage,
                    reason: "out of strikes after 2".to_string(),
                },
                EventPayload::WorktreeRetired {
                    path: repo.path().to_path_buf(),
                    reason: "the lineage was closed after 2 strikes".to_string(),
                    resumable: False,
                },
                EventPayload::AgentStatusChanged {
                    agent_id: agent,
                    status: AgentStatus::Closed,
                    reason: Some("the lineage is out of strikes".to_string()),
                },
                EventPayload::LoopStateChanged {
                    state: LoopState::Replacing,
                    builder_agent_id: Some(agent),
                    attempt_no: 2,
                    strikes: 2,
                },
                EventPayload::LoopDispatched {
                    attempt_id: attempt,
                    branch: LoopBranch::Replace,
                },
            ] {
                core.registry.append(&run, payload).expect("append");
            }
            run
        };

        let Wiring {
            mut core,
            mut rx,
            signals: _signals,
        } = wire(state.path(), repo.path());

        let cmd = tokio::time::timeout(LIMIT, rx.recv())
            .await
            .expect("the reissued worktree never reported")
            .expect("the mailbox is open");
        assert!(
            matches!(&cmd, Command::WorktreeReady { result, .. } if result.is_ok()),
            "the reconciler posted {cmd:?}"
        );
        core.handle_command(cmd).await;

        let cmd = tokio::time::timeout(LIMIT, rx.recv())
            .await
            .expect("the replacement's spawn never reported")
            .expect("the mailbox is open");
        assert!(matches!(&cmd, Command::SpawnReady { .. }), "{cmd:?}");
        core.handle_command(cmd).await;

        let replacement = core
            .registry
            .run(&run)
            .expect("the run")
            .agent_ids
            .last()
            .copied()
            .expect("the replacement agent");
        let attempt_dir = core
            .registry
            .agent(&replacement)
            .and_then(|a| a.attempt_ids.first().copied())
            .and_then(|attempt| core.registry.attempt(&attempt))
            .map(|a| a.dir.clone())
            .expect("the replacement attempt dir");
        let prompt = std::fs::read_to_string(attempt_dir.join("prompt.txt"))
            .expect("the replacement prompt was rendered");
        assert!(
            prompt.contains(expected),
            "the replacement inherits the verify failure text ({expected:?}): {prompt}"
        );
        if !absent.is_empty() {
            assert!(
                !prompt.contains(absent),
                "the stale earlier verdict must not win over the newer verify report"
            );
        }

        end_attempt(&mut core, replacement).await;
        drop(core);
    }
}

/// Nothing reaches the mailbox for [`QUIET`]. The wait is the assertion: a helper posts from a
/// spawned task, so a bare `try_recv` would pass whether or not one was started.
async fn assert_quiet(rx: &mut mpsc::Receiver<Command>, why: &str) {
    if let Ok(Some(cmd)) = tokio::time::timeout(QUIET, rx.recv()).await {
        panic!("{why}, but the mailbox got {cmd:?}");
    }
}

/// Ends whatever this test started, so no fake worker outlives the test that spawned it.
async fn end_attempt(core: &mut Core, agent: AgentId) {
    let (tx, reply) = tokio::sync::oneshot::channel();
    core.handle_command(Command::Cancel { agent, reply: tx })
        .await;
    let _ = reply.await;
}

/// One attempt of `agent` that started, learned a session, and then failed — the log a 17b strike
/// is written over.
fn fail_attempt_with_session(
    core: &mut Core,
    run: &RunId,
    agent: AgentId,
    session: &str,
    error: AttemptError,
) -> AttemptId {
    let attempt = AttemptId::new_v4();
    for payload in [
        EventPayload::AttemptStarted {
            attempt_id: attempt,
            agent_id: agent,
            attempt_kind: AttemptKind::Fresh,
            dir: core.state_dir.join("attempt"),
            argv: vec!["claude".to_string()],
            cwd: core.repo_root.clone(),
            pid: 4242,
            pgid: 4242,
            start_time: "Sat Aug 23 00:00:00 2026".to_string(),
            pre_sha: "0".repeat(40),
            timeout_sec: 900,
            spawn_budget_usd: 2.0,
        },
        EventPayload::AgentSession {
            agent_id: agent,
            attempt_id: attempt,
            session_id: session.to_string(),
            src_line: 1,
        },
        EventPayload::AttemptFinished {
            attempt_id: attempt,
            status: AttemptStatus::Failed,
            exit_code: Some(1),
            signal: None,
            post_sha: None,
            duration_ms: 10,
            error: Some(error),
        },
    ] {
        core.registry.append(run, payload).expect("append");
    }
    attempt
}

/// Restart rule (c): a 17b repair the log shows was decided and never sent.
///
/// The third shape of the marker gap. `lineage.strike` and `loop.state{repairing}` are durable and
/// `loop.dispatched{17b}` says the branch is finished — but the resume itself was a helper task,
/// and a daemon that died before it reported leaves a builder that will never be told to repair.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_that_was_never_sent_is_reissued_once_on_restart() {
    install_fake_clis();
    let state = common::temp_state_dir();
    let repo = common::temp_git_repo();

    // A log that ends exactly at the marker: struck, repairing, nothing resumed.
    let (run, agent, failed) = {
        let Wiring { mut core, .. } = wire(state.path(), repo.path());
        let run = seed_run(&mut core, repo.path(), "a repair that was never sent");
        let agent = seed_agent(&mut core, &run, repo.path());
        let lineage = seed_lineage(&mut core, &run, agent, repo.path());
        let failed = fail_attempt_with_session(
            &mut core,
            &run,
            agent,
            "session-17b",
            AttemptError {
                code: ErrorCode::SchemaInvalid,
                message: "the final message was not one JSON document".to_string(),
            },
        );
        for payload in [
            EventPayload::LineageStrike {
                lineage_id: lineage,
                agent_id: agent,
                reason: "schema_invalid: the final message was not one JSON document".to_string(),
                strikes: 1,
            },
            EventPayload::LoopStateChanged {
                state: LoopState::Repairing,
                builder_agent_id: Some(agent),
                attempt_no: 1,
                strikes: 1,
            },
            EventPayload::LoopDispatched {
                attempt_id: failed,
                branch: LoopBranch::Resume,
            },
        ] {
            core.registry.append(&run, payload).expect("append");
        }
        (run, agent, failed)
    };

    let Wiring {
        mut core,
        mut rx,
        signals: _signals,
    } = wire(state.path(), repo.path());

    let cmd = tokio::time::timeout(LIMIT, rx.recv())
        .await
        .expect("the reissued repair never reported")
        .expect("the mailbox is open");
    let resumed = match &cmd {
        Command::SpawnReady { attempt, result } => {
            assert!(
                result.is_ok(),
                "the reissued repair failed to spawn: {result:?}"
            );
            *attempt
        }
        other => panic!("the reconciler posted {other:?}"),
    };
    core.handle_command(cmd).await;

    // It is a **resume** of the session the log recorded, not a fresh session.
    let attempts = core
        .registry
        .agent(&agent)
        .expect("the agent")
        .attempt_ids
        .clone();
    assert_eq!(attempts, vec![failed, resumed], "exactly one repair turn");
    assert_eq!(
        core.registry
            .attempt(&resumed)
            .expect("the resumed attempt")
            .kind,
        AttemptKind::Resume
    );

    // …carrying the prompt 17b would have sent: the failure, quoted as data (S3).
    let prompt = std::fs::read_to_string(
        state
            .path()
            .join("runs")
            .join(run.as_uuid().simple().to_string())
            .join("attempts")
            .join(resumed.as_uuid().simple().to_string())
            .join("prompt.txt"),
    )
    .expect("the resumed attempt's prompt");
    assert!(
        prompt.contains("<<<ADVISORY DATA"),
        "the failure text must be advisory-wrapped: {prompt}"
    );
    assert!(
        prompt.contains("the final message was not one JSON document"),
        "the repair prompt must quote what went wrong: {prompt}"
    );

    core.reconcile_intents();
    assert_quiet(&mut rx, "a repair that was sent must not be sent twice").await;

    // …and it stays sent once that turn is over. The run is still `repairing` and the marker is
    // still the newest one, so what makes nothing owed here is the window itself: the resume's
    // `attempt.started` sits after the marker.
    end_attempt(&mut core, agent).await;
    core.registry
        .append(
            &run,
            EventPayload::AttemptFinished {
                attempt_id: resumed,
                status: AttemptStatus::Cancelled,
                exit_code: None,
                signal: Some("SIGTERM".to_string()),
                post_sha: None,
                duration_ms: 10,
                error: None,
            },
        )
        .expect("attempt.finished");
    core.reconcile_intents();
    assert_quiet(&mut rx, "a repair whose turn has ended must not be re-sent").await;

    drop(core);
    let Wiring { core, mut rx, .. } = wire(state.path(), repo.path());
    assert_quiet(&mut rx, "a restart over a complete log issues nothing").await;
    drop(core);
}

/// A helper's answer that arrives after the run has moved on starts nothing.
///
/// The worktree read 17c hands off is bounded by `GIT_OP_TIMEOUT`, which is thirty seconds — long
/// enough for the run to be cancelled, blocked by an unrelated failure, or integrated before the
/// answer comes back. Spawning into that run would spend money on work nobody will look at and
/// contradict the projection a human is already reading (Codex review of T35, round 2, finding 3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worktree_status_that_arrives_after_the_run_was_blocked_starts_nothing() {
    install_fake_clis();
    let state = common::temp_state_dir();
    let repo = common::temp_git_repo();

    let Wiring {
        mut core,
        mut rx,
        signals: _signals,
    } = wire(state.path(), repo.path());
    let run = seed_run(&mut core, repo.path(), "a status that came back too late");
    let agent = seed_agent(&mut core, &run, repo.path());
    let lineage = seed_lineage(&mut core, &run, agent, repo.path());

    // 17c runs: the old handle is closed, the replacement is announced, the read is in flight.
    assert!(matches!(
        core.retry_fresh(&lineage).await,
        SendResult::Ok { .. }
    ));
    let cmd = tokio::time::timeout(LIMIT, rx.recv())
        .await
        .expect("the porcelain helper never posted")
        .expect("the mailbox is open");
    let Command::RetryFreshReady {
        agent: retried,
        porcelain,
    } = cmd
    else {
        panic!("the helper posted {cmd:?}");
    };
    assert!(porcelain.is_ok());

    // …and while it was in flight, the run stopped.
    core.registry
        .append(
            &run,
            EventPayload::RunStatus_ {
                status: RunStatus::Blocked,
                reason: Some("a human stopped this run".to_string()),
            },
        )
        .expect("run.status");

    core.on_retry_fresh_ready(&retried, porcelain);

    assert!(
        core.registry
            .agent(&retried)
            .expect("the retry's agent")
            .attempt_ids
            .is_empty(),
        "no attempt may be started into a blocked run"
    );
    assert_quiet(&mut rx, "a stale worktree status starts nothing").await;

    // The pending entry is gone either way, so nothing is left holding the agent's slot: a later
    // reconciler is free to decide about it once the run is running again.
    core.reconcile_intents();
    assert_quiet(&mut rx, "and a reconciler leaves a blocked run alone too").await;
}
