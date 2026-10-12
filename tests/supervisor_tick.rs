//! T25: the attempt lifecycle — `Supervisor::{adopt, tick, cancel, reattach, signal_group}` against
//! **real spawned processes** (`reports/03-design.md` § Test Strategy, row `core/supervisor.rs`,
//! lifecycle half).
//!
//! Nothing here is mocked except the clock's patience: every test spawns the fake `claude` through
//! the same chokepoint production uses (`assert_safe_argv` → `spawn_detached`), tails a file the
//! child is really appending to, and — where the design says "real git" — asserts against
//! `git rev-parse` in a temp worktree rather than against a fake. The tick is injected at 25 ms
//! (design: "`tick_ms` is injectable; tests use 25 ms").
//!
//! Two facts that are easy to get wrong and are pinned by construction here:
//!
//! * `$ACP_FAKE_RECORD` must point **outside** `$ACP_STATE_DIR`. `assert_safe_argv`'s check 5
//!   rejects any environment value containing the state dir's path — a worker that learned it could
//!   find the socket that approves its own gate — so the record file lives in the worktree.
//! * The fake's `acpEnvKeys` reports *every* `ACP_*` key the child could see. The env-scrub test
//!   asserts that set is exactly the `ACP_FAKE_*` pass-through, which is what proves
//!   `spawn_detached`'s `.env_clear()` kept this test process's own `ACP_*` variables out.

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_control_plane::core::registry::Registry;
use agent_control_plane::core::supervisor::{
    assert_safe_argv, spawn_detached, ArgvCtx, AttemptContext, ProcessProbe, PsProbe,
    SignalOutcome, SpawnedProc, Supervisor, SupervisorSignal,
};
use agent_control_plane::core::types::{
    AgentId, Attempt, AttemptId, AttemptKind, AttemptStatus, CancelBy, ErrorCode, Event,
    EventPayload, MessageRole, ProviderName, RoleName, RoleSpec, RunId, SandboxMode, SchemaName,
    Task, ViolationKind,
};
use agent_control_plane::core::{
    channel, run_actor, spawn_signal_forwarder, spawn_tick_task, Command, Core, StatusOut,
    StatusQuery,
};
use agent_control_plane::providers::claude::ClaudeAdapter;
use agent_control_plane::providers::{ProviderAdapter, SandboxSpec, SpawnPlan, SpawnRequest};
use agent_control_plane::roles::loader::load_roles;
use agent_control_plane::workspace::git;
use globset::{Glob, GlobSet, GlobSetBuilder};
use nix::sys::signal::Signal;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

const MODEL: &str = "claude-sonnet-4-5";

/// The design's injected tick for tests.
const TICK: Duration = Duration::from_millis(25);

/// How long any one attempt may take before the test calls it a hang. Generous on purpose: it is a
/// failure detector, never a timing assertion — the assertions that care about time measure it.
const LIMIT: Duration = Duration::from_secs(30);

/// A start time no live process can be wearing — the recycled-pid case, forced.
const FORGED_START_TIME: &str = "Thu Jan  1 00:00:00 1970";

/// The run's denylist, as `roles.json` ships it (the two globs these tests exercise).
const DENYLIST: [&str; 2] = ["**/*.xcconfig", "**/*.entitlements"];

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// One attempt's worth of the world: a real `$ACP_STATE_DIR`, a real git worktree, the fake CLIs on
/// a real `PATH`, and the ids the event log is keyed by.
struct Fixture {
    state_dir: TempDir,
    repo: TempDir,
    bins: TempDir,
    run: RunId,
    agent: AgentId,
    attempt: AttemptId,
    attempt_dir: PathBuf,
    role: RoleSpec,
    schema: Arc<Value>,
    denylist: Arc<GlobSet>,
}

impl Fixture {
    fn new() -> Self {
        let state_dir = common::temp_state_dir();
        let run = RunId::new_v4();
        let attempt = AttemptId::new_v4();
        // The design's layout: `$ACP_STATE_DIR/runs/<runId>/attempts/<attemptId>`. The supervisor
        // derives `<runDir>/diffs/<attemptId>.patch` from it, so the shape is load-bearing.
        let attempt_dir = state_dir
            .path()
            .join("runs")
            .join(run.to_string())
            .join("attempts")
            .join(attempt.to_string());
        std::fs::create_dir_all(&attempt_dir).expect("create the attempt dir");
        Self {
            state_dir,
            repo: common::temp_git_repo(),
            bins: common::fixture_bin_dir(),
            run,
            agent: AgentId::new_v4(),
            attempt,
            attempt_dir,
            role: builder_role(),
            schema: Arc::new(checked_in_schema("build-result.json")),
            denylist: Arc::new(denylist()),
        }
    }

    fn worktree(&self) -> &Path {
        self.repo.path()
    }

    fn registry(&self) -> Registry {
        Registry::open(self.state_dir.path()).expect("open the registry")
    }

    /// A second attempt of the same run: a fresh id and its own directory under the same run dir.
    fn sibling_attempt(&self) -> (AttemptId, PathBuf) {
        let attempt = AttemptId::new_v4();
        let dir = self
            .state_dir
            .path()
            .join("runs")
            .join(self.run.to_string())
            .join("attempts")
            .join(attempt.to_string());
        std::fs::create_dir_all(&dir).expect("create the sibling attempt dir");
        (attempt, dir)
    }

    /// The plan the real adapter builds, pointed at the fake CLI and configured with the scenario.
    fn plan_in(&self, env: &[(&str, &str)], attempt_dir: &Path) -> SpawnPlan {
        let prompt = "Add src/adder.ts exporting add(a, b).".to_string();
        let role_prompt = "You are a builder worker. Never commit; the control plane does.\n";
        let req = SpawnRequest {
            role: &self.role,
            model: MODEL,
            prompt: &prompt,
            role_prompt,
            cwd: self.worktree(),
            attempt_dir,
            state_dir: self.state_dir.path(),
            lead_run_id: None,
            schema: ("build-result", &self.schema),
            max_turns: 12,
            spawn_budget_usd: 2.0,
            sandbox: Some(SandboxSpec {
                worktree: self.worktree(),
            }),
            session_id: None,
            effort: None,
        };
        let mut plan = ClaudeAdapter.build_fresh(&req);
        plan.env
            .insert("PATH".to_string(), common::prepend_path(self.bins.path()));
        for (key, value) in env {
            plan.env.insert((*key).to_string(), (*value).to_string());
        }
        plan
    }

    /// Runs the scenario through the whole production path: check the argv, then spawn detached.
    async fn spawn(&self, scenario: &str, env: &[(&str, &str)]) -> SpawnedProc {
        self.spawn_in(scenario, env, &self.attempt_dir).await
    }

    /// The same, into an attempt directory other than the fixture's own.
    async fn spawn_in(
        &self,
        scenario: &str,
        env: &[(&str, &str)],
        attempt_dir: &Path,
    ) -> SpawnedProc {
        let mut full = vec![("ACP_FAKE_SCENARIO", scenario)];
        full.extend_from_slice(env);
        let plan = self.plan_in(&full, attempt_dir);
        let prompt_index = ClaudeAdapter.prompt_index(&plan);
        let checked = assert_safe_argv(
            plan,
            &ArgvCtx {
                role: agent_control_plane::core::types::RoleName::Builder,
                lead_run_id: None,
                worktree: self.worktree(),
                provider: ProviderName::Claude,
                sandboxed: true,
                state_dir: self.state_dir.path(),
                prompt_index,
            },
        )
        .expect("the adapter's own plan passes the chokepoint");
        spawn_detached(checked, attempt_dir.to_path_buf())
            .await
            .expect("spawn the fake provider")
    }

    fn ctx(&self, timeout: Duration, pre_sha: &str) -> AttemptContext {
        AttemptContext {
            run: self.run,
            agent: self.agent,
            attempt: self.attempt,
            dir: self.attempt_dir.clone(),
            adapter: Arc::new(ClaudeAdapter),
            timeout,
            pre_sha: pre_sha.to_string(),
            kind: AttemptKind::Fresh,
            role: RoleName::Builder,
            worktree: self.worktree().to_path_buf(),
            worktree_lock: Arc::new(tokio::sync::Mutex::new(())),
            writes: true,
            schema: Arc::clone(&self.schema),
            schema_name: SchemaName::BuildResult,
            denylist: Arc::clone(&self.denylist),
            spawn_budget_usd: 2.0,
            rate: None,
            session_id: None,
        }
    }

    /// The same context with the session the log already recorded — what a restart hands
    /// `reattach`, where it comes from `AgentHandle.session_id`.
    fn resumed_ctx(
        &self,
        timeout: Duration,
        pre_sha: &str,
        session_id: Option<String>,
    ) -> AttemptContext {
        AttemptContext {
            session_id,
            ..self.ctx(timeout, pre_sha)
        }
    }

    /// `<runDir>/diffs/<attemptId>.patch` — where the supervisor freezes the diff.
    fn diff_path(&self) -> PathBuf {
        self.state_dir
            .path()
            .join("runs")
            .join(self.run.to_string())
            .join("diffs")
            .join(format!("{}.patch", self.attempt))
    }
}

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
fn checked_in_schema(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("schemas")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&text).expect("a checked-in schema is valid JSON")
}

fn denylist() -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    for glob in DENYLIST {
        builder.add(Glob::new(glob).expect("a shipped denylist glob compiles"));
    }
    builder.build().expect("the denylist compiles")
}

/// The supervisor's signal channel, plus the pump that applies what arrives on it.
///
/// Finalizing an exited attempt is no longer part of `tick`: the git and filesystem half runs in a
/// helper task and comes back as `SupervisorSignal::FinalizeReady`, which the production actor
/// applies in its `Command::FinalizeReady` turn (Codex review of T33, finding 1). [`Signals::pump`]
/// **is** that turn — prepare in the helper, apply here, in sequence — so every test below still
/// asserts against a whole event log.
///
/// The wake-up signals are not swallowed: they are kept in `seen` so the ladder test can still
/// prove the actor is woken rather than made to poll.
struct Signals {
    rx: mpsc::Receiver<SupervisorSignal>,
    seen: Vec<SupervisorSignal>,
}

impl Signals {
    /// Applies every finalize report that has arrived, and remembers the wake-ups.
    ///
    /// An append failure is deliberately not asserted away here: `apply_finalize` parks the report
    /// and the next `tick` retries it, which is the behaviour
    /// `a_finalize_whose_append_fails_is_retried_and_lands_exactly_once` drives on purpose.
    fn pump(&mut self, sup: &mut Supervisor, reg: &mut Registry) {
        while let Ok(signal) = self.rx.try_recv() {
            match signal {
                SupervisorSignal::FinalizeReady { report, .. } => {
                    if let Err(err) = sup.apply_finalize(*report, reg) {
                        eprintln!("finalize parked for retry: {err}");
                    }
                }
                other => self.seen.push(other),
            }
        }
    }

    fn seen(&self) -> &[SupervisorSignal] {
        &self.seen
    }
}

/// A supervisor with the injected 25 ms tick and the production `ps` probe. The [`Signals`] is kept
/// alive by the caller: a dropped receiver would make every `try_send` fail, which is survivable by
/// design but would stop the wake-up assertions from meaning anything — and would strand every
/// finalize report, which is not survivable.
fn supervisor() -> (Supervisor, Signals) {
    supervisor_with(Arc::new(PsProbe))
}

/// The same, with the liveness probe injected — the seam the design put the trait behind.
fn supervisor_with(probe: Arc<dyn ProcessProbe>) -> (Supervisor, Signals) {
    let (tx, rx) = mpsc::channel(64);
    (
        Supervisor::new(TICK, probe, tx),
        Signals {
            rx,
            seen: Vec::new(),
        },
    )
}

// ---------------------------------------------------------------------------
// Driving the loop
// ---------------------------------------------------------------------------

/// Ticks until the attempt reaches a terminal status, exactly as the actor's interval would.
async fn tick_until_finished(
    sup: &mut Supervisor,
    sig: &mut Signals,
    reg: &mut Registry,
    id: &AttemptId,
) -> Attempt {
    let deadline = Instant::now() + LIMIT;
    loop {
        sup.tick(reg).await;
        sig.pump(sup, reg);
        if let Some(attempt) = reg.attempt(id) {
            if attempt.status != AttemptStatus::Running {
                return attempt.clone();
            }
        }
        assert!(
            Instant::now() < deadline,
            "the attempt never finished within {LIMIT:?}"
        );
        tokio::time::sleep(TICK).await;
    }
}

/// Ticks until `ready` says the state under test has been reached, without finalizing anything it
/// does not have to.
async fn tick_until(
    sup: &mut Supervisor,
    sig: &mut Signals,
    reg: &mut Registry,
    what: &str,
    mut ready: impl FnMut(&Registry) -> bool,
) {
    let deadline = Instant::now() + LIMIT;
    loop {
        sup.tick(reg).await;
        sig.pump(sup, reg);
        if ready(reg) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{what} never happened within {LIMIT:?}"
        );
        tokio::time::sleep(TICK).await;
    }
}

fn events(reg: &Registry, run: &RunId) -> Vec<Arc<Event>> {
    reg.events(run, None, usize::MAX)
}

fn kinds(reg: &Registry, run: &RunId) -> Vec<String> {
    events(reg, run)
        .iter()
        .filter_map(|event| {
            serde_json::to_value(&event.payload)
                .ok()?
                .get("kind")?
                .as_str()
                .map(str::to_string)
        })
        .collect()
}

fn agent_messages(reg: &Registry, run: &RunId) -> Vec<(u64, MessageRole, String)> {
    events(reg, run)
        .iter()
        .filter_map(|event| match &event.payload {
            EventPayload::AgentMessage {
                src_line,
                role,
                text,
                ..
            } => Some((*src_line, *role, text.clone())),
            _ => None,
        })
        .collect()
}

fn violations(reg: &Registry, run: &RunId) -> Vec<(ViolationKind, Option<Vec<String>>)> {
    events(reg, run)
        .iter()
        .filter_map(|event| match &event.payload {
            EventPayload::PolicyViolated { violation, .. } => {
                Some((violation.kind, violation.files.clone()))
            }
            _ => None,
        })
        .collect()
}

/// Every `agent.progress`/`agent.session` line number, in order — the duplicate check after a
/// simulated restart.
fn tail_src_lines(reg: &Registry, run: &RunId) -> Vec<(&'static str, u64)> {
    events(reg, run)
        .iter()
        .filter_map(|event| match &event.payload {
            EventPayload::AgentProgress { src_line, .. } => Some(("agent.progress", *src_line)),
            EventPayload::AgentSession { src_line, .. } => Some(("agent.session", *src_line)),
            _ => None,
        })
        .collect()
}

/// The session id the first supervisor recorded — `agent.session` in the log, which a restart
/// reads back as `AgentHandle.session_id`.
fn recorded_session(reg: &Registry, run: &RunId) -> Option<String> {
    events(reg, run)
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::AgentSession { session_id, .. } => Some(session_id.clone()),
            _ => None,
        })
}

fn diff_frozen(reg: &Registry, run: &RunId) -> Option<(PathBuf, String, Vec<String>)> {
    events(reg, run)
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::DiffFrozen {
                diff_path,
                diff_hash,
                files,
                ..
            } => Some((diff_path.clone(), diff_hash.clone(), files.clone())),
            _ => None,
        })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn head_sha(worktree: &Path) -> String {
    git::head_sha(worktree).await.expect("read HEAD")
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_passing_attempt_succeeds_and_freezes_a_hashed_diff() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let (mut sup, mut sig) = supervisor();
    let pre_sha = head_sha(fx.worktree()).await;

    let spawned = fx.spawn("pass", &[]).await;
    sup.adopt(spawned, fx.ctx(Duration::from_secs(60), &pre_sha), &mut reg);
    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;

    assert_eq!(attempt.status, AttemptStatus::Succeeded, "{attempt:?}");
    assert_eq!(attempt.exit_code, Some(0));
    assert_eq!(
        attempt.structured_valid,
        Some(true),
        "pass-1's structured_output validates"
    );
    assert!(
        attempt.cost_usd > 0.0,
        "the result line reports a provider cost"
    );

    // The session id reached the log from `system/init` (line 1), and the tool_use/text lines were
    // coalesced into progress events.
    let kinds = kinds(&reg, &fx.run);
    for expected in [
        "attempt.started",
        "agent.session",
        "agent.progress",
        "attempt.usage",
        "attempt.result",
        "attempt.finished",
        "diff.frozen",
    ] {
        assert!(
            kinds.contains(&expected.to_string()),
            "{expected} missing from {kinds:?}"
        );
    }

    // Rev 25: `diffHash` is the sha256 of the file the reviewer will be pointed at, so a test that
    // did not re-hash the bytes would not be testing anything.
    let (diff_path, diff_hash, files) = diff_frozen(&reg, &fx.run).expect("a diff.frozen event");
    assert_eq!(diff_path, fx.diff_path());
    let bytes = std::fs::read(&diff_path).expect("the frozen diff exists on disk");
    assert_eq!(
        diff_hash,
        sha256_hex(&bytes),
        "diffHash must hash the frozen file"
    );
    assert!(files.contains(&"src/adder.ts".to_string()), "{files:?}");
    assert!(
        String::from_utf8_lossy(&bytes).contains("export function add"),
        "the diff carries the worker's change"
    );

    // The worker never commits, and this one did not: HEAD is where the attempt started.
    assert_eq!(head_sha(fx.worktree()).await, pre_sha);
    assert_eq!(attempt.post_sha.as_deref(), Some(pre_sha.as_str()));
}

async fn message_scenario(role: RoleName, count: Option<usize>) -> Vec<(u64, MessageRole, String)> {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let (mut sup, mut sig) = supervisor();
    let pre_sha = head_sha(fx.worktree()).await;
    let count = count.map(|value| value.to_string());
    let env: Vec<(&str, &str)> = count
        .as_deref()
        .map(|value| vec![("ACP_FAKE_MESSAGE_COUNT", value)])
        .unwrap_or_default();

    let spawned = fx.spawn("lead_messages", &env).await;
    let mut ctx = fx.ctx(Duration::from_secs(60), &pre_sha);
    ctx.role = role;
    ctx.writes = role == RoleName::Builder;
    sup.adopt(spawned, ctx, &mut reg);
    let _ = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;
    agent_messages(&reg, &fx.run)
}

#[tokio::test]
async fn assistant_text_blocks_are_uncoalesced_for_leads_and_absent_for_workers() {
    let lead = message_scenario(RoleName::Lead, None).await;
    assert_eq!(
        lead,
        [
            (2, MessageRole::Assistant, "First lead answer.".into()),
            (2, MessageRole::Assistant, "Second lead answer.".into()),
        ],
        "both blocks from one provider line must survive independently"
    );

    for role in [RoleName::Builder, RoleName::Reviewer] {
        assert!(
            message_scenario(role, None).await.is_empty(),
            "{role:?} prose escaped the lead-only tailer boundary"
        );
    }
}

#[tokio::test]
async fn a_lead_attempt_emits_500_messages_then_one_marker() {
    let messages = message_scenario(RoleName::Lead, Some(503)).await;
    assert_eq!(messages.len(), 501, "500 prose events plus one marker");
    assert_eq!(messages[0].2, "message 0");
    assert_eq!(messages[499].2, "message 499");
    assert!(
        messages[500].2.contains("truncated after 500 events"),
        "the final event is an explicit truncation marker: {:?}",
        messages[500]
    );
    assert!(
        messages
            .iter()
            .all(|(line, role, _)| *line == 2 && *role == MessageRole::Assistant),
        "every content block retains the provider line and fixed role"
    );
    assert!(
        !messages.iter().any(|(_, _, text)| text == "message 500"),
        "post-cap prose must be dropped"
    );
}

// ---------------------------------------------------------------------------
// The signal ladder
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_hung_attempt_times_out_through_the_signal_ladder() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let (mut sup, mut sig) = supervisor();
    let pre_sha = head_sha(fx.worktree()).await;

    let spawned = fx.spawn("hang", &[]).await;
    let started = Instant::now();
    sup.adopt(spawned, fx.ctx(Duration::from_secs(1), &pre_sha), &mut reg);
    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;
    let elapsed = started.elapsed();

    assert_eq!(attempt.status, AttemptStatus::Timeout, "{attempt:?}");
    // SIGTERM is the first rung and the fake dies on it, so the attempt resolves at the deadline —
    // not five seconds later, which is when the SIGKILL rung would have fired.
    assert_eq!(attempt.signal.as_deref(), Some("SIGTERM"), "{attempt:?}");
    assert!(
        elapsed >= Duration::from_secs(1),
        "fired before the deadline: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "waited for the SIGKILL rung instead of observing the SIGTERM: {elapsed:?}"
    );

    // The Error Handling table's record of *why* it was signalled.
    assert!(
        events(&reg, &fx.run).iter().any(|event| matches!(
            &event.payload,
            EventPayload::AttemptCancelRequested {
                by: CancelBy::Timeout,
                ..
            }
        )),
        "the timeout must record attempt.cancel_requested{{by:timeout}}"
    );
    // The actor is woken rather than being made to poll for it. `pump` kept every wake-up it did
    // not apply, so this reads the same channel the production forwarder does.
    assert!(
        sig.seen().iter().any(|signal| matches!(
            signal,
            SupervisorSignal::AttemptTimeout { attempt } if *attempt == fx.attempt
        )),
        "the deadline task posts AttemptTimeout to the mailbox"
    );
}

#[tokio::test]
async fn cancelling_a_running_attempt_ends_it_as_cancelled() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let (mut sup, mut sig) = supervisor();
    let pre_sha = head_sha(fx.worktree()).await;

    // A timeout far enough out that only the cancellation can end this.
    let spawned = fx.spawn("hang", &[]).await;
    sup.adopt(
        spawned,
        fx.ctx(Duration::from_secs(3600), &pre_sha),
        &mut reg,
    );
    tick_until(
        &mut sup,
        &mut sig,
        &mut reg,
        "the worker's first line",
        |reg| reg.attempt(&fx.attempt).is_some_and(|a| a.src_line >= 1),
    )
    .await;

    let started = Instant::now();
    sup.cancel(&fx.attempt, CancelBy::Lead, &mut reg)
        .await
        .expect("the attempt is running");
    // `cancel` schedules the SIGKILL rung, it never awaits it.
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "cancel blocked on the grace period"
    );

    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;
    assert_eq!(attempt.status, AttemptStatus::Cancelled, "{attempt:?}");
    assert!(
        events(&reg, &fx.run).iter().any(|event| matches!(
            &event.payload,
            EventPayload::AttemptCancelRequested {
                by: CancelBy::Lead,
                ..
            }
        )),
        "the request itself is durable"
    );
    assert!(
        sup.cancel(&fx.attempt, CancelBy::Lead, &mut reg)
            .await
            .is_err(),
        "a finished attempt is no longer cancellable"
    );
}

// ---------------------------------------------------------------------------
// C6 — the split line
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_line_split_across_two_writes_is_never_parsed_in_halves() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let (mut sup, mut sig) = supervisor();
    let pre_sha = head_sha(fx.worktree()).await;

    // The fake writes `split_line-1.jsonl`'s line 2 (the `result` line) in two flushes with a
    // 3 s gap, so ~120 ticks land while only the first half is on disk.
    let spawned = fx
        .spawn("split_line", &[("ACP_FAKE_DELAY_MS", "3000")])
        .await;
    sup.adopt(spawned, fx.ctx(Duration::from_secs(60), &pre_sha), &mut reg);

    let stdout = fx.attempt_dir.join("stdout.jsonl");
    let first_line = {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/jsonl/claude/split_line-1.jsonl");
        let text = std::fs::read_to_string(path).expect("read the split_line fixture");
        text.lines().next().expect("line 1").len() as u64 + 1
    };

    // Tick until the partial half of line 2 is on disk…
    tick_until(
        &mut sup,
        &mut sig,
        &mut reg,
        "the partial second line",
        |_| {
            std::fs::metadata(&stdout)
                .map(|meta| meta.len())
                .unwrap_or(0)
                > first_line
        },
    )
    .await;
    sup.tick(&mut reg).await;

    // …and there the tailer stops: the offset sits on the last `\n`, the partial bytes are buffered
    // in memory, and nothing has been parsed out of half a JSON object.
    assert_eq!(
        sup.byte_offset(&fx.attempt),
        Some(first_line),
        "the offset advanced past the incomplete line"
    );
    let during = tail_src_lines(&reg, &fx.run);
    assert_eq!(
        during,
        vec![("agent.session", 1)],
        "only line 1 has been parsed so far"
    );
    let kinds_during = kinds(&reg, &fx.run);
    assert!(
        !kinds_during.contains(&"attempt.result".to_string()),
        "{kinds_during:?}"
    );
    assert!(
        !kinds_during.contains(&"attempt.usage".to_string()),
        "{kinds_during:?}"
    );

    // Once the second half lands, the line parses exactly once, and correctly.
    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;
    assert_eq!(attempt.status, AttemptStatus::Succeeded, "{attempt:?}");
    assert_eq!(attempt.src_line, 2, "the result came from line 2");
    let results: Vec<u64> = events(&reg, &fx.run)
        .iter()
        .filter_map(|event| match &event.payload {
            EventPayload::AttemptResult { src_line, .. } => Some(*src_line),
            _ => None,
        })
        .collect();
    assert_eq!(
        results,
        vec![2],
        "exactly one result event, from the reassembled line"
    );
    assert_eq!(attempt.structured_valid, Some(true));
}

// ---------------------------------------------------------------------------
// Policy — real git
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_worker_commit_is_reset_with_real_git_and_recorded_as_a_violation() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let (mut sup, mut sig) = supervisor();
    let pre_sha = head_sha(fx.worktree()).await;

    let spawned = fx.spawn("worker_commits", &[]).await;
    sup.adopt(spawned, fx.ctx(Duration::from_secs(60), &pre_sha), &mut reg);
    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;

    // Not a mock: the fake really ran `git commit --allow-empty` in the worktree, and the soft
    // reset really moved HEAD back.
    assert_eq!(
        head_sha(fx.worktree()).await,
        pre_sha,
        "HEAD must be back at the attempt's preSha"
    );
    let violations = violations(&reg, &fx.run);
    assert!(
        violations
            .iter()
            .any(|(kind, _)| *kind == ViolationKind::WorkerCommitted),
        "{violations:?}"
    );
    // A commit is a rule broken, not a failed attempt: the work still goes to review.
    assert_eq!(attempt.status, AttemptStatus::Succeeded, "{attempt:?}");
    assert_ne!(
        attempt.post_sha.as_deref(),
        Some(pre_sha.as_str()),
        "the violation's evidence is the sha the worker moved HEAD to"
    );
    assert!(
        diff_frozen(&reg, &fx.run).is_some(),
        "the reviewer still gets a diff"
    );
}

/// A worker that ran `git add` and never committed leaves an index finalize has to clear.
///
/// The commit case has always been remediated; this is its other half. `assert_index_clean` is a
/// precondition of every integrate commit and nothing on the attempt path cleared a dirty index —
/// `undo_worker_commit` only fired when HEAD had moved — so one stray `git add` wedged the worktree
/// for good: the run could be built, reviewed, passed and approved, and never committed (round-4
/// review, finding 4). The remediation is the same `reset --mixed` to the attempt's `preSha`, which
/// unstages without touching a byte on disk.
#[tokio::test]
async fn a_worker_that_staged_without_committing_is_unstaged_and_recorded() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let (mut sup, mut sig) = supervisor();
    let pre_sha = head_sha(fx.worktree()).await;

    // The worker's `git add`: a file it wrote into its worktree and staged, and never committed.
    std::fs::write(fx.worktree().join("staged.txt"), "the worker staged this\n").expect("write");
    git::stage_paths(fx.worktree(), &["staged.txt".to_string()])
        .await
        .expect("stage");
    assert!(
        !git::index_is_clean(fx.worktree())
            .await
            .expect("read the index"),
        "the fixture has to start dirty, or this test proves nothing"
    );

    let spawned = fx.spawn("pass", &[]).await;
    sup.adopt(spawned, fx.ctx(Duration::from_secs(60), &pre_sha), &mut reg);
    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;

    // Not a mock: real git staged it and the real reset unstaged it.
    assert!(
        git::index_is_clean(fx.worktree())
            .await
            .expect("read the index"),
        "the index must be back in the state an approval can commit from"
    );
    assert_eq!(
        head_sha(fx.worktree()).await,
        pre_sha,
        "the remediation is an unstage, not a rewind"
    );
    assert!(
        fx.worktree().join("staged.txt").exists(),
        "the work is kept; only the index moved"
    );
    let violations = violations(&reg, &fx.run);
    assert!(
        violations
            .iter()
            .any(|(kind, _)| *kind == ViolationKind::WorkerStaged),
        "{violations:?}"
    );
    // A rule broken, not a failed attempt: the work still goes to review.
    assert_eq!(attempt.status, AttemptStatus::Succeeded, "{attempt:?}");
    assert!(
        diff_frozen(&reg, &fx.run).is_some(),
        "the reviewer still gets a diff"
    );
}

#[tokio::test]
async fn a_denylisted_file_escalates_without_extracting_a_result() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let (mut sup, mut sig) = supervisor();
    let pre_sha = head_sha(fx.worktree()).await;

    let spawned = fx.spawn("denylist", &[]).await;
    sup.adopt(spawned, fx.ctx(Duration::from_secs(60), &pre_sha), &mut reg);
    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;

    assert_eq!(attempt.status, AttemptStatus::Escalate, "{attempt:?}");
    assert_eq!(
        violations(&reg, &fx.run),
        vec![(
            ViolationKind::DenylistHit,
            Some(vec!["App.xcconfig".to_string()])
        )],
        "the violation names the file the worker was never allowed to touch"
    );
    // No result, no diff: a human decides before anything else looks at this work.
    let kinds = kinds(&reg, &fx.run);
    assert!(!kinds.contains(&"attempt.result".to_string()), "{kinds:?}");
    assert!(!kinds.contains(&"diff.frozen".to_string()), "{kinds:?}");
    assert_eq!(attempt.structured_valid, None);
}

#[tokio::test]
async fn a_builder_that_changed_nothing_is_invalid_output_not_success() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let (mut sup, mut sig) = supervisor();
    let pre_sha = head_sha(fx.worktree()).await;

    // The transcript claims `src/adder.ts` was written; the worktree says otherwise (Rev 25).
    let spawned = fx.spawn("no_changes", &[]).await;
    sup.adopt(spawned, fx.ctx(Duration::from_secs(60), &pre_sha), &mut reg);
    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;

    assert_eq!(attempt.status, AttemptStatus::InvalidOutput, "{attempt:?}");
    assert_eq!(
        attempt.error.as_ref().map(|error| error.code),
        Some(ErrorCode::NoChangedFiles),
        "{attempt:?}"
    );
    // The output itself was schema-valid — the diff is what failed — and no reviewer is ever
    // pointed at an empty diff.
    assert_eq!(attempt.structured_valid, Some(true));
    assert!(
        diff_frozen(&reg, &fx.run).is_none(),
        "an empty diff is never frozen"
    );
    // Exactly one terminal event: `reduce` keeps the first status it sees, so a `succeeded`
    // appended before this one would have stuck (C2).
    let finished: Vec<AttemptStatus> = events(&reg, &fx.run)
        .iter()
        .filter_map(|event| match &event.payload {
            EventPayload::AttemptFinished { status, .. } => Some(*status),
            _ => None,
        })
        .collect();
    assert_eq!(finished, vec![AttemptStatus::InvalidOutput]);
}

// ---------------------------------------------------------------------------
// Liveness and re-attach
// ---------------------------------------------------------------------------

#[test]
fn the_probe_reports_a_recycled_pid_as_dead() {
    let probe = PsProbe;
    let me = i32::try_from(std::process::id()).expect("a pid fits in an i32");

    let lstart = probe.start_time(me).expect("this process has a start time");
    assert!(probe.is_alive(me, &lstart), "this process is alive");

    // The pid-reuse case: the pid is live, but it is not the process we recorded.
    assert!(
        !probe.is_alive(me, "Thu Jan  1 00:00:00 1970"),
        "a start-time mismatch means a different process wears this pid"
    );
    assert!(
        !probe.is_alive(me, ""),
        "an unverifiable start time is never alive"
    );
    // A pid that means "my process group" to `kill` is never a process.
    assert!(!probe.is_alive(0, &lstart));
    assert!(!probe.is_alive(-1, &lstart));
}

#[tokio::test]
async fn a_restarted_supervisor_resumes_the_tail_without_duplicating_it() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let pre_sha = head_sha(fx.worktree()).await;

    // Slow enough that the "restart" lands mid-transcript.
    let spawned = fx.spawn("pass", &[("ACP_FAKE_DELAY_MS", "150")]).await;
    let (mut first, mut sig) = supervisor();
    let attempt = first.adopt(spawned, fx.ctx(Duration::from_secs(60), &pre_sha), &mut reg);
    tick_until(&mut first, &mut sig, &mut reg, "the session line", |reg| {
        reg.attempt(&fx.attempt).is_some_and(|a| a.src_line >= 1)
    })
    .await;
    let before = tail_src_lines(&reg, &fx.run);
    assert!(!before.is_empty(), "the first supervisor tailed something");

    // The daemon goes away; the worker does not (`kill_on_drop(false)`).
    drop(first);
    let recorded = reg
        .attempt(&fx.attempt)
        .cloned()
        .expect("the attempt is in the log");
    assert_eq!(recorded.attempt_id, attempt.attempt_id);
    assert_eq!(recorded.status, AttemptStatus::Running);

    // A resumed tail starts past `system/init`, so the restart carries the session the log already
    // recorded — otherwise the attempt would look like it never had one.
    let session = recorded_session(&reg, &fx.run);
    assert!(session.is_some(), "the first supervisor recorded a session");
    let (mut second, mut sig2) = supervisor();
    second.reattach(
        &recorded,
        fx.resumed_ctx(Duration::from_secs(60), &pre_sha, session),
        &reg,
    );
    let finished = tick_until_finished(&mut second, &mut sig2, &mut reg, &fx.attempt).await;

    assert_eq!(finished.status, AttemptStatus::Succeeded, "{finished:?}");
    // A re-attached attempt has no `Child`, so nobody can read its exit code.
    assert_eq!(finished.exit_code, None);
    assert!(
        diff_frozen(&reg, &fx.run).is_some(),
        "the frozen diff still happens"
    );

    // The point of `lastSrcLine`: the second supervisor skipped what the first already emitted.
    let all = tail_src_lines(&reg, &fx.run);
    let mut seen = all.clone();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), all.len(), "a line was tailed twice: {all:?}");
    assert!(
        all.starts_with(&before),
        "the first supervisor's events are intact: {all:?}"
    );
}

#[tokio::test]
async fn a_reattached_deadline_is_rearmed_from_the_original_start() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let pre_sha = head_sha(fx.worktree()).await;

    let spawned = fx.spawn("hang", &[]).await;
    let (mut first, mut sig) = supervisor();
    first.adopt(
        spawned,
        fx.ctx(Duration::from_secs(3600), &pre_sha),
        &mut reg,
    );
    tick_until(
        &mut first,
        &mut sig,
        &mut reg,
        "the worker's first line",
        |reg| reg.attempt(&fx.attempt).is_some_and(|a| a.src_line >= 1),
    )
    .await;
    drop(first);

    // The restart: the attempt was started long ago with a one-second timeout, so its deadline is
    // already in the past and must fire immediately rather than granting a fresh timeout.
    let mut recorded = reg
        .attempt(&fx.attempt)
        .cloned()
        .expect("the attempt is in the log");
    recorded.started_at = "2020-01-01T00:00:00.000Z".to_string();
    recorded.timeout_sec = 1;

    let (mut second, mut sig2) = supervisor();
    let started = Instant::now();
    second.reattach(&recorded, fx.ctx(Duration::from_secs(1), &pre_sha), &reg);
    let attempt = tick_until_finished(&mut second, &mut sig2, &mut reg, &fx.attempt).await;

    assert_eq!(attempt.status, AttemptStatus::Timeout, "{attempt:?}");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "an already-expired deadline waited: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_pid_that_no_longer_matches_its_start_time_is_never_signalled() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let pre_sha = head_sha(fx.worktree()).await;

    let spawned = fx.spawn("hang", &[]).await;
    let pid = spawned.pid;
    // The start time the process really has, kept so the test can ask the live question after the
    // supervisor has been told a false one.
    let real_start_time = spawned.start_time.clone();
    let (mut first, mut sig) = supervisor();
    first.adopt(
        spawned,
        fx.ctx(Duration::from_secs(3600), &pre_sha),
        &mut reg,
    );
    tick_until(
        &mut first,
        &mut sig,
        &mut reg,
        "the worker's first line",
        |reg| reg.attempt(&fx.attempt).is_some_and(|a| a.src_line >= 1),
    )
    .await;
    drop(first);

    // The pid-reuse case, forced: the log's `startTime` no longer describes the process wearing
    // this pid, so a re-attached supervisor must treat it as somebody else's (Revision 24).
    let mut recorded = reg
        .attempt(&fx.attempt)
        .cloned()
        .expect("the attempt is in the log");
    recorded.start_time = Some("Thu Jan  1 00:00:00 1970".to_string());

    let (mut second, mut sig2) = supervisor();
    assert_eq!(
        second.signal_group(&recorded, Signal::SIGTERM),
        SignalOutcome::Mismatch,
        "nothing may be signalled on a start-time mismatch"
    );

    second.reattach(&recorded, fx.ctx(Duration::from_secs(3600), &pre_sha), &reg);
    let attempt = tick_until_finished(&mut second, &mut sig2, &mut reg, &fx.attempt).await;
    assert_eq!(attempt.status, AttemptStatus::Lost, "{attempt:?}");

    // And the process the supervisor refused to signal is untouched — which is the whole point:
    // had it signalled on a mismatch, it would have been killing a stranger.
    assert!(
        PsProbe.is_alive(pid, &real_start_time),
        "the unsignalled process must still be alive and be the one we spawned"
    );
    // This test owns it, so this test reaps it.
    let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), Signal::SIGKILL);
}

// ---------------------------------------------------------------------------
// The worker environment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_child_sees_only_the_allowlisted_environment() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let (mut sup, mut sig) = supervisor();
    let pre_sha = head_sha(fx.worktree()).await;

    // The record file lives in the **worktree**: `$ACP_STATE_DIR` may not appear in any value the
    // child is handed (`assert_safe_argv` check 5), and a worker that learned it could find the
    // socket that approves its own gate.
    let record = fx.worktree().join("fake-record.jsonl");
    let spawned = fx
        .spawn(
            "pass",
            &[("ACP_FAKE_RECORD", &record.display().to_string())],
        )
        .await;
    sup.adopt(spawned, fx.ctx(Duration::from_secs(60), &pre_sha), &mut reg);
    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;
    assert_eq!(attempt.status, AttemptStatus::Succeeded, "{attempt:?}");

    let text = std::fs::read_to_string(&record).expect("the fake recorded its invocation");
    let line: Value = serde_json::from_str(text.lines().next().expect("one record line"))
        .expect("the record line is JSON");
    let env = &line["envSubset"];

    // C4/V5: `remote.origin.url` is neutralized, so a worker that runs `git push` pushes nowhere.
    assert_eq!(env["gitConfigCount"], Value::from("1"));
    assert_eq!(env["gitConfigKey0"], Value::from("remote.origin.url"));
    assert_eq!(env["gitConfigValue0"], Value::from(""));

    // The whole point: every `ACP_*` key the child could see, and nothing this test process's own
    // environment leaked into it.
    let keys: Vec<String> = env["acpEnvKeys"]
        .as_array()
        .expect("acpEnvKeys is an array")
        .iter()
        .map(|key| key.as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        !keys.is_empty(),
        "the scenario itself travels as ACP_FAKE_SCENARIO"
    );
    for key in &keys {
        assert!(
            key.starts_with("ACP_FAKE_"),
            "{key} reached the worker; only the ACP_FAKE_* pass-through may: {keys:?}"
        );
    }
    assert!(keys.contains(&"ACP_FAKE_SCENARIO".to_string()), "{keys:?}");
    assert!(keys.contains(&"ACP_FAKE_RECORD".to_string()), "{keys:?}");
}

// ---------------------------------------------------------------------------
// Fail-closed: an attempt the control plane could not verify never succeeds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_worktree_git_cannot_read_never_succeeds() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let (mut sup, mut sig) = supervisor();
    let pre_sha = head_sha(fx.worktree()).await;

    // The `pass` scenario touches git not at all, so removing the repository out from under it is
    // deterministic: every git call the *finalize* makes — HEAD, the changed-file set, the frozen
    // diff — fails, and with them the `worker_committed` and denylist checks.
    let spawned = fx.spawn("pass", &[]).await;
    std::fs::remove_dir_all(fx.worktree().join(".git")).expect("break the worktree");
    sup.adopt(spawned, fx.ctx(Duration::from_secs(60), &pre_sha), &mut reg);
    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;

    // The worker did everything right — its output is schema-valid — but nothing about it could be
    // verified, so it may not pass for a success.
    assert_eq!(attempt.structured_valid, Some(true));
    assert_ne!(
        attempt.status,
        AttemptStatus::Succeeded,
        "an unverified attempt must never be succeeded: {attempt:?}"
    );
    assert_eq!(attempt.status, AttemptStatus::Escalate, "{attempt:?}");
    assert_eq!(
        attempt.error.as_ref().map(|error| error.code),
        Some(ErrorCode::WorkspaceError),
        "{attempt:?}"
    );
    assert!(
        attempt
            .error
            .as_ref()
            .is_some_and(|error| !error.message.is_empty()),
        "the git failure text travels to the human: {attempt:?}"
    );
    // Nothing downstream may act on this attempt: no diff, and therefore no hash to review.
    assert!(
        diff_frozen(&reg, &fx.run).is_none(),
        "an unverifiable attempt must advertise no diff"
    );
    assert!(!kinds(&reg, &fx.run).contains(&"diff.frozen".to_string()));
}

#[tokio::test]
async fn a_diff_that_cannot_be_frozen_never_succeeds() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let (mut sup, mut sig) = supervisor();
    let pre_sha = head_sha(fx.worktree()).await;

    // The repository is intact — the changed-file set and the denylist check both run — but the
    // frozen diff cannot be written, because `<runDir>/diffs` is occupied by a regular file. The
    // hash the reviewer must echo therefore never exists.
    let diffs = fx.diff_path().parent().expect("diffs dir").to_path_buf();
    std::fs::create_dir_all(diffs.parent().expect("run dir")).expect("create the run dir");
    std::fs::write(&diffs, b"not a directory").expect("occupy the diffs path");

    let spawned = fx.spawn("pass", &[]).await;
    sup.adopt(spawned, fx.ctx(Duration::from_secs(60), &pre_sha), &mut reg);
    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;

    assert_ne!(
        attempt.status,
        AttemptStatus::Succeeded,
        "a success without a hashed diff is exactly what Rev 25 forbids: {attempt:?}"
    );
    assert_eq!(attempt.status, AttemptStatus::Escalate, "{attempt:?}");
    assert_eq!(
        attempt.error.as_ref().map(|error| error.code),
        Some(ErrorCode::WorkspaceError),
        "{attempt:?}"
    );
    assert!(
        diff_frozen(&reg, &fx.run).is_none(),
        "no diff, no diff.frozen"
    );
    // The worker still ran and still produced a result: this is our failure, not its.
    assert_eq!(attempt.structured_valid, Some(true));
    assert!(kinds(&reg, &fx.run).contains(&"attempt.result".to_string()));
}

// ---------------------------------------------------------------------------
// An unsignalled process is lost, whatever we meant to do to it
// ---------------------------------------------------------------------------

/// Re-attaches a running `hang` attempt with a start time that no longer matches the process, and
/// hands back the pid, its real start time and everything needed to drive the second supervisor.
async fn reattach_with_a_forged_start_time(
    fx: &Fixture,
    reg: &mut Registry,
    pre_sha: &str,
) -> (Attempt, i32, String) {
    let spawned = fx.spawn("hang", &[]).await;
    let pid = spawned.pid;
    let real_start_time = spawned.start_time.clone();
    let (mut first, mut sig) = supervisor();
    first.adopt(spawned, fx.ctx(Duration::from_secs(3600), pre_sha), reg);
    tick_until(
        &mut first,
        &mut sig,
        reg,
        "the worker's first line",
        |reg| reg.attempt(&fx.attempt).is_some_and(|a| a.src_line >= 1),
    )
    .await;
    drop(first);

    let mut recorded = reg
        .attempt(&fx.attempt)
        .cloned()
        .expect("the attempt is in the log");
    recorded.start_time = Some(FORGED_START_TIME.to_string());
    (recorded, pid, real_start_time)
}

#[tokio::test]
async fn cancelling_a_pid_we_can_no_longer_identify_is_lost_not_cancelled() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let pre_sha = head_sha(fx.worktree()).await;
    let (recorded, pid, real_start_time) =
        reattach_with_a_forged_start_time(&fx, &mut reg, &pre_sha).await;
    let (mut sup, mut sig) = supervisor();

    let session = recorded_session(&reg, &fx.run);
    sup.reattach(
        &recorded,
        fx.resumed_ctx(Duration::from_secs(3600), &pre_sha, session),
        &reg,
    );
    sup.cancel(&fx.attempt, CancelBy::Lead, &mut reg)
        .await
        .expect("the attempt is being supervised");
    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;

    // The SIGTERM was never delivered, so calling this "cancelled" would claim we ended something
    // we never touched.
    assert_eq!(
        attempt.status,
        AttemptStatus::Lost,
        "an unsignalled cancellation is lost, not cancelled: {attempt:?}"
    );
    assert!(
        PsProbe.is_alive(pid, &real_start_time),
        "the process we could not identify must be untouched"
    );
    let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), Signal::SIGKILL);
}

#[tokio::test]
async fn timing_out_a_pid_we_can_no_longer_identify_is_lost_not_timeout() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let pre_sha = head_sha(fx.worktree()).await;
    let (mut recorded, pid, real_start_time) =
        reattach_with_a_forged_start_time(&fx, &mut reg, &pre_sha).await;
    let (mut sup, mut sig) = supervisor();

    // An already-expired deadline, so the ladder runs before the first tick and the timeout flag is
    // set by the time the attempt is classified.
    recorded.started_at = "2020-01-01T00:00:00.000Z".to_string();
    recorded.timeout_sec = 1;
    let session = recorded_session(&reg, &fx.run);
    sup.reattach(
        &recorded,
        fx.resumed_ctx(Duration::from_secs(1), &pre_sha, session),
        &reg,
    );
    tokio::time::sleep(Duration::from_millis(150)).await;

    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;
    assert_eq!(
        attempt.status,
        AttemptStatus::Lost,
        "a deadline that signalled nothing is lost, not a timeout: {attempt:?}"
    );
    assert!(
        PsProbe.is_alive(pid, &real_start_time),
        "the process we could not identify must be untouched"
    );
    let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), Signal::SIGKILL);
}

/// A probe that answers the deadline ladder's guarded question with "still ours" and every later
/// question with "recycled".
///
/// That ordering is the race: the ladder probes, signals, and only *then* records what it learned,
/// so a tick that classifies in between must decide identity itself. The real probe shells out to
/// `ps`, which is slow enough to make the window ordinary rather than exotic.
struct RecycledAfterSignalProbe {
    calls: AtomicUsize,
    actual_start_time: String,
}

impl RecycledAfterSignalProbe {
    fn new(actual_start_time: String) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            actual_start_time,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ProcessProbe for RecycledAfterSignalProbe {
    fn is_alive(&self, _pid: i32, _start_time: &str) -> bool {
        // Only the very first caller — the ladder — is told the process is still ours, so it
        // signals and records no mismatch at all.
        self.calls.fetch_add(1, Ordering::SeqCst) == 0
    }

    fn start_time(&self, _pid: i32) -> Option<String> {
        // Alive, but wearing a start time that is not the one the log recorded.
        Some(self.actual_start_time.clone())
    }
}

#[tokio::test]
async fn a_deadline_whose_pid_was_recycled_is_lost_even_before_the_ladder_says_so() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let pre_sha = head_sha(fx.worktree()).await;
    let (mut recorded, pid, real_start_time) =
        reattach_with_a_forged_start_time(&fx, &mut reg, &pre_sha).await;

    // An expired deadline, so the ladder fires the instant the attempt is re-attached.
    recorded.started_at = "2020-01-01T00:00:00.000Z".to_string();
    recorded.timeout_sec = 1;
    let session = recorded_session(&reg, &fx.run);

    let probe = Arc::new(RecycledAfterSignalProbe::new(real_start_time.clone()));
    let (mut sup, mut sig) = supervisor_with(probe.clone());
    sup.reattach(
        &recorded,
        fx.resumed_ctx(Duration::from_secs(1), &pre_sha, session),
        &reg,
    );

    // Let the ladder run its first rung: it publishes `timed_out`, signals, and — because its own
    // probe said the process was still ours — records no mismatch.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        probe.calls(),
        1,
        "the ladder must have taken its guarded probe and nobody else"
    );

    // Now the actor ticks. `timed_out` is set and `lost` is not, so a supervisor that trusted the
    // ladder to have decided identity for it would call this a timeout.
    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;
    assert_ne!(
        attempt.status,
        AttemptStatus::Timeout,
        "the deadline fired at a pid that is no longer ours: {attempt:?}"
    );
    assert_eq!(attempt.status, AttemptStatus::Lost, "{attempt:?}");
    assert!(
        probe.calls() >= 2,
        "the tick asked its own liveness question rather than inheriting an answer"
    );

    let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), Signal::SIGKILL);
}

// ---------------------------------------------------------------------------
// An unverified workspace outranks every strikeable terminal state
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_output_with_an_unverified_workspace_escalates_instead_of_striking() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let (mut sup, mut sig) = supervisor();
    let pre_sha = head_sha(fx.worktree()).await;

    // `invalid` is a schema-invalid result — normally `invalid_output`, which **strikes the
    // builder** and sends the loop into a repair round. With the worktree unreadable, that strike
    // would be for our own blindness, against a diff nobody has verified.
    let spawned = fx.spawn("invalid", &[]).await;
    std::fs::remove_dir_all(fx.worktree().join(".git")).expect("break the worktree");
    sup.adopt(spawned, fx.ctx(Duration::from_secs(60), &pre_sha), &mut reg);
    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;

    assert_ne!(
        attempt.status,
        AttemptStatus::InvalidOutput,
        "a strikeable status must not survive an unverified workspace: {attempt:?}"
    );
    assert_eq!(attempt.status, AttemptStatus::Escalate, "{attempt:?}");
    let error = attempt.error.as_ref().expect("a terminal error");
    assert_eq!(error.code, ErrorCode::WorkspaceError, "{attempt:?}");
    // What it would have been, had we been able to check, is kept for the human.
    assert!(
        error.message.contains("invalid_output"),
        "the original classification survives in the message: {}",
        error.message
    );
    assert_eq!(attempt.structured_valid, Some(false));
    assert!(diff_frozen(&reg, &fx.run).is_none());
}

#[tokio::test]
async fn a_denylist_hit_whose_reset_failed_reports_the_unverified_workspace() {
    let fx = Fixture::new();
    let mut reg = fx.registry();
    let (mut sup, mut sig) = supervisor();

    // A well-formed sha naming no object: HEAD differs from it, so the `worker_committed` branch
    // runs and its `git reset --soft` fails — the enforcement did not happen — while the repository
    // stays readable, so the denylist check still runs and still hits.
    let unreachable_sha = "0".repeat(39) + "1";
    let spawned = fx.spawn("denylist", &[]).await;
    sup.adopt(
        spawned,
        fx.ctx(Duration::from_secs(60), &unreachable_sha),
        &mut reg,
    );
    let attempt = tick_until_finished(&mut sup, &mut sig, &mut reg, &fx.attempt).await;

    // The gate is still a denylist gate…
    assert_eq!(attempt.status, AttemptStatus::Escalate, "{attempt:?}");
    let recorded = violations(&reg, &fx.run);
    assert!(
        recorded.contains(&(
            ViolationKind::DenylistHit,
            Some(vec!["App.xcconfig".to_string()])
        )),
        "the denylist violation must survive: {recorded:?}"
    );
    assert!(
        recorded
            .iter()
            .any(|(kind, _)| *kind == ViolationKind::WorkerCommitted),
        "the failed reset is still a worker-commit violation: {recorded:?}"
    );
    // …and the human is told the worktree was never put back, rather than being shown a clean
    // escalate with no error at all.
    let error = attempt.error.as_ref().expect("a terminal error");
    assert_eq!(error.code, ErrorCode::WorkspaceError, "{attempt:?}");
    assert!(
        error.message.contains("denylist_hit"),
        "the denylist origin survives in the message: {}",
        error.message
    );
    assert!(!kinds(&reg, &fx.run).contains(&"attempt.result".to_string()));
}

// ---------------------------------------------------------------------------
// The actor is never blocked by a finalize (Codex review of T33, finding 1)
// ---------------------------------------------------------------------------

/// The marker file the pass-through `git` shim sleeps on, once, in whatever worktree holds it.
const SLOW_GIT_MARKER: &str = ".acp-slow-git";

/// Puts a **pass-through** `git` on the front of the process `PATH`.
///
/// `tests/git.rs`'s shim replaces git outright and therefore has to serialize every other test in
/// its binary behind an exclusive lock. This one cannot: it sleeps exactly once, and only in a
/// worktree that holds [`SLOW_GIT_MARKER`] (which it deletes first, so the *next* git call in the
/// same worktree is normal), and otherwise `exec`s the real git. Every other test in this binary
/// keeps seeing real git with real behaviour, so no lock is needed.
///
/// The directory is deliberately **kept**: other tests may resolve `git` through it long after this
/// one returns, and deleting it out from under them would be a flake with no relation to the thing
/// under test.
fn shim_slow_git() {
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
            "#!/bin/sh\nif [ -e \"./{SLOW_GIT_MARKER}\" ]; then rm -f \"./{SLOW_GIT_MARKER}\"; sleep 3; fi\nexec \"{}\" \"$@\"\n",
            real.display()
        ),
    )
    .expect("write the shim");
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let kept = dir.keep();
    let original = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs = vec![kept];
    dirs.extend(std::env::split_paths(&original));
    std::env::set_var("PATH", std::env::join_paths(dirs).expect("join PATH"));
}

/// Applies whatever the finalize helpers posted, **through the actor's mailbox turn** — the
/// production path, `SupervisorSignal::FinalizeReady` → `Command::FinalizeReady`.
async fn pump_into_actor(sig: &mut Signals, core: &mut Core) {
    while let Ok(signal) = sig.rx.try_recv() {
        if let SupervisorSignal::FinalizeReady { attempt, report } = signal {
            core.handle_command(Command::FinalizeReady { attempt, report })
                .await;
        }
    }
}

/// One `Status` turn, timed.
async fn status_turn(core: &mut Core) -> StatusOut {
    let (tx, rx) = oneshot::channel();
    core.handle_command(Command::Status {
        query: StatusQuery::default(),
        reply: tx,
    })
    .await;
    rx.await.expect("the actor replied").expect("status")
}

/// Decision 11, end to end: a git call wedged inside an attempt's finalize must not cost the actor
/// a single mailbox turn.
///
/// Before the split this was a real stall — `Supervisor::tick` ran `head_sha`, `soft_reset`,
/// `changed_files` and `frozen_diff` inline, so `get_status`, `cancel` and every gate resolution
/// waited behind them for up to `GIT_OP_TIMEOUT`. The shim sleeps three seconds inside the first
/// git call of the finalize; twenty `Status` turns taken while it sleeps must all answer, and the
/// attempt must still finalize correctly afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_status_turn_answers_while_a_finalize_helper_is_stuck_in_git() {
    shim_slow_git();

    let fx = Fixture::new();
    let (sup, mut sig) = supervisor();
    let (mailbox, _rx) = channel();
    let mut core = Core::new(
        fx.registry(),
        sup,
        load_roles(None).expect("the embedded roles"),
        fx.repo.path().to_path_buf(),
        fx.state_dir.path().to_path_buf(),
        mailbox,
    );
    core.registry
        .append(
            &fx.run,
            EventPayload::RunCreated {
                execution: None,
                repo_root: fx.repo.path().to_path_buf(),
                state_dir: fx.state_dir.path().to_path_buf(),
                base_ref: "main".to_string(),
                base_sha: "0".repeat(40),
                task: Task {
                    id: "T33".to_string(),
                    title: "the actor stays answerable".to_string(),
                    description: "a wedged git may never stall the mailbox".to_string(),
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

    // Read HEAD *before* planting the marker, so the shim's one sleep is spent inside the finalize.
    let pre_sha = head_sha(fx.worktree()).await;
    let spawned = fx.spawn("pass", &[]).await;
    core.supervisor.adopt(
        spawned,
        fx.ctx(Duration::from_secs(30), &pre_sha),
        &mut core.registry,
    );
    std::fs::write(fx.worktree().join(SLOW_GIT_MARKER), b"").expect("plant the marker");

    // Tick until the exit is observed. At that point the attempt has left the supervisor's running
    // set and its finalize helper is in flight — stuck in the shim's `sleep 3`.
    let deadline = Instant::now() + LIMIT;
    while core.supervisor.is_running(&fx.attempt) {
        // Including the turn that *observes* the exit and hands the attempt to the helper: that is
        // the turn that used to run the whole finalize, git and all.
        let turn = Instant::now();
        core.handle_command(Command::Tick).await;
        let turn = turn.elapsed();
        assert!(
            turn < Duration::from_secs(1),
            "a Tick turn awaited the finalize's git: {turn:?}"
        );
        assert!(Instant::now() < deadline, "the attempt never exited");
        tokio::time::sleep(TICK).await;
    }
    assert_eq!(
        core.registry.attempt(&fx.attempt).map(|a| a.status),
        Some(AttemptStatus::Running),
        "the finalize report has not been applied yet — that is what makes the next assertion mean \
         something"
    );

    // The assertion. Twenty turns, while a git call this attempt depends on is asleep.
    let started = Instant::now();
    for _ in 0..20 {
        let status = status_turn(&mut core).await;
        assert_eq!(status.schema_version, 1);
        assert_eq!(status.runs.len(), 1);
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "the mailbox stalled behind the finalize's git: 20 status turns took {elapsed:?}"
    );
    assert_eq!(
        core.registry.attempt(&fx.attempt).map(|a| a.status),
        Some(AttemptStatus::Running),
        "the finalize was still in flight for the whole measurement"
    );

    // And it still finalizes correctly once the shim wakes up.
    let deadline = Instant::now() + LIMIT;
    loop {
        core.handle_command(Command::Tick).await;
        pump_into_actor(&mut sig, &mut core).await;
        if let Some(attempt) = core.registry.attempt(&fx.attempt) {
            if attempt.status != AttemptStatus::Running {
                assert_eq!(attempt.status, AttemptStatus::Succeeded, "{attempt:?}");
                break;
            }
        }
        assert!(Instant::now() < deadline, "the attempt never finalized");
        tokio::time::sleep(TICK).await;
    }
    let frozen = kinds(&core.registry, &fx.run)
        .iter()
        .filter(|kind| *kind == "diff.frozen")
        .count();
    assert_eq!(frozen, 1, "the report is applied exactly once");
}

// ---------------------------------------------------------------------------
// A fatal stop leaves no worker behind (Codex review of T33, round 3, finding 2)
// ---------------------------------------------------------------------------

/// Makes the run's event log writable or not. `false` when the mode cannot be enforced — running as
/// root, where 0444 is advisory — so the caller can skip rather than assert something untrue.
fn set_log_writable(path: &Path, writable: bool) -> bool {
    use std::os::unix::fs::PermissionsExt;

    // Safe: a read of this process's own effective uid, no arguments, no allocation.
    if unsafe { libc::geteuid() } == 0 {
        return false;
    }
    let mode = if writable { 0o600 } else { 0o444 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).is_ok()
}

/// Is `pid` a *running* process rather than a zombie?
///
/// A worker we signalled is a zombie for the moment between its death and the runtime reaping it,
/// and a zombie holds no worktree and edits no files — it is not a worker that outlived us.
fn is_running_process(pid: i32) -> bool {
    let Ok(out) = std::process::Command::new("/bin/ps")
        .args(["-o", "state=", "-p", &pid.to_string()])
        .output()
    else {
        return false;
    };
    let state = String::from_utf8_lossy(&out.stdout);
    let state = state.trim();
    !state.is_empty() && !state.starts_with('Z')
}

/// `<state>/runs/<runId>/events.jsonl`.
fn events_log(fx: &Fixture) -> PathBuf {
    fx.state_dir
        .path()
        .join("runs")
        .join(fx.run.to_string())
        .join("events.jsonl")
}

/// The actor stopping because the log is unwritable must not leave a live worker behind — and must
/// not merely *ask* it to leave.
///
/// Workers are spawned into their own process group with `kill_on_drop(false)` precisely so a
/// restart never kills one — and on the design's normal exit path (C3) that is correct: "workers
/// survive; a restart re-attaches". It stops being correct when the log itself is gone, because
/// nothing more can be recorded about them and no restart can pick them up.
///
/// The worker here is `hang_ignore_term`, which is deaf to SIGTERM. That is deliberate and it is
/// what makes the test load-bearing: a shutdown that sends the first rung and schedules the second
/// in a detached task passes with a plain `hang` and fails here, because the actor returns and the
/// runtime drops that task before the grace period elapses. Only a shutdown that *awaits* the whole
/// ladder gets this pid reaped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_that_ignores_sigterm_does_not_outlive_a_fatal_stop() {
    let fx = Fixture::new();
    let log = events_log(&fx);

    let (mailbox, rx) = channel();
    let (sig_tx, sig_rx) = mpsc::channel(64);
    let sup = Supervisor::new(TICK, Arc::new(PsProbe), sig_tx);
    let mut core = Core::new(
        fx.registry(),
        sup,
        load_roles(None).expect("the embedded roles"),
        fx.repo.path().to_path_buf(),
        fx.state_dir.path().to_path_buf(),
        mailbox.clone(),
    );
    core.registry
        .append(
            &fx.run,
            EventPayload::RunCreated {
                execution: None,
                repo_root: fx.repo.path().to_path_buf(),
                state_dir: fx.state_dir.path().to_path_buf(),
                base_ref: "main".to_string(),
                base_sha: "0".repeat(40),
                task: Task {
                    id: "T33".to_string(),
                    title: "no worker outlives a fatal stop".to_string(),
                    description: "the log is unwritable, so nothing can be recorded".to_string(),
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

    let pre_sha = head_sha(fx.worktree()).await;

    // The worker that must not be left behind: deaf to SIGTERM, and with a timeout long enough
    // that nothing but the fatal path can end it.
    let (hang_attempt, hang_dir) = fx.sibling_attempt();
    let hang = fx.spawn_in("hang_ignore_term", &[], &hang_dir).await;
    let hang_pid = hang.pid;
    let hang_start = hang.start_time.clone();
    core.supervisor.adopt(
        hang,
        AttemptContext {
            attempt: hang_attempt,
            dir: hang_dir,
            ..fx.ctx(Duration::from_secs(300), &pre_sha)
        },
        &mut core.registry,
    );

    // The attempt whose finalize report will never be appendable.
    let pass = fx.spawn("pass", &[]).await;
    core.supervisor.adopt(
        pass,
        fx.ctx(Duration::from_secs(30), &pre_sha),
        &mut core.registry,
    );

    // Break the log. A freshly opened registry holds no append handle, so the file's mode decides.
    core.registry = Registry::open(fx.state_dir.path()).expect("reopen the registry");
    if !set_log_writable(&log, false) {
        eprintln!("skipped: the log's mode is not enforceable here");
        return;
    }

    let shutdown = CancellationToken::new();
    let _forwarder = spawn_signal_forwarder(sig_rx, mailbox.clone());
    let _ticks = spawn_tick_task(mailbox.clone(), TICK, shutdown.clone());
    let actor = tokio::spawn(run_actor(core, rx, shutdown.clone()));

    // Nobody cancels the token: the actor stops on its own, having given up on the log.
    tokio::time::timeout(LIMIT, actor)
        .await
        .expect("the actor never gave up on the unwritable log")
        .expect("the actor task did not panic");
    shutdown.cancel();

    // No polling loop and no grace of our own: `run_actor` has already returned, so the ladder is
    // over and the worker must be gone *now*. A deadline here would hide exactly the bug this test
    // exists for — a SIGKILL that fires (or does not) some time after the daemon has exited.
    let probe = PsProbe;
    assert!(
        !(probe.is_alive(hang_pid, &hang_start) && is_running_process(hang_pid)),
        "the worker outlived a fatal stop: pid {hang_pid} is still running"
    );

    // And nothing was invented about it on the way out. `abandon_all` takes no `Registry` at all,
    // which is the compile-time half of this; the log is the other half.
    assert!(set_log_writable(&log, true));
    let reg = Registry::open(fx.state_dir.path()).expect("reopen the registry");
    assert!(
        !events(&reg, &fx.run).iter().any(|event| matches!(
            &event.payload,
            EventPayload::AttemptFinished { attempt_id, .. } if *attempt_id == hang_attempt
        )),
        "a signalled worker gets no terminal event: the log could not be written"
    );
    assert_eq!(
        reg.attempt(&hang_attempt).map(|a| a.status),
        Some(AttemptStatus::Running),
        "it is left exactly as the last writable append saw it"
    );
}
