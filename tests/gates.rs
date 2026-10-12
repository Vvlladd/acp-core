//! `src/core/gates.rs` (T29): the gate lifecycle against a **real** git repository —
//! `reports/03-design.md` § Test Strategy, row `core/gates.rs`.
//!
//! Two properties are worth more than the rest and every test here exists to pin one of them:
//!
//! * **S2, approval authority** — an MCP `resolve_gate{approve:true}` on an `integrate` gate is
//!   rejected, and the rejection is paired with its positive controls (the same call with
//!   `gates.allowAgentApprove`, the same call over the socket, the same call as a denial) so a
//!   green test cannot mean "the fixture was broken".
//! * **Exactly-once commit** — asserted against `git log`, not against the projection: a second
//!   resolution must leave the commit count unchanged, and exactly one commit in the repository may
//!   ever carry a given `Acp-Gate-Id` trailer. The commit message is read back with the real
//!   `git log -1 --format=%B`.
//!
//! The write-then-act ordering is checked the only way it can be checked from outside: after
//! `begin_resolve` returns, `gate.resolving` is already in the log **and** `git log` has not grown —
//! the event is on disk before any git call, which is what makes the crash window recoverable.
//!
//! Every fixture is a `tempfile::TempDir`: one for the state dir, one for the repository (with
//! `user.name`/`user.email` set locally, because `git.rs` clears the child environment). Nothing is
//! written into the repo under test. Helpers are local to this file rather than shared, so this
//! suite has no build-order coupling to the other integration tests.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use agent_control_plane::core::gates::{
    self, CommitPlan, CoreError, GatePayload, GateResolution, NewGate, ResolveOutcome,
    TRAILER_GATE_ID,
};
use agent_control_plane::core::policy::PolicyCode;
use agent_control_plane::core::r#loop::reattach_running;
use agent_control_plane::core::registry::Registry;
use agent_control_plane::core::supervisor::{ProcessProbe, Supervisor, SupervisorSignal};
use agent_control_plane::core::types::{
    Actor, AgentId, AttemptId, AttemptKind, CommitTarget, Defaults, EventPayload, Gate, GateId,
    GateKind, GateStatus, GatesConfig, Limits, LineageId, Origin, ProviderName, RoleName,
    RolesConfig, Run, RunId, RunStatus, Task, ViolationKind,
};
use agent_control_plane::workspace::git::{
    self, GitError, FROZEN_DIFF_TRUNCATION_MARKER, MAX_FROZEN_DIFF_BYTES,
};
use tempfile::TempDir;

const SHA: &str = "1111111111111111111111111111111111111111";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Runs an async body on a thread of its own, with a runtime of its own, and returns its value.
///
/// The fixtures below are synchronous but freezing a diff is not, and half of these tests already
/// run inside [`block_on`] — starting a second runtime on a thread that is already inside one
/// panics. A fresh thread has no runtime, so this works from either side.
fn run_async<F, Fut, T>(f: F) -> T
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = T>,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(f())
    })
    .join()
    .expect("the helper thread panicked")
}

/// A fresh per-worktree lock. Every test here drives one commit at a time, so an uncontended mutex
/// is the whole of what the helper's serialization means from outside. `run_commit` takes it owned,
/// because an interrupted approval hands the lock to the cleanup it spawns.
fn lock() -> std::sync::Arc<tokio::sync::Mutex<()>> {
    std::sync::Arc::new(tokio::sync::Mutex::new(()))
}

/// A replayed attempt whose recorded process is already gone. The first supervisor tick therefore
/// starts finalization immediately, without a real pid or timing race in the test.
struct Gone;

impl ProcessProbe for Gone {
    fn is_alive(&self, _pid: i32, _start_time: &str) -> bool {
        false
    }

    fn start_time(&self, _pid: i32) -> Option<String> {
        None
    }
}

fn block_on<Fut: Future<Output = ()>>(fut: Fut) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(fut);
}

/// Runs real git in `cwd` and returns its stdout, asserting success.
fn run_git(cwd: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|err| panic!("spawn git {args:?}: {err}"));
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A fresh repository with an identity configured (`commit_all` runs a real commit and clears the
/// child environment, so the identity has to be repo-local) and one empty commit.
fn init_repo() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    run_git(dir.path(), &["init", "--quiet", "-b", "main"]);
    run_git(dir.path(), &["config", "user.name", "acp-test"]);
    run_git(
        dir.path(),
        &["config", "user.email", "acp-test@example.invalid"],
    );
    run_git(
        dir.path(),
        &["commit", "--quiet", "--allow-empty", "-m", "init"],
    );
    dir
}

fn task() -> Task {
    Task {
        id: "T29".into(),
        title: "tests/gates.rs".into(),
        description: "gate lifecycle against a real git repository".into(),
        files: vec!["tests/gates.rs".into()],
        acceptance: vec!["cargo test --test gates exits 0".into()],
    }
}

/// The shipped `roles.json` numbers; only `gates.allowAgentApprove` matters to
/// `check_gate_resolve`, so it is the one knob the tests vary.
fn roles_cfg(allow_agent_approve: bool) -> RolesConfig {
    RolesConfig {
        version: 1,
        rates_updated: "2026-08-22".into(),
        gates: GatesConfig {
            allow_agent_approve,
        },
        limits: Limits {
            max_concurrent_attempts: 2,
        },
        defaults: Defaults {
            base_ref: "HEAD".into(),
            max_depth: 2,
            run_budget_usd: 15.0,
            spawn_budget_usd: 2.0,
            attempt_timeout_sec: 1800,
            await_result_max_sec: 300,
            strikes_before_replacement: 2,
            max_lineages: 2,
            denylist_globs: Vec::new(),
        },
        rates: HashMap::new(),
        providers: BTreeMap::new(),
        roles: HashMap::new(),
    }
}

/// A state dir, a repository standing in for the worktree, and a registry with one run created.
struct World {
    state: TempDir,
    repo: TempDir,
    registry: Registry,
    run: RunId,
    /// What [`World::dirty`] has changed so far — the change set an integrate gate is opened over,
    /// and therefore the exact set its approval stages.
    dirty_files: Vec<String>,
    /// sha256 of the frozen diff the last integrate gate was opened over (Rev 25). An approval
    /// re-freezes the worktree and refuses to commit unless it still hashes to this.
    diff_hash: String,
}

impl World {
    fn new() -> Self {
        let state = tempfile::tempdir().expect("tempdir");
        let repo = init_repo();
        let mut registry = Registry::open(state.path()).expect("open registry");
        let run = RunId::new_v4();
        registry
            .append(
                &run,
                EventPayload::RunCreated {
                    execution: None,
                    repo_root: repo.path().to_path_buf(),
                    state_dir: state.path().to_path_buf(),
                    base_ref: "HEAD".into(),
                    base_sha: SHA.into(),
                    task: task(),
                    version: 1,
                    lead: Some("claude".into()),
                    team_name: None,
                    steps: None,
                },
            )
            .expect("run.created");
        Self {
            state,
            repo,
            registry,
            run,
            dirty_files: Vec::new(),
            diff_hash: String::new(),
        }
    }

    fn worktree(&self) -> PathBuf {
        self.repo.path().to_path_buf()
    }

    /// Leaves an uncommitted change in the worktree, so an integrate commit has something to make.
    ///
    /// The name is recorded: an approval stages the reviewed change set and nothing else, so the
    /// gate's `files` has to be what is actually there rather than a plausible-looking constant.
    fn dirty(&mut self, name: &str) {
        let path = self.worker_path(name);
        std::fs::create_dir_all(path.parent().expect("under src/")).expect("mkdir");
        std::fs::write(path, "work\n").expect("write");
        let repo_relative = format!("src/{name}");
        if !self.dirty_files.contains(&repo_relative) {
            self.dirty_files.push(repo_relative);
        }
    }

    /// Changes a file the gate was opened over, *after* it was opened — a worker resumed by a
    /// second `send_message`, or a human editing while the gate waits.
    fn touch_after_review(&self, name: &str) {
        std::fs::write(self.worker_path(name), "different work\n").expect("write");
    }

    /// Where a worker's file lives. Under `src/` so the reviewed set is a real repo-relative path
    /// with a directory component, which is what an approval has to stage.
    fn worker_path(&self, name: &str) -> PathBuf {
        self.repo.path().join("src").join(name)
    }

    fn head(&self) -> String {
        run_git(self.repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string()
    }

    fn diff_path(&self) -> PathBuf {
        self.state.path().join("diffs").join("frozen.patch")
    }

    /// Freezes the worktree exactly as the loop does and records the hash, so the gate this backs
    /// carries a real binding rather than a placeholder.
    fn freeze(&mut self) -> String {
        let worktree = self.repo.path().to_path_buf();
        let out = self.diff_path();
        let hash = run_async(move || async move {
            git::frozen_diff(&worktree, &out)
                .await
                .expect("freeze the worktree")
                .diff_hash
        });
        self.diff_hash.clone_from(&hash);
        hash
    }

    /// An `integrate` gate whose payload names the repository as its worktree.
    fn integrate_gate(&mut self, summary: &str) -> Gate {
        self.gate(GateKind::Integrate, summary, Some(self.worktree()))
    }

    /// An `integrate` gate whose payload also names the commit subject the loop wants — the task
    /// line — so the summary's first line (a review sentence) does not become the subject.
    fn integrate_gate_titled(&mut self, summary: &str, subject: &str) -> Gate {
        let worktree = Some(self.worktree());
        let (diff_hash, pre_sha, diff_path) = (
            Some(self.freeze()),
            Some(self.head()),
            Some(self.diff_path()),
        );
        gates::create_gate(
            &mut self.registry,
            &self.run,
            NewGate {
                kind: GateKind::Integrate,
                summary: summary.into(),
                requested_by: Origin::ControlPlane,
                payload: GatePayload {
                    worktree,
                    files: self.dirty_files.clone(),
                    diff_hash,
                    pre_sha,
                    diff_path,
                    subject: Some(subject.to_string()),
                    ..GatePayload::default()
                },
            },
        )
        .expect("create titled gate")
    }

    fn gate(&mut self, kind: GateKind, summary: &str, worktree: Option<PathBuf>) -> Gate {
        // An `integrate` gate is opened over a frozen diff, and its payload carries what binds an
        // approval to it: the hash, the commit it was taken against, and the file it was written
        // to. A gate with no worktree commits nothing, so it needs none of that.
        let (diff_hash, pre_sha, diff_path) = if worktree.is_some() {
            (
                Some(self.freeze()),
                Some(self.head()),
                Some(self.diff_path()),
            )
        } else {
            (None, None, None)
        };
        gates::create_gate(
            &mut self.registry,
            &self.run,
            NewGate {
                kind,
                summary: summary.into(),
                requested_by: Origin::ControlPlane,
                payload: GatePayload {
                    worktree,
                    files: self.dirty_files.clone(),
                    diff_hash,
                    pre_sha,
                    diff_path,
                    spend_usd: 0.42,
                    ..GatePayload::default()
                },
            },
        )
        .expect("create gate")
    }

    /// Replays the state dir from disk — what a restart does.
    fn reopen(&mut self) {
        self.registry = Registry::open(self.state.path()).expect("reopen registry");
    }

    fn gate_now(&self, gate: &Gate) -> Gate {
        self.registry
            .gate(&gate.gate_id)
            .cloned()
            .unwrap_or_else(|| panic!("gate {} is in the projection", gate.gate_id))
    }

    fn run_now(&self) -> &Run {
        self.registry.run(&self.run).expect("run")
    }

    /// The `kind` tag of every event in the run's log, in order.
    fn kinds(&self) -> Vec<String> {
        self.registry
            .events(&self.run, None, usize::MAX)
            .iter()
            .map(|e| {
                serde_json::to_value(e.as_ref()).expect("encode event")["kind"]
                    .as_str()
                    .expect("kind tag")
                    .to_string()
            })
            .collect()
    }

    fn count_kind(&self, kind: &str) -> usize {
        self.kinds().iter().filter(|k| *k == kind).count()
    }

    /// How many commits the repository has, read the way a human would.
    fn commits(&self) -> usize {
        run_git(self.repo.path(), &["log", "--oneline"])
            .lines()
            .count()
    }

    /// How many commits carry `Acp-Gate-Id: <gate>` — the exactly-once assertion.
    fn commits_for_gate(&self, gate: &Gate) -> usize {
        run_git(
            self.repo.path(),
            &[
                "log",
                "--all",
                "--format=%H",
                &format!("--grep=^{TRAILER_GATE_ID}: {}$", gate.gate_id),
            ],
        )
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count()
    }
}

/// Unwraps the `Commit` arm, failing loudly on `Settled`.
fn expect_commit(outcome: ResolveOutcome) -> CommitPlan {
    match outcome {
        ResolveOutcome::Commit(plan) => *plan,
        ResolveOutcome::Settled(r) => panic!("expected a commit plan, got {r:?}"),
    }
}

fn expect_settled(outcome: ResolveOutcome) -> GateResolution {
    match outcome {
        ResolveOutcome::Settled(r) => r,
        ResolveOutcome::Commit(plan) => panic!("expected a settled gate, got {plan:?}"),
    }
}

fn pending_ids(w: &World, run: Option<&RunId>) -> Vec<GateId> {
    gates::pending_gates(&w.registry, run)
        .iter()
        .map(|g| g.gate_id)
        .collect()
}

fn cli() -> Actor {
    Actor::Socket {
        client_name: "cli".into(),
    }
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

#[test]
fn create_gate_writes_its_payload_then_announces_it() {
    let mut w = World::new();
    w.dirty("adder.ts");
    let gate = w.integrate_gate("integrate lineage 1");

    assert_eq!(gate.status, GateStatus::Pending);
    assert_eq!(gate.kind, GateKind::Integrate);
    assert_eq!(gate.run_id, w.run);
    assert!(gate.resolved_at.is_none());
    assert!(gate.resolved_by.is_none());

    // The event names a path that already exists — the file is written before it is announced.
    assert!(
        gate.payload_path.is_file(),
        "payload at {}",
        gate.payload_path.display()
    );
    assert_eq!(
        gate.payload_path,
        w.state
            .path()
            .join("runs")
            .join(w.run.to_string())
            .join("gates")
            .join(format!("{}.payload.json", gate.gate_id))
    );

    let payload: GatePayload =
        serde_json::from_slice(&std::fs::read(&gate.payload_path).expect("read payload"))
            .expect("parse payload");
    assert_eq!(payload.worktree, Some(w.worktree()));
    assert_eq!(payload.files, vec!["src/adder.ts".to_string()]);

    assert_eq!(w.kinds(), vec!["run.created", "gate.created"]);
    assert_eq!(w.run_now().gate_ids, vec![gate.gate_id]);
}

#[test]
fn create_gate_refuses_a_run_the_projection_has_never_seen() {
    let mut w = World::new();
    let err = gates::create_gate(
        &mut w.registry,
        &RunId::new_v4(),
        NewGate {
            kind: GateKind::Integrate,
            summary: "orphan".into(),
            requested_by: Origin::Lead,
            payload: GatePayload::default(),
        },
    )
    .expect_err("unknown run");
    assert!(matches!(err, CoreError::UnknownRun(_)), "{err:?}");
    assert_eq!(w.kinds(), vec!["run.created"]);
}

#[test]
fn pending_gates_lists_only_unresolved_gates_for_the_run() {
    let mut w = World::new();
    let first = w.integrate_gate("first");
    let second = w.gate(GateKind::Escalate, "second", None);

    // Both are pending. Their relative order is `(createdAt, gateId)` and two gates minted in the
    // same millisecond tie on `createdAt`, so this asserts membership rather than a coin flip.
    let pending = pending_ids(&w, Some(&w.run));
    assert_eq!(pending.len(), 2);
    assert!(pending.contains(&first.gate_id), "{pending:?}");
    assert!(pending.contains(&second.gate_id), "{pending:?}");

    // Deny the first; it leaves the pending list.
    gates::begin_resolve(
        &mut w.registry,
        &first.gate_id,
        false,
        None,
        Actor::Mcp,
        &roles_cfg(false),
    )
    .expect("deny");

    assert_eq!(pending_ids(&w, Some(&w.run)), vec![second.gate_id]);
    assert!(gates::pending_gates(&w.registry, Some(&RunId::new_v4())).is_empty());
    assert_eq!(gates::pending_gates(&w.registry, None).len(), 1);
}

// ---------------------------------------------------------------------------
// Happy path: create → pending → resolve → approved
// ---------------------------------------------------------------------------

#[test]
fn a_socket_approval_commits_once_with_the_gate_id_trailer() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T29");
        let before = w.commits();

        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("socket approve"),
        );

        // Write-then-act: `gate.resolving` is on disk and git has not been called yet.
        assert_eq!(
            w.kinds(),
            vec!["run.created", "gate.created", "gate.resolving"]
        );
        assert_eq!(w.commits(), before, "no commit before the helper runs");
        let resolving = w.gate_now(&gate);
        assert_eq!(resolving.status, GateStatus::Resolving);
        assert_eq!(resolving.approve, Some(true));
        assert_eq!(resolving.resolved_by, Some(cli()));

        let sha = gates::run_commit(&plan, lock()).await.expect("commit");
        let resolution = gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha.clone()))
            .expect("finish")
            .expect("approved");
        assert_eq!(
            resolution,
            GateResolution::Approved {
                sha: Some(sha.clone())
            }
        );

        // The repository, read the way a human reads it.
        assert_eq!(w.commits(), before + 1);
        let body = run_git(w.repo.path(), &["log", "-1", "--format=%B"]);
        assert!(
            body.contains(&format!("Acp-Gate-Id: {}", gate.gate_id)),
            "gate trailer missing: {body:?}"
        );
        assert!(
            body.contains(&format!("Acp-Run-Id: {}", w.run)),
            "run trailer missing: {body:?}"
        );
        assert!(body.starts_with("acp: integrate T29"), "{body:?}");
        assert_eq!(w.commits_for_gate(&gate), 1);

        // The log, and the projection it produces.
        assert_eq!(
            w.kinds(),
            vec![
                "run.created",
                "gate.created",
                "gate.resolving",
                "integrate.committed",
                "gate.resolved",
            ],
            "the commit is recorded before the gate's verdict"
        );
        let approved = w.gate_now(&gate);
        assert_eq!(approved.status, GateStatus::Approved);
        assert_eq!(approved.sha, Some(sha.clone()));
        assert!(approved.resolved_at.is_some());
        assert_eq!(
            approved.resolved_by,
            Some(cli()),
            "resolvedBy is the socket clientName"
        );
        assert_eq!(w.run_now().integrated_sha, Some(sha));

        let committed = w
            .registry
            .events(&w.run, None, usize::MAX)
            .into_iter()
            .find_map(|e| match &e.payload {
                EventPayload::IntegrateCommitted {
                    worktree,
                    subject,
                    files,
                    ..
                } => Some((worktree.clone(), subject.clone(), files.clone())),
                _ => None,
            })
            .expect("integrate.committed");
        assert_eq!(committed.0, w.worktree());
        assert_eq!(committed.1, "acp: integrate T29");
        assert_eq!(committed.2, vec!["src/adder.ts".to_string()]);
    });
}

// ---------------------------------------------------------------------------
// S2: approval authority
// ---------------------------------------------------------------------------

#[test]
fn mcp_may_not_approve_an_integrate_gate() {
    let mut w = World::new();
    w.dirty("adder.ts");
    let gate = w.integrate_gate("integrate T29");
    let before = w.commits();

    let err = gates::begin_resolve(
        &mut w.registry,
        &gate.gate_id,
        true,
        None,
        Actor::Mcp,
        &roles_cfg(false),
    )
    .expect_err("S2 rejects an agent approval");

    match err {
        CoreError::Policy(e) => assert_eq!(e.code, PolicyCode::AgentApproveNotAllowed),
        other => panic!("expected a policy rejection, got {other:?}"),
    }

    // Fail closed, no side effects: nothing written, nothing committed, gate still pending.
    assert_eq!(w.kinds(), vec!["run.created", "gate.created"]);
    assert_eq!(w.commits(), before);
    assert_eq!(w.gate_now(&gate).status, GateStatus::Pending);
}

#[test]
fn mcp_may_approve_an_integrate_gate_when_the_config_allows_it() {
    let mut w = World::new();
    w.dirty("adder.ts");
    let gate = w.integrate_gate("integrate T29");

    let plan = expect_commit(
        gates::begin_resolve(
            &mut w.registry,
            &gate.gate_id,
            true,
            None,
            Actor::Mcp,
            &roles_cfg(true),
        )
        .expect("allowAgentApprove opens the door"),
    );
    assert_eq!(plan.gate_id, gate.gate_id);
    assert_eq!(w.gate_now(&gate).resolved_by, Some(Actor::Mcp));
}

#[test]
fn mcp_may_always_deny_and_the_denial_never_touches_git() {
    let mut w = World::new();
    w.dirty("adder.ts");
    let gate = w.integrate_gate("integrate T29");
    let before = w.commits();

    let resolution = expect_settled(
        gates::begin_resolve(
            &mut w.registry,
            &gate.gate_id,
            false,
            Some("the diff drops the error path".into()),
            Actor::Mcp,
            &roles_cfg(false),
        )
        .expect("deny"),
    );
    assert_eq!(
        resolution,
        GateResolution::Denied {
            feedback: Some("the diff drops the error path".into())
        }
    );

    assert_eq!(w.commits(), before, "a denial makes no commit");
    let denied = w.gate_now(&gate);
    assert_eq!(denied.status, GateStatus::Denied);
    assert_eq!(denied.approve, Some(false));
    assert_eq!(denied.resolved_by, Some(Actor::Mcp));
    assert_eq!(
        denied.feedback,
        Some("the diff drops the error path".into())
    );
    assert!(denied.sha.is_none());
    assert_eq!(w.count_kind("gate.resolved"), 1);
    assert_eq!(w.count_kind("integrate.committed"), 0);
}

#[test]
fn a_socket_approval_of_an_escalate_gate_without_a_worktree_is_refused_before_any_write() {
    let mut w = World::new();
    let gate = w.gate(GateKind::Escalate, "two lineages struck out", None);

    let err = gates::begin_resolve(
        &mut w.registry,
        &gate.gate_id,
        true,
        None,
        cli(),
        &roles_cfg(false),
    )
    .expect_err("nothing to commit");
    assert!(matches!(err, CoreError::NoWorktree(_)), "{err:?}");

    assert_eq!(w.kinds(), vec!["run.created", "gate.created"]);
    assert_eq!(w.gate_now(&gate).status, GateStatus::Pending);
}

#[test]
fn resolving_an_unknown_gate_is_an_error() {
    let mut w = World::new();
    let err = gates::begin_resolve(
        &mut w.registry,
        &GateId::new_v4(),
        false,
        None,
        cli(),
        &roles_cfg(false),
    )
    .expect_err("unknown gate");
    assert!(matches!(err, CoreError::UnknownGate(_)), "{err:?}");
}

// ---------------------------------------------------------------------------
// The approval is bound to the reviewed diff (Rev 25, Codex review of T35)
// ---------------------------------------------------------------------------

/// The hole this closes: a `PASS` is checked against `diff.frozen{diffHash}` when the gate opens,
/// but the gate then waits for a human while the worktree stays writable. Anything changed in
/// between used to ride into the integration under that PASS.
#[test]
fn a_worktree_changed_after_review_is_never_committed() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T35");
        let before = w.commits();

        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );

        // The human is still reading the diff; the worktree moves under them.
        w.touch_after_review("adder.ts");

        let err = gates::run_commit(&plan, lock())
            .await
            .expect_err("the bytes changed");
        let GitError::Failed { op, message, .. } = &err else {
            panic!("expected a refusal, got {err:?}");
        };
        assert_eq!(*op, "verify_frozen_diff");
        assert!(
            message.starts_with("worktree changed since review: expected "),
            "{message}"
        );
        assert!(message.contains(&w.diff_hash), "{message}");

        assert_eq!(w.commits(), before, "nothing was committed");

        // The refusal travels the failed-commit path: the run is blocked with the reason, the gate
        // stays `resolving`, and no `integrate.committed` was ever written.
        assert!(
            gates::finish_commit(&mut w.registry, &gate.gate_id, Err(err))
                .expect("finish")
                .is_none()
        );
        assert_eq!(w.run_now().status, RunStatus::Blocked);
        let reason = w.run_now().blocked_reason.clone().expect("a reason");
        assert!(reason.contains("worktree changed since review"), "{reason}");
        assert_eq!(w.count_kind("integrate.committed"), 0);
        assert_eq!(w.gate_now(&gate).status, GateStatus::Resolving);
    });
}

/// The same guard against the other way a worktree stops matching its diff: HEAD moved, so
/// `git diff HEAD` would be measuring against a different commit entirely.
#[test]
fn a_commit_made_after_review_is_reported_as_a_moved_head() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T35");
        let before = w.commits();

        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );

        let pre_sha = w.head();
        run_git(w.repo.path(), &["add", "-A"]);
        run_git(w.repo.path(), &["commit", "-m", "the worker committed"]);

        let err = gates::run_commit(&plan, lock())
            .await
            .expect_err("HEAD moved");
        let GitError::Failed { op, message, .. } = &err else {
            panic!("expected a refusal, got {err:?}");
        };
        assert_eq!(*op, "verify_frozen_diff");
        assert!(message.contains("HEAD moved since review"), "{message}");
        assert!(message.contains(&pre_sha), "{message}");
        assert_eq!(w.commits(), before + 1, "only the worker's own commit");
        assert_eq!(w.commits_for_gate(&gate), 0, "no integration commit");
    });
}

/// An unchanged worktree commits exactly as before — the positive control for the two refusals
/// above, and the assertion that verification does not rewrite the artifact a human reads.
#[test]
fn an_unchanged_worktree_still_commits_and_leaves_the_reviewed_diff_alone() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T35");
        let reviewed = std::fs::read(w.diff_path()).expect("the reviewed diff");

        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );
        let sha = gates::run_commit(&plan, lock()).await.expect("commit");
        gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha)).expect("finish");

        assert_eq!(w.commits_for_gate(&gate), 1);
        assert_eq!(w.gate_now(&gate).status, GateStatus::Approved);
        assert_eq!(
            std::fs::read(w.diff_path()).expect("still there"),
            reviewed,
            "the re-freeze writes beside the reviewed diff, never over it"
        );
        assert!(
            w.diff_path().with_extension("patch.verify").exists(),
            "the re-frozen copy is kept for the audit trail"
        );
    });
}

/// The reviewed path set is what is staged, and the **whole** of it: an approval that would commit
/// less than the reviewer saw is refused.
///
/// `git add -A -- .` is gone, and with it the idea that the commit is "whatever is in the worktree".
/// The staged change set has to be the reviewed one exactly — a subset is as wrong as a superset,
/// because a reviewer passed a diff, not a pile of files.
#[test]
fn a_staged_set_that_is_not_the_reviewed_one_is_refused() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        w.dirty("helper.ts");
        let gate = w.integrate_gate("integrate T35");

        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );
        assert_eq!(
            plan.target.files,
            vec!["src/adder.ts".to_string(), "src/helper.ts".to_string()],
            "the fixture froze both"
        );

        let narrowed = CommitPlan {
            target: CommitTarget {
                files: vec!["src/adder.ts".to_string()],
                ..plan.target.clone()
            },
            ..plan
        };
        let err = gates::run_commit(&narrowed, lock())
            .await
            .expect_err("half a review is not a review");
        let GitError::Failed { op, message, .. } = &err else {
            panic!("expected a refusal, got {err:?}");
        };
        // The hash is what catches it, and that is the point: the reviewed *diff* covered two files,
        // so an index holding one of them is not the object the reviewer passed, whatever the gate's
        // own path list says.
        assert_eq!(*op, "verify_frozen_diff");
        assert!(
            message.starts_with("worktree changed since review: expected "),
            "{message}"
        );
        assert!(message.contains(&w.diff_hash), "{message}");

        assert_eq!(w.commits_for_gate(&gate), 0);
        // …and the index it touched is put back the way it was found.
        assert!(
            run_git(w.repo.path(), &["diff", "--cached", "--name-only"])
                .trim()
                .is_empty(),
            "a refused approval leaves nothing staged"
        );
    });
}

/// A run in which the worker committed can still be integrated.
///
/// Step 10's remediation — undo the forbidden commit, keep the work — used to leave the worker's
/// tree staged, and an approval refuses to commit on top of a dirty index. Every such run could
/// therefore be built, reviewed and passed, and then never integrated: the gate stuck `resolving`
/// for ever, re-refused on every restart (round-3 review, finding 1).
#[test]
fn a_run_whose_worker_committed_still_integrates() {
    block_on(async {
        let mut w = World::new();
        let pre_sha = w.head();

        // The worker does the forbidden thing.
        w.dirty("adder.ts");
        run_git(w.repo.path(), &["add", "-A"]);
        run_git(
            w.repo.path(),
            &["commit", "--quiet", "-m", "the worker committed"],
        );
        assert_ne!(w.head(), pre_sha);

        // …and the control plane undoes it, exactly as `finalize_prepare` does.
        git::reset_mixed(w.repo.path(), &pre_sha)
            .await
            .expect("undo the worker commit");
        assert_eq!(w.head(), pre_sha, "HEAD is back at the attempt's preSha");

        // From here the run is an ordinary one: freeze, gate, approve, commit.
        let gate = w.integrate_gate("integrate a run the worker committed in");
        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );
        let sha = gates::run_commit(&plan, lock())
            .await
            .expect("the remediation must not block the integration");
        gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha)).expect("finish");

        assert_eq!(w.commits_for_gate(&gate), 1);
        assert_eq!(w.gate_now(&gate).status, GateStatus::Approved);
    });
}

/// A restart must reattach finalization to the very same mutex an integrate helper obtains from
/// the supervisor. While an approval owns it, even a real worker-commit remediation waits: it does
/// not inspect the approval's index, reset its HEAD, or spend its finalize timeout waiting and
/// manufacture a workspace failure against the worker.
#[tokio::test]
async fn reattached_finalize_waits_for_the_supervisors_held_worktree_lock() {
    let mut w = World::new();
    let pre_sha = w.head();
    let agent = AgentId::new_v4();
    let attempt_id = AttemptId::new_v4();
    let attempt_dir = w
        .state
        .path()
        .join("runs")
        .join(w.run.to_string())
        .join("attempts")
        .join(attempt_id.to_string());
    std::fs::create_dir_all(&attempt_dir).expect("attempt dir");
    std::fs::write(attempt_dir.join("stdout.jsonl"), b"").expect("empty transcript");

    w.registry
        .append(
            &w.run,
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
                cwd: w.worktree(),
                worktree: Some(w.worktree()),
            },
        )
        .expect("agent.created");
    w.registry
        .append(
            &w.run,
            EventPayload::AttemptStarted {
                attempt_id,
                agent_id: agent,
                attempt_kind: AttemptKind::Fresh,
                dir: attempt_dir,
                argv: vec!["claude".into(), "-p".into()],
                cwd: w.worktree(),
                pid: 4242,
                pgid: 4242,
                start_time: "recorded process has exited".into(),
                pre_sha: pre_sha.clone(),
                timeout_sec: 1800,
                spawn_budget_usd: 2.0,
            },
        )
        .expect("attempt.started");

    // The exited worker made the forbidden commit that finalization must undo after serialization.
    w.dirty("worker-commit.ts");
    run_git(w.repo.path(), &["add", "-A"]);
    run_git(
        w.repo.path(),
        &["commit", "--quiet", "-m", "the reattached worker committed"],
    );
    let worker_sha = w.head();
    assert_ne!(worker_sha, pre_sha);

    let (tx, mut signals) = tokio::sync::mpsc::channel(8);
    let mut supervisor = Supervisor::new(Duration::from_millis(25), Arc::new(Gone), tx);
    let shared = supervisor.worktree_lock(&w.worktree());
    let held_by_approval = Arc::clone(&shared).lock_owned().await;

    // This is the production restart constructor. It must fetch the AttemptContext's Arc from the
    // existing supervisor pool, not mint a second lock for the same recorded path.
    reattach_running(&mut supervisor, &w.registry, &roles_cfg(false));
    assert!(
        Arc::ptr_eq(&shared, &supervisor.worktree_lock(&w.worktree())),
        "the restart kept one Arc for the recorded worktree"
    );
    supervisor.tick(&mut w.registry).await;

    let exited = tokio::time::timeout(Duration::from_secs(1), signals.recv())
        .await
        .expect("exit wake-up")
        .expect("signal channel");
    assert!(
        matches!(exited, SupervisorSignal::AttemptExited { attempt, .. } if attempt == attempt_id),
        "unexpected first signal: {exited:?}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(150), signals.recv())
            .await
            .is_err(),
        "finalization finished while the integrate lock was held"
    );
    assert_eq!(
        w.head(),
        worker_sha,
        "remediation did not reset HEAD underneath the approval"
    );

    drop(held_by_approval);
    let report = loop {
        let signal = tokio::time::timeout(Duration::from_secs(5), signals.recv())
            .await
            .expect("finalize after releasing the lock")
            .expect("signal channel");
        if let SupervisorSignal::FinalizeReady { report, .. } = signal {
            break report;
        }
    };
    assert_eq!(
        w.head(),
        pre_sha,
        "the worker commit was remediated afterwards"
    );
    assert!(report.events().iter().any(|event| {
        matches!(
            event,
            EventPayload::PolicyViolated { violation, .. }
                if violation.kind == ViolationKind::WorkerCommitted
        )
    }));
}

/// An index that already holds something is refused before anything is staged: whatever was in it
/// was never reviewed, and `git commit` would write it.
#[test]
fn a_pre_staged_change_is_refused_before_anything_else() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T35");

        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );

        // Somebody stages an unrelated file while the gate waits for its human.
        std::fs::write(w.repo.path().join("unreviewed.txt"), "not reviewed\n").expect("write");
        run_git(w.repo.path(), &["add", "--", "unreviewed.txt"]);

        let err = gates::run_commit(&plan, lock())
            .await
            .expect_err("a dirty index may not be committed");
        let GitError::Failed { op, message, .. } = &err else {
            panic!("expected a refusal, got {err:?}");
        };
        assert_eq!(*op, "verify_index");
        assert!(
            message.contains("already holds staged changes"),
            "{message}"
        );
        assert_eq!(w.commits_for_gate(&gate), 0);
    });
}

/// An approval that is interrupted **while git is writing the index** leaves the worktree as it
/// found it: nothing staged, and no lock file behind.
///
/// Everything before the commit is `await`ed, so the future can be dropped at any of those points —
/// a cancelled task, a lost `select!`, a timeout wrapped around the helper. A dropped future runs
/// no more of its own code, so without a `Drop` guard the reviewed paths would be left staged, and
/// that is exactly the state the *next* approval refuses to commit on top of: one interruption would
/// wedge the gate for good (round-3 review, finding 3).
///
/// The interruption is aimed rather than approximate. `.git/index.lock` exists **only** while a git
/// that writes the index holds it, so waiting for it and aborting then puts the drop inside the one
/// window that matters: a `kill_on_drop` SIGKILL there used to orphan the lock, and a stale
/// `index.lock` fails every later index write in that worktree — the cleanup's own `git reset`
/// first, and then anything the human types (round-4 review, follow-up to finding 5). The three
/// assertions after the abort are the three ways that showed up: paths left staged, a lock left
/// behind, and a worktree no ordinary git can write to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupted_approval_unstages_what_it_staged() {
    let mut w = World::new();
    // More files than one `git add` batch takes, so there is a wide, reliable window between the
    // first thing being staged and the commit: the abort below lands inside it every time.
    for n in 0..96 {
        w.dirty(&format!("file-{n:03}.ts"));
    }
    let gate = w.integrate_gate("integrate a change set big enough to catch mid-staging");
    let plan = expect_commit(
        gates::begin_resolve(
            &mut w.registry,
            &gate.gate_id,
            true,
            None,
            cli(),
            &roles_cfg(false),
        )
        .expect("approve"),
    );

    let repo = w.repo.path().to_path_buf();
    let committing = tokio::spawn(async move { gates::run_commit(&plan, lock()).await });

    // Interrupt the approval while a `git add` is **provably** mid-index-write: the lock file is
    // git's own statement that one is. Nothing else in this helper writes the index, so this is the
    // only moment an interruption can leave a mess.
    let index_lock = repo.join(".git").join("index.lock");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !index_lock.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "no `git add` ever held the index lock, so nothing was interrupted"
        );
        tokio::time::sleep(std::time::Duration::from_micros(100)).await;
    }
    committing.abort();
    let _ = committing.await;

    // The guard hands its cleanup to the runtime — and the cleanup waits for the staging it is
    // cleaning up after — so this is the one place a wait is honest.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if run_git(&repo, &["diff", "--cached", "--name-only"])
            .trim()
            .is_empty()
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the interrupted approval left {} staged",
            run_git(&repo, &["diff", "--cached", "--name-only"])
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // No orphaned lock: the `git add` that was in flight finished on its own rather than being
    // SIGKILLed halfway through writing the new index.
    assert!(
        !index_lock.exists(),
        "the interrupted approval left {} behind",
        index_lock.display()
    );
    // And the worktree is one an ordinary git can still write to — the human's, not just ours.
    // `run_git` asserts success, so this fails loudly on a stale lock.
    run_git(&repo, &["add", "--", "src/file-000.ts"]);
    run_git(&repo, &["reset", "--quiet", "--", "src/file-000.ts"]);

    // Nothing was committed, and the work is still in the worktree — unstaged, not discarded.
    assert_eq!(w.commits_for_gate(&gate), 0);
    assert!(
        repo.join("src/file-000.ts").exists(),
        "the work is still there"
    );
    assert!(
        run_git(&repo, &["status", "--porcelain", "--untracked-files=all"])
            .contains("?? src/file-000.ts"),
        "and untracked again, exactly as the approval found it"
    );
}

/// A repository with a clean filter integrates like any other.
///
/// The reviewer is shown the filtered bytes — what would actually be committed — and the approval
/// re-derives the same document from the index, so the two agree and the commit goes through. Before
/// the fix the review showed the raw file, the approval showed the filtered blob, and every run in
/// such a repository was refused with "worktree changed since review" (round-3 review, finding 2).
#[test]
fn a_repository_with_a_clean_filter_still_integrates() {
    block_on(async {
        let mut w = World::new();
        run_git(
            w.repo.path(),
            &["config", "filter.shout.clean", "tr a-z A-Z"],
        );
        std::fs::write(w.repo.path().join(".gitattributes"), "*.ptr filter=shout\n")
            .expect("write attributes");
        run_git(w.repo.path(), &["add", "-A"]);
        run_git(w.repo.path(), &["commit", "--quiet", "-m", "attributes"]);

        w.dirty("payload.ptr");
        let gate = w.integrate_gate("integrate through a clean filter");

        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );
        let sha = gates::run_commit(&plan, lock())
            .await
            .expect("a clean filter must not block the integration");
        gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha.clone())).expect("finish");

        assert_eq!(w.commits_for_gate(&gate), 1);
        // The committed blob is the filtered one, which is what the reviewer was shown.
        let committed = run_git(w.repo.path(), &["show", &format!("{sha}:src/payload.ptr")]);
        assert_eq!(committed, "WORK\n");
    });
}

/// When the two freezes disagree about a worktree nobody touched, the refusal says so.
///
/// "Worktree changed since review" is the usual reading of a hash mismatch and usually the right
/// one, but it is a false accusation when the bytes on disk are untouched and it is git's own
/// storage of them that differs. The reachable case is a file past the diff's inline cap under an
/// eol attribute: the review truncates the raw bytes and then normalizes what is left, while the
/// approval normalizes the whole blob and truncates that — same file, two documents. The control
/// plane cannot integrate either way, but it can tell the human where to look.
#[test]
fn a_disagreement_about_an_untouched_worktree_is_named_as_one() {
    block_on(async {
        let mut w = World::new();
        std::fs::write(w.repo.path().join(".gitattributes"), "*.txt text\n")
            .expect("write attributes");
        run_git(w.repo.path(), &["add", "-A"]);
        run_git(w.repo.path(), &["commit", "--quiet", "-m", "attributes"]);

        // Past `MAX_UNTRACKED_DIFF_BYTES` (256 KiB) raw, under it once the CRLFs are gone.
        std::fs::create_dir_all(w.repo.path().join("src")).expect("mkdir");
        std::fs::write(
            w.repo.path().join("src/huge.txt"),
            "line\r\n".repeat(50_000),
        )
        .expect("write");
        w.dirty_files.push("src/huge.txt".to_string());
        let gate = w.integrate_gate("integrate a file past the inline cap");

        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );
        // Nothing touches the worktree between the review and here.
        let err = gates::run_commit(&plan, lock())
            .await
            .expect_err("the two freezes disagree");
        let GitError::Failed { op, message, .. } = &err else {
            panic!("expected a refusal, got {err:?}");
        };
        assert_eq!(*op, "verify_frozen_diff");
        assert!(
            message.starts_with("the worktree still matches the review"),
            "the human must not be told the worker changed something: {message}"
        );
        assert!(message.contains(".gitattributes"), "{message}");
        assert_eq!(w.commits_for_gate(&gate), 0);
    });
}

/// End to end: the commit's own diff against `preSha` **is** the diff the reviewer was shown.
///
/// The strongest statement available from outside — it reads the finished commit out of the
/// repository with plain git and hashes it, rather than trusting anything the control plane says.
/// Tracked changes only, so git's commit-to-commit diff and the frozen diff are the same document.
#[test]
fn the_commit_is_byte_for_byte_the_reviewed_diff() {
    block_on(async {
        let mut w = World::new();
        // A tracked file to modify, so the reviewed diff has no synthetic new-file section in it.
        std::fs::create_dir_all(w.repo.path().join("src")).expect("mkdir");
        std::fs::write(
            w.repo.path().join("src/adder.ts"),
            "export const add = 0;\n",
        )
        .expect("write");
        run_git(w.repo.path(), &["add", "--", "src/adder.ts"]);
        run_git(w.repo.path(), &["commit", "--quiet", "-m", "base"]);

        std::fs::write(
            w.repo.path().join("src/adder.ts"),
            "export const add = 1;\n",
        )
        .expect("write");
        w.dirty_files.push("src/adder.ts".to_string());
        let gate = w.integrate_gate("integrate T35");
        let pre_sha = w.head();

        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );
        let sha = gates::run_commit(&plan, lock()).await.expect("commit");

        let committed = run_git(
            w.repo.path(),
            &["diff", "--no-color", "--no-renames", &pre_sha, &sha],
        );
        let hashed = {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(committed.as_bytes());
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            hashed, w.diff_hash,
            "the commit's diff against preSha must hash to the reviewed diffHash"
        );
    });
}

/// A gate whose payload cannot say which diff was reviewed is never committed — the fail-closed
/// half of the binding, for a `gate.resolving` written before the fields existed.
#[test]
fn a_gate_that_names_no_reviewed_diff_is_refused() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T35");
        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );

        let unbound = CommitPlan {
            target: CommitTarget {
                diff_hash: None,
                pre_sha: None,
                diff_path: None,
                ..plan.target.clone()
            },
            ..plan
        };
        let err = gates::run_commit(&unbound, lock())
            .await
            .expect_err("an unbound target may not commit");
        let GitError::Failed { op, message, .. } = &err else {
            panic!("expected a refusal, got {err:?}");
        };
        assert_eq!(*op, "verify_frozen_diff");
        assert!(message.contains("no reviewed diff"), "{message}");
        assert_eq!(w.commits_for_gate(&gate), 0);
    });
}

// ---------------------------------------------------------------------------
// Exactly-once
// ---------------------------------------------------------------------------

#[test]
fn a_second_resolution_of_an_approved_gate_makes_no_second_commit() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T29");

        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );
        let sha = gates::run_commit(&plan, lock()).await.expect("commit");
        gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha)).expect("finish");

        let commits = w.commits();
        let kinds = w.kinds();

        // Same door again, and the other door too: both bounce off the terminal status.
        for by in [cli(), Actor::Mcp] {
            let resolution = expect_settled(
                gates::begin_resolve(
                    &mut w.registry,
                    &gate.gate_id,
                    true,
                    None,
                    by,
                    &roles_cfg(true),
                )
                .expect("second resolution"),
            );
            assert_eq!(resolution, GateResolution::AlreadyResolved);
        }

        assert_eq!(w.commits(), commits, "git log --oneline is unchanged");
        assert_eq!(
            w.commits_for_gate(&gate),
            1,
            "exactly one commit for the gate"
        );
        assert_eq!(w.kinds(), kinds, "no second event either");
        assert_eq!(w.count_kind("integrate.committed"), 1);
    });
}

#[test]
fn a_second_door_racing_the_open_commit_window_is_already_resolved() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T29");

        // The socket approves; the commit helper has NOT run yet — the window is open.
        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("socket approve"),
        );
        assert_eq!(w.gate_now(&gate).status, GateStatus::Resolving);

        // MCP tries to deny the same gate mid-flight. Allowed by S2, refused by the window.
        let racer = expect_settled(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                false,
                Some("too late".into()),
                Actor::Mcp,
                &roles_cfg(false),
            )
            .expect("racing denial"),
        );
        assert_eq!(racer, GateResolution::AlreadyResolved);
        assert_eq!(
            w.kinds(),
            vec!["run.created", "gate.created", "gate.resolving"],
            "the racer wrote nothing"
        );

        let sha = gates::run_commit(&plan, lock()).await.expect("commit");
        gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha)).expect("finish");

        assert_eq!(w.count_kind("integrate.committed"), 1);
        assert_eq!(w.commits_for_gate(&gate), 1);
        assert_eq!(w.gate_now(&gate).status, GateStatus::Approved);
        assert_eq!(w.gate_now(&gate).resolved_by, Some(cli()));
    });
}

#[test]
fn a_failed_commit_blocks_the_run_and_leaves_the_gate_resolving() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T29");

        expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );

        let outcome = gates::finish_commit(
            &mut w.registry,
            &gate.gate_id,
            Err(GitError::Timeout {
                op: "commit_all",
                secs: 30,
            }),
        )
        .expect("finish");
        assert!(outcome.is_none(), "no resolution to report");

        assert_eq!(w.gate_now(&gate).status, GateStatus::Resolving);
        assert_eq!(w.run_now().status, RunStatus::Blocked);
        let reason = w.run_now().blocked_reason.clone().expect("reason");
        assert!(reason.contains("commit failed"), "{reason:?}");
        assert!(reason.contains(&gate.gate_id.to_string()), "{reason:?}");
        assert_eq!(w.count_kind("integrate.committed"), 0);

        // The human retries. The trailer lookup finds nothing, so the retry commits — once.
        let retry = expect_commit(
            gates::reconcile_gate(&mut w.registry, &gate.gate_id)
                .await
                .expect("reconcile")
                .expect("still resolving"),
        );
        let sha = gates::run_commit(&retry, lock()).await.expect("commit");
        gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha)).expect("finish");
        assert_eq!(w.gate_now(&gate).status, GateStatus::Approved);
        assert_eq!(w.commits_for_gate(&gate), 1);
    });
}

// ---------------------------------------------------------------------------
// Reconciliation after a crash inside the window
// ---------------------------------------------------------------------------

/// Simulates the crash: `gate.resolving` is on disk — carrying the commit target, exactly as
/// `begin_resolve` writes it — and `finish_commit` was never reached.
fn crash_after_resolving(w: &mut World, gate: &Gate) {
    w.registry
        .append(
            &w.run,
            EventPayload::GateResolving {
                gate_id: gate.gate_id,
                approve: true,
                feedback: None,
                by: cli(),
                commit: Some(CommitTarget {
                    worktree: w.worktree(),
                    subject: "acp: integrate T29".into(),
                    files: vec!["src/adder.ts".into()],
                    diff_hash: Some(w.diff_hash.clone()),
                    pre_sha: Some(w.head()),
                    diff_path: Some(w.diff_path()),
                }),
            },
        )
        .expect("gate.resolving");
    w.reopen();
    assert_eq!(
        w.gate_now(gate).status,
        GateStatus::Resolving,
        "the replayed gate is stuck in the window"
    );
}

#[test]
fn reconciliation_retries_the_commit_when_no_trailer_commit_exists() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T29");
        crash_after_resolving(&mut w, &gate);
        let before = w.commits();

        let plan = expect_commit(
            gates::reconcile_gate(&mut w.registry, &gate.gate_id)
                .await
                .expect("reconcile")
                .expect("gate needed reconciling"),
        );
        assert_eq!(w.commits(), before, "the lookup alone commits nothing");

        let sha = gates::run_commit(&plan, lock()).await.expect("commit");
        let resolution = gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha.clone()))
            .expect("finish")
            .expect("approved");
        assert_eq!(resolution, GateResolution::Approved { sha: Some(sha) });

        assert_eq!(w.commits(), before + 1);
        assert_eq!(w.commits_for_gate(&gate), 1);
        assert_eq!(w.gate_now(&gate).status, GateStatus::Approved);
    });
}

#[test]
fn reconciliation_finishes_from_the_trailer_without_a_second_commit() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T29");

        // The commit the lost helper had already made before the crash.
        run_git(w.repo.path(), &["add", "-A"]);
        run_git(
            w.repo.path(),
            &[
                "commit",
                "--quiet",
                "-m",
                &format!(
                    "acp: integrate T29\n\n{TRAILER_GATE_ID}: {}\nAcp-Run-Id: {}",
                    gate.gate_id, w.run
                ),
            ],
        );
        let expected = run_git(w.repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        crash_after_resolving(&mut w, &gate);
        let before = w.commits();

        let resolution = expect_settled(
            gates::reconcile_gate(&mut w.registry, &gate.gate_id)
                .await
                .expect("reconcile")
                .expect("gate needed reconciling"),
        );
        assert_eq!(
            resolution,
            GateResolution::Approved {
                sha: Some(expected.clone())
            }
        );

        assert_eq!(w.commits(), before, "reconciliation made no second commit");
        assert_eq!(w.commits_for_gate(&gate), 1);
        let approved = w.gate_now(&gate);
        assert_eq!(approved.status, GateStatus::Approved);
        assert_eq!(approved.sha, Some(expected.clone()));
        assert_eq!(w.run_now().integrated_sha, Some(expected));
        assert_eq!(w.count_kind("integrate.committed"), 1);
    });
}

#[test]
fn reconciliation_leaves_a_gate_that_is_not_resolving_alone() {
    block_on(async {
        let mut w = World::new();
        let gate = w.integrate_gate("integrate T29");

        assert!(
            gates::reconcile_gate(&mut w.registry, &gate.gate_id)
                .await
                .expect("reconcile")
                .is_none(),
            "a pending gate needs no reconciliation"
        );
        assert_eq!(w.kinds(), vec!["run.created", "gate.created"]);
    });
}

#[test]
fn reconciliation_finishes_a_denial_caught_inside_the_window() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T29");

        // A denial's two events are written in one turn; a crash between them leaves this.
        w.registry
            .append(
                &w.run,
                EventPayload::GateResolving {
                    gate_id: gate.gate_id,
                    approve: false,
                    feedback: Some("not this diff".into()),
                    by: Actor::Mcp,
                    commit: None,
                },
            )
            .expect("gate.resolving");
        w.reopen();
        let before = w.commits();

        let resolution = expect_settled(
            gates::reconcile_gate(&mut w.registry, &gate.gate_id)
                .await
                .expect("reconcile")
                .expect("gate needed reconciling"),
        );
        assert_eq!(
            resolution,
            GateResolution::Denied {
                feedback: Some("not this diff".into())
            }
        );
        assert_eq!(w.commits(), before);
        assert_eq!(w.gate_now(&gate).status, GateStatus::Denied);
    });
}

// ---------------------------------------------------------------------------
// The payload file is not load-bearing once the window is open
// ---------------------------------------------------------------------------

#[test]
fn a_commit_finishes_even_if_the_payload_file_vanishes_mid_flight() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T29");

        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );

        // `acp gc`, a partial restore, a careless human: the payload is gone before CommitDone.
        std::fs::remove_file(&gate.payload_path).expect("remove payload");

        let sha = gates::run_commit(&plan, lock()).await.expect("commit");
        let resolution = gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha.clone()))
            .expect("finish")
            .expect("approved");
        assert_eq!(
            resolution,
            GateResolution::Approved {
                sha: Some(sha.clone())
            }
        );

        // A commit exists; both events that record it exist too.
        assert_eq!(w.commits_for_gate(&gate), 1);
        assert_eq!(w.count_kind("integrate.committed"), 1);
        assert_eq!(w.count_kind("gate.resolved"), 1);
        let approved = w.gate_now(&gate);
        assert_eq!(approved.status, GateStatus::Approved);
        assert_eq!(approved.sha, Some(sha));

        // The metadata came from `gate.resolving`, so it is still right.
        let committed = w
            .registry
            .events(&w.run, None, usize::MAX)
            .into_iter()
            .find_map(|e| match &e.payload {
                EventPayload::IntegrateCommitted {
                    worktree,
                    subject,
                    files,
                    ..
                } => Some((worktree.clone(), subject.clone(), files.clone())),
                _ => None,
            })
            .expect("integrate.committed");
        assert_eq!(committed.0, w.worktree());
        assert_eq!(committed.1, "acp: integrate T29");
        assert_eq!(committed.2, vec!["src/adder.ts".to_string()]);
    });
}

#[test]
fn reconciliation_finds_the_trailer_commit_with_the_payload_file_gone() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T29");

        // The lost helper's commit, made before the crash.
        run_git(w.repo.path(), &["add", "-A"]);
        run_git(
            w.repo.path(),
            &[
                "commit",
                "--quiet",
                "-m",
                &format!(
                    "acp: integrate T29\n\n{TRAILER_GATE_ID}: {}\nAcp-Run-Id: {}",
                    gate.gate_id, w.run
                ),
            ],
        );
        let expected = run_git(w.repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        crash_after_resolving(&mut w, &gate);
        std::fs::remove_file(&gate.payload_path).expect("remove payload");
        let before = w.commits();

        let resolution = expect_settled(
            gates::reconcile_gate(&mut w.registry, &gate.gate_id)
                .await
                .expect("reconcile")
                .expect("gate needed reconciling"),
        );
        assert_eq!(
            resolution,
            GateResolution::Approved {
                sha: Some(expected.clone())
            }
        );
        assert_eq!(w.commits(), before, "no second commit");
        assert_eq!(w.gate_now(&gate).sha, Some(expected));
        assert_eq!(w.count_kind("integrate.committed"), 1);
    });
}

#[test]
fn reconciliation_still_retries_the_commit_with_the_payload_file_gone() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T29");
        crash_after_resolving(&mut w, &gate);
        std::fs::remove_file(&gate.payload_path).expect("remove payload");
        let before = w.commits();

        let plan = expect_commit(
            gates::reconcile_gate(&mut w.registry, &gate.gate_id)
                .await
                .expect("reconcile")
                .expect("gate needed reconciling"),
        );
        assert_eq!(plan.target.worktree, w.worktree());

        let sha = gates::run_commit(&plan, lock()).await.expect("commit");
        gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha)).expect("finish");
        assert_eq!(w.commits(), before + 1);
        assert_eq!(w.commits_for_gate(&gate), 1);
        assert_eq!(w.gate_now(&gate).status, GateStatus::Approved);
    });
}
// ---------------------------------------------------------------------------
// A `gate.resolving` written before `commit` existed
// ---------------------------------------------------------------------------

/// The pre-change crash: `gate.resolving` on disk with **no** commit target, the shape every event
/// written before `CommitTarget` existed has.
fn crash_after_old_shape_resolving(w: &mut World, gate: &Gate) {
    w.registry
        .append(
            &w.run,
            EventPayload::GateResolving {
                gate_id: gate.gate_id,
                approve: true,
                feedback: None,
                by: cli(),
                commit: None,
            },
        )
        .expect("gate.resolving");
    w.reopen();
    assert_eq!(w.gate_now(gate).status, GateStatus::Resolving);
    assert!(
        w.gate_now(gate).commit.is_none(),
        "the old shape carries no target"
    );
}

#[test]
fn an_old_shape_resolving_gate_reconciles_from_the_trailer() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T29");

        run_git(w.repo.path(), &["add", "-A"]);
        run_git(
            w.repo.path(),
            &[
                "commit",
                "--quiet",
                "-m",
                &format!(
                    "acp: integrate T29\n\n{TRAILER_GATE_ID}: {}\nAcp-Run-Id: {}",
                    gate.gate_id, w.run
                ),
            ],
        );
        let expected = run_git(w.repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        crash_after_old_shape_resolving(&mut w, &gate);
        let before = w.commits();

        let resolution = expect_settled(
            gates::reconcile_gate(&mut w.registry, &gate.gate_id)
                .await
                .expect("reconcile")
                .expect("gate needed reconciling"),
        );
        assert_eq!(
            resolution,
            GateResolution::Approved {
                sha: Some(expected.clone())
            }
        );
        assert_eq!(w.commits(), before, "no second commit");
        assert_eq!(w.count_kind("integrate.committed"), 1);

        // The projection healed on the way through, and the repair kept the original resolver.
        let healed = w.gate_now(&gate);
        assert_eq!(healed.status, GateStatus::Approved);
        assert_eq!(healed.sha, Some(expected));
        assert_eq!(healed.resolved_by, Some(cli()));
        let target = healed.commit.expect("target was rebuilt");
        assert_eq!(target.worktree, w.worktree());
        assert_eq!(target.subject, "acp: integrate T29");
    });
}

#[test]
fn an_old_shape_resolving_gate_retries_the_commit_from_its_payload() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T29");
        crash_after_old_shape_resolving(&mut w, &gate);
        let before = w.commits();

        let plan = expect_commit(
            gates::reconcile_gate(&mut w.registry, &gate.gate_id)
                .await
                .expect("reconcile")
                .expect("gate needed reconciling"),
        );
        assert_eq!(plan.target.worktree, w.worktree());
        assert_eq!(w.commits(), before, "the repair alone commits nothing");
        assert!(
            w.gate_now(&gate).commit.is_some(),
            "the projection healed before the lookup"
        );

        let sha = gates::run_commit(&plan, lock()).await.expect("commit");
        gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha)).expect("finish");
        assert_eq!(w.commits(), before + 1);
        assert_eq!(w.commits_for_gate(&gate), 1);
        assert_eq!(w.gate_now(&gate).status, GateStatus::Approved);
    });
}

#[test]
fn an_old_shape_resolving_gate_with_no_payload_left_blocks_the_run() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let gate = w.integrate_gate("integrate T29");
        crash_after_old_shape_resolving(&mut w, &gate);
        std::fs::remove_file(&gate.payload_path).expect("remove payload");

        // Nothing to rebuild from and nothing committed: block, do not error, do not strand.
        assert!(
            gates::reconcile_gate(&mut w.registry, &gate.gate_id)
                .await
                .expect("reconcile does not fail the sweep")
                .is_none(),
            "no outcome to report"
        );
        assert_eq!(w.run_now().status, RunStatus::Blocked);
        let reason = w.run_now().blocked_reason.clone().expect("reason");
        assert_eq!(
            reason,
            format!("gate {} resolving without commit target", gate.gate_id)
        );
        assert_eq!(w.gate_now(&gate).status, GateStatus::Resolving);
    });
}

// ---------------------------------------------------------------------------
// Round-4 review: the cap, the hooks, and an index a worker left behind
// ---------------------------------------------------------------------------

/// Writes `.git/hooks/<name>`, executable, running under `/bin/sh`.
fn write_hook(repo: &Path, name: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    let path = repo.join(".git").join("hooks").join(name);
    std::fs::create_dir_all(path.parent().expect("hooks dir")).expect("mkdir");
    std::fs::write(&path, format!("#!/bin/sh\n{body}")).expect("write hook");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

const LARGE_TRACKED_BYTES: usize = 20 * 1024 * 1024;

fn large_tracked_contents() -> Vec<u8> {
    let line = b"replacement tracked content committed in full despite the bounded review 012345\n";
    let mut bytes = line.repeat(LARGE_TRACKED_BYTES / line.len());
    bytes.extend_from_slice(&line[..LARGE_TRACKED_BYTES - bytes.len()]);
    bytes[LARGE_TRACKED_BYTES - 1] = b'\n';
    assert_eq!(bytes.len(), LARGE_TRACKED_BYTES);
    bytes
}

/// The review artifact is capped, but an approval still commits the complete staged tracked blob.
#[test]
fn a_twenty_megabyte_tracked_modification_still_integrates_in_full() {
    block_on(async {
        let mut w = World::new();
        std::fs::create_dir_all(w.repo.path().join("src")).expect("mkdir");
        std::fs::write(w.repo.path().join("src/huge.txt"), "before\n").expect("write base");
        run_git(w.repo.path(), &["add", "--", "src/huge.txt"]);
        run_git(w.repo.path(), &["commit", "--quiet", "-m", "base"]);

        let content = large_tracked_contents();
        std::fs::write(w.repo.path().join("src/huge.txt"), &content)
            .expect("write 20 MiB modification");
        w.dirty_files.push("src/huge.txt".to_string());
        let expected_blob = run_git(w.repo.path(), &["hash-object", "--", "src/huge.txt"])
            .trim()
            .to_string();

        let gate = w.integrate_gate("integrate a tracked file past the assembled cap");
        let reviewed = std::fs::read(w.diff_path()).expect("read reviewed patch");
        assert!(reviewed.ends_with(FROZEN_DIFF_TRUNCATION_MARKER));
        assert!(reviewed.len() <= MAX_FROZEN_DIFF_BYTES + FROZEN_DIFF_TRUNCATION_MARKER.len());

        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );
        let sha = gates::run_commit(&plan, lock())
            .await
            .expect("bounded review still authorizes the complete staged index");
        gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha.clone())).expect("finish");

        let mut verify_name = w.diff_path().as_os_str().to_os_string();
        verify_name.push(".verify");
        let verified = std::fs::read(PathBuf::from(verify_name)).expect("read verification freeze");
        assert_eq!(
            verified, reviewed,
            "approval re-derived the identical bounded document"
        );
        assert_eq!(
            run_git(
                w.repo.path(),
                &["rev-parse", &format!("{sha}:src/huge.txt")]
            )
            .trim(),
            expected_blob,
            "the commit contains the full staged blob, not the truncated patch text"
        );
        assert_eq!(
            run_git(
                w.repo.path(),
                &["cat-file", "-s", &format!("{sha}:src/huge.txt")]
            )
            .trim()
            .parse::<usize>()
            .expect("blob size"),
            content.len()
        );
        assert_eq!(w.commits_for_gate(&gate), 1);
    });
}

/// A new file past the diff's inline cap integrates — text or binary.
///
/// The cap governs how much of a diff is worth *showing*; it never governed what may be committed.
/// But the freeze capped the worktree by one rule and the approval capped the index by another, so
/// the two documents differed by the tail of one line and **no** repository could integrate a new
/// file over 256 KiB — the refusal even blamed `.gitattributes`, which these repositories do not
/// have (round-4 review, finding 1).
#[test]
fn a_new_file_past_the_inline_cap_still_integrates() {
    block_on(async {
        let mut w = World::new();
        std::fs::create_dir_all(w.repo.path().join("src")).expect("mkdir");
        // 70-byte lines and 300-byte records: both cross the 256 KiB cap mid-item, which is where
        // the two capping rules used to disagree.
        let text = format!("export const value = 0; // {}\n", "x".repeat(42)).repeat(4_500);
        let mut record = vec![b'a'; 299];
        record[100] = 0;
        record.push(b'\n');
        let binary = record.repeat(1_000);
        std::fs::write(w.repo.path().join("src/huge.bin"), &binary).expect("write");
        std::fs::write(w.repo.path().join("src/huge.ts"), &text).expect("write");
        // Path-sorted, as `git status --porcelain` reports untracked files and as the gate's
        // reviewed set therefore records them.
        w.dirty_files.push("src/huge.bin".to_string());
        w.dirty_files.push("src/huge.ts".to_string());

        let gate = w.integrate_gate("integrate two files past the inline cap");
        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );
        let sha = gates::run_commit(&plan, lock())
            .await
            .expect("a file past the inline cap must still integrate");
        gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha.clone())).expect("finish");

        assert_eq!(w.commits_for_gate(&gate), 1);
        // The commit holds the whole file, not the truncated view of it the reviewer was shown.
        assert_eq!(
            run_git(w.repo.path(), &["show", &format!("{sha}:src/huge.ts")]),
            text,
            "the cap truncates the diff, never the commit"
        );
        assert_eq!(
            run_git(
                w.repo.path(),
                &["cat-file", "-s", &format!("{sha}:src/huge.bin")]
            )
            .trim()
            .parse::<usize>()
            .expect("a blob size"),
            binary.len()
        );
    });
}

/// The repository's own hooks never run on an integrate commit — **none** of them.
///
/// Hooks are the one thing that runs after the six-step order has verified the index, and every
/// stage of the commit has one: `pre-commit` may stage whatever it likes into the index that was
/// just hashed, `prepare-commit-msg` and `commit-msg` may rewrite the message and drop the trailer
/// the control plane reconciles on, and `post-commit` may `git commit --amend` the finished commit
/// into a different object entirely (round-4 review, finding 2). `--no-verify` covers only the
/// middle two — verified on git 2.54 — so the commit runs with `core.hooksPath` pointed at a path no
/// hook can live under, and the finished object is read back to prove it.
///
/// All four hooks are installed here, each one doing the damage it is capable of, and each of the
/// four assertions below is a different one failing to land.
#[test]
fn the_repositorys_hooks_never_run_on_an_integrate_commit() {
    block_on(async {
        let mut w = World::new();
        // A tracked file to modify, so the reviewed diff is git's own commit-to-commit diff and the
        // assertion below can be made with plain git.
        std::fs::create_dir_all(w.repo.path().join("src")).expect("mkdir");
        std::fs::write(
            w.repo.path().join("src/adder.ts"),
            "export const add = 0;\n",
        )
        .expect("write");
        run_git(w.repo.path(), &["add", "--", "src/adder.ts"]);
        run_git(w.repo.path(), &["commit", "--quiet", "-m", "base"]);

        write_hook(
            w.repo.path(),
            "pre-commit",
            "printf 'INJECTED\\n' >> src/adder.ts\ngit add -- src/adder.ts\n",
        );
        write_hook(
            w.repo.path(),
            "commit-msg",
            "printf 'hijacked\\n' > \"$1\"\n",
        );
        write_hook(
            w.repo.path(),
            "prepare-commit-msg",
            "printf 'rewritten by the hook\\n' > \"$1\"\n",
        );
        // The amender leaves a marker and guards against its own recursion: with the fix it never
        // runs at all, and without it the amend would otherwise re-trigger this hook for ever.
        write_hook(
            w.repo.path(),
            "post-commit",
            "[ -f .git/ACP_AMENDED ] && exit 0\n\
             : > .git/ACP_AMENDED\n\
             printf 'extra\\n' > src/extra.ts\n\
             git add -- src/extra.ts\n\
             git commit --amend --no-edit --no-verify -q\n",
        );

        std::fs::write(
            w.repo.path().join("src/adder.ts"),
            "export const add = 1;\n",
        )
        .expect("write");
        w.dirty_files.push("src/adder.ts".to_string());
        let gate = w.integrate_gate("integrate under hostile hooks");
        let pre_sha = w.head();

        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );
        let sha = gates::run_commit(&plan, lock()).await.expect("commit");
        gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha.clone())).expect("finish");

        // The message hooks would have replaced the message — trailer and all — and left the gate
        // unable to find its own commit on the next reconciliation.
        assert_eq!(
            w.commits_for_gate(&gate),
            1,
            "the trailer must survive the commit"
        );
        // The `post-commit` hook would have amended this commit into a different object holding a
        // file nobody reviewed, and `commit_staged` would have reported *that* sha.
        assert!(
            !w.repo.path().join(".git/ACP_AMENDED").exists(),
            "no post-commit hook may run on an integrate commit"
        );
        assert_eq!(
            run_git(w.repo.path(), &["show", "-s", "--format=%P", &sha]).trim(),
            pre_sha,
            "the commit sits on the reviewed preSha, and is not an amend of one that did"
        );
        assert_eq!(
            run_git(
                w.repo.path(),
                &["diff-tree", "--no-commit-id", "--name-only", "-r", &sha]
            )
            .trim(),
            "src/adder.ts",
            "the commit holds the reviewed change set and nothing else"
        );
        assert_eq!(
            run_git(w.repo.path(), &["show", &format!("{sha}:src/adder.ts")]),
            "export const add = 1;\n",
            "the committed blob is the reviewed one, not the hook's"
        );
        let committed = run_git(
            w.repo.path(),
            &["diff", "--no-color", "--no-renames", &pre_sha, &sha],
        );
        assert_eq!(
            sha256_hex(committed.as_bytes()),
            w.diff_hash,
            "the commit's diff against preSha must still hash to the reviewed diffHash"
        );
        // The hook never ran at all, so it never touched the human's worktree either.
        assert_eq!(
            std::fs::read_to_string(w.repo.path().join("src/adder.ts")).expect("read"),
            "export const add = 1;\n"
        );
    });
}

/// A worker that staged without committing does not wedge its own gate.
///
/// `git add` with no commit leaves an index that `assert_index_clean` refuses for ever, and the
/// commit-undo remediation only fired when HEAD moved — so a run could be built, reviewed, passed
/// and approved, and never committed (round-4 review, finding 4). `core::supervisor`'s finalize now
/// resets that index the same way it undoes a commit; this is the state it leaves behind, taken
/// through a real approval.
#[test]
fn a_worker_that_staged_without_committing_still_integrates() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let pre_sha = w.head();

        // The worker's `git add` — the state the attempt would have ended in.
        run_git(w.repo.path(), &["add", "--", "src/adder.ts"]);
        // What finalize does with it: `reset --mixed` to the attempt's preSha unstages and leaves
        // every byte on disk, which is the state the freeze and the approval are written against.
        git::reset_mixed(w.repo.path(), &pre_sha)
            .await
            .expect("unstage what the worker staged");

        let gate = w.integrate_gate("integrate after a worker staged");
        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("approve"),
        );
        let sha = gates::run_commit(&plan, lock())
            .await
            .expect("a worker's stray `git add` must not wedge the gate");
        gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha.clone())).expect("finish");

        assert_eq!(w.commits_for_gate(&gate), 1);
        assert_eq!(
            run_git(w.repo.path(), &["show", &format!("{sha}:src/adder.ts")]),
            "work\n"
        );
    });
}

/// B3 (T75-T79 review, finding 2): a `plan` gate caught between its approval's two appends is
/// finished by reconciliation as the commit-less approval it was — never routed at the heal path
/// that would demand a worktree it never had.
#[test]
fn reconciliation_finishes_a_plan_approval_caught_inside_the_window() {
    block_on(async {
        let mut w = World::new();
        let gate = w.gate(GateKind::Plan, "look at both branches together", None);

        w.registry
            .append(
                &w.run,
                EventPayload::GateResolving {
                    gate_id: gate.gate_id,
                    approve: true,
                    feedback: None,
                    by: cli(),
                    commit: None,
                },
            )
            .expect("gate.resolving");
        w.reopen();
        let before = w.commits();

        let resolution = expect_settled(
            gates::reconcile_gate(&mut w.registry, &gate.gate_id)
                .await
                .expect("reconcile")
                .expect("gate needed reconciling"),
        );
        assert_eq!(resolution, GateResolution::Approved { sha: None });
        assert_eq!(w.commits(), before, "a plan approval commits nothing");
        assert_eq!(w.gate_now(&gate).status, GateStatus::Approved);
        assert_eq!(w.gate_now(&gate).sha, None);
    });
}

/// A payload that names its subject wins over the summary's first line: the commit reads
/// `acp: <task line>` and the whole summary — review sentence first — becomes the body. A payload
/// without one keeps the old derivation (every other test in this file).
#[test]
fn a_payload_subject_leads_the_commit_and_the_summary_becomes_the_body() {
    block_on(async {
        let mut w = World::new();
        w.dirty("adder.ts");
        let summary = "NO reviewer ran — approving this gate IS the review.\n\nT29: Add src/adder.ts\n\n1 file(s) changed.";
        let gate = w.integrate_gate_titled(summary, "T29: Add src/adder.ts");
        let before = w.commits();

        let plan = expect_commit(
            gates::begin_resolve(
                &mut w.registry,
                &gate.gate_id,
                true,
                None,
                cli(),
                &roles_cfg(false),
            )
            .expect("socket approve"),
        );
        let sha = gates::run_commit(&plan, lock()).await.expect("commit");
        gates::finish_commit(&mut w.registry, &gate.gate_id, Ok(sha))
            .expect("finish")
            .expect("approved");
        assert_eq!(w.commits(), before + 1);

        let body = run_git(w.repo.path(), &["log", "-1", "--format=%B"]);
        let mut lines = body.lines();
        assert_eq!(lines.next(), Some("acp: T29: Add src/adder.ts"), "{body:?}");
        assert_eq!(
            lines.next(),
            Some(""),
            "a blank line separates subject and body"
        );
        assert_eq!(
            lines.next(),
            Some("NO reviewer ran — approving this gate IS the review."),
            "the summary opens the body: {body:?}"
        );
        assert!(
            body.contains(&format!("Acp-Gate-Id: {}", gate.gate_id)),
            "the trailers still close the message: {body:?}"
        );
        assert_eq!(
            w.gate_now(&gate).commit.expect("target").subject,
            "acp: T29: Add src/adder.ts",
            "integrate.committed carries the same subject"
        );
    });
}
