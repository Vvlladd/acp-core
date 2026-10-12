//! T37: the failure half of the branch table, driven end to end through the **whole actor** —
//! `reports/03-design.md` § Data Flow step 17 and § Test Strategy, row `core/loop.rs`
//! (`timeout`/`invalid` strike via 17b; `dirty_retry`/`no_session` retry fresh in the same worktree
//! via 17c; `auth_fail`/`missing_bin` block without a strike via 17a; `worker_commits`; `denylist`;
//! and Rev 25's `no_changed_files`).
//!
//! Every test starts a real `Core` behind `run_actor` and drives it through `CoreHandle::delegate`,
//! exactly as `tests/loop_pass.rs` does — see that file's header for how a scenario reaches the
//! fake CLIs (wrapper scripts on `PATH` + a `.acp-fake-env` beside each test's temp repository) and
//! for the process-hygiene rule every test here also obeys.
//!
//! Two things this file asserts that no other test can:
//!
//! * **which branch ran**, from the `loop.dispatched{branch}` marker the branch appends last. It is
//!   the loop's own durable answer to "what did I decide?", so asserting on it pins the branch
//!   table rather than a side effect that two branches happen to share;
//! * **what the next worker was actually told**, from `<attemptDir>/prompt.txt` — the file
//!   `spawn_detached` writes from the plan's own argv. A repair prompt that does not mention the
//!   schema, or a retry prompt that does not quote the worktree it inherited, is a bug a
//!   status-only assertion would miss.
//!
//! `ENV_GUARD` is taken **shared** by everything except `missing_bin`, which is *defined* as "not on
//! `PATH`" and therefore has to rewrite the process `PATH` — exclusively, so no other test in this
//! binary can observe it.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_control_plane::core::handoff::ADVISORY_OPEN;
use agent_control_plane::core::types::{
    AgentId, AgentStatus, AttemptId, AttemptKind, AttemptStatus, ErrorCode, Event, EventPayload,
    GateKind, LineageId, LoopBranch, RoleName, RunId, RunStatus, ViolationKind,
};
use agent_control_plane::core::StatusQuery;
use agent_control_plane::providers::find_on_path;

use common::{
    delegate_builder, embedded_roles, loop_task, pick, quiesce, rendered_prompt,
    roles_with_attempt_timeout, start_actor, wait_for_log, wait_for_status, ActorOpts, LoopWorld,
};

// ---------------------------------------------------------------------------
// Log queries
// ---------------------------------------------------------------------------

/// One `attempt.started`, reduced to what these tests ask about.
struct Started {
    attempt: AttemptId,
    agent: AgentId,
    kind: AttemptKind,
    dir: PathBuf,
}

fn attempts_started(events: &[Arc<Event>]) -> Vec<Started> {
    pick(events, |p| match p {
        EventPayload::AttemptStarted {
            attempt_id,
            agent_id,
            attempt_kind,
            dir,
            ..
        } => Some(Started {
            attempt: *attempt_id,
            agent: *agent_id,
            kind: *attempt_kind,
            dir: dir.clone(),
        }),
        _ => None,
    })
}

/// Every `attempt.finished`, as `(status, error code)`.
fn finished(events: &[Arc<Event>]) -> Vec<(AttemptStatus, Option<ErrorCode>)> {
    pick(events, |p| match p {
        EventPayload::AttemptFinished { status, error, .. } => {
            Some((*status, error.as_ref().map(|e| e.code)))
        }
        _ => None,
    })
}

/// The branches the loop recorded, in order — its own durable answer to "what did I decide?".
fn branches(events: &[Arc<Event>]) -> Vec<LoopBranch> {
    pick(events, |p| match p {
        EventPayload::LoopDispatched { branch, .. } => Some(*branch),
        _ => None,
    })
}

fn strikes(events: &[Arc<Event>]) -> Vec<(LineageId, u8)> {
    pick(events, |p| match p {
        EventPayload::LineageStrike {
            lineage_id,
            strikes,
            ..
        } => Some((*lineage_id, *strikes)),
        _ => None,
    })
}

/// Every `agent.created`, as `(agent, role, lineage, parent, worktree)`.
struct Created {
    agent: AgentId,
    role: RoleName,
    lineage: LineageId,
    parent: Option<AgentId>,
    worktree: Option<PathBuf>,
}

fn agents_created(events: &[Arc<Event>]) -> Vec<Created> {
    pick(events, |p| match p {
        EventPayload::AgentCreated {
            agent_id,
            role,
            lineage_id: Some(lineage_id),
            parent_agent_id,
            worktree,
            ..
        } => Some(Created {
            agent: *agent_id,
            role: *role,
            lineage: *lineage_id,
            parent: *parent_agent_id,
            worktree: worktree.clone(),
        }),
        _ => None,
    })
}

fn reviewers(events: &[Arc<Event>]) -> Vec<AgentId> {
    agents_created(events)
        .into_iter()
        .filter(|a| a.role == RoleName::Reviewer)
        .map(|a| a.agent)
        .collect()
}

fn violations(events: &[Arc<Event>]) -> Vec<(ViolationKind, Option<Vec<String>>)> {
    pick(events, |p| match p {
        EventPayload::PolicyViolated { violation, .. } => {
            Some((violation.kind, violation.files.clone()))
        }
        _ => None,
    })
}

fn gate_summaries(events: &[Arc<Event>], kind: GateKind) -> Vec<String> {
    pick(events, |p| match p {
        EventPayload::GateCreated {
            gate_kind, summary, ..
        } if *gate_kind == kind => Some(summary.clone()),
        _ => None,
    })
}

fn blocked_reasons(events: &[Arc<Event>]) -> Vec<String> {
    pick(events, |p| match p {
        EventPayload::RunStatus_ {
            status: RunStatus::Blocked,
            reason,
        } => reason.clone(),
        _ => None,
    })
}

/// `<stateDir>/runs/<runId>/attempts/<attemptId>` — the design's on-disk layout. Asserted rather
/// than reconstructed, so a change to it has to be a deliberate one.
fn assert_attempt_dir(state_dir: &Path, run: &RunId, started: &Started) {
    assert_eq!(
        started.dir,
        state_dir
            .join("runs")
            .join(run.as_uuid().simple().to_string())
            .join("attempts")
            .join(started.attempt.as_uuid().simple().to_string()),
        "the attempt dir is where the design's on-disk layout says"
    );
}

/// Runs `scenario` until the log satisfies `until`, then ends every worker and stops the actor.
///
/// The whole loop is the unit under test, so a test's body is "delegate, wait for a durable fact,
/// assert on the log" — the waiting is what has to be careful, and it is careful here.
async fn run_until(
    world: &LoopWorld,
    task_id: &str,
    roles: Arc<agent_control_plane::core::types::RolesConfig>,
    what: &str,
    until: impl FnMut(&[Arc<Event>]) -> bool,
) -> (RunId, AgentId, Vec<Arc<Event>>) {
    let actor = start_actor(world, roles, ActorOpts::default());
    let handle = actor.handle.clone();
    let out = handle
        .delegate(delegate_builder(loop_task(task_id)))
        .await
        .expect("the delegation is accepted");

    let events = wait_for_log(world, &out.run_id, what, until).await;
    quiesce(&handle).await;
    actor.stop().await;
    (out.run_id, out.agent_id, events)
}

// ---------------------------------------------------------------------------
// 17b — a resumable failure
// ---------------------------------------------------------------------------

/// A builder that never answers is ended by its own deadline, struck once, and **resumed**: the
/// `hang` scenario emits `system/init` before it blocks, so a session exists and 17b applies.
///
/// The deadline is the injected one (`roles_with_attempt_timeout`), not a `sleep`: the worker dies
/// only when the supervisor's ladder reaches it, so the timeout under test is the production one.
#[test]
fn a_hanging_builder_times_out_and_is_struck_and_resumed_via_17b() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("hang", &[]);
        let (run, builder, events) = run_until(
            &world,
            "T37-timeout",
            roles_with_attempt_timeout(2),
            "the repair attempt 17b starts",
            |events| attempts_started(events).len() >= 2,
        )
        .await;

        assert_eq!(
            finished(&events).first(),
            Some(&(AttemptStatus::Timeout, None)),
            "the deadline ended it, and a timeout carries no error of its own"
        );
        assert_eq!(
            strikes(&events).first().map(|(_, n)| *n),
            Some(1),
            "a timeout is strikeable"
        );
        assert_eq!(branches(&events).first(), Some(&LoopBranch::Resume), "17b");

        let started = attempts_started(&events);
        assert_eq!(started[1].agent, builder, "the same builder, resumed");
        assert_eq!(
            started[1].kind,
            AttemptKind::Resume,
            "in the session its first attempt opened"
        );
        assert_attempt_dir(world.state_dir(), &run, &started[1]);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.payload, EventPayload::AgentMessage { .. })),
            "a worker-bound follow-up is the loop's instruction, never a transcript turn"
        );
    });
}

/// A builder whose final message does not validate is `invalid_output`, struck via 17b, and told —
/// in the prompt it is resumed with — exactly what was wrong with it.
///
/// Reading `prompt.txt` is what makes this more than a status assertion: `build_failure_repair_prompt`
/// quotes the recorded error inside the advisory block (S3) and re-states the builder's contract, so
/// the resumed worker knows both that its output was rejected and what shape the next one must have.
#[test]
fn an_invalid_result_strikes_via_17b_and_the_repair_prompt_demands_the_schema() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("invalid", &[]);
        let (run, builder, events) = run_until(
            &world,
            "T37-invalid",
            embedded_roles(),
            "the repair attempt 17b starts",
            |events| attempts_started(events).len() >= 2,
        )
        .await;

        assert_eq!(
            finished(&events).first(),
            Some(&(AttemptStatus::InvalidOutput, Some(ErrorCode::SchemaInvalid))),
            "exit 0, but the structured output does not validate"
        );
        assert_eq!(strikes(&events).first().map(|(_, n)| *n), Some(1));
        assert_eq!(branches(&events).first(), Some(&LoopBranch::Resume), "17b");
        assert!(
            reviewers(&events).is_empty(),
            "nothing was reviewed: there is no result to review"
        );

        let started = attempts_started(&events);
        assert_eq!(started[1].agent, builder);
        assert_eq!(started[1].kind, AttemptKind::Resume);
        assert_attempt_dir(world.state_dir(), &run, &started[1]);

        let prompt = rendered_prompt(&started[1].dir);
        assert!(
            prompt.contains("does not validate against the role's result schema"),
            "the repair prompt quotes what was recorded: {prompt}"
        );
        assert!(
            prompt.contains("exactly one JSON document matching the build-result schema"),
            "…and re-states the contract the next message must meet: {prompt}"
        );
        assert!(
            prompt.contains(ADVISORY_OPEN),
            "the recorded error is worker-authored text and travels as data (S3): {prompt}"
        );
    });
}

// ---------------------------------------------------------------------------
// 17c — a non-resumable failure inherits the worktree (decision 8)
// ---------------------------------------------------------------------------

/// `dirty_retry`: the session died before it said anything, so there is nothing to resume — but the
/// worktree it dirtied is exactly as it left it, and the fresh session is told so.
///
/// Decision 8 in one test: **same lineage, same worktree, nothing cleaned**. The uncommitted file
/// is still on disk afterwards, and the new worker's prompt quotes the `git status --porcelain` that
/// names it.
#[test]
fn dirty_retry_starts_a_fresh_session_in_the_worktree_it_inherits() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("dirty_retry", &[]);
        let (run, builder, events) = run_until(
            &world,
            "T37-dirty-retry",
            embedded_roles(),
            "the retry attempt 17c starts",
            |events| attempts_started(events).len() >= 2,
        )
        .await;

        assert_eq!(
            finished(&events).first(),
            Some(&(AttemptStatus::NoSession, None)),
            "it exited before `system/init`, so no session id exists"
        );
        assert_eq!(strikes(&events).first().map(|(_, n)| *n), Some(1));
        assert_eq!(
            branches(&events).first(),
            Some(&LoopBranch::RetryFresh),
            "17c"
        );

        // The old handle is closed first — it is a writing agent in this worktree, and the
        // one-writer rule (C5) would otherwise refuse the retry on account of the agent it replaces.
        assert!(
            pick(&events, |p| match p {
                EventPayload::AgentStatusChanged {
                    agent_id,
                    status: AgentStatus::Closed,
                    ..
                } if *agent_id == builder => Some(()),
                _ => None,
            })
            .len()
                == 1,
            "the unresumable session's handle is closed"
        );

        let created = agents_created(&events);
        assert_eq!(created.len(), 2, "a new agent, not a resume");
        assert_eq!(created[1].role, RoleName::Builder);
        assert_eq!(
            created[1].lineage, created[0].lineage,
            "the same lineage: the strikes carry over"
        );
        assert_eq!(
            created[1].worktree, created[0].worktree,
            "and the same worktree, inherited as it stands (decision 8)"
        );
        assert_eq!(created[1].parent, Some(builder));

        let worktree = created[0]
            .worktree
            .clone()
            .expect("the builder has a worktree");
        assert!(
            worktree.join("dirty.txt").is_file(),
            "nothing is cleaned, reset or discarded"
        );

        let started = attempts_started(&events);
        assert_eq!(started[1].agent, created[1].agent);
        assert_eq!(
            started[1].kind,
            AttemptKind::Fresh,
            "a fresh session — there was none to resume"
        );
        assert_attempt_dir(world.state_dir(), &run, &started[1]);

        let prompt = rendered_prompt(&started[1].dir);
        assert!(
            prompt.contains("?? dirty.txt"),
            "the retry prompt quotes the porcelain of the worktree it inherited: {prompt}"
        );
        assert!(
            prompt.contains("A previous attempt left these uncommitted changes"),
            "…with the fixed sentence decision 8 requires: {prompt}"
        );
        assert!(
            prompt.contains(ADVISORY_OPEN),
            "the worktree status is worker-authored text and travels as data (S3): {prompt}"
        );
    });
}

/// `no_session` takes the same branch for the same reason, with an untouched worktree: the rule is
/// "there is no session id", not "the worktree changed".
#[test]
fn no_session_also_retries_fresh_in_the_same_lineage_and_worktree() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("no_session", &[]);
        let (_run, builder, events) = run_until(
            &world,
            "T37-no-session",
            embedded_roles(),
            "the retry attempt 17c starts",
            |events| attempts_started(events).len() >= 2,
        )
        .await;

        assert_eq!(
            finished(&events).first(),
            Some(&(AttemptStatus::NoSession, None))
        );
        assert_eq!(strikes(&events).first().map(|(_, n)| *n), Some(1));
        assert_eq!(
            branches(&events).first(),
            Some(&LoopBranch::RetryFresh),
            "17c"
        );

        let created = agents_created(&events);
        assert_eq!(created.len(), 2);
        assert_ne!(created[1].agent, builder, "a new session");
        assert_eq!(created[1].lineage, created[0].lineage);
        assert_eq!(created[1].worktree, created[0].worktree);
        assert!(reviewers(&events).is_empty());
    });
}

// ---------------------------------------------------------------------------
// 17a — an environment failure is nobody's fault and never a strike
// ---------------------------------------------------------------------------

/// Restores the process `PATH` however this test leaves, including on a panic.
struct PathGuard(std::ffi::OsString);

impl PathGuard {
    /// Narrows `PATH` to `dirs`, having first remembered what it was.
    fn narrow(dirs: &[PathBuf]) -> Self {
        let guard = Self(std::env::var_os("PATH").unwrap_or_default());
        std::env::set_var("PATH", std::env::join_paths(dirs).expect("join PATH"));
        guard
    }
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        std::env::set_var("PATH", &self.0);
    }
}

/// `missing_bin`: with no `claude` reachable, `preflight` fails before a single process is started,
/// the attempt is recorded as `spawn_failed{provider_missing}`, and the run is **blocked with no
/// strike** — a human has to install the CLI, and a repair attempt would fail identically.
///
/// The scenario is reproduced the way `fixtures/jsonl/README.md` says: an empty directory in front
/// of a `PATH` that no longer holds the fakes. That is a process-global change, so this is the one
/// test in the file that takes `ENV_GUARD` exclusively — and it installs the wrappers *before*
/// narrowing, so the one-time `PATH` edit `common` makes is not captured inside the narrow window
/// and lost when it closes.
#[test]
fn missing_bin_blocks_the_run_without_a_strike_via_17a() {
    common::with_exclusive_env(|| async {
        common::install_fake_clis();
        let world = LoopWorld::new("missing_bin", &[]);
        let git = find_on_path("git").expect("a real git on PATH");
        let empty = tempfile::tempdir().expect("an empty dir to shadow the CLIs with");

        let narrowed = PathGuard::narrow(&[
            empty.path().to_path_buf(),
            git.parent()
                .expect("git lives in a directory")
                .to_path_buf(),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ]);
        // Fail loudly rather than start a real CLI on a machine that happens to have one installed
        // somewhere this narrowed `PATH` still reaches.
        assert!(
            find_on_path("claude").is_none(),
            "this test requires `claude` to be unreachable"
        );

        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();
        let out = handle
            .delegate(delegate_builder(loop_task("T37-missing-bin")))
            .await
            .expect("the delegation is accepted — policy knows nothing about PATH");
        let run = out.run_id;

        wait_for_status(
            &handle,
            StatusQuery {
                run_id: Some(run),
                ..StatusQuery::default()
            },
            "run.status{blocked}",
            |s| {
                s.runs
                    .first()
                    .is_some_and(|r| r.status == RunStatus::Blocked)
            },
        )
        .await;
        quiesce(&handle).await;
        actor.stop().await;
        drop(narrowed);

        let events = world.events(&run);
        assert_eq!(
            finished(&events),
            vec![(AttemptStatus::SpawnFailed, Some(ErrorCode::ProviderMissing))],
            "one attempt, and it never became a process"
        );
        assert_eq!(
            branches(&events),
            vec![LoopBranch::Environment],
            "17a — not a strike, not a retry"
        );
        assert!(
            strikes(&events).is_empty(),
            "the model did nothing wrong: no strike is recorded"
        );
        assert!(
            blocked_reasons(&events)
                .iter()
                .any(|reason| reason.contains("provider_missing")),
            "the block names the cause a human has to fix: {:?}",
            blocked_reasons(&events)
        );
        assert!(reviewers(&events).is_empty());
    });
}

/// `auth_fail`: the CLI is installed but nobody is logged in. That is an **environment** failure —
/// `spawn_failed{provider_unauthenticated}`, branch 17a, **no strike** — not a bad turn.
///
/// The distinction is worth a test because the two candidate rows describe the same observation: an
/// unauthenticated CLI exits non-zero without emitting `system/init`, which is also exactly what
/// `no_session` looks like. `no_session` strikes the lineage and retries in a fresh session, so
/// reading the wrong row costs three more spawns that all fail identically on a machine nobody has
/// logged into. What separates them is the signature on **stderr**, which the supervisor now reads
/// back (`ResultCtx::stderr_head`) and each adapter matches against its own wording; the contract
/// is what `src/bin/fake-claude.rs`'s `auth_fail` scenario emits.
#[test]
fn auth_fail_blocks_the_run_without_a_strike_via_17a() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("auth_fail", &[]);
        let (_run, _builder, events) = run_until(
            &world,
            "T37-auth-fail",
            embedded_roles(),
            "the loop reacts to the first attempt",
            |events| !branches(events).is_empty(),
        )
        .await;

        assert_eq!(
            finished(&events),
            vec![(
                AttemptStatus::SpawnFailed,
                Some(ErrorCode::ProviderUnauthenticated)
            )],
            "an auth failure before any event is an environment failure, not a bad turn"
        );
        assert_eq!(branches(&events), vec![LoopBranch::Environment], "17a");
        assert!(
            strikes(&events).is_empty(),
            "17a never strikes: a repair would fail identically until a human logs in"
        );
        assert!(
            blocked_reasons(&events)
                .iter()
                .any(|reason| reason.contains("provider_unauthenticated")),
            "{:?}",
            blocked_reasons(&events)
        );
    });
}

// ---------------------------------------------------------------------------
// Steps 10-11 — what the worker did to the workspace
// ---------------------------------------------------------------------------

/// `worker_commits`: the builder committed, which only the control plane may do. The commit is
/// undone with a soft reset, the violation is recorded — and the **review still runs**, because a
/// rule broken about git says nothing about whether the change is good.
///
/// The design requires the integrate gate's summary to name every violation of the lineage, since
/// the human approving it is the last reader before the work is committed for real.
#[test]
fn worker_commits_is_recorded_as_a_violation_and_the_review_still_runs() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("worker_commits", &[]);
        let (_run, _builder, events) = run_until(
            &world,
            "T37-worker-commits",
            embedded_roles(),
            "gate.created{integrate}",
            |events| !gate_summaries(events, GateKind::Integrate).is_empty(),
        )
        .await;

        let violations = violations(&events);
        assert_eq!(
            violations.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
            vec![ViolationKind::WorkerCommitted],
            "the worker's commit is the one violation recorded"
        );

        assert_eq!(
            finished(&events).first(),
            Some(&(AttemptStatus::Succeeded, None)),
            "the violation is not a failure of the attempt"
        );
        assert_eq!(reviewers(&events).len(), 1, "the review still runs");

        let summaries = gate_summaries(&events, GateKind::Integrate);
        assert_eq!(summaries.len(), 1);
        assert!(
            summaries[0].contains("WorkerCommitted"),
            "the gate names every violation of the lineage: {}",
            summaries[0]
        );
        assert!(strikes(&events).is_empty(), "and nobody is struck for it");
    });
}

/// `denylist`: a changed file matching a denied glob stops the attempt dead — an `escalate` gate, a
/// blocked run, **no strike and no reviewer at all**.
///
/// "No reviewer" is enforced from both ends: this asserts no `agent.created{reviewer}` exists, and
/// the fake `codex` refuses to run under this scenario at all (`is_builder_only`,
/// `src/bin/fake-codex.rs`), so a loop that wrongly continued into review would fail loudly rather
/// than replay a PASS.
#[test]
fn denylist_opens_an_escalate_gate_and_never_starts_a_reviewer() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("denylist", &[]);
        let (run, _builder, events) = run_until(
            &world,
            "T37-denylist",
            embedded_roles(),
            "gate.created{escalate}",
            |events| !gate_summaries(events, GateKind::Escalate).is_empty(),
        )
        .await;

        let violations = violations(&events);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, ViolationKind::DenylistHit);
        assert_eq!(
            violations[0].1,
            Some(vec!["App.xcconfig".to_string()]),
            "the violation names what was touched"
        );

        assert_eq!(
            finished(&events),
            vec![(AttemptStatus::Escalate, None)],
            "a denied path is a human's decision, not a bad turn"
        );
        assert_eq!(branches(&events), vec![LoopBranch::Gate]);
        assert!(strikes(&events).is_empty(), "a denylist hit never strikes");
        assert!(
            reviewers(&events).is_empty(),
            "and no reviewer is ever started for it"
        );

        let summaries = gate_summaries(&events, GateKind::Escalate);
        assert_eq!(summaries.len(), 1);
        assert!(
            summaries[0].contains("DenylistHit"),
            "the escalate gate says what happened: {}",
            summaries[0]
        );
        assert_eq!(
            world
                .reopen()
                .run(&run)
                .map(|r| r.status)
                .expect("the run is in the log"),
            RunStatus::Blocked
        );
    });
}

// ---------------------------------------------------------------------------
// Rev 25 — a success that changed nothing has produced nothing to review
// ---------------------------------------------------------------------------

/// `no_changes` replays the happy-path transcript — a `build-result` claiming `src/adder.ts` was
/// written — while touching nothing. The frozen diff is empty, so the attempt is
/// `invalid_output{no_changed_files}`, it strikes via 17b, and **no reviewer is started**: a
/// reviewer with nothing to review would either invent a verdict or waste a spawn.
#[test]
fn a_success_that_changed_nothing_is_invalid_output_and_starts_no_reviewer() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("no_changes", &[]);
        let (_run, builder, events) = run_until(
            &world,
            "T37-no-changes",
            embedded_roles(),
            "the repair attempt 17b starts",
            |events| attempts_started(events).len() >= 2,
        )
        .await;

        assert_eq!(
            finished(&events).first(),
            Some(&(
                AttemptStatus::InvalidOutput,
                Some(ErrorCode::NoChangedFiles)
            )),
            "the builder claimed a change it did not make"
        );
        assert!(
            pick(&events, |p| match p {
                EventPayload::DiffFrozen { .. } => Some(()),
                _ => None,
            })
            .is_empty(),
            "an empty diff is never frozen, so there is nothing a reviewer could be shown"
        );
        assert!(
            reviewers(&events).is_empty(),
            "and no reviewer is started for one"
        );

        assert_eq!(strikes(&events).first().map(|(_, n)| *n), Some(1));
        assert_eq!(branches(&events).first(), Some(&LoopBranch::Resume), "17b");

        let started = attempts_started(&events);
        assert_eq!(started[1].agent, builder, "the same builder, resumed");
        assert_eq!(started[1].kind, AttemptKind::Resume);
        let prompt = rendered_prompt(&started[1].dir);
        assert!(
            prompt.contains("changed no files"),
            "the repair prompt says what was wrong: {prompt}"
        );
    });
}
