//! T36: the loop's happy paths, driven end to end through the **whole actor** —
//! `reports/03-design.md` § Test Strategy, row `core/loop.rs` (`PASS→gate`; `FAIL→fix→PASS`;
//! `FAIL×2 → replacement in a new worktree, old retained`) plus Rev 25's diff-hash binding.
//!
//! Nothing here is a unit test of a branch. Every test starts a real `Core` behind `run_actor`,
//! with the tick task and the signal forwarder `main.rs` spawns, and calls `delegate` on a
//! `CoreHandle` — so the worktree, the argv, the sandbox settings, the schema, the spawn, the tail,
//! the freeze and the commit are all the production ones. The only thing that is not real is the
//! provider binary: `claude` and `codex` resolve, on this process's `PATH`, to the fake CLIs
//! replaying `fixtures/jsonl/` (`fixtures/jsonl/README.md` § "Scenario → fixture map"), so no test
//! in this file spends a token.
//!
//! **How a scenario reaches the fake, and why it is not an environment variable.** The loop builds
//! every `SpawnPlan` itself and resolves the CLI against the *process* `PATH`, so the two dials a
//! loop test has — `PATH` and the process environment — are both process-global while cargo runs
//! this binary's tests on parallel threads. `tests/common` therefore puts one pair of **wrapper
//! scripts** on `PATH` for the whole binary; each wrapper walks up from the worker's own current
//! directory (its worktree, inside that test's temp repository) to the nearest `.acp-fake-env` and
//! sources it. Per-test configuration, no shared state, no serialization
//! (`common::install_fake_clis` / `common::configure_fakes`).
//!
//! **Determinism.** No test sleeps for an outcome. Waits are on the durable log — the broadcast
//! stream a socket subscriber sees, or `Registry::open` re-read from disk — or on `get_status`,
//! each with a bound that turns a regression into a failure rather than a hang. The one moving part
//! a timer could otherwise have decided, Rev 25's `diffHash`, is decided by the loop instead: the
//! codex wrapper lifts the hash out of the reviewer's own prompt, which is exactly what a real
//! reviewer is told to do.
//!
//! **Process hygiene.** Every worker is ended before its test returns (`common::quiesce`), because
//! a normal actor stop deliberately leaves workers running (C3). After a run of this suite
//! `ps -eo command | grep -F 'Add src/adder.ts' | grep -vc grep` must print `0`; `pgrep` by name
//! does not work, because a worker wears the fake binary's name, not the provider's.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_control_plane::core::gates::GatePayload;
use agent_control_plane::core::types::{
    AgentId, AgentStatus, AttemptId, AttemptKind, AttemptStatus, ErrorCode, Event, EventPayload,
    False, GateId, GateKind, LineageId, LoopState, RoleName, RunId, RunStatus, Verdict,
};
use agent_control_plane::core::{GateResolution, RecommendedNext, StatusQuery};
use serde_json::Value;

use common::{
    await_done, cli_actor, delegate_builder, embedded_roles, files_in_commit, head_sha, loop_task,
    pick, quiesce, start_actor, wait_for_log, wait_for_status, ActorOpts, LoopWorld,
    FAKE_RESET_STATE, FAKE_WRONG_HASH_ONCE, WRONG_DIFF_HASH,
};

// ---------------------------------------------------------------------------
// Log queries — the projections these tests assert on
// ---------------------------------------------------------------------------

/// Every `agent.created` of one role, in log order.
fn agents_of(events: &[Arc<Event>], role: RoleName) -> Vec<AgentId> {
    pick(events, |p| match p {
        EventPayload::AgentCreated {
            agent_id,
            role: created,
            ..
        } if *created == role => Some(*agent_id),
        _ => None,
    })
}

/// Every `attempt.started`, as `(attempt, agent, kind)`.
fn attempts_started(events: &[Arc<Event>]) -> Vec<(AttemptId, AgentId, AttemptKind)> {
    pick(events, |p| match p {
        EventPayload::AttemptStarted {
            attempt_id,
            agent_id,
            attempt_kind,
            ..
        } => Some((*attempt_id, *agent_id, *attempt_kind)),
        _ => None,
    })
}

/// Every `gate.created` of one kind, as `(gateId, summary)`.
fn gates_of(events: &[Arc<Event>], kind: GateKind) -> Vec<(GateId, String)> {
    pick(events, |p| match p {
        EventPayload::GateCreated {
            gate_id,
            gate_kind,
            summary,
            ..
        } if *gate_kind == kind => Some((*gate_id, summary.clone())),
        _ => None,
    })
}

/// Every `review.verdict`, as `(verdict, the diffHash the reviewer echoed)`.
fn verdicts(events: &[Arc<Event>]) -> Vec<(Verdict, Option<String>)> {
    pick(events, |p| match p {
        EventPayload::ReviewVerdict {
            verdict, diff_hash, ..
        } => Some((*verdict, diff_hash.clone())),
        _ => None,
    })
}

/// Every `diff.frozen`, as `(builder attempt, diffPath, diffHash, files)`.
fn frozen(events: &[Arc<Event>]) -> Vec<(AttemptId, PathBuf, String, Vec<String>)> {
    pick(events, |p| match p {
        EventPayload::DiffFrozen {
            attempt_id,
            diff_path,
            diff_hash,
            files,
            ..
        } => Some((
            *attempt_id,
            diff_path.clone(),
            diff_hash.clone(),
            files.clone(),
        )),
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

fn worktrees_created(events: &[Arc<Event>]) -> Vec<PathBuf> {
    pick(events, |p| match p {
        EventPayload::WorktreeCreated { path, .. } => Some(path.clone()),
        _ => None,
    })
}

/// `<repoRoot>/.acp/worktrees/<runId>/<agent8>` — the design's on-disk layout, spelled out here so
/// a change to it has to be a deliberate one.
fn expected_worktree(repo_root: &Path, run: &RunId, agent: &AgentId) -> PathBuf {
    let agent8: String = agent
        .as_uuid()
        .simple()
        .to_string()
        .chars()
        .take(8)
        .collect();
    repo_root
        .join(".acp/worktrees")
        .join(run.as_uuid().simple().to_string())
        .join(agent8)
}

/// The `<stateDir>/runs/<runId>/gates/<gateId>.payload.json` the design's on-disk layout names —
/// what the menu-bar app reads before offering a human the approval.
fn gate_payload(state_dir: &Path, run: &RunId, gate: &GateId) -> GatePayload {
    let path = state_dir
        .join("runs")
        .join(run.to_string())
        .join("gates")
        .join(format!("{gate}.payload.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read the gate payload {}: {err}", path.display()));
    serde_json::from_str(&text).expect("the gate payload is valid JSON")
}

// ---------------------------------------------------------------------------
// PASS → integrate gate → commit
// ---------------------------------------------------------------------------

/// The whole Phase-1 loop in one test: steps 1-6 (`delegate`), 7-13 (tail, freeze), 14-15 (the
/// reviewer the loop starts by itself), 16 (the integrate gate) and 18 (the human's approval and
/// the commit it authorises).
///
/// The approval is the part that cannot be faked. `gates::run_commit` re-freezes the worktree
/// against the gate's `preSha` and refuses unless it still hashes to the `diffHash` a reviewer
/// passed, so a sha coming back at all proves the whole chain agreed: the diff the builder
/// produced, the hash the loop froze, the hash the reviewer echoed, and the index the gate staged.
#[test]
fn pass_reaches_an_integrate_gate_and_the_human_approval_commits_the_reviewed_diff() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[]);
        let base_sha = head_sha(world.repo_root());
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let out = handle
            .delegate(delegate_builder(loop_task("T36-pass")))
            .await
            .expect("the delegation is accepted");
        let run = out.run_id;
        assert_eq!(out.status, RunStatus::Running);
        assert_eq!(
            out.worktree,
            expected_worktree(world.repo_root(), &run, &out.agent_id),
            "the worktree is where the design's on-disk layout says"
        );

        // Step 8: the lead polls its own delegation.
        let envelope = await_done(&handle, out.agent_id).await;
        assert_eq!(envelope.status, AttemptStatus::Succeeded, "{envelope:?}");
        assert_eq!(envelope.role, RoleName::Builder);
        assert!(envelope.structured_valid);
        assert_eq!(
            envelope
                .structured
                .as_ref()
                .and_then(|s| s.get("status"))
                .and_then(Value::as_str),
            Some("succeeded"),
            "the builder's own build-result: {:?}",
            envelope.structured
        );

        // Steps 14-16 happen without the lead asking for anything.
        let events = wait_for_log(&world, &run, "gate.created{integrate}", |events| {
            !gates_of(events, GateKind::Integrate).is_empty()
        })
        .await;

        assert_eq!(
            agents_of(&events, RoleName::Reviewer).len(),
            1,
            "exactly one reviewer was started"
        );
        let frozen = frozen(&events);
        assert_eq!(frozen.len(), 1, "one builder attempt, one frozen diff");
        assert_eq!(
            frozen[0].3,
            vec!["src/adder.ts".to_string()],
            "the frozen diff names what the worker wrote"
        );
        assert!(
            frozen[0].1.starts_with(world.state_dir()),
            "the diff is frozen inside the state dir, not the repo: {:?}",
            frozen[0].1
        );

        // Rev 25: the verdict is bound to the exact diff the reviewer was shown.
        assert_eq!(
            verdicts(&events),
            vec![(Verdict::Pass, Some(frozen[0].2.clone()))],
            "one PASS, echoing the frozen diff's own hash"
        );

        let gates = gates_of(&events, GateKind::Integrate);
        assert_eq!(gates.len(), 1, "exactly one integrate gate");
        let (gate_id, summary) = gates[0].clone();
        assert!(
            summary.contains("Policy violations: none recorded."),
            "the summary names every violation of the lineage: {summary}"
        );

        let status = wait_for_status(
            &handle,
            StatusQuery {
                run_id: Some(run),
                ..StatusQuery::default()
            },
            "run.status{awaiting_gate}",
            |s| {
                s.runs
                    .first()
                    .is_some_and(|r| r.status == RunStatus::AwaitingGate)
            },
        )
        .await;
        assert_eq!(status.runs[0].loop_state, LoopState::AwaitingGate);
        assert_eq!(status.gates.len(), 1);

        // Steps 13/15: the projection a human reads says what each agent is actually doing. Both
        // workers have finished, so neither is `starting` any more, and what the lead should do
        // next is approve rather than wait on anybody.
        let builder = status
            .agents
            .iter()
            .find(|a| a.agent_id == out.agent_id)
            .expect("the builder is in the projection");
        assert_eq!(builder.process_state, AgentStatus::Idle);
        assert_eq!(builder.recommended_next, RecommendedNext::ApproveGate);

        // The payload a human (or the menu-bar app) reads before approving.
        let payload = gate_payload(world.state_dir(), &run, &gate_id);
        assert_eq!(payload.worktree.as_deref(), Some(out.worktree.as_path()));
        assert_eq!(payload.diff_hash.as_deref(), Some(frozen[0].2.as_str()));
        assert_eq!(payload.pre_sha.as_deref(), Some(base_sha.as_str()));
        assert_eq!(payload.files, vec!["src/adder.ts".to_string()]);

        // Step 18. `Actor::Socket` is the human path; the same call over MCP is refused (S2, and
        // pinned in `tests/gates.rs`).
        let resolution = handle
            .resolve_gate(gate_id, true, None, cli_actor())
            .await
            .expect("the approval is answered");
        let GateResolution::Approved { sha: Some(sha) } = resolution else {
            panic!("the gate resolved as {resolution:?}");
        };

        assert_ne!(sha, base_sha, "the approval made a new commit");
        assert_eq!(
            head_sha(&out.worktree),
            sha,
            "the worktree's HEAD is the commit the gate answered with"
        );
        assert_eq!(files_in_commit(&out.worktree, &sha), vec!["src/adder.ts"]);

        let status = wait_for_status(
            &handle,
            StatusQuery {
                run_id: Some(run),
                ..StatusQuery::default()
            },
            "run.status{integrated}",
            |s| {
                s.runs
                    .first()
                    .is_some_and(|r| r.status == RunStatus::Integrated)
            },
        )
        .await;
        assert_eq!(status.runs[0].loop_state, LoopState::Done);
        assert_eq!(status.runs[0].integrated_sha.as_deref(), Some(sha.as_str()));

        let events = world.events(&run);
        assert_eq!(
            pick(&events, |p| match p {
                EventPayload::IntegrateCommitted { sha, .. } => Some(sha.clone()),
                _ => None,
            }),
            vec![sha],
            "exactly one integrate.committed"
        );
        assert_eq!(
            pick(&events, |p| match p {
                EventPayload::IntegrateCommitted { subject, .. } => Some(subject.clone()),
                _ => None,
            }),
            vec!["acp: T36-pass: Add src/adder.ts exporting add(a, b).".to_string()],
            "the commit subject names the task; the review sentence belongs to the body"
        );
        assert!(strikes(&events).is_empty(), "nothing was struck");

        quiesce(&handle).await;
        actor.stop().await;
    });
}

// ---------------------------------------------------------------------------
// FAIL → fix → PASS
// ---------------------------------------------------------------------------

/// 17b through the real loop: the reviewer's `FAIL` strikes the lineage once and the **same**
/// builder is resumed in the **same** session, while the second review is a **new** agent.
///
/// The two identity assertions are the point. A repair that minted a new builder would throw away
/// the session `send_message` exists to reuse, and a reviewer reused across two diffs could carry a
/// verdict about the wrong one.
#[test]
fn a_review_failure_resumes_the_same_builder_and_the_second_review_is_a_new_agent() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("fail_then_pass", &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let out = handle
            .delegate(delegate_builder(loop_task("T36-fail-then-pass")))
            .await
            .expect("the delegation is accepted");
        let run = out.run_id;

        let events = wait_for_log(&world, &run, "gate.created{integrate}", |events| {
            !gates_of(events, GateKind::Integrate).is_empty()
        })
        .await;

        // One strike, on the builder's own lineage, for the one review that failed.
        let struck = strikes(&events);
        assert_eq!(struck.len(), 1, "one FAIL, one strike: {struck:?}");
        assert_eq!(struck[0].1, 1);

        let verdicts = verdicts(&events);
        assert_eq!(
            verdicts.iter().map(|(v, _)| *v).collect::<Vec<_>>(),
            vec![Verdict::Fail, Verdict::Pass],
            "FAIL then PASS"
        );

        assert_eq!(
            agents_of(&events, RoleName::Builder),
            vec![out.agent_id],
            "the repair resumed the builder rather than minting a new one"
        );
        let reviewers = agents_of(&events, RoleName::Reviewer);
        assert_eq!(reviewers.len(), 2, "one reviewer per frozen diff");
        assert_ne!(reviewers[0], reviewers[1], "a fresh reviewer, not a resume");

        // The builder's second attempt is a *resume* (design, step 17b: `attempt.started{kind2}`).
        let builder_attempts: Vec<AttemptKind> = attempts_started(&events)
            .into_iter()
            .filter(|(_, agent, _)| *agent == out.agent_id)
            .map(|(_, _, kind)| kind)
            .collect();
        assert_eq!(
            builder_attempts,
            vec![AttemptKind::Fresh, AttemptKind::Resume],
            "the repair is a resume of the session the first attempt opened"
        );

        // …and the gate that finally opened is bound to the *second* diff.
        let frozen = frozen(&events);
        assert_eq!(frozen.len(), 2, "one diff per builder attempt");
        assert_eq!(
            verdicts[1].1.as_deref(),
            Some(frozen[1].2.as_str()),
            "the PASS echoes the hash of the diff it was shown"
        );
        assert_eq!(gates_of(&events, GateKind::Integrate).len(), 1);

        quiesce(&handle).await;
        actor.stop().await;
    });
}

// ---------------------------------------------------------------------------
// FAIL × 2 → 17d replacement
// ---------------------------------------------------------------------------

/// 17d: two strikes close the lineage, retire its worktree **without deleting it**, and start a
/// replacement builder in a worktree of its own.
///
/// The fixture set has no "fail twice" scenario — `fail_then_pass` is `review-fail-1` then
/// `review-pass-2`, picked by the counter in `$ACP_FAKE_STATE` (`fixtures/jsonl/README.md`). So the
/// codex wrapper is told to truncate that counter before every call (`ACP_FAKE_RESET_STATE`), which
/// pins every reviewer to the scenario's first transcript. Rewriting the file from the test between
/// the two reviews would have raced the loop; doing it in the child cannot.
#[test]
fn two_review_failures_close_the_lineage_and_replace_it_in_a_new_worktree() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("fail_then_pass", &[(FAKE_RESET_STATE, "1")]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let out = handle
            .delegate(delegate_builder(loop_task("T36-replacement")))
            .await
            .expect("the delegation is accepted");
        let run = out.run_id;

        let events = wait_for_log(&world, &run, "the replacement's worktree", |events| {
            worktrees_created(events).len() >= 2
        })
        .await;

        // Two strikes on the first lineage, then it is closed.
        let struck = strikes(&events);
        assert_eq!(
            struck.iter().map(|(_, n)| *n).collect::<Vec<_>>(),
            vec![1, 2],
            "the lineage is struck once per failed review"
        );
        let first_lineage = struck[0].0;
        assert!(
            struck.iter().all(|(lineage, _)| *lineage == first_lineage),
            "both strikes land on the same lineage"
        );

        assert_eq!(
            pick(&events, |p| match p {
                EventPayload::LineageClosed { lineage_id, .. } => Some(*lineage_id),
                _ => None,
            }),
            vec![first_lineage],
            "the lineage is closed exactly once"
        );

        let retired = pick(&events, |p| match p {
            EventPayload::WorktreeRetired {
                path, resumable, ..
            } => Some((path.clone(), *resumable)),
            _ => None,
        });
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].0, out.worktree);
        assert_eq!(retired[0].1, False, "a retired worktree is never resumed");

        // Retained, not deleted: it holds two strikes' worth of work a human may want to read.
        assert!(
            out.worktree.join("src/adder.ts").is_file(),
            "the retired worktree is still on disk with its work in it"
        );

        // The replacement gets a directory and a lineage of its own.
        let worktrees = worktrees_created(&events);
        assert_eq!(worktrees.len(), 2, "{worktrees:?}");
        assert_eq!(worktrees[0], out.worktree);
        assert_ne!(
            worktrees[1], out.worktree,
            "the replacement starts clean, in a new worktree"
        );
        assert!(worktrees[1].is_dir());

        let builders = agents_of(&events, RoleName::Builder);
        assert_eq!(builders.len(), 2, "the replacement is a new builder agent");
        assert_eq!(
            worktrees[1],
            expected_worktree(world.repo_root(), &run, &builders[1])
        );
        let lineages: Vec<LineageId> = pick(&events, |p| match p {
            EventPayload::AgentCreated {
                role: RoleName::Builder,
                lineage_id: Some(lineage_id),
                ..
            } => Some(*lineage_id),
            _ => None,
        });
        assert_ne!(lineages[0], lineages[1], "and a new lineage");

        quiesce(&handle).await;
        actor.stop().await;
    });
}

// ---------------------------------------------------------------------------
// Rev 25 — a verdict that is not about the diff we froze decides nothing
// ---------------------------------------------------------------------------

/// Runs a `pass` scenario whose reviewers all echo [`wrong_hash`], to the point where the run
/// blocks, and hands back the run's durable log.
async fn run_until_blocked_on_a_hash_mismatch(
    world: &LoopWorld,
) -> (RunId, AgentId, Vec<Arc<Event>>) {
    let actor = start_actor(world, embedded_roles(), ActorOpts::default());
    let handle = actor.handle.clone();

    let out = handle
        .delegate(delegate_builder(loop_task("T36-hash-mismatch")))
        .await
        .expect("the delegation is accepted");

    wait_for_status(
        &handle,
        StatusQuery {
            run_id: Some(out.run_id),
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
    (out.run_id, out.agent_id, world.events(&out.run_id))
}

/// A reviewer that echoes the wrong `diffHash` buys **one** replacement reviewer and then the run
/// blocks — and never, at any point, a gate.
///
/// This is the security half of Rev 25: a `PASS` is only ever applied to the diff it was shown, so
/// a reviewer answering about something else is `invalid_output{diff_hash_mismatch}` rather than an
/// approval. The builder is not struck for it — a broken reviewer says nothing about the work.
#[test]
fn a_reviewer_echoing_the_wrong_diff_hash_never_opens_a_gate() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[("ACP_FAKE_DIFF_HASH", WRONG_DIFF_HASH)]);
        let (_run, builder, events) = run_until_blocked_on_a_hash_mismatch(&world).await;

        assert_eq!(
            agents_of(&events, RoleName::Reviewer).len(),
            2,
            "one reviewer, then exactly one replacement, then the run blocks"
        );
        assert!(
            gates_of(&events, GateKind::Integrate).is_empty()
                && gates_of(&events, GateKind::Escalate).is_empty(),
            "a verdict that is not about our diff opens no gate at all"
        );

        // The first reviewer's verdict is recorded with the hash it actually echoed, and refused.
        let verdicts = verdicts(&events);
        assert_eq!(verdicts.first().map(|(v, _)| *v), Some(Verdict::Pass));
        assert_eq!(
            verdicts.first().and_then(|(_, hash)| hash.clone()),
            Some(WRONG_DIFF_HASH.to_string())
        );
        assert!(
            pick(&events, |p| match p {
                EventPayload::AttemptFinished {
                    status: AttemptStatus::InvalidOutput,
                    error: Some(err),
                    ..
                } => Some(err.code),
                _ => None,
            })
            .contains(&ErrorCode::DiffHashMismatch),
            "the reviewer attempt is re-finished as a hash mismatch"
        );

        assert!(
            strikes(&events).is_empty(),
            "the builder is never struck for a reviewer's failure"
        );
        assert_eq!(
            agents_of(&events, RoleName::Builder),
            vec![builder],
            "and it is never replaced either"
        );
    });
}

/// The replacement reviewer belongs to the **builder whose diff was frozen**, not to the reviewer
/// it replaces — and because of that its verdict is bindable and gets recorded.
///
/// `retry_reviewer` reaches `start_reviewer` from a *reviewer's* terminal attempt, so "the builder"
/// cannot be read off the finished attempt the way `branch_review` reads it. Parenting reviewer 2
/// under reviewer 1 breaks the one thing Rev 25 needs: `reviewed_diff` looks for a `diff.frozen`
/// among the parent's attempts, a reviewer has none, and the run then blocks with the wrong cause
/// and no second verdict at all. Both halves are asserted here, because the end state
/// (two reviewers, no gate, blocked run) is the same either way.
#[test]
fn the_replacement_reviewer_is_created_under_the_builder_it_reviews() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[("ACP_FAKE_DIFF_HASH", WRONG_DIFF_HASH)]);
        let (_run, builder, events) = run_until_blocked_on_a_hash_mismatch(&world).await;

        let parents: Vec<Option<AgentId>> = pick(&events, |p| match p {
            EventPayload::AgentCreated {
                role: RoleName::Reviewer,
                parent_agent_id,
                ..
            } => Some(*parent_agent_id),
            _ => None,
        });
        assert_eq!(
            parents,
            vec![Some(builder), Some(builder)],
            "every reviewer is created under the builder whose diff it reviews"
        );

        assert_eq!(
            verdicts(&events),
            vec![
                (Verdict::Pass, Some(WRONG_DIFF_HASH.to_string())),
                (Verdict::Pass, Some(WRONG_DIFF_HASH.to_string())),
            ],
            "both verdicts are recorded with the hash they echoed"
        );
        assert_eq!(
            pick(&events, |p| match p {
                EventPayload::AttemptFinished {
                    status: AttemptStatus::InvalidOutput,
                    error: Some(err),
                    ..
                } => Some(err.code),
                _ => None,
            }),
            vec![ErrorCode::DiffHashMismatch, ErrorCode::DiffHashMismatch],
            "each reviewer attempt is re-finished as a hash mismatch"
        );

        let blocked = pick(&events, |p| match p {
            EventPayload::RunStatus_ {
                status: RunStatus::Blocked,
                reason,
            } => reason.clone(),
            _ => None,
        });
        assert!(
            blocked
                .iter()
                .any(|reason| reason.contains("diffHash") && reason.contains("reviewers")),
            "the block names the hash mismatch as the cause: {blocked:?}"
        );
    });
}

// ---------------------------------------------------------------------------
// The worker environment (design, § Worker environment)
// ---------------------------------------------------------------------------

/// Restores an environment variable however this test leaves, including on a panic.
struct EnvGuard(&'static str, Option<std::ffi::OsString>);

impl EnvGuard {
    fn set(key: &'static str, value: &Path) -> Self {
        let guard = Self(key, std::env::var_os(key));
        std::env::set_var(key, value);
        guard
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.1.take() {
            Some(previous) => std::env::set_var(self.0, previous),
            None => std::env::remove_var(self.0),
        }
    }
}

/// A worker started by the real loop gets **exactly** `{PATH, HOME, TMPDIR, LANG, USER, LOGNAME}` ∪
/// `GIT_CONFIG_{COUNT,KEY_0,VALUE_0}` ∪ `ACP_FAKE_*`, and nothing else.
///
/// The proof is `ACP_FAKE_RECORD` itself. Nothing on the spawn path names it: the wrappers set only
/// the scenario and the counter file, and no test writes it into a plan — the loop builds every
/// plan itself. So the record file existing at all means `providers::base_env`'s fixed-prefix
/// pass-through carried the key from this process, through `assert_safe_argv` (whose check 5
/// accepts the prefix and rejects any forwarded value containing the state-dir path — hence the
/// separate temp dir), and into the child.
///
/// The fake reports back **every** `ACP_*` key it can see, so the same record also proves the
/// negative half of the rule: no other `ACP_*` key — `ACP_STATE_DIR` above all — reaches a worker.
///
/// Exclusive, because setting a variable in this process is something no other test may observe.
#[test]
fn a_worker_sees_the_acp_fake_pass_through_and_no_other_acp_key() {
    common::with_exclusive_env(|| async {
        // Outside `$ACP_STATE_DIR`: a forwarded value containing it is `UnsafeEnv`, which is the
        // rule that stops a worker learning the socket that approves its own gate.
        let records = tempfile::tempdir().expect("tempdir for the fake's record file");
        let record = records.path().join("calls.jsonl");
        let _env = EnvGuard::set("ACP_FAKE_RECORD", &record);

        let world = LoopWorld::new("pass", &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();
        let out = handle
            .delegate(delegate_builder(loop_task("T36-worker-env")))
            .await
            .expect("the delegation is accepted");

        wait_for_log(&world, &out.run_id, "gate.created{integrate}", |events| {
            !gates_of(events, GateKind::Integrate).is_empty()
        })
        .await;
        quiesce(&handle).await;
        actor.stop().await;

        let lines: Vec<Value> = std::fs::read_to_string(&record)
            .unwrap_or_else(|err| {
                panic!(
                    "the record file {} was never written, so ACP_FAKE_RECORD never reached a \
                     worker: {err}",
                    record.display()
                )
            })
            .lines()
            .map(|line| serde_json::from_str(line).expect("the fake writes one JSON object a line"))
            .collect();
        assert!(
            lines.len() >= 2,
            "one builder and one reviewer at least: {lines:?}"
        );

        for line in &lines {
            let env = &line["envSubset"];
            let keys: Vec<&str> = env["acpEnvKeys"]
                .as_array()
                .expect("acpEnvKeys is an array")
                .iter()
                .map(|key| key.as_str().expect("a key is a string"))
                .collect();
            assert!(
                keys.contains(&"ACP_FAKE_RECORD"),
                "the pass-through carried the key the daemon set: {keys:?}"
            );
            assert!(
                keys.iter().all(|key| key.starts_with("ACP_FAKE_")),
                "a worker may see no other ACP_ key: {keys:?}"
            );
            // C4/V5: a worker that runs `git push` pushes nowhere.
            assert_eq!(env["gitConfigCount"], Value::from("1"));
            assert_eq!(env["gitConfigKey0"], Value::from("remote.origin.url"));
            assert_eq!(env["gitConfigValue0"], Value::from(""));
        }
    });
}

/// The other half of Rev 25's rule: a refused reviewer costs **one** replacement, and that
/// replacement is a real review — a `PASS` from it opens the integrate gate.
///
/// This is what the parenting fix buys. Blocking after two bad hashes only proves the loop stops
/// spending; this proves it can still *finish*, which is the whole point of granting a second
/// reviewer rather than blocking on the first. The first call echoes a wrong hash and the second
/// echoes the real one (`ACP_FAKE_WRONG_HASH_ONCE`, resolved in the child so nothing races the
/// loop), so the two reviewers differ in exactly the fact under test.
#[test]
fn a_replacement_reviewer_that_echoes_the_right_hash_opens_the_gate() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[]);
        let marker = world.repo_root().join(".acp-fake-wrong-hash-once");
        common::configure_fakes(
            world.repo_root(),
            "pass",
            &[(FAKE_WRONG_HASH_ONCE, &marker.display().to_string())],
        );

        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();
        let out = handle
            .delegate(delegate_builder(loop_task("T36-second-reviewer")))
            .await
            .expect("the delegation is accepted");
        let run = out.run_id;

        let events = wait_for_log(&world, &run, "gate.created{integrate}", |events| {
            !gates_of(events, GateKind::Integrate).is_empty()
        })
        .await;

        // One builder attempt, one frozen diff, two reviewers of it — and only one gate.
        let frozen = frozen(&events);
        assert_eq!(frozen.len(), 1, "the builder ran once");
        let reviewers = agents_of(&events, RoleName::Reviewer);
        assert_eq!(
            reviewers.len(),
            2,
            "the refused review bought exactly one more"
        );
        assert_eq!(gates_of(&events, GateKind::Integrate).len(), 1);

        // The first verdict is refused for its hash; the second decides.
        assert_eq!(
            verdicts(&events),
            vec![
                (Verdict::Pass, Some(WRONG_DIFF_HASH.to_string())),
                (Verdict::Pass, Some(frozen[0].2.clone())),
            ],
            "a PASS only integrates the diff it was actually shown"
        );
        assert_eq!(
            pick(&events, |p| match p {
                EventPayload::AttemptFinished {
                    status: AttemptStatus::InvalidOutput,
                    error: Some(err),
                    ..
                } => Some(err.code),
                _ => None,
            }),
            vec![ErrorCode::DiffHashMismatch],
            "exactly one attempt was refused, and for the hash"
        );
        assert!(
            strikes(&events).is_empty(),
            "the builder is never struck for a reviewer's failure"
        );

        let status = wait_for_status(
            &handle,
            StatusQuery {
                run_id: Some(run),
                ..StatusQuery::default()
            },
            "run.status{awaiting_gate}",
            |s| {
                s.runs
                    .first()
                    .is_some_and(|r| r.status == RunStatus::AwaitingGate)
            },
        )
        .await;
        assert_eq!(status.runs[0].loop_state, LoopState::AwaitingGate);

        quiesce(&handle).await;
        actor.stop().await;
    });
}
