//! T38: the two things the loop has to survive — a **restart mid-run** and a **denied gate** —
//! driven through the whole actor (`reports/03-design.md` § Test Strategy, row `core/loop.rs`:
//! "restart mid-run → `get_status` equals the pre-kill snapshot; `resolve_gate(false, feedback)` →
//! resume with no strike", and the requirements' "Restart mid-run" acceptance criterion).
//!
//! See `tests/loop_pass.rs` for how a scenario reaches the fake CLIs and for the process-hygiene
//! rule every test here also obeys.
//!
//! **What makes the restart comparison meaningful.** Both snapshots are taken over a log that is
//! not moving. The worker is started with `ACP_FAKE_DELAY_MS` long enough that its second line
//! cannot arrive during the test, so a tail has nothing to append; the second core is built with
//! `ActorOpts::no_tick`, so it does not probe, sweep or tail until the comparison is done; and the
//! worker itself survives the first core on purpose (`kill_on_drop(false)` — design, C3: "workers
//! survive; a restart re-attaches"). What is left is exactly the question the design asks: does a
//! `Core` rebuilt by replaying `runs/*/events.jsonl` describe the world the same way?

mod common;

use std::sync::Arc;

use agent_control_plane::core::handoff::ADVISORY_OPEN;
use agent_control_plane::core::types::{
    AgentId, AgentStatus, AttemptKind, AttemptStatus, Event, EventPayload, GateId, GateKind,
    GateStatus, LoopState, RoleName, RunStatus,
};
use agent_control_plane::core::{Actor, GateResolution, StatusQuery};

use common::{
    delegate_builder, embedded_roles, head_sha, loop_task, pick, quiesce, rendered_prompt,
    start_actor, wait_for_log, ActorOpts, LoopWorld,
};

/// Long enough that the worker's second transcript line cannot arrive while the test is comparing
/// two snapshots, short enough that nothing waits on it: the worker is ended by a cancellation, not
/// by this timer.
const SLOW: &str = "30000";

fn attempts_started(events: &[Arc<Event>]) -> Vec<(AgentId, AttemptKind, std::path::PathBuf)> {
    pick(events, |p| match p {
        EventPayload::AttemptStarted {
            agent_id,
            attempt_kind,
            dir,
            ..
        } => Some((*agent_id, *attempt_kind, dir.clone())),
        _ => None,
    })
}

fn reviewers(events: &[Arc<Event>]) -> Vec<AgentId> {
    pick(events, |p| match p {
        EventPayload::AgentCreated {
            agent_id,
            role: RoleName::Reviewer,
            ..
        } => Some(*agent_id),
        _ => None,
    })
}

/// The `seq` of the **last** event matching `pred`, so an assertion about ordering after a gate
/// resolution is not satisfied by an identical event from earlier in the run.
fn seq_of(events: &[Arc<Event>], what: &str, pred: impl Fn(&EventPayload) -> bool) -> u64 {
    events
        .iter()
        .rev()
        .find(|event| pred(&event.payload))
        .unwrap_or_else(|| panic!("{what} is not in the log"))
        .base
        .seq
}

fn integrate_gates(events: &[Arc<Event>]) -> Vec<GateId> {
    pick(events, |p| match p {
        EventPayload::GateCreated {
            gate_id,
            gate_kind: GateKind::Integrate,
            ..
        } => Some(*gate_id),
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// Restart mid-run
// ---------------------------------------------------------------------------

/// A `Core` rebuilt from the log alone answers `get_status` exactly as the one that died did.
///
/// The design's restart contract is that `Registry::open` replays every `runs/*/events.jsonl`
/// through the same `reduce()` used at write time, so the projection is a pure function of the log
/// — and `get_status` is a pure function of the projection. Comparing the two whole `StatusOut`
/// values is therefore the strongest form of the claim: same run, same agents, same attempts, same
/// gates, same spend, same event tail, in the same order.
///
/// The in-flight attempt is the interesting part. It is still `running` in the log, the process is
/// still alive because a normal stop leaves workers running (C3), and `Supervisor::reattach` picks
/// it up from `pid` + `lstart` — so the restarted core reports it as running rather than losing it.
#[test]
fn a_core_rebuilt_from_the_log_reports_the_same_status_as_the_one_that_died() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[("ACP_FAKE_DELAY_MS", SLOW)]);
        let first = start_actor(&world, embedded_roles(), ActorOpts::default());
        let out = first
            .handle
            .delegate(delegate_builder(loop_task("T38-restart")))
            .await
            .expect("the delegation is accepted");
        let run = out.run_id;
        let query = StatusQuery {
            run_id: Some(run),
            ..StatusQuery::default()
        };

        // Partway: the attempt has started **and** at least one tick has tailed it — `agent.session`
        // is only written by the tailer, so its presence proves both.
        wait_for_log(&world, &run, "agent.session", |events| {
            events
                .iter()
                .any(|e| matches!(&e.payload, EventPayload::AgentSession { .. }))
        })
        .await;

        let before = first
            .handle
            .status(query.clone())
            .await
            .expect("the snapshot before the kill");
        assert_eq!(before.attempts.len(), 1);
        assert_eq!(before.attempts[0].status, AttemptStatus::Running);
        // …and the projection says so about the agent too (design, steps 13/15).
        assert_eq!(before.agents[0].process_state, AgentStatus::Running);
        let attempt = before.attempts[0].attempt_id;

        // The daemon goes away; the worker does not.
        first.stop().await;

        // A fresh everything — registry, supervisor, core — over the same state dir, re-attaching
        // to whatever the log still calls `running`. No tick task yet: nothing may append between
        // the two snapshots, or the comparison would be against a moving log.
        let mut second = start_actor(
            &world,
            embedded_roles(),
            ActorOpts {
                reattach: true,
                no_tick: true,
            },
        );
        let after = second
            .handle
            .status(query)
            .await
            .expect("the snapshot after the restart");

        assert_eq!(
            after, before,
            "a core rebuilt by replaying the log must describe the run identically"
        );
        assert_eq!(
            after.attempts[0].status,
            AttemptStatus::Running,
            "the re-attached attempt is still running, not silently lost"
        );
        assert_eq!(after.attempts[0].attempt_id, attempt);

        // …and the restarted core really did adopt it: with the tick task running, cancelling the
        // attempt reaches the process the *first* core started.
        second.start_ticking();
        quiesce(&second.handle).await;
        let ended = second
            .handle
            .status(StatusQuery {
                run_id: Some(run),
                ..StatusQuery::default()
            })
            .await
            .expect("the final status");
        assert_eq!(
            ended.attempts[0].status,
            AttemptStatus::Cancelled,
            "the second core signalled a worker it never started"
        );
        second.stop().await;
    });
}

// ---------------------------------------------------------------------------
// A denied gate is not a strike (decision 6)
// ---------------------------------------------------------------------------

/// `resolve_gate{approve:false, feedback}` over the **MCP** door: nothing is committed, nobody is
/// struck, and the live builder is resumed with the human's words quoted to it as data.
///
/// Three separate rules meet here. S2 lets a model *deny* a gate even though it may not approve
/// one. Decision 6 says a human asking for a change is not a failure of the model, so no
/// `lineage.strike` is appended. And S3 says the human's words are untrusted text like any other,
/// so they travel inside the advisory block rather than as instructions.
#[test]
fn denying_a_gate_with_feedback_commits_nothing_strikes_nobody_and_resumes_the_builder() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[]);
        let base_sha = head_sha(world.repo_root());
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let out = handle
            .delegate(delegate_builder(loop_task("T38-deny")))
            .await
            .expect("the delegation is accepted");
        let run = out.run_id;

        let events = wait_for_log(&world, &run, "gate.created{integrate}", |events| {
            !integrate_gates(events).is_empty()
        })
        .await;
        let gate = integrate_gates(&events)[0];
        let attempts_before = attempts_started(&events).len();

        // A lead may deny; only a human may approve (S2, pinned in `tests/gates.rs`).
        let resolution = handle
            .resolve_gate(gate, false, Some("needs work".to_string()), Actor::Mcp)
            .await
            .expect("the denial is answered");
        assert_eq!(
            resolution,
            GateResolution::Denied {
                feedback: Some("needs work".to_string())
            }
        );

        let events = wait_for_log(&world, &run, "the builder is resumed", |events| {
            attempts_started(events).len() > attempts_before
        })
        .await;

        // Nothing was committed — not by the gate, and not behind it.
        assert!(
            pick(&events, |p| match p {
                EventPayload::IntegrateCommitted { .. } => Some(()),
                _ => None,
            })
            .is_empty(),
            "a denial never commits"
        );
        assert_eq!(
            head_sha(&out.worktree),
            base_sha,
            "the worktree's HEAD is untouched"
        );

        // Decision 6: a human asking for a change is not a failure of the model.
        assert!(
            pick(&events, |p| match p {
                EventPayload::LineageStrike { .. } => Some(()),
                _ => None,
            })
            .is_empty(),
            "deny + feedback is not a strike"
        );

        // …and the builder it goes back to is the same one, in the same session.
        let started = attempts_started(&events);
        assert_eq!(started.len(), attempts_before + 1);
        let (agent, kind, dir) = started.last().cloned().expect("the resumed attempt");
        assert_eq!(agent, out.agent_id, "the same builder");
        assert_eq!(kind, AttemptKind::Resume, "in the same session");

        let prompt = rendered_prompt(&dir);
        assert!(
            prompt.contains("needs work"),
            "the human's feedback reaches the worker: {prompt}"
        );
        assert!(
            prompt.contains(ADVISORY_OPEN),
            "…quoted as data, never as instructions (S3): {prompt}"
        );

        // The gate itself is resolved, once, as denied.
        assert_eq!(
            pick(&events, |p| match p {
                EventPayload::GateResolved {
                    gate_id,
                    status,
                    sha,
                    feedback,
                } if *gate_id == gate => Some((*status, sha.clone(), feedback.clone())),
                _ => None,
            }),
            vec![(
                agent_control_plane::core::types::GateStatus::Denied,
                None,
                Some("needs work".to_string())
            )],
            "one gate.resolved{{denied}}, carrying the feedback and no sha"
        );

        quiesce(&handle).await;
        actor.stop().await;
    });
}

/// The builder a denial resumes actually **runs**, and the loop goes round again.
///
/// Step 16 leaves the run `awaiting_gate`, and every deferred spawn re-asks `run_accepts_workers`
/// (`status == Running`) immediately before adopting its child — so a denial that resumes a builder
/// without first handing the run back to the loop writes `attempt.started` and then cancels the
/// worker it has just adopted, leaving the run parked for ever behind a gate it already answered.
/// Step 19's order is what this pins: `gate.resolved` → `run.status{running}` →
/// `loop.state{repairing}` → the resume → back to step 7.
#[test]
fn a_denied_gate_lets_the_resumed_builder_actually_run() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let out = handle
            .delegate(delegate_builder(loop_task("T38-deny-runs")))
            .await
            .expect("the delegation is accepted");
        let run = out.run_id;

        let events = wait_for_log(&world, &run, "gate.created{integrate}", |events| {
            !integrate_gates(events).is_empty()
        })
        .await;
        let gate = integrate_gates(&events)[0];
        let attempts_before = attempts_started(&events).len();

        handle
            .resolve_gate(gate, false, Some("needs work".to_string()), Actor::Mcp)
            .await
            .expect("the denial is answered");

        // The second reviewer **running** is the proof the loop went round, not just one step: it
        // only starts if the resumed builder ran, succeeded and had its diff frozen.
        //
        // Waiting on its `attempt.started` rather than its `agent.created` is not a detail. The two
        // are appended in different turns — `start_reviewer` announces the agent, and the spawn
        // helper it hands off to reports back later — so a wait on the announcement returns while
        // the attempt count is still one short of what this test is about to assert.
        // B1: each build cycle is now builder → verifier → reviewer, so the resumed round adds
        // THREE attempts; waiting on +2 would release after the verifier starts, one short of
        // the reviewer this test is about.
        let events = wait_for_log(
            &world,
            &run,
            "the repaired change is reviewed again",
            |events| attempts_started(events).len() >= attempts_before + 3,
        )
        .await;

        assert!(
            !pick(&events, |p| match p {
                EventPayload::AttemptFinished { status, .. } => Some(*status),
                _ => None,
            })
            .contains(&AttemptStatus::Cancelled),
            "the builder the human asked to keep working is never cancelled out from under itself"
        );
        assert_eq!(
            reviewers(&events).len(),
            2,
            "one review per builder attempt"
        );
        assert_eq!(attempts_started(&events).len(), attempts_before + 3);

        // Step 19's durable order, read off the log rather than off a snapshot: by the time a test
        // can ask, the loop has already moved on — which is the point.
        let denied = seq_of(&events, "gate.resolved{denied}", |p| {
            matches!(
                p,
                EventPayload::GateResolved {
                    status: GateStatus::Denied,
                    ..
                }
            )
        });
        let running = seq_of(&events, "run.status{running} after the denial", |p| {
            matches!(
                p,
                EventPayload::RunStatus_ {
                    status: RunStatus::Running,
                    ..
                }
            )
        });
        let repairing = seq_of(&events, "loop.state{repairing}", |p| {
            matches!(
                p,
                EventPayload::LoopStateChanged {
                    state: LoopState::Repairing,
                    ..
                }
            )
        });
        let resumed = seq_of(&events, "the resumed attempt.started", |p| {
            matches!(
                p,
                EventPayload::AttemptStarted {
                    attempt_kind: AttemptKind::Resume,
                    ..
                }
            )
        });
        assert!(
            denied < running && running < repairing && repairing < resumed,
            "gate.resolved({denied}) → run.status{{running}}({running}) → \
             loop.state{{repairing}}({repairing}) → attempt.started({resumed})"
        );

        quiesce(&handle).await;
        actor.stop().await;
    });
}
