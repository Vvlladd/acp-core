//! T84: `run.delegated` — the lead's own run durably records, by event linkage, every run its
//! delegation caused (`reports/17-ux-design.md`, Amendment 1 + the mechanics addendum). Every
//! provider is the fake Claude CLI; no test in this file spends a token or runs an ignored live
//! probe.
//!
//! `"hang"` is used deliberately for the lead (and, where a worker's own run matters, for the
//! worker too): it keeps an attempt `Running` — never `Succeeded` — so `Core::live_lead_agent`
//! keeps seeing the lead as live for as long as the test needs it. A worker's `run.created` is
//! git-only (`add_worktree`, not the fake CLI's own output), so it lands durably regardless of
//! whether that worker's own process ever produces a line.

mod common;

use agent_control_plane::core::plan::{Plan, PlanItem, PlanItemKind, PLAN_VERSION};
use agent_control_plane::core::policy::{DelegateRequest, SessionSpec};
use agent_control_plane::core::types::{
    AgentId, AttemptStatus, DelegatedTarget, EventPayload, RoleName, RunId, RunStatus, Task,
};
use agent_control_plane::core::{CoreHandle, StatusQuery};

use common::{
    cli_actor, configure_fakes, delegate_builder, delegate_builder_from, embedded_roles,
    loop_task, quiesce, start_actor, wait_for_log, wait_for_status, ActorOpts, LoopWorld,
};

/// Starts a conversational lead and waits until its attempt is `Running` — the daemon's own
/// definition of "live" (`Core::live_lead_agent`) — before handing back its run.
async fn start_live_lead(handle: &CoreHandle) -> (RunId, AgentId) {
    let task = Task {
        id: "lead".to_string(),
        title: "Lead conversation".to_string(),
        description: "Coordinate the next task.".to_string(),
        files: Vec::new(),
        acceptance: Vec::new(),
    };
    let started = handle
        .start_lead(task, "Coordinate the next task.".to_string())
        .await
        .expect("the lead starts");
    wait_for_status(
        handle,
        StatusQuery {
            agent_id: Some(started.agent_id),
            ..StatusQuery::default()
        },
        "the lead to be running",
        |status| {
            status
                .attempts
                .iter()
                .any(|a| a.agent_id == started.agent_id && a.status == AttemptStatus::Running)
        },
    )
    .await;
    (started.run_id, started.agent_id)
}

/// The one `run.delegated` payload of `events`, if any — panics if more than one, since every
/// scenario in this file delegates exactly once.
fn only_run_delegated(
    events: &[std::sync::Arc<agent_control_plane::core::types::Event>],
) -> Option<(RunId, Option<RoleName>, DelegatedTarget)> {
    let mut found = None;
    for event in events {
        if let EventPayload::RunDelegated {
            delegated_run_id,
            role,
            target,
        } = &event.payload
        {
            assert!(found.is_none(), "more than one run.delegated on this run");
            found = Some((*delegated_run_id, *role, *target));
        }
    }
    found
}

#[tokio::test]
async fn a_valid_caller_run_id_records_run_delegated_after_the_workers_run_created() {
    let world = LoopWorld::new("hang", &[]);
    let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
    let handle = actor.handle.clone();

    let (lead_run, _lead_agent) = start_live_lead(&handle).await;

    let out = handle
        .delegate(delegate_builder_from(loop_task("T84-delegate"), lead_run))
        .await
        .expect("a validly-attested delegate is accepted");
    let worker_run = out.run_id;

    // `run.created` for the worker lands durably (git-only — independent of the hung fake CLI).
    // Because the emit site appends `run.delegated` on the lead's run in the very same,
    // never-yielding branch immediately after that append, the moment this wait resolves the
    // linkage (if any) is already durable too — no extra polling window is needed below.
    wait_for_log(&world, &worker_run, "the worker's run.created", |events| {
        events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::RunCreated { .. }))
    })
    .await;

    let lead_events = world.events(&lead_run);
    let (delegated_run, role, target) =
        only_run_delegated(&lead_events).expect("run.delegated was written to the lead's run");
    assert_eq!(delegated_run, worker_run);
    assert_eq!(role, Some(RoleName::Builder));
    assert_eq!(target, DelegatedTarget::Worker);
    assert!(
        world.reopen().run(&worker_run).is_some(),
        "the linkage must never point at a run that does not (yet) exist"
    );

    quiesce(&handle).await;
    actor.stop().await;
}

#[tokio::test]
async fn plan_start_with_a_valid_caller_run_id_records_the_container_variant() {
    let world = LoopWorld::new("hang", &[]);
    let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
    let handle = actor.handle.clone();

    let (lead_run, _lead_agent) = start_live_lead(&handle).await;

    let plan = Plan {
        version: PLAN_VERSION,
        name: "t84 plan".to_string(),
        items: vec![PlanItem {
            id: "only".to_string(),
            kind: PlanItemKind::Work,
            task: Some(loop_task("T84-plan")),
            summary: None,
            after: vec![],
            verify: None,
            review: None,
        }],
    };
    let out = handle
        .start_plan(plan, Some(lead_run))
        .await
        .expect("a validly-attested plan.start is accepted");
    let container = out.run_id;

    let lead_events = wait_for_log(
        &world,
        &lead_run,
        "run.delegated{target:\"plan\"} on the lead's run",
        |events| only_run_delegated(events).is_some(),
    )
    .await;
    let (delegated_run, role, target) =
        only_run_delegated(&lead_events).expect("run.delegated was written to the lead's run");
    assert_eq!(delegated_run, container);
    assert_eq!(role, None, "a plan container mints no single role of its own");
    assert_eq!(target, DelegatedTarget::Plan);
    assert!(world.reopen().run(&container).is_some());

    quiesce(&handle).await;
    actor.stop().await;
}

#[tokio::test]
async fn a_forged_caller_run_id_with_no_live_lead_emits_nothing_and_delegate_still_succeeds() {
    let world = LoopWorld::new("pass", &[]);
    let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
    let handle = actor.handle.clone();

    let forged = RunId::new_v4();
    let out = handle
        .delegate(delegate_builder_from(loop_task("T84-no-lead"), forged))
        .await
        .expect("an unattested delegate proceeds exactly as it always has");
    wait_for_log(&world, &out.run_id, "the worker's run.created", |events| {
        events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::RunCreated { .. }))
    })
    .await;

    // The daemon only ever confirms what it itself wrote into a proxy child's environment — with
    // no live lead at all, there is nothing to confirm, and the claimed id gets no run.delegated,
    // no run.created and no log file: it never existed as far as the registry is concerned.
    assert!(
        world.events(&forged).is_empty(),
        "a run with no live lead to attest it must receive no write whatsoever"
    );

    quiesce(&handle).await;
    actor.stop().await;
}

#[tokio::test]
async fn a_stale_caller_run_id_emits_nothing_though_a_lead_is_live() {
    let world = LoopWorld::new("hang", &[]);
    let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
    let handle = actor.handle.clone();

    let (lead_run, _lead_agent) = start_live_lead(&handle).await;
    let forged = RunId::new_v4();
    assert_ne!(forged, lead_run, "the forged id must not accidentally be the real one");

    let out = handle
        .delegate(delegate_builder_from(loop_task("T84-stale"), forged))
        .await
        .expect("delegate still succeeds — only the attribution is dropped");
    wait_for_log(&world, &out.run_id, "the worker's run.created", |events| {
        events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::RunCreated { .. }))
    })
    .await;

    assert!(
        only_run_delegated(&world.events(&lead_run)).is_none(),
        "a caller id that does not name the live lead's own run must not be attested"
    );
    assert!(
        world.events(&forged).is_empty(),
        "the forged run itself never received a write either"
    );

    quiesce(&handle).await;
    actor.stop().await;
}

#[tokio::test]
async fn no_caller_run_id_emits_nothing_the_terminal_lead_app_and_cli_shape() {
    let world = LoopWorld::new("hang", &[]);
    let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
    let handle = actor.handle.clone();

    // A live lead exists, but this delegation — like every app, CLI or terminal-lead call today —
    // carries no `callerRunId` at all.
    let (lead_run, _lead_agent) = start_live_lead(&handle).await;

    let out = handle
        .delegate(delegate_builder(loop_task("T84-no-caller")))
        .await
        .expect("delegate succeeds, byte-identical to every pre-T84 call");
    wait_for_log(&world, &out.run_id, "the worker's run.created", |events| {
        events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::RunCreated { .. }))
    })
    .await;

    assert!(
        only_run_delegated(&world.events(&lead_run)).is_none(),
        "no callerRunId means no linkage, exactly like every door before T84"
    );

    quiesce(&handle).await;
    actor.stop().await;
}

/// Review note #1: a lead may `delegate{runId: <its own run>}` — nothing in `check_delegate`
/// restricts which run a delegation attaches to, and a lead's own conversation run is one it can
/// legally name. Attaching to it is pre-existing and unremarkable, but writing `run.delegated`
/// with `delegatedRunId == caller` on the caller's own run would be a self-edge: the lead would
/// appear in its own delegation list (`delegations(for: leadRunId)`), at best duplicated, at worst
/// a cycle in any tree expansion. `record_delegation` must write nothing for it.
#[tokio::test]
async fn delegating_into_its_own_run_writes_no_self_pointing_run_delegated() {
    let world = LoopWorld::new("hang", &[]);
    let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
    let handle = actor.handle.clone();

    let (lead_run, _lead_agent) = start_live_lead(&handle).await;

    let self_delegate = DelegateRequest {
        run_id: Some(lead_run),
        caller_run_id: Some(lead_run),
        ..delegate_builder(loop_task("T84-self-edge"))
    };
    let out = handle
        .delegate(self_delegate)
        .await
        .expect("a lead delegating into its own run still succeeds");
    assert_eq!(
        out.run_id, lead_run,
        "the delegation attaches to the lead's own run, exactly as asked"
    );

    assert!(
        only_run_delegated(&world.events(&lead_run)).is_none(),
        "a lead delegating into its own run must not record itself as its own delegation"
    );

    quiesce(&handle).await;
    actor.stop().await;
}

/// Review note #4: the attach-to-existing-run emit site (`src/core/loop.rs`, the `!new_run`
/// branch) had no direct pin. The run already carries its own `run.created` — from an earlier,
/// deliberately *unattested* delegation, so that first call leaves no `run.delegated` of its own —
/// so the write this test cares about is the only one on the lead's run, and it must be immediate:
/// no worktree helper to wait on, unlike the fresh-run path.
#[tokio::test]
async fn attaching_to_an_existing_run_records_run_delegated_immediately() {
    let world = LoopWorld::new("hang", &[]);
    let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
    let handle = actor.handle.clone();

    let (lead_run, _lead_agent) = start_live_lead(&handle).await;

    let existing = handle
        .delegate(delegate_builder(loop_task("T84-attach-setup")))
        .await
        .expect("the unattested setup delegation is accepted");
    let worker_run = existing.run_id;
    wait_for_log(&world, &worker_run, "the worker's run.created", |events| {
        events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::RunCreated { .. }))
    })
    .await;
    assert!(
        only_run_delegated(&world.events(&lead_run)).is_none(),
        "the setup call was unattested and must have left no linkage of its own"
    );

    let attach = DelegateRequest {
        run_id: Some(worker_run),
        caller_run_id: Some(lead_run),
        ..delegate_builder(loop_task("T84-attach"))
    };
    let out = handle
        .delegate(attach)
        .await
        .expect("attaching a second builder to the existing run is accepted");
    assert_eq!(out.run_id, worker_run, "the attach reused the existing run");

    let (delegated_run, role, target) =
        only_run_delegated(&world.events(&lead_run)).expect("run.delegated was written on attach");
    assert_eq!(delegated_run, worker_run);
    assert_eq!(role, Some(RoleName::Builder));
    assert_eq!(target, DelegatedTarget::Worker);

    quiesce(&handle).await;
    actor.stop().await;
}

/// Review note #4: the resume emit site (`delegate_resume`) had no direct pin either. The builder
/// runs the whole happy path to a resolved integrate gate — a real `Core::resume_attempt` needs a
/// resumable session and no *pending* gate in its way — then a second, different-task `delegate`
/// resumes it with a validly-attested `callerRunId`.
///
/// The setup delegation is deliberately unattested (same reasoning as the attach test above), so
/// the one `run.delegated` this test finds is the resume's own write.
#[tokio::test]
async fn resuming_an_agent_with_a_valid_caller_run_id_records_run_delegated_on_success() {
    let world = LoopWorld::new("hang", &[]);
    let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
    let handle = actor.handle.clone();

    let (lead_run, _lead_agent) = start_live_lead(&handle).await;
    // `AttemptStatus::Running` is set the moment the process is spawned — before the wrapper
    // shell has necessarily sourced `.acp-fake-env` and exec'd the real fake binary. Waiting for
    // the lead's own `agent.session` (the `hang` scenario's one streamed line, before it blocks)
    // is proof the *real* binary already read "hang", so it is now safe to repoint the file for
    // the delegations that follow without racing the lead's own spawn.
    wait_for_log(&world, &lead_run, "the lead's agent.session", |events| {
        events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::AgentSession { .. }))
    })
    .await;

    // Repointed *after* the lead is spawned, so the still-hung lead is unaffected — wrapper CLIs
    // source `.acp-fake-env` once, at their own start (`common::configure_fakes`'s own doc).
    configure_fakes(world.repo_root(), "pass", &[]);

    let setup = handle
        .delegate(delegate_builder(loop_task("T84-resume-setup")))
        .await
        .expect("the unattested setup delegation is accepted");
    let worker_run = setup.run_id;
    let worker_agent = setup.agent_id;

    let status = wait_for_status(
        &handle,
        StatusQuery {
            run_id: Some(worker_run),
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
    let gate_id = status
        .gates
        .first()
        .expect("the pass pipeline opens one integrate gate")
        .gate_id;
    handle
        .resolve_gate(gate_id, true, None, cli_actor())
        .await
        .expect("the human approves, clearing the way for a resume");
    assert!(
        only_run_delegated(&world.events(&lead_run)).is_none(),
        "the setup call was unattested and must have left no linkage of its own"
    );

    let resume = DelegateRequest {
        run_id: Some(worker_run),
        caller_run_id: Some(lead_run),
        session: SessionSpec::Resume(worker_agent),
        ..delegate_builder(loop_task("T84-resume"))
    };
    let resumed = handle
        .delegate(resume)
        .await
        .expect("resuming the builder with a validly-attested caller succeeds");
    assert_eq!(resumed.run_id, worker_run);
    assert_eq!(resumed.agent_id, worker_agent);

    let (delegated_run, role, target) =
        only_run_delegated(&world.events(&lead_run)).expect("run.delegated was written on resume");
    assert_eq!(delegated_run, worker_run);
    assert_eq!(role, Some(RoleName::Builder));
    assert_eq!(target, DelegatedTarget::Worker);

    quiesce(&handle).await;
    actor.stop().await;
}
