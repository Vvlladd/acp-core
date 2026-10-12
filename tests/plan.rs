//! T79 (B3): the plan conductor end to end, through fake providers — the brief's acceptance
//! (`reports/06-phase2-requirements.md:52-53`): a two-item sequence and a two-item parallel
//! fanout with per-step gates, plus the refusal and restart shapes the design pins.

mod common;

use std::sync::Arc;

use agent_control_plane::core::plan::{Plan, PlanItem, PlanItemKind, PLAN_VERSION};
use agent_control_plane::core::types::{Event, EventPayload, GateKind, RunId, Task};
use agent_control_plane::core::{CoreError, GateResolution};

use common::{
    cli_actor, embedded_roles, loop_task, quiesce, start_actor, wait_for_log, ActorOpts, LoopWorld,
};

fn work(id: &str, task: Task, after: &[&str]) -> PlanItem {
    PlanItem {
        id: id.to_string(),
        kind: PlanItemKind::Work,
        task: Some(task),
        summary: None,
        after: after.iter().map(|s| (*s).to_string()).collect(),
        verify: None,
        review: None,
    }
}

fn human(id: &str, summary: &str, after: &[&str]) -> PlanItem {
    PlanItem {
        id: id.to_string(),
        kind: PlanItemKind::Human,
        task: None,
        summary: Some(summary.to_string()),
        after: after.iter().map(|s| (*s).to_string()).collect(),
        verify: None,
        review: None,
    }
}

fn plan(name: &str, items: Vec<PlanItem>) -> Plan {
    Plan {
        version: PLAN_VERSION,
        name: name.to_string(),
        items,
    }
}

/// `(itemId, status, itemRunId, gateId)` rows from the container's log, in order.
fn item_rows(events: &[Arc<Event>]) -> Vec<(String, String, Option<RunId>, Option<String>)> {
    events
        .iter()
        .filter_map(|event| match &event.payload {
            EventPayload::PlanItem {
                item_id,
                status,
                run_id,
                gate_id,
            } => Some((
                item_id.clone(),
                serde_json::to_value(status)
                    .expect("status serializes")
                    .as_str()
                    .expect("status is a string")
                    .to_string(),
                *run_id,
                gate_id.map(|g| g.to_string()),
            )),
            _ => None,
        })
        .collect()
}

/// The pending integrate gate of `run`, once it exists.
async fn integrate_gate(
    world: &LoopWorld,
    run: &RunId,
) -> agent_control_plane::core::types::GateId {
    let events = wait_for_log(world, run, "gate.created{integrate}", |events| {
        events.iter().any(|event| {
            matches!(
                &event.payload,
                EventPayload::GateCreated { gate_kind, .. } if *gate_kind == GateKind::Integrate
            )
        })
    })
    .await;
    events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::GateCreated {
                gate_id, gate_kind, ..
            } if *gate_kind == GateKind::Integrate => Some(*gate_id),
            _ => None,
        })
        .expect("an integrate gate id")
}

/// A two-item sequence: the second item starts only after the first integrates, and it builds on
/// the first item's integrated commit — `run.created.baseRef` is that sha, verbatim.
#[test]
fn a_two_item_sequence_builds_on_the_first_items_commit() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[("ACP_FAKE_SOURCE_SALT_FROM_PROMPT", "1")]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let out = handle
            .start_plan(plan(
                "two steps",
                vec![
                    work("first", loop_task("T79-seq-1"), &[]),
                    work("second", loop_task("T79-seq-2"), &["first"]),
                ],
            ), None)
            .await
            .expect("the plan starts");
        let container = out.run_id;

        // Item one starts; item two must not, while its predecessor is unfinished.
        let events = wait_for_log(&world, &container, "item one started", |events| {
            item_rows(events)
                .iter()
                .any(|(id, status, _, _)| id == "first" && status == "started")
        })
        .await;
        let rows = item_rows(&events);
        assert!(
            !rows.iter().any(|(id, _, _, _)| id == "second"),
            "the second item started before its predecessor finished: {rows:?}"
        );
        let first_run = rows
            .iter()
            .find_map(|(id, status, run, _)| (id == "first" && status == "started").then_some(*run))
            .flatten()
            .expect("item one's run id");

        // Drive item one to its gate and approve it — the only human act a work item needs.
        let gate = integrate_gate(&world, &first_run).await;
        let resolution = handle
            .resolve_gate(gate, true, None, cli_actor())
            .await
            .expect("approve item one");
        let GateResolution::Approved {
            sha: Some(first_sha),
        } = resolution
        else {
            panic!("item one's approval did not commit: {resolution:?}");
        };

        // The conductor threads the sequence: item two's run bases on item one's commit.
        let events = wait_for_log(&world, &container, "item two started", |events| {
            item_rows(events)
                .iter()
                .any(|(id, status, _, _)| id == "second" && status == "started")
        })
        .await;
        let second_run = item_rows(&events)
            .iter()
            .find_map(|(id, status, run, _)| {
                (id == "second" && status == "started").then_some(*run)
            })
            .flatten()
            .expect("item two's run id");
        // `run.created` is deferred until the worktree helper answers — wait for it.
        let second_events = wait_for_log(&world, &second_run, "item two's run.created", |events| {
            events
                .iter()
                .any(|event| matches!(&event.payload, EventPayload::RunCreated { .. }))
        })
        .await;
        let base_ref = second_events
            .iter()
            .find_map(|event| match &event.payload {
                EventPayload::RunCreated { base_ref, .. } => Some(base_ref.clone()),
                _ => None,
            })
            .expect("item two's run.created");
        assert_eq!(
            base_ref, first_sha,
            "a sequence builds on its predecessor's integrated commit"
        );

        // Land item two; the container concludes and the item lifecycle reads clean.
        let gate = integrate_gate(&world, &second_run).await;
        // Item two's first attempt must succeed on its own bytes: a strike here would mean the
        // salted write collided with its predecessor's — the false green the T75-T79 review
        // caught (a constant salt was rescued by an accidental strike-repair cycle).
        assert!(
            !world
                .events(&second_run)
                .iter()
                .any(|event| { matches!(&event.payload, EventPayload::LineageStrike { .. }) }),
            "item two struck before integrating — its diff collided with item one's bytes"
        );
        handle
            .resolve_gate(gate, true, None, cli_actor())
            .await
            .expect("approve item two");
        let events = wait_for_log(&world, &container, "the plan concluded", |events| {
            events.iter().any(|event| {
                matches!(
                    &event.payload,
                    EventPayload::RunStatus_ { status, .. }
                        if *status == agent_control_plane::core::types::RunStatus::Integrated
                )
            })
        })
        .await;
        let lifecycle: Vec<(String, String)> = item_rows(&events)
            .into_iter()
            .map(|(id, status, _, _)| (id, status))
            .collect();
        assert_eq!(
            lifecycle,
            [
                ("first".to_string(), "started".to_string()),
                ("first".to_string(), "done".to_string()),
                ("second".to_string(), "started".to_string()),
                ("second".to_string(), "done".to_string()),
            ],
            "the sequence's exact item lifecycle"
        );

        quiesce(&handle).await;
        actor.stop().await;
    });
}

/// A parallel fanout: both work items run at once, and their join is a `plan` gate a human
/// approves — which commits nothing and resolves with no sha.
#[test]
fn a_parallel_fanout_joins_into_a_human_plan_gate() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[("ACP_FAKE_SOURCE_SALT_FROM_PROMPT", "1")]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let out = handle
            .start_plan(plan(
                "fanout",
                vec![
                    work("left", loop_task("T79-par-l"), &[]),
                    work("right", loop_task("T79-par-r"), &[]),
                    human("sign", "look at both branches together", &["left", "right"]),
                ],
            ), None)
            .await
            .expect("the plan starts");
        let container = out.run_id;

        // Both items start without either integrating first — that is the fanout.
        let events = wait_for_log(&world, &container, "both items started", |events| {
            let rows = item_rows(events);
            ["left", "right"].iter().all(|id| {
                rows.iter()
                    .any(|(item, status, _, _)| item == id && status == "started")
            })
        })
        .await;
        let run_of = |name: &str| {
            item_rows(&events)
                .iter()
                .find_map(|(id, status, run, _)| {
                    (id == name && status == "started").then_some(*run)
                })
                .flatten()
                .expect("a started item has a run")
        };
        let (left, right) = (run_of("left"), run_of("right"));
        assert_ne!(left, right, "each item owns its run and worktree");

        for run in [&left, &right] {
            let gate = integrate_gate(&world, run).await;
            handle
                .resolve_gate(gate, true, None, cli_actor())
                .await
                .expect("approve a branch");
        }

        // The join: a plan-kind gate on the container, whose approval carries no sha.
        let events = wait_for_log(&world, &container, "the join's plan gate", |events| {
            item_rows(events)
                .iter()
                .any(|(id, status, _, gate)| id == "sign" && status == "started" && gate.is_some())
        })
        .await;
        let gate = events
            .iter()
            .find_map(|event| match &event.payload {
                EventPayload::GateCreated {
                    gate_id, gate_kind, ..
                } if *gate_kind == GateKind::Plan => Some(*gate_id),
                _ => None,
            })
            .expect("the plan gate exists on the container");
        let resolution = handle
            .resolve_gate(gate, true, None, cli_actor())
            .await
            .expect("approve the human item");
        assert_eq!(
            resolution,
            GateResolution::Approved { sha: None },
            "a plan gate approval commits nothing"
        );

        wait_for_log(&world, &container, "the plan concluded", |events| {
            item_rows(events)
                .iter()
                .any(|(id, status, _, _)| id == "sign" && status == "done")
        })
        .await;

        quiesce(&handle).await;
        actor.stop().await;
    });
}

/// A cyclic plan is refused at the door with `invalid_plan` and writes nothing.
#[test]
fn a_cyclic_plan_is_refused_with_its_code() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let err = handle
            .start_plan(plan(
                "cycle",
                vec![
                    work("a", loop_task("T79-cyc-a"), &["b"]),
                    work("b", loop_task("T79-cyc-b"), &["a"]),
                ],
            ), None)
            .await
            .expect_err("a cycle is refused");
        let CoreError::Policy(policy) = &err else {
            panic!("not a policy refusal: {err:?}");
        };
        assert_eq!(policy.code.as_str(), "invalid_plan");
        assert!(policy.reason.contains("cycle"), "{}", policy.reason);

        quiesce(&handle).await;
        actor.stop().await;
    });
}

/// A restart mid-plan resumes from the `plan.item` markers: nothing already `started` is
/// re-issued on replay, and the plan completes under the second actor. The restart lands in the
/// human-decision window — after item two's gate opened, before it was approved — which is the
/// widest window a real daemon restart can hit. (Restarting *inside* a worker's attempt is
/// `tests/loop_restart.rs` territory and is deliberately not re-proven here.)
#[test]
fn a_restart_mid_plan_resumes_without_duplicating_items() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[("ACP_FAKE_SOURCE_SALT_FROM_PROMPT", "1")]);
        let first_actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = first_actor.handle.clone();

        let out = handle
            .start_plan(plan(
                "restartable",
                vec![
                    work("only", loop_task("T79-restart-1"), &[]),
                    work("then", loop_task("T79-restart-2"), &["only"]),
                ],
            ), None)
            .await
            .expect("the plan starts");
        let container = out.run_id;

        // Drive item one to done and item two to its gate, all under the first actor.
        let events = wait_for_log(&world, &container, "item one started", |events| {
            item_rows(events)
                .iter()
                .any(|(id, status, _, _)| id == "only" && status == "started")
        })
        .await;
        let first_run = item_rows(&events)
            .iter()
            .find_map(|(id, status, run, _)| (id == "only" && status == "started").then_some(*run))
            .flatten()
            .expect("item one's run id");
        let gate = integrate_gate(&world, &first_run).await;
        handle
            .resolve_gate(gate, true, None, cli_actor())
            .await
            .expect("approve item one");
        let events = wait_for_log(&world, &container, "item two started", |events| {
            item_rows(events)
                .iter()
                .any(|(id, status, _, _)| id == "then" && status == "started")
        })
        .await;
        let second_run = item_rows(&events)
            .iter()
            .find_map(|(id, status, run, _)| (id == "then" && status == "started").then_some(*run))
            .flatten()
            .expect("item two's run id");
        let second_gate = integrate_gate(&world, &second_run).await;

        // The daemon dies in the human-decision window; a second replays the same log.
        first_actor.stop().await;
        let second_actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = second_actor.handle.clone();

        // Replay re-issued nothing: still exactly one `started` row per item.
        let rows = item_rows(&world.events(&container));
        for id in ["only", "then"] {
            assert_eq!(
                rows.iter()
                    .filter(|(item, status, _, _)| item == id && status == "started")
                    .count(),
                1,
                "the restart re-issued item `{id}`: {rows:?}"
            );
        }

        // The pending gate survived; approving it under the new actor completes the plan.
        handle
            .resolve_gate(second_gate, true, None, cli_actor())
            .await
            .expect("approve item two after the restart");
        wait_for_log(&world, &container, "the plan concluded", |events| {
            let rows = item_rows(events);
            rows.iter()
                .filter(|(_, status, _, _)| status == "done")
                .count()
                == 2
        })
        .await;

        quiesce(&handle).await;
        second_actor.stop().await;
    });
}
