//! Recovery drives the real actor and fake provider processes; no paid provider is invoked.
mod common;

use agent_control_plane::core::recovery::{Record, Request};
use agent_control_plane::core::team::Assignment;
use agent_control_plane::core::types::*;
use agent_control_plane::core::{Actor, CoreHandle, StatusQuery};
use common::{
    delegate_builder, embedded_roles, loop_task, quiesce, start_actor, wait_for_status, ActorOpts,
    LoopActor, LoopWorld,
};
use uuid::Uuid;

fn human() -> Actor {
    Actor::Socket {
        client_name: "recovery-test".into(),
    }
}

async fn interrupted(world: &LoopWorld) -> (LoopActor, RunId, AgentId) {
    let actor = start_actor(world, embedded_roles(), ActorOpts::default());
    let out = actor
        .handle
        .delegate(delegate_builder(loop_task("recovery")))
        .await
        .unwrap();
    wait_for_status(
        &actor.handle,
        StatusQuery::default(),
        "builder interrupted",
        |s| {
            s.runs
                .iter()
                .any(|r| r.run_id == out.run_id && r.status == RunStatus::Blocked)
        },
    )
    .await;
    (actor, out.run_id, out.agent_id)
}

async fn request(handle: &CoreHandle, run: RunId, agent: AgentId) -> Request {
    let preview = handle.recovery_preview(run).await.unwrap();
    assert!(
        preview.unavailable_reason.is_none(),
        "{:?}",
        preview.unavailable_reason
    );
    assert!(preview.candidates.iter().any(|c| c.agent_id == agent));
    Request {
        run_id: run,
        source_agent_id: agent,
        expected_seq: preview.seq,
        request_id: Uuid::new_v4(),
        builder: Assignment {
            provider: ProviderName::Codex,
            model: "gpt-5.5".into(),
            effort: None,
        },
        feedback: "Keep the preserved draft and complete the task".into(),
    }
}

#[test]
fn recovery_changes_only_builder_preserves_draft_and_reruns_checks() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("auth_fail", &[]);
        let (actor, run, source) = interrupted(&world).await;
        let before = world.reopen().run(&run).unwrap().clone();
        let worktree = world
            .reopen()
            .agent(&source)
            .unwrap()
            .worktree
            .clone()
            .unwrap();
        std::fs::write(worktree.join("preserved.txt"), "human draft\n").unwrap();
        let request = request(&actor.handle, run, source).await;
        common::configure_fakes(world.repo_root(), "pass", &[]);
        let outcome = actor
            .handle
            .recover_run(request.clone(), human())
            .await
            .unwrap();
        assert_ne!(outcome.agent_id, source);
        assert_eq!(
            actor
                .handle
                .recover_run(request.clone(), human())
                .await
                .unwrap(),
            outcome
        );
        let mut altered = request.clone();
        altered.feedback = "different instruction".into();
        assert!(actor.handle.recover_run(altered, human()).await.is_err());
        let status = wait_for_status(
            &actor.handle,
            StatusQuery::default(),
            "recovered approval",
            |s| {
                s.gates.iter().any(|g| {
                    g.run_id == run
                        && g.kind == GateKind::Integrate
                        && g.status == GateStatus::Pending
                })
            },
        )
        .await;
        assert_eq!(
            std::fs::read_to_string(worktree.join("preserved.txt")).unwrap(),
            "human draft\n"
        );
        let after = status.runs.iter().find(|r| r.run_id == run).unwrap();
        let mut expected = before.execution.unwrap();
        expected
            .assignments
            .insert("builder".into(), request.builder.clone());
        assert_eq!(after.execution.as_ref(), Some(&expected));
        let reg = world.reopen();
        let replacement = reg.agent(&outcome.agent_id).unwrap();
        assert_eq!(replacement.worktree.as_ref(), Some(&worktree));
        assert_eq!(reg.agent(&source).unwrap().status, AgentStatus::Closed);
        let events = world.events(&run);
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e.payload, EventPayload::RunRecovered { .. }))
                .count(),
            1
        );
        let recovered_seq = events
            .iter()
            .find(|e| matches!(e.payload, EventPayload::RunRecovered { .. }))
            .unwrap()
            .base
            .seq;
        assert!(events.iter().any(|e| e.base.seq > recovered_seq
            && matches!(e.payload, EventPayload::ReviewVerdict { .. })));
        if expected.steps.verify {
            assert!(events.iter().any(|e| e.base.seq > recovered_seq
                && matches!(e.payload, EventPayload::VerifyReport { .. })));
        }
        assert!(!events
            .iter()
            .any(|e| matches!(e.payload, EventPayload::IntegrateCommitted { .. })));
        assert!(actor
            .handle
            .recovery_preview(run)
            .await
            .unwrap()
            .unavailable_reason
            .unwrap()
            .contains("decision"));
        let preview = actor.handle.recovery_preview(run).await.unwrap();
        assert!(preview
            .candidates
            .first()
            .unwrap()
            .recorded_files
            .contains(&"preserved.txt".into()));
        assert_eq!(
            actor.handle.recover_run(request, human()).await.unwrap(),
            outcome,
            "duplicate after completion is read-only"
        );
        quiesce(&actor.handle).await;
        actor.stop().await;
    });
}

#[test]
fn stale_choices_and_agent_authority_never_change_the_run() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("auth_fail", &[]);
        let (actor, run, source) = interrupted(&world).await;
        let original = request(&actor.handle, run, source).await;
        let before = world.events(&run);
        let mut stale = original.clone();
        stale.expected_seq -= 1;
        assert!(actor
            .handle
            .recover_run(stale, human())
            .await
            .unwrap_err()
            .to_string()
            .contains("changed"));
        let mut invalid = original.clone();
        invalid.builder.model = "not-a-model".into();
        assert!(actor.handle.recover_run(invalid, human()).await.is_err());
        let mut wrong_source = original.clone();
        wrong_source.source_agent_id = AgentId::new_v4();
        assert!(actor
            .handle
            .recover_run(wrong_source, human())
            .await
            .is_err());
        let mut too_long = original.clone();
        too_long.feedback = "x".repeat(4001);
        assert!(actor.handle.recover_run(too_long, human()).await.is_err());
        assert!(actor
            .handle
            .recover_run(original, Actor::Mcp)
            .await
            .is_err());
        assert_eq!(before, world.events(&run));
        actor.stop().await;
    });
}

#[test]
fn accepted_intent_replays_once_from_retired_draft_and_answers_only_escalations() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("auth_fail", &[]);
        let (first, run, source) = interrupted(&world).await;
        let mut request = request(&first.handle, run, source).await;
        first.stop().await;
        let mut reg = world.reopen();
        let lineage = reg.agent(&source).unwrap().lineage_id.unwrap();
        reg.append(
            &run,
            EventPayload::LineageClosed {
                lineage_id: lineage,
                reason: "retired draft".into(),
            },
        )
        .unwrap();
        let gate = GateId::new_v4();
        reg.append(
            &run,
            EventPayload::GateCreated {
                gate_id: gate,
                gate_kind: GateKind::Escalate,
                summary: "Provider unavailable".into(),
                requested_by: Origin::Lead,
                payload_path: world.state_dir().join("unused-gate.json"),
            },
        )
        .unwrap();
        request.expected_seq = reg.run(&run).unwrap().last_seq;
        let record = Record {
            request: request.clone(),
            agent_id: AgentId::new_v4(),
            by: human(),
            gate_ids: vec![gate],
        };
        // Crash boundary: only the atomic acceptance record is durable; no helper ever ran.
        reg.append(
            &run,
            EventPayload::RunRecovered {
                recovery: record.clone(),
            },
        )
        .unwrap();
        let state = reg.state().clone();
        let event = reg
            .events(&run, None, usize::MAX)
            .last()
            .unwrap()
            .as_ref()
            .clone();
        let mut duplicate = state.clone();
        agent_control_plane::core::registry::reduce(&mut duplicate, &event);
        assert_eq!(state, duplicate);
        assert_eq!(reg.gate(&gate).unwrap().status, GateStatus::Denied);
        assert!(
            !reg.run(&run)
                .unwrap()
                .lineages
                .iter()
                .find(|l| l.lineage_id == lineage)
                .unwrap()
                .closed
        );
        drop(reg);
        common::configure_fakes(world.repo_root(), "pass", &[]);
        let second = start_actor(&world, embedded_roles(), ActorOpts::default());
        let recovered = second.handle.recover_run(request, human()).await.unwrap();
        assert_eq!(recovered.agent_id, record.agent_id);
        wait_for_status(
            &second.handle,
            StatusQuery::default(),
            "replayed recovery completes",
            |s| {
                s.gates.iter().any(|g| {
                    g.run_id == run
                        && g.kind == GateKind::Integrate
                        && g.status == GateStatus::Pending
                })
            },
        )
        .await;
        let reg = world.reopen();
        assert_eq!(reg.agent(&record.agent_id).unwrap().attempt_ids.len(), 1);
        assert_eq!(
            reg.agent(&record.agent_id).unwrap().provider,
            ProviderName::Codex
        );
        assert_eq!(reg.gate(&gate).unwrap().status, GateStatus::Denied);
        quiesce(&second.handle).await;
        second.stop().await;
    });
}

#[test]
fn concurrent_confirmations_start_only_one_replacement() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("auth_fail", &[]);
        let (actor, run, source) = interrupted(&world).await;
        let a = request(&actor.handle, run, source).await;
        let mut b = a.clone();
        b.request_id = Uuid::new_v4();
        let (first, second) = tokio::join!(
            actor.handle.recover_run(a, human()),
            actor.handle.recover_run(b, human())
        );
        assert_ne!(first.is_ok(), second.is_ok());
        quiesce(&actor.handle).await;
        actor.stop().await;
        assert_eq!(
            world
                .events(&run)
                .iter()
                .filter(|e| matches!(e.payload, EventPayload::RunRecovered { .. }))
                .count(),
            1
        );
    });
}

#[test]
fn missing_draft_blocks_without_starting_or_deleting_history() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("auth_fail", &[]);
        let (actor, run, source) = interrupted(&world).await;
        let request = request(&actor.handle, run, source).await;
        let worktree = world
            .reopen()
            .agent(&source)
            .unwrap()
            .worktree
            .clone()
            .unwrap();
        let moved = worktree.with_extension("preserved");
        std::fs::rename(&worktree, &moved).unwrap();
        let out = actor.handle.recover_run(request, human()).await.unwrap();
        wait_for_status(
            &actor.handle,
            StatusQuery::default(),
            "missing draft is refused",
            |s| {
                s.runs
                    .iter()
                    .any(|r| r.run_id == run && r.status == RunStatus::Blocked)
            },
        )
        .await;
        assert!(world
            .reopen()
            .agent(&out.agent_id)
            .unwrap()
            .attempt_ids
            .is_empty());
        assert!(moved.exists());
        assert!(world.reopen().agent(&source).is_some());
        actor.stop().await;
    });
}

#[test]
fn terminal_tasks_pending_decisions_budget_and_modes_refuse_without_mutation() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("auth_fail", &[]);
        let (actor, run, source) = interrupted(&world).await;
        let original = request(&actor.handle, run, source).await;
        actor.stop().await;
        for status in [
            RunStatus::Completed,
            RunStatus::Integrated,
            RunStatus::Cancelled,
        ] {
            world
                .reopen()
                .append(
                    &run,
                    EventPayload::RunStatus_ {
                        status,
                        reason: None,
                    },
                )
                .unwrap();
            let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
            // Replayed cancellation closes the agent on the first actor tick. Await that
            // independent mutation before asserting recovery itself leaves the log unchanged.
            if status == RunStatus::Cancelled {
                wait_for_status(&actor.handle, StatusQuery::default(), "replayed cancellation", |s| {
                    s.agents.iter().any(|a| a.agent_id == source && a.process_state == AgentStatus::Cancelled)
                }).await;
            }
            let preview = actor.handle.recovery_preview(run).await.unwrap();
            assert!(preview.unavailable_reason.is_some());
            let mut denied = original.clone();
            denied.expected_seq = preview.seq;
            let before = world.events(&run);
            assert!(actor.handle.recover_run(denied, human()).await.is_err());
            assert_eq!(before, world.events(&run));
            actor.stop().await;
        }
        world
            .reopen()
            .append(
                &run,
                EventPayload::RunStatus_ {
                    status: RunStatus::Blocked,
                    reason: Some("Provider unavailable".into()),
                },
            )
            .unwrap();
        let mut low_budget = (*embedded_roles()).clone();
        low_budget.defaults.run_budget_usd = 0.0;
        let actor = start_actor(
            &world,
            std::sync::Arc::new(low_budget),
            ActorOpts::default(),
        );
        assert!(actor
            .handle
            .recovery_preview(run)
            .await
            .unwrap()
            .unavailable_reason
            .unwrap()
            .contains("exceed"));
        actor.stop().await;
        for (kind, resolving) in [
            (GateKind::Plan, false),
            (GateKind::Integrate, false),
            (GateKind::Escalate, true),
        ] {
            let gate = GateId::new_v4();
            let mut reg = world.reopen();
            reg.append(
                &run,
                EventPayload::GateCreated {
                    gate_id: gate,
                    gate_kind: kind,
                    summary: "Decision waiting".into(),
                    requested_by: Origin::Lead,
                    payload_path: world.state_dir().join("unused.json"),
                },
            )
            .unwrap();
            if resolving {
                reg.append(
                    &run,
                    EventPayload::GateResolving {
                        gate_id: gate,
                        approve: false,
                        feedback: None,
                        by: human(),
                        commit: None,
                    },
                )
                .unwrap();
            }
            drop(reg);
            let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
            assert!(actor
                .handle
                .recovery_preview(run)
                .await
                .unwrap()
                .unavailable_reason
                .is_some());
            actor.stop().await;
            world
                .reopen()
                .append(
                    &run,
                    EventPayload::GateResolved {
                        gate_id: gate,
                        status: GateStatus::Denied,
                        sha: None,
                        feedback: None,
                    },
                )
                .unwrap();
        }
        // A new plan-mode record with a builder-shaped historical handle must still fail closed.
        let mut reg = world.reopen();
        let new_run = RunId::new_v4();
        let mut execution = reg.run(&run).unwrap().execution.clone().unwrap();
        execution.mode = RunMode::Plan;
        reg.append(
            &new_run,
            EventPayload::RunCreated {
                execution: Some(execution),
                repo_root: world.repo_root().into(),
                state_dir: world.state_dir().into(),
                base_ref: "main".into(),
                base_sha: "a".repeat(40),
                task: loop_task("plan"),
                version: 1,
                lead: None,
                team_name: None,
                steps: None,
            },
        )
        .unwrap();
        reg.append(
            &new_run,
            EventPayload::RunStatus_ {
                status: RunStatus::Blocked,
                reason: None,
            },
        )
        .unwrap();
        drop(reg);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        assert!(actor
            .handle
            .recovery_preview(new_run)
            .await
            .unwrap()
            .unavailable_reason
            .unwrap()
            .contains("build tasks"));
        actor.stop().await;
    });
}

#[test]
fn worktree_validation_rejects_redirects_and_changed_base_without_resetting() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("auth_fail", &[]);
        let (actor, run, source) = interrupted(&world).await;
        let reg = world.reopen();
        let worktree = reg.agent(&source).unwrap().worktree.clone().unwrap();
        let base = reg.run(&run).unwrap().base_sha.clone();
        actor.stop().await;
        use agent_control_plane::workspace::git;
        assert!(git::recovery_status(world.repo_root(), &worktree, &base)
            .await
            .is_ok());
        let moved = worktree.with_extension("saved");
        std::fs::rename(&worktree, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &worktree).unwrap();
        assert!(git::recovery_status(world.repo_root(), &worktree, &base)
            .await
            .is_err());
        std::fs::remove_file(&worktree).unwrap();
        std::fs::rename(&moved, &worktree).unwrap();
        let out = std::process::Command::new("git")
            .args(["commit", "--allow-empty", "-m", "changed fixture base"])
            .current_dir(&worktree)
            .output()
            .unwrap();
        assert!(out.status.success());
        let changed = git::head_sha(&worktree).await.unwrap();
        assert_ne!(changed, base);
        assert!(git::recovery_status(world.repo_root(), &worktree, &base)
            .await
            .is_err());
        assert_eq!(
            git::head_sha(&worktree).await.unwrap(),
            changed,
            "validation must never reset a human commit"
        );
    });
}
