//! T88: no-builder audits through the real actor/supervisor with fake provider CLIs.
mod common;
use agent_control_plane::core::{
    team::{self, Team},
    types::{AuditOutcome, EventPayload, RoleName, RunStatus},
};
use agent_control_plane::workspace::git::audit::{Selection, Target};
use common::{embedded_roles, loop_task, quiesce, start_actor, wait_for_log, ActorOpts, LoopWorld};
use serde_json::json;

fn setup(verify: bool, review: bool, extra: &[(&str, &str)]) -> LoopWorld {
    setup_with_security(verify, review, false, extra)
}
fn setup_with_security(
    verify: bool,
    review: bool,
    security: bool,
    extra: &[(&str, &str)],
) -> LoopWorld {
    let world = LoopWorld::new("pass", extra);
    // Wrapper configuration is test infrastructure, never part of the selected project changes.
    std::fs::write(
        world.repo_root().join(".git/info/exclude"),
        ".acp/\n.acp-fake-*\n",
    )
    .unwrap();
    let mut roles = serde_json::Map::new();
    if verify {
        roles.insert(
            "verifier".into(),
            json!({"provider":"claude","model":"haiku"}),
        );
    }
    if review {
        roles.insert(
            "reviewer".into(),
            json!({"provider":"codex","model":"gpt-5.5"}),
        );
    }
    if security {
        roles.insert(
            "security".into(),
            json!({"provider":"codex","model":"gpt-5.5"}),
        );
    }
    let team: Team =
        serde_json::from_value(json!({"version":3,"mode":"audit","name":"Audit","roles":roles}))
            .unwrap();
    team::save_team(world.state_dir(), &team).unwrap();
    world
}
fn selection() -> Selection {
    Selection {
        base_ref: "HEAD".into(),
        target: Target::WorkingTree {},
    }
}

#[test]
fn each_audit_subset_finishes_without_builder_or_human_integration_gate() {
    common::with_shared_env(|| async {
        for mask in 1..8 {
            let (verify, review, security) = (mask & 1 != 0, mask & 2 != 0, mask & 4 != 0);
            let world = setup_with_security(verify, review, security, &[]);
            std::fs::write(
                world.repo_root().join("existing.txt"),
                "selected existing work\n",
            )
            .unwrap();
            let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
            let run = actor
                .handle
                .start_audit(loop_task("T88-audit"), selection(), None)
                .await
                .unwrap()
                .run_id;
            let events = wait_for_log(&world, &run, "audit terminal", |events| {
                events.iter().any(|e| {
                    matches!(
                        e.payload,
                        EventPayload::RunStatus_ {
                            status: RunStatus::Completed | RunStatus::Blocked | RunStatus::Failed,
                            ..
                        }
                    )
                })
            })
            .await;
            let registry = world.reopen();
            let record = registry.run(&run).unwrap();
            assert_eq!(record.status, RunStatus::Completed, "{events:#?}");
            let roles: Vec<_> = events
                .iter()
                .filter_map(|e| match e.payload {
                    EventPayload::AgentCreated { role, .. } => Some(role),
                    _ => None,
                })
                .collect();
            let expected: Vec<_> = [
                (RoleName::Verifier, verify),
                (RoleName::Reviewer, review),
                (RoleName::Security, security),
            ]
            .into_iter()
            .filter(|(_, on)| *on)
            .map(|(role, _)| role)
            .collect();
            assert_eq!(roles, expected);
            assert!(record.gate_ids.is_empty());
            assert!(record.lineages.is_empty());
            let audit = record.audit.as_ref().unwrap();
            assert_eq!(audit.checks.len(), expected.len());
            assert!(audit
                .checks
                .iter()
                .all(|check| check.outcome == AuditOutcome::Pass));
            for agent in &record.agent_ids {
                let mut req = common::delegate_builder(loop_task("T88-no-resume"));
                req.run_id = Some(run);
                req.role = registry.agent(agent).unwrap().role;
                assert!(
                    actor.handle.delegate(req.clone()).await.is_err(),
                    "no generic fresh audit worker"
                );
                req.session = agent_control_plane::core::policy::SessionSpec::Resume(*agent);
                assert!(
                    actor.handle.delegate(req).await.is_err(),
                    "no generic audit worker resume"
                );
                assert!(matches!(
                    actor
                        .handle
                        .send_message(*agent, "resume this check".into())
                        .await
                        .unwrap(),
                    agent_control_plane::core::SendResult::Rejected { .. }
                ));
            }
            assert_eq!(
                std::fs::read_to_string(world.repo_root().join("existing.txt")).unwrap(),
                "selected existing work\n"
            );
            quiesce(&actor.handle).await;
            actor.stop().await;
        }
    });
}

#[test]
fn empty_audit_runs_no_checks_and_failed_verification_never_starts_a_repair() {
    common::with_shared_env(|| async {
        for changed in [false, true] {
            let world = setup(true, true, &[("ACP_FAKE_VERIFY_SCENARIO", "verify_fail")]);
            if changed {
                std::fs::write(world.repo_root().join("existing.txt"), "change\n").unwrap();
            }
            let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
            let run = actor
                .handle
                .start_audit(loop_task("T88-result"), selection(), None)
                .await
                .unwrap()
                .run_id;
            let events = wait_for_log(&world, &run, "audit terminal", |events| {
                events.iter().any(|e| {
                    matches!(
                        e.payload,
                        EventPayload::RunStatus_ {
                            status: RunStatus::Completed | RunStatus::Blocked | RunStatus::Failed,
                            ..
                        }
                    )
                })
            })
            .await;
            let registry = world.reopen();
            let record = registry.run(&run).unwrap();
            assert_eq!(
                record.status,
                if changed {
                    RunStatus::Failed
                } else {
                    RunStatus::Completed
                },
                "{events:#?}"
            );
            assert_eq!(record.agent_ids.len(), usize::from(changed));
            assert!(record.gate_ids.is_empty());
            assert!(record.lineages.is_empty());
            quiesce(&actor.handle).await;
            actor.stop().await;
        }
    });
}

#[test]
fn audit_recovery_keeps_the_snapshot_and_selection_while_the_source_and_team_change() {
    common::with_shared_env(|| async {
        let world = setup(true, true, &[]);
        let release = world.state_dir().join("release-verifier");
        common::configure_fakes(
            world.repo_root(),
            "pass",
            &[("ACP_FAKE_WAIT_FILE", release.to_str().unwrap())],
        );
        std::fs::write(world.repo_root().join("existing.txt"), "selected bytes\n").unwrap();
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let run = actor
            .handle
            .start_audit(loop_task("T88-restart"), selection(), None)
            .await
            .unwrap()
            .run_id;
        wait_for_log(&world, &run, "verifier session before restart", |events| {
            events
                .iter()
                .any(|e| matches!(e.payload, EventPayload::AgentSession { .. }))
        })
        .await;
        let snapshot = world
            .reopen()
            .run(&run)
            .unwrap()
            .audit
            .as_ref()
            .unwrap()
            .snapshot
            .clone();
        std::fs::write(world.repo_root().join("existing.txt"), "newer human edit\n").unwrap();
        std::fs::write(
            team::team_path(world.state_dir()),
            b"broken newer saved team",
        )
        .unwrap();
        actor.stop().await;
        let restarted = start_actor(
            &world,
            embedded_roles(),
            ActorOpts {
                reattach: true,
                no_tick: false,
            },
        );
        std::fs::write(&release, "continue").unwrap();
        let events = wait_for_log(&world, &run, "recovered audit terminal", |events| {
            events.iter().any(|e| {
                matches!(
                    e.payload,
                    EventPayload::RunStatus_ {
                        status: RunStatus::Completed | RunStatus::Blocked | RunStatus::Failed,
                        ..
                    }
                )
            })
        })
        .await;
        let registry = world.reopen();
        let record = registry.run(&run).unwrap();
        assert_eq!(record.status, RunStatus::Completed, "{events:#?}");
        assert_eq!(record.audit.as_ref().unwrap().snapshot, snapshot);
        assert_eq!(record.agent_ids.len(), 2);
        assert_eq!(record.audit.as_ref().unwrap().checks.len(), 2);
        assert_eq!(
            std::fs::read_to_string(world.repo_root().join("existing.txt")).unwrap(),
            "newer human edit\n"
        );
        quiesce(&restarted.handle).await;
        restarted.stop().await;
    });
}

#[test]
fn changed_source_in_the_snapshot_blocks_a_false_pass_before_review() {
    common::with_shared_env(|| async {
        let world = setup(true, true, &[]);
        let release = world.state_dir().join("release-verifier");
        common::configure_fakes(
            world.repo_root(),
            "pass",
            &[("ACP_FAKE_WAIT_FILE", release.to_str().unwrap())],
        );
        std::fs::write(world.repo_root().join("existing.txt"), "selected bytes\n").unwrap();
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let run = actor
            .handle
            .start_audit(loop_task("T88-mutation"), selection(), None)
            .await
            .unwrap()
            .run_id;
        wait_for_log(&world, &run, "verifier session before mutation", |events| {
            events
                .iter()
                .any(|e| matches!(e.payload, EventPayload::AgentSession { .. }))
        })
        .await;
        let snapshot = world
            .reopen()
            .run(&run)
            .unwrap()
            .audit
            .as_ref()
            .unwrap()
            .snapshot
            .clone();
        std::fs::write(
            snapshot.worktree.join("existing.txt"),
            "forbidden verifier edit\n",
        )
        .unwrap();
        std::fs::write(&release, "continue").unwrap();
        wait_for_log(&world, &run, "audit mutation blocked", |events| {
            events.iter().any(|e| {
                matches!(
                    e.payload,
                    EventPayload::RunStatus_ {
                        status: RunStatus::Blocked,
                        ..
                    }
                )
            })
        })
        .await;
        let registry = world.reopen();
        let record = registry.run(&run).unwrap();
        assert!(record
            .blocked_reason
            .as_deref()
            .unwrap()
            .contains("tracked source"));
        assert_eq!(record.agent_ids.len(), 1);
        assert!(record.gate_ids.is_empty());
        assert!(
            record.audit.as_ref().unwrap().checks.is_empty(),
            "a provider PASS is not a passed audit check"
        );
        quiesce(&actor.handle).await;
        actor.stop().await;
    });
}

#[test]
fn mismatched_hash_fails_once_and_nothing_to_run_is_reported_truthfully() {
    common::with_shared_env(|| async {
        for nothing in [false, true] {
            let extra = if nothing {
                vec![("ACP_FAKE_VERIFY_SCENARIO", "verify_nothing")]
            } else {
                vec![(
                    "ACP_FAKE_VERIFY_HASH",
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                )]
            };
            let world = setup(true, false, &extra);
            std::fs::write(world.repo_root().join("existing.txt"), "selected bytes\n").unwrap();
            let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
            let run = actor
                .handle
                .start_audit(loop_task("T88-hash"), selection(), None)
                .await
                .unwrap()
                .run_id;
            let events = wait_for_log(&world, &run, "audit result", |events| {
                events.iter().any(|e| {
                    matches!(
                        e.payload,
                        EventPayload::RunStatus_ {
                            status: RunStatus::Completed | RunStatus::Blocked | RunStatus::Failed,
                            ..
                        }
                    )
                })
            })
            .await;
            let registry = world.reopen();
            let record = registry.run(&run).unwrap();
            assert_eq!(
                record.status,
                if nothing {
                    RunStatus::Completed
                } else {
                    RunStatus::Failed
                },
                "{events:#?}"
            );
            assert_eq!(record.agent_ids.len(), 1);
            assert!(record.gate_ids.is_empty());
            assert_eq!(
                record.audit.as_ref().unwrap().checks[0].outcome,
                if nothing {
                    AuditOutcome::NothingToRun
                } else {
                    AuditOutcome::Fail
                }
            );
            quiesce(&actor.handle).await;
            actor.stop().await;
        }
    });
}

#[test]
fn cancel_and_stop_finishes_an_active_audit_without_a_following_check() {
    common::with_shared_env(|| async {
        let world = setup(true, true, &[]);
        let release = world.state_dir().join("never-release-verifier");
        common::configure_fakes(
            world.repo_root(),
            "pass",
            &[("ACP_FAKE_WAIT_FILE", release.to_str().unwrap())],
        );
        std::fs::write(world.repo_root().join("existing.txt"), "selected bytes\n").unwrap();
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let run = actor
            .handle
            .start_audit(loop_task("T88-cancel"), selection(), None)
            .await
            .unwrap()
            .run_id;
        wait_for_log(&world, &run, "verifier session before cancel", |events| {
            events
                .iter()
                .any(|e| matches!(e.payload, EventPayload::AgentSession { .. }))
        })
        .await;
        use agent_control_plane::core::lifecycle::{Request, StopMode};
        actor
            .handle
            .lifecycle(Request::Stop {
                mode: StopMode::CancelWork,
            })
            .await
            .unwrap();
        quiesce(&actor.handle).await;
        let registry = world.reopen();
        let record = registry.run(&run).unwrap();
        assert_eq!(record.status, RunStatus::Cancelled);
        assert_eq!(record.agent_ids.len(), 1);
        assert!(record.gate_ids.is_empty());
        assert!(record.audit.as_ref().unwrap().checks.is_empty());
        assert!(
            record.audit.as_ref().unwrap().snapshot.worktree.exists(),
            "cancel retains the snapshot"
        );
        actor.stop().await;
    });
}

#[test]
fn failed_security_only_audit_records_findings_without_build_repair_or_integration() {
    common::with_shared_env(|| async {
        let world = setup_with_security(
            false,
            false,
            true,
            &[("ACP_FAKE_SECURITY_SCENARIO", "fail_then_pass")],
        );
        std::fs::write(world.repo_root().join("existing.txt"), "selected bytes\n").unwrap();
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let run = actor
            .handle
            .start_audit(loop_task("security-audit"), selection(), None)
            .await
            .unwrap()
            .run_id;
        let events = wait_for_log(&world, &run, "security audit failed", |events| {
            events.iter().any(|e| {
                matches!(
                    e.payload,
                    EventPayload::RunStatus_ {
                        status: RunStatus::Failed,
                        ..
                    }
                )
            })
        })
        .await;
        let reg = world.reopen();
        let record = reg.run(&run).unwrap();
        assert_eq!(record.agent_ids.len(), 1);
        assert_eq!(
            reg.agent(&record.agent_ids[0]).unwrap().role,
            RoleName::Security
        );
        let check = &record.audit.as_ref().unwrap().checks[0];
        assert_eq!(check.role, RoleName::Security);
        assert_eq!(check.outcome, AuditOutcome::Fail);
        assert!(check.summary.contains("Security review"));
        assert!(record.lineages.is_empty() && record.gate_ids.is_empty());
        assert!(!events
            .iter()
            .any(|e| matches!(e.payload, EventPayload::LineageStrike { .. })));
        quiesce(&actor.handle).await;
        actor.stop().await;
    });
}

#[test]
fn human_audit_setup_is_required_recorded_and_enforced_after_team_changes() {
    common::with_shared_env(|| async {
        let world = setup(false, true, &[]);
        common::configure_fakes(world.repo_root(), "lead_messages", &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let task = loop_task("T88-human-audit");
        let saved = team::load_team(world.state_dir()).unwrap().unwrap();
        let selected = Selection { base_ref: "HEAD".into(), target: Target::Revision { revision: "HEAD".into() } };
        assert!(actor.handle.start_lead(task.clone(), task.description.clone()).await.is_err());
        assert!(world.reopen().state().runs.is_empty(), "no run before input selection");
        let mut wrong_team = saved.clone();
        wrong_team.name = "someone else's setup".into();
        let rejected = agent_control_plane::core::LeadSetup {
            audit_selection: Some(selected.clone()), expected_team: Some(wrong_team),
        };
        assert!(actor.handle.start_lead_with_setup(task.clone(), task.description.clone(), rejected).await.is_err());
        assert!(world.reopen().state().runs.is_empty(), "team conflict has no partial run");
        let setup = agent_control_plane::core::LeadSetup {
            audit_selection: Some(selected.clone()), expected_team: Some(saved),
        };
        let lead = actor.handle.start_lead_with_setup(task.clone(), task.description.clone(), setup).await.unwrap();
        wait_for_log(&world, &lead.run_id, "audit lead ended", |events| events.iter().any(|e|
            matches!(e.payload, EventPayload::AttemptFinished { .. }))).await;
        let registry = world.reopen();
        let execution = registry.run(&lead.run_id).unwrap().execution.as_ref().unwrap();
        assert_eq!(execution.authorized_audit_selection, Some(selected.clone()));
        assert!(execution.audit_selection.is_none(), "a conversation is not an audit snapshot workflow");
        assert!(registry.run(&lead.run_id).unwrap().audit.is_none());
        let plan: Team = serde_json::from_value(json!({"version":3,"mode":"plan","name":"New team","roles":{}})).unwrap();
        team::save_team(world.state_dir(), &plan).unwrap();
        assert!(actor.handle.start_audit(task.clone(), selection(), Some(lead.run_id)).await.is_err(),
            "the lead cannot replace a committed input with the working tree");
        assert!(actor.handle.start_lead_with_setup(task.clone(), task.description.clone(),
            agent_control_plane::core::LeadSetup { audit_selection: Some(selected.clone()), expected_team: Some(plan) })
            .await.is_err(), "planning cannot silently consume an audit selection");
        let run = actor.handle.start_audit(task, selected.clone(), Some(lead.run_id)).await.unwrap().run_id;
        wait_for_log(&world, &run, "empty human audit", |events| events.iter().any(|e|
            matches!(e.payload, EventPayload::RunStatus_ { status: RunStatus::Completed, .. }))).await;
        let registry = world.reopen();
        let record = registry.run(&run).unwrap();
        assert_eq!(record.execution.as_ref().unwrap().authorized_audit_selection, Some(selected));
        assert!(record.agent_ids.is_empty());
        assert!(record.gate_ids.is_empty());
        quiesce(&actor.handle).await;
        actor.stop().await;
    });
}
