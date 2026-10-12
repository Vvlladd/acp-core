//! T89: selected security checks, with real isolated Git work and fake providers only.
mod common;
use agent_control_plane::core::{
    team::{self, Team},
    types::{EventPayload, GateKind, RoleName, RunStatus, Verdict},
};
use common::{embedded_roles, loop_task, quiesce, start_actor, wait_for_log, ActorOpts, LoopWorld};
use serde_json::json;

fn setup(verify: bool, review: bool, extra: &[(&str, &str)]) -> LoopWorld {
    let world = LoopWorld::new("pass", extra);
    let mut roles = serde_json::Map::new();
    roles.insert(
        "builder".into(),
        json!({"provider":"claude","model":"haiku"}),
    );
    roles.insert(
        "security".into(),
        json!({"provider":"codex","model":"gpt-5.5"}),
    );
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
    let team: Team =
        serde_json::from_value(json!({"version":3,"mode":"build","name":"Security","roles":roles}))
            .unwrap();
    team::save_team(world.state_dir(), &team).unwrap();
    world
}

#[test]
fn security_follows_every_selected_subset_and_its_result_is_not_mislabeled_as_code_review() {
    common::with_shared_env(|| async {
        for (verify, review) in [(false, false), (true, false), (false, true), (true, true)] {
            let world = setup(verify, review, &[]);
            let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
            let run = actor
                .handle
                .delegate(common::delegate_builder(loop_task("security")))
                .await
                .unwrap()
                .run_id;
            let events = wait_for_log(&world, &run, "security then gate", |events| {
                events.iter().any(|e| {
                    matches!(
                        e.payload,
                        EventPayload::GateCreated {
                            gate_kind: GateKind::Integrate,
                            ..
                        }
                    )
                })
            })
            .await;
            let roles: Vec<_> = events
                .iter()
                .filter_map(|e| match e.payload {
                    EventPayload::AgentCreated { role, .. } => Some(role),
                    _ => None,
                })
                .collect();
            let expected: Vec<_> = [
                (RoleName::Builder, true),
                (RoleName::Verifier, verify),
                (RoleName::Reviewer, review),
                (RoleName::Security, true),
            ]
            .into_iter()
            .filter_map(|(role, on)| on.then_some(role))
            .collect();
            assert_eq!(roles, expected);
            let security = events
                .iter()
                .position(|e| {
                    matches!(
                        e.payload,
                        EventPayload::SecurityVerdict {
                            verdict: Verdict::Pass,
                            ..
                        }
                    )
                })
                .unwrap();
            let gate = events
                .iter()
                .position(|e| matches!(e.payload, EventPayload::GateCreated { .. }))
                .unwrap();
            assert!(security < gate);
            let reg = world.reopen();
            let record = reg.run(&run).unwrap();
            let gate = reg.gate(&record.gate_ids[0]).unwrap();
            assert!(gate
                .summary
                .contains("Security review passed for this frozen diff."));
            assert_eq!(gate.summary.contains("NO reviewer ran"), !review);
            let payload: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&gate.payload_path).unwrap()).unwrap();
            if review {
                let reviewer = record
                    .agent_ids
                    .iter()
                    .find_map(|id| reg.agent(id).filter(|a| a.role == RoleName::Reviewer))
                    .unwrap();
                let expected = reg
                    .attempt(&reviewer.attempt_ids[0])
                    .unwrap()
                    .result_path
                    .as_ref()
                    .unwrap();
                assert_eq!(payload["verdictPath"], json!(expected));
            } else {
                assert!(payload["verdictPath"].is_null());
            }
            actor
                .handle
                .resolve_gate(gate.gate_id, true, None, common::cli_actor())
                .await
                .unwrap();
            assert_eq!(
                world.reopen().run(&run).unwrap().status,
                RunStatus::Integrated
            );
            let target = record
                .agent_ids
                .iter()
                .find(|id| reg.agent(id).unwrap().role == RoleName::Security)
                .unwrap();
            let mut resume = common::delegate_builder(loop_task("no-security-resume"));
            resume.run_id = Some(run);
            resume.role = RoleName::Reviewer;
            resume.session = agent_control_plane::core::policy::SessionSpec::Resume(*target);
            assert!(matches!(actor.handle.delegate(resume).await,
                Err(agent_control_plane::core::gates::CoreError::Policy(ref e))
                if e.code == agent_control_plane::core::policy::PolicyCode::DelegationNotAllowed));
            quiesce(&actor.handle).await;
            actor.stop().await;
        }
    });
}

#[test]
fn security_failure_repairs_and_reruns_every_selected_check_on_the_new_diff() {
    common::with_shared_env(|| async {
        let world = setup(
            true,
            true,
            &[("ACP_FAKE_SECURITY_SCENARIO", "fail_then_pass")],
        );
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let run = actor
            .handle
            .delegate(common::delegate_builder(loop_task("security-repair")))
            .await
            .unwrap()
            .run_id;
        let events = wait_for_log(&world, &run, "repaired security gate", |events| {
            events.iter().any(|e| {
                matches!(
                    e.payload,
                    EventPayload::GateCreated {
                        gate_kind: GateKind::Integrate,
                        ..
                    }
                )
            })
        })
        .await;
        let verdicts: Vec<_> = events
            .iter()
            .filter_map(|e| match e.payload {
                EventPayload::SecurityVerdict {
                    verdict,
                    builder_attempt_id,
                    ..
                } => Some((verdict, builder_attempt_id)),
                _ => None,
            })
            .collect();
        assert_eq!(verdicts.len(), 2);
        assert_eq!(verdicts[0].0, Verdict::Fail);
        assert_eq!(verdicts[1].0, Verdict::Pass);
        assert_ne!(verdicts[0].1, verdicts[1].1);
        for role in [RoleName::Verifier, RoleName::Reviewer, RoleName::Security] {
            assert_eq!(events.iter().filter(|e| matches!(e.payload, EventPayload::AgentCreated { role: r, .. } if r==role)).count(),2);
        }
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e.payload, EventPayload::GateCreated { .. }))
                .count(),
            1
        );
        quiesce(&actor.handle).await;
        actor.stop().await;
    });
}

#[test]
fn invalid_security_hash_retries_only_security_then_blocks_without_a_gate_or_builder_repair() {
    common::with_shared_env(|| async {
        let world = setup(
            false,
            false,
            &[("ACP_FAKE_SECURITY_HASH", common::WRONG_DIFF_HASH)],
        );
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let run = actor
            .handle
            .delegate(common::delegate_builder(loop_task("security-hash")))
            .await
            .unwrap()
            .run_id;
        let events = wait_for_log(&world, &run, "security blocks", |events| {
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
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(
                    e.payload,
                    EventPayload::AgentCreated {
                        role: RoleName::Security,
                        ..
                    }
                ))
                .count(),
            2
        );
        assert!(!events.iter().any(|e| matches!(
            e.payload,
            EventPayload::SecurityVerdict { .. }
                | EventPayload::GateCreated { .. }
                | EventPayload::LineageStrike { .. }
        )));
        quiesce(&actor.handle).await;
        actor.stop().await;
    });
}

#[test]
fn claude_security_has_only_read_tools_and_returns_the_same_bound_verdict() {
    common::with_shared_env(|| async {
        let world = setup(true, true, &[]);
        let mut team: Team =
            serde_json::from_slice(&std::fs::read(team::team_path(world.state_dir())).unwrap())
                .unwrap();
        team.roles.insert(
            "security".into(),
            serde_json::from_value(json!({"provider":"claude","model":"haiku"})).unwrap(),
        );
        team::save_team(world.state_dir(), &team).unwrap();
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let run = actor
            .handle
            .delegate(common::delegate_builder(loop_task("claude-security")))
            .await
            .unwrap()
            .run_id;
        wait_for_log(&world, &run, "Claude security pass", |events| {
            events.iter().any(|e| {
                matches!(
                    e.payload,
                    EventPayload::GateCreated {
                        gate_kind: GateKind::Integrate,
                        ..
                    }
                )
            })
        })
        .await;
        let reg = world.reopen();
        let record = reg.run(&run).unwrap();
        let security = record
            .agent_ids
            .iter()
            .find_map(|id| reg.agent(id).filter(|a| a.role == RoleName::Security))
            .unwrap();
        assert!(!security.writes);
        assert!(matches!(
            actor
                .handle
                .send_message(security.agent_id, "inspect again".into())
                .await
                .unwrap(),
            agent_control_plane::core::SendResult::Rejected { .. }
        ));
        let events = reg.events(&run, None, usize::MAX);
        let args = events
            .iter()
            .find_map(|e| match &e.payload {
                EventPayload::AttemptStarted { agent_id, argv, .. }
                    if *agent_id == security.agent_id =>
                {
                    Some(argv)
                }
                _ => None,
            })
            .unwrap();
        let start = args.iter().position(|s| s == "--allowedTools").unwrap() + 1;
        let end = args.iter().position(|s| s == "--disallowedTools").unwrap();
        assert_eq!(&args[start..end], ["Read", "Glob", "Grep"]);
        quiesce(&actor.handle).await;
        actor.stop().await;
    });
}

#[test]
fn manual_gate_cannot_skip_security_and_a_new_inspection_intent_revokes_an_old_pass() {
    common::with_shared_env(|| async {
        use agent_control_plane::core::{gates, policy::PolicyCode, registry::Registry};
        let world = setup(true, true, &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let run = actor
            .handle
            .delegate(common::delegate_builder(loop_task("security-proof")))
            .await
            .unwrap()
            .run_id;
        let events = wait_for_log(&world, &run, "security proof gate", |events| {
            events.iter().any(|e| {
                matches!(
                    e.payload,
                    EventPayload::GateCreated {
                        gate_kind: GateKind::Integrate,
                        ..
                    }
                )
            })
        })
        .await;
        quiesce(&actor.handle).await;
        actor.stop().await;
        let proof = events
            .iter()
            .find(|e| matches!(e.payload, EventPayload::SecurityVerdict { .. }))
            .unwrap();
        let gate = events
            .iter()
            .find_map(|e| match e.payload {
                EventPayload::GateCreated { gate_id, .. } => Some(gate_id),
                _ => None,
            })
            .unwrap();
        for missing in ["verify.report", "review.verdict"] {
            let partial = tempfile::tempdir().unwrap();
            let mut reg = Registry::open(partial.path()).unwrap();
            for e in &events {
                if serde_json::to_value(&e.payload).unwrap()["kind"] != missing {
                    reg.append(&run, e.payload.clone()).unwrap();
                }
            }
            assert!(
                matches!(gates::begin_resolve(&mut reg, &gate, true, None, common::cli_actor(), &embedded_roles()),
                Err(gates::CoreError::Policy(ref e)) if e.code == PolicyCode::DelegationNotAllowed),
                "selected {missing} cannot be skipped"
            );
        }
        // Reconstruct the durable prefix with a human-requested gate but no security proof.
        let state = tempfile::tempdir().unwrap();
        let mut reg = Registry::open(state.path()).unwrap();
        for event in &events {
            if !matches!(event.payload, EventPayload::SecurityVerdict { .. }) {
                reg.append(&run, event.payload.clone()).unwrap();
            }
        }
        let before = reg.events(&run, None, usize::MAX).len();
        assert!(
            matches!(gates::begin_resolve(&mut reg, &gate, true, None, common::cli_actor(), &embedded_roles()),
            Err(gates::CoreError::Policy(ref e)) if e.code == PolicyCode::DelegationNotAllowed)
        );
        assert_eq!(reg.events(&run, None, usize::MAX).len(), before);
        reg.append(&run, proof.payload.clone()).unwrap();
        // Restart must derive eligibility from recorded proof, independently of the saved team.
        drop(reg);
        let mut reg = Registry::open(state.path()).unwrap();
        let mut intent = events
            .iter()
            .find(|e| {
                matches!(
                    e.payload,
                    EventPayload::AgentCreated {
                        role: RoleName::Security,
                        ..
                    }
                )
            })
            .unwrap()
            .payload
            .clone();
        if let EventPayload::AgentCreated { agent_id, .. } = &mut intent {
            *agent_id = agent_control_plane::core::types::AgentId::new_v4();
        }
        // A PASS is eligible before the newer intent. Use a separate replay to avoid resolving it.
        let other = tempfile::tempdir().unwrap();
        let mut positive = Registry::open(other.path()).unwrap();
        for event in reg.events(&run, None, usize::MAX) {
            positive.append(&run, event.payload.clone()).unwrap();
        }
        assert!(matches!(
            gates::begin_resolve(
                &mut positive,
                &gate,
                true,
                None,
                common::cli_actor(),
                &embedded_roles()
            )
            .unwrap(),
            gates::ResolveOutcome::Commit(_)
        ));
        reg.append(&run, intent).unwrap();
        assert!(
            matches!(gates::begin_resolve(&mut reg, &gate, true, None, common::cli_actor(), &embedded_roles()),
            Err(gates::CoreError::Policy(ref e)) if e.code == PolicyCode::DelegationNotAllowed)
        );
    });
}

#[test]
fn security_membership_requires_v3_and_is_frozen_with_the_run() {
    let cfg = embedded_roles();
    assert!(!team::capture_execution(&cfg, None).steps.security);
    for version in [1, 2, 3] {
        let mut value = json!({"version":version,"name":"security","roles":{
            "builder":{"provider":"claude","model":"haiku"},
            "security":{"provider":"codex","model":"gpt-5.5"}}});
        if version == 3 {
            value["mode"] = json!("build");
        }
        let input: Team = serde_json::from_value(value).unwrap();
        let valid = team::validate_team(&cfg, &input);
        if version == 2 {
            assert!(valid.is_err());
            continue;
        }
        let valid = valid.unwrap();
        let execution = team::capture_execution(&cfg, Some(&valid));
        assert_eq!(execution.steps.security, version == 3);
        assert_eq!(
            team::from_execution(&cfg, &execution)
                .unwrap()
                .step_enabled(RoleName::Security),
            version == 3
        );
    }
    let audit: Team =
        serde_json::from_value(json!({"version":3,"mode":"audit","name":"security only",
        "roles":{"security":{"provider":"codex","model":"gpt-5.5"}}}))
        .unwrap();
    let valid = team::validate_team(&cfg, &audit).unwrap();
    let execution = team::capture_execution(&cfg, Some(&valid));
    assert!(execution.steps.security);
    assert!(!execution.steps.verify && !execution.steps.review);
}
