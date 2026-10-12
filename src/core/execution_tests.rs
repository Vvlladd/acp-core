//! Behavioral regression cases for run configuration, including the pre-worktree and replay windows.
use super::*;
use crate::core::plan::{PlanItem, PlanItemKind};
use crate::core::supervisor::PsProbe;
use crate::core::types::{Actor, AttemptKind};
use crate::core::{channel, Command};
use serde_json::json;
use tempfile::TempDir;
use tokio::sync::mpsc;

fn core(dir: &TempDir) -> (Core, mpsc::Receiver<Command>) {
    let (tx, rx) = channel();
    let (signals, _) = mpsc::channel(8);
    (
        Core::new(
            Registry::open(dir.path()).unwrap(),
            Supervisor::new(Duration::from_millis(25), Arc::new(PsProbe), signals),
            loader::load_roles(None).unwrap(),
            dir.path().join("repo"),
            dir.path().into(),
            tx,
        ),
        rx,
    )
}
fn task() -> Task {
    Task {
        id: "config-test".into(),
        title: "Record the selected team".into(),
        description: "Implement this task with the selected providers.".into(),
        files: vec![],
        acceptance: vec!["The selected provider runs".into()],
    }
}
fn request(run_id: Option<RunId>) -> DelegateRequest {
    DelegateRequest {
        run_id,
        role: RoleName::Builder,
        task: task(),
        model: None,
        session: SessionSpec::Fresh,
        base_ref: None,
        worktree: None,
        steps: None,
        caller_run_id: None,
    }
}
fn team_value(mode: &str, roles: Value) -> team::Team {
    serde_json::from_value(json!({"version":3,"mode":mode,"name":"selection","roles":roles}))
        .unwrap()
}
fn builder_team(model: &str) -> team::Team {
    team_value(
        "build",
        json!({"builder":{"provider":"claude","model":model}}),
    )
}
fn execution(core: &Core, team: &team::Team) -> RunExecution {
    team::capture_execution(
        &core.roles,
        Some(&team::validate_team(&core.roles, team).unwrap()),
    )
}
fn seed_run(core: &mut Core, execution: RunExecution) -> RunId {
    let run = RunId::new_v4();
    core.registry
        .append(
            &run,
            EventPayload::RunCreated {
                steps: Some(execution.steps),
                execution: Some(execution),
                repo_root: core.repo_root.clone(),
                state_dir: core.state_dir.clone(),
                base_ref: "HEAD".into(),
                base_sha: "a".repeat(40),
                task: task(),
                version: 1,
                lead: None,
                team_name: None,
            },
        )
        .unwrap();
    run
}

#[tokio::test]
async fn no_builder_caller_cannot_resume_or_repair_another_run_even_after_its_lead_exits() {
    let dir = TempDir::new().unwrap();
    let (mut core, _rx) = core(&dir);
    let build_execution = execution(&core, &builder_team("haiku"));
    let build = seed_run(&mut core, build_execution);
    let worker = AgentId::new_v4();
    core.registry
        .append(
            &build,
            EventPayload::AgentCreated {
                agent_id: worker,
                role: RoleName::Builder,
                provider: ProviderName::Claude,
                model: "haiku".into(),
                lineage_id: None,
                depth: 0,
                parent_agent_id: None,
                origin: Origin::Lead,
                writes: true,
                cwd: core.repo_root.clone(),
                worktree: None,
            },
        )
        .unwrap();
    let gate = gates::create_gate(
        &mut core.registry,
        &build,
        NewGate {
            kind: GateKind::Plan,
            summary: "human decision".into(),
            requested_by: Origin::Lead,
            payload: GatePayload::default(),
        },
    )
    .unwrap()
    .gate_id;
    for selected in [
        team_value("plan", json!({})),
        team_value(
            "audit",
            json!({"reviewer":{"provider":"codex","model":"gpt-5.5"}}),
        ),
    ] {
        let captured = execution(&core, &selected);
        let caller = seed_run(&mut core, captured);
        // No live lead exists: a delayed request retains its no-builder restriction.
        let (reply, response) = tokio::sync::oneshot::channel();
        core.handle_command(Command::CallerScoped {
            caller_run_id: caller,
            command: Box::new(Command::SendMessage {
                agent: worker,
                message: "repair".into(),
                reply,
            }),
        })
        .await;
        assert!(matches!(response.await.unwrap(), Err(CoreError::Policy(_))));
        let (reply, response) = tokio::sync::oneshot::channel();
        core.handle_command(Command::CallerScoped {
            caller_run_id: caller,
            command: Box::new(Command::ResolveGate {
                gate,
                approve: false,
                feedback: Some("repair".into()),
                by: Actor::Socket {
                    client_name: "mcp-proxy".into(),
                },
                reply,
            }),
        })
        .await;
        assert!(matches!(response.await.unwrap(), Err(CoreError::Policy(_))));
        let mut req = request(None);
        req.caller_run_id = Some(caller);
        assert!(core.delegate(req).is_err());
        assert!(core.start_plan(waiting_plan(), Some(caller)).is_err());
    }
    assert_eq!(
        core.registry.gate(&gate).unwrap().status,
        GateStatus::Pending
    );
    assert!(core.pending_worktree.is_empty());
    assert!(core.pending_spawn.is_empty());
    // Build and human requests reach normal policy; no fixture process needs to run.
    for caller in [Some(build), None] {
        let (reply, _response) = tokio::sync::oneshot::channel();
        let cmd = Command::SendMessage {
            agent: worker,
            message: "repair".into(),
            reply,
        };
        let cmd = match caller {
            Some(caller_run_id) => Command::CallerScoped {
                caller_run_id,
                command: Box::new(cmd),
            },
            None => cmd,
        };
        assert!(matches!(
            core.admit_caller_scope(cmd),
            Some(Command::SendMessage { .. })
        ));
    }
    let (reply, response) = tokio::sync::oneshot::channel();
    core.handle_command(Command::ResolveGate {
        gate,
        approve: false,
        feedback: None,
        by: Actor::Socket {
            client_name: "human".into(),
        },
        reply,
    })
    .await;
    response.await.unwrap().unwrap();
    assert_eq!(
        core.registry.gate(&gate).unwrap().status,
        GateStatus::Denied
    );
}

#[test]
fn mode_is_explicit_and_old_membership_is_not_reinterpreted() {
    let cfg = loader::load_roles(None).unwrap();
    for (value, accepted) in [
        (json!({"version":1,"name":"legacy","roles":{}}), true),
        (json!({"version":2,"name":"legacy","roles":{}}), false),
        (
            json!({"version":2,"mode":"plan","name":"legacy","roles":{}}),
            false,
        ),
        (
            json!({"version":3,"name":"missing intent","roles":{}}),
            false,
        ),
        (
            json!({"version":3,"mode":"plan","name":"planning","roles":{}}),
            true,
        ),
        (
            json!({"version":3,"mode":"audit","name":"empty audit","roles":{}}),
            false,
        ),
        (
            json!({"version":3,"mode":"audit","name":"audit","roles":{"reviewer":{"provider":"codex","model":"gpt-5.5"}}}),
            true,
        ),
    ] {
        let team: team::Team = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            team::validate_team(&cfg, &team).is_ok(),
            accepted,
            "{value}"
        );
    }
}

#[tokio::test]
async fn pending_helpers_share_the_first_run_configuration() {
    let dir = TempDir::new().unwrap();
    let (mut core, _rx) = core(&dir);
    team::save_team(dir.path(), &builder_team("haiku")).unwrap();
    let run = RunId::new_v4();
    let first = core.delegate(request(Some(run))).unwrap();
    team::save_team(dir.path(), &builder_team("sonnet")).unwrap();
    let second = core.delegate(request(Some(run))).unwrap();
    assert_ne!(first.agent_id, second.agent_id);
    assert_eq!(core.pending_worktree.len(), 2);
    for pending in core.pending_worktree.values() {
        assert_eq!(pending.model, "haiku");
        assert_eq!(
            pending.execution.as_ref().unwrap().assignments["builder"].model,
            "haiku"
        );
    }
    let mut override_request = request(Some(run));
    override_request.model = Some("sonnet".into());
    assert!(
        core.delegate(override_request).is_err(),
        "a second creation cannot overwrite the choice"
    );
}

#[tokio::test]
async fn replay_keeps_assignment_and_effort_when_saved_team_is_unreadable() {
    let dir = TempDir::new().unwrap();
    let (mut original, _rx) = core(&dir);
    let selected = team_value(
        "build",
        json!({"builder":{"provider":"codex","model":"gpt-5.5","effort":"high"}}),
    );
    let captured = execution(&original, &selected);
    let run = seed_run(&mut original, captured.clone());
    drop(original);
    std::fs::write(team::team_path(dir.path()), b"corrupt current team").unwrap();
    let (mut recovered, _rx) = core(&dir);
    assert_eq!(
        recovered.registry.run(&run).unwrap().execution,
        Some(captured)
    );
    recovered.delegate(request(Some(run))).unwrap();
    let pending = recovered.pending_worktree.values().next().unwrap();
    assert_eq!(pending.provider, ProviderName::Codex);
    assert_eq!(pending.model, "gpt-5.5");
    assert_eq!(pending.effort, Some(Effort::High));
}

#[tokio::test]
async fn delayed_build_caller_keeps_its_team_after_the_lead_exits() {
    let dir = TempDir::new().unwrap();
    let (mut core, _rx) = core(&dir);
    let captured = execution(&core, &builder_team("haiku"));
    let caller = seed_run(&mut core, captured.clone());
    // No live lead, and the user's newer default explicitly has no builder.
    team::save_team(dir.path(), &team_value("plan", json!({}))).unwrap();
    let mut req = request(None);
    req.caller_run_id = Some(caller);
    core.delegate(req).unwrap();
    assert_eq!(
        core.pending_worktree
            .values()
            .next()
            .unwrap()
            .execution
            .as_ref(),
        Some(&captured)
    );
    let plan = core.start_plan(waiting_plan(), Some(caller)).unwrap();
    assert_eq!(
        core.registry.run(&plan).unwrap().execution.as_ref(),
        Some(&captured)
    );
    // Liveness still controls run.delegated; delayed calls cannot manufacture attribution.
    assert!(!core
        .registry
        .events(&caller, None, usize::MAX)
        .iter()
        .any(|e| matches!(e.payload, EventPayload::RunDelegated { .. })));
}

#[tokio::test]
async fn planning_lead_cannot_gain_workers_or_integration_after_team_edit() {
    let dir = TempDir::new().unwrap();
    let (mut core, _rx) = core(&dir);
    let captured = execution(&core, &team_value("plan", json!({})));
    let run = seed_run(&mut core, captured);
    let agent = AgentId::new_v4();
    core.registry
        .append(
            &run,
            EventPayload::AgentCreated {
                agent_id: agent,
                role: RoleName::Lead,
                provider: ProviderName::Claude,
                model: "haiku".into(),
                lineage_id: None,
                depth: 0,
                parent_agent_id: None,
                origin: Origin::Lead,
                writes: false,
                cwd: core.repo_root.clone(),
                worktree: None,
            },
        )
        .unwrap();
    // Projected identity only. No process is created, adopted, probed or signalled in this test.
    core.registry
        .append(
            &run,
            EventPayload::AttemptStarted {
                attempt_id: AttemptId::new_v4(),
                agent_id: agent,
                attempt_kind: AttemptKind::Fresh,
                dir: dir.path().join("attempt"),
                argv: vec![],
                cwd: core.repo_root.clone(),
                pid: 42,
                pgid: 42,
                start_time: "fixture".into(),
                pre_sha: String::new(),
                timeout_sec: 60,
                spawn_budget_usd: 2.0,
            },
        )
        .unwrap();
    team::save_team(dir.path(), &builder_team("sonnet")).unwrap();
    let mut child = request(None);
    child.caller_run_id = Some(run);
    assert!(core.delegate(child).is_err());
    assert!(core.delegate(request(Some(run))).is_err());
    assert!(core.start_plan(waiting_plan(), Some(run)).is_err());
    assert!(gates::create_gate(
        &mut core.registry,
        &run,
        NewGate {
            kind: GateKind::Integrate,
            summary: "cannot integrate".into(),
            requested_by: Origin::Lead,
            payload: GatePayload::default(),
        }
    )
    .is_err());
    assert!(core.pending_worktree.is_empty());
    assert!(core.registry.state().gates.is_empty());
    assert_eq!(core.registry.state().runs.len(), 1);
}

fn waiting_plan() -> Plan {
    Plan {
        version: 1,
        name: "Paused plan".into(),
        items: vec![
            PlanItem {
                id: "ready".into(),
                kind: PlanItemKind::Human,
                task: None,
                summary: Some("Begin the work".into()),
                after: vec![],
                verify: None,
                review: None,
            },
            PlanItem {
                id: "work".into(),
                kind: PlanItemKind::Work,
                task: Some(task()),
                summary: None,
                after: vec!["ready".into()],
                verify: Some(true),
                review: Some(true),
            },
        ],
    }
}

#[tokio::test]
async fn paused_plan_replays_its_team_and_honors_check_overrides() {
    let dir = TempDir::new().unwrap();
    let (mut original, _rx) = core(&dir);
    team::save_team(dir.path(), &builder_team("haiku")).unwrap();
    let run = original.start_plan(waiting_plan(), None).unwrap();
    let captured = original
        .registry
        .run(&run)
        .unwrap()
        .execution
        .clone()
        .unwrap();
    assert!(!captured.steps.verify && !captured.steps.review);
    assert!(
        captured.assignments.contains_key("verifier"),
        "record fallback choice before any later override"
    );
    drop(original);
    std::fs::write(team::team_path(dir.path()), b"unreadable newer settings").unwrap();
    let (mut recovered, _rx) = core(&dir);
    let gate = recovered.registry.run(&run).unwrap().gate_ids[0];
    let (reply, response) = tokio::sync::oneshot::channel();
    recovered
        .handle_command(Command::ResolveGate {
            gate,
            approve: true,
            feedback: None,
            by: Actor::Socket {
                client_name: "test-human".into(),
            },
            reply,
        })
        .await;
    response.await.unwrap().unwrap();
    let pending = recovered
        .pending_worktree
        .values()
        .next()
        .expect("next item was admitted");
    assert_eq!(pending.model, "haiku");
    assert_eq!(
        pending.steps,
        Some(RunSteps {
            security: false,
            verify: true,
            review: true
        })
    );
    let child = pending.execution.as_ref().unwrap();
    assert_eq!(child.assignments, captured.assignments);
    let checked = team::from_execution(&recovered.roles, child).unwrap();
    assert!(checked.step_enabled(RoleName::Verifier) && checked.step_enabled(RoleName::Reviewer));
}
