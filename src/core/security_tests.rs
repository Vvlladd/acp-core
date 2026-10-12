//! Security decision failures and stale completion use only projected process records.
use super::*;
use crate::core::channel;
use crate::core::supervisor::PsProbe;
use serde_json::json;
use tempfile::TempDir;

fn seed() -> (TempDir, Core, RunId, AgentId, AttemptId, AgentId, AttemptId) {
    let dir = TempDir::new().unwrap();
    let (tx, _) = channel();
    let (signals, _) = tokio::sync::mpsc::channel(8);
    let mut core = Core::new(
        Registry::open(dir.path()).unwrap(),
        Supervisor::new(Duration::from_millis(25), Arc::new(PsProbe), signals),
        loader::load_roles(None).unwrap(),
        dir.path().join("repo"),
        dir.path().into(),
        tx,
    );
    let run = RunId::new_v4();
    let team: team::Team = serde_json::from_value(json!({"version":3,"mode":"build","name":"security",
        "roles":{"builder":{"provider":"claude","model":"haiku"},"security":{"provider":"codex","model":"gpt-5.5"}}})).unwrap();
    let execution = team::capture_execution(
        &core.roles,
        Some(&team::validate_team(&core.roles, &team).unwrap()),
    );
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
                task: Task {
                    id: "security".into(),
                    title: "Security".into(),
                    description: "Inspect".into(),
                    files: vec![],
                    acceptance: vec![],
                },
                version: 1,
                lead: None,
                team_name: None,
            },
        )
        .unwrap();
    let builder = AgentId::new_v4();
    agent(&mut core, run, builder, RoleName::Builder, None);
    let built = attempt(&mut core, run, builder);
    freeze(&mut core, run, built, "b");
    let checker = AgentId::new_v4();
    agent(&mut core, run, checker, RoleName::Security, Some(builder));
    let checked = attempt(&mut core, run, checker);
    (dir, core, run, builder, built, checker, checked)
}
fn agent(core: &mut Core, run: RunId, id: AgentId, role: RoleName, parent: Option<AgentId>) {
    core.registry
        .append(
            &run,
            EventPayload::AgentCreated {
                agent_id: id,
                role,
                provider: ProviderName::Codex,
                model: "gpt-5.5".into(),
                lineage_id: None,
                depth: 1,
                parent_agent_id: parent,
                origin: Origin::ControlPlane,
                writes: role == RoleName::Builder,
                cwd: core.repo_root.clone(),
                worktree: None,
            },
        )
        .unwrap();
}
fn attempt(core: &mut Core, run: RunId, agent: AgentId) -> AttemptId {
    let id = AttemptId::new_v4();
    core.registry
        .append(
            &run,
            EventPayload::AttemptStarted {
                attempt_id: id,
                agent_id: agent,
                attempt_kind: AttemptKind::Fresh,
                dir: core.state_dir.join(id.to_string()),
                argv: vec![],
                cwd: core.repo_root.clone(),
                pid: 42,
                pgid: 42,
                start_time: "fixture only".into(),
                pre_sha: "a".repeat(40),
                timeout_sec: 60,
                spawn_budget_usd: 1.0,
            },
        )
        .unwrap();
    core.registry
        .append(
            &run,
            EventPayload::AttemptFinished {
                attempt_id: id,
                status: AttemptStatus::Succeeded,
                exit_code: Some(0),
                signal: None,
                post_sha: None,
                duration_ms: 1,
                error: None,
            },
        )
        .unwrap();
    id
}
fn freeze(core: &mut Core, run: RunId, id: AttemptId, hash: &str) {
    core.registry.append(&run, serde_json::from_value(json!({"kind":"diff.frozen","attemptId":id,
        "diffPath":core.state_dir.join(format!("{id}.patch")),"diffHash":hash.repeat(64),"files":["src.rs"],
        "added":1,"deleted":0})).unwrap()).unwrap();
}
fn finished(core: &Core, run: RunId, agent: AgentId, id: AttemptId) -> Finished {
    Finished {
        attempt: id,
        run,
        agent,
        status: AttemptStatus::Succeeded,
        error: None,
        structured: Some(json!({"verdict":"PASS","diffHash":"b".repeat(64),"findings":[]})),
        finish_seq: core.finish_seq(&run, &id).unwrap(),
        parent: core.registry.agent(&agent).unwrap().parent_agent_id,
    }
}

#[tokio::test]
async fn superseded_security_completion_keeps_original_input_and_cannot_advance_newer_checks() {
    let (_dir, mut core, run, builder, built, checker, checked) = seed();
    let newer = attempt(&mut core, run, builder);
    freeze(&mut core, run, newer, "c");
    let input = inspection_diff(&core.registry, &run, checker).unwrap();
    assert_eq!(input.attempt, built);
    assert_eq!(input.hash, "b".repeat(64));
    let before = core.registry.events(&run, None, usize::MAX).len();
    core.branch_reviewer(&finished(&core, run, checker, checked))
        .await;
    let events = core.registry.events(&run, None, usize::MAX);
    assert!(events[before..]
        .iter()
        .all(|e| matches!(e.payload, EventPayload::LoopDispatched { .. })));
    assert!(!current_builder_diff(&core.registry, &run, built));
}

#[tokio::test]
async fn failed_security_verdict_append_leaves_no_gate_or_dispatch_marker_and_retries_after_reopen()
{
    let (dir, mut core, run, _, built, checker, checked) = seed();
    let f = finished(&core, run, checker, checked);
    let frozen = inspection_diff(&core.registry, &run, checker).unwrap();
    let verdict: ReviewVerdict = serde_json::from_value(f.structured.clone().unwrap()).unwrap();
    core.registry = Registry::open(dir.path()).unwrap();
    let path = dir
        .path()
        .join("runs")
        .join(run.to_string())
        .join("events.jsonl");
    let saved = path.with_extension("saved");
    std::fs::rename(&path, &saved).unwrap();
    std::fs::create_dir(&path).unwrap();
    let before = core.registry.events(&run, None, usize::MAX).len();
    core.branch_reviewer(&f).await;
    assert_eq!(core.registry.events(&run, None, usize::MAX).len(), before);
    assert!(passed_attempt(&core.registry, &run, built, &frozen.hash).is_none());
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&saved, &path).unwrap();
    core.registry = Registry::open(dir.path()).unwrap();
    assert!(core.persist_security_verdict(&f, &frozen, &verdict));
    core.registry = Registry::open(dir.path()).unwrap();
    assert_eq!(
        passed_attempt(&core.registry, &run, built, &frozen.hash),
        Some(checked)
    );
    assert!(core.persist_security_verdict(&f, &frozen, &verdict));
    assert_eq!(
        core.registry.events(&run, None, usize::MAX).len(),
        before + 1
    );
}
