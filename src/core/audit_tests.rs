//! Durable boundary tests. Fixture process identities are projected only; never spawned/signalled.
use super::*;
use crate::core::supervisor::PsProbe;
use crate::core::{channel, loop_dispatch};
use tempfile::TempDir;

fn core(dir: &TempDir) -> Core {
    let (tx, _rx) = channel();
    let (signals, _rx) = tokio::sync::mpsc::channel(8);
    Core::new(
        Registry::open(dir.path()).unwrap(),
        Supervisor::new(Duration::from_millis(25), Arc::new(PsProbe), signals),
        loader::load_roles(None).unwrap(),
        dir.path().join("repo"),
        dir.path().into(),
        tx,
    )
}
fn snapshot(dir: &TempDir) -> Snapshot {
    Snapshot {
        version: 1,
        selection: Selection {
            base_ref: "main".into(),
            target: git::audit::Target::WorkingTree {},
        },
        base_sha: "a".repeat(40),
        tree_sha: "b".repeat(40),
        worktree: dir.path().join("snapshot"),
        diff_path: dir.path().join("audit.diff"),
        diff_hash: "c".repeat(64),
        files: vec!["source.txt".into()],
        manifest_path: dir.path().join("tracked-files.json"),
        manifest_hash: "d".repeat(64),
        source_hash: "e".repeat(64),
    }
}
fn seed(core: &mut Core, dir: &TempDir, prepared: bool) -> (RunId, AgentId) {
    let team: team::Team =
        serde_json::from_value(serde_json::json!({"version":3,"mode":"audit","name":"test",
        "roles":{"verifier":{"provider":"claude","model":"haiku"}}}))
        .unwrap();
    let mut execution = team::capture_execution(
        &core.roles,
        Some(&team::validate_team(&core.roles, &team).unwrap()),
    );
    execution.audit_selection = Some(snapshot(dir).selection);
    let run = RunId::new_v4();
    let agent = AgentId::new_v4();
    core.registry
        .append(
            &run,
            EventPayload::RunCreated {
                steps: Some(execution.steps),
                execution: Some(execution),
                repo_root: core.repo_root.clone(),
                state_dir: core.state_dir.clone(),
                base_ref: "main".into(),
                base_sha: String::new(),
                task: Task {
                    id: "audit".into(),
                    title: "Audit".into(),
                    description: "Inspect the existing changes".into(),
                    files: vec![],
                    acceptance: vec!["Report checks".into()],
                },
                version: RUN_VERSION,
                lead: None,
                team_name: None,
            },
        )
        .unwrap();
    if prepared {
        core.registry
            .append(
                &run,
                EventPayload::AuditPrepared {
                    snapshot: snapshot(dir),
                },
            )
            .unwrap();
        core.registry
            .append(
                &run,
                EventPayload::AgentCreated {
                    agent_id: agent,
                    role: RoleName::Verifier,
                    provider: ProviderName::Claude,
                    model: "haiku".into(),
                    lineage_id: None,
                    depth: 1,
                    parent_agent_id: None,
                    origin: Origin::ControlPlane,
                    writes: false,
                    cwd: snapshot(dir).worktree,
                    worktree: None,
                },
            )
            .unwrap();
    }
    (run, agent)
}
fn finished(core: &mut Core, dir: &TempDir, run: RunId, agent: AgentId) -> AttemptId {
    let attempt = AttemptId::new_v4();
    core.registry
        .append(
            &run,
            EventPayload::AttemptStarted {
                attempt_id: attempt,
                agent_id: agent,
                attempt_kind: AttemptKind::Fresh,
                dir: dir.path().join("attempt"),
                argv: vec![],
                cwd: snapshot(dir).worktree,
                pid: 42,
                pgid: 42,
                start_time: "fixture only".into(),
                pre_sha: String::new(),
                timeout_sec: 60,
                spawn_budget_usd: 1.0,
            },
        )
        .unwrap();
    core.registry
        .append(
            &run,
            EventPayload::AttemptFinished {
                attempt_id: attempt,
                status: AttemptStatus::Failed,
                exit_code: Some(1),
                signal: None,
                post_sha: None,
                duration_ms: 1,
                error: None,
            },
        )
        .unwrap();
    attempt
}

#[test]
fn failed_result_append_cannot_be_followed_by_a_completion_marker_and_every_prefix_recovers() {
    let dir = TempDir::new().unwrap();
    let mut actor = core(&dir);
    let (run, agent) = seed(&mut actor, &dir, true);
    let attempt = finished(&mut actor, &dir, run, agent);
    let first = actor.registry.events(&run, None, usize::MAX).len();
    // Reopen closes the cached append descriptor; replacing its path then forces one failed open.
    actor.registry = Registry::open(dir.path()).unwrap();
    let path = dir
        .path()
        .join("runs")
        .join(run.to_string())
        .join("events.jsonl");
    let saved = path.with_extension("saved");
    std::fs::rename(&path, &saved).unwrap();
    std::fs::create_dir(&path).unwrap();
    actor.pending_audit.insert(run, Pending::After { attempt });
    actor.audit_validated(run, Ok(()));
    assert!(actor
        .registry
        .run(&run)
        .unwrap()
        .audit
        .as_ref()
        .unwrap()
        .checks
        .is_empty());
    assert_eq!(loop_dispatch(&actor.registry, &attempt), None);
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&saved, &path).unwrap();
    actor.pending_audit.insert(run, Pending::After { attempt });
    actor.audit_validated(run, Ok(()));
    assert_eq!(
        loop_dispatch(&actor.registry, &attempt),
        Some(LoopBranch::Audit)
    );
    let events = actor.registry.events(&run, None, usize::MAX);
    for length in first..=events.len() {
        let replay_dir = TempDir::new().unwrap();
        let mut reg = Registry::open(replay_dir.path()).unwrap();
        for event in &events[..length] {
            reg.append(&run, event.payload.clone()).unwrap();
        }
        drop(reg);
        let mut replay = core(&replay_dir); // Outside a runtime: no helper or worker can start.
        if replay
            .registry
            .run(&run)
            .unwrap()
            .audit
            .as_ref()
            .unwrap()
            .checks
            .is_empty()
        {
            replay.pending_audit.insert(run, Pending::After { attempt });
            replay.audit_validated(run, Ok(()));
        } else {
            replay.audit_attempt_finished(attempt);
        }
        replay.drive_audits();
        assert_eq!(
            replay
                .registry
                .run(&run)
                .unwrap()
                .audit
                .as_ref()
                .unwrap()
                .checks
                .len(),
            1,
            "prefix {length}"
        );
        assert_eq!(
            loop_dispatch(&replay.registry, &attempt),
            Some(LoopBranch::Audit),
            "prefix {length}"
        );
        assert!(replay.pending_spawn.is_empty());
        assert_eq!(
            replay.registry.run(&run).unwrap().status,
            RunStatus::Failed,
            "prefix {length}"
        );
    }
}

#[test]
fn cancelled_or_closed_zero_attempt_spawn_intent_is_never_reissued() {
    for status in [AgentStatus::Cancelled, AgentStatus::Closed] {
        let dir = TempDir::new().unwrap();
        let mut original = core(&dir);
        let (run, agent) = seed(&mut original, &dir, true);
        original
            .registry
            .append(
                &run,
                EventPayload::AgentStatusChanged {
                    agent_id: agent,
                    status,
                    reason: Some("human cancelled before adoption".into()),
                },
            )
            .unwrap();
        drop(original);
        let mut restored = core(&dir);
        restored.drive_audits();
        assert_eq!(
            restored.registry.run(&run).unwrap().status,
            RunStatus::Cancelled
        );
        assert!(restored.pending_audit.is_empty());
        assert!(restored.pending_spawn.is_empty());
        assert!(restored
            .registry
            .agent(&agent)
            .unwrap()
            .attempt_ids
            .is_empty());
    }
}

#[test]
fn cancellation_during_capture_cannot_start_a_worker() {
    let dir = TempDir::new().unwrap();
    let mut actor = core(&dir);
    let (run, _) = seed(&mut actor, &dir, false);
    actor.pending_audit.insert(run, Pending::Capture);
    actor.record_run_cancellation(&run).unwrap();
    assert!(!actor.lifecycle_busy_reasons().is_empty());
    actor.audit_captured(run, Ok(snapshot(&dir)));
    assert!(actor.pending_audit.is_empty());
    assert!(actor.pending_spawn.is_empty());
    assert!(actor.registry.run(&run).unwrap().audit.is_none());
    assert_eq!(
        actor.registry.run(&run).unwrap().status,
        RunStatus::Cancelled
    );
}

#[test]
fn prepared_snapshot_is_retained_when_its_append_fails() {
    let dir = TempDir::new().unwrap();
    let mut actor = core(&dir);
    let (run, _) = seed(&mut actor, &dir, false);
    actor.registry = Registry::open(dir.path()).unwrap();
    let path = dir
        .path()
        .join("runs")
        .join(run.to_string())
        .join("events.jsonl");
    let saved = path.with_extension("saved");
    std::fs::rename(&path, &saved).unwrap();
    std::fs::create_dir(&path).unwrap();
    actor.pending_audit.insert(run, Pending::Capture);
    let prepared = snapshot(&dir);
    actor.audit_captured(run, Ok(prepared.clone()));
    assert!(matches!(
        actor.pending_audit.get(&run),
        Some(Pending::Captured(_))
    ));
    assert!(actor.registry.run(&run).unwrap().audit.is_none());
    assert_eq!(actor.registry.run(&run).unwrap().status, RunStatus::Running);
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&saved, &path).unwrap();
    // Re-drive may schedule validation, but this fixture has no real artifact or mailbox reader;
    // it cannot spawn a provider. Only persistence of the original helper result is under test.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        actor.drive_audits();
    });
    assert_eq!(
        actor
            .registry
            .run(&run)
            .unwrap()
            .audit
            .as_ref()
            .unwrap()
            .snapshot,
        prepared
    );
    assert!(actor.pending_spawn.is_empty());
}

#[test]
fn negative_validation_survives_failed_append_and_every_durable_prefix_stays_blocked() {
    for after in [false, true] {
        let dir = TempDir::new().unwrap();
        let mut actor = core(&dir);
        let (run, agent) = seed(&mut actor, &dir, true);
        let attempt = after.then(|| finished(&mut actor, &dir, run, agent));
        let first = actor.registry.events(&run, None, usize::MAX).len();
        actor.registry = Registry::open(dir.path()).unwrap();
        let path = dir
            .path()
            .join("runs")
            .join(run.to_string())
            .join("events.jsonl");
        let saved = path.with_extension("saved");
        std::fs::rename(&path, &saved).unwrap();
        std::fs::create_dir(&path).unwrap();
        actor.pending_audit.insert(
            run,
            match attempt {
                Some(attempt) => Pending::After { attempt },
                None => Pending::Before {
                    role: RoleName::Verifier,
                    agent: Some(agent),
                },
            },
        );
        actor.audit_validated(
            run,
            Err(GitError::Failed {
                op: "audit fingerprint",
                status: "changed".into(),
                message: "source was modified".into(),
            }),
        );
        assert!(matches!(
            actor.pending_audit.get(&run),
            Some(Pending::Blocked { .. })
        ));
        assert_eq!(actor.registry.run(&run).unwrap().status, RunStatus::Running);
        // A late/duplicate helper result must not overwrite the retained failure.
        actor.audit_validated(run, Ok(()));
        actor.audit_captured(run, Ok(snapshot(&dir)));
        assert!(matches!(
            actor.pending_audit.get(&run),
            Some(Pending::Blocked { .. })
        ));
        actor.drive_audits(); // Still unwritable; must not launch a revalidation helper.
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&saved, &path).unwrap();
        actor.drive_audits(); // Outside Tokio: a mistaken revalidation would panic here.
        let events = actor.registry.events(&run, None, usize::MAX);
        assert!(matches!(
            events[first].payload,
            EventPayload::RunStatus_ {
                status: RunStatus::Blocked,
                ..
            }
        ));
        for length in first + 1..=events.len() {
            let replay_dir = TempDir::new().unwrap();
            let mut reg = Registry::open(replay_dir.path()).unwrap();
            for event in &events[..length] {
                reg.append(&run, event.payload.clone()).unwrap();
            }
            drop(reg);
            let mut replay = core(&replay_dir);
            if let Some(attempt) = attempt {
                replay.audit_attempt_finished(attempt);
                replay.audit_attempt_finished(attempt); // Already recorded marker is idempotent.
                assert_eq!(
                    loop_dispatch(&replay.registry, &attempt),
                    Some(LoopBranch::Audit)
                );
                assert_eq!(
                    replay
                        .registry
                        .events(&run, None, usize::MAX)
                        .iter()
                        .filter(|e| matches!(e.payload, EventPayload::LoopDispatched { .. }))
                        .count(),
                    1
                );
            }
            replay.drive_audits();
            let record = replay.registry.run(&run).unwrap();
            assert_eq!(record.status, RunStatus::Blocked, "prefix {length}");
            assert!(record
                .blocked_reason
                .as_ref()
                .unwrap()
                .contains("source was modified"));
            assert!(record.audit.as_ref().unwrap().checks.is_empty());
            assert!(replay.pending_spawn.is_empty());
            assert!(replay.pending_audit.is_empty());
        }
    }
}
