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
    std::fs::create_dir_all(dir.path().join("repo")).unwrap();
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
        evidence: None,
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
                run_budget_usd: None,
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

struct EvidenceOwner {
    _owner: TempDir,
    root: PathBuf,
}

impl Drop for EvidenceOwner {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        for path in [&self.root, &self.root.join("files")] {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        }
    }
}

fn evidence_reference(
    repo: &Path,
    state: &Path,
) -> (
    Box<crate::workspace::evidence::EvidenceReference>,
    EvidenceOwner,
) {
    evidence_reference_named(repo, state, "updated sources", b"source snapshot")
}

fn evidence_reference_named(
    repo: &Path,
    state: &Path,
    title: &str,
    contents: &[u8],
) -> (
    Box<crate::workspace::evidence::EvidenceReference>,
    EvidenceOwner,
) {
    use sha2::{Digest, Sha256};
    let owner = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let input = owner.path().join("evidence-input");
    std::fs::create_dir_all(&input).unwrap();
    std::fs::write(input.join("source.txt"), contents).unwrap();
    let manifest = input.join("bundle.json");
    std::fs::write(
        &manifest,
        serde_json::to_vec(&json!({
            "version":1, "title":title, "sources":[{
                "file":"source.txt", "url":"https://example.test/source",
                "retrievedAt":"2026-11-10T12:30:00Z", "provenance":"installed_version",
                "sha256":format!("{:x}", Sha256::digest(contents))
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let installed = crate::workspace::evidence::import(repo, state, &manifest).unwrap();
    let evidence = installed.reference(repo, state).unwrap();
    let guard = EvidenceOwner {
        _owner: owner,
        root: evidence.root.clone(),
    };
    (Box::new(evidence), guard)
}

fn synthetic_evidence_reference(
    state: &Path,
    title: &str,
    contents: &[u8],
) -> Box<crate::workspace::evidence::EvidenceReference> {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Manifest<'a> {
        version: u32,
        title: &'a str,
        sources: &'a [crate::workspace::evidence::SourceEntry],
    }
    use crate::workspace::evidence::{EvidenceReference, Provenance, SourceEntry};
    use sha2::{Digest, Sha256};
    let sources = vec![SourceEntry {
        url: "https://example.test/source".into(),
        retrieved_at: "2026-11-10T12:30:00Z".into(),
        source_date: Some("2026-11-09".into()),
        provenance: Provenance::InstalledVersion,
        sha256: format!("{:x}", Sha256::digest(contents)),
        file: "source.txt".into(),
    }];
    let bundle_id = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&Manifest {
                version: 1,
                title,
                sources: &sources,
            })
            .unwrap()
        )
    );
    let reference = EvidenceReference {
        root: state
            .join(".acp-evidence")
            .join("c".repeat(64))
            .join(&bundle_id),
        bundle_id,
        title: title.into(),
        sources,
        network_capability: "unverified_provider_controlled".into(),
    };
    reference.validate_metadata().unwrap();
    Box::new(reference)
}

#[test]
fn claude_read_only_lead_refuses_only_the_evidence_attachment_before_launch() {
    let dir = TempDir::new().unwrap();
    let (mut core, _rx) = core(&dir);
    // Admission rejects this provider route before bundle I/O; a metadata-shaped reference keeps
    // the regression independent of host paths that this worker sandbox cannot create.
    let bundle_id = "a".repeat(64);
    let evidence = Box::new(crate::workspace::evidence::EvidenceReference {
        root: PathBuf::from("/tmp/.acp-evidence")
            .join("b".repeat(64))
            .join(&bundle_id),
        bundle_id,
        title: "host snapshot".into(),
        sources: vec![],
        network_capability: "unverified_provider_controlled".into(),
    });
    let mut attached = task();
    attached.evidence = Some(evidence);

    let error = core
        .spawn_lead(attached, "Review the supplied sources".into())
        .expect_err("Claude's non-writing profile cannot receive the evidence path");
    assert!(matches!(error, CoreError::Policy(ref policy)
        if policy.code == PolicyCode::SandboxMissing
            && policy.reason.contains("supported confined Codex worker")));
    assert!(
        core.pending_spawn.is_empty(),
        "no provider launch may be queued"
    );
    assert!(core
        .registry
        .runs()
        .any(|run| run.status == RunStatus::Blocked
            && run
                .blocked_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("remove the attachment"))));
}

#[test]
fn evidence_update_event_replays_into_the_authoritative_task() {
    let owner = TempDir::new().unwrap();
    let dir = TempDir::new_in(owner.path()).unwrap();
    let (mut core, _rx) = core(&dir);
    let captured = execution(&core, &builder_team("haiku"));
    let run = seed_run(&mut core, captured);
    let (evidence, _evidence_owner) =
        evidence_reference(&core.repo_root, core.registry.state_dir());
    core.registry
        .append(
            &run,
            EventPayload::TaskEvidenceUpdated {
                evidence: evidence.clone(),
            },
        )
        .unwrap();
    assert_eq!(
        core.registry.run(&run).unwrap().task.evidence.as_ref(),
        Some(&evidence)
    );
    drop(core);

    let replayed = Registry::open(dir.path()).unwrap();
    assert_eq!(
        replayed.run(&run).unwrap().task.evidence.as_ref(),
        Some(&evidence)
    );
}

#[tokio::test]
async fn evidence_update_admission_is_atomic_and_resume_run_identity_cannot_be_spoofed() {
    let owner = TempDir::new().unwrap();
    let dir = TempDir::new_in(owner.path()).unwrap();
    let (mut core, _rx) = core(&dir);
    let captured = execution(&core, &builder_team("haiku"));
    let run = seed_run(&mut core, captured);

    // The first delegation is now preparing its worktree inside this actor. A second task with
    // new evidence must observe that in-memory state and fail before another helper is launched.
    core.delegate(request(Some(run))).unwrap();
    let mut update = request(Some(run));
    let (evidence, _evidence_owner) =
        evidence_reference(&core.repo_root, core.registry.state_dir());
    update.task.evidence = Some(evidence);
    let err = core.delegate(update).unwrap_err();
    assert!(matches!(err, CoreError::Policy(ref error) if error.code == PolicyCode::WorktreeBusy));

    let other = RunId::new_v4();
    let agent = AgentId::new_v4();
    core.registry
        .append(
            &run,
            EventPayload::AgentCreated {
                agent_id: agent,
                role: RoleName::Builder,
                provider: ProviderName::Claude,
                model: "haiku".into(),
                lineage_id: Some(LineageId::new_v4()),
                depth: 1,
                parent_agent_id: None,
                origin: Origin::Lead,
                writes: true,
                cwd: core.repo_root.clone(),
                worktree: Some(core.repo_root.clone()),
            },
        )
        .unwrap();
    let mut spoofed = request(Some(other));
    spoofed.session = SessionSpec::Resume(agent);
    let (evidence, _spoofed_evidence_owner) =
        evidence_reference(&core.repo_root, core.registry.state_dir());
    spoofed.task.evidence = Some(evidence);
    let err = core.delegate(spoofed).unwrap_err();
    assert!(matches!(err, CoreError::Policy(ref error) if error.code == PolicyCode::InvalidTask));
}

#[tokio::test]
async fn refused_resume_keeps_the_durable_evidence_identity() {
    let owner = TempDir::new().unwrap();
    let dir = TempDir::new_in(owner.path()).unwrap();
    let (mut core, _rx) = core(&dir);
    let selected = team_value(
        "build",
        json!({
            "builder":{"provider":"claude","model":"haiku"},
            "reviewer":{"provider":"claude","model":"opus"}
        }),
    );
    let captured = execution(&core, &selected);
    let run = seed_run(&mut core, captured);
    let original = synthetic_evidence_reference(
        core.registry.state_dir(),
        "original sources",
        b"original source snapshot",
    );
    core.registry
        .append(
            &run,
            EventPayload::TaskEvidenceUpdated {
                evidence: original.clone(),
            },
        )
        .unwrap();
    let agent = AgentId::new_v4();
    let attempt = AttemptId::new_v4();
    core.registry
        .append(
            &run,
            EventPayload::AgentCreated {
                agent_id: agent,
                role: RoleName::Reviewer,
                provider: ProviderName::Claude,
                model: "opus".into(),
                lineage_id: Some(LineageId::new_v4()),
                depth: 1,
                parent_agent_id: None,
                origin: Origin::Lead,
                writes: false,
                cwd: core.repo_root.clone(),
                worktree: Some(core.repo_root.clone()),
            },
        )
        .unwrap();
    core.registry
        .append(
            &run,
            EventPayload::AgentSession {
                agent_id: agent,
                attempt_id: attempt,
                session_id: "session-1".into(),
                src_line: 1,
            },
        )
        .unwrap();
    core.registry
        .append(
            &run,
            EventPayload::AgentStatusChanged {
                agent_id: agent,
                status: AgentStatus::Idle,
                reason: None,
            },
        )
        .unwrap();

    let attempts_before = core.registry.agent(&agent).unwrap().attempt_ids.clone();
    let evidence = synthetic_evidence_reference(
        core.registry.state_dir(),
        "replacement sources",
        b"replacement source snapshot",
    );
    let mut update = request(Some(run));
    update.role = RoleName::Reviewer;
    update.session = SessionSpec::Resume(agent);
    update.task.evidence = Some(evidence);
    let error = core
        .delegate(update)
        .expect_err("this reviewer cannot consume an evidence attachment");
    assert!(
        matches!(error, CoreError::Policy(ref p) if p.code == PolicyCode::SandboxMissing),
        "{error:?}"
    );
    let replay = Registry::open(dir.path()).unwrap();
    assert_eq!(
        replay.run(&run).unwrap().task.evidence.as_ref(),
        Some(&original),
        "refused resume changed durable evidence"
    );
    assert_eq!(
        replay
            .events(&run, None, usize::MAX)
            .iter()
            .filter(|e| matches!(e.payload, EventPayload::TaskEvidenceUpdated { .. }))
            .count(),
        1,
        "refused resume appended an evidence update"
    );
    assert_eq!(
        replay.agent(&agent).unwrap().attempt_ids,
        attempts_before,
        "refused resume created an accepted attempt"
    );
    assert!(core.pending_spawn.is_empty(), "refused resume queued a worker");
    assert!(
        core.pending_worktree.is_empty(),
        "refused resume queued a worktree"
    );
    drop(replay);

    // A later supported continuation that omits evidence inherits the original identity and is
    // still usable; the refused replacement must not become a hidden default.
    let accepted = core.delegate(request(Some(run))).unwrap();
    let pending = core
        .pending_worktree
        .values()
        .find(|pending| pending.attempt == accepted.attempt_id)
        .unwrap();
    assert_eq!(pending.task.evidence.as_ref(), Some(&original));
}

#[tokio::test]
async fn idle_resume_persists_evidence_before_the_continuation_prompt() {
    let owner = TempDir::new().unwrap();
    let dir = TempDir::new_in(owner.path()).unwrap();
    let (mut core, mut rx) = core(&dir);
    let captured = execution(&core, &builder_team("haiku"));
    let run = seed_run(&mut core, captured);
    let agent = AgentId::new_v4();
    let attempt = AttemptId::new_v4();
    core.registry
        .append(
            &run,
            EventPayload::AgentCreated {
                agent_id: agent,
                role: RoleName::Builder,
                provider: ProviderName::Claude,
                model: "haiku".into(),
                lineage_id: Some(LineageId::new_v4()),
                depth: 1,
                parent_agent_id: None,
                origin: Origin::Lead,
                writes: true,
                cwd: core.repo_root.clone(),
                worktree: Some(core.repo_root.clone()),
            },
        )
        .unwrap();
    core.registry
        .append(
            &run,
            EventPayload::AgentSession {
                agent_id: agent,
                attempt_id: attempt,
                session_id: "session-1".into(),
                src_line: 1,
            },
        )
        .unwrap();
    core.registry
        .append(
            &run,
            EventPayload::AgentStatusChanged {
                agent_id: agent,
                status: AgentStatus::Idle,
                reason: None,
            },
        )
        .unwrap();

    let (evidence, _evidence_owner) =
        evidence_reference(&core.repo_root, core.registry.state_dir());
    let mut update = request(Some(run));
    update.session = SessionSpec::Resume(agent);
    update.task.title = "Follow-up title".into();
    update.task.description = "Deliver the NEW continuation instructions".into();
    update.task.files = vec!["new-continuation.rs".into()];
    update.task.acceptance = vec!["Check the NEW continuation criterion".into()];
    update.task.evidence = Some(evidence.clone());
    let out = core.delegate(update).unwrap();
    assert!(core.registry.events(&run, None, usize::MAX).iter()
        .any(|event| matches!(event.payload, EventPayload::TaskEvidenceUpdated { .. })));
    let message = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
    assert!(matches!(message, Command::EvidenceValidated { attempt, result: Ok(()), .. }
        if attempt == out.attempt_id), "resume must validate the newly recorded evidence before spawning");
    assert_eq!(
        core.registry.run(&run).unwrap().task.evidence.as_ref(),
        Some(&evidence)
    );
    let durable_prompt = handoff::build_builder_prompt(
        &core.registry.run(&run).unwrap().task,
        &schema_hint(RoleName::Builder),
    );
    assert!(durable_prompt.contains(&evidence.bundle_id));
}

#[tokio::test]
async fn fresh_existing_run_persists_and_inherits_evidence_before_worktree_preparation() {
    for supply_update in [true, false] {
        let owner = TempDir::new().unwrap();
        let dir = TempDir::new_in(owner.path()).unwrap();
        let (mut core, _rx) = core(&dir);
        let captured = execution(&core, &builder_team("haiku"));
        let run = seed_run(&mut core, captured);
        let (evidence, _evidence_owner) =
            evidence_reference(&core.repo_root, core.registry.state_dir());
        if !supply_update {
            core.registry
                .append(
                    &run,
                    EventPayload::TaskEvidenceUpdated {
                        evidence: evidence.clone(),
                    },
                )
                .unwrap();
        }
        let mut followup = request(Some(run));
        followup.task.title = "Fresh continuation title".into();
        followup.task.description = "Fresh continuation instructions".into();
        followup.task.files = vec!["fresh-continuation.rs".into()];
        followup.task.acceptance = vec!["Check the fresh continuation criterion".into()];
        if supply_update {
            followup.task.evidence = Some(evidence.clone());
        }
        let mut expected_task = followup.task.clone();
        expected_task.evidence = Some(evidence.clone());
        core.delegate(followup).unwrap();
        assert_eq!(
            core.registry.run(&run).unwrap().task.evidence.as_ref(),
            Some(&evidence)
        );
        let pending = core
            .pending_worktree
            .values()
            .find(|pending| pending.run == run)
            .unwrap();
        assert!(pending.prompt.contains("Fresh continuation instructions"));
        assert!(pending.prompt.contains(&evidence.bundle_id));
        assert_eq!(pending.task, expected_task);
        assert_eq!(
            core.registry
                .events(&run, None, usize::MAX)
                .iter()
                .filter(|event| matches!(event.payload, EventPayload::TaskEvidenceUpdated { .. }))
                .count(),
            1
        );
        drop(core);
        let replayed = Registry::open(dir.path()).unwrap();
        assert_eq!(
            replayed.run(&run).unwrap().task.evidence.as_ref(),
            Some(&evidence)
        );
    }
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

/// acp-core #8: a resume (lead or worker) reuses the recorded claude `opus`/`medium` effort even
/// after the saved team changes, and drops it when the agent no longer runs the recorded model.
#[tokio::test]
async fn resume_keeps_the_recorded_claude_effort_after_a_team_change() {
    let dir = TempDir::new().unwrap();
    let (mut core, _rx) = core(&dir);
    let selected: team::Team = serde_json::from_value(json!({
        "version": 3, "mode": "build", "name": "selection",
        "lead": {"provider":"claude","model":"opus","effort":"medium"},
        "roles": {"builder": {"provider":"claude","model":"opus","effort":"medium"}}
    }))
    .unwrap();
    let mut captured = execution(&core, &selected);
    // As the lead-start path records it (`execution.assignments["lead"]`).
    captured
        .assignments
        .insert("lead".into(), selected.lead.clone().unwrap());
    let run = seed_run(&mut core, captured);
    team::save_team(&core.state_dir, &builder_team("sonnet")).unwrap();
    for role in [RoleName::Builder, RoleName::Lead] {
        assert_eq!(
            core.recorded_effort(&run, role, ProviderName::Claude, "opus"),
            Some(Effort::Medium),
            "{role:?}"
        );
    }
    assert_eq!(
        core.recorded_effort(&run, RoleName::Builder, ProviderName::Claude, "sonnet"),
        None
    );
    assert_eq!(
        core.recorded_effort(&run, RoleName::Builder, ProviderName::Codex, "opus"),
        None
    );
    assert_eq!(
        core.recorded_effort(&run, RoleName::Reviewer, ProviderName::Claude, "opus"),
        None
    );
    // A team that omits effort records none, so the resume argv stays exactly as before.
    let captured = execution(&core, &builder_team("opus"));
    let plain = seed_run(&mut core, captured);
    assert_eq!(
        core.recorded_effort(&plain, RoleName::Builder, ProviderName::Claude, "opus"),
        None
    );
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
