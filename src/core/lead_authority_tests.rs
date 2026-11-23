use super::*;
use crate::core::gates::{self, GatePayload, GateResolution, NewGate, ResolveOutcome};
use crate::core::registry::Registry;
use crate::core::supervisor::{PsProbe, Supervisor};
use crate::core::types::{
    Actor, AgentId, AttemptKind, GateStatus, Origin, ProviderName, RunSteps, Task,
};
use crate::core::{channel, team, StatusQuery};
use crate::roles::loader;
use crate::workspace::git;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

fn core(root: &Path, state: &Path) -> Core {
    let (tx, _commands) = channel();
    let (signals, _signals_rx) = tokio::sync::mpsc::channel(8);
    Core::new(
        Registry::open(state).unwrap(),
        Supervisor::new(Duration::from_millis(25), Arc::new(PsProbe), signals),
        loader::load_roles(None).unwrap(),
        root.into(),
        state.into(),
        tx,
    )
}

fn task() -> Task {
    Task {
        evidence: None,
        id: "lead-test".into(),
        title: "Scoped lead decision".into(),
        description: "Update the source in a local task worktree".into(),
        files: vec![],
        acceptance: vec![],
    }
}

fn seed_run(core: &mut Core, owner: Option<RunId>, checks: RunSteps) -> RunId {
    let run = RunId::new_v4();
    let mut execution = team::capture_execution(&core.roles, None);
    execution.lead_owner_run_id = owner;
    execution.steps = checks;
    core.registry
        .append(
            &run,
            EventPayload::RunCreated {
                run_budget_usd: None,
                execution: Some(execution),
                repo_root: core.repo_root.clone(),
                state_dir: core.state_dir.clone(),
                base_ref: "HEAD".into(),
                base_sha: String::new(),
                task: task(),
                version: 1,
                lead: None,
                team_name: None,
                steps: Some(checks),
            },
        )
        .unwrap();
    run
}

fn no_checks() -> RunSteps {
    RunSteps {
        verify: false,
        review: false,
        security: false,
    }
}

fn create_gate(core: &mut Core, run: RunId, kind: GateKind, payload: GatePayload) -> GateId {
    gates::create_gate(
        &mut core.registry,
        &run,
        NewGate {
            kind,
            requested_by: Origin::ControlPlane,
            summary: "Decide the recorded candidate".into(),
            payload,
        },
    )
    .unwrap()
    .gate_id
}

fn decision(gate_id: GateId, terminal_claim: Option<uuid::Uuid>) -> LeadDecision {
    LeadDecision {
        gate_id,
        approve: true,
        feedback: None,
        diff_hash: None,
        builder_attempt_id: None,
        terminal_claim,
    }
}

fn host() -> (tokio::process::Child, PeerProcess, ProcessIdentity) {
    let child = tokio::process::Command::new("/bin/sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = i32::try_from(child.id().unwrap()).unwrap();
    let peer = PeerProcess::from_pid(pid).unwrap();
    let owner = peer.0[0].0;
    (child, peer, owner)
}

fn human() -> PeerProcess {
    PeerProcess::from_pid(i32::try_from(std::process::id()).unwrap()).unwrap()
}

fn allow(actor: &mut Core, run: RunId, human: &PeerProcess) -> LeadAuthorized {
    let prompt = actor
        .lead_authorization_prompt(run, Some(human))
        .unwrap()
        .unwrap();
    let proof = crate::ipc::human_confirmation::Proof::for_test(&prompt);
    actor
        .authorize_lead_run(run, Some(human), Some(proof))
        .unwrap()
}

#[tokio::test]
async fn unconfirmed_or_changed_start_leaves_no_run() {
    use crate::core::LeadSetup;
    use crate::ipc::human_confirmation::Proof;
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let mut actor = core(repo.path(), state.path());
    let setup = LeadSetup {
        lead_approved: true,
        ..LeadSetup::default()
    };
    let task = Task {
        evidence: None,
        id: "lead".into(),
        title: "Lead conversation".into(),
        description: "Prepare the build".into(),
        files: Vec::new(),
        acceptance: Vec::new(),
    };
    let prompt = actor
        .prepare_lead_confirmation(&task, "Prepare the build", &setup)
        .unwrap();
    assert!(actor
        .spawn_lead_with_setup(task.clone(), "Prepare the build".into(), setup.clone())
        .is_err());
    assert!(actor
        .spawn_lead_with_confirmation(
            task,
            "Prepare another build".into(),
            setup,
            Some(Proof::for_test(&prompt))
        )
        .is_err());
    assert_eq!(actor.registry.runs().count(), 0);
}

#[tokio::test]
async fn opted_in_gate_rechecks_mode_feedback_and_native_proof_in_the_actor() {
    use crate::core::{Command, HumanDecision};
    use crate::ipc::human_confirmation::Proof;
    use tokio::sync::oneshot;

    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let mut actor = core(repo.path(), state.path());
    let (_host, terminal, owner) = host();
    let human = human();
    let root = seed_run(&mut actor, None, no_checks());
    actor.record_terminal_lead(owner, root).unwrap();
    let item = seed_run(&mut actor, Some(root), no_checks());
    let gate = create_gate(&mut actor, item, GateKind::Escalate, GatePayload::default());
    let by = Actor::Socket {
        client_name: "test-human".into(),
    };
    let feedback = "Use the preserved draft";
    let request = || HumanDecision::Gate {
        gate,
        approve: false,
        feedback: Some(feedback.into()),
    };
    // The ordinary door can observe a human-gated run before a concurrent opt-in finishes.
    assert!(actor
        .check_human_decision(request(), Some(&human))
        .unwrap()
        .is_none());
    assert!(allow(&mut actor, root, &terminal).lead_approved);

    for without_proof in [by.clone(), Actor::Mcp] {
        let (reply, result) = oneshot::channel();
        actor
            .handle_command(Command::ResolveGate {
                gate,
                approve: false,
                feedback: Some(feedback.into()),
                by: without_proof,
                reply,
            })
            .await;
        assert!(result.await.unwrap().is_err());
        assert_eq!(
            actor.registry.gate(&gate).unwrap().status,
            GateStatus::Pending
        );
    }

    let prompt = actor
        .check_human_decision(request(), Some(&human))
        .unwrap()
        .unwrap();
    let (reply, result) = oneshot::channel();
    actor
        .handle_command(Command::ConfirmedGate {
            gate,
            approve: false,
            feedback: Some("substituted direction".into()),
            by: by.clone(),
            proof: Proof::for_test(&prompt),
            reply,
        })
        .await;
    assert!(result.await.unwrap().is_err());
    assert_eq!(
        actor.registry.gate(&gate).unwrap().status,
        GateStatus::Pending
    );

    let (reply, result) = oneshot::channel();
    actor
        .handle_command(Command::ConfirmedGate {
            gate,
            approve: false,
            feedback: Some(feedback.into()),
            by: by.clone(),
            proof: Proof::for_test(&prompt),
            reply,
        })
        .await;
    assert!(matches!(
        result.await.unwrap().unwrap(),
        GateResolution::Denied { .. }
    ));
    let recorded = actor.registry.gate(&gate).unwrap();
    assert_eq!(recorded.resolved_by, Some(by));
    assert_eq!(recorded.lead_decision, None);
}

#[tokio::test]
async fn terminal_grants_bind_human_choice_host_process_and_a_private_per_run_claim() {
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let mut actor = core(repo.path(), state.path());
    let (_host, terminal, owner) = host();
    let (_another, other_terminal, _) = host();
    let human = human();
    let target = seed_run(&mut actor, None, no_checks());
    let other = seed_run(&mut actor, None, no_checks());
    let owned_item = seed_run(&mut actor, Some(target), no_checks());
    let terminal_claim = actor.record_terminal_lead(owner, target).unwrap();
    let other_claim = actor.record_terminal_lead(owner, other).unwrap();
    let plan = create_gate(
        &mut actor,
        owned_item,
        GateKind::Plan,
        GatePayload::default(),
    );
    let escalation = create_gate(
        &mut actor,
        owned_item,
        GateKind::Escalate,
        GatePayload::default(),
    );
    let foreign_gate = create_gate(&mut actor, other, GateKind::Plan, GatePayload::default());

    assert!(actor
        .authorize_lead_run(target, Some(&terminal), None)
        .is_err());
    assert!(actor
        .authorize_human_gate_peer(plan, Some(&terminal))
        .is_err());
    assert!(actor
        .authorize_lead_decision(&decision(plan, Some(terminal_claim)), Some(&terminal))
        .is_err());
    assert!(allow(&mut actor, target, &human).lead_approved);
    assert!(actor
        .authorize_lead_run(owned_item, Some(&human), None)
        .is_err());
    assert!(actor
        .authorize_lead_decision(&decision(plan, None), Some(&terminal))
        .is_err());
    assert!(actor
        .authorize_lead_decision(&decision(plan, Some(other_claim)), Some(&terminal))
        .is_err());
    assert!(actor
        .authorize_lead_decision(&decision(plan, Some(terminal_claim)), Some(&other_terminal))
        .is_err());
    assert!(actor
        .authorize_lead_decision(&decision(escalation, Some(terminal_claim)), Some(&terminal))
        .is_err());
    assert!(actor
        .authorize_lead_decision(&decision(foreign_gate, Some(other_claim)), Some(&terminal))
        .is_err());
    assert_eq!(actor.lead_approval_root(&owned_item), Some(target));
    assert_eq!(actor.lead_approval_root(&other), None);
    let status = serde_json::to_string(&actor.status(&StatusQuery::default())).unwrap();
    assert!(!status.contains(&terminal_claim.to_string()));
    assert!(status.contains("terminalLeadRequested"));
    drop(actor);

    let mut actor = core(repo.path(), state.path());
    let request = decision(plan, Some(terminal_claim));
    actor
        .authorize_lead_decision(&request, Some(&terminal))
        .unwrap();
    assert!(matches!(
        gates::begin_lead_resolve(&mut actor.registry, request, &actor.roles).unwrap(),
        ResolveOutcome::Settled(GateResolution::Approved { sha: None })
    ));
    let plan = actor.registry.gate(&plan).unwrap();
    assert_eq!(plan.resolved_by, Some(Actor::Lead));
    assert_eq!(plan.lead_decision, Some(true));
    assert_eq!(
        actor.registry.gate(&escalation).unwrap().status,
        GateStatus::Pending
    );
}

#[tokio::test]
async fn spawned_claude_and_codex_prove_their_own_run_and_workers_cannot_grant() {
    for provider in [ProviderName::Claude, ProviderName::Codex] {
        let repo = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        let mut actor = core(repo.path(), state.path());
        let (_lead, lead_peer, lead_owner) = host();
        let (_worker, worker_peer, worker_owner) = host();
        let root = seed_run(&mut actor, None, no_checks());
        let work = seed_run(&mut actor, Some(root), no_checks());
        let ordinary = seed_run(&mut actor, None, no_checks());
        for (run, role, owner) in [
            (root, RoleName::Lead, lead_owner),
            (work, RoleName::Builder, worker_owner),
        ] {
            let agent_id = AgentId::new_v4();
            let attempt_id = AttemptId::new_v4();
            actor
                .registry
                .append(
                    &run,
                    EventPayload::AgentCreated {
                        agent_id,
                        role,
                        provider,
                        model: "fixture".into(),
                        lineage_id: None,
                        depth: 0,
                        parent_agent_id: None,
                        origin: Origin::ControlPlane,
                        writes: role == RoleName::Builder,
                        cwd: repo.path().into(),
                        worktree: None,
                    },
                )
                .unwrap();
            actor
                .registry
                .append(
                    &run,
                    EventPayload::AttemptStarted {
                        attempt_id,
                        agent_id,
                        attempt_kind: AttemptKind::Fresh,
                        dir: state.path().into(),
                        argv: vec![],
                        cwd: repo.path().into(),
                        pid: owner.pid,
                        pgid: owner.pid,
                        start_time: "fixture".into(),
                        pre_sha: String::new(),
                        timeout_sec: 60,
                        spawn_budget_usd: 0.5,
                    },
                )
                .unwrap();
            actor.register_managed_process(attempt_id, owner.pid);
        }
        assert!(actor
            .lead_authorization_prompt(root, Some(&lead_peer))
            .is_err());
        assert!(actor
            .lead_authorization_prompt(root, Some(&worker_peer))
            .is_err());
        allow(&mut actor, root, &human());
        let scoped = create_gate(&mut actor, work, GateKind::Plan, GatePayload::default());
        let unscoped = create_gate(&mut actor, ordinary, GateKind::Plan, GatePayload::default());
        actor
            .authorize_lead_decision(&decision(scoped, None), Some(&lead_peer))
            .unwrap();
        assert!(actor
            .authorize_lead_decision(&decision(scoped, None), Some(&worker_peer))
            .is_err());
        assert!(actor
            .authorize_lead_decision(&decision(unscoped, None), Some(&lead_peer))
            .is_err());
    }
}

#[test]
fn private_claim_reader_refuses_links_fifos_public_or_oversized_files() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};
    let dir = TempDir::new().unwrap();
    let private = dir.path().join("private");
    std::fs::write(&private, b"claim").unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(read_private_regular(&private, 5).unwrap(), b"claim");
    assert!(read_private_regular(&private, 4).is_err());
    let link = dir.path().join("link");
    symlink(&private, &link).unwrap();
    assert!(read_private_regular(&link, 16).is_err());
    let fifo = dir.path().join("fifo");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    assert!(read_private_regular(&fifo, 16).is_err());
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_private_regular(&private, 16).is_err());
}

fn git_command(repo: &Path, args: &[&str]) -> String {
    let answer = std::process::Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        answer.status.success(),
        "git {:?}: {}",
        args,
        String::from_utf8_lossy(&answer.stderr)
    );
    String::from_utf8(answer.stdout).unwrap().trim().to_string()
}

fn record_candidate(
    actor: &mut Core,
    run: RunId,
    worktree: &Path,
    base: &str,
    diff: &Path,
    stat: &git::DiffStat,
) -> (GateId, AttemptId) {
    let agent_id = AgentId::new_v4();
    let attempt_id = AttemptId::new_v4();
    actor
        .registry
        .append(
            &run,
            EventPayload::AgentCreated {
                agent_id,
                role: RoleName::Builder,
                provider: ProviderName::Claude,
                model: "haiku".into(),
                lineage_id: None,
                depth: 0,
                parent_agent_id: None,
                origin: Origin::Lead,
                writes: true,
                cwd: worktree.to_path_buf(),
                worktree: Some(worktree.to_path_buf()),
            },
        )
        .unwrap();
    actor
        .registry
        .append(
            &run,
            EventPayload::AttemptStarted {
                attempt_id,
                agent_id,
                attempt_kind: AttemptKind::Fresh,
                dir: actor.state_dir.clone(),
                argv: vec![],
                cwd: worktree.to_path_buf(),
                pid: 0,
                pgid: 0,
                start_time: String::new(),
                pre_sha: base.to_owned(),
                timeout_sec: 60,
                spawn_budget_usd: 0.5,
            },
        )
        .unwrap();
    actor
        .registry
        .append(
            &run,
            EventPayload::AttemptFinished {
                attempt_id,
                status: AttemptStatus::Succeeded,
                exit_code: Some(0),
                signal: None,
                post_sha: Some(base.to_owned()),
                duration_ms: 1,
                error: None,
            },
        )
        .unwrap();
    actor
        .registry
        .append(
            &run,
            EventPayload::DiffFrozen {
                source_inventory_hash: None,
                attempt_id,
                diff_path: diff.to_path_buf(),
                diff_hash: stat.diff_hash.clone(),
                files: stat.files.clone(),
                added: stat.added,
                deleted: stat.deleted,
            },
        )
        .unwrap();
    let gate = create_gate(
        actor,
        run,
        GateKind::Integrate,
        GatePayload {
            worktree: Some(worktree.to_path_buf()),
            pre_sha: Some(base.to_owned()),
            diff_path: Some(diff.to_path_buf()),
            diff_hash: Some(stat.diff_hash.clone()),
            files: stat.files.clone(),
            ..GatePayload::default()
        },
    );
    actor
        .registry
        .append(
            &run,
            EventPayload::RunStatus_ {
                status: RunStatus::AwaitingGate,
                reason: None,
            },
        )
        .unwrap();
    (gate, attempt_id)
}

#[tokio::test]
async fn stale_or_unchecked_candidates_cannot_open_the_lead_commit_window() {
    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    git_command(repo.path(), &["init", "--initial-branch=main"]);
    git_command(repo.path(), &["config", "user.name", "ACP test"]);
    git_command(
        repo.path(),
        &["config", "user.email", "acp-test@example.invalid"],
    );
    git_command(repo.path(), &["commit", "--allow-empty", "-m", "base"]);
    let base = git_command(repo.path(), &["rev-parse", "HEAD"]);
    git_command(
        repo.path(),
        &["update-ref", "refs/remotes/origin/main", &base],
    );
    let mut actor = core(repo.path(), state.path());
    let (_host, terminal, owner) = host();
    let human = human();
    let root = seed_run(&mut actor, None, no_checks());
    let run = seed_run(&mut actor, Some(root), no_checks());
    let worktree = repo.path().join("isolated-worktree");
    git_command(
        repo.path(),
        &[
            "worktree",
            "add",
            "-b",
            "acp-test",
            worktree.to_str().unwrap(),
        ],
    );
    std::fs::write(worktree.join("approved.txt"), "the approved candidate\n").unwrap();
    let diff = state.path().join("frozen.diff");
    let stat = git::frozen_diff(&worktree, &diff).await.unwrap();
    let (gate, attempt_id) = record_candidate(&mut actor, run, &worktree, &base, &diff, &stat);
    let checked_root = seed_run(
        &mut actor,
        None,
        RunSteps {
            verify: true,
            ..no_checks()
        },
    );
    let unchecked = seed_run(&mut actor, Some(checked_root), no_checks());
    let (unchecked_gate, unchecked_attempt) =
        record_candidate(&mut actor, unchecked, &worktree, &base, &diff, &stat);
    let unchecked_claim = actor.record_terminal_lead(owner, checked_root).unwrap();
    allow(&mut actor, checked_root, &human);
    let mut unchecked_decision = decision(unchecked_gate, Some(unchecked_claim));
    unchecked_decision.builder_attempt_id = Some(unchecked_attempt);
    unchecked_decision.diff_hash = Some(stat.diff_hash.clone());
    actor
        .authorize_lead_decision(&unchecked_decision, Some(&terminal))
        .unwrap();
    assert!(
        gates::begin_lead_resolve(&mut actor.registry, unchecked_decision, &actor.roles).is_err()
    );
    assert_eq!(
        actor.registry.gate(&unchecked_gate).unwrap().status,
        GateStatus::Pending
    );

    let claim = actor.record_terminal_lead(owner, root).unwrap();
    allow(&mut actor, root, &human);
    let status = actor.status(&StatusQuery {
        run_id: Some(run),
        last_events: 0,
        agent_id: None,
    });
    let projected = status.gates[0].lead_evidence.as_ref().unwrap();
    assert_eq!(projected.builder_attempt_id, attempt_id);
    assert_eq!(projected.diff_hash, stat.diff_hash);
    let mut request = decision(gate, Some(claim));
    request.builder_attempt_id = Some(attempt_id);
    request.diff_hash = Some("f".repeat(64));
    actor
        .authorize_lead_decision(&request, Some(&terminal))
        .unwrap();
    assert!(gates::begin_lead_resolve(&mut actor.registry, request.clone(), &actor.roles).is_err());
    assert_eq!(
        actor.registry.gate(&gate).unwrap().status,
        GateStatus::Pending
    );
    request.diff_hash = Some(stat.diff_hash);

    actor
        .delegate(crate::core::policy::DelegateRequest {
            run_id: Some(run),
            role: RoleName::Builder,
            task: task(),
            model: None,
            session: crate::core::policy::SessionSpec::Fresh,
            base_ref: None,
            worktree: None,
            steps: None,
            caller_run_id: None,
        })
        .unwrap();
    assert!(actor
        .authorize_lead_decision(&request, Some(&terminal))
        .is_err());
    assert_eq!(
        actor.registry.gate(&gate).unwrap().status,
        GateStatus::Pending
    );
    actor.pending_worktree.clear();

    let ResolveOutcome::Commit(plan) =
        gates::begin_lead_resolve(&mut actor.registry, request.clone(), &actor.roles).unwrap()
    else {
        panic!("an exact candidate must use the existing commit helper");
    };
    let sha = gates::run_commit(&plan, actor.supervisor.worktree_lock(&worktree))
        .await
        .unwrap();
    gates::finish_commit(&mut actor.registry, &gate, Ok(sha.clone())).unwrap();
    assert!(matches!(
        gates::begin_lead_resolve(&mut actor.registry, request.clone(), &actor.roles).unwrap(),
        ResolveOutcome::Settled(GateResolution::AlreadyResolved)
    ));
    drop(actor);
    let mut actor = core(repo.path(), state.path());
    actor
        .authorize_lead_decision(&request, Some(&terminal))
        .unwrap();
    assert!(matches!(
        gates::begin_lead_resolve(&mut actor.registry, request, &actor.roles).unwrap(),
        ResolveOutcome::Settled(GateResolution::AlreadyResolved)
    ));
    assert_eq!(
        git_command(&worktree, &["rev-list", "--count", "HEAD", "^main"]),
        "1"
    );
    assert_eq!(
        git_command(&worktree, &["show", "HEAD:approved.txt"]),
        "the approved candidate"
    );
    assert_eq!(git_command(repo.path(), &["rev-parse", "main"]), base);
    assert_eq!(
        git_command(repo.path(), &["rev-parse", "refs/remotes/origin/main"]),
        base
    );
    assert_eq!(
        actor.registry.gate(&gate).unwrap().sha.as_deref(),
        Some(sha.as_str())
    );
}

#[tokio::test]
async fn only_exact_human_accepted_host_evidence_satisfies_a_blocked_verifier() {
    use crate::core::types::{
        ExternalCommandResult, ExternalCommandStatus, ExternalVerificationEvidence, VerifyReport,
        VerifyStatus,
    };

    let repo = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let mut actor = core(repo.path(), state.path());
    let run = seed_run(
        &mut actor,
        None,
        RunSteps {
            verify: true,
            ..no_checks()
        },
    );
    let hash = "a".repeat(64);
    let diff = state.path().join("frozen.diff");
    let stat = git::DiffStat {
        diff_hash: hash.clone(),
        ..git::DiffStat::default()
    };
    let (_, builder) =
        record_candidate(&mut actor, run, repo.path(), &"a".repeat(40), &diff, &stat);
    let builder_agent = actor.registry.attempt(&builder).unwrap().agent_id;
    let verification_passed = |actor: &Core| {
        crate::core::r#loop::security::verification_passed(&actor.registry, &run, builder, &hash)
    };
    let verify = |actor: &mut Core, status, commands: Vec<String>, blockers: Vec<String>| {
        let agent_id = AgentId::new_v4();
        let attempt_id = AttemptId::new_v4();
        for event in [
            EventPayload::AgentCreated {
                agent_id,
                role: RoleName::Verifier,
                provider: ProviderName::Claude,
                model: "haiku".into(),
                lineage_id: None,
                depth: 1,
                parent_agent_id: Some(builder_agent),
                origin: Origin::ControlPlane,
                writes: false,
                cwd: repo.path().into(),
                worktree: None,
            },
            EventPayload::AttemptStarted {
                attempt_id,
                agent_id,
                attempt_kind: AttemptKind::Fresh,
                dir: state.path().into(),
                argv: vec![],
                cwd: repo.path().into(),
                pid: 0,
                pgid: 0,
                start_time: String::new(),
                pre_sha: String::new(),
                timeout_sec: 60,
                spawn_budget_usd: 0.5,
            },
            EventPayload::AttemptResult {
                attempt_id,
                src_line: 1,
                result_path: state.path().join("verify.json"),
                schema: "verify-report".into(),
                structured_valid: true,
                structured: Some(
                    serde_json::to_value(VerifyReport {
                        status,
                        summary: "fixture verification".into(),
                        commands: commands.clone(),
                        blockers: blockers.clone(),
                        failures: vec![],
                        diff_hash: hash.clone(),
                    })
                    .unwrap(),
                ),
            },
            EventPayload::AttemptFinished {
                attempt_id,
                status: AttemptStatus::Succeeded,
                exit_code: Some(0),
                signal: None,
                post_sha: None,
                duration_ms: 1,
                error: None,
            },
            EventPayload::VerifyReport {
                attempt_id,
                builder_attempt_id: builder,
                status,
                summary: "fixture verification".into(),
                commands,
                blockers,
                failures: vec![],
            },
        ] {
            actor.registry.append(&run, event).unwrap();
        }
    };
    verify(
        &mut actor,
        VerifyStatus::Blocked,
        vec!["cargo test".into()],
        vec!["runner unavailable".into()],
    );
    assert!(!verification_passed(&actor));

    let record_external = |actor: &mut Core, worker_command: &str, by| {
        let gate_id = GateId::new_v4();
        actor
            .registry
            .append(
                &run,
                EventPayload::GateCreated {
                    gate_id,
                    gate_kind: GateKind::ExternalVerification,
                    summary: "Host verification".into(),
                    payload_path: state.path().join("external.json"),
                    requested_by: Origin::ControlPlane,
                    repair_binding: None,
                },
            )
            .unwrap();
        actor
            .registry
            .append(
                &run,
                EventPayload::GateResolving {
                    gate_id,
                    approve: true,
                    by,
                    feedback: None,
                    lead_decision: None,
                    commit: None,
                    external_verification: Some(ExternalVerificationEvidence {
                        builder_attempt_id: builder,
                        diff_hash: hash.clone(),
                        expected_run_seq: 1,
                        commands: vec![ExternalCommandResult {
                            worker_command: worker_command.into(),
                            argv: vec!["cargo".into(), "test".into()],
                            status: ExternalCommandStatus::Passed,
                            exit_status: Some(0),
                        }],
                        toolchain_identity: "test host".into(),
                        provenance: "immutable fixture".into(),
                        source_inventory_before_hash: hash.clone(),
                        source_inventory_after_hash: hash.clone(),
                        attestation: "Human-verified command result fixture".into(),
                        limitations: vec![],
                    }),
                },
            )
            .unwrap();
        actor
            .registry
            .append(
                &run,
                EventPayload::GateResolved {
                    gate_id,
                    status: GateStatus::Approved,
                    sha: None,
                    feedback: None,
                },
            )
            .unwrap();
    };
    let by_human = Actor::Socket {
        client_name: "test-human".into(),
    };
    record_external(&mut actor, "cargo check", by_human.clone());
    assert!(!verification_passed(&actor));
    record_external(&mut actor, "cargo test", Actor::Lead);
    assert!(!verification_passed(&actor));
    record_external(&mut actor, "cargo test", by_human);
    assert!(verification_passed(&actor));

    verify(&mut actor, VerifyStatus::NothingToRun, vec![], vec![]);
    assert!(!verification_passed(&actor));
    verify(
        &mut actor,
        VerifyStatus::NativePermissionRequired,
        vec![],
        vec![],
    );
    assert!(!verification_passed(&actor));
}
