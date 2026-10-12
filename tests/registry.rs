//! `src/core/registry.rs` (T10): the event log, its projection and the guarantees the rest of the
//! control plane leans on — `reports/03-design.md` § Test Strategy, row `core/registry.rs`.
//!
//! Every test drives a `tempfile::TempDir` state dir; nothing is written into the repo. Two of them
//! deliberately bypass `append()` and write `events.jsonl` by hand, because a projection that can
//! only be built by the writer that produced it is not a replay — the hand-written log is also the
//! wire-format check that the on-disk layout is exactly
//! `<state_dir>/runs/<runId>/events.jsonl` with camelCase keys (including `kind2` and `gkind`).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agent_control_plane::core::registry::{AuditEntry, Registry};
use agent_control_plane::core::types::{
    Actor, AgentHandle, AgentId, AgentStatus, AttemptId, AttemptKind, AttemptStatus, CostSource,
    EventPayload, GateId, GateKind, GateStatus, LineageId, LineageState, LoopState, NewEvent,
    Origin, PolicyViolation, ProviderName, RoleName, Run, RunId, RunStatus, Task, TokenUsage,
    ViolationKind,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::time::timeout;

const SHA: &str = "1111111111111111111111111111111111111111";
const POST_SHA: &str = "2222222222222222222222222222222222222222";

fn state_dir() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn task() -> Task {
    Task {
        id: "T10".into(),
        title: "tests/registry.rs".into(),
        description: "append/reduce/replay/idempotency".into(),
        files: vec!["tests/registry.rs".into()],
        acceptance: vec!["cargo test --test registry exits 0".into()],
    }
}

fn tokens() -> TokenUsage {
    TokenUsage {
        input: 1200,
        cached_input: 800,
        output: 340,
        reasoning: Some(64),
    }
}

fn run_created(repo_root: &Path, state: &Path) -> NewEvent {
    EventPayload::RunCreated {
        execution: None,
        repo_root: repo_root.to_path_buf(),
        state_dir: state.to_path_buf(),
        base_ref: "main".into(),
        base_sha: SHA.into(),
        task: task(),
        version: 1,
        lead: Some("claude".into()),
        team_name: None,
        steps: None,
    }
}

fn worktree_created(agent: AgentId, lineage: LineageId, worktree: &Path) -> NewEvent {
    EventPayload::WorktreeCreated {
        agent_id: agent,
        lineage_id: lineage,
        path: worktree.to_path_buf(),
        branch: "acp/run/agent".into(),
        base_sha: SHA.into(),
    }
}

fn agent_created(
    agent: AgentId,
    lineage: LineageId,
    role: RoleName,
    writes: bool,
    worktree: &Path,
) -> NewEvent {
    EventPayload::AgentCreated {
        agent_id: agent,
        role,
        provider: if writes {
            ProviderName::Claude
        } else {
            ProviderName::Codex
        },
        model: "claude-haiku".into(),
        lineage_id: Some(lineage),
        depth: 1,
        parent_agent_id: None,
        origin: Origin::Lead,
        writes,
        cwd: worktree.to_path_buf(),
        worktree: Some(worktree.to_path_buf()),
    }
}

fn attempt_started(attempt: AttemptId, agent: AgentId, dir: &Path) -> NewEvent {
    EventPayload::AttemptStarted {
        attempt_id: attempt,
        agent_id: agent,
        attempt_kind: AttemptKind::Fresh,
        dir: dir.to_path_buf(),
        argv: vec!["claude".into(), "-p".into()],
        cwd: dir.to_path_buf(),
        pid: 4242,
        pgid: 4242,
        start_time: "Sat Aug 22 09:00:00 2026".into(),
        pre_sha: SHA.into(),
        timeout_sec: 900,
        spawn_budget_usd: 2.0,
    }
}

fn attempt_usage(attempt: AttemptId, src_line: u64, cost_usd: f64) -> NewEvent {
    EventPayload::AttemptUsage {
        attempt_id: attempt,
        src_line,
        cost_usd,
        tokens: tokens(),
        source: CostSource::Provider,
    }
}

fn attempt_finished(attempt: AttemptId, status: AttemptStatus) -> NewEvent {
    EventPayload::AttemptFinished {
        attempt_id: attempt,
        status,
        exit_code: Some(0),
        signal: None,
        post_sha: Some(POST_SHA.into()),
        duration_ms: 12_345,
        error: None,
    }
}

fn agent_status(agent: AgentId, status: AgentStatus) -> NewEvent {
    EventPayload::AgentStatusChanged {
        agent_id: agent,
        status,
        reason: None,
    }
}

fn events_path(state: &Path, run: RunId) -> PathBuf {
    state
        .join("runs")
        .join(run.to_string())
        .join("events.jsonl")
}

/// Writes `lines` to `<state>/runs/<run>/events.jsonl` **without** going through `append()`.
fn write_log(state: &Path, run: RunId, lines: &[Value]) {
    let path = events_path(state, run);
    fs::create_dir_all(path.parent().expect("parent")).expect("create run dir");
    let body: String = lines
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<Vec<_>>()
        .concat();
    fs::write(&path, body).expect("write events.jsonl");
}

fn close_enough(actual: f64, expected: f64) -> bool {
    (actual - expected).abs() < 1e-9
}

// ---------------------------------------------------------------------------
// append → reduce
// ---------------------------------------------------------------------------

#[test]
fn appended_events_project_the_hand_computed_run() {
    let state = state_dir();
    let repo = state_dir();
    let worktree = repo.path().join(".acp/worktrees/run/agent");
    let mut registry = Registry::open(state.path()).expect("open");

    let run = RunId::new_v4();
    let lineage = LineageId::new_v4();
    let agent = AgentId::new_v4();
    let attempt = AttemptId::new_v4();

    let created = registry
        .append(&run, run_created(repo.path(), state.path()))
        .expect("run.created");
    registry
        .append(&run, worktree_created(agent, lineage, &worktree))
        .expect("worktree.created");
    registry
        .append(
            &run,
            agent_created(agent, lineage, RoleName::Builder, true, &worktree),
        )
        .expect("agent.created");
    registry
        .append(&run, attempt_started(attempt, agent, &worktree))
        .expect("attempt.started");
    registry
        .append(&run, attempt_usage(attempt, 7, 0.25))
        .expect("attempt.usage");
    let last = registry
        .append(
            &run,
            EventPayload::RunStatus_ {
                status: RunStatus::AwaitingGate,
                reason: None,
            },
        )
        .expect("run.status");

    assert_eq!(created.base.seq, 1, "seq starts at 1");
    assert_eq!(last.base.seq, 6, "seq is monotonic per run");
    assert_eq!(created.base.run_id, run);

    let expected = Run {
        audit: None,
        execution: None,
        run_id: run,
        repo_root: repo.path().to_path_buf(),
        state_dir: state.path().to_path_buf(),
        base_ref: "main".into(),
        base_sha: SHA.into(),
        task: task(),
        status: RunStatus::AwaitingGate,
        blocked_reason: None,
        loop_state: LoopState::Building,
        created_at: created.base.ts.clone(),
        spend_usd: 0.25,
        agent_ids: vec![agent],
        gate_ids: Vec::new(),
        integrated_sha: None,
        lineages: vec![LineageState {
            lineage_id: lineage,
            agent_ids: vec![agent],
            worktree: worktree.clone(),
            strikes: 0,
            closed: false,
            closed_reason: None,
        }],
        last_seq: 6,
        steps: None,
    };
    assert_eq!(registry.run(&run), Some(&expected));

    let projected = registry.attempt(&attempt).expect("attempt projected");
    assert_eq!(projected.status, AttemptStatus::Running);
    assert_eq!(projected.agent_id, agent);
    assert_eq!(projected.src_line, 7, "lastSrcLine tracks the tailer");
    assert!(close_enough(projected.cost_usd, 0.25));
    assert_eq!(
        registry.agent(&agent).expect("agent projected").attempt_ids,
        vec![attempt]
    );
}

#[test]
fn append_writes_the_line_before_it_is_reduced() {
    let state = state_dir();
    let repo = state_dir();
    let mut registry = Registry::open(state.path()).expect("open");
    let run = RunId::new_v4();

    registry
        .append(&run, run_created(repo.path(), state.path()))
        .expect("run.created");

    // Write-then-apply: the durable line exists for every event the projection knows about, and it
    // is flushed by the time `append` returns rather than at some later buffer boundary.
    let body = fs::read_to_string(events_path(state.path(), run)).expect("events.jsonl exists");
    let line: Value = serde_json::from_str(body.trim_end()).expect("one well-formed JSON line");
    assert_eq!(line["kind"], "run.created");
    assert_eq!(line["seq"], 1);
    assert_eq!(line["runId"], run.to_string());
    assert!(body.ends_with('\n'), "lines are newline-terminated");
    assert!(
        registry.run(&run).is_some(),
        "and the projection is applied"
    );
}

#[test]
fn a_write_that_fails_leaves_the_projection_untouched() {
    let state = state_dir();
    let repo = state_dir();
    let mut registry = Registry::open(state.path()).expect("open");
    let run = RunId::new_v4();

    // The run directory path is occupied by a regular file, so the log cannot be created.
    let run_dir = state.path().join("runs").join(run.to_string());
    fs::create_dir_all(run_dir.parent().expect("parent")).expect("create runs dir");
    fs::write(&run_dir, "not a directory").expect("occupy the run dir path");

    let err = registry
        .append(&run, run_created(repo.path(), state.path()))
        .expect_err("append cannot succeed without a log");
    assert!(
        err.to_string().contains("runs"),
        "the error names the path: {err}"
    );

    // Write-then-apply: nothing was reduced, so a caller that retries cannot skip a seq or observe
    // state the log does not contain.
    assert!(registry.run(&run).is_none());
    assert!(registry.events(&run, None, 10).is_empty());
}

// ---------------------------------------------------------------------------
// hand-written log → open()
// ---------------------------------------------------------------------------

#[test]
fn a_hand_written_log_replays_into_the_expected_state() {
    let state = state_dir();
    let run = RunId::new_v4();
    let agent = AgentId::new_v4();
    let attempt = AttemptId::new_v4();
    let gate = GateId::new_v4();

    write_log(
        state.path(),
        run,
        &[
            json!({
                "seq": 1, "ts": "2026-08-22T09:00:00.000Z", "runId": run.to_string(),
                "kind": "run.created", "repoRoot": "/repo", "stateDir": "/state",
                "baseRef": "main", "baseSha": SHA, "version": 1, "lead": "codex",
                "task": {"id": "T10", "title": "t", "description": "d", "files": [], "acceptance": []},
            }),
            json!({
                "seq": 2, "ts": "2026-08-22T09:00:01.000Z", "runId": run.to_string(),
                "kind": "agent.created", "agentId": agent.to_string(), "role": "builder",
                "provider": "claude", "model": "claude-haiku", "lineageId": LineageId::new_v4().to_string(),
                "depth": 1, "parentAgentId": null, "origin": "lead", "writes": true,
                "cwd": "/repo/.acp/worktrees/r/a", "worktree": "/repo/.acp/worktrees/r/a",
            }),
            json!({
                "seq": 3, "ts": "2026-08-22T09:00:02.000Z", "runId": run.to_string(),
                "kind": "attempt.started", "attemptId": attempt.to_string(),
                "agentId": agent.to_string(), "kind2": "fresh", "dir": "/state/attempt",
                "argv": ["claude", "-p"], "cwd": "/repo/.acp/worktrees/r/a", "pid": 11, "pgid": 11,
                "startTime": "Sat Aug 22 09:00:02 2026", "preSha": SHA, "timeoutSec": 900,
                "spawnBudgetUsd": 2.0,
            }),
            json!({
                "seq": 4, "ts": "2026-08-22T09:00:03.000Z", "runId": run.to_string(),
                "kind": "attempt.finished", "attemptId": attempt.to_string(),
                "status": "succeeded", "exitCode": 0, "signal": null, "postSha": POST_SHA,
                "durationMs": 3000, "error": null,
            }),
            json!({
                "seq": 5, "ts": "2026-08-22T09:00:04.000Z", "runId": run.to_string(),
                "kind": "gate.created", "gateId": gate.to_string(), "gkind": "integrate",
                "summary": "integrate T10", "payloadPath": "/state/gates/g.json",
                "requestedBy": "control-plane",
            }),
        ],
    );

    let registry = Registry::open(state.path()).expect("open");

    let projected = registry.run(&run).expect("run replayed");
    assert_eq!(projected.status, RunStatus::Running, "no run.status event");
    assert_eq!(projected.loop_state, LoopState::Building);
    assert_eq!(projected.created_at, "2026-08-22T09:00:00.000Z");
    assert_eq!(projected.base_sha, SHA);
    assert_eq!(projected.agent_ids, vec![agent]);
    assert_eq!(projected.gate_ids, vec![gate]);
    assert_eq!(projected.last_seq, 5);
    assert!(close_enough(projected.spend_usd, 0.0));

    let projected = registry.agent(&agent).expect("agent replayed");
    assert_eq!(projected.status, AgentStatus::Starting);
    assert_eq!(projected.role, RoleName::Builder);
    assert!(projected.writes);
    assert_eq!(projected.session_id, None);
    assert_eq!(projected.attempt_ids, vec![attempt]);

    let projected = registry.attempt(&attempt).expect("attempt replayed");
    assert_eq!(projected.status, AttemptStatus::Succeeded);
    assert_eq!(projected.kind, AttemptKind::Fresh);
    assert_eq!(projected.exit_code, Some(0));
    assert_eq!(projected.post_sha.as_deref(), Some(POST_SHA));
    assert_eq!(
        projected.finished_at.as_deref(),
        Some("2026-08-22T09:00:03.000Z")
    );

    let projected = registry.gate(&gate).expect("gate replayed");
    assert_eq!(projected.status, GateStatus::Pending);
    assert_eq!(projected.kind, GateKind::Integrate);
    assert_eq!(projected.requested_by, Origin::ControlPlane);

    // `sinceSeq` backfill is exclusive, and `limit` caps it.
    let backfill = registry.events(&run, Some(3), 10);
    assert_eq!(
        backfill.iter().map(|e| e.base.seq).collect::<Vec<_>>(),
        vec![4, 5]
    );
    assert_eq!(registry.events(&run, None, 2).len(), 2);
    assert_eq!(registry.runs().count(), 1);
}

// ---------------------------------------------------------------------------
// replay equality after a kill
// ---------------------------------------------------------------------------

#[test]
fn reopening_after_a_kill_rebuilds_an_identical_state() {
    let state = state_dir();
    let repo = state_dir();
    let worktree = repo.path().join(".acp/worktrees/run/agent");
    let run = RunId::new_v4();
    let lineage = LineageId::new_v4();
    let agent = AgentId::new_v4();
    let attempt = AttemptId::new_v4();
    let gate = GateId::new_v4();

    let snapshot = {
        let mut registry = Registry::open(state.path()).expect("open");
        for event in [
            run_created(repo.path(), state.path()),
            EventPayload::LoopStateChanged {
                state: LoopState::Building,
                builder_agent_id: Some(agent),
                attempt_no: 1,
                strikes: 0,
            },
            worktree_created(agent, lineage, &worktree),
            agent_created(agent, lineage, RoleName::Builder, true, &worktree),
            attempt_started(attempt, agent, &worktree),
            EventPayload::AgentSession {
                agent_id: agent,
                attempt_id: attempt,
                session_id: "sess-1".into(),
                src_line: 1,
            },
            EventPayload::AgentProgress {
                attempt_id: attempt,
                src_line: 4,
                phase: "tool_use".into(),
                note: None,
            },
            attempt_usage(attempt, 9, 0.5),
            EventPayload::PolicyViolated {
                attempt_id: Some(attempt),
                agent_id: Some(agent),
                violation: PolicyViolation {
                    kind: ViolationKind::WorkerCommitted,
                    detail: "worker committed".into(),
                    files: Some(vec!["src/adder.ts".into()]),
                    pre_sha: Some(SHA.into()),
                    post_sha: Some(POST_SHA.into()),
                },
            },
            EventPayload::LineageStrike {
                lineage_id: lineage,
                agent_id: agent,
                reason: "review FAIL".into(),
                strikes: 1,
            },
            EventPayload::GateCreated {
                gate_id: gate,
                gate_kind: GateKind::Integrate,
                summary: "integrate".into(),
                payload_path: state.path().join("gates/g.json"),
                requested_by: Origin::ControlPlane,
            },
            EventPayload::GateResolving {
                gate_id: gate,
                approve: true,
                feedback: None,
                by: Actor::Socket {
                    client_name: "acp-mac".into(),
                },
                commit: None,
            },
        ] {
            registry.append(&run, event).expect("append");
        }
        registry.state().clone()
        // the registry is dropped here — the kill
    };

    let reopened = Registry::open(state.path()).expect("reopen");
    assert_eq!(&snapshot, reopened.state(), "replay is not identical");

    // Spot-check the parts a `==` on hash maps would hide behind a bad `PartialEq`.
    let projected = reopened.run(&run).expect("run");
    assert_eq!(projected.last_seq, 12);
    assert_eq!(projected.lineages[0].strikes, 1);
    assert!(close_enough(projected.spend_usd, 0.5));
    assert_eq!(
        reopened.agent(&agent).expect("agent").session_id.as_deref(),
        Some("sess-1")
    );
    assert_eq!(
        reopened
            .attempt(&attempt)
            .expect("attempt")
            .violations
            .len(),
        1
    );
    assert_eq!(
        reopened.gate(&gate).expect("gate").status,
        GateStatus::Resolving
    );
    assert_eq!(reopened.events(&run, None, 100).len(), 12);

    // `seq` continues where the log left off rather than restarting at 1.
    let mut reopened = reopened;
    let next = reopened
        .append(&run, agent_status(agent, AgentStatus::Idle))
        .expect("append after reopen");
    assert_eq!(next.base.seq, 13);
}

// ---------------------------------------------------------------------------
// C2 — duplicated tail replay
// ---------------------------------------------------------------------------

#[test]
fn a_duplicated_tail_replay_neither_regresses_status_nor_double_counts_cost() {
    let state = state_dir();
    let repo = state_dir();
    let worktree = repo.path().join(".acp/worktrees/run/agent");
    let mut registry = Registry::open(state.path()).expect("open");

    let run = RunId::new_v4();
    let lineage = LineageId::new_v4();
    let agent = AgentId::new_v4();
    let attempt = AttemptId::new_v4();

    registry
        .append(&run, run_created(repo.path(), state.path()))
        .expect("run.created");
    registry
        .append(
            &run,
            agent_created(agent, lineage, RoleName::Builder, true, &worktree),
        )
        .expect("agent.created");
    registry
        .append(&run, attempt_started(attempt, agent, &worktree))
        .expect("attempt.started");

    let finished = attempt_finished(attempt, AttemptStatus::Succeeded);
    let usage = attempt_usage(attempt, 12, 1.0);
    registry.append(&run, finished.clone()).expect("finished");
    registry.append(&run, usage.clone()).expect("usage");

    let first = registry.attempt(&attempt).expect("attempt").clone();
    assert_eq!(first.status, AttemptStatus::Succeeded);
    assert!(close_enough(first.cost_usd, 1.0));

    // The tailer re-parses the same two transcript lines after a restart and appends them again.
    registry.append(&run, finished).expect("duplicate finished");
    registry.append(&run, usage).expect("duplicate usage");
    // …and a *different* terminal status must not overwrite the first one either.
    registry
        .append(&run, attempt_finished(attempt, AttemptStatus::Failed))
        .expect("late failed");

    let after = registry.attempt(&attempt).expect("attempt");
    assert_eq!(
        after.status,
        AttemptStatus::Succeeded,
        "a terminal status must never regress"
    );
    assert_eq!(
        after.finished_at, first.finished_at,
        "the first finish wins"
    );
    assert!(
        close_enough(after.cost_usd, 1.0),
        "attempt.costUsd counted twice: {}",
        after.cost_usd
    );
    let projected = registry.run(&run).expect("run");
    assert!(
        close_enough(projected.spend_usd, 1.0),
        "run.spendUsd counted twice: {}",
        projected.spend_usd
    );

    // A *new* transcript line for the same attempt is still charged: the dedup key is the source
    // line, not the attempt.
    registry
        .append(&run, attempt_usage(attempt, 13, 0.5))
        .expect("later usage");
    assert!(close_enough(
        registry.attempt(&attempt).expect("attempt").cost_usd,
        1.5
    ));
    assert!(close_enough(
        registry.run(&run).expect("run").spend_usd,
        1.5
    ));

    // Idempotency is a property of the projection, not of the log: every line is still durable.
    assert_eq!(registry.events(&run, None, 100).len(), 9);

    // And the same duplicates replayed from disk reach the same state.
    let snapshot = registry.state().clone();
    drop(registry);
    assert_eq!(
        &snapshot,
        Registry::open(state.path()).expect("reopen").state()
    );
}

// ---------------------------------------------------------------------------
// broadcast
// ---------------------------------------------------------------------------

#[tokio::test]
async fn append_broadcasts_the_appended_event() {
    let state = state_dir();
    let repo = state_dir();
    let mut registry = Registry::open(state.path()).expect("open");
    let run = RunId::new_v4();

    let mut rx = registry.subscribe();
    let appended = registry
        .append(&run, run_created(repo.path(), state.path()))
        .expect("run.created");

    let received = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("an event within 5s")
        .expect("no lag, no closed channel");
    assert!(
        Arc::ptr_eq(&appended, &received),
        "subscribers get the very Arc that was appended"
    );
    assert_eq!(received.base.seq, 1);
    assert_eq!(received.base.run_id, run);
}

// ---------------------------------------------------------------------------
// malformed trailing line
// ---------------------------------------------------------------------------

#[test]
fn a_malformed_trailing_line_is_skipped_and_the_events_before_it_survive() {
    let state = state_dir();
    let repo = state_dir();
    let worktree = repo.path().join(".acp/worktrees/run/agent");
    let run = RunId::new_v4();
    let lineage = LineageId::new_v4();
    let agent = AgentId::new_v4();

    {
        let mut registry = Registry::open(state.path()).expect("open");
        registry
            .append(&run, run_created(repo.path(), state.path()))
            .expect("run.created");
        registry
            .append(
                &run,
                agent_created(agent, lineage, RoleName::Builder, true, &worktree),
            )
            .expect("agent.created");
    }

    // A kill mid-write: half an object, no trailing newline.
    let path = events_path(state.path(), run);
    let fragment = format!(
        "{{\"seq\":3,\"ts\":\"2026-08-22T09:00:02.000Z\",\"runId\":\"{run}\",\"kind\":\"agent.st"
    );
    let mut body = fs::read_to_string(&path).expect("read log");
    body.push_str(&fragment);
    fs::write(&path, &body).expect("write log");

    let mut registry = Registry::open(state.path()).expect("a partial line is not an open failure");
    assert!(registry.run(&run).is_some(), "earlier events still load");
    assert_eq!(registry.run(&run).expect("run").last_seq, 2);
    assert!(registry.agent(&agent).is_some());
    assert_eq!(registry.events(&run, None, 100).len(), 2);

    // The next append must not be concatenated onto the fragment — it has to be readable itself.
    let appended = registry
        .append(&run, agent_status(agent, AgentStatus::Running))
        .expect("append after a partial line");
    assert_eq!(appended.base.seq, 3);
    drop(registry);

    let body = fs::read_to_string(&path).expect("read log");
    assert!(body.contains(&fragment), "log bytes are never deleted");
    let registry = Registry::open(state.path()).expect("reopen");
    assert_eq!(registry.events(&run, None, 100).len(), 3);
    assert_eq!(
        registry.agent(&agent).expect("agent").status,
        AgentStatus::Running
    );
}

// ---------------------------------------------------------------------------
// live_writers (C5)
// ---------------------------------------------------------------------------

#[test]
fn live_writers_lists_only_live_writing_agents_in_that_worktree() {
    let state = state_dir();
    let repo = state_dir();
    let worktree = repo.path().join(".acp/worktrees/run/builder");
    let other = repo.path().join(".acp/worktrees/run/replacement");
    let mut registry = Registry::open(state.path()).expect("open");

    let run = RunId::new_v4();
    let lineage = LineageId::new_v4();
    let starting = AgentId::new_v4();
    let idle = AgentId::new_v4();
    let closed = AgentId::new_v4();
    let reviewer = AgentId::new_v4();
    let elsewhere = AgentId::new_v4();

    registry
        .append(&run, run_created(repo.path(), state.path()))
        .expect("run.created");
    for (agent, role, writes, dir) in [
        (starting, RoleName::Builder, true, &worktree),
        (idle, RoleName::Builder, true, &worktree),
        (closed, RoleName::Builder, true, &worktree),
        (reviewer, RoleName::Reviewer, false, &worktree),
        (elsewhere, RoleName::Builder, true, &other),
    ] {
        registry
            .append(&run, agent_created(agent, lineage, role, writes, dir))
            .expect("agent.created");
    }
    registry
        .append(&run, agent_status(idle, AgentStatus::Idle))
        .expect("agent.status idle");
    registry
        .append(&run, agent_status(closed, AgentStatus::Closed))
        .expect("agent.status closed");
    registry
        .append(&run, agent_status(reviewer, AgentStatus::Running))
        .expect("agent.status running");
    registry
        .append(&run, agent_status(elsewhere, AgentStatus::Running))
        .expect("agent.status running");

    let live = registry.live_writers(&worktree);
    let ids = sorted_ids(&live);
    assert_eq!(
        ids,
        sorted(vec![starting, idle]),
        "starting and idle writers are live"
    );
    assert!(
        !ids.contains(&closed),
        "a closed agent is not a live writer even in the same worktree"
    );
    assert!(
        !ids.contains(&reviewer),
        "a non-writing reviewer sharing the worktree is not a live writer"
    );
    assert!(
        !ids.contains(&elsewhere),
        "another worktree is another lease"
    );

    // The remaining live statuses, and the empty case the policy check depends on.
    registry
        .append(&run, agent_status(starting, AgentStatus::Running))
        .expect("agent.status running");
    assert_eq!(
        sorted_ids(&registry.live_writers(&worktree)),
        sorted(vec![starting, idle])
    );
    assert_eq!(sorted_ids(&registry.live_writers(&other)), vec![elsewhere]);
    for status in [
        AgentStatus::Cancelled,
        AgentStatus::Lost,
        AgentStatus::Closed,
    ] {
        registry
            .append(&run, agent_status(starting, status))
            .expect("agent.status");
        registry
            .append(&run, agent_status(idle, status))
            .expect("agent.status");
        assert!(
            registry.live_writers(&worktree).is_empty(),
            "{status:?} is not a live status"
        );
    }
    assert!(registry
        .live_writers(&repo.path().join("nowhere"))
        .is_empty());
}

fn sorted_ids(agents: &[&AgentHandle]) -> Vec<AgentId> {
    sorted(agents.iter().map(|a| a.agent_id).collect())
}

fn sorted(mut ids: Vec<AgentId>) -> Vec<AgentId> {
    ids.sort_by_key(|id| *id.as_uuid());
    ids
}

// ---------------------------------------------------------------------------
// audit + on-disk modes
// ---------------------------------------------------------------------------

#[test]
fn policy_rejections_are_audited_outside_every_run_log() {
    let state = state_dir();
    let mut registry = Registry::open(state.path()).expect("open");

    registry.audit(AuditEntry::new(
        "delegate",
        "worktree_busy",
        "another builder is live in that worktree",
        "sha256:abcd",
    ));
    registry.audit(AuditEntry::new(
        "resolve_gate",
        "agent_approve_not_allowed",
        "approval is a human action",
        "sha256:ef01",
    ));

    let body = fs::read_to_string(state.path().join("audit.jsonl")).expect("audit.jsonl");
    let lines: Vec<Value> = body
        .lines()
        .map(|line| serde_json::from_str(line).expect("one JSON object per line"))
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["tool"], "delegate");
    assert_eq!(lines[0]["code"], "worktree_busy");
    assert_eq!(lines[0]["requestDigest"], "sha256:abcd");
    assert!(lines[0]["ts"].as_str().expect("ts").ends_with('Z'));
    assert_eq!(lines[1]["code"], "agent_approve_not_allowed");

    // A rejection has no side effects: it never creates a run.
    assert_eq!(registry.runs().count(), 0);
}

#[test]
fn state_is_created_0700_with_0600_files() {
    let state = state_dir();
    let repo = state_dir();
    let mut registry = Registry::open(state.path()).expect("open");
    let run = RunId::new_v4();
    registry
        .append(&run, run_created(repo.path(), state.path()))
        .expect("run.created");
    registry.audit(AuditEntry::new(
        "delegate",
        "unknown_role",
        "no",
        "sha256:0",
    ));

    assert_eq!(mode(&state.path().join("runs")), 0o700);
    assert_eq!(
        mode(&state.path().join("runs").join(run.to_string())),
        0o700
    );
    assert_eq!(mode(&events_path(state.path(), run)), 0o600);
    assert_eq!(mode(&state.path().join("audit.jsonl")), 0o600);
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path)
        .unwrap_or_else(|err| panic!("stat {}: {err}", path.display()))
        .permissions()
        .mode()
        & 0o777
}
