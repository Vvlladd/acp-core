//! The event log and its projection — sole writer of `events.jsonl`.
//! Implemented in T09 (`reports/03-design.md` § `src/core/registry.rs`).
//!
//! `<state_dir>/runs/<runId>/events.jsonl` is the only durable truth (design, § On-disk layout).
//! [`Registry::append`] writes and flushes the line **before** [`reduce`] touches the projection —
//! write-then-apply, so a crash can only ever lose the in-memory copy of state the log rebuilds.
//! [`Registry::open`] replays every log through the same [`reduce`] used at write time, which is
//! what makes "reopen after kill" produce a byte-for-byte identical [`State`].
//!
//! Idempotency (C2) is a property of [`reduce`], not of the caller: a duplicated tail line —
//! re-parsed after a restart and appended again with a fresh `seq` — must not regress a terminal
//! attempt's status and must not charge its cost twice. Tailer-derived events therefore carry
//! `srcLine`, and the reducer dedupes `attempt.usage` / `attempt.result` on
//! `(attemptId, kind, srcLine)`.
//!
//! Directories are created 0700 and files 0600. `libc::umask(0o077)` is set once at process start
//! (T43, `src/main.rs`), so the explicit modes here are belt-and-braces for a state dir a caller
//! points us at rather than the only control.
//!
//! This module must not know about providers, git or processes (design, § `src/core/registry.rs`).

use std::collections::{HashMap, HashSet};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::core::types::{
    AgentHandle, AgentId, AgentStatus, Attempt, AttemptId, AttemptStatus, Event, EventBase,
    EventPayload, Gate, GateId, GateStatus, LineageId, LineageState, LoopState, MessageRole,
    NewEvent, Run, RunId, RunStatus,
};

/// Slots in the event broadcast channel; a subscriber that falls further behind is lagged on
/// purpose rather than allowed to grow an unbounded queue (design, § Local IPC contract).
pub const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// `<state_dir>/runs/` — one directory per run (design, § On-disk layout).
const RUNS_DIR: &str = "runs";
/// `<state_dir>/runs/<runId>/events.jsonl` — the only durable truth.
const EVENTS_FILE: &str = "events.jsonl";
/// `<state_dir>/audit.jsonl` — policy rejections, which never touch a run log.
const AUDIT_FILE: &str = "audit.jsonl";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Anything that can stop the log being read or written. Never returned for a *malformed* log
/// line: a partial trailing line left by a kill mid-write is skipped, not propagated.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("{op} {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("encoding {what}: {source}")]
    Encode {
        what: &'static str,
        #[source]
        source: serde_json::Error,
    },
}

fn io_err<'a>(op: &'static str, path: &'a Path) -> impl FnOnce(io::Error) -> RegistryError + 'a {
    move |source| RegistryError::Io {
        op,
        path: path.to_path_buf(),
        source,
    }
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// One policy rejection, appended to `<state_dir>/audit.jsonl` (design, § Event union: "Policy
/// rejections never touch a run log (fail closed, no side effects)").
///
/// `code` is a plain string rather than `policy::PolicyCode` so the registry keeps knowing nothing
/// about policy; `policy.rs` owns the codes and stringifies them here.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub ts: String,
    pub tool: String,
    pub code: String,
    pub reason: String,
    pub request_digest: String,
}

impl AuditEntry {
    /// A rejection stamped with the current time.
    #[must_use]
    pub fn new(
        tool: impl Into<String>,
        code: impl Into<String>,
        reason: impl Into<String>,
        request_digest: impl Into<String>,
    ) -> Self {
        Self {
            ts: now_rfc3339(),
            tool: tool.into(),
            code: code.into(),
            reason: reason.into(),
            request_digest: request_digest.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// State + reducer
// ---------------------------------------------------------------------------

/// Which tailer-derived event a `(attempt, srcLine)` pair was already applied for. `attempt.usage`
/// and `attempt.result` can be derived from the *same* transcript line (Claude's final `result`
/// line carries both), so the source line alone is not a unique key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum TailEvent {
    Usage,
    Result,
}

/// The projection of one state dir's event logs: every run, agent, attempt and gate the control
/// plane knows about. Rebuilt from scratch by [`Registry::open`], so two processes replaying the
/// same logs hold equal `State`s.
#[derive(Clone, Default, PartialEq, Debug)]
pub struct State {
    pub runs: HashMap<RunId, Run>,
    pub agents: HashMap<AgentId, AgentHandle>,
    pub attempts: HashMap<AttemptId, Attempt>,
    pub gates: HashMap<GateId, Gate>,
    /// B3: the plan each container run carries, folded from `plan.created`/`plan.item`. The
    /// conductor reads only this — replayed state, never anything in-memory-only.
    pub plans: HashMap<RunId, PlanProjection>,
    /// C2 bookkeeping: the `(attempt, kind, srcLine)` triples already folded in. Private so the
    /// idempotency invariant cannot be broken from outside this module.
    applied: HashSet<(AttemptId, TailEvent, u64)>,
}

/// One container run's plan, as the log tells it.
#[derive(Clone, PartialEq, Debug)]
pub struct PlanProjection {
    pub plan: crate::core::plan::Plan,
    pub items: std::collections::BTreeMap<String, PlanItemState>,
}

/// Where one plan item stands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PlanItemState {
    pub status: crate::core::plan::PlanItemStatus,
    pub run_id: Option<RunId>,
    pub gate_id: Option<GateId>,
}

impl Default for PlanItemState {
    fn default() -> Self {
        PlanItemState {
            status: crate::core::plan::PlanItemStatus::Pending,
            run_id: None,
            gate_id: None,
        }
    }
}

/// Folds one event into the projection. Pure, total and **idempotent for terminal attempts** (C2):
/// re-applying an already-folded `attempt.finished` / `attempt.usage` / `attempt.result` leaves
/// `State` unchanged, so a duplicated tail line replayed after a restart cannot regress a status or
/// double-charge a run.
///
/// An event about an entity we have never seen (a hand-written log, a truncated prefix) is dropped
/// rather than fabricating one: `run.created`, `agent.created`, `attempt.started`,
/// `worktree.created` and `gate.created` are the only constructors.
pub fn reduce(s: &mut State, e: &Event) {
    let run_id = e.base.run_id;
    if let Some(run) = s.runs.get_mut(&run_id) {
        run.last_seq = run.last_seq.max(e.base.seq);
    }

    match &e.payload {
        EventPayload::RunRecovered { recovery } => super::recovery::reduce(s, e, recovery),
        EventPayload::AuditPrepared { snapshot } => {
            if let Some(run) = s.runs.get_mut(&run_id) {
                if run.audit.is_none() {
                    run.base_sha = snapshot.base_sha.clone();
                    run.audit = Some(crate::core::types::AuditRecord { snapshot: snapshot.clone(), checks: vec![] });
                }
            }
        }
        EventPayload::AuditChecked { check } => {
            if let Some(audit) = s.runs.get_mut(&run_id).and_then(|run| run.audit.as_mut()) {
                if !audit.checks.iter().any(|old| old.attempt_id == check.attempt_id) {
                    audit.checks.push(check.clone());
                }
            }
        }
        EventPayload::RunCreated {
            repo_root,
            state_dir,
            base_ref,
            base_sha,
            task,
            steps,
            execution,
            ..
        } => {
            s.runs.entry(run_id).or_insert_with(|| Run {
                audit: None,
                run_id,
                repo_root: repo_root.clone(),
                state_dir: state_dir.clone(),
                base_ref: base_ref.clone(),
                base_sha: base_sha.clone(),
                task: task.clone(),
                status: RunStatus::Running,
                blocked_reason: None,
                loop_state: LoopState::Building,
                created_at: e.base.ts.clone(),
                spend_usd: 0.0,
                agent_ids: Vec::new(),
                gate_ids: Vec::new(),
                integrated_sha: None,
                lineages: Vec::new(),
                last_seq: e.base.seq,
                steps: *steps,
                execution: execution.clone(),
            });
        }

        EventPayload::RunStatus_ { status, reason } => {
            if let Some(run) = s.runs.get_mut(&run_id) {
                run.status = *status;
                run.blocked_reason = reason.clone();
            }
        }

        EventPayload::LoopStateChanged { state, .. } => {
            if let Some(run) = s.runs.get_mut(&run_id) {
                run.loop_state = *state;
            }
        }

        EventPayload::WorktreeCreated {
            agent_id,
            lineage_id,
            path,
            ..
        } => {
            if let Some(run) = s.runs.get_mut(&run_id) {
                let lineage = lineage_mut(run, *lineage_id);
                lineage.worktree.clone_from(path);
                if !lineage.agent_ids.contains(agent_id) {
                    lineage.agent_ids.push(*agent_id);
                }
            }
        }

        // The worktree is gone from disk, so the lineage that owned it is over. `lineage.closed`
        // normally arrives first and is authoritative about the reason; this only closes a lineage
        // that is somehow still open.
        EventPayload::WorktreeRetired { path, reason, .. } => {
            if let Some(run) = s.runs.get_mut(&run_id) {
                if let Some(lineage) = run.lineages.iter_mut().find(|l| l.worktree == *path) {
                    if !lineage.closed {
                        lineage.closed = true;
                        lineage.closed_reason = Some(reason.clone());
                    }
                }
            }
        }

        EventPayload::AgentCreated {
            agent_id,
            role,
            provider,
            model,
            lineage_id,
            depth,
            parent_agent_id,
            origin,
            writes,
            cwd,
            worktree,
        } => {
            s.agents.entry(*agent_id).or_insert_with(|| AgentHandle {
                agent_id: *agent_id,
                run_id,
                role: *role,
                provider: *provider,
                model: model.clone(),
                lineage_id: *lineage_id,
                depth: *depth,
                parent_agent_id: *parent_agent_id,
                origin: *origin,
                writes: *writes,
                worktree: worktree.clone(),
                cwd: cwd.clone(),
                session_id: None,
                status: AgentStatus::Starting,
                resumable: false,
                attempt_ids: Vec::new(),
                created_at: e.base.ts.clone(),
            });
            if let Some(run) = s.runs.get_mut(&run_id) {
                if !run.agent_ids.contains(agent_id) {
                    run.agent_ids.push(*agent_id);
                }
                if let Some(lineage_id) = lineage_id {
                    if let Some(lineage) = run
                        .lineages
                        .iter_mut()
                        .find(|l| l.lineage_id == *lineage_id)
                    {
                        if !lineage.agent_ids.contains(agent_id) {
                            lineage.agent_ids.push(*agent_id);
                        }
                    }
                }
            }
        }

        EventPayload::AgentSession {
            agent_id,
            attempt_id,
            session_id,
            src_line,
        } => {
            if let Some(agent) = s.agents.get_mut(agent_id) {
                agent.session_id = Some(session_id.clone());
                agent.resumable = true;
            }
            bump_src_line(s, attempt_id, *src_line);
        }

        EventPayload::AgentStatusChanged {
            agent_id, status, ..
        } => {
            if let Some(agent) = s.agents.get_mut(agent_id) {
                agent.status = *status;
            }
        }

        EventPayload::AttemptStarted {
            attempt_id,
            agent_id,
            attempt_kind,
            dir,
            pid,
            pgid,
            start_time,
            pre_sha,
            timeout_sec,
            spawn_budget_usd,
            ..
        } => {
            // A duplicated `attempt.started` must not reset a finished attempt to `running` (C2).
            if !s.attempts.contains_key(attempt_id) {
                s.attempts.insert(
                    *attempt_id,
                    Attempt {
                        attempt_id: *attempt_id,
                        agent_id: *agent_id,
                        run_id,
                        kind: *attempt_kind,
                        dir: dir.clone(),
                        pid: Some(*pid),
                        pgid: Some(*pgid),
                        start_time: Some(start_time.clone()),
                        status: AttemptStatus::Running,
                        error: None,
                        started_at: e.base.ts.clone(),
                        finished_at: None,
                        pre_sha: pre_sha.clone(),
                        post_sha: None,
                        exit_code: None,
                        signal: None,
                        cost_usd: 0.0,
                        tokens: None,
                        src_line: 0,
                        byte_offset: 0,
                        timeout_sec: *timeout_sec,
                        spawn_budget_usd: *spawn_budget_usd,
                        result_path: None,
                        structured_valid: None,
                        structured: None,
                        violations: Vec::new(),
                        diff_path: None,
                    },
                );
            }
            if let Some(agent) = s.agents.get_mut(agent_id) {
                if !agent.attempt_ids.contains(attempt_id) {
                    agent.attempt_ids.push(*attempt_id);
                }
            }
        }

        EventPayload::AgentProgress {
            attempt_id,
            src_line,
            ..
        } => bump_src_line(s, attempt_id, *src_line),

        // `agent.progress` is the line-level cursor commit after every message block from that
        // provider line is durable. Advancing on an individual message would let a crash skip its
        // later siblings on restart.
        EventPayload::AgentMessage { .. } => {}

        // B3: the conductor's projection. `plan.created` seeds every item `pending`; each
        // `plan.item` is a transition the conductor made durable before acting on it.
        EventPayload::PlanCreated { plan } => {
            s.plans.entry(run_id).or_insert_with(|| PlanProjection {
                plan: plan.clone(),
                items: plan
                    .items
                    .iter()
                    .map(|item| (item.id.clone(), PlanItemState::default()))
                    .collect(),
            });
        }
        EventPayload::PlanItem {
            item_id,
            status,
            run_id: item_run,
            gate_id,
        } => {
            if let Some(plan) = s.plans.get_mut(&run_id) {
                if let Some(item) = plan.items.get_mut(item_id) {
                    item.status = *status;
                    if item_run.is_some() {
                        item.run_id = *item_run;
                    }
                    if gate_id.is_some() {
                        item.gate_id = *gate_id;
                    }
                }
            }
        }

        // Cost accrues per transcript line, so the dedup key is the source line — *not* the
        // attempt's terminal status: the drain that produces `attempt.usage` can land after
        // `attempt.finished`, and that first copy still has to be counted (exactly once).
        EventPayload::AttemptUsage {
            attempt_id,
            src_line,
            cost_usd,
            tokens,
            ..
        } => {
            if let Some(attempt) = s.attempts.get_mut(attempt_id) {
                if s.applied.insert((*attempt_id, TailEvent::Usage, *src_line)) {
                    attempt.cost_usd += *cost_usd;
                    attempt.tokens = Some(*tokens);
                    attempt.src_line = attempt.src_line.max(*src_line);
                    if let Some(run) = s.runs.get_mut(&run_id) {
                        run.spend_usd += *cost_usd;
                    }
                }
            }
        }

        EventPayload::AttemptResult {
            attempt_id,
            src_line,
            result_path,
            structured_valid,
            structured,
            ..
        } => {
            if let Some(attempt) = s.attempts.get_mut(attempt_id) {
                if s.applied
                    .insert((*attempt_id, TailEvent::Result, *src_line))
                {
                    attempt.result_path = Some(result_path.clone());
                    attempt.structured_valid = Some(*structured_valid);
                    attempt.structured = structured.clone();
                    attempt.src_line = attempt.src_line.max(*src_line);
                }
            }
        }

        // A cancellation *request* is a durable record; the outcome arrives as `attempt.finished`.
        EventPayload::AttemptCancelRequested { .. } => {}

        EventPayload::AttemptFinished {
            attempt_id,
            status,
            exit_code,
            signal,
            post_sha,
            error,
            ..
        } => {
            if let Some(attempt) = s.attempts.get_mut(attempt_id) {
                // C2: the first terminal status wins; a replayed copy never regresses it.
                if attempt.status == AttemptStatus::Running {
                    attempt.status = *status;
                    attempt.exit_code = *exit_code;
                    attempt.signal = signal.clone();
                    attempt.post_sha = post_sha.clone();
                    attempt.error = error.clone();
                    attempt.finished_at = Some(e.base.ts.clone());
                }
            }
        }

        EventPayload::PolicyViolated {
            attempt_id,
            violation,
            ..
        } => {
            if let Some(attempt) = attempt_id.as_ref().and_then(|id| s.attempts.get_mut(id)) {
                if !attempt.violations.contains(violation) {
                    attempt.violations.push(violation.clone());
                }
            }
        }

        EventPayload::DiffFrozen {
            attempt_id,
            diff_path,
            ..
        } => {
            if let Some(attempt) = s.attempts.get_mut(attempt_id) {
                attempt.diff_path = Some(diff_path.clone());
            }
        }

        // The verdict drives `loop.state` and `gate.created`; the reviewer's own attempt already
        // carries the structured payload, so there is nothing further to project.
        EventPayload::ReviewVerdict { .. } => {}

        // Same shape as the verdict above: the verify step's outcome will drive the loop's branch
        // decision (T64), and the verifier's own attempt will carry the structured report.
        EventPayload::VerifyReport { .. } => {}

        // The event carries the resulting count, not an increment, so replaying it is a no-op.
        EventPayload::LineageStrike {
            lineage_id,
            strikes,
            ..
        } => {
            if let Some(run) = s.runs.get_mut(&run_id) {
                if let Some(lineage) = run
                    .lineages
                    .iter_mut()
                    .find(|l| l.lineage_id == *lineage_id)
                {
                    lineage.strikes = *strikes;
                }
            }
        }

        EventPayload::LineageClosed { lineage_id, reason } => {
            if let Some(run) = s.runs.get_mut(&run_id) {
                if let Some(lineage) = run
                    .lineages
                    .iter_mut()
                    .find(|l| l.lineage_id == *lineage_id)
                {
                    lineage.closed = true;
                    lineage.closed_reason = Some(reason.clone());
                }
            }
        }

        EventPayload::GateCreated {
            gate_id,
            gate_kind,
            summary,
            payload_path,
            requested_by,
        } => {
            s.gates.entry(*gate_id).or_insert_with(|| Gate {
                gate_id: *gate_id,
                run_id,
                kind: *gate_kind,
                status: GateStatus::Pending,
                summary: summary.clone(),
                payload_path: payload_path.clone(),
                requested_by: *requested_by,
                created_at: e.base.ts.clone(),
                resolved_at: None,
                resolved_by: None,
                approve: None,
                feedback: None,
                sha: None,
                commit: None,
            });
            if let Some(run) = s.runs.get_mut(&run_id) {
                if !run.gate_ids.contains(gate_id) {
                    run.gate_ids.push(*gate_id);
                }
            }
        }

        EventPayload::GateResolving {
            gate_id,
            approve,
            feedback,
            by,
            commit,
        } => {
            if let Some(gate) = s.gates.get_mut(gate_id) {
                // Only a pending gate enters the in-flight window; a resolved one stays resolved.
                if gate.status == GateStatus::Pending {
                    gate.status = GateStatus::Resolving;
                }
                gate.approve = Some(*approve);
                gate.resolved_by = Some(by.clone());
                if feedback.is_some() {
                    gate.feedback.clone_from(feedback);
                }
                // What the commit helper was told to do, so finishing it never has to re-read the
                // gate's payload file. Kept on the same "a later `None` does not erase it" rule as
                // `feedback`: a denial carries none, and must not blank a target already recorded.
                if commit.is_some() {
                    gate.commit.clone_from(commit);
                }
            }
        }

        // `approve` is what the resolver *asked for* and is recorded by `gate.resolving`; the final
        // status is not evidence of it (an approved gate whose commit fails is not an approval).
        EventPayload::GateResolved {
            gate_id,
            status,
            sha,
            feedback,
        } => {
            if let Some(gate) = s.gates.get_mut(gate_id) {
                gate.status = *status;
                gate.resolved_at = Some(e.base.ts.clone());
                if sha.is_some() {
                    gate.sha.clone_from(sha);
                }
                if feedback.is_some() {
                    gate.feedback.clone_from(feedback);
                }
            }
        }

        EventPayload::IntegrateCommitted { gate_id, sha, .. } => {
            if let Some(run) = s.runs.get_mut(&run_id) {
                run.integrated_sha = Some(sha.clone());
            }
            if let Some(gate) = s.gates.get_mut(gate_id) {
                gate.sha = Some(sha.clone());
            }
        }

        // `loop.dispatched` carries nothing the projection needs: it is a marker the restart path
        // reads straight out of the log, and folding it in would put a fact about the *daemon's*
        // progress into a projection that describes the run (`core::mod`, `loop_dispatch`).
        EventPayload::LoopDispatched { .. } => {}

        // T84: a linkage on the *lead's* run to a run its delegation caused. Nothing the
        // projection tracks describes a run from the outside looking in; the delegated run's own
        // events are what drive its own state.
        EventPayload::RunDelegated { .. } | EventPayload::SecurityVerdict { .. } => {}
    }
}

/// The lineage with this id, created empty if `worktree.created` has not been seen for it yet.
fn lineage_mut(run: &mut Run, lineage_id: LineageId) -> &mut LineageState {
    if let Some(i) = run.lineages.iter().position(|l| l.lineage_id == lineage_id) {
        return &mut run.lineages[i];
    }
    run.lineages.push(LineageState {
        lineage_id,
        agent_ids: Vec::new(),
        worktree: PathBuf::new(),
        strikes: 0,
        closed: false,
        closed_reason: None,
    });
    run.lineages.last_mut().expect("just pushed")
}

/// `lastSrcLine` is the high-water mark over every tailer-derived event, and it is what a
/// re-attached tailer skips to (design, § Process model: "Re-attach").
fn bump_src_line(s: &mut State, attempt_id: &AttemptId, src_line: u64) {
    if let Some(attempt) = s.attempts.get_mut(attempt_id) {
        attempt.src_line = attempt.src_line.max(src_line);
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// The event log and its projection: the append handles, the replayed [`State`], the per-run event
/// history and the broadcast channel every subscriber (MCP `get_status`, socket `subscribe`, the
/// loop) reads.
pub struct Registry {
    state_dir: PathBuf,
    state: State,
    /// Append handles, opened lazily on the first append for a run.
    logs: HashMap<RunId, File>,
    /// Every event, in `seq` order per run — what `events(run, since, limit)` backfills from.
    events: HashMap<RunId, Vec<Arc<Event>>>,
    audit: Option<File>,
    tx: broadcast::Sender<Arc<Event>>,
}

impl Registry {
    /// Replays every `runs/*/events.jsonl` under `state_dir` through [`reduce`]. Takes no lock —
    /// `acp status` reads a state dir with no daemon running (design, § Process model).
    ///
    /// A malformed line (the partial tail a kill mid-write leaves behind) is skipped, not
    /// propagated: the well-formed events around it still load.
    ///
    /// # Errors
    /// Fails only on genuine I/O: the state dir cannot be created, or a log cannot be read.
    pub fn open(state_dir: &Path) -> Result<Self, RegistryError> {
        let (tx, _rx) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let mut registry = Self {
            state_dir: state_dir.to_path_buf(),
            state: State::default(),
            logs: HashMap::new(),
            events: HashMap::new(),
            audit: None,
            tx,
        };

        create_dir_0700(state_dir)?;
        let runs_dir = state_dir.join(RUNS_DIR);
        create_dir_0700(&runs_dir)?;

        let mut dirs = Vec::new();
        for entry in fs::read_dir(&runs_dir).map_err(io_err("read_dir", &runs_dir))? {
            let entry = entry.map_err(io_err("read_dir", &runs_dir))?;
            if entry.path().is_dir() {
                dirs.push(entry.path());
            }
        }
        // Replay order is deterministic across restarts; `seq` ordering *within* a run is the log's.
        dirs.sort();
        for dir in dirs {
            registry.replay(&dir.join(EVENTS_FILE))?;
        }
        Ok(registry)
    }

    /// Appends an event to `run`'s log and folds it into the projection.
    ///
    /// `seq` is monotonic per run and `ts` is RFC 3339 `now`. The line is written **and flushed
    /// before** [`reduce`] runs (write-then-apply), and the `Arc<Event>` is broadcast only after
    /// the write succeeded, so no subscriber can observe an event that is not on disk.
    ///
    /// # Errors
    /// Fails if the run directory or log cannot be opened or written, or the event cannot be
    /// encoded (a non-finite `costUsd` is the only realistic case).
    pub fn append(&mut self, run: &RunId, e: NewEvent) -> Result<Arc<Event>, RegistryError> {
        let seq = self
            .events
            .get(run)
            .and_then(|events| events.last())
            .map_or(0, |last| last.base.seq)
            + 1;
        let event = Event {
            base: EventBase {
                seq,
                ts: now_rfc3339(),
                run_id: *run,
            },
            payload: e,
        };
        let line = serde_json::to_string(&event).map_err(|source| RegistryError::Encode {
            what: "an event",
            source,
        })?;

        let path = self.log_path(run);
        if !self.logs.contains_key(run) {
            self.logs.insert(*run, open_append(&path)?);
        }
        let file = self.logs.get_mut(run).expect("just inserted");
        append_line(file, &line, &path)?;

        let event = Arc::new(event);
        reduce(&mut self.state, event.as_ref());
        self.events
            .entry(*run)
            .or_default()
            .push(Arc::clone(&event));
        // No subscribers is not an error — the log on disk is the recoverable truth.
        let _ = self.tx.send(Arc::clone(&event));
        Ok(event)
    }

    /// The whole projection — the snapshot a replay-equality check compares.
    #[must_use]
    pub fn state(&self) -> &State {
        &self.state
    }

    /// The state dir this registry replayed.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    #[must_use]
    pub fn run(&self, id: &RunId) -> Option<&Run> {
        self.state.runs.get(id)
    }

    #[must_use]
    pub fn agent(&self, id: &AgentId) -> Option<&AgentHandle> {
        self.state.agents.get(id)
    }

    #[must_use]
    pub fn attempt(&self, id: &AttemptId) -> Option<&Attempt> {
        self.state.attempts.get(id)
    }

    #[must_use]
    pub fn gate(&self, id: &GateId) -> Option<&Gate> {
        self.state.gates.get(id)
    }

    /// Every run, oldest first (ties broken by id) so listings do not shuffle between calls.
    pub fn runs(&self) -> impl Iterator<Item = &Run> {
        let mut runs: Vec<&Run> = self.state.runs.values().collect();
        runs.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.run_id.as_uuid().cmp(b.run_id.as_uuid()))
        });
        runs.into_iter()
    }

    /// The agents that may be writing in `worktree` right now: a writing role in a live state
    /// (design, § `src/core/policy.rs`: one writer per worktree, C5). There are no lease files —
    /// this scan *is* the rule. Paths are compared as recorded; the caller resolves symlinks.
    #[must_use]
    pub fn live_writers(&self, worktree: &Path) -> Vec<&AgentHandle> {
        let mut writers: Vec<&AgentHandle> = self
            .state
            .agents
            .values()
            .filter(|a| a.writes && is_live(a.status) && a.worktree.as_deref() == Some(worktree))
            .collect();
        writers.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.agent_id.as_uuid().cmp(b.agent_id.as_uuid()))
        });
        writers
    }

    /// Up to `limit` of `run`'s events with `seq > since_seq` — the socket's `sinceSeq` backfill.
    #[must_use]
    pub fn events(&self, run: &RunId, since_seq: Option<u64>, limit: usize) -> Vec<Arc<Event>> {
        let since = since_seq.unwrap_or(0);
        self.events
            .get(run)
            .into_iter()
            .flatten()
            .filter(|e| e.base.seq > since)
            .take(limit)
            .map(Arc::clone)
            .collect()
    }

    /// Number of already-durable **assistant** `agent.message` events for one attempt, stopping
    /// at the only meaningful ceiling (500 messages plus one marker). Used to restore the cap on
    /// reattach. A `user` turn (T82) shares the resumed attempt's id but is the human's, not one
    /// of the provider's 500 — counting it would cost the lead a message and, at exactly 500,
    /// hide a truncation marker that was never written.
    pub(crate) fn agent_message_count(&self, run: &RunId, attempt: &AttemptId) -> usize {
        self.events
            .get(run)
            .into_iter()
            .flatten()
            .filter(|event| {
                matches!(
                    &event.payload,
                    EventPayload::AgentMessage {
                        attempt_id,
                        role: MessageRole::Assistant,
                        ..
                    } if attempt_id == attempt
                )
            })
            .take(501)
            .count()
    }

    /// Whether at least `wanted` byte-identical payloads are already durable for `run`. The bound
    /// keeps retry dedup finite even when several identical text blocks share one `srcLine`.
    pub(crate) fn has_payload_occurrence(
        &self,
        run: &RunId,
        payload: &EventPayload,
        wanted: usize,
    ) -> bool {
        self.events
            .get(run)
            .into_iter()
            .flatten()
            .filter(|event| event.payload == *payload)
            .take(wanted)
            .count()
            == wanted
    }

    /// A receiver for every event appended from now on. Attach it *before* taking a backfill
    /// snapshot: the contract delivers an event twice rather than dropping it (design, § Local IPC
    /// contract).
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Event>> {
        self.tx.subscribe()
    }

    /// The broadcast sender, for the `CoreHandle` the MCP and socket doors share.
    #[must_use]
    pub fn event_sender(&self) -> broadcast::Sender<Arc<Event>> {
        self.tx.clone()
    }

    /// Records a policy rejection in `<state_dir>/audit.jsonl`. Rejections are fail-closed and have
    /// no side effects, so an audit that cannot be written is logged and dropped rather than turned
    /// into a second failure for the caller to handle.
    pub fn audit(&mut self, entry: AuditEntry) {
        if let Err(err) = self.write_audit(&entry) {
            tracing::warn!(%err, tool = %entry.tool, code = %entry.code, "audit entry not recorded");
        }
    }

    fn write_audit(&mut self, entry: &AuditEntry) -> Result<(), RegistryError> {
        let line = serde_json::to_string(entry).map_err(|source| RegistryError::Encode {
            what: "an audit entry",
            source,
        })?;
        let path = self.state_dir.join(AUDIT_FILE);
        if self.audit.is_none() {
            self.audit = Some(open_append(&path)?);
        }
        let file = self.audit.as_mut().expect("just inserted");
        append_line(file, &line, &path)
    }

    fn log_path(&self, run: &RunId) -> PathBuf {
        self.state_dir
            .join(RUNS_DIR)
            .join(run.to_string())
            .join(EVENTS_FILE)
    }

    /// Folds one `events.jsonl` into the projection, skipping lines that do not parse.
    fn replay(&mut self, path: &Path) -> Result<(), RegistryError> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(io_err("open", path)(err)),
        };

        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line = match line {
                Ok(line) => line,
                // Not UTF-8: the same class of damage as a partial line, and just as skippable.
                Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                    tracing::warn!(path = %path.display(), line = index + 1, %err,
                        "skipping an undecodable event line");
                    continue;
                }
                Err(err) => return Err(io_err("read", path)(err)),
            };
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Event>(&line) {
                Ok(event) => {
                    let event = Arc::new(event);
                    reduce(&mut self.state, event.as_ref());
                    self.events
                        .entry(event.base.run_id)
                        .or_default()
                        .push(event);
                }
                // A kill mid-write leaves half an object with no newline: tolerated, never fatal.
                Err(err) => {
                    tracing::warn!(path = %path.display(), line = index + 1, %err,
                        "skipping a malformed event line");
                }
            }
        }
        Ok(())
    }
}

/// The agent statuses that count as "might be writing" for C5.
fn is_live(status: AgentStatus) -> bool {
    matches!(
        status,
        AgentStatus::Starting | AgentStatus::Running | AgentStatus::Idle
    )
}

fn create_dir_0700(path: &Path) -> Result<(), RegistryError> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(io_err("create_dir", path))
}

/// Opens `path` for appending, creating it 0600 with its parents 0700.
///
/// If the file does not end in a newline — a kill mid-write — one is written first, so the next
/// event lands on a line of its own instead of being concatenated onto the fragment (which would
/// make the *new* event unreadable too). The fragment itself is left alone: nothing on this path
/// ever deletes log bytes.
fn open_append(path: &Path) -> Result<File, RegistryError> {
    if let Some(parent) = path.parent() {
        create_dir_0700(parent)?;
    }
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .map_err(io_err("open", path))?;

    let len = file.seek(SeekFrom::End(0)).map_err(io_err("seek", path))?;
    if len > 0 {
        file.seek(SeekFrom::Start(len - 1))
            .map_err(io_err("seek", path))?;
        let mut last = [0_u8; 1];
        file.read_exact(&mut last).map_err(io_err("read", path))?;
        if last[0] != b'\n' {
            file.write_all(b"\n").map_err(io_err("write", path))?;
        }
    }
    Ok(file)
}

fn append_line(file: &mut File, line: &str, path: &Path) -> Result<(), RegistryError> {
    file.write_all(line.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.flush())
        .map_err(io_err("write", path))
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// `2026-08-22T09:41:07.412Z` — the RFC 3339 UTC form every `ts` / `createdAt` / `finishedAt`
/// carries. Hand-rolled because the design's dependency set has no date crate, and the format has
/// to be stable: these strings are compared across restarts.
#[must_use]
pub fn now_rfc3339() -> String {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339_utc(
        i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX),
        since_epoch.subsec_millis(),
    )
}

fn rfc3339_utc(unix_secs: i64, millis: u32) -> String {
    let (year, month, day) = civil_from_days(unix_secs.div_euclid(86_400));
    let secs_of_day = unix_secs.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z",
        hour = secs_of_day / 3600,
        minute = (secs_of_day / 60) % 60,
        second = secs_of_day % 60,
    )
}

/// Days since 1970-01-01 → `(year, month, day)`. Howard Hinnant's `civil_from_days`, the standard
/// branch-free proleptic-Gregorian conversion.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097; // [0, 146_096]
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365; // [0, 399]
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100); // [0, 365]
    let month_prime = (5 * day_of_year + 2) / 153; // [0, 11], March-based
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1; // [1, 31]
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (year + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_renders_known_epochs() {
        assert_eq!(rfc3339_utc(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_utc(1_700_000_000, 412), "2023-11-14T22:13:20.412Z");
        // The leap day the naive `days / 365` conversions get wrong.
        assert_eq!(rfc3339_utc(1_709_164_800, 0), "2024-02-29T00:00:00.000Z");
        assert_eq!(rfc3339_utc(1_709_251_199, 999), "2024-02-29T23:59:59.999Z");
    }

    #[test]
    fn now_rfc3339_is_sortable_and_well_formed() {
        let now = now_rfc3339();
        assert_eq!(now.len(), 24, "{now}");
        assert!(now.ends_with('Z'), "{now}");
        // Lexical order is chronological order, which is what `runs()` and `status` rely on.
        assert!(now.as_str() > "2026-01-01T00:00:00.000Z", "{now}");
    }

    #[test]
    fn live_statuses_are_exactly_starting_running_idle() {
        assert!(is_live(AgentStatus::Starting));
        assert!(is_live(AgentStatus::Running));
        assert!(is_live(AgentStatus::Idle));
        assert!(!is_live(AgentStatus::Lost));
        assert!(!is_live(AgentStatus::Cancelled));
        assert!(!is_live(AgentStatus::Closed));
    }
}
