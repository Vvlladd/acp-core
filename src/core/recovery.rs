//! Human-confirmed recovery from an idle, preserved builder draft (Revision 30).
//! One durable event is the acceptance point; the existing inherited-worktree dispatcher owns
//! spawning/replay. No provider process or filesystem work happens in the actor's preview.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::policy::{self, PolicyCode, PolicyError};
use super::team::{self, Assignment};
use super::types::*;
use super::{is_terminal, Core, CoreError};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub run_id: RunId,
    pub source_agent_id: AgentId,
    pub expected_seq: u64,
    pub request_id: Uuid,
    pub builder: Assignment,
    pub feedback: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub request: Request,
    pub agent_id: AgentId,
    pub by: Actor,
    pub gate_ids: Vec<GateId>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub run_id: RunId,
    pub agent_id: AgentId,
    pub request_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub agent_id: AgentId,
    pub worktree: PathBuf,
    pub builder: Assignment,
    pub retired: bool,
    pub recorded_files: Vec<String>,
    pub recorded_file_count: Option<usize>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub run_id: RunId,
    pub seq: u64,
    pub reason: String,
    pub unavailable_reason: Option<String>,
    pub candidates: Vec<Candidate>,
    pub execution: Option<RunExecution>,
}

fn refuse(reason: impl Into<String>) -> CoreError {
    PolicyError::new(PolicyCode::RecoveryUnavailable, reason).into()
}

impl Core {
    pub fn recovery_preview(&self, run_id: RunId) -> Result<Preview, CoreError> {
        let run = self
            .registry
            .run(&run_id)
            .ok_or_else(|| refuse("This task is no longer available."))?;
        let events = self.registry.events(&run_id, None, usize::MAX);
        let mut paths = std::collections::HashSet::new();
        let candidates: Vec<_> = run
            .agent_ids
            .iter()
            .rev()
            .filter_map(|id| {
                let agent = self.registry.agent(id)?;
                if agent.role != RoleName::Builder {
                    return None;
                }
                let worktree = agent.worktree.clone()?;
                let lineage = run
                    .lineages
                    .iter()
                    .find(|l| Some(l.lineage_id) == agent.lineage_id)?;
                if lineage.worktree != worktree {
                    return None;
                }
                let files = events.iter().rev().find_map(|e| match &e.payload {
                    EventPayload::DiffFrozen {
                        attempt_id, files, ..
                    } if agent.attempt_ids.contains(attempt_id) => Some(files),
                    _ => None,
                });
                Some(Candidate {
                    recorded_file_count: files.map(Vec::len),
                    recorded_files: files
                        .map(|files| {
                            files
                                .iter()
                                .take(8)
                                .map(|s| s.chars().take(160).collect())
                                .collect()
                        })
                        .unwrap_or_default(),
                    agent_id: *id,
                    worktree,
                    builder: Assignment {
                        provider: agent.provider,
                        model: agent.model.clone(),
                        effort: run
                            .execution
                            .as_ref()
                            .and_then(|e| e.assignments.get("builder"))
                            .filter(|a| a.provider == agent.provider && a.model == agent.model)
                            .and_then(|a| a.effort),
                    },
                    retired: lineage.closed
                        || matches!(agent.status, AgentStatus::Closed | AgentStatus::Cancelled),
                    last_error: agent
                        .attempt_ids
                        .last()
                        .and_then(|id| self.registry.attempt(id))
                        .and_then(|a| a.error.as_ref())
                        .map(|e| e.message.chars().take(1000).collect()),
                })
            })
            // Inherited sessions share a draft: keep its newest handle before applying the cap.
            .filter(|c| paths.insert(c.worktree.clone()))
            .take(32)
            .collect();
        let reason = run
            .blocked_reason
            .clone()
            .or_else(|| {
                run.gate_ids
                    .iter()
                    .rev()
                    .filter_map(|id| self.registry.gate(id))
                    .find(|g| g.kind == GateKind::Escalate && g.status == GateStatus::Pending)
                    .map(|g| g.summary.clone())
            })
            .or_else(|| candidates.iter().find_map(|c| c.last_error.clone()))
            .unwrap_or_else(|| "Inspect the preserved draft and choose how to continue.".into());
        Ok(Preview {
            run_id,
            seq: run.last_seq,
            reason: reason.chars().take(4000).collect(),
            unavailable_reason: self.check_recovery_idle(run).err().map(|e| match e {
                CoreError::Policy(error) => error.reason,
                other => other.to_string(),
            }),
            candidates,
            execution: run.execution.clone(),
        })
    }

    fn check_recovery_idle(&self, run: &Run) -> Result<(), CoreError> {
        if self.lifecycle.cancelling() {
            return Err(refuse("Cancellation is still in progress."));
        }
        if !matches!(
            run.status,
            RunStatus::Running | RunStatus::Blocked | RunStatus::Failed | RunStatus::AwaitingGate
        ) {
            return Err(refuse(
                "Completed, integrated or cancelled tasks cannot be recovered.",
            ));
        }
        let execution = run.execution.as_ref().ok_or_else(|| {
            refuse("This older task has no recorded execution setup. Start a new task.")
        })?;
        if execution.version != 1
            || execution.mode != RunMode::Build
            || run.audit.is_some()
            || self.registry.state().plans.contains_key(&run.run_id)
        {
            return Err(refuse(
                "Recovery is available for recorded build tasks only.",
            ));
        }
        if !self.pending_spawn.is_empty()
            || !self.pending_worktree.is_empty()
            || !self.pending_retry.is_empty()
            || !self.pending_audit.is_empty()
            || !self.in_flight.is_empty()
            || !self.settled.is_empty()
            || !self.gate_waiters.is_empty()
            || self.supervisor.pending_finalize_count() > 0
            || !self.supervisor.active_attempts().is_empty()
        {
            return Err(refuse("Preparation, finalization or a decision is still in progress. Refresh when it finishes."));
        }
        for agent in run
            .agent_ids
            .iter()
            .filter_map(|id| self.registry.agent(id))
        {
            if agent
                .attempt_ids
                .iter()
                .filter_map(|id| self.registry.attempt(id))
                .any(|a| !is_terminal(a.status) || !self.dispatched.contains(&a.attempt_id))
            {
                return Err(refuse("Work is still running or its result is being processed. Refresh when it finishes."));
            }
        }
        let gates: Vec<_> = run
            .gate_ids
            .iter()
            .filter_map(|id| self.registry.gate(id))
            .collect();
        if gates.iter().any(|g| {
            g.status == GateStatus::Resolving
                || (g.status == GateStatus::Pending && g.kind != GateKind::Escalate)
        }) {
            return Err(refuse(
                "Resolve the pending plan or integration decision before recovering work.",
            ));
        }
        let interrupted = matches!(run.status, RunStatus::Blocked | RunStatus::Failed)
            || gates
                .iter()
                .any(|g| g.status == GateStatus::Pending && g.kind == GateKind::Escalate)
            || run
                .agent_ids
                .iter()
                .rev()
                .filter_map(|id| self.registry.agent(id))
                .find(|a| a.role == RoleName::Builder)
                .and_then(|a| a.attempt_ids.last())
                .and_then(|id| self.registry.attempt(id))
                .is_some_and(|a| is_terminal(a.status) && a.status != AttemptStatus::Succeeded);
        if !interrupted {
            return Err(refuse(
                "This task has no interrupted builder work to recover.",
            ));
        }
        let role = self
            .roles
            .roles
            .get(&RoleName::Builder)
            .ok_or_else(|| refuse("No builder is configured."))?;
        if !role.writes
            || !self
                .roles
                .roles
                .get(&RoleName::Lead)
                .is_some_and(|lead| lead.allowed_delegations.contains(&RoleName::Builder))
        {
            return Err(refuse(
                "The current role policy does not allow a writing builder.",
            ));
        }
        policy::check_budget(run, role.spawn_budget_usd, &self.roles)?;
        if self
            .registry
            .state()
            .attempts
            .values()
            .filter(|a| !is_terminal(a.status))
            .count()
            >= self.roles.limits.max_concurrent_attempts as usize
        {
            return Err(refuse("The worker concurrency limit has been reached."));
        }
        Ok(())
    }

    pub fn recover_run(&mut self, request: Request, by: Actor) -> Result<Outcome, CoreError> {
        if !matches!(by, Actor::Socket { .. }) {
            return Err(refuse("Recovery is a human socket action."));
        }
        if request.feedback.chars().count() > 4000 {
            return Err(refuse("Recovery direction is limited to 4,000 characters."));
        }
        for event in self.registry.events(&request.run_id, None, usize::MAX) {
            if let EventPayload::RunRecovered { recovery } = &event.payload {
                if recovery.request.request_id == request.request_id {
                    if recovery.request != request {
                        return Err(refuse(
                            "This recovery request id was already used with different choices.",
                        ));
                    }
                    return Ok(Outcome {
                        run_id: request.run_id,
                        agent_id: recovery.agent_id,
                        request_id: request.request_id,
                    });
                }
            }
        }
        let run = self
            .registry
            .run(&request.run_id)
            .ok_or_else(|| refuse("This task is no longer available."))?;
        if run.last_seq != request.expected_seq {
            return Err(refuse(
                "This task changed after the preview. Refresh and confirm the current draft.",
            ));
        }
        self.check_recovery_idle(run)?;
        let source = self
            .registry
            .agent(&request.source_agent_id)
            .filter(|a| a.run_id == request.run_id && a.role == RoleName::Builder && a.writes)
            .ok_or_else(|| refuse("Choose a preserved builder draft from this task."))?;
        let worktree = source
            .worktree
            .as_ref()
            .ok_or_else(|| refuse("The builder has no preserved worktree."))?;
        if !run
            .lineages
            .iter()
            .any(|l| Some(l.lineage_id) == source.lineage_id && &l.worktree == worktree)
        {
            return Err(refuse(
                "The preserved worktree no longer matches the task's recorded lineage.",
            ));
        }
        if self.registry.state().agents.values().any(|a| {
            a.run_id != run.run_id
                && a.worktree.as_ref() == Some(worktree)
                && !matches!(a.status, AgentStatus::Closed | AgentStatus::Cancelled)
        }) {
            return Err(refuse("Another task still owns this worktree."));
        }
        if source.depth > self.roles.defaults.max_depth {
            return Err(refuse("The builder exceeds the current depth limit."));
        }
        let mut execution = run
            .execution
            .clone()
            .ok_or_else(|| refuse("The recorded setup is missing."))?;
        execution
            .assignments
            .insert("builder".into(), request.builder.clone());
        team::from_execution(&self.roles, &execution).map_err(|issues| {
            refuse(format!(
                "The selected builder or recorded checks are unavailable: {}",
                issues
                    .iter()
                    .take(4)
                    .map(|i| format!("{}: {}", i.role, i.detail))
                    .collect::<Vec<_>>()
                    .join("; ")
            ))
        })?;
        let gate_ids = run
            .gate_ids
            .iter()
            .filter_map(|id| self.registry.gate(id))
            .filter(|g| g.kind == GateKind::Escalate && g.status == GateStatus::Pending)
            .map(|g| g.gate_id)
            .collect();
        let agent_id = AgentId::new_v4();
        let outcome = Outcome {
            run_id: request.run_id,
            agent_id,
            request_id: request.request_id,
        };
        self.registry.append(
            &request.run_id,
            EventPayload::RunRecovered {
                recovery: Record {
                    request: request.clone(),
                    agent_id,
                    by,
                    gate_ids,
                },
            },
        )?;
        self.reissue_spawn(&agent_id);
        Ok(outcome)
    }
}

/// Fold the whole recovery transaction, or none of it. Reusing an existing replacement id is a
/// no-op even if replay sees a duplicate after that replacement has completed or integrated.
pub(super) fn reduce(state: &mut super::registry::State, event: &Event, record: &Record) {
    if state.agents.contains_key(&record.agent_id) {
        return;
    }
    let Some(source) = state.agents.get(&record.request.source_agent_id).cloned() else {
        return;
    };
    let Some(run) = state.runs.get_mut(&event.base.run_id) else {
        return;
    };
    if source.run_id != run.run_id || record.request.run_id != run.run_id {
        return;
    }
    let Some(execution) = run.execution.as_mut() else {
        return;
    };
    execution
        .assignments
        .insert("builder".into(), record.request.builder.clone());
    run.status = RunStatus::Running;
    run.blocked_reason = None;
    run.loop_state = LoopState::Retrying;
    for lineage in &mut run.lineages {
        lineage.closed = Some(lineage.lineage_id) != source.lineage_id;
        lineage.closed_reason = lineage
            .closed
            .then(|| "Superseded by human-confirmed recovery".into());
    }
    for id in &run.agent_ids {
        if let Some(a) = state.agents.get_mut(id) {
            if a.role != RoleName::Lead {
                a.status = AgentStatus::Closed;
            }
        }
    }
    for id in &record.gate_ids {
        if let Some(gate) = state.gates.get_mut(id) {
            if gate.run_id == run.run_id
                && gate.kind == GateKind::Escalate
                && gate.status == GateStatus::Pending
            {
                gate.status = GateStatus::Denied;
                gate.approve = Some(false);
                gate.resolved_by = Some(record.by.clone());
                gate.resolved_at = Some(event.base.ts.clone());
                gate.feedback = Some(format!("Recovery requested: {}", record.request.feedback));
            }
        }
    }
    // Reuse the ordinary constructor so derived handles and lineage membership stay identical.
    super::registry::reduce(
        state,
        &Event {
            base: event.base.clone(),
            payload: EventPayload::AgentCreated {
                agent_id: record.agent_id,
                role: RoleName::Builder,
                provider: record.request.builder.provider,
                model: record.request.builder.model.clone(),
                lineage_id: source.lineage_id,
                depth: source.depth,
                parent_agent_id: Some(source.agent_id),
                origin: Origin::ControlPlane,
                writes: true,
                cwd: source.cwd,
                worktree: source.worktree,
            },
        },
    );
}
