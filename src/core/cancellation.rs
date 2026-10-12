//! Human cancel-and-stop, serialized with work admission by the core actor. Cancellation intent
//! is the durable cancelled run status; ticks and restart recovery never revive those runs.

use std::collections::HashSet;
use std::time::Instant;

use super::gates::{self, ResolveOutcome};
use super::lifecycle::{Request, Status, StopMode};
use super::plan::PlanItemStatus;
use super::types::{
    Actor, AgentStatus, AttemptId, AttemptStatus, CancelBy, EventPayload, GateStatus, RunId,
    RunStatus,
};
use super::{Command, Core, CoreError};

#[derive(Default)]
pub(super) struct Cancellation {
    pub worktrees: HashSet<super::types::LineageId>,
    signalled: HashSet<AttemptId>,
}

fn refusal(reason: &str) -> CoreError {
    CoreError::Lifecycle {
        code: "daemon_cancelling",
        reason: reason.into(),
    }
}

impl Core {
    /// Keep reads, helper completions and cancellation available while refusing new work.
    pub(super) fn admit_during_cancellation(&self, cmd: Command) -> Option<Command> {
        if !self.lifecycle.cancelling() {
            return Some(cmd);
        }
        let reason = "work is being cancelled; wait for it to finish or withdraw the stop request";
        match cmd {
            Command::CheckStart { reply, .. } => { let _ = reply.send(Err(refusal(reason))); }
            Command::RecoverRun { reply, .. } => { let _ = reply.send(Err(refusal(reason))); }
            Command::LeadStart { reply, .. } => {
                let _ = reply.send(Err(refusal(reason)));
            }
            Command::StartPlan { reply, .. } => {
                let _ = reply.send(Err(refusal(reason)));
            }
            Command::AuditStart { reply, .. } => {
                let _ = reply.send(Err(refusal(reason)));
            }
            Command::Delegate { reply, .. } => {
                let _ = reply.send(Err(refusal(reason)));
            }
            Command::SendMessage { reply, .. } => {
                let _ = reply.send(Err(refusal(reason)));
            }
            Command::CreateGate { reply, .. } => {
                let _ = reply.send(Err(refusal(reason)));
            }
            Command::ResolveGate {
                approve: true,
                reply,
                ..
            } => {
                let _ = reply.send(Err(refusal(reason)));
            }
            other => return Some(other),
        }
        None
    }

    pub(super) async fn lifecycle_request(
        &mut self,
        request: Request,
    ) -> Result<Status, CoreError> {
        let cancel = matches!(
            request,
            Request::Stop {
                mode: StopMode::CancelWork
            }
        );
        if cancel
            && (self
                .registry
                .state()
                .gates
                .values()
                .any(|g| g.status == GateStatus::Resolving)
                || !self.gate_waiters.is_empty())
        {
            return Err(refusal(
                "an integration is resolving; let it finish before cancelling work",
            ));
        }
        let mut status = self
            .lifecycle
            .request(request, self.lifecycle_busy_reasons(), Instant::now())
            .map_err(|e| CoreError::Lifecycle {
                code: e.code,
                reason: e.reason,
            })?;
        if cancel {
            self.cancel_local_checks();
            self.cancellation
                .worktrees
                .extend(self.pending_worktree.keys().copied());
            let runs: Vec<_> = self
                .registry
                .runs()
                .filter(|r| {
                    matches!(
                        r.status,
                        RunStatus::Running | RunStatus::AwaitingGate | RunStatus::Blocked
                    )
                })
                .map(|r| r.run_id)
                .collect();
            for run in runs {
                if let Err(error) = self.record_run_cancellation(&run) {
                    self.lifecycle
                        .fail_stop(format!("Could not record cancellation of {run}: {error}"));
                    return Err(error);
                }
            }
            self.reconcile_cancellations().await;
            status = self
                .lifecycle
                .request(
                    Request::Status,
                    self.lifecycle_busy_reasons(),
                    Instant::now(),
                )
                .map_err(|e| CoreError::Lifecycle {
                    code: e.code,
                    reason: e.reason,
                })?;
        }
        status.active_tasks = self
            .registry
            .runs()
            .filter(|r| {
                matches!(
                    r.status,
                    RunStatus::Running | RunStatus::AwaitingGate | RunStatus::Blocked
                )
            })
            .map(|r| super::lifecycle::ActiveTask {
                run_id: r.run_id,
                title: r.task.title.clone(),
            })
            .collect();
        Ok(status)
    }

    pub(super) fn record_run_cancellation(&mut self, run: &RunId) -> Result<(), CoreError> {
        self.registry.append(
            run,
            EventPayload::RunStatus_ {
                status: RunStatus::Cancelled,
                reason: Some("Cancelled by the human's stop request".into()),
            },
        )?;
        Ok(())
    }

    /// Called even without a live stop request: a restart must finish durable cancellations.
    /// Never infer success from sending SIGTERM. Lost identity holds the daemon for the human.
    pub(super) async fn reconcile_cancellations(&mut self) {
        let runs: Vec<_> = self
            .registry
            .runs()
            .filter(|r| r.status == RunStatus::Cancelled)
            .map(|r| r.run_id)
            .collect();
        for run in runs {
            if let Err(error) = self.close_cancelled_run(&run) {
                self.lifecycle
                    .fail_stop(format!("Cancellation of {run} is incomplete: {error}"));
                continue;
            }
            for attempt in self
                .registry
                .state()
                .attempts
                .values()
                .filter(|a| a.run_id == run)
            {
                if attempt.status == AttemptStatus::Lost {
                    self.lifecycle.fail_stop(format!("Cannot verify cancellation of attempt {}: its process identity was lost. Supervision remains available.", attempt.attempt_id));
                }
            }
            for (attempt, owner) in self.supervisor.active_attempts() {
                if owner != run {
                    continue;
                }
                if self.cancellation.signalled.insert(attempt) {
                    if let Err(error) = self
                        .supervisor
                        .cancel(&attempt, CancelBy::Cli, &mut self.registry)
                        .await
                    {
                        self.lifecycle
                            .fail_stop(format!("Could not cancel attempt {attempt}: {error}"));
                    }
                }
                if self.supervisor.cancellation_signal_refused(&attempt) {
                    self.lifecycle.fail_stop(format!("Could not cancel attempt {attempt}: the operating system refused a stop signal. Supervision remains available."));
                }
            }
        }
    }

    fn close_cancelled_run(&mut self, run: &RunId) -> Result<(), CoreError> {
        let agents: Vec<_> = self
            .registry
            .state()
            .agents
            .values()
            .filter(|a| {
                a.run_id == *run
                    && !matches!(a.status, AgentStatus::Cancelled | AgentStatus::Closed)
            })
            .map(|a| a.agent_id)
            .collect();
        for agent in agents {
            self.cancel_pending_spawns(&agent)?;
            self.registry.append(
                run,
                EventPayload::AgentStatusChanged {
                    agent_id: agent,
                    status: AgentStatus::Cancelled,
                    reason: Some("Run cancelled by the human".into()),
                },
            )?;
        }
        if let Some(plan) = self.registry.state().plans.get(run).cloned() {
            for (id, item) in plan.items {
                if matches!(
                    item.status,
                    PlanItemStatus::Pending | PlanItemStatus::Started
                ) {
                    self.registry.append(
                        run,
                        EventPayload::PlanItem {
                            item_id: id,
                            status: PlanItemStatus::Skipped,
                            run_id: item.run_id,
                            gate_id: item.gate_id,
                        },
                    )?;
                }
            }
        }
        let gates: Vec<_> = self
            .registry
            .state()
            .gates
            .values()
            .filter(|g| g.run_id == *run && g.status == GateStatus::Pending)
            .map(|g| g.gate_id)
            .collect();
        for gate in gates {
            // Denial is durable, but deliberately does not enter the repair dispatcher.
            let outcome = gates::begin_resolve(
                &mut self.registry,
                &gate,
                false,
                Some("Run cancelled by the human's stop request".into()),
                Actor::Socket {
                    client_name: "acp-stop".into(),
                },
                &self.roles,
            )?;
            debug_assert!(matches!(outcome, ResolveOutcome::Settled(_)));
        }
        Ok(())
    }
}
