//! A no-builder lead cannot resume another task's writer or deny its gate into a repair.
//! Provenance is injected by the MCP proxy, never accepted as a model-authored tool argument.
use super::policy::{PolicyCode, PolicyError};
use super::types::{GateKind, RoleName, RunId, RunMode};
use super::{Command, Core, CoreError};

fn refusal() -> CoreError {
    PolicyError::new(
        PolicyCode::DelegationNotAllowed,
        "this task has no builder; it cannot start or change another task's work",
    )
    .into()
}

impl Core {
    /// Read persisted intent even after a lead exits. Liveness only controls attribution, not
    /// permission: a delayed request must not gain writing authority when its lead becomes idle.
    pub(super) fn caller_without_builder(&self, caller: Option<RunId>) -> bool {
        caller
            .and_then(|id| self.registry.run(&id))
            .and_then(|run| run.execution.as_ref())
            .is_some_and(|execution| execution.mode != RunMode::Build || execution.version != 1)
    }

    pub(super) fn admit_caller_scope(&self, cmd: Command) -> Option<Command> {
        let Command::CallerScoped {
            command,
            caller_run_id,
        } = cmd
        else {
            return Some(cmd);
        };
        let cmd = *command;
        if !self.caller_without_builder(Some(caller_run_id)) {
            return Some(cmd);
        }
        match cmd {
            Command::Delegate { reply, .. } => {
                let _ = reply.send(Err(refusal()));
            }
            Command::StartPlan { reply, .. } => {
                let _ = reply.send(Err(refusal()));
            }
            Command::LeadStart { reply, .. } => {
                let _ = reply.send(Err(refusal()));
            }
            Command::SendMessage {
                agent,
                reply,
                message,
            } => {
                if self
                    .registry
                    .agent(&agent)
                    .is_some_and(|a| a.run_id == caller_run_id && a.role == RoleName::Lead)
                {
                    return Some(Command::SendMessage {
                        agent,
                        reply,
                        message,
                    });
                }
                let _ = reply.send(Err(refusal()));
            }
            Command::ResolveGate {
                gate,
                approve,
                feedback,
                by,
                reply,
            } => {
                if !approve
                    && self
                        .registry
                        .gate(&gate)
                        .is_some_and(|g| g.run_id == caller_run_id && g.kind == GateKind::Plan)
                {
                    return Some(Command::ResolveGate {
                        gate,
                        approve,
                        feedback,
                        by,
                        reply,
                    });
                }
                let _ = reply.send(Err(refusal()));
            }
            Command::CreateGate { req, reply } => {
                if req.run_id == caller_run_id && req.gate.kind == GateKind::Plan {
                    return Some(Command::CreateGate { req, reply });
                }
                let _ = reply.send(Err(refusal()));
            }
            Command::Cancel { agent, reply } => {
                if self
                    .registry
                    .agent(&agent)
                    .is_some_and(|a| a.run_id == caller_run_id)
                {
                    return Some(Command::Cancel { agent, reply });
                }
                let _ = reply.send(Err(refusal()));
            }
            other => return Some(other),
        }
        None
    }
}
