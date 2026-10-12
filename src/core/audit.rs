//! No-builder execution. Captured input is immutable; checks never enter builder repair or gates.
use super::*;
use crate::core::{
    types::{AuditCheck, AuditOutcome},
    Command,
};
use crate::workspace::git::{
    self,
    audit::{Selection, Snapshot},
};

#[derive(Debug)]
pub(crate) enum Pending {
    Capture,
    Captured(Box<Snapshot>),
    Before {
        role: RoleName,
        agent: Option<AgentId>,
    },
    After {
        attempt: AttemptId,
    },
    Blocked {
        reason: String,
        attempt: Option<AttemptId>,
    },
}

fn invalid(reason: impl Into<String>) -> CoreError {
    PolicyError::new(PolicyCode::DelegationNotAllowed, reason).into()
}

pub(super) fn validate_selection(selection: &Selection) -> Result<(), CoreError> {
    if selection.base_ref.is_empty() || selection.base_ref.len() > 256 {
        return Err(PolicyError::new(
            PolicyCode::InvalidBaseRef,
            "audit requires an explicit base ref, up to 256 bytes",
        )
        .into());
    }
    if let git::audit::Target::Revision { revision } = &selection.target {
        if revision.is_empty() || revision.len() > 256 {
            return Err(PolicyError::new(
                PolicyCode::InvalidBaseRef,
                "audit target revision must be 1–256 bytes",
            )
            .into());
        }
    }
    Ok(())
}

impl Core {
    /// Audit decisions must be durable before their dispatch marker. A failed append is retried
    /// from the same snapshot/terminal attempt; never turn it into a completed loop branch.
    fn audit_emit(&mut self, run: RunId, event: EventPayload) -> bool {
        match self.registry.append(&run, event) {
            Ok(_) => true,
            Err(error) => {
                tracing::error!(%run, %error, "audit decision append failed; retaining pending decision");
                false
            }
        }
    }

    fn block_audit(&mut self, run: RunId, reason: &str) {
        self.queue_audit_block(run, reason.to_owned(), None);
    }

    fn queue_audit_block(&mut self, run: RunId, reason: String, attempt: Option<AttemptId>) {
        self.pending_audit
            .insert(run, Pending::Blocked { reason, attempt });
        self.persist_audit_block(run);
    }

    /// Preserve the observed failure while storage is unavailable. Revalidating later could
    /// accept restored bytes and erase evidence of a check's source mutation. Status goes first:
    /// every durable prefix must stop recovery from scheduling another validation or worker.
    fn persist_audit_block(&mut self, run: RunId) {
        let Some(Pending::Blocked { reason, attempt }) = self.pending_audit.get(&run) else {
            return;
        };
        let (reason, attempt) = (reason.clone(), *attempt);
        let Some(record) = self.registry.run(&run) else {
            return;
        };
        if record.status == RunStatus::Cancelled {
            self.pending_audit.remove(&run);
            return;
        }
        if record.status != RunStatus::Blocked
            && !self.audit_emit(
                run,
                EventPayload::RunStatus_ {
                    status: RunStatus::Blocked,
                    reason: Some(reason),
                },
            )
        {
            return;
        }
        if self
            .registry
            .run(&run)
            .is_some_and(|r| r.loop_state != LoopState::Blocked)
            && !self.audit_emit(
                run,
                EventPayload::LoopStateChanged {
                    state: LoopState::Blocked,
                    builder_agent_id: None,
                    attempt_no: 0,
                    strikes: 0,
                },
            )
        {
            return;
        }
        if let Some(attempt) = attempt {
            if crate::core::loop_dispatch(&self.registry, &attempt).is_none()
                && !self.audit_emit(
                    run,
                    EventPayload::LoopDispatched {
                        attempt_id: attempt,
                        branch: LoopBranch::Audit,
                    },
                )
            {
                return;
            }
        }
        self.pending_audit.remove(&run);
    }
    pub fn start_audit(
        &mut self,
        task: Task,
        selection: Selection,
        caller: Option<RunId>,
    ) -> Result<RunId, CoreError> {
        let inherited = caller
            .and_then(|id| self.registry.run(&id))
            .and_then(|r| r.execution.clone());
        let mut execution = match inherited {
            Some(execution) => execution,
            None => {
                let team = self.valid_team()?;
                team::capture_execution(&self.roles, team.as_ref())
            }
        };
        team::from_execution(&self.roles, &execution).map_err(|issues| {
            invalid(format!(
                "recorded audit selection is unsupported: {issues:?}"
            ))
        })?;
        if execution.mode != RunMode::Audit {
            return Err(invalid(
                "audit requires explicitly selected checks and no builder",
            ));
        }
        validate_selection(&selection)?;
        if let Some(authorized) = &execution.authorized_audit_selection {
            if authorized != &selection {
                return Err(invalid("audit input differs from the human's recorded selection; start a new task to change it"));
            }
        }
        execution.audit_selection = Some(selection.clone());
        let run = RunId::new_v4();
        self.registry.append(
            &run,
            EventPayload::RunCreated {
                steps: Some(execution.steps),
                execution: Some(execution),
                repo_root: self.repo_root.clone(),
                state_dir: self.state_dir.clone(),
                base_ref: selection.base_ref.clone(),
                base_sha: String::new(),
                task,
                version: RUN_VERSION,
                lead: None,
                team_name: None,
            },
        )?;
        self.record_delegation(
            self.validated_caller_run(caller),
            run,
            None,
            DelegatedTarget::Worker,
        );
        self.pending_audit.insert(run, Pending::Capture);
        let repo = self.repo_root.clone();
        let artifact = self
            .state_dir
            .join(RUNS_DIR)
            .join(run.to_string())
            .join("audit");
        let worktree = self
            .repo_root
            .join(WORKTREES_DIR)
            .join(run.to_string())
            .join("audit");
        let branch = format!("acp/{run}/audit");
        let lock = self.supervisor.worktree_lock(&worktree);
        let tx = self.mailbox();
        tokio::spawn(async move {
            let _guard = lock.lock().await;
            let result = git::audit::capture(&repo, selection, &artifact, &worktree, &branch).await;
            let _ = tx.send(Command::AuditCaptured { run, result }).await;
        });
        Ok(run)
    }

    pub(crate) fn audit_captured(&mut self, run: RunId, result: Result<Snapshot, GitError>) {
        if !matches!(self.pending_audit.get(&run), Some(Pending::Capture)) {
            return;
        }
        self.pending_audit.remove(&run);
        if !self.audit_running(run) {
            return;
        }
        match result {
            Ok(snapshot) => {
                if !self.audit_emit(
                    run,
                    EventPayload::AuditPrepared {
                        snapshot: snapshot.clone(),
                    },
                ) {
                    self.pending_audit
                        .insert(run, Pending::Captured(Box::new(snapshot)));
                }
            }
            Err(error) => {
                self.block_audit(run, &format!("Audit input could not be captured: {error}"));
            }
        }
    }

    fn audit_running(&self, run: RunId) -> bool {
        self.registry.run(&run).is_some_and(|r| {
            r.status == RunStatus::Running
                && r.execution
                    .as_ref()
                    .is_some_and(|e| e.mode == RunMode::Audit && e.audit_selection.is_some())
        })
    }

    /// Re-drive only from recorded snapshots. A crash during initial capture blocks the task;
    /// silently capturing newer filesystem contents would change its promised input.
    pub(crate) fn drive_audits(&mut self) {
        let blocked: Vec<_> = self
            .pending_audit
            .iter()
            .filter_map(|(run, stage)| matches!(stage, Pending::Blocked { .. }).then_some(*run))
            .collect();
        for run in blocked {
            self.persist_audit_block(run);
        }
        let ready: Vec<_> = self
            .pending_audit
            .iter()
            .filter_map(|(run, stage)| match stage {
                Pending::Captured(snapshot) => Some((*run, snapshot.clone())),
                _ => None,
            })
            .collect();
        for (run, snapshot) in ready {
            if !self.audit_running(run)
                || self.audit_emit(
                    run,
                    EventPayload::AuditPrepared {
                        snapshot: *snapshot,
                    },
                )
            {
                self.pending_audit.remove(&run);
            }
        }
        let runs: Vec<_> = self
            .registry
            .runs()
            .filter(|r| self.audit_running(r.run_id))
            .map(|r| r.run_id)
            .collect();
        for run in runs {
            self.drive_audit(run);
        }
    }

    fn drive_audit(&mut self, run: RunId) {
        if self.pending_audit.contains_key(&run) {
            return;
        }
        let Some(record) = self.registry.run(&run) else {
            return;
        };
        let Some(audit) = record.audit.clone() else {
            self.block_audit(
                run,
                "Audit capture was interrupted before its snapshot was recorded; start a new audit",
            );
            return;
        };
        let steps = record
            .execution
            .as_ref()
            .expect("audit_running checked execution")
            .steps;
        if audit
            .checks
            .iter()
            .any(|check| check.outcome == AuditOutcome::Fail)
        {
            self.finish_audit(
                run,
                RunStatus::Failed,
                "A selected audit check failed; no changes were integrated",
            );
            return;
        }
        let next = [
            (RoleName::Verifier, steps.verify),
            (RoleName::Reviewer, steps.review),
            (RoleName::Security, steps.security),
        ]
        .into_iter()
        .find(|(role, enabled)| *enabled && !audit.checks.iter().any(|check| check.role == *role));
        let Some((role, _)) = next.filter(|_| !audit.snapshot.files.is_empty()) else {
            let reason = if audit.snapshot.files.is_empty() {
                "No change to inspect; checks were not run"
            } else {
                "Audit finished; selected check results are recorded and no changes were integrated"
            };
            self.finish_audit(run, RunStatus::Completed, reason);
            return;
        };
        let agent = record
            .agent_ids
            .iter()
            .filter_map(|id| self.registry.agent(id))
            .find(|agent| agent.role == role);
        if agent.is_some_and(|a| matches!(a.status, AgentStatus::Cancelled | AgentStatus::Closed)) {
            self.finish_audit(
                run,
                RunStatus::Cancelled,
                "The selected audit check was cancelled; no further checks ran",
            );
            return;
        }
        // Running or terminal attempts belong to supervision / after-attempt validation. A
        // recorded agent without an attempt is a spawn intent recovered with the same identity.
        if agent.is_some_and(|a| {
            !a.attempt_ids.is_empty()
                || self
                    .pending_spawn
                    .values()
                    .any(|pending| pending.agent() == a.agent_id)
        }) {
            return;
        }
        let agent = agent.map(|a| a.agent_id);
        self.validate_audit(run, audit.snapshot, Pending::Before { role, agent });
    }

    fn finish_audit(&mut self, run: RunId, status: RunStatus, reason: &str) {
        if self.audit_emit(
            run,
            EventPayload::LoopStateChanged {
                state: LoopState::Done,
                builder_agent_id: None,
                attempt_no: 0,
                strikes: 0,
            },
        ) {
            self.audit_emit(
                run,
                EventPayload::RunStatus_ {
                    status,
                    reason: Some(reason.into()),
                },
            );
        }
    }

    fn validate_audit(&mut self, run: RunId, snapshot: Snapshot, stage: Pending) {
        self.pending_audit.insert(run, stage);
        let lock = self.supervisor.worktree_lock(&snapshot.worktree);
        let tx = self.mailbox();
        tokio::spawn(async move {
            let _guard = lock.lock().await;
            let result = git::audit::validate(&snapshot).await;
            let _ = tx.send(Command::AuditValidated { run, result }).await;
        });
    }

    pub(crate) fn audit_attempt_finished(&mut self, attempt: AttemptId) {
        let Some(a) = self.registry.attempt(&attempt) else {
            return;
        };
        let run = a.run_id;
        if !is_terminal(a.status)
            || self.pending_audit.contains_key(&run)
            || crate::core::loop_dispatch(&self.registry, &attempt).is_some()
        {
            return;
        }
        let Some(audit) = self.registry.run(&run).and_then(|r| r.audit.as_ref()) else {
            return;
        };
        if audit.checks.iter().any(|check| check.attempt_id == attempt) {
            self.audit_emit(
                run,
                EventPayload::LoopDispatched {
                    attempt_id: attempt,
                    branch: LoopBranch::Audit,
                },
            );
            return;
        }
        if !self.audit_running(run) {
            if self
                .registry
                .run(&run)
                .is_some_and(|r| r.status == RunStatus::Blocked)
            {
                let reason = self
                    .registry
                    .run(&run)
                    .and_then(|r| r.blocked_reason.clone())
                    .unwrap_or_else(|| "Audit blocked before its result was recorded".into());
                self.queue_audit_block(run, reason, Some(attempt));
            }
            return;
        }
        self.validate_audit(run, audit.snapshot.clone(), Pending::After { attempt });
    }

    pub(crate) fn audit_validated(&mut self, run: RunId, result: Result<(), GitError>) {
        if !matches!(
            self.pending_audit.get(&run),
            Some(Pending::Before { .. } | Pending::After { .. })
        ) {
            return;
        }
        let Some(stage) = self.pending_audit.remove(&run) else {
            return;
        };
        if !self.audit_running(run) {
            return;
        }
        if let Err(error) = result {
            let attempt = if let Pending::After { attempt } = stage {
                Some(attempt)
            } else {
                None
            };
            self.queue_audit_block(
                run,
                format!("Audit snapshot validation failed: {error}"),
                attempt,
            );
            return;
        }
        match stage {
            Pending::Before { role, agent } => {
                if let Err(error) = self.start_audit_check(run, role, agent) {
                    self.block_audit(
                        run,
                        &format!("Audit check could not start: {}", error.reason),
                    );
                }
            }
            Pending::After { attempt } => {
                let Some(check) = self.audit_check_result(run, attempt) else {
                    self.block_audit(run, "Audit result lost its attempt or snapshot identity");
                    return;
                };
                if !self.audit_emit(run, EventPayload::AuditChecked { check }) {
                    return;
                }
                self.drive_audit(run);
                self.audit_emit(
                    run,
                    EventPayload::LoopDispatched {
                        attempt_id: attempt,
                        branch: LoopBranch::Audit,
                    },
                );
            }
            Pending::Capture | Pending::Captured(_) | Pending::Blocked { .. } => {
                unreachable!("validated stage checked above")
            }
        }
    }

    fn start_audit_check(
        &mut self,
        run: RunId,
        role: RoleName,
        existing: Option<AgentId>,
    ) -> Result<(), PolicyError> {
        if existing.is_some_and(|id| {
            self.registry
                .agent(&id)
                .is_none_or(|a| matches!(a.status, AgentStatus::Cancelled | AgentStatus::Closed))
        }) {
            return Err(PolicyError::new(
                PolicyCode::RunBlocked,
                "a cancelled or closed audit check cannot restart",
            ));
        }
        let record = self.registry.run(&run).expect("audit_running checked run");
        let task = record.task.clone();
        let snapshot = record
            .audit
            .as_ref()
            .expect("validation requires snapshot")
            .snapshot
            .clone();
        let req = DelegateRequest {
            run_id: Some(run),
            role,
            task: task.clone(),
            model: None,
            session: SessionSpec::Fresh,
            base_ref: Some(snapshot.base_sha.clone()),
            worktree: None,
            steps: None,
            caller_run_id: None,
        };
        let resolved = self.resolve_internal(&req)?;
        let agent = existing.unwrap_or_else(AgentId::new_v4);
        if existing.is_none() {
            self.registry
                .append(
                    &run,
                    EventPayload::AgentCreated {
                        agent_id: agent,
                        role,
                        provider: resolved.provider,
                        model: resolved.model.clone(),
                        lineage_id: None,
                        depth: resolved.depth,
                        parent_agent_id: None,
                        origin: Origin::ControlPlane,
                        writes: false,
                        cwd: snapshot.worktree.clone(),
                        worktree: None,
                    },
                )
                .map_err(|error| PolicyError::new(PolicyCode::RunBlocked, error.to_string()))?;
        }
        let prompt = match role {
            RoleName::Verifier => handoff::build_verifier_prompt(
                &task,
                &snapshot.diff_path,
                &snapshot.diff_hash,
                None,
            ),
            RoleName::Reviewer | RoleName::Security => handoff::build_reviewer_prompt(
                &task,
                &snapshot.diff_path,
                &snapshot.diff_hash,
                None,
                None,
            ),
            _ => {
                return Err(PolicyError::new(
                    PolicyCode::DelegationNotAllowed,
                    "only selected checks can run in an audit",
                ))
            }
        };
        let prompt = format!("This is a no-builder audit of existing work in an isolated snapshot. No builder produced it. Do not edit tracked source, stage, commit or repair findings. Report only what you actually checked.\n\n{prompt}");
        let spawn = self
            .spawn_for_agent(&agent, AttemptId::new_v4(), prompt)
            .ok_or_else(|| {
                PolicyError::new(
                    PolicyCode::RunBlocked,
                    "audit check has no recorded spawn configuration",
                )
            })?;
        self.start_attempt(spawn)
    }

    fn audit_check_result(&self, run: RunId, attempt: AttemptId) -> Option<AuditCheck> {
        let a = self.registry.attempt(&attempt)?;
        let role = self.registry.agent(&a.agent_id)?.role;
        let hash = self
            .registry
            .run(&run)?
            .audit
            .as_ref()?
            .snapshot
            .diff_hash
            .clone();
        let mut check = AuditCheck {
            attempt_id: attempt,
            role,
            diff_hash: hash.clone(),
            outcome: AuditOutcome::Fail,
            summary: "The check did not return a valid result bound to this snapshot".into(),
        };
        if a.status != AttemptStatus::Succeeded {
            return Some(check);
        }
        match (role, a.structured.clone()) {
            (RoleName::Verifier, Some(value)) => {
                if let Ok(report) = serde_json::from_value::<VerifyReport>(value) {
                    if report.diff_hash == hash {
                        check.outcome = match report.status {
                            VerifyStatus::Pass => AuditOutcome::Pass,
                            VerifyStatus::Fail => AuditOutcome::Fail,
                            VerifyStatus::NothingToRun => AuditOutcome::NothingToRun,
                        };
                        check.summary = clamp_untrusted(&report.summary, 4000);
                    }
                }
            }
            (RoleName::Reviewer | RoleName::Security, Some(value)) => {
                if let Ok(report) = serde_json::from_value::<ReviewVerdict>(value) {
                    if report.diff_hash == hash {
                        let blocking = role == RoleName::Security && report.findings.iter().any(|f| f.severity == Severity::Blocking);
                        check.outcome = if report.verdict == Verdict::Pass && !blocking {
                            AuditOutcome::Pass
                        } else {
                            AuditOutcome::Fail
                        };
                        check.summary = format!(
                            "{} {:?}; {} finding(s)",
                            if role == RoleName::Security { "Security review" } else { "Code review" },
                            check.outcome,
                            report.findings.len()
                        );
                    }
                }
            }
            _ => {}
        }
        Some(check)
    }
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
