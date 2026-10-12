//! Optional security inspection, distinct from ordinary review and bound to one builder diff.
use super::*;

/// Recover the immutable input from the durable spawn intent, before later builder turns.
pub(super) fn inspection_diff(registry: &Registry, run: &RunId, agent: AgentId) -> Option<Frozen> {
    let parent = registry.agent(&agent)?.parent_agent_id?;
    let events = registry.events(run, None, usize::MAX);
    let created = events
        .iter()
        .find(|e| {
            matches!(e.payload,
        EventPayload::AgentCreated { agent_id, .. } if agent_id == agent)
        })?
        .base
        .seq;
    events
        .iter()
        .rev()
        .filter(|e| e.base.seq < created)
        .find_map(|e| match &e.payload {
            EventPayload::DiffFrozen {
                attempt_id,
                diff_path,
                diff_hash,
                files,
                ..
            } if registry
                .attempt(attempt_id)
                .is_some_and(|a| a.agent_id == parent) =>
            {
                Some(Frozen {
                    attempt: *attempt_id,
                    path: diff_path.clone(),
                    hash: diff_hash.clone(),
                    files: files.clone(),
                })
            }
            _ => None,
        })
}

pub(crate) fn current_builder_diff(registry: &Registry, run: &RunId, attempt: AttemptId) -> bool {
    registry
        .run(run)
        .and_then(|r| {
            r.agent_ids
                .iter()
                .rev()
                .filter_map(|id| registry.agent(id))
                .find(|a| a.role == RoleName::Builder)
        })
        .is_some_and(|builder| {
            builder.attempt_ids.last() == Some(&attempt)
                && registry
                    .attempt(&attempt)
                    .is_some_and(|a| a.status == AttemptStatus::Succeeded)
        })
}

fn latest_check(
    registry: &Registry,
    run: &RunId,
    builder: AttemptId,
    role: RoleName,
) -> Option<AttemptId> {
    let events = registry.events(run, None, usize::MAX);
    let agent = events.iter().rev().find_map(|e| match e.payload {
        EventPayload::AgentCreated {
            agent_id,
            role: r,
            origin: Origin::ControlPlane,
            ..
        } if r == role
            && inspection_diff(registry, run, agent_id).is_some_and(|f| f.attempt == builder) =>
        {
            registry.agent(&agent_id)
        }
        _ => None,
    })?;
    let id = *agent.attempt_ids.last()?;
    registry
        .attempt(&id)
        .filter(|a| a.status == AttemptStatus::Succeeded)
        .map(|_| id)
}

/// All selected predecessors must have durable, successful results for these exact bytes.
pub(crate) fn predecessors_passed(
    registry: &Registry,
    run: &RunId,
    builder: AttemptId,
    hash: &str,
) -> bool {
    if !current_builder_diff(registry, run, builder) {
        return false;
    }
    let steps = registry.run(run).and_then(|r| r.steps).unwrap_or_default();
    let events = registry.events(run, None, usize::MAX);
    if steps.verify {
        let Some(id) = latest_check(registry, run, builder, RoleName::Verifier) else {
            return false;
        };
        let report = registry
            .attempt(&id)
            .and_then(|a| a.structured.clone())
            .and_then(|v| serde_json::from_value::<VerifyReport>(v).ok());
        if !report.is_some_and(|r| r.diff_hash == hash && r.status != VerifyStatus::Fail)
            || !events.iter().any(|e| matches!(e.payload, EventPayload::VerifyReport { attempt_id, builder_attempt_id, status, .. }
                if attempt_id == id && builder_attempt_id == builder && status != VerifyStatus::Fail)) { return false; }
    }
    if steps.review {
        let Some(id) = latest_check(registry, run, builder, RoleName::Reviewer) else {
            return false;
        };
        if !events.iter().any(|e| matches!(&e.payload, EventPayload::ReviewVerdict {
            attempt_id, builder_attempt_id, verdict: Verdict::Pass, diff_hash, .. }
            if *attempt_id == id && *builder_attempt_id == builder && diff_hash.as_deref() == Some(hash))) { return false; }
    }
    true
}

pub(crate) fn passed_attempt(
    registry: &Registry,
    run: &RunId,
    builder_attempt: AttemptId,
    hash: &str,
) -> Option<AttemptId> {
    let builder = registry.attempt(&builder_attempt)?;
    if builder.run_id != *run || !current_builder_diff(registry, run, builder_attempt) {
        return None;
    }
    let events = registry.events(run, None, usize::MAX);
    // A newer inspection intent or attempt supersedes an old PASS, even before it has a result.
    let security = events.iter().rev().find_map(|event| match event.payload {
        EventPayload::AgentCreated {
            agent_id,
            role: RoleName::Security,
            parent_agent_id: Some(parent),
            origin: Origin::ControlPlane,
            ..
        } if parent == builder.agent_id => registry.agent(&agent_id),
        _ => None,
    })?;
    let latest = *security.attempt_ids.last()?;
    events.iter().rev().find_map(|event| {
        let EventPayload::SecurityVerdict {
            attempt_id,
            builder_attempt_id,
            verdict,
            findings,
            diff_hash,
        } = &event.payload
        else {
            return None;
        };
        if *attempt_id != latest
            || *builder_attempt_id != builder_attempt
            || diff_hash != hash
            || *verdict != Verdict::Pass
            || findings.iter().any(|f| f.severity == Severity::Blocking)
        {
            return None;
        }
        let attempt = registry.attempt(attempt_id)?;
        (attempt.status == AttemptStatus::Succeeded
            && registry
                .agent(&attempt.agent_id)
                .is_some_and(|a| a.role == RoleName::Security))
        .then_some(*attempt_id)
    })
}

impl Core {
    pub(super) fn review_role(&self, f: &Finished) -> RoleName {
        if self
            .registry
            .agent(&f.agent)
            .is_some_and(|a| a.role == RoleName::Security)
        {
            RoleName::Security
        } else {
            RoleName::Reviewer
        }
    }

    /// A failed append cannot be followed by a branch-complete marker or a gate/repair decision.
    pub(super) fn persist_security_verdict(
        &mut self,
        f: &Finished,
        frozen: &Frozen,
        verdict: &ReviewVerdict,
    ) -> bool {
        if self.registry.events(&f.run, None, usize::MAX).iter().any(|e|
            matches!(e.payload, EventPayload::SecurityVerdict { attempt_id, .. } if attempt_id == f.attempt)) {
            return true;
        }
        match self.registry.append(
            &f.run,
            EventPayload::SecurityVerdict {
                attempt_id: f.attempt,
                builder_attempt_id: frozen.attempt,
                verdict: verdict.verdict,
                findings: verdict.findings.clone(),
                diff_hash: verdict.diff_hash.clone(),
            },
        ) {
            Ok(_) => true,
            Err(error) => {
                tracing::error!(%error, "security verdict append failed; retrying before dispatch");
                false
            }
        }
    }

    /// Every route to integration goes through this test, including builder-only and verifier-only
    /// teams. A durable security spawn intent is recovered by the existing worker intent driver.
    pub(super) fn security_ready_for_gate(&mut self, f: &Finished, frozen: &Frozen) -> bool {
        if !self.run_steps(&f.run).security {
            return true;
        }
        if !predecessors_passed(&self.registry, &f.run, frozen.attempt, &frozen.hash) {
            self.block_run(
                &f.run,
                "Selected checks have not passed for this builder diff",
            );
            return false;
        }
        if passed_attempt(&self.registry, &f.run, frozen.attempt, &frozen.hash).is_some() {
            return true;
        }
        if self.workers_for(&f.run, frozen.attempt, RoleName::Security) == 0 {
            let builder = self.registry.attempt(&frozen.attempt).map(|a| a.agent_id);
            let Some(builder) = builder else {
                self.block_run(&f.run, "Security review has no recorded builder diff");
                return false;
            };
            if let Err(error) = self.start_review_role(&f.run, builder, frozen, RoleName::Security)
            {
                self.block_run(
                    &f.run,
                    &format!("Security review could not start: {}", error.reason),
                );
            }
        }
        false
    }

    pub(super) fn ordinary_review_for_diff(
        &self,
        run: &RunId,
        frozen: &Frozen,
    ) -> Option<AttemptId> {
        self.registry
            .events(run, None, usize::MAX)
            .iter()
            .rev()
            .find_map(|event| match &event.payload {
                EventPayload::ReviewVerdict {
                    attempt_id,
                    builder_attempt_id,
                    verdict: Verdict::Pass,
                    diff_hash,
                    ..
                } if *builder_attempt_id == frozen.attempt
                    && diff_hash.as_deref() == Some(frozen.hash.as_str()) =>
                {
                    Some(*attempt_id)
                }
                _ => None,
            })
    }
}

#[cfg(test)]
#[path = "security_tests.rs"]
mod tests;
