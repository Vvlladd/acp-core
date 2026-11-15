//! Bounded inventory and human-confirmed retirement of completed ACP worktrees.
//!
//! Eligibility is revalidated by the actor. Slow Git/filesystem work runs under the same
//! per-worktree mutex used by workers and integration.

use std::collections::HashMap;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::policy::{PolicyCode, PolicyError};
use super::types::*;
use super::{Command, Core, CoreError, Reply};
use crate::workspace::git::{self, GitError, RetirementTicket};

pub const MAX_INVENTORY: usize = 128;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    Retained,
    Eligible,
    Stale,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub repo_root: PathBuf,
    pub run_id: RunId,
    pub lineage_id: LineageId,
    pub seq: u64,
    pub worktree: PathBuf,
    pub branch: Option<String>,
    pub integrated_sha: Option<String>,
    pub disposition: Disposition,
    pub reason: String,
    pub retired: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_token: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    pub items: Vec<Item>,
    pub truncated: bool,
}

/// Optional narrowing is applied before the inventory bound. This lets a caller name a run or
/// lineage that falls beyond the first unfiltered page without changing the stable, bounded
/// unfiltered response.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InventoryQuery {
    #[serde(default)]
    pub run_id: Option<RunId>,
    #[serde(default)]
    pub lineage_id: Option<LineageId>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub request_id: Uuid,
    pub run_id: RunId,
    pub lineage_id: LineageId,
    pub expected_seq: u64,
    pub worktree: PathBuf,
    pub branch: String,
    pub integrated_sha: String,
    pub preview_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub request_id: Uuid,
    pub run_id: RunId,
    pub lineage_id: LineageId,
    pub worktree: PathBuf,
    pub preserved_ref: String,
    pub restore_path: PathBuf,
    pub disk_space_reclaimed: bool,
    pub removed: bool,
    pub already_retired: bool,
}

pub(crate) type Prepared = (
    String,
    bool,
    Option<RetirementTicket>,
    tokio::sync::OwnedMutexGuard<()>,
);

fn refuse(reason: impl Into<String>) -> CoreError {
    PolicyError::new(PolicyCode::RecoveryUnavailable, reason).into()
}

fn preview_token(repo: &std::path::Path, request: &Request, checkout: &git::PreviewCheckout) -> String {
    let mut hash = Sha256::new();
    for field in [
        repo.as_os_str().as_bytes(),
        request.run_id.to_string().as_bytes(),
        request.lineage_id.to_string().as_bytes(),
        request.expected_seq.to_string().as_bytes(),
        request.worktree.as_os_str().as_bytes(),
        request.branch.as_bytes(),
        request.integrated_sha.as_bytes(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.update(serde_json::to_vec(checkout).expect("checkout identity contains only integers"));
    let digest = hash.finalize();
    let encoded: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("v2.{}.{}", request.expected_seq, encoded)
}

impl Core {
    fn retirement_run_busy(&self, run: &Run) -> bool {
        let id = run.run_id;
        self.supervisor.owns_work_for_run(id)
            || self
                .pending_worktree
                .values()
                .any(|pending| pending.run() == id)
            || self
                .pending_spawn
                .values()
                .any(|pending| pending.run_id() == id)
            || self
                .pending_retry
                .keys()
                .any(|agent| run.agent_ids.contains(agent))
            || self.pending_audit.contains_key(&id)
            || self.in_flight.iter().any(|attempt| {
                self.registry
                    .attempt(attempt)
                    .is_some_and(|attempt| attempt.run_id == id)
            })
            || run
                .gate_ids
                .iter()
                .any(|gate| self.gate_waiters.contains_key(gate))
            || self
                .settled
                .iter()
                .any(|(gate, _)| run.gate_ids.contains(gate))
            || self.registry.retention_run_has_running_attempt(&id)
    }

    pub fn retention_inventory(&self, query: &InventoryQuery) -> Inventory {
        let mut items = Vec::new();
        let (lineages, truncated) = self.registry.retention_lineages(
            query.run_id,
            query.lineage_id,
            MAX_INVENTORY,
        );
        let mut finalizing_by_run = HashMap::new();
        for recorded in lineages {
            let Some(run) = self.registry.run(&recorded.run_id) else {
                continue;
            };
            let finalizing = *finalizing_by_run
                .entry(run.run_id)
                .or_insert_with(|| self.retirement_run_busy(run));
            let Some(lineage) = run
                .lineages
                .iter()
                .find(|lineage| lineage.lineage_id == recorded.lineage_id)
            else {
                continue;
            };
                let created = recorded.branch.clone();
                let retired = self
                    .registry
                    .retention_retired(&run.run_id, &recorded.worktree);
                let public_exists = lineage.worktree.exists();
                let handoff_planned = git::retirement_handoff_planned(
                    &self.state_dir,
                    &run.repo_root,
                    &run.run_id.to_string(),
                    &lineage.lineage_id.to_string(),
                )
                .is_ok();
                let resolving = self.registry.retention_gate_is_resolving(&run.run_id);
                let integrated_here = run.integrated_sha.as_ref().is_some_and(|sha| {
                    self.registry
                        .retention_integrated(&run.run_id, &recorded.worktree, sha)
                });
                let running = self
                    .registry
                    .retention_lineage_is_live(&run.run_id, &lineage.lineage_id);
                let (disposition, reason) = if created.is_none() {
                    (
                        Disposition::Unavailable,
                        "the lineage has no matching durable ACP ownership record".into(),
                    )
                } else if retired && !public_exists && !handoff_planned {
                    (
                        Disposition::Stale,
                        "the retired worktree cleanup receipt is missing or invalid".into(),
                    )
                } else if !public_exists && !retired {
                    (
                        Disposition::Stale,
                        "the registered ACP path is missing; no cleanup will inspect another path"
                            .into(),
                    )
                } else if run.loop_state == LoopState::Reviewing {
                    (
                        Disposition::Retained,
                        "review is still in progress and the worktree remains resumable".into(),
                    )
                } else if run.status != RunStatus::Integrated || run.integrated_sha.is_none() {
                    (
                        Disposition::Retained,
                        format!("the run is {:?} and remains recoverable", run.status)
                            .to_lowercase(),
                    )
                } else if run.loop_state != LoopState::Done {
                    (
                        Disposition::Retained,
                        "the task lifecycle has not reached its completed state".into(),
                    )
                } else if !integrated_here {
                    (
                        Disposition::Retained,
                        "this lineage was not the worktree used for the recorded integration"
                            .into(),
                    )
                } else if running {
                    (
                        Disposition::Retained,
                        "an agent is still starting or running in the worktree".into(),
                    )
                } else if resolving || finalizing {
                    (
                        Disposition::Retained,
                        "integration or attempt finalization is still in progress".into(),
                    )
                } else if retired {
                    (
                        Disposition::Eligible,
                        if handoff_planned {
                            "retirement is recorded; cleanup can resume or verify its recoverable Trash item".into()
                        } else {
                            "retirement is recorded; confirmation will revalidate the still-registered clean tree".into()
                        },
                    )
                } else {
                    (Disposition::Eligible, "completed integration is recorded; confirmation will run exact ownership and content checks".into())
                };
                let token_request = match (&created, &run.integrated_sha) {
                    (Some(branch), Some(integrated_sha))
                        if disposition == Disposition::Eligible =>
                    {
                        Some(Request {
                            request_id: Uuid::nil(),
                            run_id: run.run_id,
                            lineage_id: lineage.lineage_id,
                            expected_seq: run.last_seq,
                            worktree: lineage.worktree.clone(),
                            branch: branch.clone(),
                            integrated_sha: integrated_sha.clone(),
                            preview_token: String::new(),
                        })
                    }
                    _ => None,
                };
                items.push(Item {
                    repo_root: run.repo_root.clone(),
                    run_id: run.run_id,
                    lineage_id: lineage.lineage_id,
                    seq: run.last_seq,
                    worktree: lineage.worktree.clone(),
                    branch: created,
                    integrated_sha: run.integrated_sha.clone(),
                    disposition,
                    reason,
                    retired,
                    confirmation_token: token_request
                        .as_ref()
                        .and_then(|request| git::PreviewCheckout::capture(&request.worktree).ok()
                            .map(|checkout| preview_token(&run.repo_root, request, &checkout))),
                });
        }
        Inventory { items, truncated }
    }

    pub(crate) fn validate_retirement(&self, request: &Request) -> Result<bool, CoreError> {
        let run = self
            .registry
            .run(&request.run_id)
            .ok_or_else(|| refuse("This task is no longer available."))?;
        let lineage = run
            .lineages
            .iter()
            .find(|lineage| lineage.lineage_id == request.lineage_id)
            .ok_or_else(|| refuse("The recorded lineage is no longer available."))?;
        if lineage.worktree != request.worktree {
            return Err(refuse("The worktree identity changed; request a fresh preview."));
        }
        let checkout = git::PreviewCheckout::capture(&lineage.worktree)
            .map_err(|e| refuse(format!("Could not identify the worktree for the original preview: {e}")))?;
        if request.preview_token != preview_token(&run.repo_root, request, &checkout) {
            return Err(refuse("The confirmation value does not match that exact preview; request a fresh preview."));
        }
        if run.last_seq != request.expected_seq {
            return Err(refuse(
                "The task changed after preview; refresh the worktree inventory.",
            ));
        }
        if run.status != RunStatus::Integrated
            || run.integrated_sha.as_deref() != Some(&request.integrated_sha)
        {
            return Err(refuse(
                "Only a completed integrated task can be cleaned up.",
            ));
        }
        if run.loop_state != LoopState::Done {
            return Err(refuse(
                "The task lifecycle has not reached its completed state.",
            ));
        }
        if self.retirement_run_busy(run) {
            return Err(refuse("Preparation, work, or finalization is still in progress; refresh when it finishes."));
        }
        if self.registry.retention_gate_is_resolving(&run.run_id) {
            return Err(refuse(
                "Integration finalization is still in progress; refresh when it finishes.",
            ));
        }
        let owned = self
            .registry
            .retention_lineages(Some(request.run_id), Some(request.lineage_id), 1)
            .0
            .first()
            .is_some_and(|lineage| {
                lineage.worktree == request.worktree
                    && lineage.branch.as_deref() == Some(request.branch.as_str())
            });
        if !owned {
            return Err(refuse(
                "The path and branch have no matching durable ACP ownership record.",
            ));
        }
        if self
            .registry
            .retention_lineage_is_live(&run.run_id, &lineage.lineage_id)
        {
            return Err(refuse(
                "An agent is still starting or running in this worktree.",
            ));
        }
        if !self.registry.retention_integrated(
            &request.run_id,
            &request.worktree,
            &request.integrated_sha,
        ) {
            return Err(refuse(
                "The integrated commit is not durably recorded for this exact worktree.",
            ));
        }
        let retired = self
            .registry
            .retention_retired(&request.run_id, &request.worktree);
        // While the registered tree is still present, prepare_retirement can revalidate its exact
        // inode, Git registration, branch, integrated SHA, cleanliness, and durable identity. A
        // handoff plan becomes mandatory only after the public path has moved or disappeared.
        if retired && !request.worktree.exists() {
            git::retirement_handoff_planned(
                &self.state_dir,
                &run.repo_root,
                &run.run_id.to_string(),
                &lineage.lineage_id.to_string(),
            )
            .map_err(|error| {
                refuse(format!(
                    "The retired worktree cleanup receipt is unavailable: {error}"
                ))
            })?;
        }
        Ok(retired)
    }

    pub(crate) fn begin_retirement(
        &mut self,
        request: Request,
        by: Actor,
        reply: Reply<Outcome>,
    ) -> Result<(), (Reply<Outcome>, CoreError)> {
        if matches!(by, Actor::Mcp) {
            return Err((reply, refuse("Agents cannot confirm worktree cleanup.")));
        }
        if self.lifecycle.cancelling() {
            return Err((reply, refuse("Cancellation is still in progress.")));
        }
        let already_retired = match self.validate_retirement(&request) {
            Ok(value) => value,
            Err(error) => return Err((reply, error)),
        };
        if self.retention_waiters.contains_key(&request.request_id) {
            return Err((
                reply,
                refuse("This cleanup request is already in progress."),
            ));
        }
        let repo = self
            .registry
            .run(&request.run_id)
            .expect("validated run")
            .repo_root
            .clone();
        let state_dir = self.state_dir.clone();
        let lock = self.supervisor.worktree_lock(&request.worktree);
        self.retention_waiters.insert(request.request_id, reply);
        let tx = self.tx.clone();
        let sent = request.clone();
        tokio::spawn(async move {
            let guard = lock.lock_owned().await;
            let checkout = git::PreviewCheckout::capture(&sent.worktree);
            let previewed = checkout.as_ref().is_ok_and(|observed|
                sent.preview_token == preview_token(&repo, &sent, observed));
            let preserved = format!("refs/acp/retained/{}/{}", sent.run_id, sent.lineage_id);
            let result = if !previewed {
                Err(GitError::RecoveryInvalid { reason: "the worktree changed after preview; request a fresh preview".into() })
            } else if already_retired && matches!(checkout, Ok(git::PreviewCheckout::Absent)) {
                Ok((preserved, false, None, guard))
            } else {
                git::prepare_previewed_retirement(
                    &repo,
                    &sent.worktree,
                    &sent.integrated_sha,
                    &sent.branch,
                    &state_dir,
                    git::RetirementTarget::new(&sent.run_id.to_string(), &sent.lineage_id.to_string()),
                    &checkout.expect("matched preview"),
                )
                .await
                .map(|ticket| (ticket.preserved_ref.clone(), false, Some(ticket), guard))
            };
            let _ = tx
                .send(Command::RetirementPrepared {
                    request: sent,
                    already_retired,
                    result,
                })
                .await;
        });
        Ok(())
    }

    pub(crate) fn retirement_prepared(
        &mut self,
        request: Request,
        already_retired: bool,
        result: Result<Prepared, GitError>,
    ) {
        let (preserved_ref, complete, ticket, guard) = match result {
            Ok(value) => value,
            Err(error) => return self.finish_retirement_error(request.request_id, error.into()),
        };
        if let Err(error) = self.validate_retirement(&request) {
            return self.finish_retirement_error(request.request_id, error);
        }
        if complete {
            drop(guard);
            return self.finish_retirement_success(
                request,
                preserved_ref,
                None,
                false,
                false,
                true,
            );
        }
        let lineage = self
            .registry
            .run(&request.run_id)
            .expect("validated run")
            .lineages
            .iter()
            .find(|lineage| lineage.lineage_id == request.lineage_id)
            .expect("validated lineage");
        if !lineage.closed {
            if let Err(error) = self.registry.append(
                &request.run_id,
                EventPayload::LineageClosed {
                    lineage_id: request.lineage_id,
                    reason: "human-confirmed cleanup after completed integration".into(),
                },
            ) {
                return self.finish_retirement_error(request.request_id, error.into());
            }
        }
        if !already_retired {
            if let Err(error) = self.registry.append(&request.run_id, EventPayload::WorktreeRetired {
                path: request.worktree.clone(),
                reason: "human-confirmed cleanup after completed integration; commit preserved by a refs/acp/retained ref".into(),
                resumable: False,
            }) { return self.finish_retirement_error(request.request_id, error.into()); }
        }
        let repo = self
            .registry
            .run(&request.run_id)
            .expect("validated run")
            .repo_root
            .clone();
        let state_dir = self.state_dir.clone();
        let tx = self.tx.clone();
        let sent = request.clone();
        tokio::spawn(async move {
            let result = git::quarantine_and_remove_worktree(
                &repo,
                &sent.worktree,
                &sent.integrated_sha,
                &state_dir,
                &sent.branch,
                git::RetirementTarget::new(&sent.run_id.to_string(), &sent.lineage_id.to_string()),
                ticket,
            )
            .await;
            drop(guard);
            let _ = tx
                .send(Command::RetirementRemoved {
                    request: sent,
                    already_retired,
                    preserved_ref,
                    result,
                })
                .await;
        });
    }

    pub(crate) fn retirement_removed(
        &mut self,
        request: Request,
        already_retired: bool,
        _preserved_ref: String,
        result: Result<git::RetirementResult, GitError>,
    ) {
        match result {
            Ok(result) => self.finish_retirement_success(
                request,
                result.preserved_ref,
                Some(result.restore_path),
                result.disk_space_reclaimed,
                true,
                already_retired,
            ),
            Err(error) => self.finish_retirement_error(request.request_id, error.into()),
        }
    }

    fn finish_retirement_success(
        &mut self,
        request: Request,
        preserved_ref: String,
        restore_path: Option<PathBuf>,
        disk_space_reclaimed: bool,
        removed: bool,
        already_retired: bool,
    ) {
        if let Some(reply) = self.retention_waiters.remove(&request.request_id) {
            let _ = reply.send(Ok(Outcome {
                request_id: request.request_id,
                run_id: request.run_id,
                lineage_id: request.lineage_id,
                worktree: request.worktree,
                restore_path: restore_path.unwrap_or_default(),
                preserved_ref,
                disk_space_reclaimed,
                removed,
                already_retired,
            }));
        }
    }

    fn finish_retirement_error(&mut self, request_id: Uuid, error: CoreError) {
        if let Some(reply) = self.retention_waiters.remove(&request_id) {
            let _ = reply.send(Err(error));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::registry::Registry;
    use crate::core::supervisor::{PsProbe, Supervisor};
    use crate::roles::loader::load_roles;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::sync::mpsc;

    struct Seed {
        run: RunId,
        lineage: LineageId,
        agent: AgentId,
        path: PathBuf,
        branch: String,
        sha: String,
    }

    fn core(dir: &TempDir) -> Core {
        let (tx, _rx) = mpsc::channel(super::super::MAILBOX_CAPACITY);
        let (signals, _signal_rx) = mpsc::channel(8);
        Core::new(
            Registry::open(dir.path()).expect("registry"),
            Supervisor::new(Duration::from_millis(25), Arc::new(PsProbe), signals),
            load_roles(None).expect("roles"),
            dir.path().join("repo"),
            dir.path().to_path_buf(),
            tx,
        )
    }

    fn seed(core: &mut Core, name: &str, path_exists: bool) -> Seed {
        let run = RunId::new_v4();
        let lineage = LineageId::new_v4();
        let agent = AgentId::new_v4();
        let path = core.repo_root.join(".acp/worktrees").join(name);
        if path_exists {
            std::fs::create_dir_all(&path).expect("worktree fixture");
        }
        let branch = format!("acp/{run}/{lineage}");
        let sha = "a".repeat(40);
        core.registry
            .append(
                &run,
                EventPayload::RunCreated {
                    execution: None,
                    repo_root: core.repo_root.clone(),
                    state_dir: core.state_dir.clone(),
                    base_ref: "HEAD".into(),
                    base_sha: sha.clone(),
                    task: Task {
                        id: name.into(),
                        title: name.into(),
                        description: "fixture".into(),
                        files: vec![],
                        acceptance: vec![],
                        evidence: None,
                    },
                    version: 1,
                    lead: None,
                    team_name: None,
                    steps: None,
                    run_budget_usd: None,
                },
            )
            .expect("run");
        core.registry
            .append(
                &run,
                EventPayload::AgentCreated {
                    agent_id: agent,
                    role: RoleName::Builder,
                    provider: ProviderName::Claude,
                    model: "sonnet".into(),
                    lineage_id: Some(lineage),
                    depth: 1,
                    parent_agent_id: None,
                    origin: Origin::Lead,
                    writes: true,
                    cwd: path.clone(),
                    worktree: Some(path.clone()),
                },
            )
            .expect("agent");
        core.registry
            .append(
                &run,
                EventPayload::WorktreeCreated {
                    agent_id: agent,
                    lineage_id: lineage,
                    path: path.clone(),
                    branch: branch.clone(),
                    base_sha: sha.clone(),
                },
            )
            .expect("worktree");
        core.registry
            .append(
                &run,
                EventPayload::AgentStatusChanged {
                    agent_id: agent,
                    status: AgentStatus::Idle,
                    reason: None,
                },
            )
            .expect("idle");
        Seed {
            run,
            lineage,
            agent,
            path,
            branch,
            sha,
        }
    }

    fn integrate(core: &mut Core, seed: &Seed) {
        core.registry
            .append(
                &seed.run,
                EventPayload::IntegrateCommitted {
                    gate_id: GateId::new_v4(),
                    worktree: seed.path.clone(),
                    sha: seed.sha.clone(),
                    subject: "integrated fixture".into(),
                    files: vec![],
                },
            )
            .expect("commit");
        core.registry
            .append(
                &seed.run,
                EventPayload::RunStatus_ {
                    status: RunStatus::Integrated,
                    reason: None,
                },
            )
            .expect("integrated");
        core.registry
            .append(
                &seed.run,
                EventPayload::LoopStateChanged {
                    state: LoopState::Done,
                    builder_agent_id: Some(seed.agent),
                    attempt_no: 1,
                    strikes: 0,
                },
            )
            .expect("done");
    }

    fn request(core: &Core, seed: &Seed) -> Request {
        let mut request = Request {
            request_id: Uuid::new_v4(),
            run_id: seed.run,
            lineage_id: seed.lineage,
            expected_seq: core.registry.run(&seed.run).expect("run").last_seq,
            worktree: seed.path.clone(),
            branch: seed.branch.clone(),
            integrated_sha: seed.sha.clone(),
            preview_token: String::new(),
        };
        request.preview_token = preview_token(&core.repo_root, &request, &git::PreviewCheckout::capture(&request.worktree).unwrap());
        request
    }

    #[test]
    fn safe_stop_waits_for_a_retirement_even_after_the_client_disconnects() {
        use crate::core::lifecycle::{Request as LifecycleRequest, StopMode};
        use tokio_util::sync::CancellationToken;

        let dir = TempDir::new().expect("temporary repository");
        let mut core = core(&dir);
        let selected = seed(&mut core, "finished", true);
        integrate(&mut core, &selected);
        let shutdown = CancellationToken::new();
        core.lifecycle.configure(false, shutdown.clone());
        let now = std::time::Instant::now();
        let request_id = Uuid::new_v4();
        let (reply, receiver) = tokio::sync::oneshot::channel();
        core.retention_waiters.insert(request_id, reply);
        drop(receiver);

        let reasons = core.lifecycle_busy_reasons();
        core.lifecycle.request(LifecycleRequest::Stop { mode: StopMode::WhenIdle }, reasons, now)
            .expect("safe stop requested");
        core.lifecycle.tick(!core.lifecycle_busy_reasons().is_empty(), now);
        assert!(!shutdown.is_cancelled(), "safe stop interrupted a retirement handoff");
        core.finish_retirement_error(request_id, refuse("fixture handoff finished"));
        core.lifecycle.tick(!core.lifecycle_busy_reasons().is_empty(), now);
        assert!(shutdown.is_cancelled(), "shutdown can finish after the helper reports back");
    }

    #[test]
    fn inventory_explains_recoverable_active_finalizing_and_stale_trees() {
        let dir = TempDir::new().expect("tempdir");
        let mut core = core(&dir);
        let draft = seed(&mut core, "draft", true);
        let stale = seed(&mut core, "stale", false);
        let review = seed(&mut core, "review", true);
        core.registry
            .append(
                &review.run,
                EventPayload::LoopStateChanged {
                    state: LoopState::Reviewing,
                    builder_agent_id: Some(review.agent),
                    attempt_no: 1,
                    strikes: 0,
                },
            )
            .expect("reviewing");
        let active = seed(&mut core, "active", true);
        integrate(&mut core, &active);
        core.registry
            .append(
                &active.run,
                EventPayload::AgentStatusChanged {
                    agent_id: active.agent,
                    status: AgentStatus::Running,
                    reason: None,
                },
            )
            .expect("active");
        let finalizing = seed(&mut core, "finalizing", true);
        integrate(&mut core, &finalizing);
        let gate = GateId::new_v4();
        core.registry
            .append(
                &finalizing.run,
                EventPayload::GateCreated {
                    gate_id: gate,
                    gate_kind: GateKind::Integrate,
                    summary: "finishing".into(),
                    payload_path: dir.path().join("gate.json"),
                    repair_binding: None,
                    requested_by: Origin::Lead,
                },
            )
            .expect("gate");
        core.registry
            .append(
                &finalizing.run,
                EventPayload::GateResolving {
                    gate_id: gate,
                    approve: true,
                    feedback: None,
                    by: Actor::Socket {
                        client_name: "cli".into(),
                    },
                    commit: None,
                    external_verification: None,
                },
            )
            .expect("resolving");

        let inventory = core.retention_inventory(&InventoryQuery::default());
        let item = |run| {
            inventory
                .items
                .iter()
                .find(|item| item.run_id == run)
                .expect("item")
        };
        assert_eq!(item(draft.run).disposition, Disposition::Retained);
        assert!(item(draft.run).reason.contains("recoverable"));
        assert_eq!(item(stale.run).disposition, Disposition::Stale);
        assert_eq!(item(review.run).disposition, Disposition::Retained);
        assert!(item(review.run).reason.contains("review"));
        assert_eq!(item(active.run).disposition, Disposition::Retained);
        assert!(item(active.run).reason.contains("running"));
        assert_eq!(item(finalizing.run).disposition, Disposition::Retained);
        assert!(item(finalizing.run).reason.contains("finalization"));
    }

    #[test]
    fn scoped_inventory_applies_its_bound_after_selecting_the_requested_run_or_lineage() {
        let dir = TempDir::new().expect("tempdir");
        let mut core = core(&dir);
        let mut target = None;
        for index in 0..=MAX_INVENTORY {
            let seeded = seed(&mut core, &format!("inventory-{index}"), true);
            integrate(&mut core, &seeded);
            if index == MAX_INVENTORY {
                target = Some(seeded);
            }
        }
        let target = target.expect("target beyond an unfiltered page");
        let unfiltered = core.retention_inventory(&InventoryQuery::default());
        assert_eq!(unfiltered.items.len(), MAX_INVENTORY);
        assert!(unfiltered.truncated);

        let by_run = core.retention_inventory(&InventoryQuery {
            run_id: Some(target.run),
            lineage_id: None,
        });
        assert_eq!(by_run.items.len(), 1);
        assert_eq!(by_run.items[0].run_id, target.run);
        assert!(!by_run.truncated);
        assert_eq!(by_run.items[0].disposition, Disposition::Eligible);

        let by_lineage = core.retention_inventory(&InventoryQuery {
            run_id: None,
            lineage_id: Some(target.lineage),
        });
        assert_eq!(by_lineage.items.len(), 1);
        assert_eq!(by_lineage.items[0].lineage_id, target.lineage);
        assert!(!by_lineage.truncated);
    }

    #[test]
    fn global_page_counts_only_recorded_worktrees_and_uses_one_extra_item() {
        let dir = TempDir::new().expect("tempdir");
        let mut active = core(&dir);
        for index in 0..64 {
            let run = RunId::new_v4();
            active.registry
                .append(
                    &run,
                    EventPayload::RunCreated {
                        execution: None,
                        repo_root: active.repo_root.clone(),
                        state_dir: active.state_dir.clone(),
                        base_ref: "HEAD".into(),
                        base_sha: "0".repeat(40),
                        task: Task {
                            id: format!("planning-{index}"),
                            title: "planning".into(),
                            description: "no worktree".into(),
                            files: vec![],
                            acceptance: vec![],
                            evidence: None,
                        },
                        version: 1,
                        lead: None,
                        team_name: None,
                        steps: None,
                        run_budget_usd: None,
                    },
                )
                .expect("planning run");
        }
        for index in 0..MAX_INVENTORY {
            seed(&mut active, &format!("exact-{index}"), false);
        }
        let exact = active.retention_inventory(&InventoryQuery::default());
        assert_eq!(exact.items.len(), MAX_INVENTORY);
        assert!(!exact.truncated, "exactly 128 qualifying entries is a complete page");

        seed(&mut active, "one-extra", false);
        let extra = active.retention_inventory(&InventoryQuery::default());
        assert_eq!(extra.items.len(), MAX_INVENTORY);
        assert!(extra.truncated, "the 129th qualifying entry marks truncation");

        let reopened = core(&dir);
        let replayed = reopened.retention_inventory(&InventoryQuery::default());
        assert_eq!(replayed.items.len(), MAX_INVENTORY);
        assert!(replayed.truncated);
    }

    #[test]
    fn agent_projected_worktree_without_ownership_event_remains_visible_and_unavailable() {
        let dir = TempDir::new().expect("tempdir");
        let mut active = core(&dir);
        let seeded = seed(&mut active, "missing-created", false);
        let path = active
            .state_dir
            .join("runs")
            .join(seeded.run.to_string())
            .join("events.jsonl");
        let body = std::fs::read_to_string(&path).expect("history");
        let filtered = body
            .lines()
            .filter(|line| !line.contains("\"kind\":\"worktree.created\""))
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        std::fs::write(&path, filtered).expect("legacy history fixture");

        let reopened = core(&dir);
        let inventory = reopened.retention_inventory(&InventoryQuery {
            run_id: Some(seeded.run),
            lineage_id: Some(seeded.lineage),
        });
        assert_eq!(inventory.items.len(), 1);
        assert_eq!(inventory.items[0].worktree, seeded.path);
        assert_eq!(inventory.items[0].disposition, Disposition::Unavailable);
        assert!(inventory.items[0].branch.is_none());
    }

    #[test]
    fn long_unrelated_history_does_not_change_indexed_retirement_facts_after_reopen() {
        let dir = TempDir::new().expect("tempdir");
        let mut active = core(&dir);
        let seeded = seed(&mut active, "long-history", true);
        integrate(&mut active, &seeded);
        for index in 0..512 {
            active
                .registry
                .append(
                    &seeded.run,
                    EventPayload::AgentStatusChanged {
                        agent_id: seeded.agent,
                        status: AgentStatus::Idle,
                        reason: Some(format!("unrelated history {index}")),
                    },
                )
                .expect("unrelated event");
        }
        let request = request(&active, &seeded);
        assert!(active.validate_retirement(&request).is_ok());
        let before = active.retention_inventory(&InventoryQuery {
            run_id: Some(seeded.run),
            lineage_id: Some(seeded.lineage),
        });

        let reopened = core(&dir);
        assert!(reopened.validate_retirement(&request).is_ok());
        let after = reopened.retention_inventory(&InventoryQuery {
            run_id: Some(seeded.run),
            lineage_id: Some(seeded.lineage),
        });
        assert_eq!(before.items.len(), 1);
        assert_eq!(after.items.len(), 1);
        assert_eq!(before.items[0].branch, after.items[0].branch);
        assert_eq!(before.items[0].retired, after.items[0].retired);
        assert_eq!(before.items[0].disposition, after.items[0].disposition);
    }

    #[test]
    fn missing_cleanup_receipt_prevents_a_repeat_confirmation() {
        let dir = TempDir::new().expect("tempdir");
        let mut core = core(&dir);
        let seed = seed(&mut core, "missing-receipt", false);
        integrate(&mut core, &seed);
        core.registry
            .append(
                &seed.run,
                EventPayload::WorktreeRetired {
                    path: seed.path.clone(),
                    reason: "retired".into(),
                    resumable: False,
                },
            )
            .expect("retired");
        assert_eq!(
            core.retention_inventory(&InventoryQuery::default()).items[0].disposition,
            Disposition::Stale
        );
        assert!(core.validate_retirement(&request(&core, &seed)).is_err());
    }

    #[test]
    fn malformed_or_mismatched_cleanup_receipt_is_stale_and_refused() {
        let dir = TempDir::new().expect("tempdir");
        let mut core = core(&dir);
        let seed = seed(&mut core, "invalid-receipt", false);
        integrate(&mut core, &seed);
        core.registry
            .append(
                &seed.run,
                EventPayload::WorktreeRetired {
                    path: seed.path.clone(),
                    reason: "retired".into(),
                    resumable: False,
                },
            )
            .expect("retired");
        let identity = git::retirement_identity_path(
            &core.repo_root,
            &seed.run.to_string(),
            &seed.lineage.to_string(),
        );
        std::fs::create_dir_all(identity.parent().expect("receipt parent"))
            .expect("receipt parent");

        for bytes in [
            b"not json".to_vec(),
            serde_json::to_vec(&serde_json::json!({
                "preserved_ref": "refs/acp/retained/another/run",
                "root_dev": 1,
                "root_ino": 2,
                "git_file": [1],
                "git_dir": core.repo_root.join(".git/worktrees/invalid"),
                "git_dir_dev": 3,
                "git_dir_ino": 4,
                "trash_path": core.repo_root.join("fixture-trash/item"),
                "git_quarantine_path": identity.with_file_name(format!("{}.git-admin", seed.lineage)),
                "registration_retired": false
            })).expect("mismatched receipt"),
        ] {
            std::fs::write(&identity, bytes).expect("receipt fixture");
            let inventory = core.retention_inventory(&InventoryQuery::default());
            let item = &inventory.items[0];
            assert_eq!(item.disposition, Disposition::Stale);
            assert!(item.reason.contains("missing or invalid"));
            assert!(core.validate_retirement(&request(&core, &seed)).is_err());
        }
    }

    #[test]
    fn retired_sessions_stay_closed_when_provider_events_arrive_late_or_replay() {
        let dir = TempDir::new().expect("tempdir");
        let mut core = core(&dir);
        let seed = seed(&mut core, "retired-session", true);
        let sibling = AgentId::new_v4();
        core.registry
            .append(
                &seed.run,
                EventPayload::AgentCreated {
                    agent_id: sibling,
                    role: RoleName::Reviewer,
                    provider: ProviderName::Codex,
                    model: "codex".into(),
                    lineage_id: Some(seed.lineage),
                    depth: 1,
                    parent_agent_id: None,
                    origin: Origin::Lead,
                    writes: false,
                    cwd: seed.path.clone(),
                    worktree: Some(seed.path.clone()),
                },
            )
            .expect("reviewer");
        for agent in [seed.agent, sibling] {
            core.registry
                .append(
                    &seed.run,
                    EventPayload::AgentSession {
                        agent_id: agent,
                        attempt_id: AttemptId::new_v4(),
                        session_id: "session".into(),
                        src_line: 1,
                    },
                )
                .expect("session");
            assert!(core.registry.agent(&agent).expect("agent").resumable);
        }
        core.registry
            .append(
                &seed.run,
                EventPayload::WorktreeRetired {
                    path: seed.path,
                    reason: "retired".into(),
                    resumable: False,
                },
            )
            .expect("retired");
        core.registry
            .append(
                &seed.run,
                EventPayload::AgentStatusChanged {
                    agent_id: sibling,
                    status: AgentStatus::Idle,
                    reason: None,
                },
            )
            .expect("late status");
        core.registry
            .append(
                &seed.run,
                EventPayload::AgentSession {
                    agent_id: sibling,
                    attempt_id: AttemptId::new_v4(),
                    session_id: "late".into(),
                    src_line: 2,
                },
            )
            .expect("late session");
        let replayed = Registry::open(dir.path()).expect("restart");
        for registry in [&core.registry, &replayed] {
            for agent in [seed.agent, sibling] {
                let handle = registry.agent(&agent).expect("agent");
                assert_eq!(handle.status, AgentStatus::Closed);
                assert!(!handle.resumable);
                let ctx = super::super::policy::PolicyCtx {
                    registry,
                    cfg: &core.roles,
                    caller_role: RoleName::Lead,
                    caller_depth: 0,
                    now: || 0,
                };
                assert_eq!(
                    super::super::policy::check_send_message(&agent, &ctx)
                        .expect_err("retired agent cannot resume")
                        .code,
                    PolicyCode::AgentNotResumable
                );
            }
        }
    }

    #[test]
    fn pending_retry_blocks_only_its_own_completed_run() {
        let dir = TempDir::new().expect("tempdir");
        let mut core = core(&dir);
        let busy = seed(&mut core, "busy", true);
        let idle = seed(&mut core, "idle", true);
        integrate(&mut core, &busy);
        integrate(&mut core, &idle);
        core.pending_retry.insert(busy.agent, AttemptId::new_v4());
        let inventory = core.retention_inventory(&InventoryQuery::default());
        let disposition = |run| {
            inventory
                .items
                .iter()
                .find(|item| item.run_id == run)
                .unwrap()
                .disposition
        };
        assert_eq!(disposition(busy.run), Disposition::Retained);
        assert_eq!(disposition(idle.run), Disposition::Eligible);
        assert!(core.validate_retirement(&request(&core, &busy)).is_err());
        assert!(!core.validate_retirement(&request(&core, &idle)).unwrap());
    }

    #[test]
    fn confirmation_rechecks_resolving_gate_in_the_actor() {
        let dir = TempDir::new().expect("tempdir");
        let mut core = core(&dir);
        let seed = seed(&mut core, "integrated", true);
        integrate(&mut core, &seed);
        assert!(!core
            .validate_retirement(&request(&core, &seed))
            .expect("initially eligible"));
        let gate = GateId::new_v4();
        core.registry
            .append(
                &seed.run,
                EventPayload::GateCreated {
                    gate_id: gate,
                    gate_kind: GateKind::Integrate,
                    summary: "late finalization".into(),
                    payload_path: dir.path().join("gate.json"),
                    repair_binding: None,
                    requested_by: Origin::Lead,
                },
            )
            .expect("gate");
        core.registry
            .append(
                &seed.run,
                EventPayload::GateResolving {
                    gate_id: gate,
                    approve: true,
                    feedback: None,
                    by: Actor::Socket {
                        client_name: "cli".into(),
                    },
                    commit: None,
                    external_verification: None,
                },
            )
            .expect("resolving");
        let error = core
            .validate_retirement(&request(&core, &seed))
            .expect_err("resolving gate refused");
        assert!(error.to_string().contains("finalization"), "{error}");
    }

    #[test]
    fn preview_token_binds_repository_identity_and_original_sequence_across_restart() {
        let dir = TempDir::new().expect("tempdir");
        let mut active = core(&dir);
        let seed = seed(&mut active, "token", true);
        integrate(&mut active, &seed);
        let request = request(&active, &seed);
        assert!(active.validate_retirement(&request).is_ok());

        let restarted = core(&dir);
        assert!(
            restarted.validate_retirement(&request).is_ok(),
            "a legitimate daemon restart keeps the exact preview valid"
        );

        let mut omitted = request.clone();
        omitted.preview_token.clear();
        assert!(restarted
            .validate_retirement(&omitted)
            .unwrap_err()
            .to_string()
            .contains("fresh preview"));

        let mut mismatched = request.clone();
        mismatched.worktree = restarted.repo_root.join(".acp/worktrees/another");
        assert!(restarted
            .validate_retirement(&mismatched)
            .unwrap_err()
            .to_string()
            .contains("fresh preview"));

        let moved = seed.path.with_file_name("token-original");
        std::fs::rename(&seed.path, &moved).expect("move previewed checkout");
        std::fs::create_dir(&seed.path).expect("replacement checkout");
        assert!(restarted
            .validate_retirement(&request)
            .unwrap_err()
            .to_string()
            .contains("fresh preview"));
        std::fs::remove_dir(&seed.path).expect("remove replacement checkout");
        std::fs::rename(&moved, &seed.path).expect("restore previewed checkout");
        assert!(restarted.validate_retirement(&request).is_ok());

        active
            .registry
            .append(
                &seed.run,
                EventPayload::AgentStatusChanged {
                    agent_id: seed.agent,
                    status: AgentStatus::Idle,
                    reason: Some("sequence changed".into()),
                },
            )
            .expect("advance sequence");
        assert!(active
            .validate_retirement(&request)
            .unwrap_err()
            .to_string()
            .contains("changed after preview"));
    }
}
