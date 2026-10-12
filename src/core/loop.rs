//! The Phase-1 build/review loop driver (`impl Core`), declared as `pub mod r#loop;`.
//! Implemented in T35 (`reports/03-design.md` § `src/core/loop.rs`, § Data Flow steps 1-19).
//!
//! This module is where a finished attempt becomes the next step: a reviewer, an integrate gate, a
//! strike, a retry, a replacement, or a blocked run. Three rules shape every function in it.
//!
//! 1. **A branch is one mailbox turn, and its last append is `loop.dispatched`.** The marker is the
//!    only durable answer to "has the loop already reacted to this attempt?" (see
//!    [`loop_dispatch`](crate::core::loop_dispatch)), so everything a branch does has to be durable
//!    *before* it, and the branch may not wait on a helper task in the middle — an attempt whose
//!    branch has not reached its marker is swept again on the next tick, so a branch that parked
//!    itself half-way would be run twice.
//! 2. **Delivery is at least once, so every side effect is checked against the log first.** A crash
//!    between a branch's first append and its marker re-drives the whole branch on the next start.
//!    `struck_since`, `gate_since`, `agent_created_since` and friends below are that check: each
//!    asks "did this already happen *after* the attempt finished?", which is exactly the window a
//!    re-drive would duplicate.
//! 3. **The actor never waits on I/O.** There is no `.await` on git or on a spawn anywhere in this
//!    module: `add_worktree`, `status_porcelain` and every `spawn_detached` run in the helper tasks
//!    `core/mod.rs` owns, and a branch starts one and ends. Rules 1 and 3 pull in opposite
//!    directions — a branch may not park half-way, but it may not wait either — and what reconciles
//!    them is [`Core::reconcile_intents`]: a branch's *durable* half is appended before the marker,
//!    and the helper work that follows it is an **intent the log can be re-read for**, so a daemon
//!    that dies with a helper in flight reissues it on the next start instead of stalling.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde_json::Value;

use crate::core::gates::{self, GatePayload, NewGate};
use crate::core::plan::{validate_plan, Plan, PlanItemKind, PlanItemStatus};
use crate::core::policy::{self, DelegateRequest, PolicyCode, PolicyCtx, PolicyError, SessionSpec};
use crate::core::registry::PlanProjection;
use crate::core::registry::{AuditEntry, Registry};
use crate::core::supervisor::{
    assert_safe_argv, ArgvCtx, AttemptContext, SpawnError, SpawnedProc, Supervisor,
};
use crate::core::team::{self, Effort, ValidTeam};
use crate::core::types::{
    require_all_properties, strip_dollar_schema, AgentId, AgentStatus, AttemptError, AttemptId,
    AttemptKind, AttemptStatus, BuildResult, CancelBy, DelegatedTarget, ErrorCode, Event,
    EventPayload, False, GateId, GateKind, GateStatus, LineageId, LoopBranch, LoopState,
    MessageRole, Origin, ProviderName, ReviewFinding, ReviewVerdict, RoleName, RolesConfig, Run,
    RunId, RunStatus, RunSteps, RunExecution, RunMode, SchemaName, Severity, Task, Verdict, VerifyReport, VerifyStatus,
};
use crate::core::{
    clamp_untrusted, handoff, is_terminal, Core, CoreError, DelegateOut, GateResolution,
    WorktreeInfo,
};
use crate::providers::claude::ClaudeAdapter;
use crate::providers::codex::CodexAdapter;
use crate::providers::{ProviderAdapter, SandboxSpec, SpawnRequest};
use crate::roles::loader;
use crate::workspace::git::GitError;

pub use crate::core::SendResult;

#[path = "audit.rs"]
pub mod audit;
#[path = "security.rs"]
pub(crate) mod security;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `<repoRoot>/.acp/worktrees/<runId>/<agentShort>` (design, § On-disk layout). Worktrees are the
/// one part of the control plane's state that lives in the repository, because git requires it.
const WORKTREES_DIR: &str = ".acp/worktrees";

/// `<stateDir>/runs/<runId>/attempts/<attemptId>` (design, § On-disk layout).
const RUNS_DIR: &str = "runs";
const ATTEMPTS_DIR: &str = "attempts";

/// How much of an id names a worktree directory and a branch. Eight hex characters of a v4 uuid
/// keep both readable in `git worktree list` while staying collision-free within one run.
const SHORT_ID: usize = 8;

/// `run.created{version}` — the run record's own format version.
const RUN_VERSION: u32 = 1;

/// Longest gate summary (design, § MCP tools: "`summary ≤ 4 000`"). The summary quotes worker- and
/// reviewer-authored text, so it is clamped rather than trusted to be short.
const MAX_SUMMARY_CHARS: usize = 4_000;

/// Longest team name copied from the human-managed `team.json` into the durable event log.
///
/// `team.set` is not the only writer (the macOS app can write the file directly), so this bound
/// belongs at the log ingress. It follows the control plane's 4-K character ceiling for untrusted
/// free text and leaves the on-disk team untouched.
const MAX_TEAM_NAME_CHARS: usize = 4_000;

/// How many reviewers one frozen diff may consume before the run blocks (Rev 25): the first, and
/// **one** replacement for a reviewer that crashed or echoed the wrong `diffHash`.
const MAX_REVIEWERS_PER_DIFF: usize = 2;

/// B1's mirror of the reviewer budget: the first verifier, and **one** replacement for a
/// verifier that crashed or echoed the wrong hash — it told us nothing about the change, so the
/// builder is not struck for it; a second one doing the same is a fault a human has to look at,
/// not a loop to keep spending money in.
const MAX_VERIFIERS_PER_DIFF: usize = 2;

// ---------------------------------------------------------------------------
// Pending helper-task state
// ---------------------------------------------------------------------------

/// A delegation waiting for its worktree: everything `on_worktree_ready` needs to write the run,
/// the agent and the first attempt once `add_worktree` has reported the base sha it used.
///
/// It is deliberately plain data. A crash loses it along with the helper task that would have
/// answered it, and the log — which at that point holds nothing about this run — is consistent
/// with a delegation that never happened.
pub struct PendingWorktree {
    execution: Option<RunExecution>,
    run: RunId,
    /// `true` when this delegation still owes `run.created`.
    new_run: bool,
    agent: AgentId,
    attempt: AttemptId,
    lineage: LineageId,
    role: RoleName,
    provider: ProviderName,
    model: String,
    effort: Option<Effort>,
    depth: u8,
    parent: Option<AgentId>,
    origin: Origin,
    writes: bool,
    /// Where the worktree is being created. Only the failure path reads it — the helper echoes
    /// the path back on success — and it reads it to say *which* worktree could not be made.
    worktree: PathBuf,
    base_ref: String,
    task: Task,
    prompt: String,
    lead: Option<String>,
    team_name: Option<String>,
    /// The step switches captured from the team at delegate time (B3); only a `new_run`
    /// delegation writes them into `run.created`.
    steps: Option<RunSteps>,
    timeout_sec: u64,
    spawn_budget_usd: f64,
    attempt_no: u32,
    strikes: u8,
    /// T84: the caller's already-*validated* lead run (`Core::validated_caller_run`), carried
    /// across the worktree helper so `run.delegated` can be written once `run.created` for a
    /// brand-new run is durable. `None` for every internal delegation and every caller whose claim
    /// failed strict validation.
    caller_run_id: Option<RunId>,
}

impl PendingWorktree {
    /// Which run this worktree is being created for — the in-flight guard
    /// [`Core::reconcile_intents`] reads.
    #[must_use]
    pub fn run(&self) -> RunId {
        self.run
    }
}

/// An attempt waiting for its process. The context is what [`Supervisor::adopt`] takes on success;
/// `argv` and `cwd` are what `attempt.started` records when the spawn failed instead.
///
/// [`Supervisor::adopt`]: crate::core::supervisor::Supervisor::adopt
pub struct PendingSpawn {
    ctx: AttemptContext,
    argv: Vec<String>,
    cwd: PathBuf,
}

impl PendingSpawn {
    /// Which agent this spawn belongs to — the in-flight guard [`Core::reconcile_intents`] reads.
    #[must_use]
    pub fn agent(&self) -> AgentId {
        self.ctx.agent
    }
}

// ---------------------------------------------------------------------------
// Branch classification (design, § Data Flow step 17)
// ---------------------------------------------------------------------------

/// Which branch of the loop a terminal attempt takes. Pure: derived from the attempt's status, its
/// error code and its role, and from nothing else, so the table is directly testable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Branch {
    /// 17a — the CLI is missing or unauthenticated. No strike; a human has to fix the machine.
    Environment,
    /// A denylist hit or an unverifiable workspace: an `escalate` gate, no strike, no reviewer.
    Escalate,
    /// The builder succeeded: freeze, then verify (B1) or review (steps 13-14).
    Review,
    /// A reviewer attempt ended: verdict, replacement reviewer, or block (steps 15-16, Rev 25).
    Reviewer,
    /// A verifier attempt ended (B1): report recorded, then review, strike, replacement or block.
    Verify,
    /// 17b/17c/17d — a strikeable failure of the builder.
    Strike,
    /// A conversational lead turn ended; no worker lineage branch follows it.
    Lead,
    /// Nothing for the loop to do: a human cancelled the attempt, or it was declared `lost` and is
    /// never auto-resumed (design, § Error Handling).
    None,
}

/// The branch table, in the order its rows must be read.
///
/// Environment first because it is the one failure that is never the model's fault and never
/// resolves on its own; `escalate` next because a denylist hit or an unverified worktree must not
/// be turned into a strike; then the two states a human owns; then role and success.
fn branch_of(role: RoleName, status: AttemptStatus, error: Option<&AttemptError>) -> Branch {
    if matches!(
        error.map(|e| e.code),
        Some(ErrorCode::ProviderMissing | ErrorCode::ProviderUnauthenticated)
    ) {
        return Branch::Environment;
    }
    match status {
        AttemptStatus::Escalate => Branch::Escalate,
        AttemptStatus::Cancelled | AttemptStatus::Lost | AttemptStatus::Running => Branch::None,
        // A lead turn is conversational: after it ends, the human may resume it through
        // `send_message`. It never enters the builder/reviewer branch table and mints no lineage.
        _ if role == RoleName::Lead => Branch::Lead,
        _ if matches!(role, RoleName::Reviewer | RoleName::Security) => Branch::Reviewer,
        // B1: role first, like the reviewer row above — a verifier's crash, timeout or success
        // all land in `Branch::Verify`; the builder is never struck for a verifier's *failure*.
        _ if role == RoleName::Verifier => Branch::Verify,
        AttemptStatus::Succeeded => Branch::Review,
        _ => Branch::Strike,
    }
}

/// Why a lineage is being struck, and therefore which repair prompt the builder is given.
enum StrikeCause {
    /// A reviewer rejected the work (17b's `build_repair_prompt`).
    ReviewFail(Vec<ReviewFinding>),
    /// Verification failed the work (B1 — `build_verify_repair_prompt`, failure text verbatim).
    VerifyFail(Box<VerifyReport>),
    /// The attempt itself ended badly (17b's `build_failure_repair_prompt`).
    Failure(Option<AttemptError>),
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

/// The facts about one terminal attempt the branch table reads, copied out of the projection before
/// anything is appended — every branch mutates the registry, and the borrow checker is right to
/// object to holding a `&Attempt` across that.
struct Finished {
    attempt: AttemptId,
    run: RunId,
    agent: AgentId,
    status: AttemptStatus,
    error: Option<AttemptError>,
    structured: Option<Value>,
    /// `seq` of this attempt's `attempt.finished`. Everything appended after it is what a re-drive
    /// of this branch would duplicate, which makes it the window every idempotency check looks in.
    finish_seq: u64,
    parent: Option<AgentId>,
}

/// The builder a branch acts on. For a builder's own failure that is the attempt's agent; when a
/// reviewer FAILs it is the builder the reviewer was reviewing.
struct Target {
    agent: AgentId,
    lineage: LineageId,
    worktree: PathBuf,
    cwd: PathBuf,
    session: Option<String>,
    resumable: bool,
    strikes: u8,
    attempt_no: u32,
}

/// A 17b repair the log says was decided and never sent: which builder owes it, and the attempt
/// whose branch owed it (the cause the repair prompt is rebuilt from).
struct OwedResume {
    run: RunId,
    agent: AgentId,
    marked: AttemptId,
}

/// The frozen diff of one builder attempt (`diff.frozen`).
#[derive(Clone)]
struct Frozen {
    attempt: AttemptId,
    path: PathBuf,
    hash: String,
    files: Vec<String>,
}

/// Everything one spawn needs, resolved. Owned so it outlives the policy borrow it came from.
struct StartSpawn {
    run: RunId,
    agent: AgentId,
    attempt: AttemptId,
    role: RoleName,
    provider: ProviderName,
    model: String,
    effort: Option<Effort>,
    prompt: String,
    cwd: PathBuf,
    worktree: PathBuf,
    writes: bool,
    pre_sha: String,
    kind: AttemptKind,
    session_id: Option<String>,
    timeout_sec: u64,
    spawn_budget_usd: f64,
}

/// What `check_delegate` resolved, owned. [`ResolvedSpawn`](policy::ResolvedSpawn) borrows the
/// `RolesConfig` *and* the registry through its context, and every caller here mutates the registry
/// next.
struct Resolved {
    provider: ProviderName,
    model: String,
    effort: Option<Effort>,
    depth: u8,
    base_ref: String,
    writes: bool,
    spawn_budget_usd: f64,
    attempt_timeout_sec: u64,
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

/// Reconstructed from the durable run during prefix recovery as well as initial setup.
fn lead_setup_prompt(message: &str, execution: Option<&RunExecution>) -> String {
    let Some(selection) = execution.and_then(|e| e.authorized_audit_selection.as_ref()) else {
        return message.to_string();
    };
    format!("{message}\n\nACP human setup: audit existing work using exactly this selection: {}. \
        Call audit_existing with this baseRef and target; do not delegate a builder or invent another comparison. \
        Report the selected checks' results without requesting integration.",
        serde_json::to_string(selection).expect("audit selection is serializable"))
}

impl Core {
    /// Starts one conversational lead directly in the repository root. This is the daemon-side
    /// spawn primitive; T58's socket-only `lead.start` door owns human-input validation and the
    /// one-live-lead policy before it calls here.
    ///
    /// No `worktree.created` event is emitted, and `agent.created.lineageId` is absent, so the
    /// projection creates no lineage and no path under `.acp/worktrees`.
    pub fn spawn_lead(
        &mut self,
        task: Task,
        message: String,
    ) -> Result<(RunId, AgentId), CoreError> {
        self.spawn_lead_with_setup(task, message, super::LeadSetup::default())
    }

    pub fn spawn_lead_with_setup(
        &mut self, task: Task, message: String, setup: super::LeadSetup,
    ) -> Result<(RunId, AgentId), CoreError> {
        if let Some(agent) = self.live_lead_agent() {
            return Err(CoreError::Policy(
                PolicyError::new(
                    PolicyCode::LeadBusy,
                    format!("lead agent {agent} already has a live attempt"),
                )
                .with_detail(serde_json::json!({ "agentId": agent.to_string() })),
            ));
        }
        let role = loader::role_spec(&self.roles, RoleName::Lead)
            .map_err(|err| PolicyError::new(PolicyCode::UnknownRole, err.to_string()))?.clone();
        let spawn_budget_usd = role.spawn_budget_usd;
        let team = self.valid_team()?;
        if setup.expected_team.as_ref().is_some_and(|expected| team.as_ref().map(|t| t.team()) != Some(expected)) {
            return Err(PolicyError::new(PolicyCode::TeamInvalid,
                "the saved team changed during setup; review the choices and start again").into());
        }
        // v1/v2 lead was informational. Only explicit v3 setup chooses a spawned provider.
        let selected = team.as_ref().filter(|t| t.team().version >= 3);
        let assignment = team::resolve_assignment(&self.roles, selected, RoleName::Lead);
        let provider = assignment.provider;
        let model = assignment.model.clone();
        if !role.models.contains(&model)
            || !self.roles.providers.get(&provider).is_some_and(|p| p.models.contains(&model)) {
            return Err(CoreError::Policy(PolicyError::new(
                PolicyCode::UnknownModel, "the selected lead model is outside the role catalog")));
        }
        let mut execution = team::capture_execution(&self.roles, team.as_ref());
        execution.assignments.insert("lead".into(), assignment.clone());
        if execution.mode == RunMode::Audit {
            let selection = setup.audit_selection.ok_or_else(|| PolicyError::new(
                PolicyCode::InvalidBaseRef, "choose an explicit audit base and target before starting"))?;
            audit::validate_selection(&selection)?;
            execution.authorized_audit_selection = Some(selection);
        } else if setup.audit_selection.is_some() {
            return Err(PolicyError::new(PolicyCode::TeamInvalid,
                "audit input applies only to a task with checks and no builder").into());
        }
        let message = lead_setup_prompt(&message, Some(&execution));
        let run = RunId::new_v4();
        let agent = AgentId::new_v4();
        let attempt = AttemptId::new_v4();
        self.registry.append(
            &run,
            EventPayload::RunCreated {
                execution: Some(execution.clone()),
                repo_root: self.repo_root.clone(),
                state_dir: self.state_dir.clone(),
                base_ref: self.roles.defaults.base_ref.clone(),
                // No worktree base is resolved for a read-only conversation. A builder delegated
                // into this run records its own resolved base on `worktree.created`.
                base_sha: String::new(),
                task,
                version: RUN_VERSION,
                lead: Some(format!("{}:{model}", provider_key(provider))),
                team_name: team.as_ref().map(|t| t.name().to_string()),
                steps: Some(execution.steps),
            },
        )?;
        self.registry.append(
            &run,
            EventPayload::AgentCreated {
                agent_id: agent,
                role: RoleName::Lead,
                provider,
                model: model.clone(),
                lineage_id: None,
                depth: 0,
                parent_agent_id: None,
                origin: Origin::Lead,
                writes: false,
                cwd: self.repo_root.clone(),
                worktree: None,
            },
        )?;

        let spawn = StartSpawn {
            run,
            agent,
            attempt,
            role: RoleName::Lead,
            provider,
            model,
            effort: assignment.effort,
            prompt: message,
            cwd: self.repo_root.clone(),
            worktree: self.repo_root.clone(),
            writes: false,
            pre_sha: String::new(),
            kind: AttemptKind::Fresh,
            session_id: None,
            timeout_sec: self.roles.defaults.attempt_timeout_sec,
            spawn_budget_usd,
        };
        if let Err(err) = self.start_attempt(spawn) {
            self.block_run(
                &run,
                &format!("the lead could not be started: {}", err.reason),
            );
            return Err(CoreError::Policy(err));
        }
        Ok((run, agent))
    }

    /// The one lead that has a pending provider spawn or any attempt still running.
    /// The actor serializes `LeadStart` commands, so this check and the subsequent durable
    /// `agent.created` append are one decision: two racing socket requests cannot both pass it.
    fn live_lead_agent(&self) -> Option<AgentId> {
        self.registry
            .state()
            .agents
            .values()
            .filter(|agent| agent.role == RoleName::Lead)
            .filter(|agent| {
                self.pending_spawn
                    .values()
                    .any(|pending| pending.agent() == agent.agent_id)
                    || agent.attempt_ids.iter().any(|attempt| {
                        self.registry
                            .attempt(attempt)
                            .is_some_and(|attempt| attempt.status == AttemptStatus::Running)
                    })
            })
            .map(|agent| agent.agent_id)
            .min_by_key(|agent| *agent.as_uuid())
    }

    /// T84's fail-closed attribution check: `claimed` is trustworthy only when it names the run of
    /// the daemon's own [`Core::live_lead_agent`] — the one fact the daemon itself wrote into an
    /// `acp mcp-proxy` child's `ACP_LEAD_RUN_ID`. Anything else (absent, stale, forged, or no lead
    /// live at all) answers `None`; the caller then writes nothing rather than guessing.
    fn validated_caller_run(&self, claimed: Option<RunId>) -> Option<RunId> {
        let claimed = claimed?;
        let agent = self.live_lead_agent()?;
        let live_run = self.registry.agent(&agent)?.run_id;
        (claimed == live_run).then_some(live_run)
    }

    /// Writes `run.delegated` on `caller`'s own run once `delegated`'s `run.created` is durable
    /// (T84). A `None` caller — no attested lead, or one `validated_caller_run` rejected — writes
    /// nothing: the invariant is "every run a *validated* lead's delegation caused", not every run.
    /// Nor does a caller that names its own run (review note #1): a lead may legally
    /// `delegate{runId: <its own run>}`, but recording it would be a self-edge — the lead showing
    /// up in its own delegation list — so that case writes nothing either.
    fn record_delegation(
        &mut self,
        caller: Option<RunId>,
        delegated: RunId,
        role: Option<RoleName>,
        target: DelegatedTarget,
    ) {
        let Some(caller) = caller else {
            return;
        };
        if caller == delegated {
            return;
        }
        self.emit(
            &caller,
            EventPayload::RunDelegated {
                delegated_run_id: delegated,
                role,
                target,
            },
        );
    }

    // -----------------------------------------------------------------------
    // delegate (steps 1-6)
    // -----------------------------------------------------------------------

    /// Validates a delegation and starts it, answering **before** the worktree exists.
    ///
    /// Policy runs inline because it is pure and takes microseconds (design, § `src/core/loop.rs`);
    /// a rejection therefore costs no worktree, no process and no run — it is an `audit.jsonl` line
    /// and a structured error. On acceptance the ids are minted, `add_worktree` goes to a helper
    /// task and the tool call is answered immediately with `{agentId, runId, attemptId, worktree}`.
    ///
    /// The design's step 3 puts `run.created` here. It is appended in
    /// [`Core::on_worktree_ready`] instead, for one reason: `run.created` carries the run's
    /// `baseSha`, `roles.json` ships `defaults.baseRef = "HEAD"`, and resolving a ref is a git call
    /// this function may not wait for (decision 11). The helper resolves it and reports the sha it
    /// created the worktree at, which is the first moment the event can be written truthfully.
    ///
    /// # Errors
    /// [`CoreError::Policy`] for any rejection [`policy::check_delegate`] can raise, plus
    /// `TeamInvalid` for a `team.json` that exists and cannot be trusted (Rev 26) and `InvalidTask`
    /// for a fresh `reviewer` delegation, which only the control plane may start.
    pub fn delegate(&mut self, req: DelegateRequest) -> Result<DelegateOut, CoreError> {
        if self.caller_without_builder(req.caller_run_id) {
            return Err(PolicyError::new(PolicyCode::DelegationNotAllowed,
                "this lead's recorded task has no builder").into());
        }
        let inherited = req.caller_run_id
            .and_then(|id| self.registry.run(&id)).and_then(|r| r.execution.clone());
        if inherited.as_ref().is_some_and(|e| e.mode != RunMode::Build) {
            return Err(PolicyError::new(PolicyCode::DelegationNotAllowed,
                "this lead's task has no writing workers; start a separately configured task").into());
        }
        self.delegate_with_execution(req, inherited)
    }

    fn delegate_with_execution(&mut self, req: DelegateRequest, inherited: Option<RunExecution>) -> Result<DelegateOut, CoreError> {
        let cfg = Arc::clone(&self.roles);
        let captured = self.request_execution(&req).cloned().or(inherited);
        let team = match captured.as_ref() {
            Some(execution) => Some(team::from_execution(&cfg, execution).map_err(|issues|
                PolicyError::new(PolicyCode::TeamInvalid, format!("recorded team is unsupported: {issues:?}")))?),
            None => self.valid_team()?,
        };
        if team.as_ref().is_some_and(|team| team.mode() != RunMode::Build) {
            return Err(PolicyError::new(PolicyCode::DelegationNotAllowed,
                "planning and audit cannot use build delegation or resume; audit checks use the snapshot dispatcher").into());
        }
        if let Some(assignment) = captured.as_ref().and_then(|e| e.assignments.get(role_key(req.role))) {
            if req.model.as_ref().is_some_and(|m| m != &assignment.model) {
                return Err(PolicyError::new(PolicyCode::UnknownModel,
                    "a task keeps its recorded model assignment").into());
            }
        }
        let digest = format!("{}:{}", role_key(req.role), req.task.id);

        let decided = {
            let ctx = PolicyCtx {
                registry: &self.registry,
                cfg: &cfg,
                caller_role: RoleName::Lead,
                caller_depth: 0,
                now: epoch_secs,
            };
            policy::check_delegate(&req, &ctx, team.as_ref()).map(|r| Resolved {
                provider: r.provider,
                model: r.model.to_string(),
                effort: r.effort,
                depth: r.depth,
                base_ref: r.base_ref.clone(),
                writes: r.writes,
                spawn_budget_usd: r.spawn_budget_usd,
                attempt_timeout_sec: r.attempt_timeout_sec,
            })
        };
        let resolved = match decided {
            Ok(resolved) => resolved,
            Err(err) => return Err(self.reject("delegate", &digest, err)),
        };
        // T84: validated once, up front, against whatever lead is live *now* — before any of this
        // delegation's own side effects can change that answer.
        let validated_caller = self.validated_caller_run(req.caller_run_id);

        if let SessionSpec::Resume(agent) = req.session {
            return self.delegate_resume(agent, &req, &resolved, &digest, validated_caller);
        }

        // A reviewer reviews a **frozen diff**, and only the loop knows which one: there is no
        // diff for a reviewer a lead starts by hand, and pointing one at a live worktree would let
        // it review bytes that change under it — the thing Rev 25's diff-hash binding exists to
        // prevent.
        if req.role == RoleName::Reviewer {
            let err = PolicyError::new(
                PolicyCode::InvalidTask,
                "a reviewer is started by the control plane once a builder's diff is frozen; \
                 delegate a builder instead",
            );
            return Err(self.reject("delegate", &digest, err));
        }

        let mut execution = captured.unwrap_or_else(|| team::capture_execution(&cfg, team.as_ref()));
        execution.steps = req.steps.unwrap_or(execution.steps);
        execution.assignments.insert(role_key(req.role).into(), team::Assignment {
            provider: resolved.provider, model: resolved.model.clone(), effort: resolved.effort,
        });
        let run = req.run_id.unwrap_or_else(RunId::new_v4);
        let new_run = self.registry.run(&run).is_none();
        let agent = AgentId::new_v4();
        let attempt = AttemptId::new_v4();
        let lineage = LineageId::new_v4();
        let worktree = worktree_path(&self.repo_root, &run, &agent);
        let branch = branch_name(&run, &agent);
        let prompt = handoff::build_builder_prompt(&req.task, &schema_hint(req.role));

        self.pending_worktree.insert(
            lineage,
            PendingWorktree {
                execution: Some(execution.clone()),
                run,
                new_run,
                agent,
                attempt,
                lineage,
                role: req.role,
                provider: resolved.provider,
                model: resolved.model,
                effort: resolved.effort,
                depth: resolved.depth,
                parent: None,
                origin: Origin::Lead,
                writes: resolved.writes,
                worktree: worktree.clone(),
                base_ref: resolved.base_ref.clone(),
                task: req.task.clone(),
                prompt,
                lead: team.as_ref().and_then(lead_label),
                team_name: team.as_ref().map(|t| t.name().to_string()),
                steps: Some(execution.steps),
                timeout_sec: resolved.attempt_timeout_sec,
                spawn_budget_usd: resolved.spawn_budget_usd,
                attempt_no: 1,
                strikes: 0,
                // A brand-new run's own `run.created` is not durable yet — deferred to
                // `on_worktree_ready`, right after it is. An *existing* run this delegation
                // attaches to already has one, so it is safe to record right away, below.
                caller_run_id: new_run.then_some(validated_caller).flatten(),
            },
        );
        if !new_run {
            self.record_delegation(validated_caller, run, Some(req.role), DelegatedTarget::Worker);
        }
        self.spawn_worktree_from_ref(
            lineage,
            self.repo_root.clone(),
            worktree.clone(),
            branch,
            resolved.base_ref,
        );

        Ok(DelegateOut {
            agent_id: agent,
            run_id: run,
            attempt_id: attempt,
            status: RunStatus::Running,
            worktree,
        })
    }

    /// `delegate{session:"resume:<uuid>"}`: the task goes to a session that already exists, in the
    /// worktree it already has. No worktree is created and no agent is minted.
    ///
    /// T84: a resume still "causes" work in `run` from `validated_caller`'s point of view — most
    /// visibly when a *different* live lead resumes an agent an earlier conversation started — so
    /// on success this records the same linkage a fresh spawn into an existing run would. The run
    /// already exists (it is `handle.run_id`), so there is no `run.created` ordering to wait for.
    fn delegate_resume(
        &mut self,
        agent: AgentId,
        req: &DelegateRequest,
        resolved: &Resolved,
        digest: &str,
        validated_caller: Option<RunId>,
    ) -> Result<DelegateOut, CoreError> {
        let Some(handle) = self.registry.agent(&agent) else {
            let err = PolicyError::new(
                PolicyCode::ResumeTargetMissing,
                format!("no agent {agent} in this state dir"),
            );
            return Err(self.reject("delegate", digest, err));
        };
        let (run, worktree) = (
            handle.run_id,
            handle
                .worktree
                .clone()
                .unwrap_or_else(|| handle.cwd.clone()),
        );
        let attempt = AttemptId::new_v4();
        let prompt = handoff::build_builder_prompt(&req.task, &schema_hint(req.role));
        match self.resume_attempt(agent, attempt, prompt, resolved.spawn_budget_usd) {
            Ok(()) => {
                self.record_delegation(validated_caller, run, Some(req.role), DelegatedTarget::Worker);
                Ok(DelegateOut {
                    agent_id: agent,
                    run_id: run,
                    attempt_id: attempt,
                    status: RunStatus::Running,
                    worktree,
                })
            }
            Err(err) => Err(self.reject("delegate", digest, err)),
        }
    }

    // -----------------------------------------------------------------------
    // The helper-task completions (steps 4-5)
    // -----------------------------------------------------------------------

    /// `add_worktree` finished: write the run, the worktree, the agent, and start the process.
    ///
    /// An `Err` is a git fault, which the design handles by blocking the affected run rather than
    /// by striking anybody — nothing about the worker is being asserted, the control plane could
    /// not do its own job. The run is created first when this delegation owed it, so the failure is
    /// visible to `get_status` instead of vanishing with the reply that already promised a runId;
    /// its `baseSha` is empty, which is the honest record of a base that was never resolved.
    pub fn on_worktree_ready(
        &mut self,
        lineage: &LineageId,
        result: Result<WorktreeInfo, GitError>,
    ) {
        let Some(p) = self.pending_worktree.remove(lineage) else {
            // A duplicate completion, or one for a delegation this process did not start.
            tracing::warn!(%lineage, "worktree completion with no pending delegation");
            return;
        };
        let cancelled = self.cancellation.worktrees.remove(lineage)
            || self.registry.run(&p.run).is_some_and(|r| r.status == RunStatus::Cancelled);
        let info = match result {
            Ok(info) => info,
            Err(err) => {
                let reason = format!(
                    "the worktree {} could not be created: {err}",
                    p.worktree.display()
                );
                if p.new_run {
                    let created = run_created(
                        &p,
                        self.repo_root.clone(),
                        self.state_dir.clone(),
                        String::new(),
                    );
                    self.emit(&p.run, created);
                    // T84: `run.created` just landed, even though the run is about to be
                    // blocked — the linkage is honest either way (the delegation *did* cause
                    // this run to exist), and the invariant does not condition on outcome.
                    self.record_delegation(p.caller_run_id, p.run, Some(p.role), DelegatedTarget::Worker);
                }
                self.registry.audit(AuditEntry::new(
                    "delegate",
                    PolicyCode::GitTimeout.as_str(),
                    &reason,
                    p.task.id.clone(),
                ));
                if cancelled {
                    if let Err(error) = self.record_run_cancellation(&p.run) {
                        self.lifecycle.fail_stop(format!("Could not record cancelled worktree: {error}"));
                    }
                } else { self.block_run(&p.run, &reason); }
                return;
            }
        };

        if p.new_run {
            let created = run_created(
                &p,
                self.repo_root.clone(),
                self.state_dir.clone(),
                info.base_sha.clone(),
            );
            self.emit(&p.run, created);
            // T84: only now — this run's own `run.created` is durable — may the caller's run say
            // this delegation caused it. `None` (no attested lead, or one that failed strict
            // validation) writes nothing.
            self.record_delegation(p.caller_run_id, p.run, Some(p.role), DelegatedTarget::Worker);
            if !cancelled {
                self.emit(
                    &p.run,
                    EventPayload::RunStatus_ {
                        status: RunStatus::Running,
                        reason: None,
                    },
                );
                self.emit(
                    &p.run,
                    EventPayload::LoopStateChanged {
                        state: LoopState::Building,
                        builder_agent_id: Some(p.agent),
                        attempt_no: p.attempt_no,
                        strikes: p.strikes,
                    },
                );
            }
        }
        // Make cancellation durable before an agent exists for restart reconciliation.
        if cancelled {
            if let Err(error) = self.record_run_cancellation(&p.run) {
                self.lifecycle.fail_stop(format!("Could not record cancelled worktree: {error}"));
                return;
            }
        }
        self.emit(
            &p.run,
            EventPayload::WorktreeCreated {
                agent_id: p.agent,
                lineage_id: p.lineage,
                path: info.path.clone(),
                branch: info.branch.clone(),
                base_sha: info.base_sha.clone(),
            },
        );
        self.emit(
            &p.run,
            EventPayload::AgentCreated {
                agent_id: p.agent,
                role: p.role,
                provider: p.provider,
                model: p.model.clone(),
                lineage_id: Some(p.lineage),
                depth: p.depth,
                parent_agent_id: p.parent,
                origin: p.origin,
                writes: p.writes,
                cwd: info.path.clone(),
                worktree: Some(info.path.clone()),
            },
        );

        // `add_worktree` may have taken the whole `GIT_OP_TIMEOUT`. The worktree and the agent are
        // recorded either way — they exist, and the log should say so — but nothing is started into
        // a run that has stopped accepting workers.
        if cancelled { return; }
        if !self.run_accepts_workers(&p.run) {
            tracing::info!(run = %p.run, agent = %p.agent, "the run no longer accepts workers; no builder was started");
            return;
        }

        let spawn = StartSpawn {
            run: p.run,
            agent: p.agent,
            attempt: p.attempt,
            role: p.role,
            provider: p.provider,
            model: p.model,
            effort: p.effort,
            prompt: p.prompt,
            cwd: info.path.clone(),
            worktree: info.path,
            writes: p.writes,
            pre_sha: info.base_sha,
            kind: AttemptKind::Fresh,
            session_id: None,
            timeout_sec: p.timeout_sec,
            spawn_budget_usd: p.spawn_budget_usd,
        };
        if let Err(err) = self.start_attempt(spawn) {
            let reason = format!("the builder could not be started: {}", err.reason);
            self.registry.audit(AuditEntry::new(
                "delegate",
                err.code.as_str(),
                &reason,
                p.task.id,
            ));
            self.block_run(&p.run, &reason);
        }
    }

    /// `spawn_detached` finished: hand the child to the supervisor, or record the failure as the
    /// attempt it would have been.
    ///
    /// A spawn failure is recorded as `attempt.started` + `attempt.finished{spawn_failed}` rather
    /// than as a bare terminal event, because the reducer only knows an attempt it has seen start:
    /// without the pair the failure would project to nothing at all, `await_result` would never
    /// resolve and the branch table would never see it. The recorded pid is 0, which
    /// `supervisor::signal_target` refuses to signal.
    pub async fn on_spawn_ready(
        &mut self,
        attempt: &AttemptId,
        result: Result<SpawnedProc, SpawnError>,
    ) {
        let cancel_requested = self.cancelled_spawn.remove(attempt);
        let Some(pending) = self.pending_spawn.remove(attempt) else {
            match result {
                // Nothing can be done with a child this process has no context for: it is already
                // detached and `kill_on_drop(false)` keeps it alive. Say so loudly — it holds a
                // worktree and spends budget.
                Ok(proc) => tracing::error!(
                    %attempt, pid = proc.pid,
                    "a worker started with no pending attempt to adopt it; it is now unsupervised"
                ),
                Err(err) => tracing::warn!(%attempt, %err, "spawn failure with no pending attempt"),
            }
            return;
        };
        match result {
            Ok(proc) => {
                // The child exists whatever the run's state is now, so it is adopted either way:
                // an unsupervised worker is the one outcome with no recovery. If the run stopped
                // accepting workers while the spawn was in flight, the supervisor is then told to
                // end the one it just took charge of.
                let run = pending.ctx.run;
                let agent = pending.ctx.agent;
                let adopted = self.supervisor.adopt(proc, pending.ctx, &mut self.registry);
                if cancel_requested {
                    tracing::info!(%attempt, %run, "a cancelled pending spawn arrived; adopting then cancelling");
                } else {
                    self.set_agent_status(
                        &run,
                        &agent,
                        AgentStatus::Running,
                        "a worker is running for this agent",
                    );
                }
                if cancel_requested || !self.run_accepts_workers(&run) {
                    if !cancel_requested {
                        tracing::info!(%attempt, %run, "the run stopped accepting workers mid-spawn; cancelling");
                    }
                    if let Err(err) = self
                        .supervisor
                        .cancel(&adopted.attempt_id, CancelBy::Lead, &mut self.registry)
                        .await
                    {
                        tracing::warn!(%attempt, %err, "the mid-spawn cancellation found nothing to end");
                    }
                }
            }
            Err(err) => {
                let error = AttemptError {
                    code: ErrorCode::SpawnError,
                    message: err.to_string(),
                };
                self.fail_attempt(&pending, AttemptStatus::SpawnFailed, error);
            }
        }
    }

    // -----------------------------------------------------------------------
    // send_message / retry_fresh
    // -----------------------------------------------------------------------

    /// Sends a follow-up turn to a live agent by resuming its provider session.
    ///
    /// `strike` is the design's parameter and it does what it says: `true` records a
    /// `lineage.strike` for the agent's lineage first. Every caller inside this module passes
    /// `false` — 17b strikes *before* it decides whether to repair or replace (the count is what
    /// decides), and a denied gate is explicitly not a strike (decision 6) — so it exists for a
    /// door that wants the two in one call.
    ///
    /// A rejection is a **value**, not an error: `core::loop` branches on it, and a run that cannot
    /// resume its builder becomes `run.status{blocked}` rather than propagating anything to a door.
    pub async fn send_message(&mut self, agent: &AgentId, msg: &str, strike: bool) -> SendResult {
        let Some(handle) = self.registry.agent(agent) else {
            return SendResult::Rejected {
                code: PolicyCode::AgentNotResumable,
                reason: format!("no agent {agent} with a resumable session"),
            };
        };
        if handle.role == RoleName::Lead {
            if let Some(busy) = self.live_lead_agent() {
                return SendResult::Rejected {
                    code: PolicyCode::LeadBusy,
                    reason: format!("lead agent {busy} already has a live attempt"),
                };
            }
        }
        let (run, lineage, role) = (handle.run_id, handle.lineage_id, handle.role);
        if role == RoleName::Security {
            return SendResult::Rejected { code: PolicyCode::DelegationNotAllowed,
                reason: "security checks are single-use inspections; change the input and start a new check through the workflow".into() };
        }
        if role != RoleName::Lead && self.registry.run(&run).is_some_and(|r| r.audit.is_some()) {
            return SendResult::Rejected { code: PolicyCode::DelegationNotAllowed,
                reason: "audit checks cannot be resumed or repaired; start a new audit for new input".into() };
        }
        let spawn_cap = self
            .roles
            .roles
            .get(&handle.role)
            .map_or(self.roles.defaults.spawn_budget_usd, |r| r.spawn_budget_usd);

        if strike {
            let Some(lineage) = lineage else {
                return SendResult::Rejected {
                    code: PolicyCode::AgentNotResumable,
                    reason: "a lead has no worker lineage to strike".to_string(),
                };
            };
            let strikes = self.lineage_strikes(&run, &lineage).saturating_add(1);
            self.emit(
                &run,
                EventPayload::LineageStrike {
                    lineage_id: lineage,
                    agent_id: *agent,
                    reason: "a follow-up turn was sent with a strike".to_string(),
                    strikes,
                },
            );
        }

        let attempt = AttemptId::new_v4();
        match self.resume_attempt(*agent, attempt, msg.to_string(), spawn_cap) {
            Ok(()) => {
                // The human's half of a lead conversation becomes durable the moment it is
                // accepted (B3 walkthrough fix). Keyed on the *target's* role: every door that
                // can reach an idle lead today is the human's (the app, `acp send`), workers
                // carry no MCP config, and a lead's own send to itself is `lead_busy` while it
                // lives — so a lead-bound send is a human turn, and a worker-bound send is the
                // loop's own repair instruction, never a transcript turn. The text is stored
                // whole, exactly as `lead.start` stores the first message in `run.created` — the
                // door has already bounded it — and a rejected send records nothing.
                if role == RoleName::Lead {
                    self.emit(
                        &run,
                        EventPayload::AgentMessage {
                            attempt_id: attempt,
                            src_line: 0,
                            role: MessageRole::User,
                            text: msg.to_string(),
                            part: None,
                        },
                    );
                }
                SendResult::Ok { attempt }
            }
            Err(err) => {
                self.registry.audit(AuditEntry::new(
                    "send_message",
                    err.code.as_str(),
                    &err.reason,
                    agent.to_string(),
                ));
                SendResult::Rejected {
                    code: err.code,
                    reason: err.reason,
                }
            }
        }
    }

    /// Records a cancellation that arrives before `spawn_detached` has returned. The helper must
    /// still deliver its child so [`on_spawn_ready`](Self::on_spawn_ready) can adopt and terminate
    /// it safely; removing the pending context would deliberately create an unsupervised process.
    /// Marking the agent cancelled is also the durable restart guard against reissuing the intent.
    ///
    /// # Errors
    /// [`CoreError::Registry`] if the cancellation status cannot be made durable, or
    /// [`CoreError::Policy`] if a pending spawn has lost its projected agent.
    pub fn cancel_pending_spawns(&mut self, agent: &AgentId) -> Result<bool, CoreError> {
        let attempts: Vec<AttemptId> = self
            .pending_spawn
            .iter()
            .filter_map(|(attempt, pending)| (pending.agent() == *agent).then_some(*attempt))
            .collect();
        if attempts.is_empty() {
            return Ok(false);
        }
        let run = self
            .registry
            .agent(agent)
            .map(|handle| handle.run_id)
            .ok_or_else(|| {
                CoreError::Policy(PolicyError::new(
                    PolicyCode::AgentNotResumable,
                    format!("pending spawn has no agent {agent} in the durable registry"),
                ))
            })?;
        self.registry.append(
            &run,
            EventPayload::AgentStatusChanged {
                agent_id: *agent,
                status: AgentStatus::Cancelled,
                reason: Some("the provider spawn was cancelled before adoption".to_string()),
            },
        )?;
        self.cancelled_spawn.extend(attempts);
        Ok(true)
    }

    /// 17c: a fresh session in the **inherited** worktree (decision 8).
    ///
    /// Nothing is cleaned, reset or discarded — the whole point of the branch is that the dead
    /// session's work is still there, so `git status --porcelain` is read and quoted into the new
    /// worker's prompt as data. The old handle is closed first: it is a writing agent in that
    /// worktree, and `check_delegate`'s one-writer rule (C5) would otherwise refuse the retry on
    /// account of the agent it is replacing.
    ///
    /// **The git read happens off the actor** (Codex review of T35, finding 3). Everything durable
    /// — the closed handle and the new `agent.created` — is appended here, in the branch's own
    /// turn, so the marker that follows still means "the branch is done"; the worktree read goes to
    /// [`Core::spawn_porcelain_helper`] and comes back as [`Command::RetryFreshReady`], and the
    /// spawn it starts is what [`Core::reconcile_intents`] reissues if the daemon dies in between.
    /// A wedged git therefore costs this run its next turn and no other run anything at all.
    ///
    /// `async` is kept because the design's signature has it and because
    /// [`Core::on_attempt_finished`] awaits it; nothing inside it waits on I/O any more.
    pub async fn retry_fresh(&mut self, lineage: &LineageId) -> SendResult {
        let Some((run, prior)) = self.lineage_target(lineage) else {
            return SendResult::Rejected {
                code: PolicyCode::ResumeTargetMissing,
                reason: format!("no lineage {lineage} to retry"),
            };
        };
        let Some(task) = self.task_of(&run) else {
            return SendResult::Rejected {
                code: PolicyCode::ResumeTargetMissing,
                reason: format!("no run {run}"),
            };
        };

        // The old handle is closed **before** the policy check, not after: it is a writing agent in
        // this worktree and `check_delegate`'s one-writer rule (C5) exempts only the agent whose
        // session is being *resumed*, which is precisely what 17c cannot do. Closing it first is
        // also honest — the branch has already established that its session is gone — and a
        // rejection below then leaves a closed handle and a blocked run rather than a phantom
        // writer that keeps every future retry out of the worktree.
        self.emit(
            &run,
            EventPayload::AgentStatusChanged {
                agent_id: prior.agent,
                status: AgentStatus::Closed,
                reason: Some(
                    "the provider session cannot be resumed; a fresh session inherits the worktree"
                        .to_string(),
                ),
            },
        );

        let request = DelegateRequest {
            run_id: Some(run),
            role: RoleName::Builder,
            task,
            model: None,
            session: SessionSpec::Fresh,
            base_ref: None,
            worktree: Some(prior.worktree.clone()),
            steps: None,
            // Internal (a replacement the loop itself decided on), not a lead's own delegate call.
            caller_run_id: None,
        };
        let resolved = match self.resolve_internal(&request) {
            Ok(resolved) => resolved,
            Err(err) => {
                return SendResult::Rejected {
                    code: err.code,
                    reason: err.reason,
                }
            }
        };

        let agent = AgentId::new_v4();
        let attempt = AttemptId::new_v4();
        self.emit(
            &run,
            EventPayload::AgentCreated {
                agent_id: agent,
                role: RoleName::Builder,
                provider: resolved.provider,
                model: resolved.model.clone(),
                lineage_id: Some(*lineage),
                depth: resolved.depth,
                parent_agent_id: Some(prior.agent),
                origin: Origin::ControlPlane,
                writes: resolved.writes,
                cwd: prior.worktree.clone(),
                worktree: Some(prior.worktree.clone()),
            },
        );

        // The id the caller is answered with is the one the porcelain handler will start, so a
        // lead that polls `await_result` on it is waiting for the attempt that actually runs.
        self.pending_retry.insert(agent, attempt);
        self.spawn_porcelain_helper(agent, prior.worktree);
        SendResult::Ok { attempt }
    }

    /// The second half of 17c: the inherited worktree's `git status`, and the spawn it feeds.
    ///
    /// Idempotent in both directions. An agent that already has an attempt is left alone — a
    /// duplicate completion, or a reconciler that raced this one, must not start a second worker —
    /// and an agent whose id the pending map has lost (a restart) still spawns, with a fresh
    /// attempt id, because nothing durable ever named the old one.
    pub fn on_retry_fresh_ready(&mut self, agent: &AgentId, porcelain: Result<String, GitError>) {
        let attempt = self
            .pending_retry
            .remove(agent)
            .unwrap_or_else(AttemptId::new_v4);
        let Some(handle) = self.registry.agent(agent) else {
            tracing::warn!(%agent, "a worktree status came back for an agent this state dir lost");
            return;
        };
        let (run, worktree) = (
            handle.run_id,
            handle
                .worktree
                .clone()
                .unwrap_or_else(|| handle.cwd.clone()),
        );
        let parent = handle.parent_agent_id;

        // The worktree read may have taken the whole `GIT_OP_TIMEOUT`, and the run may have been
        // cancelled, blocked or integrated in the meantime — or the retry may already have been
        // started by a reconciler that ran while this was in flight.
        if !self.agent_accepts_a_spawn(agent)
            || self
                .registry
                .run(&run)
                .is_none_or(|r| r.loop_state != LoopState::Retrying)
        {
            tracing::info!(%agent, "the worktree status is stale; no retry was started");
            return;
        }

        let status = match porcelain {
            Ok(status) => status,
            Err(err) => {
                // The prompt would have to lie about what is in the worktree, so the branch ends
                // here rather than guessing (design: a git fault blocks the affected run).
                self.block_run(
                    &run,
                    &format!(
                        "the inherited worktree {} could not be read: {err}",
                        worktree.display()
                    ),
                );
                return;
            }
        };
        let Some(task) = self.task_of(&run) else {
            self.block_run(&run, "the run has no task on record to retry");
            return;
        };
        let last_error = parent.and_then(|parent| self.last_attempt_error(&parent));
        let mut prompt = handoff::build_retry_prompt(&task, &status, last_error.as_ref());
        if let Some(record) = self.registry.events(&run, None, usize::MAX).iter().find_map(|e| match &e.payload {
            EventPayload::RunRecovered { recovery } if recovery.agent_id == *agent => Some(recovery.clone()),
            _ => None,
        }) {
            let findings = vec![ReviewFinding { severity: Severity::Blocking, file: None, line: None,
                problem: record.request.feedback, fix: None }];
            prompt.push_str("\nHuman-confirmed recovery. Preserve useful existing changes and complete the task. All selected checks will run again.\n");
            prompt.push_str(&handoff::build_repair_prompt(&findings, &task));
        }

        let Some(spawn) = self.spawn_for_agent(agent, attempt, prompt) else {
            self.block_run(&run, "the retry agent is not startable from the log");
            return;
        };
        if let Err(err) = self.start_attempt(spawn) {
            self.block_run(
                &run,
                &format!("the retry could not be started: {}", err.reason),
            );
        }
    }

    // -----------------------------------------------------------------------
    // on_attempt_finished — the branch table (step 17)
    // -----------------------------------------------------------------------

    /// Reacts to one terminal attempt, exactly once, and never fails.
    ///
    /// There is no `Result` by design (C1): every internal failure this can meet — a git fault, a
    /// policy rejection of the next spawn, a log that will not take an append — becomes
    /// `run.status{blocked, reason}` or a warning, because there is no caller to hand an error to.
    /// The `Command::Tick` that swept the attempt is long gone by the time a branch runs.
    pub async fn on_attempt_finished(&mut self, attempt: AttemptId) {
        if self.registry.attempt(&attempt).and_then(|a| self.registry.run(&a.run_id))
            .is_some_and(|r| r.status == RunStatus::Cancelled) { return; }
        if self.registry.attempt(&attempt).and_then(|a| self.registry.run(&a.run_id)).is_some_and(|r| r.audit.is_some()) {
            self.mark_idle(&attempt);
            self.audit_attempt_finished(attempt);
            return;
        }
        // Classify before building the snapshot: the "nothing to do" answer is reached on every
        // tick for the rest of the run's life (see `Branch::None` below), and it must not cost a
        // pass over the run's log to reach it.
        let Some(branch) = self
            .registry
            .attempt(&attempt)
            .filter(|a| is_terminal(a.status))
            .and_then(|a| {
                let role = self.registry.agent(&a.agent_id)?.role;
                Some(branch_of(role, a.status, a.error.as_ref()))
            })
        else {
            tracing::debug!(%attempt, "no terminal attempt to dispatch");
            return;
        };
        // Steps 13/15: an agent whose attempt has ended is no longer running. It is appended
        // before the branch, so it is true for every terminal attempt rather than only the ones a
        // branch happens to touch, and it is **not** a consequence marker: no `*_since` predicate
        // matches `agent.status`, and `loop_dispatch` remains the only restart oracle, so writing
        // it says nothing about whether the branch below has run.
        self.mark_idle(&attempt);
        if branch == Branch::None {
            // A cancelled or lost attempt: a human owns what happens next (design, § Error
            // Handling), so no branch runs and no marker is written. The attempt stays "owed" and
            // is offered again on the next tick, which is the honest state — nothing durable has
            // been decided about it — and costs the two lookups above.
            tracing::debug!(%attempt, "the loop has nothing to do with this attempt");
            return;
        }
        let Some(f) = self.finished(&attempt) else {
            tracing::debug!(%attempt, "no terminal attempt to dispatch");
            return;
        };
        match branch {
            Branch::Environment => self.branch_environment(&f),
            Branch::Escalate => self.branch_escalate(&f),
            Branch::Review => self.branch_review(&f).await,
            Branch::Reviewer => self.branch_reviewer(&f).await,
            Branch::Verify => self.branch_verify(&f).await,
            Branch::Strike => {
                let Some(target) = self.target_of(&f.agent) else {
                    self.block_run(&f.run, "the attempt names an agent this state dir has lost");
                    self.mark(&f, LoopBranch::Resume);
                    return;
                };
                let cause = StrikeCause::Failure(f.error.clone());
                self.branch_strike(&f, &target, cause).await;
            }
            Branch::Lead => self.mark(&f, LoopBranch::Lead),
            // Answered above, before the snapshot was built.
            Branch::None => {}
        }
    }

    /// 17a — an environment failure. **No strike**: the model did nothing wrong and a repair
    /// attempt would fail identically until a human installs or logs into the CLI.
    fn branch_environment(&mut self, f: &Finished) {
        let reason = f.error.as_ref().map_or_else(
            || "the provider CLI could not be started".to_string(),
            |err| format!("{}: {}", error_key(err.code), err.message),
        );
        self.block_run(&f.run, &reason);
        self.mark(f, LoopBranch::Environment);
    }

    /// A denylist hit (step 11) or an unverifiable workspace: an `escalate` gate and a blocked run,
    /// with **no strike** — the first is a rule a human owns, the second is our own blindness.
    fn branch_escalate(&mut self, f: &Finished) {
        let reason = f.error.as_ref().map_or_else(
            || "the attempt touched a denied path; a human has to decide".to_string(),
            |err| format!("{}: {}", error_key(err.code), err.message),
        );
        if !self.gate_since(&f.run, f.finish_seq) {
            let summary = format!(
                "An attempt was stopped and needs a human decision.\n\n{}\n\n{}",
                reason,
                self.violation_summary(&f.agent)
            );
            self.open_gate(&f.run, GateKind::Escalate, &summary, GatePayload::default());
        }
        self.block_run(&f.run, &reason);
        self.mark(f, LoopBranch::Gate);
    }

    /// Steps 13-14: the builder succeeded, so the frozen diff goes to a fresh reviewer.
    ///
    /// Rev 25(1) is enforced twice on purpose. `finalize_prepare` turns a success with an empty
    /// diff into `invalid_output{no_changed_files}` *before* `attempt.finished`, because the
    /// reducer keeps the first terminal status it sees; this is the second gate on the same rule,
    /// for a success that arrives with no `diff.frozen` at all — a reviewer is never started for a
    /// diff that does not exist.
    async fn branch_review(&mut self, f: &Finished) {
        let frozen = self
            .frozen_diff(&f.run, &f.attempt)
            .filter(|d| !d.files.is_empty());
        let Some(frozen) = frozen else {
            let error = AttemptError {
                code: ErrorCode::NoChangedFiles,
                message: "the attempt reported success but changed no files".to_string(),
            };
            self.emit(
                &f.run,
                EventPayload::AttemptFinished {
                    attempt_id: f.attempt,
                    status: AttemptStatus::InvalidOutput,
                    exit_code: None,
                    signal: None,
                    post_sha: None,
                    duration_ms: 0,
                    error: Some(error.clone()),
                },
            );
            let Some(target) = self.target_of(&f.agent) else {
                self.block_run(&f.run, "the attempt names an agent this state dir has lost");
                self.mark(f, LoopBranch::Resume);
                return;
            };
            self.branch_strike(f, &target, StrikeCause::Failure(Some(error)))
                .await;
            return;
        };

        // B1: when the config carries a verifier, the diff is verified before it is reviewed.
        // A config without one keeps the Phase-1 path byte-for-byte. The reviewer guard covers
        // the mid-upgrade window (T64 review F6): a run whose reviewer was already started under
        // a pre-verifier config must not sprout a verifier on re-drive. B3 adds the run's own
        // captured switch: a team that dropped the verifier skips straight past the step.
        if self.verifier_configured()
            && self.run_steps(&f.run).verify
            && !self.reviewer_created_since(&f.run, f.finish_seq)
        {
            if !self.verifier_created_since(&f.run, f.finish_seq) {
                if let Err(err) = self.start_verifier(&f.run, f.agent, &frozen) {
                    let reason = format!("the verifier could not be started: {}", err.reason);
                    self.block_run(&f.run, &reason);
                }
            }
            self.mark(f, LoopBranch::Verify);
            return;
        }
        // B3 role subsets: a team without a reviewer sends the diff straight to the human gate.
        // The gate is the review then — mandatory as ever (S2) and loud about what did not run.
        if !self.run_steps(&f.run).review {
            self.open_integrate_gate(f, &frozen, false);
            self.mark(f, LoopBranch::Gate);
            return;
        }
        if !self.reviewer_created_since(&f.run, f.finish_seq) {
            if let Err(err) = self.start_reviewer(&f.run, f.agent, &frozen) {
                let reason = format!("the reviewer could not be started: {}", err.reason);
                self.block_run(&f.run, &reason);
            }
        }
        self.mark(f, LoopBranch::Review);
    }

    /// Steps 15-16 and Rev 25(3): what one reviewer attempt bought.
    ///
    /// A `PASS` opens the integrate gate **only** when its `diffHash` is the hash of the diff the
    /// reviewer was shown. Anything else — a wrong hash, an unparseable verdict, a crashed reviewer
    /// — buys one fresh reviewer, and then the run blocks. The builder is never struck for a
    /// reviewer's failure; a `FAIL`, which is a judgement rather than a failure, goes to 17b.
    async fn branch_reviewer(&mut self, f: &Finished) {
        let security = self.review_role(f) == RoleName::Security;
        let Some(frozen) = self.reviewed_diff(f) else {
            self.block_run(
                &f.run,
                "a reviewer finished with no frozen diff on record to bind its verdict to",
            );
            self.mark(f, LoopBranch::Review);
            return;
        };
        if self.run_steps(&f.run).security && !security::current_builder_diff(&self.registry, &f.run, frozen.attempt) {
            self.mark(f, LoopBranch::Review);
            return;
        }
        let verdict = f
            .structured
            .clone()
            .filter(|_| f.status == AttemptStatus::Succeeded)
            .and_then(|v| serde_json::from_value::<ReviewVerdict>(v).ok());

        let Some(mut verdict) = verdict else {
            let reason = f.error.as_ref().map_or_else(
                || "the reviewer produced no verdict".to_string(),
                |err| format!("{}: {}", error_key(err.code), err.message),
            );
            self.retry_reviewer(f, &frozen, &reason);
            return;
        };

        if security && verdict.findings.iter().any(|f| f.severity == Severity::Blocking) {
            verdict.verdict = Verdict::Fail;
        }
        if !security && !self.verdict_since(&f.run, f.finish_seq) {
            self.emit(
                &f.run,
                EventPayload::ReviewVerdict {
                    attempt_id: f.attempt,
                    builder_attempt_id: frozen.attempt,
                    verdict: verdict.verdict,
                    findings: verdict.findings.clone(),
                    diff_hash: Some(verdict.diff_hash.clone()),
                },
            );
        }

        if verdict.diff_hash != frozen.hash {
            // The verdict cannot be shown to be about the diff we froze, so it decides nothing.
            self.emit(
                &f.run,
                EventPayload::AttemptFinished {
                    attempt_id: f.attempt,
                    status: AttemptStatus::InvalidOutput,
                    exit_code: None,
                    signal: None,
                    post_sha: None,
                    duration_ms: 0,
                    error: Some(AttemptError {
                        code: ErrorCode::DiffHashMismatch,
                        message: format!(
                            "the verdict echoed diffHash {} but the frozen diff hashes to {}",
                            clamp_untrusted(&verdict.diff_hash, 64),
                            frozen.hash
                        ),
                    }),
                },
            );
            self.retry_reviewer(f, &frozen, "the reviewer echoed the wrong diffHash");
            return;
        }

        if verdict.verdict == Verdict::Pass {
            if security && !self.persist_security_verdict(f, &frozen, &verdict) { return; }
            self.open_integrate_gate(f, &frozen, !security || self.run_steps(&f.run).review);
            self.mark(f, LoopBranch::Gate);
            return;
        }

        // FAIL: the builder is struck and repaired, in the builder's own lineage.
        if security && !self.persist_security_verdict(f, &frozen, &verdict) { return; }
        let Some(builder) = f.parent.and_then(|agent| self.target_of(&agent)) else {
            self.block_run(
                &f.run,
                "the review failed and the builder it reviewed is no longer on record",
            );
            self.mark(f, LoopBranch::Resume);
            return;
        };
        self.branch_strike(f, &builder, StrikeCause::ReviewFail(verdict.findings))
            .await;
    }

    /// 17b / 17c / 17d: strike the lineage, then repair it, retry it, or replace it.
    ///
    /// The strike is appended first because its *count* is what chooses the branch, and it is
    /// appended only once per finished attempt: a re-drive of this branch after a crash sees the
    /// strike it already wrote in the window after `attempt.finished` and does not add a second.
    async fn branch_strike(&mut self, f: &Finished, target: &Target, cause: StrikeCause) {
        let cap = self.roles.defaults.strikes_before_replacement;
        let already = self.struck_since(&f.run, f.finish_seq, &target.lineage);
        let strikes = if already {
            target.strikes
        } else {
            target.strikes.saturating_add(1)
        };
        if !already {
            self.emit(
                &f.run,
                EventPayload::LineageStrike {
                    lineage_id: target.lineage,
                    agent_id: target.agent,
                    reason: strike_reason(&cause),
                    strikes,
                },
            );
        }

        if strikes >= cap {
            self.branch_replace(f, target, &cause, strikes);
            return;
        }

        let resumable = target.resumable && target.session.is_some() && target.cwd.is_dir();
        if resumable {
            self.emit(&f.run, loop_state(LoopState::Repairing, target, strikes));
            if !self.attempt_started_since(&f.run, f.finish_seq, &target.agent) {
                // No task, no prompt: a worker is never spawned with an empty one, so a run whose
                // `run.created` is missing blocks here rather than starting a turn about nothing.
                let Some(task) = self.task_of(&f.run) else {
                    self.block_run(&f.run, "the run has no task on record to repair against");
                    self.mark(f, LoopBranch::Resume);
                    return;
                };
                let prompt = match &cause {
                    StrikeCause::ReviewFail(findings) => {
                        handoff::build_repair_prompt(findings, &task)
                    }
                    // B1: the verifier's failure text, verbatim, is the repair instruction.
                    StrikeCause::VerifyFail(report) => {
                        handoff::build_verify_repair_prompt(report, &task)
                    }
                    StrikeCause::Failure(err) => {
                        let err = err.clone().unwrap_or_else(unknown_failure);
                        handoff::build_failure_repair_prompt(&err, &task)
                    }
                };
                match self.send_message(&target.agent, &prompt, false).await {
                    SendResult::Ok { .. } => {}
                    SendResult::Rejected { code, reason } => {
                        self.block_run(&f.run, &format!("{code}: {reason}"));
                    }
                }
            }
            self.mark(f, LoopBranch::Resume);
            return;
        }

        self.emit(&f.run, loop_state(LoopState::Retrying, target, strikes));
        if !self.agent_created_since(&f.run, f.finish_seq, RoleName::Builder) {
            match self.retry_fresh(&target.lineage).await {
                SendResult::Ok { .. } => {}
                SendResult::Rejected { code, reason } => {
                    self.block_run(&f.run, &format!("{code}: {reason}"));
                }
            }
        }
        self.mark(f, LoopBranch::RetryFresh);
    }

    /// 17d: the lineage is out of strikes. Close it, retire its worktree, and either start a fresh
    /// lineage or — for the second lineage to burn out, or a run already at `maxLineages` — open an
    /// `escalate` gate and stop.
    ///
    /// The retired worktree is left on disk. It holds two strikes' worth of work a human may want
    /// to read, and nothing else will ever write in it: the record says `resumable: false` and the
    /// replacement gets a directory of its own.
    fn branch_replace(&mut self, f: &Finished, target: &Target, cause: &StrikeCause, strikes: u8) {
        if !self.closed_since(&f.run, f.finish_seq, &target.lineage) {
            self.emit(
                &f.run,
                EventPayload::LineageClosed {
                    lineage_id: target.lineage,
                    reason: format!("out of strikes after {strikes}"),
                },
            );
            self.emit(
                &f.run,
                EventPayload::WorktreeRetired {
                    path: target.worktree.clone(),
                    reason: format!("the lineage was closed after {strikes} strikes"),
                    resumable: False,
                },
            );
            self.emit(
                &f.run,
                EventPayload::AgentStatusChanged {
                    agent_id: target.agent,
                    status: AgentStatus::Closed,
                    reason: Some("the lineage is out of strikes".to_string()),
                },
            );
        }

        let max_lineages = usize::from(self.roles.defaults.max_lineages);
        let (burnt, lineages) = self.registry.run(&f.run).map_or((0, 0), |run| {
            (
                run.lineages.iter().filter(|l| l.closed).count(),
                run.lineages.len(),
            )
        });
        if burnt >= 2 || lineages >= max_lineages {
            let reason = format!(
                "{burnt} of {lineages} lineages are out of strikes; the task needs a human"
            );
            if !self.gate_since(&f.run, f.finish_seq) {
                let summary = format!(
                    "Two builder lineages failed review on this task.\n\n{}\n\n{}",
                    reason,
                    self.violation_summary(&target.agent)
                );
                self.open_gate(&f.run, GateKind::Escalate, &summary, GatePayload::default());
            }
            self.block_run(&f.run, &reason);
            self.mark(f, LoopBranch::Replace);
            return;
        }

        self.emit(&f.run, loop_state(LoopState::Replacing, target, strikes));
        if !self.agent_created_since(&f.run, f.finish_seq, RoleName::Builder) {
            if let Err(err) = self.start_replacement(f, target, cause) {
                let reason = format!("a replacement builder could not be started: {}", err.reason);
                self.block_run(&f.run, &reason);
            }
        }
        self.mark(f, LoopBranch::Replace);
    }

    // -----------------------------------------------------------------------
    // on_gate_resolved (steps 18-19)
    // -----------------------------------------------------------------------

    /// What a resolved gate does to the run.
    ///
    /// An approval is the end of the loop: the commit is already recorded by `gates::finish_commit`
    /// and this writes the run's own conclusion. A denial resumes the live builder with the human's
    /// feedback and **no strike** (decision 6) — a human asking for a change is not a failure of the
    /// model — and blocks the run when there is no session left to resume.
    pub async fn on_gate_resolved(&mut self, gate: GateId, r: &GateResolution) {
        let Some(run) = self.registry.gate(&gate).map(|g| g.run_id) else {
            tracing::warn!(%gate, "resolution for a gate this state dir does not know");
            return;
        };
        if self.registry.run(&run).is_some_and(|r| r.status == RunStatus::Cancelled) { return; }
        let kind = self.registry.gate(&gate).map(|g| g.kind);
        match r {
            GateResolution::Approved { .. } => {
                // Only an integrate approval concludes its run. A `plan` (or `escalate`) approval
                // is an answered question: the conductor reads the gate itself on the poke below.
                if kind == Some(GateKind::Integrate) {
                    if self.registry.run(&run).map(|r| r.status) == Some(RunStatus::Integrated) {
                        self.drive_plans();
                        return;
                    }
                    self.emit(
                        &run,
                        EventPayload::RunStatus_ {
                            status: RunStatus::Integrated,
                            reason: None,
                        },
                    );
                    self.emit(
                        &run,
                        EventPayload::LoopStateChanged {
                            state: LoopState::Done,
                            builder_agent_id: self.live_builder(&run),
                            attempt_no: 0,
                            strikes: 0,
                        },
                    );
                }
                self.drive_plans();
            }
            GateResolution::Denied { feedback } => {
                let Some(agent) = self.live_builder(&run) else {
                    self.block_run(
                        &run,
                        "the gate was denied and no builder session is live to act on it",
                    );
                    return;
                };
                let Some(task) = self.task_of(&run) else {
                    self.block_run(
                        &run,
                        "the gate was denied and the run has no task on record",
                    );
                    return;
                };
                let Some(target) = self.target_of(&agent) else {
                    self.block_run(&run, "the gate was denied and its builder is not on record");
                    return;
                };
                // **The run goes back to `running` before anything is started in it.** Step 16 left
                // it `awaiting_gate`, and every deferred spawn asks `run_accepts_workers` — which
                // is `status == Running` — immediately before adopting its child. Resuming the
                // builder without this wrote `attempt.started` and then cancelled the worker it had
                // just adopted, one turn later, leaving the run parked for ever behind a gate that
                // was already answered. The three appends are the design's step-19 order:
                // `gate.resolved` (already durable, written by `gates::begin_resolve`) →
                // `run.status{running}` → `loop.state{repairing}` → the resume.
                //
                // Guarded on the status it is undoing, so a re-drive cannot resurrect a run that
                // has since been blocked, cancelled or integrated.
                if self.registry.run(&run).map(|r| r.status) == Some(RunStatus::AwaitingGate) {
                    self.emit(
                        &run,
                        EventPayload::RunStatus_ {
                            status: RunStatus::Running,
                            reason: None,
                        },
                    );
                }
                self.emit(
                    &run,
                    loop_state(LoopState::Repairing, &target, target.strikes),
                );
                // The human's words are untrusted text like any other: they travel as one blocking
                // finding inside the advisory block `build_repair_prompt` wraps (S3).
                let findings = vec![ReviewFinding {
                    severity: Severity::Blocking,
                    file: None,
                    line: None,
                    problem: feedback
                        .clone()
                        .unwrap_or_else(|| "the human denied this gate".to_string()),
                    fix: None,
                }];
                let prompt = handoff::build_repair_prompt(&findings, &task);
                if let SendResult::Rejected { code, reason } =
                    self.send_message(&agent, &prompt, false).await
                {
                    self.block_run(&run, &format!("{code}: {reason}"));
                }
            }
            GateResolution::AlreadyResolved => {}
        }
    }

    // -----------------------------------------------------------------------
    // Restart reconciliation
    // -----------------------------------------------------------------------

    /// Reissues the helper work a branch had started but not finished when the daemon stopped.
    ///
    /// **Why this exists.** `loop.dispatched` is appended as the last event of a branch and it
    /// stops that branch from ever running again — which is exactly right for the branch's durable
    /// decisions (never strike twice, never open a second gate) and exactly wrong for the helper
    /// task it hands off to. A daemon that exits between the marker and `WorktreeReady` /
    /// `SpawnReady` loses `pending_worktree` / `pending_spawn` with the process, and the marker
    /// then guarantees nobody looks again: the run sits in `replacing` for ever, or an
    /// `agent.created` never gets an attempt (Codex review of T35, finding 2).
    ///
    /// The fix is not another event kind — the union stays at 24 — but a **re-read of the log**:
    /// the two intents above are both visible as a gap in it, and closing them is idempotent
    /// because the log is what says whether they are still open.
    ///
    /// Three rules, and nothing else:
    ///
    /// * **(a) an agent with no attempt.** `agent.created`, not closed, no `attempt.started`, no
    ///   entry in this process's pending maps → the spawn it was created for never happened, so it
    ///   is issued again. The prompt is rebuilt from the log exactly as the branch built it, which
    ///   is possible because every input is in there: a reviewer's from the frozen diff of the
    ///   builder it was created under; a replacement's from the closed lineage's findings and
    ///   files; a retry's from the inherited worktree (via the same `status_porcelain` helper 17c
    ///   uses); a first builder's from the task.
    /// * **(b) a run stuck mid-repair.** The newest `loop.state` is `repairing`, the run carries a
    ///   `loop.dispatched{17b}`, and the live builder has started nothing since it → the resume
    ///   helper never reported, so the repair turn is sent again with the prompt the branch built.
    /// * **(c) a run stuck mid-replacement.** The newest `loop.state` is `replacing`, a lineage was
    ///   closed, and no `worktree.created` followed it → 17d's worktree helper never reported, so
    ///   the replacement is started again from the log's own record of what was abandoned.
    ///
    /// Called from [`Core::new`] (when a runtime is present to spawn into) and from the first
    /// [`Command::Tick`], so a `Core` built outside a runtime still reconciles a moment later.
    /// Running it twice is a no-op: the first pass fills the pending maps, and the second sees them.
    pub fn reconcile_intents(&mut self) {
        self.drive_audits();
        for agent in self.agents_owed_a_spawn() {
            self.reissue_spawn(&agent);
        }
        for owed in self.resumes_owed() {
            self.reissue_resume(&owed);
        }
        for run in self.runs_owed_a_replacement() {
            self.reissue_replacement(&run);
        }
        // B3: plans resume the same way every branch does — from the replayed log. Items whose
        // runs exist re-drive through those runs' own markers; a `started` item whose delegate
        // died before `run.created` is reissued inside the drive.
        self.drive_plans();
    }

    /// Agents the log says were announced and never started, oldest first.
    ///
    /// A run that is not `running` is skipped: a blocked, integrated or cancelled run must never
    /// have a worker started behind it by a restart.
    fn agents_owed_a_spawn(&self) -> Vec<AgentId> {
        let pending_spawn: Vec<AgentId> = self
            .pending_spawn
            .values()
            .map(|pending| pending.agent())
            .collect();
        let mut owed: Vec<(&str, AgentId)> = self
            .registry
            .state()
            .agents
            .values()
            .filter(|agent| agent.attempt_ids.is_empty())
            .filter(|agent| !matches!(agent.status, AgentStatus::Closed | AgentStatus::Cancelled))
            .filter(|agent| !pending_spawn.contains(&agent.agent_id))
            .filter(|agent| !self.pending_retry.contains_key(&agent.agent_id))
            .filter(|agent| {
                self.registry
                    .run(&agent.run_id)
                    .is_some_and(|run| run.status == RunStatus::Running && run.audit.is_none())
            })
            .map(|agent| (agent.created_at.as_str(), agent.agent_id))
            .collect();
        owed.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.as_uuid().cmp(b.1.as_uuid())));
        owed.into_iter().map(|(_, id)| id).collect()
    }

    /// Starts the spawn `agent.created` promised, with the prompt its branch would have built.
    pub(super) fn reissue_spawn(&mut self, agent: &AgentId) {
        if !self.agent_accepts_a_spawn(agent) {
            return;
        }
        let Some(handle) = self.registry.agent(agent) else {
            return;
        };
        let (run, role, lineage, parent) = (
            handle.run_id,
            handle.role,
            handle.lineage_id,
            handle.parent_agent_id,
        );
        let inherited = self.inherits_its_worktree(agent);
        tracing::info!(%agent, ?role, "reissuing a spawn the log shows was never started");

        // 17c is the one intent whose prompt needs the worktree read: hand it to the same helper
        // the branch uses and let `on_retry_fresh_ready` finish it.
        if inherited {
            let worktree = handle
                .worktree
                .clone()
                .unwrap_or_else(|| handle.cwd.clone());
            self.pending_retry.insert(*agent, AttemptId::new_v4());
            self.spawn_porcelain_helper(*agent, worktree);
            return;
        }

        let Some(task) = self.task_of(&run) else {
            self.block_run(
                &run,
                "an agent is owed a spawn but the run has no task on record",
            );
            return;
        };
        let prompt = match role {
            RoleName::Reviewer | RoleName::Security => {
                let frozen = if self.run_steps(&run).security {
                    security::inspection_diff(&self.registry, &run, *agent)
                } else { parent
                    .and_then(|parent| self.registry.agent(&parent))
                    .map(|builder| builder.attempt_ids.clone())
                    .and_then(|attempts| self.newest_frozen(&run, &attempts))
                };
                let Some(frozen) = frozen else {
                    self.block_run(
                        &run,
                        "a reviewer is owed a spawn but the diff it was created for is not on record",
                    );
                    return;
                };
                if self.run_steps(&run).security && !security::current_builder_diff(&self.registry, &run, frozen.attempt) {
                    self.block_run(&run, "A recovered inspection's builder input was superseded; start a new task");
                    return;
                }
                let build = self
                    .registry
                    .attempt(&frozen.attempt)
                    .and_then(|a| a.structured.clone())
                    .and_then(|v| serde_json::from_value::<BuildResult>(v).ok());
                let verify = self.recorded_verify_report(&run, frozen.attempt);
                handoff::build_reviewer_prompt(
                    &task,
                    &frozen.path,
                    &frozen.hash,
                    build.as_ref(),
                    verify.as_ref(),
                )
            }
            // B1: same reconstruction as the reviewer arm above, with the verifier's prompt.
            RoleName::Verifier => {
                let frozen = if self.run_steps(&run).security {
                    security::inspection_diff(&self.registry, &run, *agent)
                } else { parent
                    .and_then(|parent| self.registry.agent(&parent))
                    .map(|builder| builder.attempt_ids.clone())
                    .and_then(|attempts| self.newest_frozen(&run, &attempts))
                };
                let Some(frozen) = frozen else {
                    self.block_run(
                        &run,
                        "a verifier is owed a spawn but the diff it was created for is not on record",
                    );
                    return;
                };
                if self.run_steps(&run).security && !security::current_builder_diff(&self.registry, &run, frozen.attempt) {
                    self.block_run(&run, "A recovered inspection's builder input was superseded; start a new task");
                    return;
                }
                let build = self
                    .registry
                    .attempt(&frozen.attempt)
                    .and_then(|a| a.structured.clone())
                    .and_then(|v| serde_json::from_value::<BuildResult>(v).ok());
                handoff::build_verifier_prompt(&task, &frozen.path, &frozen.hash, build.as_ref())
            }
            // A builder whose parent belongs to a **closed** lineage is 17d's replacement; one with
            // no parent at all is a lead's first builder.
            RoleName::Lead => lead_setup_prompt(&task.description, self.registry.run(&run).and_then(|r| r.execution.as_ref())),
            RoleName::Builder => match parent {
                Some(parent) if self.lineage_of(&parent) != lineage => {
                    let (findings, files) = self.abandoned_context(&run, &parent);
                    handoff::build_replacement_prompt(&task, &findings, &files)
                }
                _ => handoff::build_builder_prompt(&task, &schema_hint(role)),
            },
        };

        let Some(spawn) = self.spawn_for_agent(agent, AttemptId::new_v4(), prompt) else {
            self.block_run(
                &run,
                "an agent is owed a spawn but is not startable from the log",
            );
            return;
        };
        if let Err(err) = self.start_attempt(spawn) {
            self.block_run(
                &run,
                &format!("a reissued spawn was refused: {}", err.reason),
            );
        }
    }

    /// Does this agent inherit a worktree a previous session left behind (17c)? True when its
    /// parent is in the **same** lineage, which is what `retry_fresh` creates and nothing else does.
    fn inherits_its_worktree(&self, agent: &AgentId) -> bool {
        let Some(handle) = self.registry.agent(agent) else {
            return false;
        };
        handle
            .parent_agent_id
            .and_then(|parent| self.lineage_of(&parent))
            .is_some_and(|parent_lineage| Some(parent_lineage) == handle.lineage_id)
            && handle.role == RoleName::Builder
    }

    fn lineage_of(&self, agent: &AgentId) -> Option<LineageId> {
        self.registry.agent(agent).and_then(|a| a.lineage_id)
    }

    /// Repairs the log says were decided and never sent.
    ///
    /// 17b is the third shape of the same gap as (a) and (b): the strike and `loop.state{repairing}`
    /// are durable, the marker says the branch is finished, and the resume itself was a helper task
    /// that died with the process. The difference is only which event proves it — here it is
    /// `loop.dispatched{17b}` with no `attempt.started` for the builder after it.
    ///
    /// The marker's own `seq` is the window, not the attempt's `finish_seq`: the marker is the last
    /// event the branch writes and the resume's `attempt.started` lands *after* it, so "started
    /// since the marker" is exactly "the resume happened".
    fn resumes_owed(&self) -> Vec<OwedResume> {
        let pending: Vec<AgentId> = self
            .pending_spawn
            .values()
            .map(PendingSpawn::agent)
            .collect();
        let mut owed = Vec::new();
        for run in self.registry.runs() {
            if run.status != RunStatus::Running || run.loop_state != LoopState::Repairing {
                continue;
            }
            let Some((seq, marked)) = self.newest_resume_marker(&run.run_id) else {
                continue;
            };
            let Some(agent) = self.live_builder(&run.run_id) else {
                continue;
            };
            if pending.contains(&agent) || self.pending_retry.contains_key(&agent) {
                continue;
            }
            // A builder whose newest attempt is still running is mid-turn, not owed one.
            let running = self
                .registry
                .agent(&agent)
                .and_then(|a| a.attempt_ids.last().copied())
                .and_then(|id| self.registry.attempt(&id))
                .is_none_or(|a| !is_terminal(a.status));
            if running {
                continue;
            }
            if self.attempt_started_since(&run.run_id, seq, &agent) {
                continue;
            }
            owed.push(OwedResume {
                run: run.run_id,
                agent,
                marked,
            });
        }
        owed.sort_by(|a, b| a.agent.as_uuid().cmp(b.agent.as_uuid()));
        owed
    }

    /// The newest `loop.dispatched{17b}` of a run: its `seq` and the attempt it named.
    fn newest_resume_marker(&self, run: &RunId) -> Option<(u64, AttemptId)> {
        self.registry
            .events(run, None, usize::MAX)
            .iter()
            .rev()
            .find_map(|e| match &e.payload {
                EventPayload::LoopDispatched {
                    attempt_id,
                    branch: LoopBranch::Resume,
                } => Some((e.base.seq, *attempt_id)),
                _ => None,
            })
    }

    /// Sends the repair turn 17b decided on, rebuilt from the log exactly as the branch built it.
    ///
    /// Which prompt depends on what the marked attempt was, and the log says: a **reviewer**
    /// attempt means the strike came from a `FAIL`, so the reviewer's own findings are quoted
    /// back (`build_repair_prompt`); a **verifier** attempt means a verify-fail strike, so its
    /// structured report is quoted back (`build_verify_repair_prompt` — the report is read from
    /// `attempt.structured`, not the `verify.report` event, which drops `commands`); anything
    /// else is the builder's own failure (`build_failure_repair_prompt`). All wrap the
    /// worker-authored text in the advisory block (S3).
    fn reissue_resume(&mut self, owed: &OwedResume) {
        if !self.run_accepts_workers(&owed.run) {
            return;
        }
        let Some(task) = self.task_of(&owed.run) else {
            self.block_run(
                &owed.run,
                "a repair is owed but the run has no task on record",
            );
            return;
        };
        let marked_role = self
            .registry
            .attempt(&owed.marked)
            .and_then(|a| self.registry.agent(&a.agent_id))
            .map(|a| a.role);
        let verify_report = || {
            self.registry
                .attempt(&owed.marked)
                .and_then(|a| a.structured.clone())
                .and_then(|v| serde_json::from_value::<VerifyReport>(v).ok())
        };
        let prompt = if marked_role == Some(RoleName::Verifier) {
            // B1 (T64 review F3): a verifier that reported `fail` *succeeded*, so its error is
            // None — the failure text lives in its structured report. Fall back to the generic
            // failure prompt only for a hand-written log with no report on record.
            match verify_report() {
                Some(report) => handoff::build_verify_repair_prompt(&report, &task),
                None => handoff::build_failure_repair_prompt(&unknown_failure(), &task),
            }
        } else if matches!(marked_role, Some(RoleName::Reviewer | RoleName::Security)) {
            let findings = self
                .registry
                .events(&owed.run, None, usize::MAX)
                .iter()
                .rev()
                .find_map(|e| match &e.payload {
                    EventPayload::ReviewVerdict { attempt_id, findings, .. }
                    | EventPayload::SecurityVerdict { attempt_id, findings, .. }
                    if *attempt_id == owed.marked => Some(findings.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            handoff::build_repair_prompt(&findings, &task)
        } else {
            let error = self
                .registry
                .attempt(&owed.marked)
                .and_then(|a| a.error.clone())
                .unwrap_or_else(unknown_failure);
            handoff::build_failure_repair_prompt(&error, &task)
        };

        tracing::info!(agent = %owed.agent, "reissuing a repair the log shows was never sent");
        let spawn_cap = self
            .registry
            .agent(&owed.agent)
            .and_then(|a| self.roles.roles.get(&a.role))
            .map_or(self.roles.defaults.spawn_budget_usd, |r| r.spawn_budget_usd);
        let attempt = AttemptId::new_v4();
        if let Err(err) = self.resume_attempt(owed.agent, attempt, prompt, spawn_cap) {
            self.block_run(
                &owed.run,
                &format!("a reissued repair was refused: {}", err.reason),
            );
        }
    }

    /// Runs whose 17d never got its new worktree, oldest first.
    fn runs_owed_a_replacement(&self) -> Vec<RunId> {
        let pending: Vec<RunId> = self
            .pending_worktree
            .values()
            .map(PendingWorktree::run)
            .collect();
        let mut owed: Vec<RunId> = self
            .registry
            .runs()
            .filter(|run| run.status == RunStatus::Running)
            .filter(|run| run.loop_state == LoopState::Replacing)
            .filter(|run| !pending.contains(&run.run_id))
            .filter(|run| self.replacement_is_owed(run))
            .map(|run| run.run_id)
            .collect();
        owed.sort_by(|a, b| a.as_uuid().cmp(b.as_uuid()));
        owed
    }

    /// Was a lineage closed with no `worktree.created` after it? That gap is 17d's lost helper.
    fn replacement_is_owed(&self, run: &Run) -> bool {
        let events = self.registry.events(&run.run_id, None, usize::MAX);
        let closed = events
            .iter()
            .rev()
            .find(|e| matches!(&e.payload, EventPayload::LineageClosed { .. }))
            .map(|e| e.base.seq);
        let Some(closed) = closed else {
            return false;
        };
        !events.iter().any(|e| {
            e.base.seq > closed && matches!(&e.payload, EventPayload::WorktreeCreated { .. })
        })
    }

    /// Restarts 17d's replacement from the log: the closed lineage names what was abandoned.
    fn reissue_replacement(&mut self, run: &RunId) {
        if !self.run_accepts_workers(run) {
            return;
        }
        let Some(closed) = self
            .registry
            .run(run)
            .and_then(|r| r.lineages.iter().rev().find(|l| l.closed).cloned())
        else {
            return;
        };
        let Some(agent) = closed.agent_ids.last().copied() else {
            return;
        };
        let Some(target) = self.target_of(&agent) else {
            return;
        };
        tracing::info!(%run, lineage = %closed.lineage_id, "reissuing a replacement the log shows was never created");
        let (findings, _) = self.abandoned_context(run, &agent);
        // The ReviewFail label is safe even when the closer was a verify failure:
        // `start_replacement` reads the cause only to derive findings, and `abandoned_context`
        // already synthesized the verify failures into findings. The first cause-dependent line
        // added to the replacement prompt must revisit this.
        let cause = StrikeCause::ReviewFail(findings);
        let f = Finished {
            // The replacement is started from the *run*, not from an attempt: nothing here appends
            // an attempt-scoped event, and `start_replacement` only reads `f.run`.
            attempt: AttemptId::new_v4(),
            run: *run,
            agent,
            status: AttemptStatus::Failed,
            error: None,
            structured: None,
            finish_seq: 0,
            parent: None,
        };
        if let Err(err) = self.start_replacement(&f, &target, &cause) {
            self.block_run(
                run,
                &format!("a reissued replacement was refused: {}", err.reason),
            );
        }
    }

    /// What the abandoned lineage left behind: the findings that closed it and the files it had
    /// changed — the two inputs of `build_replacement_prompt`.
    ///
    /// B1 (T64 review F8): the lineage can be closed by a review FAIL **or** by verify failures,
    /// and the newest of the two is what actually closed it — a restart-reissued replacement
    /// must not walk into the same broken build because the log's last *verdict* predates the
    /// verify failure that struck the lineage out. Verify failures are synthesized into blocking
    /// findings exactly as `start_replacement` does in-process.
    // KNOWN residual: the THIRD closer — `StrikeCause::Failure` (a builder crash/timeout) — is
    // not reconstructible here; a restart-reissue after a failure strike-out gets the newest
    // verdict/report findings rather than the crash error the in-process path would have used.
    // Pre-existing, narrower than F8, recorded rather than fixed.
    fn abandoned_context(&self, run: &RunId, agent: &AgentId) -> (Vec<ReviewFinding>, Vec<String>) {
        let lineage = self.lineage_of(agent);
        let events = self.registry.events(run, None, usize::MAX);
        let newest = events.iter().rev().find_map(|e| match &e.payload {
            EventPayload::ReviewVerdict { findings, .. } | EventPayload::SecurityVerdict { findings, .. } => Some(findings.clone()),
            EventPayload::VerifyReport {
                status: VerifyStatus::Fail,
                summary,
                failures,
                ..
            } => {
                let mut findings: Vec<ReviewFinding> = failures
                    .iter()
                    .map(|line| ReviewFinding {
                        severity: Severity::Blocking,
                        file: None,
                        line: None,
                        problem: line.clone(),
                        fix: None,
                    })
                    .collect();
                if findings.is_empty() {
                    findings.push(ReviewFinding {
                        severity: Severity::Blocking,
                        file: None,
                        line: None,
                        problem: summary.clone(),
                        fix: None,
                    });
                }
                Some(findings)
            }
            _ => None,
        });
        let findings = newest.unwrap_or_default();
        let files = lineage.map_or_else(Vec::new, |lineage| self.lineage_files(run, &lineage));
        (findings, files)
    }

    /// The newest `diff.frozen` among `attempts`.
    fn newest_frozen(&self, run: &RunId, attempts: &[AttemptId]) -> Option<Frozen> {
        self.registry
            .events(run, None, usize::MAX)
            .iter()
            .rev()
            .find_map(|e| match &e.payload {
                EventPayload::DiffFrozen {
                    attempt_id,
                    diff_path,
                    diff_hash,
                    files,
                    ..
                } if attempts.contains(attempt_id) => Some(Frozen {
                    attempt: *attempt_id,
                    path: diff_path.clone(),
                    hash: diff_hash.clone(),
                    files: files.clone(),
                }),
                _ => None,
            })
    }

    /// May this run still start a worker?
    ///
    /// **Every deferred spawn asks this again, immediately before spawning.** A helper task's answer
    /// can arrive long after the branch that started it — a worktree read, a `git worktree add`, a
    /// reconciler's reissue — and in between the run may have been cancelled, blocked by an
    /// unrelated failure, or integrated. Starting a worker into a run in any of those states spends
    /// money on work nobody will look at and, worse, contradicts the projection a human is reading
    /// (Codex review of T35, round 2, finding 3).
    fn run_accepts_workers(&self, run: &RunId) -> bool {
        self.registry
            .run(run)
            .is_some_and(|run| run.status == RunStatus::Running)
    }

    /// The same question about one agent: is *this* agent still the one to start, and has it not
    /// already been started?
    fn agent_accepts_a_spawn(&self, agent: &AgentId) -> bool {
        let Some(handle) = self.registry.agent(agent) else {
            return false;
        };
        self.run_accepts_workers(&handle.run_id)
            && handle.attempt_ids.is_empty()
            && !matches!(handle.status, AgentStatus::Closed | AgentStatus::Cancelled)
    }

    // -----------------------------------------------------------------------
    // Spawning
    // -----------------------------------------------------------------------

    /// The one path from a decision to a process: prompt → adapter → `assert_safe_argv` →
    /// `spawn_detached` in a helper task.
    ///
    /// A **preflight** failure is recorded as a failed attempt rather than returned: "the CLI is
    /// not installed" is a fact about this attempt that the branch table knows how to act on (17a),
    /// not a rejection of the caller. An **argv** failure is returned: a plan that fails
    /// `assert_safe_argv` is a control-plane bug or an attack, and it must not be recorded as
    /// something the worker did.
    fn start_attempt(&mut self, s: StartSpawn) -> Result<(), PolicyError> {
        let cfg = Arc::clone(&self.roles);
        let role = loader::role_spec(&cfg, s.role)
            .map_err(|err| PolicyError::new(PolicyCode::UnknownRole, err.to_string()))?;
        let role_prompt = loader::role_prompt(&cfg, s.role)
            .map_err(|err| PolicyError::new(PolicyCode::RolePromptTampered, err.to_string()))?;
        let schema_name = schema_of(s.role);
        let schema = schema_doc(schema_name);
        let dir = attempt_dir(&self.state_dir, &s.run, &s.attempt);

        let adapter = adapter_for(s.provider);
        // B1: the sandbox keys on the same log-sourced pair the accounting reads — never on the
        // freshly loaded spec, so a roles-file edit between restarts cannot strip a recorded
        // writer of its sandbox. A verifier is sandboxed into the builder's worktree without
        // owning it; `s.writes` keeps driving worktree/finalize semantics unchanged.
        let sandboxed = crate::core::types::requires_sandbox(s.role, s.writes);
        let req = SpawnRequest {
            role,
            model: &s.model,
            prompt: &s.prompt,
            role_prompt,
            cwd: &s.cwd,
            attempt_dir: &dir,
            state_dir: &self.state_dir,
            // Only a lead spawn carries its own run into the proxy child's env (T84); every
            // worker's adapter ignores this field entirely (its `--mcp-config` is always empty).
            lead_run_id: (s.role == RoleName::Lead).then_some(s.run),
            schema: (schema_key(schema_name), &schema),
            max_turns: role.max_turns,
            spawn_budget_usd: s.spawn_budget_usd,
            sandbox: sandboxed.then_some(SandboxSpec {
                worktree: &s.worktree,
            }),
            session_id: s.session_id.as_deref(),
            // A resumed session keeps the effort it started with — codex's resume argv carries no
            // `model_reasoning_effort` at all — so this only ever travels on a fresh spawn.
            effort: s.effort,
        };

        let worktree_lock = self.supervisor.worktree_lock(&s.worktree);
        let ctx = AttemptContext {
            run: s.run,
            agent: s.agent,
            attempt: s.attempt,
            dir: dir.clone(),
            adapter: Arc::clone(&adapter),
            timeout: Duration::from_secs(s.timeout_sec),
            pre_sha: s.pre_sha.clone(),
            kind: s.kind,
            role: s.role,
            worktree: s.worktree.clone(),
            worktree_lock,
            writes: s.writes,
            schema: Arc::clone(&schema),
            schema_name,
            denylist: compile_denylist(&cfg),
            spawn_budget_usd: s.spawn_budget_usd,
            rate: cfg.rates.get(&s.model).copied(),
            // Every reattach and every resume must carry the session the transcript already named,
            // or `extract_result` reads the resumed stream as a thread that never started.
            session_id: s.session_id.clone(),
        };

        if let Some(error) = adapter.preflight(&req) {
            let pending = PendingSpawn {
                ctx,
                argv: Vec::new(),
                cwd: s.cwd,
            };
            self.fail_attempt(&pending, AttemptStatus::SpawnFailed, error);
            return Ok(());
        }

        let plan = if s.session_id.is_some() {
            adapter.build_resume(&req)
        } else {
            adapter.build_fresh(&req)
        };
        let prompt_index = adapter.prompt_index(&plan);
        let checked = assert_safe_argv(
            plan,
            &ArgvCtx {
                role: s.role,
                lead_run_id: (s.role == RoleName::Lead).then_some(s.run),
                worktree: &s.worktree,
                provider: s.provider,
                sandboxed,
                state_dir: &self.state_dir,
                prompt_index,
            },
        )?;
        let argv = checked.plan().argv.clone();

        self.pending_spawn.insert(
            s.attempt,
            PendingSpawn {
                ctx,
                argv,
                cwd: s.cwd,
            },
        );
        self.spawn_process_helper(s.attempt, checked, dir);
        Ok(())
    }

    /// A fresh spawn for an agent that is **already in the log**: role, provider, model, cwd,
    /// worktree and writes come from its `agent.created` and are not re-decided.
    ///
    /// That is deliberate. Those values were resolved by policy when the agent was announced, and a
    /// `team.json` edited a second later must not change what an already-announced agent runs as —
    /// the projection would then disagree with the process. Only `effort`, which `agent.created`
    /// does not carry, is re-derived, and only while the team still names the same provider for the
    /// role; a team file that cannot be read simply leaves the adapter on its own constant here
    /// (the `delegate` door is where an untrustworthy team file is refused).
    ///
    /// `None` for an agent the projection has lost, or one whose role is not in the config.
    fn spawn_for_agent(
        &self,
        agent: &AgentId,
        attempt: AttemptId,
        prompt: String,
    ) -> Option<StartSpawn> {
        let handle = self.registry.agent(agent)?;
        let role = self.roles.roles.get(&handle.role)?;
        let worktree = handle
            .worktree
            .clone()
            .unwrap_or_else(|| handle.cwd.clone());
        let effort = if let Some(execution) = self.registry.run(&handle.run_id).and_then(|r| r.execution.as_ref()) {
            execution.assignments.get(role_key(handle.role))
                .filter(|a| a.provider == handle.provider && a.model == handle.model)
                .and_then(|a| a.effort)
        } else {
            team::load_team(&self.state_dir).ok().flatten()
                .and_then(|team| team::validate_team(&self.roles, &team).ok())
                .and_then(|team| team.assignment(handle.role)
                    .filter(|a| a.provider == handle.provider).and_then(|a| a.effort))
        };
        Some(StartSpawn {
            run: handle.run_id,
            agent: *agent,
            attempt,
            role: handle.role,
            provider: handle.provider,
            model: handle.model.clone(),
            effort,
            prompt,
            cwd: handle.cwd.clone(),
            worktree,
            writes: handle.writes,
            pre_sha: handle
                .lineage_id
                .as_ref()
                .map_or_else(String::new, |lineage| {
                    self.lineage_base_sha(&handle.run_id, lineage)
                }),
            kind: AttemptKind::Fresh,
            session_id: None,
            timeout_sec: self.roles.defaults.attempt_timeout_sec,
            spawn_budget_usd: role.spawn_budget_usd,
        })
    }

    /// The resume half of [`Core::start_attempt`]: the same chain, with the agent's own session,
    /// cwd, provider and model — a resumed session never changes any of them, whatever the team
    /// says today.
    fn resume_attempt(
        &mut self,
        agent: AgentId,
        attempt: AttemptId,
        prompt: String,
        spawn_cap: f64,
    ) -> Result<(), PolicyError> {
        let cfg = Arc::clone(&self.roles);
        let checked = {
            let ctx = PolicyCtx {
                registry: &self.registry,
                cfg: &cfg,
                caller_role: RoleName::Lead,
                caller_depth: 0,
                now: epoch_secs,
            };
            policy::check_send_message(&agent, &ctx).map(|h| StartSpawn {
                run: h.run_id,
                agent,
                attempt,
                role: h.role,
                provider: h.provider,
                model: h.model.clone(),
                effort: None,
                prompt,
                cwd: h.cwd.clone(),
                worktree: h.worktree.clone().unwrap_or_else(|| h.cwd.clone()),
                writes: h.writes,
                pre_sha: String::new(),
                kind: AttemptKind::Resume,
                session_id: h.session_id.clone(),
                timeout_sec: cfg.defaults.attempt_timeout_sec,
                spawn_budget_usd: spawn_cap,
            })
        };
        let mut spawn = checked?;
        if spawn.role == RoleName::Lead {
            spawn.effort = self.registry.run(&spawn.run).and_then(|r| r.execution.as_ref())
                .and_then(|e| e.assignments.get("lead")).and_then(|a| a.effort);
        }
        // The worktree's HEAD is the lineage's base commit: a worker that commits is soft-reset
        // back to it, so this is the sha the next attempt diffs against.
        spawn.pre_sha = self.agent_base_sha(&agent);
        self.start_attempt(spawn)
    }

    /// Records an attempt that never ran: `attempt.started` with pid 0 (which
    /// `supervisor::signal_target` refuses to signal) followed immediately by its terminal event.
    ///
    /// Both are needed. `reduce` only knows an attempt it has seen start, so a lone
    /// `attempt.finished` would project to nothing — no envelope for `await_result`, no row in
    /// `get_status`, and nothing for the branch table to sweep.
    fn fail_attempt(&mut self, p: &PendingSpawn, status: AttemptStatus, error: AttemptError) {
        let ctx = &p.ctx;
        let run = ctx.run;
        self.emit(
            &run,
            EventPayload::AttemptStarted {
                attempt_id: ctx.attempt,
                agent_id: ctx.agent,
                attempt_kind: ctx.kind,
                dir: ctx.dir.clone(),
                argv: p.argv.clone(),
                cwd: p.cwd.clone(),
                pid: 0,
                pgid: 0,
                start_time: String::new(),
                pre_sha: ctx.pre_sha.clone(),
                timeout_sec: ctx.timeout.as_secs(),
                spawn_budget_usd: ctx.spawn_budget_usd,
            },
        );
        self.emit(
            &run,
            EventPayload::AttemptFinished {
                attempt_id: ctx.attempt,
                status,
                exit_code: None,
                signal: None,
                post_sha: None,
                duration_ms: 0,
                error: Some(error),
            },
        );
    }

    /// Step 14: the reviewer the loop starts itself once a builder's diff is frozen.
    ///
    /// It runs **read-only in the builder's worktree** and carries the builder's own lineage id, so
    /// the review shows up in the lineage it is about. `check_delegate` runs for it exactly as it
    /// does for a lead's delegation — that is the budget check the design asks for here, plus the
    /// team's choice of provider and model for the reviewer role (Rev 26).
    ///
    /// **`builder` is a parameter, not `f.agent`.** Both callers reach here from a *terminal
    /// attempt*, and only one of them is the builder's: `branch_review` arrives from the builder,
    /// `retry_reviewer` (Rev 25's one replacement) arrives from the **reviewer** that just failed.
    /// Reading the agent off the finished attempt therefore parented the replacement under its dead
    /// predecessor, and `reviewed_diff` — which looks for a `diff.frozen` among the *parent's*
    /// attempts — then found none and blocked the run with the wrong cause. The builder's own
    /// report is read from the frozen attempt for the same reason: `f.structured` is the reviewer's
    /// verdict on that path, not a `BuildResult`.
    fn start_reviewer(&mut self, run: &RunId, builder: AgentId, frozen: &Frozen) -> Result<(), PolicyError> {
        self.start_review_role(run, builder, frozen, RoleName::Reviewer)
    }

    fn start_review_role(
        &mut self,
        run: &RunId,
        builder: AgentId,
        frozen: &Frozen,
        role: RoleName,
    ) -> Result<(), PolicyError> {
        let Some(target) = self.target_of(&builder) else {
            return Err(PolicyError::new(
                PolicyCode::ResumeTargetMissing,
                "the builder is no longer on record",
            ));
        };
        let Some(task) = self.task_of(run) else {
            return Err(PolicyError::new(
                PolicyCode::ResumeTargetMissing,
                "the run has no task on record",
            ));
        };
        let request = DelegateRequest {
            run_id: Some(*run),
            role,
            task: task.clone(),
            model: None,
            session: SessionSpec::Fresh,
            base_ref: None,
            // A reviewer writes nothing, so it is not a writer for C5's one-writer rule and must
            // not be tested against it — the builder it reviews is idle in that worktree.
            worktree: None,
            steps: None,
            // Internal (the loop starts the reviewer itself), not a lead's own delegate call.
            caller_run_id: None,
        };
        let resolved = self.resolve_internal(&request)?;

        let agent = AgentId::new_v4();
        let attempt = AttemptId::new_v4();
        self.registry.append(
            run,
            EventPayload::AgentCreated {
                agent_id: agent,
                role,
                provider: resolved.provider,
                model: resolved.model.clone(),
                lineage_id: Some(target.lineage),
                depth: resolved.depth,
                parent_agent_id: Some(builder),
                origin: Origin::ControlPlane,
                writes: false,
                cwd: target.worktree.clone(),
                worktree: None,
            },
        ).map_err(|error| PolicyError::new(PolicyCode::RunBlocked, error.to_string()))?;
        self.registry.append(
            run,
            loop_state(if role == RoleName::Security { LoopState::SecurityReviewing } else { LoopState::Reviewing }, &target, target.strikes),
        ).map_err(|error| PolicyError::new(PolicyCode::RunBlocked, error.to_string()))?;

        // The claim the reviewer is asked to check, read from the attempt whose diff was frozen —
        // the one place it is true on both call paths.
        let build = self
            .registry
            .attempt(&frozen.attempt)
            .and_then(|a| a.structured.clone())
            .and_then(|v| serde_json::from_value::<BuildResult>(v).ok());
        // B1: the recorded verify report (when the verify step ran) rides into the reviewer's
        // prompt. Read from the log rather than passed by the caller so a replacement reviewer
        // after a crash — and a re-drive after a restart — carries it identically.
        let verify = self.recorded_verify_report(run, frozen.attempt);
        let prompt = handoff::build_reviewer_prompt(
            &task,
            &frozen.path,
            &frozen.hash,
            build.as_ref(),
            verify.as_ref(),
        );
        self.start_attempt(StartSpawn {
            run: *run,
            agent,
            attempt,
            role,
            provider: resolved.provider,
            model: resolved.model,
            effort: resolved.effort,
            prompt,
            cwd: target.worktree.clone(),
            worktree: target.worktree,
            writes: false,
            pre_sha: String::new(),
            kind: AttemptKind::Fresh,
            session_id: None,
            timeout_sec: resolved.attempt_timeout_sec,
            spawn_budget_usd: resolved.spawn_budget_usd,
        })
    }

    /// B1: a fresh verifier in the builder's worktree — the mirror of [`Self::start_reviewer`],
    /// sandboxed (the role requires it) but not a writer. The **loop** never dispatches into
    /// this worktree while the verifier runs (the builder's attempt is terminal first, and
    /// repairs are dispatched by `branch_verify`/`branch_strike`, strictly after the verifier
    /// finishes) — but the lead/human `send_message` door is not fenced by worktree occupancy,
    /// exactly as for the reviewer today. A builder turn racing the verifier can at worst make
    /// the verify report wrong about a tree the integrate re-freeze re-checks fail-closed
    /// (Rev 25); recorded as a residual, not a guarantee.
    fn start_verifier(
        &mut self,
        run: &RunId,
        builder: AgentId,
        frozen: &Frozen,
    ) -> Result<(), PolicyError> {
        let Some(target) = self.target_of(&builder) else {
            return Err(PolicyError::new(
                PolicyCode::ResumeTargetMissing,
                "the builder is no longer on record",
            ));
        };
        let Some(task) = self.task_of(run) else {
            return Err(PolicyError::new(
                PolicyCode::ResumeTargetMissing,
                "the run has no task on record",
            ));
        };
        let request = DelegateRequest {
            run_id: Some(*run),
            role: RoleName::Verifier,
            task: task.clone(),
            model: None,
            session: SessionSpec::Fresh,
            base_ref: None,
            // Like the reviewer: not a writer for C5's one-writer rule — the builder it verifies
            // is idle in that worktree, and the verifier owns no deliverable.
            worktree: None,
            steps: None,
            // Internal (the loop starts the verifier itself), not a lead's own delegate call.
            caller_run_id: None,
        };
        let resolved = self.resolve_internal(&request)?;

        let agent = AgentId::new_v4();
        let attempt = AttemptId::new_v4();
        self.emit(
            run,
            EventPayload::AgentCreated {
                agent_id: agent,
                role: RoleName::Verifier,
                provider: resolved.provider,
                model: resolved.model.clone(),
                lineage_id: Some(target.lineage),
                depth: resolved.depth,
                parent_agent_id: Some(builder),
                origin: Origin::ControlPlane,
                writes: false,
                cwd: target.worktree.clone(),
                worktree: None,
            },
        );
        self.emit(
            run,
            loop_state(LoopState::Verifying, &target, target.strikes),
        );

        let build = self
            .registry
            .attempt(&frozen.attempt)
            .and_then(|a| a.structured.clone())
            .and_then(|v| serde_json::from_value::<BuildResult>(v).ok());
        let prompt =
            handoff::build_verifier_prompt(&task, &frozen.path, &frozen.hash, build.as_ref());
        self.start_attempt(StartSpawn {
            run: *run,
            agent,
            attempt,
            role: RoleName::Verifier,
            provider: resolved.provider,
            model: resolved.model,
            effort: resolved.effort,
            prompt,
            cwd: target.worktree.clone(),
            worktree: target.worktree,
            writes: false,
            pre_sha: String::new(),
            kind: AttemptKind::Fresh,
            session_id: None,
            timeout_sec: resolved.attempt_timeout_sec,
            spawn_budget_usd: resolved.spawn_budget_usd,
        })
    }

    /// B1's mirror of [`Self::retry_reviewer`]: one replacement verifier per frozen diff, then
    /// the run blocks. The builder is never struck for a verifier's failure.
    fn retry_verifier(&mut self, f: &Finished, frozen: &Frozen, reason: &str) {
        // Re-drive first (T64 review F5): a replacement created before a crash must count as
        // "already handled", not as a second failure — else the re-driven branch false-blocks a
        // live (or already-successful) replacement.
        if self.verifier_created_since(&f.run, f.finish_seq) {
            self.mark(f, LoopBranch::Verify);
            return;
        }
        let tries = self.verifiers_for(&f.run, frozen.attempt);
        if tries >= MAX_VERIFIERS_PER_DIFF {
            self.block_run(
                &f.run,
                &format!("{reason}; {tries} verifiers have now failed on this diff"),
            );
            self.mark(f, LoopBranch::Verify);
            return;
        }
        let builder = self
            .registry
            .attempt(&frozen.attempt)
            .map(|attempt| attempt.agent_id);
        let Some(builder) = builder else {
            self.block_run(
                &f.run,
                "verification must be repeated but the builder whose diff was frozen is no longer on record",
            );
            self.mark(f, LoopBranch::Verify);
            return;
        };
        // The early return above already covered the created-since case; start unconditionally.
        if let Err(err) = self.start_verifier(&f.run, builder, frozen) {
            self.block_run(
                &f.run,
                &format!(
                    "a replacement verifier could not be started: {}",
                    err.reason
                ),
            );
        }
        self.mark(f, LoopBranch::Verify);
    }

    /// B1: what one verifier attempt decided. Unlike `branch_reviewer` (which emits the
    /// verdict before its hash check), the report is emitted only **after** the hash check on
    /// purpose: `recorded_verify_report` must never surface a report bound to the wrong diff.
    /// A parseable report whose hash matches the frozen diff drives the loop — `fail` strikes the builder with the failure text, `pass` and
    /// `nothing-to-run` hand the diff (and the report) to a reviewer. Anything else — a crash,
    /// an unparseable report, a wrong hash — buys one replacement verifier, then the run blocks.
    async fn branch_verify(&mut self, f: &Finished) {
        let Some(frozen) = self.reviewed_diff(f) else {
            self.block_run(
                &f.run,
                "a verifier finished with no frozen diff on record to bind its report to",
            );
            self.mark(f, LoopBranch::Verify);
            return;
        };
        if self.run_steps(&f.run).security && !security::current_builder_diff(&self.registry, &f.run, frozen.attempt) {
            self.mark(f, LoopBranch::Verify);
            return;
        }
        let report = f
            .structured
            .clone()
            .filter(|_| f.status == AttemptStatus::Succeeded)
            .and_then(|v| serde_json::from_value::<VerifyReport>(v).ok());

        let Some(report) = report else {
            let reason = f.error.as_ref().map_or_else(
                || "the verifier produced no report".to_string(),
                |err| format!("{}: {}", error_key(err.code), err.message),
            );
            self.retry_verifier(f, &frozen, &reason);
            return;
        };

        if report.diff_hash != frozen.hash {
            // The report cannot be shown to be about the state we froze, so it decides nothing.
            self.emit(
                &f.run,
                EventPayload::AttemptFinished {
                    attempt_id: f.attempt,
                    status: AttemptStatus::InvalidOutput,
                    exit_code: None,
                    signal: None,
                    post_sha: None,
                    duration_ms: 0,
                    error: Some(AttemptError {
                        code: ErrorCode::DiffHashMismatch,
                        message: format!(
                            "the report echoed diffHash {} but the frozen diff hashes to {}",
                            clamp_untrusted(&report.diff_hash, 64),
                            frozen.hash
                        ),
                    }),
                },
            );
            self.retry_verifier(f, &frozen, "the verifier echoed the wrong diffHash");
            return;
        }

        if !self.verify_report_since(&f.run, f.finish_seq) {
            self.emit(
                &f.run,
                EventPayload::VerifyReport {
                    attempt_id: f.attempt,
                    builder_attempt_id: frozen.attempt,
                    status: report.status,
                    // Schema validation already bounds these (summary <= 4000, failures <= 50 x
                    // 1000); the clamp is belt-and-braces for a hand-written log.
                    summary: clamp_untrusted(&report.summary, 4_000),
                    failures: report
                        .failures
                        .iter()
                        .map(|line| clamp_untrusted(line, 1_000))
                        .collect(),
                },
            );
        }

        if report.status == VerifyStatus::Fail {
            let Some(builder) = f.parent.and_then(|agent| self.target_of(&agent)) else {
                self.block_run(
                    &f.run,
                    "verification failed and the builder it verified is no longer on record",
                );
                self.mark(f, LoopBranch::Verify);
                return;
            };
            self.branch_strike(f, &builder, StrikeCause::VerifyFail(Box::new(report)))
                .await;
            return;
        }

        // `pass` and `nothing-to-run` both proceed: a repo that declares no test command must
        // never fail verification for it (requirements, edge cases). B3: with review disabled,
        // a verified diff goes straight to the human gate.
        if !self.run_steps(&f.run).review {
            self.open_integrate_gate(f, &frozen, false);
            self.mark(f, LoopBranch::Verify);
            return;
        }
        if !self.reviewer_created_since(&f.run, f.finish_seq) {
            let builder_agent = self.registry.attempt(&frozen.attempt).map(|a| a.agent_id);
            let Some(builder_agent) = builder_agent else {
                self.block_run(
                    &f.run,
                    "verification passed but the builder whose diff was frozen is no longer on record",
                );
                self.mark(f, LoopBranch::Verify);
                return;
            };
            if let Err(err) = self.start_reviewer(&f.run, builder_agent, &frozen) {
                let reason = format!("the reviewer could not be started: {}", err.reason);
                self.block_run(&f.run, &reason);
            }
        }
        self.mark(f, LoopBranch::Verify);
    }

    /// Rev 25: one replacement reviewer per frozen diff, then the run blocks.
    ///
    /// A reviewer that crashed or answered about the wrong diff has told us nothing, so the builder
    /// is not struck; but a second reviewer that does the same is a fault a human has to look at,
    /// not a loop to keep spending money in.
    fn retry_reviewer(&mut self, f: &Finished, frozen: &Frozen, reason: &str) {
        let role = self.review_role(f);
        // Same re-drive-first rule as `retry_verifier` (T64 review F5): a replacement created
        // before a crash is "handled", never a second strike against the cap.
        if self.agent_created_since(&f.run, f.finish_seq, role) {
            self.mark(f, LoopBranch::Review);
            return;
        }
        let tries = self.workers_for(&f.run, frozen.attempt, role);
        if tries >= MAX_REVIEWERS_PER_DIFF {
            let label = if role == RoleName::Security { "security reviewers" } else { "reviewers" };
            self.block_run(
                &f.run,
                &format!("{reason}; {tries} {label} have now failed on this diff"),
            );
            self.mark(f, LoopBranch::Review);
            return;
        }
        // The replacement belongs to the **builder whose diff was frozen**, not to the reviewer
        // that just failed — `f` is the reviewer's here. The frozen attempt names that builder,
        // and it is the same answer whether this is the first replacement or a re-drive.
        let builder = self
            .registry
            .attempt(&frozen.attempt)
            .map(|attempt| attempt.agent_id);
        let Some(builder) = builder else {
            self.block_run(
                &f.run,
                "a review must be repeated but the builder whose diff was frozen is no longer on record",
            );
            self.mark(f, LoopBranch::Review);
            return;
        };
        // The early return above already covered the created-since case; start unconditionally.
        if let Err(err) = self.start_review_role(&f.run, builder, frozen, role) {
            self.block_run(
                &f.run,
                &format!(
                    "a replacement reviewer could not be started: {}",
                    err.reason
                ),
            );
        }
        self.mark(f, LoopBranch::Review);
    }

    /// 17d's fresh start: a new lineage, a new worktree, and a builder that is told what the
    /// abandoned attempt changed and why it was rejected — but inherits none of its work.
    fn start_replacement(
        &mut self,
        f: &Finished,
        target: &Target,
        cause: &StrikeCause,
    ) -> Result<(), PolicyError> {
        let Some(task) = self.task_of(&f.run) else {
            return Err(PolicyError::new(
                PolicyCode::ResumeTargetMissing,
                "the run has no task on record",
            ));
        };
        let request = DelegateRequest {
            run_id: Some(f.run),
            role: RoleName::Builder,
            task: task.clone(),
            model: None,
            session: SessionSpec::Fresh,
            base_ref: None,
            worktree: None,
            steps: None,
            // Internal (the loop's own replacement), not a lead's own delegate call.
            caller_run_id: None,
        };
        let resolved = self.resolve_internal(&request)?;

        let agent = AgentId::new_v4();
        let attempt = AttemptId::new_v4();
        let lineage = LineageId::new_v4();
        let worktree = worktree_path(&self.repo_root, &f.run, &agent);
        let branch = branch_name(&f.run, &agent);
        let findings = match cause {
            StrikeCause::ReviewFail(findings) => findings.clone(),
            // B1: a replacement after a verify-fail strike-out inherits the failure lines as
            // blocking findings, so it does not walk into the same broken build.
            StrikeCause::VerifyFail(report) => {
                let mut findings: Vec<ReviewFinding> = report
                    .failures
                    .iter()
                    .map(|line| ReviewFinding {
                        severity: Severity::Blocking,
                        file: None,
                        line: None,
                        problem: line.clone(),
                        fix: None,
                    })
                    .collect();
                if findings.is_empty() {
                    findings.push(ReviewFinding {
                        severity: Severity::Blocking,
                        file: None,
                        line: None,
                        problem: report.summary.clone(),
                        fix: None,
                    });
                }
                findings
            }
            StrikeCause::Failure(err) => err
                .as_ref()
                .map(|err| {
                    vec![ReviewFinding {
                        severity: Severity::Blocking,
                        file: None,
                        line: None,
                        problem: format!("{}: {}", error_key(err.code), err.message),
                        fix: None,
                    }]
                })
                .unwrap_or_default(),
        };
        let prior_files = self.lineage_files(&f.run, &target.lineage);
        let prompt = handoff::build_replacement_prompt(&task, &findings, &prior_files);

        self.pending_worktree.insert(
            lineage,
            PendingWorktree {
                execution: None,
                run: f.run,
                new_run: false,
                agent,
                attempt,
                lineage,
                role: RoleName::Builder,
                provider: resolved.provider,
                model: resolved.model,
                effort: resolved.effort,
                depth: resolved.depth,
                parent: Some(target.agent),
                origin: Origin::ControlPlane,
                writes: resolved.writes,
                worktree: worktree.clone(),
                base_ref: resolved.base_ref.clone(),
                task,
                prompt,
                lead: None,
                team_name: None,
                // A replacement joins an existing run (`new_run: false`), whose `run.created`
                // already captured the steps — nothing here may rewrite them.
                steps: None,
                timeout_sec: resolved.attempt_timeout_sec,
                spawn_budget_usd: resolved.spawn_budget_usd,
                attempt_no: target.attempt_no.saturating_add(1),
                strikes: 0,
                // Internal (the loop's own replacement, `Origin::ControlPlane` above), not a
                // lead's own delegate call — and `new_run: false` means no `run.created` is owed
                // here regardless.
                caller_run_id: None,
            },
        );
        self.spawn_worktree_from_ref(
            lineage,
            self.repo_root.clone(),
            worktree,
            branch,
            resolved.base_ref,
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Gates
    // -----------------------------------------------------------------------

    /// Step 16: the gate a `PASS` opens. Its summary names **every** policy violation of the
    /// lineage, because the human approving it is the last reader before the work is committed.
    fn open_integrate_gate(&mut self, f: &Finished, frozen: &Frozen, reviewed: bool) {
        if !self.security_ready_for_gate(f, frozen) { return; }
        if self.gate_since(&f.run, f.finish_seq) {
            self.set_awaiting_gate(&f.run);
            return;
        }
        // `None`, not `Some("")`, when the attempt is not in the projection: an approval refuses
        // either way, but a gate that says it was reviewed against the empty sha is a lie about why
        // (round-4 review, finding 5).
        let (pre_sha, build_path) = self
            .registry
            .attempt(&frozen.attempt)
            .map_or((None, None), |a| {
                (Some(a.pre_sha.clone()), a.result_path.clone())
            });
        let builder_worktree = self
            .registry
            .attempt(&frozen.attempt)
            .and_then(|a| self.registry.agent(&a.agent_id))
            .and_then(|a| a.worktree.clone());
        // Only a reviewer's finish leaves a verdict behind; on the B3 no-review path `f` is the
        // builder's (or verifier's) own finish and pointing at its result would mislabel it.
        let verdict_path = if reviewed {
            self.ordinary_review_for_diff(&f.run, frozen)
                .and_then(|id| self.registry.attempt(&id))
                .and_then(|a| a.result_path.clone())
        } else {
            None
        };
        let spend = self.registry.run(&f.run).map_or(0.0, |r| r.spend_usd);
        // B1: the human sees what verification found, one clamped line, right in the gate card.
        let verify_line = self
            .recorded_verify_report(&f.run, frozen.attempt)
            .map_or_else(String::new, |report| match report.status {
                VerifyStatus::Pass => {
                    format!(
                        "Verified: pass — {}\n\n",
                        clamp_untrusted(&report.summary, 200)
                    )
                }
                VerifyStatus::NothingToRun => "Verified: nothing to run.\n\n".to_string(),
                VerifyStatus::Fail => {
                    format!(
                        "Verified: FAIL — {}\n\n",
                        clamp_untrusted(&report.summary, 200)
                    )
                }
            });
        let lead_line = if reviewed {
            "A reviewer passed this change."
        } else {
            "NO reviewer ran — this team disables review; approving this gate IS the review."
        };
        // On the no-review path the finish in hand is not the builder's; the violations worth
        // showing are the ones recorded against the agent whose diff is being integrated.
        let violations_agent = if reviewed {
            f.agent
        } else {
            self.registry
                .attempt(&frozen.attempt)
                .map_or(f.agent, |a| a.agent_id)
        };
        let task_line = self
            .task_of(&f.run)
            .map(|t| format!("{}: {}", t.id, t.title));
        let summary = format!(
            "{lead_line}\n\n{}\n\n{verify_line}{}\n\n{} file(s) changed.\n\n{}",
            if self.run_steps(&f.run).security { "Security review passed for this frozen diff." }
            else { "Security review was not run." },
            task_line.clone().unwrap_or_default(),
            frozen.files.len(),
            self.violation_summary(&violations_agent)
        );
        let payload = GatePayload {
            worktree: builder_worktree,
            // The commit subject is the task line; the summary above — review sentence first, as
            // loud as the human gate needs it — becomes the commit body.
            subject: task_line,
            diff_path: Some(frozen.path.clone()),
            // The three fields that bind an approval to this exact diff (Rev 25): the commit helper
            // re-freezes the worktree against `pre_sha` and refuses to commit unless it still
            // hashes to `diff_hash`.
            diff_hash: Some(frozen.hash.clone()),
            files: frozen.files.clone(),
            build_result_path: build_path,
            verdict_path,
            pre_sha,
            spend_usd: spend,
        };
        self.open_gate(&f.run, GateKind::Integrate, &summary, payload);
        self.set_awaiting_gate(&f.run);
    }

    // -----------------------------------------------------------------------
    // The plan conductor (B3, T76)
    // -----------------------------------------------------------------------

    /// Validates and starts a plan: mints the container run (the A5 conversation-run shape — no
    /// worktree, no lineage), records the document, and starts every item with no predecessors.
    ///
    /// `caller_run_id` is T84's attestation — `acp mcp-proxy`'s `ACP_LEAD_RUN_ID`, forwarded as
    /// `plan.start`'s `callerRunId` — validated against [`Core::validated_caller_run`] before a
    /// `run.delegated{target:"plan"}` is written to it, once the container's own `run.created` is
    /// durable. Every other door passes `None` and nothing is written.
    ///
    /// # Errors
    /// `PolicyCode::InvalidPlan` with the full issue list; `TeamInvalid` for an untrustable
    /// `team.json`; `Registry` if the log will not take the events.
    pub fn start_plan(
        &mut self,
        plan: Plan,
        caller_run_id: Option<RunId>,
    ) -> Result<RunId, CoreError> {
        if let Err(issues) = validate_plan(&plan) {
            let detail = issues
                .iter()
                .map(|i| {
                    if i.item.is_empty() {
                        format!("{}: {}", i.code, i.detail)
                    } else {
                        format!("{} ({}): {}", i.item, i.code, i.detail)
                    }
                })
                .collect::<Vec<_>>()
                .join("; ");
            return Err(CoreError::Policy(PolicyError::new(
                PolicyCode::InvalidPlan,
                format!("the plan was refused: {detail}"),
            )));
        }
        if self.caller_without_builder(caller_run_id) {
            return Err(PolicyError::new(PolicyCode::DelegationNotAllowed,
                "this lead's recorded task has no builder").into());
        }
        let inherited = caller_run_id
            .and_then(|id| self.registry.run(&id)).and_then(|r| r.execution.clone());
        let team = match inherited.as_ref() {
            Some(e) => Some(team::from_execution(&self.roles, e).map_err(|issues|
                PolicyError::new(PolicyCode::TeamInvalid, format!("recorded team is unsupported: {issues:?}")))?),
            None => self.valid_team()?,
        };
        let execution = inherited.unwrap_or_else(|| team::capture_execution(&self.roles, team.as_ref()));
        if execution.mode != RunMode::Build {
            return Err(PolicyError::new(PolicyCode::DelegationNotAllowed,
                "a work plan requires build mode; planning and audit never create builders").into());
        }
        // Validated *before* the container run is minted, against whatever lead is live right now
        // (T84) — the same daemon-owned fact `delegate` checks, so a caller cannot widen its own
        // attribution window by racing the mint.
        let validated_caller = self.validated_caller_run(caller_run_id);
        let run = RunId::new_v4();
        self.registry.append(
            &run,
            EventPayload::RunCreated {
                execution: Some(execution.clone()),
                repo_root: self.repo_root.clone(),
                state_dir: self.state_dir.clone(),
                base_ref: self.roles.defaults.base_ref.clone(),
                // Like a conversation run: no worktree base of its own — every work item's run
                // resolves one for itself.
                base_sha: String::new(),
                task: Task {
                    id: "plan".to_string(),
                    title: clamp_untrusted(&plan.name, 200),
                    description: clamp_untrusted(&plan.name, MAX_SUMMARY_CHARS),
                    files: vec![],
                    acceptance: vec![],
                },
                version: RUN_VERSION,
                lead: team.as_ref().and_then(lead_label),
                team_name: team.as_ref().map(|t| t.name().to_string()),
                steps: Some(execution.steps),
            },
        )?;
        // T84: only now — the container's own `run.created` is durable — may the lead's run say
        // this delegation caused it.
        self.record_delegation(validated_caller, run, None, DelegatedTarget::Plan);
        self.registry
            .append(&run, EventPayload::PlanCreated { plan })?;
        self.drive_plans();
        Ok(run)
    }

    /// Re-examines every plan after something moved. Cheap — plans are ≤ 20 items and rare — and
    /// re-entrancy-guarded: the drive may block a container run, and `block_run` pokes back here.
    pub(crate) fn drive_plans(&mut self) {
        if self.driving_plans {
            return;
        }
        self.driving_plans = true;
        let containers: Vec<RunId> = self.registry.state().plans.keys().copied().collect();
        for run in containers {
            self.drive_plan(&run);
        }
        self.driving_plans = false;
    }

    /// One pass over one plan: fold the world into item statuses, start what became ready, and
    /// conclude the container when everything is done. Every transition is emitted before it is
    /// acted on, so a restart replays to exactly this state (`plan.item` is the marker).
    fn drive_plan(&mut self, container: &RunId) {
        if self.registry.run(container).is_some_and(|r| r.status == RunStatus::Cancelled) { return; }
        let Some(proj) = self.registry.state().plans.get(container).cloned() else {
            return;
        };

        // 1. Fold: started items whose runs or gates settled become done/blocked.
        for item in &proj.plan.items {
            let Some(state) = proj.items.get(&item.id).copied() else {
                continue;
            };
            if state.status != PlanItemStatus::Started {
                continue;
            }
            match item.kind {
                PlanItemKind::Work => {
                    let Some(item_run) = state.run_id else {
                        continue;
                    };
                    match self.registry.run(&item_run).map(|r| r.status) {
                        Some(RunStatus::Integrated) => {
                            self.plan_item(
                                container,
                                &item.id,
                                PlanItemStatus::Done,
                                Some(item_run),
                                None,
                            );
                        }
                        Some(RunStatus::Blocked | RunStatus::Failed | RunStatus::Cancelled) => {
                            self.plan_item_blocked(container, &proj, &item.id);
                        }
                        Some(_) => {}
                        None => {
                            // The delegate died before `run.created` landed. With nothing in
                            // flight for that run, reissue — the fresh `started` marker with the
                            // new run id supersedes this one on replay.
                            let in_flight =
                                self.pending_worktree.values().any(|p| p.run() == item_run);
                            if !in_flight {
                                self.start_plan_work_item(container, &proj, item);
                            }
                        }
                    }
                }
                PlanItemKind::Human => {
                    let Some(gate) = state.gate_id else {
                        continue;
                    };
                    match self.registry.gate(&gate).map(|g| g.status) {
                        Some(GateStatus::Approved) => {
                            self.plan_item(
                                container,
                                &item.id,
                                PlanItemStatus::Done,
                                None,
                                Some(gate),
                            );
                        }
                        Some(GateStatus::Denied) => {
                            self.plan_item_blocked(container, &proj, &item.id);
                        }
                        _ => {}
                    }
                }
            }
        }

        // 2. Start: pending items whose predecessors are all done. A blocked plan starts nothing.
        let Some(proj) = self.registry.state().plans.get(container).cloned() else {
            return;
        };
        if proj
            .items
            .values()
            .any(|i| i.status == PlanItemStatus::Blocked)
        {
            return;
        }
        for item in &proj.plan.items {
            if proj.items.get(&item.id).map(|s| s.status) != Some(PlanItemStatus::Pending) {
                continue;
            }
            let ready = item.after.iter().all(|dep| {
                proj.items
                    .get(dep)
                    .is_some_and(|d| d.status == PlanItemStatus::Done)
            });
            if !ready {
                continue;
            }
            match item.kind {
                PlanItemKind::Work => self.start_plan_work_item(container, &proj, item),
                PlanItemKind::Human => self.start_plan_human_item(container, item),
            }
        }

        // 3. Conclude: everything done ends the container.
        let Some(proj) = self.registry.state().plans.get(container).cloned() else {
            return;
        };
        if proj
            .items
            .values()
            .all(|i| i.status == PlanItemStatus::Done)
            && self.registry.run(container).map(|r| r.status) != Some(RunStatus::Integrated)
        {
            self.emit(
                container,
                EventPayload::RunStatus_ {
                    status: RunStatus::Integrated,
                    reason: None,
                },
            );
            self.emit(
                container,
                EventPayload::LoopStateChanged {
                    state: LoopState::Done,
                    builder_agent_id: None,
                    attempt_no: 0,
                    strikes: 0,
                },
            );
        }
    }

    /// One durable item transition.
    fn plan_item(
        &mut self,
        container: &RunId,
        item: &str,
        status: PlanItemStatus,
        run: Option<RunId>,
        gate: Option<GateId>,
    ) {
        self.emit(
            container,
            EventPayload::PlanItem {
                item_id: item.to_string(),
                status,
                run_id: run,
                gate_id: gate,
            },
        );
    }

    /// Marks an item blocked, marks its still-pending transitive dependents skipped — visible,
    /// never silent — and blocks the container. The human resolves the underlying run or gate;
    /// nothing here is terminal for the plan's own document.
    fn plan_item_blocked(&mut self, container: &RunId, proj: &PlanProjection, item_id: &str) {
        self.plan_item(container, item_id, PlanItemStatus::Blocked, None, None);
        let mut dead: Vec<String> = vec![item_id.to_string()];
        let mut cursor = 0;
        while cursor < dead.len() {
            let current = dead[cursor].clone();
            cursor += 1;
            for item in &proj.plan.items {
                if item.after.contains(&current)
                    && proj.items.get(&item.id).map(|s| s.status) == Some(PlanItemStatus::Pending)
                    && !dead.contains(&item.id)
                {
                    self.plan_item(container, &item.id, PlanItemStatus::Skipped, None, None);
                    dead.push(item.id.clone());
                }
            }
        }
        self.block_run(container, &format!("plan item `{item_id}` is blocked"));
    }

    /// Delegates one work item as an ordinary run: the team's captured steps with the item's
    /// overrides on top, and — for exactly one done work predecessor — that item's integrated sha
    /// as the base, which is what makes a sequence build on itself.
    fn start_plan_work_item(
        &mut self,
        container: &RunId,
        proj: &PlanProjection,
        item: &crate::core::plan::PlanItem,
    ) {
        let Some(task) = item.task.clone() else {
            return;
        };
        let done_preds: Vec<&String> = item
            .after
            .iter()
            .filter(|dep| {
                proj.items
                    .get(*dep)
                    .is_some_and(|d| d.status == PlanItemStatus::Done && d.run_id.is_some())
            })
            .collect();
        let base_ref = if done_preds.len() == 1 {
            proj.items[done_preds[0]]
                .run_id
                .and_then(|r| self.registry.run(&r).and_then(|r| r.integrated_sha.clone()))
        } else {
            // Zero work predecessors, a human predecessor, or a fanout join: the default base.
            // Joined branches stay unmerged — landing them together is the human's, like main.
            None
        };
        let inherited = self.registry.run(container).and_then(|r| r.execution.clone());
        let mut execution = match inherited {
            Some(e) => e,
            None => match self.valid_team() {
                Ok(team) => team::capture_execution(&self.roles, team.as_ref()),
                Err(err) => {
                    self.plan_item(container, &item.id, PlanItemStatus::Blocked, None, None);
                    self.block_run(container, &format!("plan item `{}` could not read the team: {err}", item.id));
                    return;
                }
            },
        };
        let mut steps = execution.steps;
        if let Some(verify) = item.verify {
            steps.verify = verify;
        }
        if let Some(review) = item.review {
            steps.review = review;
        }
        let request = DelegateRequest {
            run_id: None,
            role: RoleName::Builder,
            task,
            model: None,
            session: SessionSpec::Fresh,
            base_ref,
            worktree: None,
            steps: Some(steps),
            // Internal (the plan conductor's own item start): the container→item linkage is
            // already `plan.item.itemRunId`, so this must not also mint a `run.delegated`.
            caller_run_id: None,
        };
        execution.steps = steps;
        match self.delegate_with_execution(request, Some(execution)) {
            Ok(out) => {
                self.plan_item(
                    container,
                    &item.id,
                    PlanItemStatus::Started,
                    Some(out.run_id),
                    None,
                );
            }
            Err(err) => {
                self.plan_item(container, &item.id, PlanItemStatus::Blocked, None, None);
                self.block_run(
                    container,
                    &format!("plan item `{}` could not start: {err}", item.id),
                );
            }
        }
    }

    /// Mints the item's `plan` gate on the container run. Resolution is socket-only like every
    /// gate (S2); approval marks the item done on the next poke.
    fn start_plan_human_item(&mut self, container: &RunId, item: &crate::core::plan::PlanItem) {
        let summary = item.summary.clone().unwrap_or_default();
        match self.open_gate(container, GateKind::Plan, &summary, GatePayload::default()) {
            Some(gate) => {
                self.plan_item(
                    container,
                    &item.id,
                    PlanItemStatus::Started,
                    None,
                    Some(gate),
                );
            }
            None => {
                self.plan_item(container, &item.id, PlanItemStatus::Blocked, None, None);
                self.block_run(
                    container,
                    &format!("plan item `{}` could not open its gate", item.id),
                );
            }
        }
    }

    fn open_gate(
        &mut self,
        run: &RunId,
        kind: GateKind,
        summary: &str,
        payload: GatePayload,
    ) -> Option<GateId> {
        let gate = NewGate {
            kind,
            summary: clamp_untrusted(summary, MAX_SUMMARY_CHARS),
            requested_by: Origin::ControlPlane,
            payload,
        };
        match gates::create_gate(&mut self.registry, run, gate) {
            Ok(gate) => {
                tracing::info!(%run, gate = %gate.gate_id, ?kind, "gate opened");
                Some(gate.gate_id)
            }
            Err(err) => {
                tracing::warn!(%run, %err, "the gate could not be opened");
                None
            }
        }
    }

    fn set_awaiting_gate(&mut self, run: &RunId) {
        self.emit(
            run,
            EventPayload::RunStatus_ {
                status: RunStatus::AwaitingGate,
                reason: None,
            },
        );
        self.emit(
            run,
            EventPayload::LoopStateChanged {
                state: LoopState::AwaitingGate,
                builder_agent_id: self.live_builder(run),
                attempt_no: 0,
                strikes: 0,
            },
        );
    }

    // -----------------------------------------------------------------------
    // Shared plumbing
    // -----------------------------------------------------------------------

    /// The validated `team.json`, read at `delegate` time so `team.set` takes effect on the next
    /// spawn (Rev 26).
    ///
    /// A file that exists and cannot be trusted **rejects the delegation**: the daemon never
    /// silently falls back to the defaults when a human has written a team it cannot honour.
    fn valid_team(&mut self) -> Result<Option<ValidTeam>, CoreError> {
        let path = team::team_path(&self.state_dir);
        let team = match team::load_team(&self.state_dir) {
            Ok(None) => return Ok(None),
            Ok(Some(team)) => team,
            Err(err) => {
                let error = PolicyError::new(
                    PolicyCode::TeamInvalid,
                    format!("{}: {err}", path.display()),
                );
                return Err(self.reject("delegate", "team", error));
            }
        };
        match team::validate_team(&self.roles, &team) {
            Ok(valid) => Ok(Some(valid)),
            Err(issues) => {
                let detail = issues
                    .iter()
                    .map(|i| format!("{} {}: {}", i.role, i.code, i.detail))
                    .collect::<Vec<_>>()
                    .join("; ");
                let error = PolicyError::new(
                    PolicyCode::TeamInvalid,
                    format!("{}: {detail}", path.display()),
                );
                Err(self.reject("delegate", "team", error))
            }
        }
    }

    fn request_execution(&self, req: &DelegateRequest) -> Option<&RunExecution> {
        let run = match req.session {
            SessionSpec::Resume(agent) => self.registry.agent(&agent).map(|a| a.run_id),
            SessionSpec::Fresh => req.run_id,
        }?;
        self.registry.run(&run).and_then(|r| r.execution.as_ref()).or_else(||
            self.pending_worktree.values().find(|p| p.run == run).and_then(|p| p.execution.as_ref()))
    }

    /// `check_delegate` for a spawn the **control plane** asks for (a reviewer, a retry, a
    /// replacement). It is the same chokepoint a lead's call passes: budget, concurrency, the
    /// one-writer rule and the team's provider/model for the role.
    fn resolve_internal(&mut self, req: &DelegateRequest) -> Result<Resolved, PolicyError> {
        let cfg = Arc::clone(&self.roles);
        let team = match if self.request_execution(req).is_some() { Ok(None) } else { self.valid_team() } {
            Ok(team) => team,
            Err(CoreError::Policy(err)) => return Err(err),
            Err(err) => {
                return Err(PolicyError::new(PolicyCode::TeamInvalid, err.to_string()));
            }
        };
        let ctx = PolicyCtx {
            registry: &self.registry,
            cfg: &cfg,
            caller_role: RoleName::Lead,
            caller_depth: 0,
            now: epoch_secs,
        };
        policy::check_delegate(req, &ctx, team.as_ref()).map(|r| Resolved {
            provider: r.provider,
            model: r.model.to_string(),
            effort: r.effort,
            depth: r.depth,
            base_ref: r.base_ref.clone(),
            writes: r.writes,
            spawn_budget_usd: r.spawn_budget_usd,
            attempt_timeout_sec: r.attempt_timeout_sec,
        })
    }

    /// Audits a rejection and turns it into the error a door reports.
    fn reject(&mut self, tool: &str, digest: &str, err: PolicyError) -> CoreError {
        self.registry.audit(AuditEntry::new(
            tool,
            err.code.as_str(),
            &err.reason,
            digest,
        ));
        CoreError::Policy(err)
    }

    /// `agent.status{idle}` for the agent whose attempt just ended, when it still has a session to
    /// come back to (design, steps 13/15).
    ///
    /// Without it every live agent projected as `starting` for the whole run — nothing else ever
    /// moved the field — so `get_status`'s `processState` and `recommendedNext` described a worker
    /// that had long since finished. `closed` stays where it already is: 17c's dead session and
    /// 17d's retired lineage are the only two places the loop knows an agent is *done*.
    ///
    /// An agent with no session is left alone: it never became resumable, and 17c is about to close
    /// it. So are `closed`, `cancelled` and `lost` — all three outrank `idle`, and two of them are
    /// a human's decision.
    fn mark_idle(&mut self, attempt: &AttemptId) {
        let Some(agent) = self
            .registry
            .attempt(attempt)
            .and_then(|a| self.registry.agent(&a.agent_id))
        else {
            return;
        };
        if agent.session_id.is_none()
            || matches!(
                agent.status,
                AgentStatus::Idle
                    | AgentStatus::Closed
                    | AgentStatus::Cancelled
                    | AgentStatus::Lost
            )
        {
            return;
        }
        let (run, agent) = (agent.run_id, agent.agent_id);
        self.set_agent_status(&run, &agent, AgentStatus::Idle, "its attempt finished");
    }

    /// Moves an agent's `status`, and only when it is actually moving.
    ///
    /// The guard is the whole idempotency story: the projection's current value is what says
    /// whether the append is owed, so a re-driven branch — or a duplicated completion — writes
    /// nothing the second time and the reducer's C2 rules never have to reason about it.
    fn set_agent_status(
        &mut self,
        run: &RunId,
        agent: &AgentId,
        status: AgentStatus,
        reason: &str,
    ) {
        if self.registry.agent(agent).map(|a| a.status) == Some(status) {
            return;
        }
        self.emit(
            run,
            EventPayload::AgentStatusChanged {
                agent_id: *agent,
                status,
                reason: Some(reason.to_string()),
            },
        );
    }

    /// Appends one event, logging (never propagating) a log that will not take it.
    ///
    /// The loop has no caller to hand a `RegistryError` to: `on_attempt_finished` returns `()` by
    /// design. A genuinely unwritable log is caught by the supervisor's finalize retry budget,
    /// which is what stops the actor.
    fn emit(&mut self, run: &RunId, payload: EventPayload) {
        if let Err(err) = self.registry.append(run, payload) {
            tracing::warn!(%run, %err, "the loop could not append an event");
        }
    }

    /// `run.status{blocked, reason}` + `loop.state{blocked}` — the design's answer to every
    /// internal failure the loop meets (C1).
    fn block_run(&mut self, run: &RunId, reason: &str) {
        let reason = clamp_untrusted(reason, MAX_SUMMARY_CHARS);
        tracing::warn!(%run, %reason, "the run is blocked");
        let builder = self.live_builder(run);
        self.emit(
            run,
            EventPayload::RunStatus_ {
                status: RunStatus::Blocked,
                reason: Some(reason),
            },
        );
        self.emit(
            run,
            EventPayload::LoopStateChanged {
                state: LoopState::Blocked,
                builder_agent_id: builder,
                attempt_no: 0,
                strikes: 0,
            },
        );
        // A blocked item run must reach its plan (B3); the guard makes this a no-op while the
        // conductor itself is what blocked the run.
        self.drive_plans();
    }

    /// The branch's last append: everything it did is durable behind this.
    fn mark(&mut self, f: &Finished, branch: LoopBranch) {
        self.emit(
            &f.run,
            EventPayload::LoopDispatched {
                attempt_id: f.attempt,
                branch,
            },
        );
    }

    // -----------------------------------------------------------------------
    // Projection reads
    // -----------------------------------------------------------------------

    /// The snapshot the branch table runs on, or `None` for an attempt that is not terminal (or
    /// that this state dir has never seen).
    fn finished(&self, attempt: &AttemptId) -> Option<Finished> {
        let a = self.registry.attempt(attempt)?;
        if !is_terminal(a.status) {
            return None;
        }
        let agent = self.registry.agent(&a.agent_id)?;
        let finish_seq = self.finish_seq(&a.run_id, attempt)?;
        Some(Finished {
            attempt: *attempt,
            run: a.run_id,
            agent: a.agent_id,
            status: a.status,
            error: a.error.clone(),
            structured: a.structured.clone(),
            finish_seq,
            parent: agent.parent_agent_id,
        })
    }

    /// The builder facts a branch acts on.
    fn target_of(&self, agent: &AgentId) -> Option<Target> {
        let handle = self.registry.agent(agent)?;
        let run = self.registry.run(&handle.run_id)?;
        let lineage_id = handle.lineage_id?;
        let lineage = run.lineages.iter().find(|l| l.lineage_id == lineage_id);
        let worktree = handle
            .worktree
            .clone()
            .or_else(|| lineage.map(|l| l.worktree.clone()))
            .unwrap_or_else(|| handle.cwd.clone());
        Some(Target {
            agent: *agent,
            lineage: lineage_id,
            worktree,
            cwd: handle.cwd.clone(),
            session: handle.session_id.clone(),
            resumable: handle.resumable,
            strikes: lineage.map_or(0, |l| l.strikes),
            attempt_no: u32::try_from(handle.attempt_ids.len()).unwrap_or(u32::MAX),
        })
    }

    /// The newest builder of `run` that could still take a turn.
    fn live_builder(&self, run: &RunId) -> Option<AgentId> {
        let run = self.registry.run(run)?;
        run.agent_ids
            .iter()
            .rev()
            .filter_map(|id| self.registry.agent(id))
            .find(|a| a.role == RoleName::Builder && a.resumable && a.status != AgentStatus::Closed)
            .map(|a| a.agent_id)
    }

    fn task_of(&self, run: &RunId) -> Option<Task> {
        self.registry.run(run).map(|r| r.task.clone())
    }

    fn lineage_strikes(&self, run: &RunId, lineage: &LineageId) -> u8 {
        self.registry.run(run).map_or(0, |run| {
            run.lineages
                .iter()
                .find(|l| l.lineage_id == *lineage)
                .map_or(0, |l| l.strikes)
        })
    }

    /// The run and the newest agent of a lineage — what 17c retries from.
    fn lineage_target(&self, lineage: &LineageId) -> Option<(RunId, Target)> {
        let run = self
            .registry
            .runs()
            .find(|r| r.lineages.iter().any(|l| l.lineage_id == *lineage))?;
        let agent = run
            .lineages
            .iter()
            .find(|l| l.lineage_id == *lineage)?
            .agent_ids
            .last()?;
        let target = self.target_of(agent)?;
        Some((run.run_id, target))
    }

    /// The commit a lineage's worktree was created at: the sha its next attempt diffs against,
    /// because a worker that commits is soft-reset back to it.
    fn lineage_base_sha(&self, run: &RunId, lineage: &LineageId) -> String {
        self.registry
            .events(run, None, usize::MAX)
            .iter()
            .rev()
            .find_map(|e| match &e.payload {
                EventPayload::WorktreeCreated {
                    lineage_id,
                    base_sha,
                    ..
                } if lineage_id == lineage => Some(base_sha.clone()),
                _ => None,
            })
            .or_else(|| self.registry.run(run).map(|r| r.base_sha.clone()))
            .unwrap_or_default()
    }

    pub(super) fn agent_base_sha(&self, agent: &AgentId) -> String {
        self.registry.agent(agent).map_or_else(String::new, |a| {
            a.lineage_id.as_ref().map_or_else(String::new, |lineage| {
                self.lineage_base_sha(&a.run_id, lineage)
            })
        })
    }

    /// The newest error recorded against any attempt of `agent` — what the retry prompt quotes.
    fn last_attempt_error(&self, agent: &AgentId) -> Option<AttemptError> {
        let handle = self.registry.agent(agent)?;
        handle
            .attempt_ids
            .iter()
            .rev()
            .filter_map(|id| self.registry.attempt(id))
            .find_map(|a| a.error.clone())
    }

    /// Every file the lineage's attempts are known to have changed, for the replacement prompt.
    fn lineage_files(&self, run: &RunId, lineage: &LineageId) -> Vec<String> {
        let Some(state) = self
            .registry
            .run(run)
            .and_then(|r| r.lineages.iter().find(|l| l.lineage_id == *lineage))
        else {
            return Vec::new();
        };
        let attempts: Vec<AttemptId> = state
            .agent_ids
            .iter()
            .filter_map(|id| self.registry.agent(id))
            .flat_map(|a| a.attempt_ids.clone())
            .collect();
        let mut files: Vec<String> = Vec::new();
        for event in self.registry.events(run, None, usize::MAX) {
            if let EventPayload::DiffFrozen {
                attempt_id,
                files: changed,
                ..
            } = &event.payload
            {
                if attempts.contains(attempt_id) {
                    for file in changed {
                        if !files.contains(file) {
                            files.push(file.clone());
                        }
                    }
                }
            }
        }
        files
    }

    /// Every `policy.violation` recorded against the lineage this agent belongs to, rendered for a
    /// gate summary. The design requires the integrate gate to name all of them.
    fn violation_summary(&self, agent: &AgentId) -> String {
        let Some(handle) = self.registry.agent(agent) else {
            return String::new();
        };
        let Some(run) = self.registry.run(&handle.run_id) else {
            return String::new();
        };
        let agents: Vec<AgentId> = run
            .lineages
            .iter()
            .find(|l| Some(l.lineage_id) == handle.lineage_id)
            .map_or_else(|| vec![*agent], |l| l.agent_ids.clone());
        let mut lines = Vec::new();
        for id in agents {
            let Some(handle) = self.registry.agent(&id) else {
                continue;
            };
            for attempt in &handle.attempt_ids {
                let Some(attempt) = self.registry.attempt(attempt) else {
                    continue;
                };
                for violation in &attempt.violations {
                    lines.push(format!(
                        "- {:?}: {}{}",
                        violation.kind,
                        violation.detail,
                        violation
                            .files
                            .as_ref()
                            .map(|f| format!(" [{}]", f.join(", ")))
                            .unwrap_or_default()
                    ));
                }
            }
        }
        if lines.is_empty() {
            "Policy violations: none recorded.".to_string()
        } else {
            format!("Policy violations:\n{}", lines.join("\n"))
        }
    }

    /// The `diff.frozen` of one attempt.
    fn frozen_diff(&self, run: &RunId, attempt: &AttemptId) -> Option<Frozen> {
        self.registry
            .events(run, None, usize::MAX)
            .iter()
            .rev()
            .find_map(|e| match &e.payload {
                EventPayload::DiffFrozen {
                    attempt_id,
                    diff_path,
                    diff_hash,
                    files,
                    ..
                } if attempt_id == attempt => Some(Frozen {
                    attempt: *attempt_id,
                    path: diff_path.clone(),
                    hash: diff_hash.clone(),
                    files: files.clone(),
                }),
                _ => None,
            })
    }

    /// The diff a reviewer attempt was shown: the newest `diff.frozen` of the builder it was
    /// created under, falling back to the newest one in the run.
    fn reviewed_diff(&self, f: &Finished) -> Option<Frozen> {
        if self.run_steps(&f.run).security {
            return security::inspection_diff(&self.registry, &f.run, f.agent);
        }
        let builder_attempts: Vec<AttemptId> = f
            .parent
            .and_then(|agent| self.registry.agent(&agent))
            .map(|a| a.attempt_ids.clone())
            .unwrap_or_default();
        self.registry
            .events(&f.run, None, usize::MAX)
            .iter()
            .rev()
            .find_map(|e| match &e.payload {
                EventPayload::DiffFrozen {
                    attempt_id,
                    diff_path,
                    diff_hash,
                    files,
                    ..
                } if builder_attempts.is_empty() || builder_attempts.contains(attempt_id) => {
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

    /// B1: whether the loaded roles config carries a verifier — the one switch that turns the
    /// verify step on. A custom roles file without the role runs the Phase-1 path unchanged.
    fn verifier_configured(&self) -> bool {
        self.roles.roles.contains_key(&RoleName::Verifier)
    }

    /// The step switches this run was created with (B3). `Default` — everything on — for
    /// pre-B3 logs and teamless runs, exactly the meaning absence has always had. Reading the
    /// run's captured value rather than today's `team.json` is what keeps a mid-run team edit
    /// from changing a running run's shape.
    fn run_steps(&self, run: &RunId) -> RunSteps {
        self.registry
            .run(run)
            .and_then(|r| r.steps)
            .unwrap_or_default()
    }

    /// B1: the schema-validated report of the newest verifier attempt for one frozen diff, read
    /// back from the attempt projection. From the log rather than a parameter so replacement
    /// reviewers and restart re-drives carry the identical report.
    fn recorded_verify_report(
        &self,
        run: &RunId,
        builder_attempt: AttemptId,
    ) -> Option<VerifyReport> {
        self.registry
            .events(run, None, usize::MAX)
            .iter()
            .rev()
            .find_map(|e| match &e.payload {
                EventPayload::VerifyReport {
                    attempt_id,
                    builder_attempt_id,
                    ..
                } if *builder_attempt_id == builder_attempt => Some(*attempt_id),
                _ => None,
            })
            .and_then(|attempt| self.registry.attempt(&attempt))
            .and_then(|a| a.structured.clone())
            .and_then(|v| serde_json::from_value::<VerifyReport>(v).ok())
    }

    /// B1's mirror of [`Self::reviewers_for`]: how many verifiers one frozen diff has consumed.
    fn verifiers_for(&self, run: &RunId, builder_attempt: AttemptId) -> usize {
        self.workers_for(run, builder_attempt, RoleName::Verifier)
    }

    /// Workers of one role started after one diff was frozen — the shared body of the two
    /// per-diff budgets above.
    fn workers_for(&self, run: &RunId, builder_attempt: AttemptId, role: RoleName) -> usize {
        let events = self.registry.events(run, None, usize::MAX);
        let frozen_seq = events
            .iter()
            .find_map(|e| match &e.payload {
                EventPayload::DiffFrozen { attempt_id, .. } if *attempt_id == builder_attempt => {
                    Some(e.base.seq)
                }
                _ => None,
            })
            .unwrap_or(0);
        events
            .iter()
            .filter(|e| e.base.seq > frozen_seq)
            .filter(|e| {
                matches!(
                    &e.payload,
                    EventPayload::AgentCreated { role: created, .. } if *created == role
                )
            })
            .count()
    }

    /// `seq` of an attempt's terminal event — the start of every idempotency window below.
    fn finish_seq(&self, run: &RunId, attempt: &AttemptId) -> Option<u64> {
        self.registry
            .events(run, None, usize::MAX)
            .iter()
            .find(|e| {
                matches!(&e.payload, EventPayload::AttemptFinished { attempt_id, .. }
                    if attempt_id == attempt)
            })
            .map(|e| e.base.seq)
    }

    /// Everything appended after `seq` — what a re-drive of the branch would duplicate.
    fn since(&self, run: &RunId, seq: u64) -> Vec<Arc<Event>> {
        self.registry.events(run, Some(seq), usize::MAX)
    }

    fn struck_since(&self, run: &RunId, seq: u64, lineage: &LineageId) -> bool {
        self.since(run, seq).iter().any(|e| {
            matches!(&e.payload, EventPayload::LineageStrike { lineage_id, .. }
                if lineage_id == lineage)
        })
    }

    fn closed_since(&self, run: &RunId, seq: u64, lineage: &LineageId) -> bool {
        self.since(run, seq).iter().any(|e| {
            matches!(&e.payload, EventPayload::LineageClosed { lineage_id, .. }
                if lineage_id == lineage)
        })
    }

    fn gate_since(&self, run: &RunId, seq: u64) -> bool {
        self.since(run, seq)
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::GateCreated { .. }))
    }

    fn verdict_since(&self, run: &RunId, seq: u64) -> bool {
        self.since(run, seq)
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::ReviewVerdict { .. }))
    }

    fn agent_created_since(&self, run: &RunId, seq: u64, role: RoleName) -> bool {
        self.since(run, seq).iter().any(|e| {
            matches!(&e.payload, EventPayload::AgentCreated { role: created, .. }
                if *created == role)
        })
    }

    fn reviewer_created_since(&self, run: &RunId, seq: u64) -> bool {
        self.agent_created_since(run, seq, RoleName::Reviewer)
    }

    fn verifier_created_since(&self, run: &RunId, seq: u64) -> bool {
        self.agent_created_since(run, seq, RoleName::Verifier)
    }

    fn verify_report_since(&self, run: &RunId, seq: u64) -> bool {
        self.since(run, seq)
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::VerifyReport { .. }))
    }

    fn attempt_started_since(&self, run: &RunId, seq: u64, agent: &AgentId) -> bool {
        self.since(run, seq).iter().any(|e| {
            matches!(&e.payload, EventPayload::AttemptStarted { agent_id, .. }
                if agent_id == agent)
        })
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

fn run_created(
    p: &PendingWorktree,
    repo_root: PathBuf,
    state_dir: PathBuf,
    base_sha: String,
) -> EventPayload {
    EventPayload::RunCreated {
        execution: p.execution.clone(),
        repo_root,
        state_dir,
        base_ref: p.base_ref.clone(),
        base_sha,
        task: p.task.clone(),
        version: RUN_VERSION,
        lead: p.lead.clone(),
        team_name: p.team_name.as_deref().map(bounded_team_name),
        steps: p.steps,
    }
}

/// Clamps without splitting a Unicode scalar and keeps the returned value at or below the bound,
/// including the marker that tells a reader the persisted name was longer.
fn bounded_team_name(name: &str) -> String {
    if name.chars().count() <= MAX_TEAM_NAME_CHARS {
        return name.to_string();
    }
    let mut bounded: String = name.chars().take(MAX_TEAM_NAME_CHARS - 1).collect();
    bounded.push('…');
    bounded
}

fn loop_state(state: LoopState, target: &Target, strikes: u8) -> EventPayload {
    EventPayload::LoopStateChanged {
        state,
        builder_agent_id: Some(target.agent),
        attempt_no: target.attempt_no,
        strikes,
    }
}

fn strike_reason(cause: &StrikeCause) -> String {
    match cause {
        StrikeCause::ReviewFail(findings) => {
            let blocking = findings
                .iter()
                .filter(|f| f.severity == Severity::Blocking)
                .count();
            format!("the review failed with {blocking} blocking finding(s)")
        }
        StrikeCause::VerifyFail(report) => {
            format!(
                "verification failed with {} failure(s)",
                report.failures.len()
            )
        }
        StrikeCause::Failure(Some(err)) => format!("{}: {}", error_key(err.code), err.message),
        StrikeCause::Failure(None) => "the attempt ended without a usable result".to_string(),
    }
}

fn unknown_failure() -> AttemptError {
    AttemptError {
        code: ErrorCode::ProviderError,
        message: "the attempt ended without a usable result".to_string(),
    }
}

/// `<repoRoot>/.acp/worktrees/<runId>/<agentShort>` (design, § On-disk layout).
fn worktree_path(repo_root: &Path, run: &RunId, agent: &AgentId) -> PathBuf {
    repo_root
        .join(WORKTREES_DIR)
        .join(run.as_uuid().simple().to_string())
        .join(short(&agent.as_uuid().simple().to_string()))
}

/// `acp/<runId>/<agentShort>` — the branch a worktree is checked out on.
fn branch_name(run: &RunId, agent: &AgentId) -> String {
    format!(
        "acp/{}/{}",
        run.as_uuid().simple(),
        short(&agent.as_uuid().simple().to_string())
    )
}

/// `<stateDir>/runs/<runId>/attempts/<attemptId>` (design, § On-disk layout).
fn attempt_dir(state_dir: &Path, run: &RunId, attempt: &AttemptId) -> PathBuf {
    state_dir
        .join(RUNS_DIR)
        .join(run.as_uuid().simple().to_string())
        .join(ATTEMPTS_DIR)
        .join(attempt.as_uuid().simple().to_string())
}

fn short(id: &str) -> String {
    id.chars().take(SHORT_ID).collect()
}

/// Re-adopts every attempt the replayed log still calls `running` — **the restart path**.
///
/// A worker is a detached process in its own process group, so it survives the control plane that
/// started it (C3: "workers survive; a restart re-attaches"). What does *not* survive is the
/// supervisor's knowledge of it: the byte offset it was tailing, the deadline it was bounded by,
/// and the fact that anyone is waiting for it. Without this, a restarted daemon leaves such an
/// attempt `running` forever — untailed, untimed, never finalized — and the run behind it stalls.
///
/// It must run **before** the actor takes ownership of the supervisor, and it is deliberately a
/// free function rather than a `Core` method so that the daemon and the tests reach the *same*
/// implementation at the same point in the sequence.
///
/// Per attempt it rebuilds the [`AttemptContext`] from the log alone — the adapter and result
/// schema from the agent's provider and role, the denylist and rate card from the config, the
/// worktree and `session_id` from the agent handle. `session_id` is load-bearing: a resumed tail
/// starts past `system/init`, so without it `extract_result` reads the stream as a thread that
/// never started. [`Supervisor::reattach`] then re-arms the deadline from
/// `started_at + timeout_sec` (an already-expired one fires immediately) and the tailer resumes
/// from the recorded `srcLine`, so a duplicate re-parse is a reducer no-op (C2).
///
/// An attempt whose agent is missing from the projection is skipped rather than guessed at: that
/// is a log we cannot reconstruct a spawn from, and inventing one would be worse than leaving it.
pub fn reattach_running(supervisor: &mut Supervisor, registry: &Registry, roles: &RolesConfig) {
    let running: Vec<_> = registry
        .state()
        .attempts
        .values()
        .filter(|attempt| attempt.status == AttemptStatus::Running)
        .cloned()
        .collect();
    let denylist = compile_denylist(roles);

    for attempt in running {
        let Some(agent) = registry.agent(&attempt.agent_id) else {
            tracing::warn!(
                attempt = %attempt.attempt_id,
                "a running attempt has no agent in the log; not re-attaching it"
            );
            continue;
        };
        let schema_name = schema_of(agent.role);
        let worktree = agent.worktree.clone().unwrap_or_else(|| agent.cwd.clone());
        let worktree_lock = supervisor.worktree_lock(&worktree);
        let ctx = AttemptContext {
            run: attempt.run_id,
            agent: attempt.agent_id,
            attempt: attempt.attempt_id,
            dir: attempt.dir.clone(),
            adapter: adapter_for(agent.provider),
            timeout: Duration::from_secs(attempt.timeout_sec),
            pre_sha: attempt.pre_sha.clone(),
            kind: attempt.kind,
            role: agent.role,
            worktree,
            worktree_lock,
            writes: agent.writes,
            schema: schema_doc(schema_name),
            schema_name,
            denylist: Arc::clone(&denylist),
            spawn_budget_usd: attempt.spawn_budget_usd,
            rate: roles.rates.get(&agent.model).copied(),
            session_id: agent.session_id.clone(),
        };
        tracing::info!(
            attempt = %attempt.attempt_id,
            agent = %attempt.agent_id,
            pid = attempt.pid.unwrap_or_default(),
            "re-attaching to a worker that outlived the control plane"
        );
        supervisor.reattach(&attempt, ctx, registry);
    }
}

fn adapter_for(provider: ProviderName) -> Arc<dyn ProviderAdapter> {
    match provider {
        ProviderName::Claude => Arc::new(ClaudeAdapter),
        ProviderName::Codex => Arc::new(CodexAdapter),
    }
}

fn schema_of(role: RoleName) -> SchemaName {
    match role {
        RoleName::Reviewer | RoleName::Security => SchemaName::ReviewVerdict,
        RoleName::Verifier => SchemaName::VerifyReport,
        RoleName::Builder => SchemaName::BuildResult,
        RoleName::Lead => SchemaName::FreeText,
    }
}

fn schema_key(name: SchemaName) -> &'static str {
    match name {
        SchemaName::BuildResult => "build-result",
        SchemaName::ReviewVerdict => "review-verdict",
        SchemaName::VerifyReport => "verify-report",
        SchemaName::FreeText => "free-text",
    }
}

/// The post-processed schema document a role's worker must satisfy (V7): generated from the same
/// type `schemas/*.json` is generated from, `$schema` stripped, and cached — it is handed to the
/// CLI, compiled by `jsonschema` and quoted into the builder's prompt on every spawn.
fn schema_doc(name: SchemaName) -> Arc<Value> {
    static BUILD_RESULT: OnceLock<Arc<Value>> = OnceLock::new();
    static REVIEW_VERDICT: OnceLock<Arc<Value>> = OnceLock::new();
    static VERIFY_REPORT: OnceLock<Arc<Value>> = OnceLock::new();
    // Free text has no document: nothing is handed to a CLI and nothing is validated.
    static FREE_TEXT: OnceLock<Arc<Value>> = OnceLock::new();
    let cell = match name {
        SchemaName::BuildResult => &BUILD_RESULT,
        SchemaName::ReviewVerdict => &REVIEW_VERDICT,
        SchemaName::VerifyReport => &VERIFY_REPORT,
        SchemaName::FreeText => return Arc::clone(FREE_TEXT.get_or_init(|| Arc::new(Value::Null))),
    };
    Arc::clone(cell.get_or_init(|| {
        let doc = match name {
            SchemaName::BuildResult => serde_json::to_value(schemars::schema_for!(BuildResult)),
            SchemaName::ReviewVerdict => serde_json::to_value(schemars::schema_for!(ReviewVerdict)),
            SchemaName::VerifyReport => serde_json::to_value(schemars::schema_for!(VerifyReport)),
            SchemaName::FreeText => unreachable!("free text returned above"),
        };
        Arc::new(require_all_properties(strip_dollar_schema(
            doc.unwrap_or(Value::Null),
        )))
    }))
}

/// The schema as the builder's prompt quotes it.
fn schema_hint(role: RoleName) -> String {
    serde_json::to_string_pretty(&*schema_doc(schema_of(role))).unwrap_or_default()
}

/// The run's denylist, compiled. A glob that does not compile is dropped with a warning rather than
/// failing the spawn: the remaining patterns still deny, and `roles.json` is validated at load.
fn compile_denylist(cfg: &crate::core::types::RolesConfig) -> Arc<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in &cfg.defaults.denylist_globs {
        match Glob::new(pattern) {
            Ok(glob) => {
                builder.add(glob);
            }
            Err(err) => tracing::warn!(%pattern, %err, "denylist glob ignored"),
        }
    }
    Arc::new(builder.build().unwrap_or_else(|err| {
        tracing::error!(%err, "the denylist did not compile; nothing is denied");
        GlobSet::empty()
    }))
}

fn lead_label(team: &ValidTeam) -> Option<String> {
    team.lead()
        .map(|lead| format!("{}:{}", provider_key(lead.provider), lead.model))
}

fn provider_key(provider: ProviderName) -> &'static str {
    match provider {
        ProviderName::Claude => "claude",
        ProviderName::Codex => "codex",
    }
}

fn role_key(role: RoleName) -> &'static str {
    match role {
        RoleName::Lead => "lead",
        RoleName::Builder => "builder",
        RoleName::Reviewer => "reviewer",
        RoleName::Verifier => "verifier",
        RoleName::Security => "security",
    }
}

fn error_key(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::ProviderMissing => "provider_missing",
        ErrorCode::ProviderUnauthenticated => "provider_unauthenticated",
        ErrorCode::ResumeTargetMissing => "resume_target_missing",
        ErrorCode::SpawnError => "spawn_error",
        ErrorCode::SchemaInvalid => "schema_invalid",
        ErrorCode::MaxTurns => "max_turns",
        ErrorCode::BudgetHit => "budget_hit",
        ErrorCode::ProviderError => "provider_error",
        ErrorCode::NoChangedFiles => "no_changed_files",
        ErrorCode::DiffHashMismatch => "diff_hash_mismatch",
        ErrorCode::WorkspaceError => "workspace_error",
    }
}

/// Epoch seconds for [`PolicyCtx::now`]. Hand-rolled because the dependency set carries no date
/// crate (the registry stamps events the same way).
fn epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(code: ErrorCode) -> AttemptError {
        AttemptError {
            code,
            message: "…".to_string(),
        }
    }

    /// The design's step-17 table, row by row (§ Error Handling).
    #[test]
    fn the_branch_table_matches_the_design() {
        use AttemptStatus as S;
        let b = RoleName::Builder;
        let l = RoleName::Lead;
        let r = RoleName::Reviewer;

        // 17a — never a strike, whatever the status carrying it.
        assert_eq!(
            branch_of(b, S::SpawnFailed, Some(&err(ErrorCode::ProviderMissing))),
            Branch::Environment
        );
        assert_eq!(
            branch_of(
                r,
                S::SpawnFailed,
                Some(&err(ErrorCode::ProviderUnauthenticated))
            ),
            Branch::Environment
        );
        // A denylist hit and an unverifiable workspace both escalate without striking.
        assert_eq!(branch_of(b, S::Escalate, None), Branch::Escalate);
        assert_eq!(
            branch_of(b, S::Escalate, Some(&err(ErrorCode::WorkspaceError))),
            Branch::Escalate
        );
        // A human's decision, and a process we never identified: the loop does nothing.
        assert_eq!(branch_of(b, S::Cancelled, None), Branch::None);
        assert_eq!(branch_of(b, S::Lost, None), Branch::None);
        // Success and the reviewer's own turn.
        assert_eq!(branch_of(b, S::Succeeded, None), Branch::Review);
        assert_eq!(branch_of(r, S::Succeeded, None), Branch::Reviewer);
        assert_eq!(branch_of(r, S::Failed, None), Branch::Reviewer);
        // B1: every verifier ending — success, crash, timeout, garbage — lands in Verify; the
        // builder is never struck for a verifier's failure, and a verifier is never mis-read as
        // a builder that succeeded.
        let v = RoleName::Verifier;
        for status in [
            S::Succeeded,
            S::Failed,
            S::Timeout,
            S::InvalidOutput,
            S::NoSession,
        ] {
            assert_eq!(branch_of(v, status, None), Branch::Verify, "{status:?}");
        }
        assert_eq!(
            branch_of(v, S::SpawnFailed, Some(&err(ErrorCode::ProviderMissing))),
            Branch::Environment,
            "17a outranks the verifier row, like every role"
        );
        assert_eq!(branch_of(v, S::Cancelled, None), Branch::None);
        for status in [
            S::Succeeded,
            S::Failed,
            S::Timeout,
            S::InvalidOutput,
            S::NoSession,
        ] {
            assert_eq!(branch_of(l, status, None), Branch::Lead, "{status:?}");
        }
        // Everything else strikes.
        for status in [S::Failed, S::Timeout, S::InvalidOutput, S::NoSession] {
            assert_eq!(branch_of(b, status, None), Branch::Strike, "{status:?}");
        }
        assert_eq!(
            branch_of(b, S::SpawnFailed, Some(&err(ErrorCode::SpawnError))),
            Branch::Strike
        );
        assert_eq!(
            branch_of(
                b,
                S::SpawnFailed,
                Some(&err(ErrorCode::ResumeTargetMissing))
            ),
            Branch::Strike
        );
    }

    #[test]
    fn worktrees_and_branches_are_named_from_the_ids() {
        let run = RunId::new_v4();
        let agent = AgentId::new_v4();
        let path = worktree_path(Path::new("/repo"), &run, &agent);
        let branch = branch_name(&run, &agent);
        let short = short(&agent.as_uuid().simple().to_string());

        assert_eq!(short.len(), SHORT_ID);
        assert!(path.starts_with("/repo/.acp/worktrees"));
        assert!(path.ends_with(&short));
        assert_eq!(branch, format!("acp/{}/{short}", run.as_uuid().simple()));
        // The branch and the directory agree, which is what makes `git worktree list` readable.
        assert!(path
            .to_string_lossy()
            .ends_with(branch.trim_start_matches("acp/")));
    }

    #[test]
    fn the_attempt_dir_is_the_documented_layout() {
        let run = RunId::new_v4();
        let attempt = AttemptId::new_v4();
        let dir = attempt_dir(Path::new("/state"), &run, &attempt);
        assert_eq!(
            dir,
            Path::new("/state")
                .join("runs")
                .join(run.as_uuid().simple().to_string())
                .join("attempts")
                .join(attempt.as_uuid().simple().to_string())
        );
    }

    /// The document handed to the CLIs must be the `$schema`-stripped one (V7) — `claude
    /// --json-schema` rejects the other.
    #[test]
    fn the_spawned_schema_is_post_processed_and_cached() {
        let doc = schema_doc(SchemaName::BuildResult);
        assert!(doc.get("$schema").is_none());
        assert!(doc.get("properties").is_some());
        assert!(Arc::ptr_eq(&doc, &schema_doc(SchemaName::BuildResult)));
        let verdict = schema_doc(SchemaName::ReviewVerdict);
        assert!(verdict.get("$schema").is_none());
        // Rev 25: the reviewer's schema demands the hash it must echo.
        assert!(verdict.to_string().contains("diffHash"));
        // B1: the cell match and the schema_for! match must agree — a transposed arm would spawn
        // verifiers with the reviewer's schema and no test anywhere else would notice.
        let verify = schema_doc(SchemaName::VerifyReport);
        assert!(verify.to_string().contains("nothing-to-run"));
        assert!(Arc::ptr_eq(&verify, &schema_doc(SchemaName::VerifyReport)));
        // T83: free text has no document — `null`, cached like the others, never a real schema.
        let free = schema_doc(SchemaName::FreeText);
        assert!(free.is_null());
        assert!(Arc::ptr_eq(&free, &schema_doc(SchemaName::FreeText)));
    }

    #[test]
    fn a_team_name_is_bounded_before_it_enters_run_created() {
        let long = format!("{}tail", "é".repeat(MAX_TEAM_NAME_CHARS));
        let pending = PendingWorktree {
            execution: None,
            run: RunId::new_v4(),
            new_run: true,
            agent: AgentId::new_v4(),
            attempt: AttemptId::new_v4(),
            lineage: LineageId::new_v4(),
            role: RoleName::Builder,
            provider: ProviderName::Claude,
            model: "sonnet".to_string(),
            effort: None,
            depth: 1,
            parent: None,
            origin: Origin::Lead,
            writes: true,
            worktree: PathBuf::from("/repo/worktree"),
            base_ref: "HEAD".to_string(),
            task: Task {
                id: "T50".to_string(),
                title: "bound the team name".to_string(),
                description: "observe the value on run.created".to_string(),
                files: vec![],
                acceptance: vec![],
            },
            prompt: String::new(),
            lead: None,
            team_name: Some(long),
            timeout_sec: 60,
            spawn_budget_usd: 1.0,
            attempt_no: 1,
            strikes: 0,
            steps: None,
            caller_run_id: None,
        };

        let event = run_created(
            &pending,
            PathBuf::from("/repo"),
            PathBuf::from("/state"),
            "a".repeat(40),
        );
        let value = serde_json::to_value(event).expect("run.created serializes");
        let bounded = value["teamName"].as_str().expect("teamName");
        assert_eq!(bounded.chars().count(), MAX_TEAM_NAME_CHARS);
        assert!(bounded.ends_with('…'));
        assert!(!bounded.ends_with("tail"));
    }
}

#[cfg(test)]
#[path = "execution_tests.rs"]
mod execution_tests;
