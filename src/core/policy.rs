//! Fail-closed validation of every state-changing request, and the argv deny-list constants.
//! Implemented in T20 (`reports/03-design.md` § `src/core/policy.rs`).
//!
//! Every function here is **pure**: it reads the `Registry` projection and the `RolesConfig` it is
//! handed and returns a decision. It creates no worktree, spawns no process and appends no event —
//! a rejection is a `PolicyError` and nothing else, which is what makes "reject → no side effects"
//! (design, § Data Flow step 2) a property of these signatures rather than of the caller's care.
//!
//! What this module deliberately does **not** do:
//!
//! - `assert_safe_argv` / `CheckedPlan` and the codes they raise (`UnsafeArgv`, `SandboxMissing`,
//!   `ArgvTooLarge`, `UnsafeEnv`) live in `core::supervisor` (T22), which imports [`DENIED_ARGV`]
//!   and [`MAX_ARGV_BYTES`] from here. The constants are here because this module owns every
//!   `PolicyCode`; the check is there because `CheckedPlan`'s private field is only unforgeable
//!   inside the module that spawns (S5).
//! - `InvalidTask` is raised by the MCP door's `DelegateArgs::validate()` — the shape of caller
//!   input is a parsing concern, not a state concern.
//! - `RunBlocked`, `ResumeTargetMissing`, `RolePromptTampered` and `GitTimeout` are raised where
//!   the fact is known: the actor, the roles loader and the git helpers respectively. They are
//!   declared here so there is exactly one list of rejection codes in the system.
//!
//! **Must NOT know**: git, the filesystem, providers (design, § `src/core/policy.rs`).

use std::fmt;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

use crate::core::registry::Registry;
use crate::core::team::{provider_str, resolve_assignment, Effort, ValidTeam};
use crate::core::types::{
    Actor, AgentHandle, AgentId, AttemptStatus, Gate, GateKind, GateStatus, ProviderName, RoleName,
    RoleSpec, RolesConfig, Run, RunId, RunStatus, Task,
};

// ---------------------------------------------------------------------------
// Codes and errors
// ---------------------------------------------------------------------------

/// Every way the control plane says no. Closed set: a rejection the lead sees over MCP, the human
/// sees in `audit.jsonl` and the loop matches on is always one of these (design,
/// § `src/core/policy.rs`).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCode {
    UnknownRole,
    UnknownModel,
    DelegationNotAllowed,
    DepthExceeded,
    BudgetRunExceeded,
    BudgetSpawnExceeded,
    WorktreeBusy,
    /// A socket-started lead already has a provider spawn or running attempt in this repository.
    LeadBusy,
    GatePending,
    InvalidTask,
    /// A submitted B3 plan whose shape failed `plan::validate_plan` — the reason carries the
    /// per-item issue list.
    InvalidPlan,
    InvalidBaseRef,
    RunBlocked,
    AgentNotResumable,
    ResumeTargetMissing,
    UnsafeArgv,
    SandboxMissing,
    ArgvTooLarge,
    UnsafeEnv,
    AgentApproveNotAllowed,
    TooManyAttempts,
    RolePromptTampered,
    GitTimeout,
    /// The model asked for is one the role allows, but not one the provider that would actually
    /// spawn it understands (Rev 26). A role's `models` may span providers so a team can move the
    /// role between them; which provider runs is the team's choice, and the two have to agree.
    ModelProviderMismatch,
    /// `team.json` exists but cannot be trusted — malformed, a newer format, or naming a
    /// provider/model/effort the config does not allow. The `delegate` is rejected rather than
    /// run against the defaults (Rev 26): a team file the human wrote is not silently ignored.
    RecoveryUnavailable,
    TeamInvalid,
}

impl PolicyCode {
    /// The wire spelling — identical to what `serde` emits, and what
    /// [`AuditEntry`](crate::core::registry::AuditEntry) stores as a plain string so the registry
    /// keeps knowing nothing about policy.
    ///
    /// The match is exhaustive on purpose: a new code cannot be added without being named here.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyCode::UnknownRole => "unknown_role",
            PolicyCode::UnknownModel => "unknown_model",
            PolicyCode::DelegationNotAllowed => "delegation_not_allowed",
            PolicyCode::DepthExceeded => "depth_exceeded",
            PolicyCode::BudgetRunExceeded => "budget_run_exceeded",
            PolicyCode::BudgetSpawnExceeded => "budget_spawn_exceeded",
            PolicyCode::WorktreeBusy => "worktree_busy",
            PolicyCode::LeadBusy => "lead_busy",
            PolicyCode::GatePending => "gate_pending",
            PolicyCode::InvalidTask => "invalid_task",
            PolicyCode::InvalidPlan => "invalid_plan",
            PolicyCode::InvalidBaseRef => "invalid_base_ref",
            PolicyCode::RunBlocked => "run_blocked",
            PolicyCode::AgentNotResumable => "agent_not_resumable",
            PolicyCode::ResumeTargetMissing => "resume_target_missing",
            PolicyCode::UnsafeArgv => "unsafe_argv",
            PolicyCode::SandboxMissing => "sandbox_missing",
            PolicyCode::ArgvTooLarge => "argv_too_large",
            PolicyCode::UnsafeEnv => "unsafe_env",
            PolicyCode::AgentApproveNotAllowed => "agent_approve_not_allowed",
            PolicyCode::TooManyAttempts => "too_many_attempts",
            PolicyCode::RolePromptTampered => "role_prompt_tampered",
            PolicyCode::GitTimeout => "git_timeout",
            PolicyCode::ModelProviderMismatch => "model_provider_mismatch",
            PolicyCode::RecoveryUnavailable => "recovery_unavailable",
            PolicyCode::TeamInvalid => "team_invalid",
        }
    }
}

impl fmt::Display for PolicyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One rejection: a code the caller branches on, a sentence a human can act on, and optional
/// structured evidence (the allowed models, the agent holding the worktree, the budget figures).
#[derive(Debug, Error)]
#[error("{code:?}: {reason}")]
pub struct PolicyError {
    pub code: PolicyCode,
    pub reason: String,
    pub detail: Option<Value>,
}

impl PolicyError {
    /// A rejection with no structured evidence.
    #[must_use]
    pub fn new(code: PolicyCode, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
            detail: None,
        }
    }

    /// Attaches the evidence behind the rejection.
    #[must_use]
    pub fn with_detail(mut self, detail: Value) -> Self {
        self.detail = Some(detail);
        self
    }
}

// ---------------------------------------------------------------------------
// argv constants (enforced in `core::supervisor`)
// ---------------------------------------------------------------------------

/// The flags and flag *values* a spawned worker may never be given: the "skip every permission
/// check" escapes of the two CLIs, their auto-approve modes, and the three ways to point a worker
/// at a directory outside its worktree (design, § Security).
///
/// An argv token other than the provider adapter's declared prompt position is unsafe if it
/// *contains* one of these, not merely if it equals one, so
/// `--settings={"permissions":{"defaultMode":"bypassPermissions"}}` and `--add-dir=/etc` are both
/// caught. A declared prompt is instead refused when it begins with `-`, so human-authored prose
/// may quote flags without becoming one. `supervisor::assert_safe_argv` is the single place this
/// is enforced.
pub const DENIED_ARGV: &[&str] = &[
    "--dangerously-skip-permissions",
    "bypassPermissions",
    "danger-full-access",
    "--dangerously-bypass-approvals-and-sandbox",
    "--dangerously-bypass-hook-trust",
    "--full-auto",
    "--add-dir",
    "-C",
    "--cd",
    "--plugin-dir",
];

/// Ceiling on one spawn's argv **plus** its environment, in UTF-8 bytes. Well under macOS's
/// `ARG_MAX` (1 MiB), so a prompt that grew without bound fails as a policy rejection we can
/// explain rather than as `E2BIG` from `execve` (design, § Security: "≤ 200 KB with the env
/// included").
pub const MAX_ARGV_BYTES: usize = 200_000;

/// Longest `base_ref` this module accepts. Git has no such limit of its own; the bound exists so a
/// caller cannot push an unbounded string through the audit log and into a `git` argv.
const MAX_BASE_REF_CHARS: usize = 200;

/// Longest caller-supplied string this module ever copies into a `reason` or a `detail`. Both end
/// up in `audit.jsonl` and in an MCP error payload, neither of which should carry an unbounded
/// echo of the request that was rejected.
const MAX_ECHO_CHARS: usize = 80;

/// Validates a git ref the caller supplied, before it reaches any `git` argv (design,
/// § `src/workspace/git.rs`: "character-class validation of caller input … is `core::policy`'s
/// job").
///
/// Accepts a non-empty ref of at most [`MAX_BASE_REF_CHARS`] characters drawn from
/// `[A-Za-z0-9._/-]` that does not begin with `-` (which `git` would read as a flag — S4's
/// `--end-of-options` makes that harmless, but a ref that *looks* like a flag is never legitimate)
/// and contains no `..` (which git's own `check-ref-format` forbids, and which is the traversal
/// spelling a `.`-permitting character class would otherwise let through).
///
/// Hand-written on purpose: the design fixes the dependency set and `regex` is not in it.
#[must_use]
pub fn is_valid_base_ref(s: &str) -> bool {
    if s.is_empty() || s.chars().count() > MAX_BASE_REF_CHARS {
        return false;
    }
    if s.starts_with('-') || s.contains("..") {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
}

// ---------------------------------------------------------------------------
// Request / context / decision types
// ---------------------------------------------------------------------------

/// Everything a check may read, borrowed from the actor that owns it. Holding the `Registry` and
/// the `RolesConfig` by shared reference is what keeps these functions pure — there is no handle
/// here through which a check could mutate state.
#[derive(Clone, Copy)]
pub struct PolicyCtx<'a> {
    pub registry: &'a Registry,
    pub cfg: &'a RolesConfig,
    /// The role that made the call — `Lead` for anything arriving over MCP.
    pub caller_role: RoleName,
    /// How deep the caller already is; the spawn it asks for is one deeper.
    pub caller_depth: u8,
    /// Injected clock (epoch seconds), so a time-dependent check stays testable.
    pub now: fn() -> i64,
}

/// Which provider session an attempt should use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionSpec {
    /// A brand-new provider session.
    Fresh,
    /// Resume the named agent's session. The actor resolves `"resume:<uuid>"` to this and raises
    /// [`PolicyCode::ResumeTargetMissing`] itself when the id names no agent of this run.
    Resume(AgentId),
}

/// A `delegate` call as the core actor sees it: the MCP `DelegateArgs` (design, § MCP tools) plus
/// the two facts the actor resolves before policy runs — which agent (if any) the session belongs
/// to, and which worktree the spawn would write in.
///
/// `model` is an `Option` because `delegate` accepts no model over MCP (design, § Security:
/// "closed enums"): the door leaves it `None` and the role's `defaultModel` applies. The field
/// exists so the control plane's own retries can pin a model, and every value — supplied or
/// defaulted — is checked against the role's closed `models` list.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DelegateRequest {
    /// The run to attach to; `None` mints a new one.
    pub run_id: Option<RunId>,
    pub role: RoleName,
    /// The unit of work, from `DelegateArgs.task` (design, § MCP tools). Its *shape* is checked by
    /// `DelegateArgs::validate()` at the door; it travels this far because `run.created` records
    /// it and every prompt the loop builds is written around it.
    pub task: Task,
    pub model: Option<String>,
    pub session: SessionSpec,
    /// `None` inherits `defaults.baseRef`.
    pub base_ref: Option<String>,
    /// The worktree the spawn would write in, when it already exists (a resume, or a retry in an
    /// inherited lineage). `None` for a worktree that does not exist yet, which by definition no
    /// agent can be writing in.
    pub worktree: Option<PathBuf>,
    /// B3: the conductor's per-item step override. `None` — every door and every internal spawn
    /// except a plan item — captures the team's own decision instead. Neither MCP nor the socket
    /// exposes this field (their arg structs are `deny_unknown_fields`), so only the control
    /// plane can set it.
    pub steps: Option<crate::core::types::RunSteps>,
    /// T84: the run `acp mcp-proxy` attests this delegation came from, read out of its own
    /// `ACP_LEAD_RUN_ID` environment and carried on the socket's `DelegateParams.callerRunId`.
    /// Door-set like `steps` — the MCP tool schema does not expose it — but untrusted until
    /// `core::loop::validated_caller_run` confirms it names the current `live_lead_agent()`'s own
    /// run; nothing here treats it as authoritative on its own.
    pub caller_run_id: Option<RunId>,
}

/// What `check_delegate` resolved: the role to spawn from with every default applied and every
/// bound already checked. Borrowed from the `RolesConfig` the context carried.
#[derive(Clone, PartialEq, Debug)]
pub struct ResolvedSpawn<'a> {
    pub role: &'a RoleSpec,
    /// Which provider CLI to spawn — the team's choice for this role, or the role's own default.
    /// **The spawn path must read the adapter from here, never from `role.provider`** (Rev 26):
    /// `role.provider` is only the default, and a team can move the role to the other provider.
    pub provider: ProviderName,
    pub model: &'a str,
    /// The codex reasoning effort the team asked for, if any. `None` leaves the adapter on its
    /// configured constant; claude ignores it.
    pub effort: Option<Effort>,
    /// `caller_depth + 1`.
    pub depth: u8,
    pub base_ref: String,
    pub writes: bool,
    pub spawn_budget_usd: f64,
    /// What is left of the run budget once this spawn's cap is reserved.
    pub headroom_usd: f64,
    pub attempt_timeout_sec: u64,
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/// Validates a delegation and resolves it (design, § Data Flow step 2), in this order: the role
/// exists, the model is in that role's closed list *and* in the catalog of the provider that would
/// run it, the caller is allowed to delegate to it, the depth ceiling holds, the base ref is
/// well-formed, the budget has headroom, the run is under its attempt ceiling (S9), and no other
/// agent is writing in the target worktree (C5).
///
/// Order matters for the message the caller gets: the cheapest, most specific configuration error
/// is reported first, so "you asked for a role that does not exist" never surfaces as a budget
/// complaint.
///
/// `team` is the validated `team.json` (design Revision 26, § Team layer), or `None` when there is
/// none. It is what makes provider and model **one decision instead of two**: a role's `models` may
/// list models of either provider so a team can move the role between them, so the provider that
/// will actually spawn — the team's, not `role.provider` — is resolved here and the model is
/// checked against *its* catalog. Splitting the two is how `--model gpt-5.5` would reach `claude`.
///
/// The task's *shape* is not checked here — `DelegateArgs::validate()` owns that and raises
/// [`PolicyCode::InvalidTask`] before the request reaches the actor.
///
/// # Errors
/// One of `UnknownRole`, `UnknownModel`, `ModelProviderMismatch`, `DelegationNotAllowed`,
/// `DepthExceeded`, `InvalidBaseRef`, `BudgetRunExceeded`, `BudgetSpawnExceeded`,
/// `TooManyAttempts`, `WorktreeBusy`.
pub fn check_delegate<'a>(
    req: &DelegateRequest,
    ctx: &PolicyCtx<'a>,
    team: Option<&ValidTeam>,
) -> Result<ResolvedSpawn<'a>, PolicyError> {
    let cfg = ctx.cfg;

    let role = cfg.roles.get(&req.role).ok_or_else(|| {
        PolicyError::new(
            PolicyCode::UnknownRole,
            format!("no role `{}` in roles.json", role_str(req.role)),
        )
    })?;

    // Which provider will run this role, and what it runs by default: the team's entry when there
    // is one, the role's own `provider`/`defaultModel` when there is not (Rev 26).
    let run = match req.session {
        SessionSpec::Resume(agent) => ctx.registry.agent(&agent).and_then(|a| ctx.registry.run(&a.run_id)),
        SessionSpec::Fresh => req.run_id.as_ref().and_then(|id| ctx.registry.run(id)),
    };
    let execution = run.and_then(|r| r.execution.as_ref());
    if execution.is_some_and(|e| e.version != 1) {
        return Err(PolicyError::new(PolicyCode::TeamInvalid, "this run configuration version is unsupported"));
    }
    let mode = execution.map(|e| e.mode).or_else(|| team.map(ValidTeam::mode)).unwrap_or_default();
    if mode != crate::core::types::RunMode::Build && req.role == RoleName::Builder {
        return Err(PolicyError::new(PolicyCode::DelegationNotAllowed,
            "this task has no builder; planning and audit cannot write code"));
    }
    if mode == crate::core::types::RunMode::Plan && req.role != RoleName::Lead {
        return Err(PolicyError::new(PolicyCode::DelegationNotAllowed,
            "planning mode has no workers"));
    }
    let assignment = match execution {
        Some(e) => e.assignments.get(role_str(req.role)).cloned().ok_or_else(||
            PolicyError::new(PolicyCode::DelegationNotAllowed, "the run did not select this role"))?,
        None => resolve_assignment(cfg, team, req.role),
    };
    if execution.is_some() && req.model.as_ref().is_some_and(|m| m != &assignment.model) {
        return Err(PolicyError::new(PolicyCode::UnknownModel,
            "a running task keeps its recorded model assignment"));
    }
    let provider = assignment.provider;

    // The role's `models` list is the closed enum: a model that is not in it — including a
    // `defaultModel` the config forgot to list — is not spawnable. The borrow is taken from the
    // role's own list, so the resolved model always outlives the assignment it came from.
    let requested = req.model.as_deref().unwrap_or(&assignment.model);
    let model = role
        .models
        .iter()
        .find(|candidate| candidate.as_str() == requested)
        .ok_or_else(|| {
            PolicyError::new(
                PolicyCode::UnknownModel,
                format!(
                    "model `{}` is not allowed for role `{}`",
                    echo(requested),
                    role_str(req.role)
                ),
            )
            .with_detail(json!({ "allowed": role.models }))
        })?
        .as_str();

    // …and it has to be a model the provider that will actually spawn understands. Fails closed on
    // a config that carries no catalog for that provider: an unverifiable model is not a spawnable
    // one.
    let provider_models = cfg
        .providers
        .get(&provider)
        .map_or(&[][..], |spec| spec.models.as_slice());
    if !provider_models.iter().any(|m| m == model) {
        return Err(PolicyError::new(
            PolicyCode::ModelProviderMismatch,
            format!(
                "role `{}` would be spawned with provider `{}`, which has no model `{}`",
                role_str(req.role),
                provider_str(provider),
                echo(model)
            ),
        )
        .with_detail(json!({ "provider": provider_str(provider), "allowed": provider_models })));
    }

    let caller = cfg.roles.get(&ctx.caller_role).ok_or_else(|| {
        PolicyError::new(
            PolicyCode::UnknownRole,
            format!(
                "calling role `{}` is not in roles.json",
                role_str(ctx.caller_role)
            ),
        )
    })?;
    if !caller.allowed_delegations.contains(&req.role) {
        return Err(PolicyError::new(
            PolicyCode::DelegationNotAllowed,
            format!(
                "role `{}` may not delegate to `{}`",
                role_str(ctx.caller_role),
                role_str(req.role)
            ),
        )
        .with_detail(json!({ "allowedDelegations": caller.allowed_delegations })));
    }

    // `saturating_add` rather than `+`: a caller_depth of 255 must be rejected, not panic.
    let depth = ctx.caller_depth.saturating_add(1);
    if depth > cfg.defaults.max_depth {
        return Err(PolicyError::new(
            PolicyCode::DepthExceeded,
            format!(
                "delegation depth {depth} exceeds maxDepth {}",
                cfg.defaults.max_depth
            ),
        ));
    }

    // The configured default is validated too: a bad `defaults.baseRef` must fail closed rather
    // than reach a `git` argv unchecked.
    let base_ref = req
        .base_ref
        .clone()
        .unwrap_or_else(|| cfg.defaults.base_ref.clone());
    if !is_valid_base_ref(&base_ref) {
        return Err(PolicyError::new(
            PolicyCode::InvalidBaseRef,
            "baseRef must be 1-200 characters of [A-Za-z0-9._/-], must not start with `-` and must not contain `..`",
        )
        .with_detail(json!({ "baseRef": echo(&base_ref) })));
    }

    let run = req.run_id.and_then(|id| ctx.registry.run(&id));
    if run.is_some_and(|r| r.status == RunStatus::Cancelled) {
        return Err(PolicyError::new(PolicyCode::RunBlocked, "cancelled runs cannot accept new work; start a new task"));
    }
    if let SessionSpec::Resume(agent) = req.session {
        if ctx.registry.agent(&agent).and_then(|a| ctx.registry.run(&a.run_id))
            .is_some_and(|r| r.status == RunStatus::Cancelled) {
            return Err(PolicyError::new(PolicyCode::RunBlocked, "cancelled runs cannot be resumed; start a new task"));
        }
    }
    if let SessionSpec::Resume(agent) = req.session {
        if ctx.registry.agent(&agent).is_some_and(|a| a.role == RoleName::Lead) {
            return Err(PolicyError::new(PolicyCode::DelegationNotAllowed,
                "a lead is not a delegatable worker; human follow-ups use send_message"));
        }
    }
    let spawn_budget_usd = role.spawn_budget_usd;
    // A run the registry has never seen is one the actor is about to mint: nothing spent yet.
    let headroom_usd = budget_headroom(run.map_or(0.0, |r| r.spend_usd), spawn_budget_usd, cfg)?;

    if let Some(run) = run {
        let cap = usize::try_from(cfg.limits.max_concurrent_attempts).unwrap_or(usize::MAX);
        let running = running_attempts(ctx.registry, &run.run_id);
        if running >= cap {
            return Err(PolicyError::new(
                PolicyCode::TooManyAttempts,
                format!("{running} attempts already running, maxConcurrentAttempts is {cap}"),
            ));
        }
    }

    // C5, one writer per worktree. There are no lease files — the registry scan *is* the rule, and
    // the agent whose session is being resumed is allowed to be the writer it already is.
    if let Some(worktree) = req.worktree.as_deref() {
        let target = match req.session {
            SessionSpec::Fresh => None,
            SessionSpec::Resume(agent) => Some(agent),
        };
        if let Some(holder) = ctx
            .registry
            .live_writers(worktree)
            .into_iter()
            .find(|a| Some(a.agent_id) != target)
        {
            return Err(PolicyError::new(
                PolicyCode::WorktreeBusy,
                format!(
                    "agent {} is already writing in this worktree",
                    holder.agent_id
                ),
            )
            .with_detail(json!({
                "agentId": holder.agent_id.to_string(),
                "worktree": worktree,
            })));
        }
    }

    Ok(ResolvedSpawn {
        role,
        provider,
        model,
        effort: assignment.effort,
        depth,
        base_ref,
        writes: role.writes,
        spawn_budget_usd,
        headroom_usd,
        attempt_timeout_sec: cfg.defaults.attempt_timeout_sec,
    })
}

/// Validates a follow-up turn on a live agent: the agent must exist with a provider session we can
/// resume, no integrate gate for its run may still be pending or resolving, and its run must still
/// have budget for another turn.
///
/// An unknown agent and a non-resumable one are the same rejection on purpose — "there is no
/// session to send this message to" is one fact, and separating them would tell a caller which
/// agent ids exist.
///
/// # Errors
/// `AgentNotResumable`, `GatePending`, `BudgetRunExceeded` or `BudgetSpawnExceeded`.
pub fn check_send_message<'a>(
    agent: &AgentId,
    ctx: &PolicyCtx<'a>,
) -> Result<&'a AgentHandle, PolicyError> {
    let handle = ctx.registry.agent(agent).ok_or_else(|| {
        PolicyError::new(
            PolicyCode::AgentNotResumable,
            format!("no agent {agent} with a resumable session"),
        )
    })?;
    if handle.role == RoleName::Security {
        return Err(PolicyError::new(PolicyCode::DelegationNotAllowed,
            "security checks are single-use inspections; start a new workflow for new input"));
    }
    if ctx.registry.run(&handle.run_id).is_some_and(|r| r.status == RunStatus::Cancelled) {
        return Err(PolicyError::new(PolicyCode::RunBlocked, "this task was cancelled; start a new task"));
    }
    if !handle.resumable {
        return Err(PolicyError::new(
            PolicyCode::AgentNotResumable,
            format!("agent {agent} has no provider session to resume yet"),
        ));
    }

    // An integrate gate is the human's decision window over this run's worktree. Starting another
    // turn before that window settles would let the worker change the reviewed bytes, and a
    // resolving approval may already have staged them. This runs before the budget check so a
    // gate-owned worktree is always named as the actionable refusal, even when the run is also out
    // of money. Pick by id because the projection is a HashMap and error details must be stable.
    if let Some(gate) = ctx
        .registry
        .state()
        .gates
        .values()
        .filter(|gate| {
            gate.run_id == handle.run_id
                && gate.kind == GateKind::Integrate
                && matches!(gate.status, GateStatus::Pending | GateStatus::Resolving)
        })
        .min_by_key(|gate| *gate.gate_id.as_uuid())
    {
        let status = match gate.status {
            GateStatus::Pending => "pending",
            GateStatus::Resolving => "resolving",
            GateStatus::Approved | GateStatus::Denied => unreachable!("filtered above"),
        };
        return Err(PolicyError::new(
            PolicyCode::GatePending,
            format!(
                "integrate gate {} is {status}; resolve or deny it before resuming agent {agent}",
                gate.gate_id
            ),
        )
        .with_detail(json!({
            "gateId": gate.gate_id.to_string(),
            "status": status,
        })));
    }

    let spawn_cap = ctx
        .cfg
        .roles
        .get(&handle.role)
        .map_or(ctx.cfg.defaults.spawn_budget_usd, |r| r.spawn_budget_usd);
    if let Some(run) = ctx.registry.run(&handle.run_id) {
        check_budget(run, spawn_cap, ctx.cfg)?;
    }

    Ok(handle)
}

/// Enforces S2, the approval authority: a model may not approve its own integration.
///
/// Only the MCP door is restricted, and only for `integrate` gates — `Actor::Socket` is the human
/// path (the `acp` CLI and the menu-bar app) and is always allowed, and an `escalate`/`plan` gate
/// carries no commit.
///
/// # Errors
/// `AgentApproveNotAllowed`.
pub fn check_gate_resolve(
    g: &Gate,
    approve: bool,
    by: &Actor,
    cfg: &RolesConfig,
) -> Result<(), PolicyError> {
    if approve
        && matches!(by, Actor::Mcp)
        && g.kind == GateKind::Integrate
        && !cfg.gates.allow_agent_approve
    {
        return Err(PolicyError::new(
            PolicyCode::AgentApproveNotAllowed,
            "only a human may approve an integrate gate; ask them to run `acp gate approve`",
        )
        .with_detail(json!({ "gateId": g.gate_id.to_string() })));
    }
    Ok(())
}

/// Checks that `run` can afford one more spawn capped at `spawn_cap_usd`, returning the run budget
/// that would be left once that cap is reserved.
///
/// The run ceiling is tested before the per-spawn ceiling: a run that is out of money is out of
/// money whatever the spawn asks for.
///
/// # Errors
/// `BudgetRunExceeded` or `BudgetSpawnExceeded`.
pub fn check_budget(run: &Run, spawn_cap_usd: f64, cfg: &RolesConfig) -> Result<f64, PolicyError> {
    budget_headroom(run.spend_usd, spawn_cap_usd, cfg)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The arithmetic behind [`check_budget`], over a bare spend figure so `check_delegate` can apply
/// it to a run the registry has not minted yet.
fn budget_headroom(
    spend_usd: f64,
    spawn_cap_usd: f64,
    cfg: &RolesConfig,
) -> Result<f64, PolicyError> {
    let run_budget = cfg.defaults.run_budget_usd;
    if spend_usd + spawn_cap_usd > run_budget {
        return Err(PolicyError::new(
            PolicyCode::BudgetRunExceeded,
            format!(
                "run has spent ${spend_usd:.2} of ${run_budget:.2}; a ${spawn_cap_usd:.2} spawn would exceed it"
            ),
        )
        .with_detail(json!({
            "spendUsd": spend_usd,
            "spawnCapUsd": spawn_cap_usd,
            "runBudgetUsd": run_budget,
        })));
    }
    let spawn_budget = cfg.defaults.spawn_budget_usd;
    if spawn_cap_usd > spawn_budget {
        return Err(PolicyError::new(
            PolicyCode::BudgetSpawnExceeded,
            format!("spawn cap ${spawn_cap_usd:.2} exceeds spawnBudgetUsd ${spawn_budget:.2}"),
        )
        .with_detail(json!({
            "spawnCapUsd": spawn_cap_usd,
            "spawnBudgetUsd": spawn_budget,
        })));
    }
    Ok(run_budget - spend_usd - spawn_cap_usd)
}

/// How many of `run`'s attempts are still running (S9).
fn running_attempts(registry: &Registry, run: &RunId) -> usize {
    registry
        .state()
        .attempts
        .values()
        .filter(|a| a.run_id == *run && a.status == AttemptStatus::Running)
        .count()
}

/// The wire spelling of a role name, for reasons and audit lines. Exhaustive, so a new role cannot
/// be added without deciding how it is named here.
fn role_str(role: RoleName) -> &'static str {
    match role {
        RoleName::Lead => "lead",
        RoleName::Builder => "builder",
        RoleName::Reviewer => "reviewer",
        RoleName::Verifier => "verifier",
        RoleName::Security => "security",
    }
}

/// Truncates caller-supplied text on a char boundary before it is echoed into a rejection.
fn echo(s: &str) -> String {
    match s.char_indices().nth(MAX_ECHO_CHARS) {
        Some((cut, _)) => format!("{}…", &s[..cut]),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant, so the `as_str` drift guard below covers the whole enum.
    const ALL: &[PolicyCode] = &[
        PolicyCode::UnknownRole,
        PolicyCode::UnknownModel,
        PolicyCode::DelegationNotAllowed,
        PolicyCode::DepthExceeded,
        PolicyCode::BudgetRunExceeded,
        PolicyCode::BudgetSpawnExceeded,
        PolicyCode::WorktreeBusy,
        PolicyCode::LeadBusy,
        PolicyCode::GatePending,
        PolicyCode::InvalidTask,
        PolicyCode::InvalidBaseRef,
        PolicyCode::RunBlocked,
        PolicyCode::AgentNotResumable,
        PolicyCode::ResumeTargetMissing,
        PolicyCode::UnsafeArgv,
        PolicyCode::SandboxMissing,
        PolicyCode::ArgvTooLarge,
        PolicyCode::UnsafeEnv,
        PolicyCode::AgentApproveNotAllowed,
        PolicyCode::TooManyAttempts,
        PolicyCode::RolePromptTampered,
        PolicyCode::GitTimeout,
        PolicyCode::ModelProviderMismatch,
        PolicyCode::TeamInvalid,
    ];

    /// Twenty in the design as first written, plus `team_invalid` and `model_provider_mismatch`
    /// from Rev 26, `gate_pending` from the T35 final-review follow-up, and A5's `lead_busy`.
    #[test]
    fn the_code_set_is_the_twenty_four_the_design_fixes() {
        assert_eq!(ALL.len(), 24);
    }

    #[test]
    fn as_str_matches_the_serde_spelling_for_every_code() {
        for code in ALL {
            let wire = serde_json::to_value(code).expect("serialize");
            assert_eq!(wire, Value::String(code.as_str().to_string()), "{code:?}");
        }
    }

    #[test]
    fn denied_argv_is_the_ten_tokens_the_design_lists() {
        assert_eq!(DENIED_ARGV.len(), 10);
        assert_eq!(DENIED_ARGV[0], "--dangerously-skip-permissions");
        assert_eq!(DENIED_ARGV[9], "--plugin-dir");
    }

    #[test]
    fn echo_truncates_on_a_char_boundary() {
        let long = "é".repeat(MAX_ECHO_CHARS + 5);
        let echoed = echo(&long);
        assert!(echoed.ends_with('…'));
        assert_eq!(echoed.chars().count(), MAX_ECHO_CHARS + 1);
        assert_eq!(echo("main"), "main");
    }
}
