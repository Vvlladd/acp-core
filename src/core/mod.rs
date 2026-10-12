//! The core actor: owns the registry, supervisor and role config, and serializes every mutation
//! through a `Command` mailbox. Slow I/O (git, spawn, commit) runs in helper tasks that post
//! completions back, so a mailbox turn never awaits.
//!
//! Hazard: this module is named `core`, so inside this crate the standard library's `core` crate
//! must be spelled `::core::`. It appears nowhere in the code today.
//!
//! The actor is one task (decision 10) and it never awaits unbounded I/O (decision 11). Those two
//! rules are what make exactly-once integration structural rather than incidental, and they are
//! the two properties [`Core::handle_command`] exists to make testable: it is the whole body of
//! the `select!` arm, so "a mailbox turn is fast" is a property of a single, directly callable
//! function.
//!
//! T33 built the mailbox, the waiters, the helper-task chokepoints and the `get_status` projection;
//! T35 filled in the dispatch: every arm that decides something now calls into [`r#loop`], which
//! owns the branch table and is the only thing that turns a finished attempt into the next step.

mod cancellation;
mod caller_scope;
mod local_checks;
pub mod gates;
pub mod handoff;
pub mod lifecycle;
pub mod recovery;
pub mod plan;
pub mod policy;
pub mod registry;
pub mod supervisor;
pub mod team;
pub mod types;
// `loop` is a reserved word — the module is declared with a raw identifier.
pub mod r#loop;

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::core::gates::{CommitPlan, NewGate, ResolveOutcome};
use crate::core::policy::{DelegateRequest, PolicyCode, PolicyError};
use crate::core::registry::Registry;
use crate::core::supervisor::{
    CheckedPlan, FinalizeReport, SpawnError, SpawnedProc, Supervisor, SupervisorSignal,
};
use crate::core::types::{
    AgentHandle, AgentId, AgentStatus, Attempt, AttemptError, AttemptId, AttemptStatus, CancelBy,
    Event, EventPayload, Gate, GateId, GateStatus, HandoffEnvelope, LineageId, LoopBranch,
    LoopState, ProviderName, RoleName, RolesConfig, Run, RunId, RunStatus, Task, TokenUsage,
};
use crate::workspace::git::{self, GitError};

pub use crate::core::gates::{CoreError, GateResolution};
pub use crate::core::types::Actor;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `get_status.schemaVersion` (Rev 25). The CLI and the macOS app are released independently of
/// the daemon, so the projection carries its own version rather than relying on the binary's.
pub const STATUS_SCHEMA_VERSION: u32 = 1;

/// Mailbox depth. Deep enough that a burst of tail-driven wake-ups never blocks the supervisor's
/// `try_send`, shallow enough that a wedged actor is noticed rather than buffered indefinitely.
pub const MAILBOX_CAPACITY: usize = 256;

/// Production tick period (design, § Process model: "Why keep a tick?"). Tests inject 25 ms.
pub const DEFAULT_TICK: Duration = Duration::from_secs(2);

/// `lastEvents` when the caller does not say (design, § MCP tools: `0..=100 = 20`).
pub const DEFAULT_LAST_EVENTS: usize = 20;

/// Hard ceiling on `lastEvents`, applied here as well as at the door: the projection is fail-closed
/// about how much of an untrusted transcript it will echo back in one response.
pub const MAX_LAST_EVENTS: usize = 100;

/// Longest `AgentSummary::last_message` (Rev 25), in characters — it is worker-authored text.
pub const LAST_MESSAGE_CHARS: usize = 200;

/// How far back through a run's log `last_message` looks for the newest assistant note. Bounded so
/// a `get_status` on a long-running run stays O(1) in the length of the log.
const LAST_MESSAGE_SCAN: u64 = 200;

// ---------------------------------------------------------------------------
// Mailbox
// ---------------------------------------------------------------------------

/// The reply half of a request command.
///
/// The design writes these as `oneshot::Sender<DelegateOut>` and gives `CoreHandle` the signature
/// `-> Result<DelegateOut, CoreError>`; the `Result` has to be produced somewhere, and producing it
/// in the actor is what lets a policy rejection (`CoreError::Policy`) and a registry write failure
/// reach the door unchanged instead of being flattened into a success shape. `CoreError::Unavailable`
/// is reserved for "the actor is gone or dropped this channel" and is what a closed mailbox or a
/// dropped sender turns into at the handle.
pub type Reply<T> = oneshot::Sender<Result<T, CoreError>>;

/// A parked `await_result` call: a `oneshot::Sender` keyed by agent in [`Core::waiters`].
///
/// Parking is the whole point — the actor answers the `AwaitResult` command in the same turn it
/// receives it and never holds a mailbox turn open waiting for a worker.
struct Waiter(Reply<AwaitOut>);

/// Optional human setup carried only by the socket lead-start door. The actor compares the
/// confirmed team before creating the run, closing the team.set → lead.start race.
#[derive(Clone, Debug, Default)]
pub struct LeadSetup {
    pub audit_selection: Option<git::audit::Selection>,
    pub expected_team: Option<team::Team>,
}

/// Everything that can reach the actor. `LeadStart` remains daemon-internal until T58 attaches its
/// socket-only human door; it is deliberately absent from MCP. The rest are the established door
/// requests, helper completions and supervisor wake-ups.
///
/// Three deviations from the design's sketch, all forced:
///
/// * `AttemptExited` carries `exit_code`/`signal` rather than a `std::process::ExitStatus`, because
///   `ExitStatus` has no public constructor and [`SupervisorSignal`] has already decomposed it —
///   these two variants forward a supervisor signal verbatim.
/// * every request variant replies `Result<_, CoreError>` (see [`Reply`]).
/// * two completions the original design did not list exist because their work may not happen in a
///   mailbox turn: [`Command::FinalizeReady`] and [`Command::RetryFreshReady`]. Each is documented
///   at its own variant.
#[derive(Debug)]
pub enum Command {
    CheckStart { request: crate::checks::Request, reply: Reply<crate::checks::Summary> },
    CheckCancel { id: uuid::Uuid, reply: Reply<crate::checks::Summary> },
    CheckFinished { id: uuid::Uuid, result: Result<(crate::checks::Report, String), String> },
    CheckList { offset: usize, reply: Reply<serde_json::Value> },
    /// Keeps admission alive when a caller disconnects after enqueueing its command.
    Admitted { command: Box<Command>, admission: Arc<lifecycle::ActivityGuard> },
    /// Proxy-supplied provenance, outside the model's tool arguments. Restricts no-builder leads.
    CallerScoped { command: Box<Command>, caller_run_id: RunId },
    Lifecycle {
        request: lifecycle::Request,
        reply: Reply<lifecycle::Status>,
    },
    RecoveryPreview { run: RunId, reply: Reply<recovery::Preview> },
    RecoverRun { request: recovery::Request, by: Actor, reply: Reply<recovery::Outcome> },
    LeadStart {
        task: Task,
        message: String,
        setup: LeadSetup,
        reply: Reply<LeadStartOut>,
    },
    AuditStart {
        task: Task,
        selection: git::audit::Selection,
        caller_run_id: Option<RunId>,
        reply: Reply<PlanStartOut>,
    },
    AuditCaptured { run: RunId, result: Result<git::audit::Snapshot, GitError> },
    AuditValidated { run: RunId, result: Result<(), GitError> },
    /// B3: start a plan (socket `plan.start`, MCP `submit_plan`, CLI `acp plan`).
    StartPlan {
        plan: crate::core::plan::Plan,
        /// T84: the caller's attested lead run, or `None` for every door but `acp mcp-proxy`.
        caller_run_id: Option<RunId>,
        reply: Reply<PlanStartOut>,
    },
    Delegate {
        req: DelegateRequest,
        reply: Reply<DelegateOut>,
    },
    SendMessage {
        agent: AgentId,
        message: String,
        reply: Reply<SendResult>,
    },
    /// Parks a waiter; never blocks the actor.
    AwaitResult {
        agent: AgentId,
        reply: Reply<AwaitOut>,
    },
    Status {
        query: StatusQuery,
        reply: Reply<StatusOut>,
    },
    Cancel {
        agent: AgentId,
        reply: Reply<CancelOut>,
    },
    CreateGate {
        req: GateRequest,
        reply: Reply<GateOut>,
    },
    ResolveGate {
        gate: GateId,
        approve: bool,
        feedback: Option<String>,
        by: Actor,
        reply: Reply<GateResolution>,
    },

    // Completions posted by helper tasks so the mailbox never awaits slow I/O (decision 11).
    WorktreeReady {
        lineage: LineageId,
        result: Result<WorktreeInfo, GitError>,
    },
    SpawnReady {
        attempt: AttemptId,
        result: Box<Result<SpawnedProc, SpawnError>>,
    },
    CommitDone {
        gate: GateId,
        result: Result<String, GitError>,
    },
    /// `git status --porcelain` of an inherited worktree, read off the actor for 17c's retry prompt
    /// (decision 8).
    ///
    /// 17c has to quote the worktree the dead session left behind, and
    /// reading it is a git call — bounded, but a wedged git would hold the mailbox for
    /// [`GIT_OP_TIMEOUT`](crate::workspace::git::GIT_OP_TIMEOUT) and every door with it (Codex
    /// review of T35, finding 3). So the branch appends its durable events, hands the read to
    /// [`Core::spawn_porcelain_helper`] and ends; this carries the answer back, and the spawn it
    /// starts is covered by [`Core::reconcile_intents`] if the daemon dies in between.
    RetryFreshReady {
        agent: AgentId,
        porcelain: Result<String, GitError>,
    },
    /// The git and filesystem half of finalizing an exited attempt, done off the actor. Applying
    /// it is appends only.
    ///
    /// This completion was added after the design sketch (Codex review of T33, finding 1). It
    /// exists because `Supervisor::tick` used to finalize inline — `head_sha`, `soft_reset`,
    /// `changed_files`, `frozen_diff` — so a wedged git in one run's worktree stalled `get_status`,
    /// `cancel` and every gate resolution for up to `GIT_OP_TIMEOUT`, which is exactly what
    /// decision 11 forbids. The supervisor now runs that work in a helper task and posts the
    /// resulting plain-data [`FinalizeReport`] here.
    FinalizeReady {
        attempt: AttemptId,
        report: Box<FinalizeReport>,
    },

    // Wake-ups forwarded from the supervisor. These two carry no truth of their own: they only say
    // "look now" sooner than the tick would have, so handling them must be idempotent.
    /// The process was reaped. **The log is not yet whole** — the terminal events arrive with the
    /// `FinalizeReady` that follows this.
    AttemptExited {
        attempt: AttemptId,
        exit_code: Option<i32>,
        signal: Option<String>,
    },
    AttemptTimeout {
        attempt: AttemptId,
    },
    Tick,
}

impl Command {
    /// The actor and test actors retain these guards for the complete mailbox turn.
    pub fn into_unwrapped(mut self) -> (Self, Vec<Arc<lifecycle::ActivityGuard>>) {
        let mut guards = Vec::new();
        while let Self::Admitted { command, admission } = self {
            guards.push(admission);
            self = *command;
        }
        (self, guards)
    }
}

// ---------------------------------------------------------------------------
// Request / reply payloads
// ---------------------------------------------------------------------------

/// What the worktree helper produced, handed back through [`Command::WorktreeReady`].
///
/// The lineage id rides on the command rather than in here, so this struct is exactly what the
/// helper task learned and nothing the actor already knew — `base_sha` in particular is the
/// **resolved** sha the worktree was created at, not the ref the caller asked for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WorktreeInfo {
    pub path: PathBuf,
    pub branch: String,
    pub base_sha: String,
}

/// The `delegate` answer (design, § MCP tools). `status` is always [`RunStatus::Running`] — the
/// design's `RunningLiteral`, spelled with the closed enum that already serializes to `"running"`
/// rather than a second one-value type.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DelegateOut {
    pub agent_id: AgentId,
    pub run_id: RunId,
    pub attempt_id: AttemptId,
    pub status: RunStatus,
    pub worktree: PathBuf,
}

/// What `plan.start` answered: the container run every `plan.*` event lands on.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PlanStartOut {
    pub run_id: RunId,
}

/// The daemon-side result of starting a conversational lead. T58's socket wire response mirrors
/// these identifiers and deliberately exposes no worktree or lineage.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LeadStartOut {
    pub run_id: RunId,
    pub agent_id: AgentId,
}

/// What `send_message` (and `retry_fresh`) answered.
///
/// The design declares this in `core/loop.rs`; it is declared here because the mailbox needs it to
/// compile before `core::loop` exists, and because `core::loop`'s 17b/17c branches call
/// `send_message` internally and must observe a rejection as a **value** — a run that cannot resume
/// its builder becomes `run.status{blocked}`, it does not propagate an error to a door.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SendResult {
    Ok { attempt: AttemptId },
    Rejected { code: PolicyCode, reason: String },
}

/// What `await_result` answered: the finished worker's envelope, or "still running" plus the last
/// event, which is what the caller's own timeout produces (design, § `src/core/mod.rs`).
#[derive(Serialize, Clone, PartialEq, Debug)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum AwaitOut {
    Done {
        envelope: Box<HandoffEnvelope>,
    },
    Running {
        /// Boxed so the two arms of this enum stay the same size — an `Event` is ~300 bytes and
        /// `HandoffEnvelope` is already behind a `Box`. Serialization is unaffected.
        last_event: Option<Box<Event>>,
    },
}

/// What `get_status` was asked about.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StatusQuery {
    pub run_id: Option<RunId>,
    pub agent_id: Option<AgentId>,
    pub last_events: usize,
}

impl Default for StatusQuery {
    fn default() -> Self {
        Self {
            run_id: None,
            agent_id: None,
            last_events: DEFAULT_LAST_EVENTS,
        }
    }
}

/// What a lead should do next with one agent (Rev 25). A closed set, so a client can branch on it.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedNext {
    /// Nothing to do — the control plane's own loop is driving.
    Wait,
    AwaitResult,
    SendMessage,
    ApproveGate,
    DelegateFresh,
    FixEnvironment,
}

/// One agent as `get_status` reports it (Rev 25).
///
/// `process_state` is [`AgentStatus`] and `turn_state` is [`LoopState`] rather than two new
/// enums: the design lists the values a stable state rests in (`starting/running/idle/closed/lost`
/// and `building/reviewing/awaiting_gate/blocked/done`), and both existing enums are supersets that
/// carry the transient states too (`cancelled`; `repairing/retrying/replacing`). Narrowing them
/// would be lossy in exactly the moments a human is watching.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AgentSummary {
    pub agent_id: AgentId,
    pub run_id: RunId,
    pub role: RoleName,
    pub provider: ProviderName,
    pub model: String,
    pub process_state: AgentStatus,
    pub turn_state: LoopState,
    pub last_activity_at: String,
    /// The newest assistant note, ≤ [`LAST_MESSAGE_CHARS`] characters with control characters
    /// flattened to spaces. **Untrusted** worker-authored text: render it, never act on it.
    pub last_message: Option<String>,
    pub recommended_next: RecommendedNext,
    pub usage: TokenUsage,
    pub error: Option<AttemptError>,
}

/// The `get_status` projection (Rev 25).
///
/// No `JsonSchema`: it carries `Event`, which is deliberately schema-less (`flatten` over an
/// internally tagged enum, forward-compatible by design). The MCP door advertises its own output
/// shape for this tool.
#[derive(Serialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StatusOut {
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub runs: Vec<Run>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<AgentSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attempts: Vec<Attempt>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub gates: Vec<Gate>,
    pub spend_usd: f64,
    pub run_budget_usd: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    pub events: Vec<Event>,
}

/// What `cancel` answered (design, § MCP tools).
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CancelOut {
    Cancelled,
    AlreadyFinished,
}

/// A `request_human_gate` call: which run, and the gate to mint in it.
#[derive(Clone, PartialEq, Debug)]
pub struct GateRequest {
    pub run_id: RunId,
    pub gate: NewGate,
}

/// What `request_human_gate` answered. `human_action` is the sentence the lead is meant to relay —
/// approving is a human action performed in the CLI or the menu-bar app (S2).
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GateOut {
    pub gate_id: GateId,
    pub status: GateStatus,
    pub human_action: String,
}

/// The one sentence that tells a lead how a gate gets approved (design, § Data Flow step 16).
#[must_use]
pub fn human_action(gate: &GateId) -> String {
    format!("acp gate approve {gate}  (or approve in the menu-bar app)")
}

/// Whether an attempt has stopped. Everything except [`AttemptStatus::Running`] is terminal, and a
/// terminal attempt's events are reducer no-ops (C2).
#[must_use]
pub fn is_terminal(status: AttemptStatus) -> bool {
    !matches!(status, AttemptStatus::Running)
}

/// Which branch of the loop already ran for this attempt, if any.
///
/// This is the restart question, and its answer is a **durable marker**, not an inference.
/// `on_attempt_finished` is the only thing that turns a terminal attempt into the next step — a
/// reviewer, an integrate gate, a strike, a retry, a blocked run — and it is not part of the same
/// append as `attempt.finished`. A crash in between leaves an attempt that is terminal and has had
/// nothing done about it, and a restarted actor must re-drive it.
///
/// The first cut of this asked "is there any later event of a kind the loop writes?". That reads a
/// *partial* branch as a finished one: 17b writes `lineage.strike` and then resumes the builder, so
/// a crash between the two left a struck attempt with no repair attempt and a restart that
/// concluded the branch was done (Codex review of T33, round 2, finding 2). `loop.dispatched` is
/// appended last, so its presence means every side effect of the branch is already durable and its
/// absence means the branch owes work — with no middle ground to guess about.
///
/// `None` for an attempt still running, one whose branch never completed, or one the projection has
/// never seen.
#[must_use]
pub fn loop_dispatch(reg: &Registry, attempt: &AttemptId) -> Option<LoopBranch> {
    let record = reg.attempt(attempt)?;
    reg.events(&record.run_id, None, usize::MAX)
        .iter()
        .rev()
        .find_map(|event| match &event.payload {
            EventPayload::LoopDispatched { attempt_id, branch } if attempt_id == attempt => {
                Some(*branch)
            }
            _ => None,
        })
}

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

/// The single owner of every mutable thing in the control plane.
///
/// Two fields beyond the design's sketch, both structural rather than incidental:
///
/// * `tx` — the actor's own mailbox sender. Decision 11's helper tasks post their completion back
///   through it, which is the only way `add_worktree`, `spawn_detached` and `commit_all` reach the
///   actor at all.
/// * `gate_waiters` — an approval's answer is not known until the commit helper finishes, so the
///   reply is parked exactly as an `await_result` waiter is. Without it, `resolve_gate(approve)`
///   would have to await `commit_all` inside a mailbox turn, which is the thing decision 11 forbids.
///   At most one reply is ever parked per gate: the second resolution of a gate observes a
///   non-`Pending` status and is answered `AlreadyResolved` without reaching here.
pub struct Core {
    local_checks: HashMap<uuid::Uuid, local_checks::Pending>,
    pub lifecycle: lifecycle::Lifecycle,
    cancellation: cancellation::Cancellation,
    pub registry: Registry,
    pub supervisor: Supervisor,
    pub roles: Arc<RolesConfig>,
    pub repo_root: PathBuf,
    pub state_dir: PathBuf,
    tx: mpsc::Sender<Command>,
    waiters: HashMap<AgentId, Vec<Waiter>>,
    gate_waiters: HashMap<GateId, Reply<GateResolution>>,
    /// Attempts whose branch **completed**: the log holds their `loop.dispatched` marker. Seeded in
    /// [`Core::new`] from the markers in the replayed log, so a restart re-drives exactly the
    /// branches that never finished, and extended only by [`Core::finish_dispatch`] once a marker
    /// is durable.
    dispatched: HashSet<AttemptId>,
    /// Attempts whose branch is running right now.
    ///
    /// A sweep must not start a branch that is already in flight, and membership of `dispatched` is
    /// no longer the thing that says so — an attempt joins that set only once its marker is on
    /// disk. This is the guard for the window in between. It is released whether the branch
    /// succeeded or failed, so a branch that died before its marker is swept again on the next
    /// tick instead of waiting for a restart (Codex review of T33, round 3, finding 1).
    in_flight: HashSet<AttemptId>,
    /// Delegations waiting for `add_worktree`, keyed by the lineage the helper reports back with
    /// (`core::loop`). A crash loses them along with the helper tasks that would have answered
    /// them, which is consistent: nothing about those runs is in the log yet.
    pending_worktree: HashMap<LineageId, r#loop::PendingWorktree>,
    /// Attempts waiting for `spawn_detached`: the [`AttemptContext`] the supervisor will adopt, or
    /// the argv the failure will be recorded with.
    pending_spawn: HashMap<AttemptId, r#loop::PendingSpawn>,
    /// Pending provider spawns a human cancelled before the helper returned. They must still be
    /// adopted when they arrive — dropping a detached child would make it unsupervised — and are
    /// then cancelled through the supervisor before any later turn may use them.
    cancelled_spawn: HashSet<AttemptId>,
    /// The attempt id 17c already answered `send_message`/`retry_fresh` with, waiting for the
    /// worktree's `git status`. It is also the in-flight guard that keeps
    /// [`Core::reconcile_intents`] from issuing a second spawn for the same agent.
    pending_retry: HashMap<AgentId, AttemptId>,
    pending_audit: HashMap<RunId, r#loop::audit::Pending>,
    /// Re-entrancy guard for the B3 plan conductor: `drive_plans` may block a container run,
    /// and `block_run` pokes the conductor — without this flag that would recurse.
    driving_plans: bool,
    /// Whether [`Core::reconcile_intents`] has run. It runs in [`Core::new`] when there is a
    /// runtime to spawn helpers into, and otherwise on the first [`Command::Tick`]; either way it
    /// runs exactly once per process, and running it twice would be a no-op anyway.
    reconciled: bool,
    /// Gates that reached a terminal resolution in this turn, waiting for the loop to act on them.
    ///
    /// `begin_resolve` and `finish_commit` are synchronous — they only append — while
    /// [`Core::on_gate_resolved`] resumes a builder and is therefore `async`. Queuing here keeps
    /// the door's reply on the fast path (it is sent before the loop runs) and keeps the whole
    /// reaction inside the same mailbox turn, which [`Core::after_turn`] drains.
    settled: Vec<(GateId, GateResolution)>,
    /// Why the actor must stop, once it must.
    ///
    /// There is one such reason: the event log — "the only durable truth" — could not be written
    /// after [`MAX_FINALIZE_ATTEMPTS`](crate::core::supervisor::MAX_FINALIZE_ATTEMPTS). Recording a
    /// `run.status{blocked}` would need the very thing that is broken, so the honest answer is to
    /// stop: [`run_actor`] breaks, [`Core::shutdown`] drops every parked reply, and every door then
    /// answers [`CoreError::Unavailable`] — the design's "`serve` exits non-zero rather than
    /// serving stale state".
    fatal: Option<String>,
}

impl Core {
    /// Takes ownership of the registry and supervisor. `tx` must be the sender half of the receiver
    /// [`run_actor`] is given — helper tasks post their completions through it.
    #[must_use]
    pub fn new(
        registry: Registry,
        supervisor: Supervisor,
        roles: Arc<RolesConfig>,
        repo_root: PathBuf,
        state_dir: PathBuf,
        tx: mpsc::Sender<Command>,
    ) -> Self {
        // Seed the "already handed to the loop" set from the durable markers, and from nothing
        // else: exactly the attempts carrying a `loop.dispatched`. Every terminal attempt without
        // one is owed a branch and will be re-driven, which is the whole point (Codex review of
        // T33, round 2, finding 2). One pass over each run's log, once, at startup.
        let runs: Vec<RunId> = registry.runs().map(|run| run.run_id).collect();
        let dispatched: HashSet<AttemptId> = runs
            .into_iter()
            .flat_map(|run| registry.events(&run, None, usize::MAX))
            .filter_map(|event| match &event.payload {
                EventPayload::LoopDispatched { attempt_id, .. } => Some(*attempt_id),
                _ => None,
            })
            .collect();
        let mut core = Self {
            local_checks: HashMap::new(),
            lifecycle: lifecycle::Lifecycle::default(),
            registry,
            supervisor,
            roles,
            repo_root,
            state_dir,
            tx,
            waiters: HashMap::new(),
            gate_waiters: HashMap::new(),
            dispatched,
            in_flight: HashSet::new(),
            pending_worktree: HashMap::new(),
            pending_spawn: HashMap::new(),
            cancelled_spawn: HashSet::new(),
            cancellation: cancellation::Cancellation::default(),
            pending_retry: HashMap::new(),
            pending_audit: HashMap::new(),
            settled: Vec::new(),
            driving_plans: false,
            reconciled: false,
            fatal: None,
        };
        // The intents a marked branch left behind (`core::loop`). Guarded on a runtime being
        // present because it spawns helper tasks: a `Core` built outside one — which nothing in the
        // daemon does — simply reconciles on its first tick instead.
        if tokio::runtime::Handle::try_current().is_ok() {
            core.reconcile_intents();
            core.reconciled = true;
        }
        core
    }

    /// A handle onto this core's mailbox and event stream, for the MCP and socket doors.
    #[must_use]
    pub fn handle(&self) -> CoreHandle {
        CoreHandle(self.tx.clone(), self.registry.event_sender(), Arc::clone(&self.lifecycle.ingress), None)
    }

    /// The mailbox sender, for the tick task and the supervisor-signal forwarder.
    #[must_use]
    pub fn mailbox(&self) -> mpsc::Sender<Command> {
        self.tx.clone()
    }

    /// Why the actor must stop, if it must. `Some` is checked by [`run_actor`] after every turn.
    #[must_use]
    pub fn fatal(&self) -> Option<&str> {
        self.fatal.as_deref()
    }

    /// Retries every finalize report whose append failed, once per tick.
    ///
    /// A report that has burnt its retry budget is not a run-level failure to record — the thing
    /// that records is what is broken — so it becomes [`Core::fatal`] and the actor stops.
    fn retry_finalize(&mut self) {
        if let Err(stalled) = self.supervisor.retry_finalize(&mut self.registry) {
            tracing::error!(%stalled, "the event log is unwritable; the core actor is stopping");
            self.fatal = Some(stalled.to_string());
        }
    }

    /// How many `await_result` waiters are parked for `agent`.
    ///
    /// A door that timed out has already dropped its receiver; those are pruned when the next
    /// `AwaitResult` for the same agent is parked and again on every mutating turn, so this never
    /// exceeds one dead entry per agent no matter how many times a caller times out and retries.
    #[must_use]
    pub fn waiter_count(&self, agent: &AgentId) -> usize {
        self.waiters.get(agent).map_or(0, Vec::len)
    }

    // -----------------------------------------------------------------------
    // The mailbox turn
    // -----------------------------------------------------------------------

    /// Handles exactly one command. **This is the whole body of the actor's `select!` arm**, so it
    /// is also the unit a test times: nothing in here awaits git, a spawn or a worker.
    ///
    /// The only `await`s reachable from a match arm are [`Supervisor::tick`] and
    /// [`Supervisor::cancel`], and neither waits on a child — `cancel` sends SIGTERM and *schedules*
    /// the SIGKILL in a detached task rather than sleeping out the grace period.
    pub async fn handle_command(&mut self, cmd: Command) {
        let (cmd, _admission) = cmd.into_unwrapped();
        let Some(cmd) = self.admit_caller_scope(cmd) else { return; };
        let Some(cmd) = self.admit_during_cancellation(cmd) else { return; };
        match cmd {
            Command::CheckStart { request, reply } => { let result = self.start_check(request); let _ = reply.send(result); }
            Command::CheckCancel { id, reply } => { let result = self.cancel_check(id); let _ = reply.send(result); }
            Command::CheckFinished { id, result } => self.finish_check(id, result),
            Command::CheckList { offset, reply } => self.list_checks(offset, reply),
            Command::Admitted { .. } | Command::CallerScoped { .. } => unreachable!("unwrapped above"),
            Command::Lifecycle { request, reply } => {
                let out = self.lifecycle_request(request).await;
                let _ = reply.send(out);
            }
            Command::RecoveryPreview { run, reply } => { let _ = reply.send(self.recovery_preview(run)); }
            Command::RecoverRun { request, by, reply } => {
                let out = self.recover_run(request, by);
                let _ = reply.send(out);
                self.after_turn().await;
            }
            // -- doors ------------------------------------------------------
            Command::LeadStart {
                task,
                message,
                setup,
                reply,
            } => {
                let out = self
                    .spawn_lead_with_setup(task, message, setup)
                    .map(|(run_id, agent_id)| LeadStartOut { run_id, agent_id });
                let _ = reply.send(out);
                self.after_turn().await;
            }
            Command::AuditStart { task, selection, caller_run_id, reply } => {
                let out = self.start_audit(task, selection, caller_run_id).map(|run_id| PlanStartOut { run_id });
                let _ = reply.send(out);
                self.after_turn().await;
            }
            Command::AuditCaptured { run, result } => {
                self.audit_captured(run, result);
                self.after_turn().await;
            }
            Command::AuditValidated { run, result } => {
                self.audit_validated(run, result);
                self.after_turn().await;
            }
            Command::StartPlan {
                plan,
                caller_run_id,
                reply,
            } => {
                let out = self
                    .start_plan(plan, caller_run_id)
                    .map(|run_id| PlanStartOut { run_id });
                let _ = reply.send(out);
                self.after_turn().await;
            }
            Command::Delegate { req, reply } => {
                // Policy runs inline; the worktree and the spawn are helper tasks, so this replies
                // before either finishes (design, § `src/core/loop.rs`).
                let out = self.delegate(req);
                let _ = reply.send(out);
                self.after_turn().await;
            }
            Command::SendMessage {
                agent,
                message,
                reply,
            } => {
                // A policy refusal is a `SendResult::Rejected` value, not an error: `core::loop`
                // calls this same path internally and branches on it.
                let out = self.send_message(&agent, &message, false).await;
                let _ = reply.send(Ok(out));
                self.after_turn().await;
            }
            Command::AwaitResult { agent, reply } => self.park_waiter(agent, reply),
            Command::Status { query, reply } => {
                let out = self.status(&query);
                let _ = reply.send(Ok(out));
            }
            Command::Cancel { agent, reply } => {
                let out = self.cancel_agent(&agent).await;
                let _ = reply.send(out);
                self.after_turn().await;
            }
            Command::CreateGate { req, reply } => {
                let out = gates::create_gate(&mut self.registry, &req.run_id, req.gate).map(|g| {
                    GateOut {
                        gate_id: g.gate_id,
                        status: g.status,
                        human_action: human_action(&g.gate_id),
                    }
                });
                let _ = reply.send(out);
                self.after_turn().await;
            }
            Command::ResolveGate {
                gate,
                approve,
                feedback,
                by,
                reply,
            } => {
                self.begin_resolve(gate, approve, feedback, by, reply);
                self.after_turn().await;
            }

            // -- helper-task completions (decision 11) ----------------------
            Command::WorktreeReady { lineage, result } => {
                self.on_worktree_ready(&lineage, result);
                self.after_turn().await;
            }
            Command::SpawnReady { attempt, result } => {
                self.on_spawn_ready(&attempt, *result).await;
                self.after_turn().await;
            }
            Command::CommitDone { gate, result } => {
                self.finish_commit(gate, result);
                self.after_turn().await;
            }
            Command::RetryFreshReady { agent, porcelain } => {
                self.on_retry_fresh_ready(&agent, porcelain);
                self.after_turn().await;
            }

            Command::FinalizeReady { attempt, report } => {
                tracing::debug!(%attempt, status = ?report.status(), "applying the finalize report");
                if let Err(err) = self.supervisor.apply_finalize(*report, &mut self.registry) {
                    // The report is parked, not lost: the next tick retries it, and the attempt
                    // stays `running` until its terminal event is genuinely durable.
                    tracing::warn!(%attempt, %err, "the finalize report was parked for retry");
                }
                self.after_turn().await;
            }

            // -- supervisor wake-ups ---------------------------------------
            Command::AttemptExited {
                attempt,
                exit_code,
                signal,
            } => {
                // Only the reaping is recorded at this point; `attempt.finished` lands with the
                // `FinalizeReady` that follows, so there is nothing to drive yet. The sweep runs
                // anyway because it is idempotent and costs one pass over the projection.
                tracing::debug!(%attempt, ?exit_code, ?signal, "attempt exited");
                self.after_turn().await;
            }
            Command::AttemptTimeout { attempt } => {
                // The deadline task holds no registry, so `attempt.cancel_requested{by:timeout}` is
                // written by the first tick that observes the flag it set. Ticking now records it
                // immediately instead of up to `tick_ms` later; the tick is idempotent.
                tracing::debug!(%attempt, "attempt timed out");
                self.retry_finalize();
                self.supervisor.tick(&mut self.registry).await;
                self.after_turn().await;
            }
            Command::Tick => {
                if !self.reconciled {
                    self.reconciled = true;
                    self.reconcile_intents();
                }
                self.reconcile_cancellations().await;
                self.retry_finalize();
                self.supervisor.tick(&mut self.registry).await;
                self.after_turn().await;
                // A finalize completion can reveal lost identity during this very tick.
                self.reconcile_cancellations().await;
                if self.fatal.is_none() {
                    let busy = !self.lifecycle_busy_reasons().is_empty();
                    self.lifecycle.tick(busy, std::time::Instant::now());
                }
            }
        }
    }

    /// Everything that must happen after a turn that may have changed state: hand newly terminal
    /// attempts to the loop, then resolve and prune the parked `await_result` waiters.
    async fn after_turn(&mut self) {
        self.drive_audits();
        // Gates first: a denial that resumes a builder is part of the same turn that resolved it.
        for (gate, resolution) in std::mem::take(&mut self.settled) {
            self.on_gate_resolved(gate, &resolution).await;
        }
        for attempt in self.sweep_finished() {
            // The 17a–17d branch table (`core::loop`). The marker contract the restart path
            // depends on:
            //   * the LAST append of every branch is
            //     `EventPayload::LoopDispatched { attempt_id, branch }` — 17a `Environment`,
            //     17b `Resume`, 17c `RetryFresh`, 17d `Replace`, steps 13-14 `Review`,
            //     steps 11/16 `Gate`;
            //   * every side effect before it must be idempotent. Delivery is **at least once**:
            //     a crash before the marker re-drives the whole branch on the next start, so a
            //     second run of it must not strike twice, open a second gate or start a second
            //     reviewer.
            self.on_attempt_finished(attempt).await;

            // Always, on every path out of the branch — including a failing one. `finish_dispatch`
            // promotes the attempt only if its marker is durable, so a branch that died half-way
            // is released and swept again on the next tick.
            self.finish_dispatch(&attempt);
        }
        self.resolve_waiters();
    }

    // -----------------------------------------------------------------------
    // await_result
    // -----------------------------------------------------------------------

    /// Answers immediately when the agent's newest attempt has already finished, otherwise parks.
    ///
    /// Parking prunes this agent's dead waiters first, which is what bounds the map: a door that
    /// timed out dropped its receiver, and the next call for the same agent clears it.
    fn park_waiter(&mut self, agent: AgentId, reply: Reply<AwaitOut>) {
        if self.registry.agent(&agent).is_none() {
            // Fail closed and name the agent rather than parking a waiter that can never resolve.
            let _ = reply.send(Err(CoreError::Policy(PolicyError::new(
                PolicyCode::ResumeTargetMissing,
                format!("no agent {agent} in this state dir"),
            ))));
            return;
        }
        if let Some(out) = self.finished_out(&agent) {
            let _ = reply.send(Ok(out));
            return;
        }
        let waiters = self.waiters.entry(agent).or_default();
        waiters.retain(|w| !w.0.is_closed());
        waiters.push(Waiter(reply));
    }

    /// The envelope for an agent whose newest attempt is terminal, or `None` while it runs.
    fn finished_out(&self, agent: &AgentId) -> Option<AwaitOut> {
        let handle = self.registry.agent(agent)?;
        let attempt = self.registry.attempt(handle.attempt_ids.last()?)?;
        if !is_terminal(attempt.status) {
            return None;
        }
        let run = self.registry.run(&handle.run_id)?;
        Some(AwaitOut::Done {
            envelope: Box::new(handoff::make_envelope(attempt, handle, run)),
        })
    }

    /// Delivers to every waiter whose agent has finished, and drops the ones whose caller is gone.
    fn resolve_waiters(&mut self) {
        let agents: Vec<AgentId> = self.waiters.keys().copied().collect();
        for agent in agents {
            let out = self.finished_out(&agent);
            let Some(waiters) = self.waiters.get_mut(&agent) else {
                continue;
            };
            waiters.retain(|w| !w.0.is_closed());
            if let Some(out) = out {
                for waiter in waiters.drain(..) {
                    let _ = waiter.0.send(Ok(out.clone()));
                }
            }
            if waiters.is_empty() {
                self.waiters.remove(&agent);
            }
        }
    }

    /// Attempts that reached a terminal status since the last sweep, oldest first.
    fn sweep_finished(&mut self) -> Vec<AttemptId> {
        let mut finished: Vec<(&str, AttemptId)> = self
            .registry
            .state()
            .attempts
            .values()
            .filter(|a| {
                is_terminal(a.status)
                    && !self.dispatched.contains(&a.attempt_id)
                    && !self.in_flight.contains(&a.attempt_id)
            })
            .map(|a| {
                (
                    a.finished_at.as_deref().unwrap_or(&a.started_at),
                    a.attempt_id,
                )
            })
            .collect();
        // Deterministic order, so two replays of the same log drive the loop identically.
        finished.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.as_uuid().cmp(b.1.as_uuid())));
        let ids: Vec<AttemptId> = finished.into_iter().map(|(_, id)| id).collect();
        // `in_flight`, **not** `dispatched`: marking an attempt done before its branch has run is
        // what let a branch that failed half-way be forgotten until the next restart. Only a
        // durable `loop.dispatched` promotes it, in `finish_dispatch`.
        for id in &ids {
            self.in_flight.insert(*id);
        }
        ids
    }

    /// Records the outcome of one branch execution.
    ///
    /// The log is the arbiter, not the branch's return value: an attempt is done when its
    /// `loop.dispatched` is durable and owed otherwise. That is the same rule [`Core::new`] uses on
    /// a restart, so the running actor and a restarted one can never disagree about what is left to
    /// do.
    fn finish_dispatch(&mut self, attempt: &AttemptId) {
        self.in_flight.remove(attempt);
        if loop_dispatch(&self.registry, attempt).is_some() {
            self.dispatched.insert(*attempt);
        } else {
            // Debug, not warn: until T35 there is no branch at all, so every finished attempt takes
            // this path on every tick and a warning would be noise rather than news. T35 owns the
            // level once a branch exists that can genuinely fail before its marker.
            tracing::debug!(%attempt, "no loop.dispatched marker; the attempt stays owed");
        }
    }

    // -----------------------------------------------------------------------
    // cancel
    // -----------------------------------------------------------------------

    /// Cancels every pending spawn or running attempt of `agent`.
    ///
    /// `CancelBy::Lead` because [`Command::Cancel`] carries no actor — the design's `cancel` tool is
    /// the lead's door, and the CLI's cancellation path is the signal ladder, not this one.
    async fn cancel_agent(&mut self, agent: &AgentId) -> Result<CancelOut, CoreError> {
        let attempts = self
            .registry
            .agent(agent)
            .map(|a| a.attempt_ids.clone())
            .unwrap_or_default();
        let mut cancelled = self.cancel_pending_spawns(agent)?;
        for attempt in attempts {
            if !self.supervisor.is_running(&attempt) {
                continue;
            }
            match self
                .supervisor
                .cancel(&attempt, CancelBy::Lead, &mut self.registry)
                .await
            {
                Ok(()) => cancelled = true,
                Err(supervisor::SupervisorError::SignalRefused(_)) => {
                    return Err(CoreError::Lifecycle { code: "cancel_failed", reason: format!("the operating system refused the stop signal for attempt {attempt}") });
                }
                Err(err) => tracing::debug!(%attempt, %err, "nothing to cancel"),
            }
        }
        if cancelled {
            Ok(CancelOut::Cancelled)
        } else {
            Ok(CancelOut::AlreadyFinished)
        }
    }

    // -----------------------------------------------------------------------
    // gates
    // -----------------------------------------------------------------------

    /// Opens the exactly-once window and, for an approval, parks the reply behind the commit helper.
    fn begin_resolve(
        &mut self,
        gate: GateId,
        approve: bool,
        feedback: Option<String>,
        by: Actor,
        reply: Reply<GateResolution>,
    ) {
        match gates::begin_resolve(
            &mut self.registry,
            &gate,
            approve,
            feedback,
            by,
            &self.roles,
        ) {
            Ok(ResolveOutcome::Settled(resolution)) => {
                let _ = reply.send(Ok(resolution.clone()));
                // A denial resumes the live builder with the feedback and **no strike**
                // (decision 6). The door is answered first: what the loop does next is the run's
                // business, not the caller's, and it must not hold the reply.
                self.settled.push((gate, resolution));
            }
            Ok(ResolveOutcome::Commit(plan)) => {
                self.gate_waiters.insert(gate, reply);
                self.spawn_commit_helper(*plan);
            }
            Err(err) => {
                let _ = reply.send(Err(err));
            }
        }
    }

    /// Closes the window [`Core::begin_resolve`] opened, from [`Command::CommitDone`].
    fn finish_commit(&mut self, gate: GateId, result: Result<String, GitError>) {
        // `GitError` is not `Clone` and `finish_commit` consumes it to build the block reason, so
        // the text the door is told is captured here rather than reconstructed afterwards.
        let failure = result.as_ref().err().map(ToString::to_string);
        let resolution = match gates::finish_commit(&mut self.registry, &gate, result) {
            Ok(Some(resolution)) => {
                // `run.status{integrated}` + `loop.state{done}`, once the commit is durable.
                self.settled.push((gate, resolution.clone()));
                Ok(resolution)
            }
            // The commit failed: `finish_commit` has already blocked the run and left the gate
            // `resolving`, which is what makes the human's retry idempotent by trailer.
            Ok(None) => Err(CoreError::Git(GitError::Failed {
                op: "commit_all",
                status: "blocked".to_string(),
                message: failure.unwrap_or_else(|| "the commit did not complete".to_string()),
            })),
            Err(err) => Err(err),
        };
        if let Some(reply) = self.gate_waiters.remove(&gate) {
            let _ = reply.send(resolution);
        }
    }

    // -----------------------------------------------------------------------
    // Helper tasks — the only way slow I/O reaches the mailbox (decision 11)
    // -----------------------------------------------------------------------

    /// Runs `git worktree add` off the actor and posts [`Command::WorktreeReady`].
    ///
    /// `base_sha` is an already-resolved 40-hex sha — `git::add_worktree` accepts nothing else.
    /// A caller holding a *ref* wants [`Core::spawn_worktree_from_ref`].
    ///
    /// The outer [`git::GIT_OP_TIMEOUT`] is belt and braces: every individual git invocation is
    /// already bounded inside `workspace::git`, and this bounds the whole operation should that
    /// ever grow to more than one call.
    pub fn spawn_worktree_helper(
        &self,
        lineage: LineageId,
        repo: PathBuf,
        path: PathBuf,
        branch: String,
        base_sha: String,
    ) -> JoinHandle<()> {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let call = git::add_worktree(&repo, &path, &branch, &base_sha);
            let result = match tokio::time::timeout(git::GIT_OP_TIMEOUT, call).await {
                Ok(Ok(())) => Ok(WorktreeInfo {
                    path,
                    branch,
                    base_sha,
                }),
                Ok(Err(err)) => Err(err),
                Err(_elapsed) => Err(GitError::Timeout {
                    op: "add_worktree",
                    secs: git::GIT_OP_TIMEOUT.as_secs(),
                }),
            };
            let _ = tx.send(Command::WorktreeReady { lineage, result }).await;
        })
    }

    /// Resolves `base_ref` and then creates the worktree at the sha it names — the same completion,
    /// one git call earlier.
    ///
    /// **`core::loop` uses this one, and the resolution has to happen here.** `roles.json` ships
    /// `defaults.baseRef = "HEAD"`, a caller may name any ref, `git::add_worktree` takes a
    /// validated sha only, and the actor may not run `rev-parse` itself (decision 11). Doing it in
    /// this task is also what lets `run.created` carry a `baseSha` that is true:
    /// [`WorktreeInfo::base_sha`] is then the sha the worktree was actually created at — the one
    /// fact the helper learned and the actor could not know.
    ///
    /// Both calls are individually bounded inside `workspace::git` and the pair is bounded here, so
    /// a failure names the git operation that actually stalled.
    pub fn spawn_worktree_from_ref(
        &self,
        lineage: LineageId,
        repo: PathBuf,
        path: PathBuf,
        branch: String,
        base_ref: String,
    ) -> JoinHandle<()> {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let call = async {
                let base_sha = git::resolve_ref(&repo, &base_ref).await?;
                git::add_worktree(&repo, &path, &branch, &base_sha).await?;
                Ok::<String, GitError>(base_sha)
            };
            let result = match tokio::time::timeout(git::GIT_OP_TIMEOUT, call).await {
                Ok(Ok(base_sha)) => Ok(WorktreeInfo {
                    path,
                    branch,
                    base_sha,
                }),
                Ok(Err(err)) => Err(err),
                Err(_elapsed) => Err(GitError::Timeout {
                    op: "add_worktree",
                    secs: git::GIT_OP_TIMEOUT.as_secs(),
                }),
            };
            let _ = tx.send(Command::WorktreeReady { lineage, result }).await;
        })
    }

    /// Starts the provider off the actor and posts [`Command::SpawnReady`].
    pub fn spawn_process_helper(
        &self,
        attempt: AttemptId,
        plan: CheckedPlan,
        dir: PathBuf,
    ) -> JoinHandle<()> {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let call = supervisor::spawn_detached(plan, dir.clone());
            let result = match tokio::time::timeout(git::GIT_OP_TIMEOUT, call).await {
                Ok(result) => result,
                Err(_elapsed) => Err(SpawnError::Io {
                    op: "spawn_detached",
                    path: dir,
                    source: io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the spawn exceeded GIT_OP_TIMEOUT",
                    ),
                }),
            };
            let _ = tx
                .send(Command::SpawnReady {
                    attempt,
                    result: Box::new(result),
                })
                .await;
        })
    }

    /// Reads `git status --porcelain` off the actor and posts [`Command::RetryFreshReady`].
    ///
    /// The one git call 17c makes, and the reason it is here rather than in the branch: a wedged
    /// git in one run's worktree must not stop `get_status`, `cancel` or a gate resolution for
    /// every other run (decision 11).
    pub fn spawn_porcelain_helper(&self, agent: AgentId, worktree: PathBuf) -> JoinHandle<()> {
        let tx = self.tx.clone();
        let recovery = self.registry.agent(&agent).and_then(|a| {
            self.registry.events(&a.run_id, None, usize::MAX).iter().any(|e|
                matches!(&e.payload, EventPayload::RunRecovered { recovery } if recovery.agent_id == agent))
                .then(|| (self.repo_root.clone(), self.agent_base_sha(&agent)))
        });
        tokio::spawn(async move {
            let call = async {
                if let Some((repo, base)) = recovery { git::recovery_status(&repo, &worktree, &base).await }
                else { git::status_porcelain(&worktree).await }
            };
            let porcelain = match tokio::time::timeout(git::GIT_OP_TIMEOUT, call).await {
                Ok(result) => result,
                Err(_elapsed) => Err(GitError::Timeout {
                    op: "status_porcelain",
                    secs: git::GIT_OP_TIMEOUT.as_secs(),
                }),
            };
            let _ = tx.send(Command::RetryFreshReady { agent, porcelain }).await;
        })
    }

    /// Runs the integrate commit off the actor and posts [`Command::CommitDone`].
    pub fn spawn_commit_helper(&mut self, plan: CommitPlan) -> JoinHandle<()> {
        let tx = self.tx.clone();
        // One mutex per worktree, held by `run_commit` across the whole check-stage-hash-commit
        // sequence: two approvals of two gates on one worktree — or an approval racing a retry —
        // would otherwise interleave a `git add` with somebody else's index.
        let lock = self.supervisor.worktree_lock(&plan.target.worktree);
        tokio::spawn(async move {
            let gate = plan.gate_id;
            // **No outer timeout, deliberately.** Decision 11's contract is that every individual
            // git invocation is bounded inside `workspace::git`, and this helper makes several —
            // a head read, an index check, one `git add` per batch, a re-freeze that reads one blob
            // per new file, and the commit. One `GIT_OP_TIMEOUT` around the lot both under-sized
            // the work and, worse, cut the future between `git add` and `git commit`, skipping the
            // cleanup and leaving the index staged (round-3 review, finding 3). The sequence is
            // finite and every step of it is individually bounded, so the bound is already there.
            let result = gates::run_commit(&plan, lock).await;
            let _ = tx.send(Command::CommitDone { gate, result }).await;
        })
    }

    // -----------------------------------------------------------------------
    // get_status projection (Rev 25)
    // -----------------------------------------------------------------------

    /// The `get_status` answer: runs, per-agent summaries, attempts, gates and a bounded event tail.
    #[must_use]
    pub fn status(&self, q: &StatusQuery) -> StatusOut {
        let limit = q.last_events.min(MAX_LAST_EVENTS);
        let runs: Vec<Run> = match (q.run_id, q.agent_id) {
            (Some(run), _) => self.registry.run(&run).cloned().into_iter().collect(),
            (None, Some(agent)) => self
                .registry
                .agent(&agent)
                .and_then(|a| self.registry.run(&a.run_id))
                .cloned()
                .into_iter()
                .collect(),
            (None, None) => self.registry.runs().cloned().collect(),
        };

        let mut agents = Vec::new();
        let mut attempts = Vec::new();
        let mut gates = Vec::new();
        let mut events: Vec<Event> = Vec::new();
        let mut spend_usd = 0.0;
        let mut blocked_reason = None;

        for run in &runs {
            spend_usd += run.spend_usd;
            if blocked_reason.is_none() {
                blocked_reason.clone_from(&run.blocked_reason);
            }
            for gate in &run.gate_ids {
                if let Some(gate) = self.registry.gate(gate) {
                    gates.push(gate.clone());
                }
            }
            for agent in &run.agent_ids {
                if q.agent_id.is_some_and(|wanted| wanted != *agent) {
                    continue;
                }
                let Some(handle) = self.registry.agent(agent) else {
                    continue;
                };
                for attempt in &handle.attempt_ids {
                    if let Some(attempt) = self.registry.attempt(attempt) {
                        attempts.push(attempt.clone());
                    }
                }
                agents.push(self.summarize(run, handle));
            }
            if limit > 0 {
                // Each run contributes at most `limit` **candidates**: the global newest `limit`
                // cannot contain more than that from any one run, so this is the whole candidate
                // set and the merge below does the real capping.
                let since = run.last_seq.saturating_sub(limit as u64);
                events.extend(
                    self.registry
                        .events(&run.run_id, Some(since), limit)
                        .into_iter()
                        .map(|e| (*e).clone()),
                );
            }
        }

        // Chronological across runs, `seq`-ordered within one, and fully deterministic — two
        // replays of the same logs answer identically.
        events.sort_by(|a, b| {
            a.base
                .ts
                .cmp(&b.base.ts)
                .then_with(|| a.base.run_id.as_uuid().cmp(b.base.run_id.as_uuid()))
                .then_with(|| a.base.seq.cmp(&b.base.seq))
        });
        // `lastEvents` bounds the **response**, not each run inside it (Codex review of T33,
        // finding 3): a three-run status with `lastEvents: 20` returns 20 events, not 60. The
        // newest are the ones worth having, so the excess comes off the front.
        if events.len() > limit {
            events.drain(..events.len() - limit);
        }
        attempts.sort_by(|a, b| {
            a.started_at
                .cmp(&b.started_at)
                .then_with(|| a.attempt_id.as_uuid().cmp(b.attempt_id.as_uuid()))
        });
        gates.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.gate_id.as_uuid().cmp(b.gate_id.as_uuid()))
        });

        StatusOut {
            schema_version: STATUS_SCHEMA_VERSION,
            runs,
            agents,
            attempts,
            gates,
            spend_usd,
            run_budget_usd: self.roles.defaults.run_budget_usd,
            blocked_reason,
            events,
        }
    }

    /// One [`AgentSummary`], derived entirely from the projection.
    fn summarize(&self, run: &Run, agent: &AgentHandle) -> AgentSummary {
        let attempts: Vec<&Attempt> = agent
            .attempt_ids
            .iter()
            .filter_map(|id| self.registry.attempt(id))
            .collect();
        let newest = attempts.last().copied();

        let mut usage = TokenUsage::default();
        for attempt in &attempts {
            if let Some(tokens) = attempt.tokens {
                usage.input += tokens.input;
                usage.cached_input += tokens.cached_input;
                usage.output += tokens.output;
                if let Some(reasoning) = tokens.reasoning {
                    usage.reasoning = Some(usage.reasoning.unwrap_or(0) + reasoning);
                }
            }
        }

        let last_activity_at = attempts
            .iter()
            .filter_map(|a| a.finished_at.as_ref().unwrap_or(&a.started_at).into())
            .max()
            .cloned()
            .unwrap_or_else(|| agent.created_at.clone());

        let error = newest.and_then(|a| a.error.clone());
        AgentSummary {
            agent_id: agent.agent_id,
            run_id: agent.run_id,
            role: agent.role,
            provider: agent.provider,
            model: agent.model.clone(),
            process_state: agent.status,
            turn_state: run.loop_state,
            last_activity_at,
            last_message: self.last_message(run, agent),
            recommended_next: recommended_next(run, agent, error.as_ref(), self.run_is_busy(run)),
            usage,
            error,
        }
    }

    /// Is any attempt of this run still running? An idle agent in a run nothing is driving is one
    /// the lead has to nudge; an idle agent in a run that is mid-flight is one to wait on.
    fn run_is_busy(&self, run: &Run) -> bool {
        run.agent_ids
            .iter()
            .filter_map(|id| self.registry.agent(id))
            .flat_map(|a| a.attempt_ids.iter())
            .filter_map(|id| self.registry.attempt(id))
            .any(|a| !is_terminal(a.status))
    }

    /// The newest assistant note this agent produced, clamped and flattened.
    fn last_message(&self, run: &Run, agent: &AgentHandle) -> Option<String> {
        let since = run.last_seq.saturating_sub(LAST_MESSAGE_SCAN);
        let window = usize::try_from(LAST_MESSAGE_SCAN).unwrap_or(usize::MAX);
        self.registry
            .events(&run.run_id, Some(since), window)
            .iter()
            .rev()
            .find_map(|event| match &event.payload {
                EventPayload::AgentProgress {
                    attempt_id,
                    note: Some(note),
                    ..
                } if agent.attempt_ids.contains(attempt_id) => {
                    Some(clamp_untrusted(note, LAST_MESSAGE_CHARS))
                }
                _ => None,
            })
    }

    // -----------------------------------------------------------------------
    // Shutdown
    // -----------------------------------------------------------------------

    /// Drops every parked reply so each door hears `Unavailable` instead of hanging, and — on the
    /// fatal path only — ends every live worker first.
    ///
    /// It is `async` for that second job and nothing else: the fatal ladder is **awaited**, so
    /// [`run_actor`] does not return until the workers are actually gone. Scheduling it and
    /// returning was the bug — the runtime shuts down behind a returning actor and drops the
    /// detached rung with it (Codex review of T33, round 4). A normal shutdown has no ladder to
    /// wait for and returns immediately.
    ///
    /// Nothing is flushed here: `Registry::append` writes and flushes before it reduces, so a state
    /// dir is always as durable as the last command that returned.
    async fn shutdown(&mut self) {
        self.cancel_local_checks();
        // A normal stop leaves workers running on purpose: the design's exit path (C3) is "workers
        // survive; a restart re-attaches", and `.process_group(0)` plus `kill_on_drop(false)` exist
        // to make that true. A **fatal** stop is the one case where that reasoning fails — the log
        // cannot be written, so nothing more can be recorded about these processes and no restart
        // could re-attach them. Leaving them holding worktrees and spending budget with nobody
        // watching is worse than ending them (Codex review of T33, round 3, finding 2).
        if self.fatal.is_some() {
            let abandoned = self.supervisor.abandon_all().await;
            if !abandoned.is_empty() {
                tracing::error!(
                    count = abandoned.len(),
                    "signalled every live worker: the event log is unwritable, so a restart could \
                     not re-attach them"
                );
            }
        }
        self.waiters.clear();
        self.gate_waiters.clear();
    }
}

/// What a lead should do next with one agent (Rev 25), in priority order.
///
/// The environment check comes first because it is the one branch that is never the model's fault
/// and never resolves on its own (17a: no strike, the run is blocked until a human fixes the CLI).
fn recommended_next(
    run: &Run,
    agent: &AgentHandle,
    error: Option<&AttemptError>,
    run_is_busy: bool,
) -> RecommendedNext {
    use crate::core::types::ErrorCode;

    if let Some(error) = error {
        if matches!(
            error.code,
            ErrorCode::ProviderMissing | ErrorCode::ProviderUnauthenticated
        ) {
            return RecommendedNext::FixEnvironment;
        }
    }
    match run.status {
        RunStatus::AwaitingGate => return RecommendedNext::ApproveGate,
        // A blocked run always has an open question: an `escalate` gate to answer, or a lineage
        // that is out of strikes and needs a fresh delegation.
        RunStatus::Blocked => {
            return if run.loop_state == LoopState::AwaitingGate {
                RecommendedNext::ApproveGate
            } else {
                RecommendedNext::DelegateFresh
            }
        }
        RunStatus::Running | RunStatus::Completed | RunStatus::Integrated | RunStatus::Cancelled | RunStatus::Failed => {}
    }
    match agent.status {
        // Never auto-resumed (decision 4): the lead decides, and `send_message` is the resume door
        // when the recorded cwd still exists.
        AgentStatus::Lost => {
            if agent.resumable {
                RecommendedNext::SendMessage
            } else {
                RecommendedNext::DelegateFresh
            }
        }
        AgentStatus::Starting | AgentStatus::Running => RecommendedNext::AwaitResult,
        AgentStatus::Idle if run.status == RunStatus::Running && !run_is_busy => {
            RecommendedNext::SendMessage
        }
        AgentStatus::Idle | AgentStatus::Cancelled | AgentStatus::Closed => RecommendedNext::Wait,
    }
}

/// Clamps worker-authored text to `max` characters and flattens control characters to spaces, so a
/// status line can never carry a newline that forges a second line of output.
fn clamp_untrusted(text: &str, max: usize) -> String {
    let mut out: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max)
        .collect();
    if text.chars().count() > max {
        out.push('…');
    }
    out.trim().to_string()
}

// ---------------------------------------------------------------------------
// CoreHandle
// ---------------------------------------------------------------------------

/// The doors' view of the core: one async method per [`Command`], plus the event stream.
///
/// Cheap to clone — one `mpsc::Sender` and one `broadcast::Sender` — so every MCP tool call and
/// every socket connection holds its own.
#[derive(Clone)]
pub struct CoreHandle(mpsc::Sender<Command>, broadcast::Sender<Arc<Event>>, Arc<lifecycle::Ingress>, Option<RunId>);

impl CoreHandle {
    pub async fn check_start(&self, request: crate::checks::Request) -> Result<crate::checks::Summary, CoreError> {
        self.ask(|reply| Command::CheckStart { request, reply }).await
    }
    pub async fn check_cancel(&self, id: uuid::Uuid) -> Result<crate::checks::Summary, CoreError> {
        self.ask(|reply| Command::CheckCancel { id, reply }).await
    }
    pub async fn check_list(&self, offset: usize) -> Result<serde_json::Value, CoreError> {
        self.ask(|reply| Command::CheckList { offset, reply }).await
    }
    #[must_use]
    pub fn new(tx: mpsc::Sender<Command>, events: broadcast::Sender<Arc<Event>>) -> Self {
        Self(tx, events, Arc::default(), None)
    }

    /// Restrict a proxy request by its persisted lead mode; human handles remain unscoped.
    #[must_use]
    pub fn with_caller(&self, caller: Option<RunId>) -> Self {
        Self(self.0.clone(), self.1.clone(), Arc::clone(&self.2), caller)
    }

    /// Sends one command and awaits its reply. A closed mailbox or a dropped reply channel is
    /// [`CoreError::Unavailable`] — the design's "if the actor task ever panics, every door answers
    /// `-32001` / `core_unavailable` rather than serving stale state".
    async fn ask<T>(&self, make: impl FnOnce(Reply<T>) -> Command) -> Result<T, CoreError> {
        let _request = Arc::new(self.2.request().ok_or(CoreError::Unavailable)?);
        let (tx, rx) = oneshot::channel();
        let command = make(tx);
        let command = match self.3 {
            Some(caller_run_id) => Command::CallerScoped { command: Box::new(command), caller_run_id },
            None => command,
        };
        self.0
            .send(Command::Admitted { command: Box::new(command), admission: Arc::clone(&_request) })
            .await
            .map_err(|_| CoreError::Unavailable)?;
        rx.await.map_err(|_| CoreError::Unavailable)?
    }

    pub fn ingress(&self) -> &Arc<lifecycle::Ingress> {
        &self.2
    }

    pub async fn lifecycle(&self, request: lifecycle::Request) -> Result<lifecycle::Status, CoreError> {
        self.ask(|reply| Command::Lifecycle { request, reply }).await
    }

    /// Starts a lead through the actor without exposing the operation on the MCP door. T58's
    /// socket method is the only external caller.
    pub async fn start_lead(&self, task: Task, message: String) -> Result<LeadStartOut, CoreError> {
        self.start_lead_with_setup(task, message, LeadSetup::default()).await
    }

    pub async fn start_lead_with_setup(&self, task: Task, message: String, setup: LeadSetup) -> Result<LeadStartOut, CoreError> {
        self.ask(|reply| Command::LeadStart { task, message, setup, reply }).await
    }

    pub async fn start_audit(&self, task: Task, selection: git::audit::Selection, caller_run_id: Option<RunId>) -> Result<PlanStartOut, CoreError> {
        self.ask(|reply| Command::AuditStart { task, selection, caller_run_id, reply }).await
    }

    /// Starts a B3 plan through the actor (socket, MCP `submit_plan`, or the CLI).
    ///
    /// # Errors
    /// [`CoreError::Policy`] with `invalid_plan` and the issue list, or [`CoreError::Unavailable`].
    pub async fn start_plan(
        &self,
        plan: crate::core::plan::Plan,
        caller_run_id: Option<RunId>,
    ) -> Result<PlanStartOut, CoreError> {
        self.ask(|reply| Command::StartPlan {
            plan,
            caller_run_id,
            reply,
        })
        .await
    }

    /// # Errors
    /// [`CoreError::Policy`] when the delegation is refused, [`CoreError::Unavailable`] when the
    /// actor is gone.
    pub async fn delegate(&self, req: DelegateRequest) -> Result<DelegateOut, CoreError> {
        self.ask(|reply| Command::Delegate { req, reply }).await
    }

    /// Read the current recovery eligibility without starting work.
    /// # Errors
    /// [`CoreError::Policy`] if the task is missing; [`CoreError::Unavailable`] if the actor stopped.
    pub async fn recovery_preview(&self, run: RunId) -> Result<recovery::Preview, CoreError> {
        self.ask(|reply| Command::RecoveryPreview { run, reply }).await
    }

    /// Confirm a preview; duplicate accepted requests return their original replacement.
    /// # Errors
    /// [`CoreError::Policy`] for stale/ineligible choices, or registry/availability errors.
    pub async fn recover_run(&self, request: recovery::Request, by: Actor) -> Result<recovery::Outcome, CoreError> {
        self.ask(|reply| Command::RecoverRun { request, by, reply }).await
    }

    /// # Errors
    /// [`CoreError::Unavailable`]. Policy refusals are [`SendResult::Rejected`] values.
    pub async fn send_message(
        &self,
        agent: AgentId,
        message: String,
    ) -> Result<SendResult, CoreError> {
        self.ask(|reply| Command::SendMessage {
            agent,
            message,
            reply,
        })
        .await
    }

    /// Waits up to `timeout` for the agent's current attempt to finish.
    ///
    /// The bound is applied **here**, never in the actor: the command parks a waiter and returns in
    /// the same mailbox turn, and on expiry this drops the receiver — the actor discards the closed
    /// waiter on its next sweep — and answers `{status:"running", lastEvent}` from the projection.
    ///
    /// # Errors
    /// [`CoreError::Policy`] for an agent that does not exist, [`CoreError::Unavailable`].
    pub async fn await_result(
        &self,
        agent: AgentId,
        timeout: Duration,
    ) -> Result<AwaitOut, CoreError> {
        let _request = Arc::new(self.2.request().ok_or(CoreError::Unavailable)?);
        let (tx, rx) = oneshot::channel();
        self.0
            .send(Command::Admitted { command: Box::new(Command::AwaitResult { agent, reply: tx }), admission: Arc::clone(&_request) })
            .await
            .map_err(|_| CoreError::Unavailable)?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(out)) => out,
            Ok(Err(_)) => Err(CoreError::Unavailable),
            Err(_elapsed) => {
                let status = self
                    .status(StatusQuery {
                        run_id: None,
                        agent_id: Some(agent),
                        last_events: 1,
                    })
                    .await?;
                Ok(AwaitOut::Running {
                    last_event: status.events.into_iter().next_back().map(Box::new),
                })
            }
        }
    }

    /// # Errors
    /// [`CoreError::Unavailable`].
    pub async fn status(&self, query: StatusQuery) -> Result<StatusOut, CoreError> {
        self.ask(|reply| Command::Status { query, reply }).await
    }

    /// # Errors
    /// [`CoreError::Unavailable`].
    pub async fn cancel(&self, agent: AgentId) -> Result<CancelOut, CoreError> {
        self.ask(|reply| Command::Cancel { agent, reply }).await
    }

    /// # Errors
    /// [`CoreError::UnknownRun`], [`CoreError::GatePayload`], [`CoreError::Unavailable`].
    pub async fn request_gate(&self, req: GateRequest) -> Result<GateOut, CoreError> {
        self.ask(|reply| Command::CreateGate { req, reply }).await
    }

    /// Resolves a gate. For an approval the answer arrives only once the commit helper finishes —
    /// the reply is parked in the actor, not awaited by it.
    ///
    /// # Errors
    /// [`CoreError::UnknownGate`], [`CoreError::Policy`] (`AgentApproveNotAllowed`, S2),
    /// [`CoreError::Git`] when the commit failed and the run was blocked, [`CoreError::Unavailable`].
    pub async fn resolve_gate(
        &self,
        gate: GateId,
        approve: bool,
        feedback: Option<String>,
        by: Actor,
    ) -> Result<GateResolution, CoreError> {
        self.ask(|reply| Command::ResolveGate {
            gate,
            approve,
            feedback,
            by,
            reply,
        })
        .await
    }

    /// Every event appended from now on. Capacity is
    /// [`EVENT_CHANNEL_CAPACITY`](crate::core::registry::EVENT_CHANNEL_CAPACITY); a subscriber that
    /// falls behind receives `RecvError::Lagged`, which the socket renders as `acp.lagged`.
    #[must_use]
    pub fn events(&self) -> broadcast::Receiver<Arc<Event>> {
        self.1.subscribe()
    }

    /// Whether the actor's mailbox is closed — `serve` exits non-zero rather than serving a core
    /// that is no longer there.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

// ---------------------------------------------------------------------------
// The actor task and its two companions
// ---------------------------------------------------------------------------

/// A mailbox pair of [`MAILBOX_CAPACITY`].
#[must_use]
pub fn channel() -> (mpsc::Sender<Command>, mpsc::Receiver<Command>) {
    mpsc::channel(MAILBOX_CAPACITY)
}

/// The single state-owning task (decision 10).
///
/// Every turn is one [`Core::handle_command`] call, so the loop itself has no logic to get wrong:
/// shutdown wins the `select!` (`biased`), a closed mailbox ends the loop, and on the way out every
/// parked reply is dropped so no door is left hanging.
pub async fn run_actor(
    mut core: Core,
    mut rx: mpsc::Receiver<Command>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            cmd = rx.recv() => match cmd {
                Some(cmd) => {
                    core.handle_command(cmd).await;
                    if let Some(reason) = core.fatal() {
                        tracing::error!(reason, "the core actor is stopping");
                        break;
                    }
                }
                None => break,
            },
        }
    }
    core.shutdown().await;
}

/// The tick task (design, § Process model: "Task layout"). Sends [`Command::Tick`] every `period`.
///
/// `MissedTickBehavior::Skip`: a tick the actor was too busy to take is dropped rather than fired
/// back-to-back, because the tick's jobs — tailing and liveness — are idempotent and a burst of
/// them buys nothing.
pub fn spawn_tick_task(
    tx: mpsc::Sender<Command>,
    period: Duration,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    if tx.send(Command::Tick).await.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

/// Forwards [`SupervisorSignal`]s into the mailbox.
///
/// The supervisor names its own signal type because it compiles before the actor does; both cases
/// map one-to-one onto a `Command`, and both are wake-ups — the durable events are already written
/// when they arrive, so a dropped signal costs latency and never correctness.
pub fn spawn_signal_forwarder(
    mut signals: mpsc::Receiver<SupervisorSignal>,
    tx: mpsc::Sender<Command>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(next) = signals.recv().await {
            let cmd = match next {
                SupervisorSignal::AttemptExited {
                    attempt,
                    exit_code,
                    signal,
                } => Command::AttemptExited {
                    attempt,
                    exit_code,
                    signal,
                },
                SupervisorSignal::AttemptTimeout { attempt } => Command::AttemptTimeout { attempt },
                SupervisorSignal::FinalizeReady { attempt, report } => {
                    Command::FinalizeReady { attempt, report }
                }
            };
            if tx.send(cmd).await.is_err() {
                break;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::supervisor::PsProbe;
    use crate::core::types::{Origin, Task};
    use crate::roles::loader::load_roles;
    use std::fs;
    use std::time::Instant;
    use tempfile::TempDir;

    fn task() -> Task {
        Task {
            id: "T33".to_string(),
            title: "actor".to_string(),
            description: "the mailbox".to_string(),
            files: vec![],
            acceptance: vec![],
        }
    }

    /// A core over an empty state dir, plus the receiver `run_actor` would be given.
    fn core(dir: &TempDir) -> (Core, mpsc::Receiver<Command>) {
        let (tx, rx) = channel();
        let (sig_tx, _sig_rx) = mpsc::channel(8);
        let registry = Registry::open(dir.path()).expect("open registry");
        let supervisor = Supervisor::new(Duration::from_millis(25), Arc::new(PsProbe), sig_tx);
        let core = Core::new(
            registry,
            supervisor,
            load_roles(None).expect("embedded roles"),
            dir.path().join("repo"),
            dir.path().to_path_buf(),
            tx,
        );
        (core, rx)
    }

    /// A run with one running builder agent and no attempts.
    fn seed(core: &mut Core) -> (RunId, AgentId) {
        let run = RunId::new_v4();
        let agent = AgentId::new_v4();
        core.registry
            .append(
                &run,
                EventPayload::RunCreated {
                    execution: None,
                    repo_root: core.repo_root.clone(),
                    state_dir: core.state_dir.clone(),
                    base_ref: "main".to_string(),
                    base_sha: "0".repeat(40),
                    task: task(),
                    version: 1,
                    lead: None,
                    team_name: None,
                    steps: None,
                },
            )
            .expect("run.created");
        core.registry
            .append(
                &run,
                EventPayload::AgentCreated {
                    agent_id: agent,
                    role: RoleName::Builder,
                    provider: ProviderName::Claude,
                    model: "sonnet".to_string(),
                    lineage_id: Some(LineageId::new_v4()),
                    depth: 1,
                    parent_agent_id: None,
                    origin: Origin::Lead,
                    writes: true,
                    cwd: core.repo_root.clone(),
                    worktree: Some(core.repo_root.clone()),
                },
            )
            .expect("agent.created");
        (run, agent)
    }

    #[tokio::test]
    async fn cancel_stop_closes_plan_and_gate_without_repair_and_refuses_new_work() {
        use crate::core::plan::{Plan, PlanItem, PlanItemKind, PlanItemStatus};
        use crate::core::types::GateKind;
        let dir = TempDir::new().unwrap();
        let (mut core, _rx) = core(&dir);
        let (run, agent) = seed(&mut core);
        core.registry.append(&run, EventPayload::PlanCreated { plan: Plan {
            version: 1, name: "cancel this plan".into(), items: vec![PlanItem {
                id: "human".into(), kind: PlanItemKind::Human, task: None,
                summary: Some("Approve this step".into()), after: vec![], verify: None, review: None,
            }],
        }}).unwrap();
        let gate = gates::create_gate(&mut core.registry, &run, NewGate {
            kind: GateKind::Plan, summary: "waiting".into(), requested_by: Origin::Lead,
            payload: gates::GatePayload::default(),
        }).unwrap();
        let signal = CancellationToken::new();
        core.lifecycle.configure(true, signal.clone());
        let status = core.lifecycle_request(lifecycle::Request::Stop { mode: lifecycle::StopMode::CancelWork }).await.unwrap();
        assert_eq!(status.stop_requested, Some(lifecycle::StopMode::CancelWork));
        assert!(!signal.is_cancelled(), "reply is available before the stopping tick");
        assert_eq!(core.registry.run(&run).unwrap().status, RunStatus::Cancelled);
        assert_eq!(core.registry.agent(&agent).unwrap().status, AgentStatus::Cancelled);
        assert_eq!(core.registry.gate(&gate.gate_id).unwrap().status, GateStatus::Denied);
        assert_eq!(core.registry.state().plans[&run].items["human"].status, PlanItemStatus::Skipped);
        let (reply, answered) = oneshot::channel();
        core.handle_command(Command::LeadStart { task: task(), message: "new work".into(), setup: LeadSetup::default(), reply }).await;
        assert!(matches!(answered.await.unwrap(), Err(CoreError::Lifecycle { code: "daemon_cancelling", .. })));
        core.handle_command(Command::Tick).await;
        assert!(signal.is_cancelled());
        assert!(core.pending_spawn.is_empty());
        assert!(core.registry.state().attempts.is_empty());
        assert_eq!(core.registry.run(&run).unwrap().status, RunStatus::Cancelled);
    }

    #[tokio::test]
    async fn cancel_stop_refuses_resolving_integration_before_changing_work() {
        let dir = TempDir::new().unwrap();
        let (mut core, _rx) = core(&dir);
        let (run, agent) = seed(&mut core);
        let gate = gates::create_gate(&mut core.registry, &run, NewGate {
            kind: crate::core::types::GateKind::Integrate, summary: "committing".into(),
            requested_by: Origin::Lead, payload: gates::GatePayload::default(),
        }).unwrap();
        core.registry.append(&run, EventPayload::GateResolving {
            gate_id: gate.gate_id, approve: true, feedback: None,
            by: Actor::Socket { client_name: "human".into() }, commit: None,
        }).unwrap();
        assert!(core.lifecycle_request(lifecycle::Request::Stop { mode: lifecycle::StopMode::CancelWork }).await.is_err());
        assert_eq!(core.registry.run(&run).unwrap().status, RunStatus::Running);
        assert_ne!(core.registry.agent(&agent).unwrap().status, AgentStatus::Cancelled);
        assert!(!core.lifecycle.draining());
    }

    #[tokio::test]
    async fn cancelled_run_with_lost_identity_holds_stop_across_replay() {
        let dir = TempDir::new().unwrap();
        let (mut first, _rx) = core(&dir);
        let (run, agent) = seed(&mut first);
        finish_attempt(&mut first, &run, agent, AttemptStatus::Lost);
        let status = first.lifecycle_request(lifecycle::Request::Stop { mode: lifecycle::StopMode::CancelWork }).await.unwrap();
        assert!(status.stop_error.unwrap().contains("identity was lost"));
        drop(first);
        let (mut restored, _rx) = core(&dir);
        let signal = CancellationToken::new();
        restored.lifecycle.configure(true, signal.clone());
        restored.lifecycle_request(lifecycle::Request::Stop { mode: lifecycle::StopMode::WhenIdle }).await.unwrap();
        restored.handle_command(Command::Tick).await;
        assert!(!signal.is_cancelled());
        let status = restored.lifecycle_request(lifecycle::Request::Status).await.unwrap();
        assert!(status.stop_error.is_some());
        assert_eq!(restored.registry.run(&run).unwrap().status, RunStatus::Cancelled);
    }

    #[tokio::test]
    async fn cancel_stop_tracks_each_preparing_helper_even_when_run_ids_match() {
        for fail_second in [false, true] {
            let dir = TempDir::new().unwrap();
            let (mut core, _rx) = core(&dir);
            let run = RunId::new_v4();
            for _ in 0..2 {
                core.delegate(DelegateRequest {
                    run_id: Some(run), role: RoleName::Builder, task: task(), model: None,
                    session: policy::SessionSpec::Fresh, base_ref: None, worktree: None,
                    steps: None, caller_run_id: None,
                }).unwrap();
            }
            let helpers: Vec<_> = core.pending_worktree.keys().copied().collect();
            assert_eq!(helpers.len(), 2);
            core.lifecycle_request(lifecycle::Request::Stop { mode: lifecycle::StopMode::CancelWork }).await.unwrap();
            for (index, lineage) in helpers.iter().enumerate() {
                let info = WorktreeInfo {
                    path: dir.path().join(format!("worktree-{index}")), branch: format!("cancel-test-{index}"), base_sha: "0".repeat(40),
                };
                let result = if fail_second && index == 1 {
                    Err(GitError::Timeout { op: "cancel-test", secs: 30 })
                } else { Ok(info) };
                core.on_worktree_ready(lineage, result);
                assert_eq!(core.registry.run(&run).unwrap().status, RunStatus::Cancelled);
                assert!(core.pending_spawn.is_empty());
            }
            assert!(core.cancellation.worktrees.is_empty());
            let mut projected = registry::State::default();
            let mut cancellation_seen = false;
            for event in core.registry.events(&run, None, usize::MAX) {
                registry::reduce(&mut projected, &event);
                if projected.runs.get(&run).is_some_and(|r| r.status == RunStatus::Cancelled) { cancellation_seen = true; }
                if cancellation_seen || !projected.agents.is_empty() {
                    assert_eq!(projected.runs[&run].status, RunStatus::Cancelled,
                        "every crash prefix after cancellation or agent creation stays cancelled");
                }
            }
        }
    }

    #[tokio::test]
    async fn cancelled_run_does_not_dispatch_a_success_that_finalized_late() {
        let dir = TempDir::new().unwrap();
        let (mut core, _rx) = core(&dir);
        let (run, agent) = seed(&mut core);
        let attempt = finish_attempt(&mut core, &run, agent, AttemptStatus::Succeeded);
        core.record_run_cancellation(&run).unwrap();
        core.on_attempt_finished(attempt).await;
        assert_eq!(core.registry.run(&run).unwrap().status, RunStatus::Cancelled);
        assert!(core.pending_spawn.is_empty());
        assert!(core.pending_retry.is_empty());
        assert!(core.registry.state().gates.is_empty());
    }

    #[tokio::test]
    async fn abandoned_queued_request_holds_safe_stop_until_processed() {
        let dir = TempDir::new().unwrap();
        let (mut core, mut rx) = core(&dir);
        let signal = CancellationToken::new();
        core.lifecycle.configure(true, signal.clone());
        core.lifecycle.request(lifecycle::Request::Stop { mode: lifecycle::StopMode::WhenIdle }, vec![], Instant::now()).unwrap();
        let handle = core.handle();
        let caller = tokio::spawn(async move { handle.status(StatusQuery::default()).await });
        let command = rx.recv().await.unwrap();
        caller.abort();
        let _ = caller.await;
        core.handle_command(Command::Tick).await;
        assert!(!signal.is_cancelled(), "queued admission survives its caller");
        core.handle_command(command).await;
        core.handle_command(Command::Tick).await;
        assert!(signal.is_cancelled());
    }

    #[test]
    fn a_lead_is_not_spawned_when_its_required_log_record_cannot_be_written() {
        let dir = TempDir::new().expect("tempdir");
        let (mut core, _rx) = core(&dir);
        let runs = dir.path().join("runs");
        fs::remove_dir(&runs).expect("empty runs directory");
        fs::write(&runs, b"not a directory").expect("block run log creation");

        let err = core
            .spawn_lead(task(), "coordinate this request".to_string())
            .expect_err("an unwritable durable record must fail closed");

        assert!(matches!(err, CoreError::Registry(_)));
        assert!(
            core.pending_spawn.is_empty(),
            "no provider spawn was queued"
        );
        assert!(core.registry.state().runs.is_empty());
        assert!(core.registry.state().agents.is_empty());
        assert!(core.registry.state().attempts.is_empty());
    }

    #[tokio::test]
    async fn await_result_parks_a_waiter_instead_of_holding_the_turn() {
        let dir = TempDir::new().expect("tempdir");
        let (mut core, _rx) = core(&dir);
        let (_run, agent) = seed(&mut core);

        let (tx, mut rx) = oneshot::channel();
        let started = Instant::now();
        core.handle_command(Command::AwaitResult { agent, reply: tx })
            .await;

        assert!(started.elapsed() < Duration::from_millis(200));
        assert_eq!(core.waiter_count(&agent), 1);
        // The waiter is parked, not answered: the agent has no finished attempt.
        assert!(rx.try_recv().is_err());

        // …and the actor still answers the next command in the same breath.
        let (tx, rx) = oneshot::channel();
        core.handle_command(Command::Status {
            query: StatusQuery::default(),
            reply: tx,
        })
        .await;
        let status = rx.await.expect("status replied").expect("status ok");
        assert_eq!(status.schema_version, STATUS_SCHEMA_VERSION);
        assert_eq!(status.agents.len(), 1);
        // `agent.created` projects to `starting`, so the lead is told to await its result.
        assert_eq!(
            status.agents[0].process_state,
            crate::core::types::AgentStatus::Starting
        );
        assert_eq!(
            status.agents[0].recommended_next,
            RecommendedNext::AwaitResult
        );
    }

    #[tokio::test]
    async fn dropped_await_receivers_do_not_accumulate() {
        let dir = TempDir::new().expect("tempdir");
        let (mut core, _rx) = core(&dir);
        let (_run, agent) = seed(&mut core);

        for _ in 0..25 {
            let (tx, rx) = oneshot::channel();
            core.handle_command(Command::AwaitResult { agent, reply: tx })
                .await;
            drop(rx);
        }
        assert_eq!(
            core.waiter_count(&agent),
            1,
            "only the newest waiter is kept"
        );

        // A turn that changes state sweeps the last dead one away too.
        core.handle_command(Command::Tick).await;
        assert_eq!(core.waiter_count(&agent), 0);
    }

    #[tokio::test]
    async fn await_result_on_an_unknown_agent_is_refused_rather_than_parked() {
        let dir = TempDir::new().expect("tempdir");
        let (mut core, _rx) = core(&dir);
        let agent = AgentId::new_v4();

        let (tx, rx) = oneshot::channel();
        core.handle_command(Command::AwaitResult { agent, reply: tx })
            .await;
        let err = rx.await.expect("replied").expect_err("unknown agent");
        assert!(matches!(err, CoreError::Policy(_)));
        assert_eq!(core.waiter_count(&agent), 0);
    }

    #[tokio::test]
    async fn resolving_an_unknown_gate_answers_the_door() {
        let dir = TempDir::new().expect("tempdir");
        let (mut core, _rx) = core(&dir);
        let gate = GateId::new_v4();

        let (tx, rx) = oneshot::channel();
        core.handle_command(Command::ResolveGate {
            gate,
            approve: false,
            feedback: None,
            by: Actor::Socket {
                client_name: "cli".to_string(),
            },
            reply: tx,
        })
        .await;
        let err = rx.await.expect("replied").expect_err("unknown gate");
        assert!(matches!(err, CoreError::UnknownGate(_)));
    }

    #[tokio::test]
    async fn every_door_reports_unavailable_once_the_actor_is_gone() {
        let dir = TempDir::new().expect("tempdir");
        let (core, rx) = core(&dir);
        let handle = core.handle();
        let shutdown = CancellationToken::new();
        let actor = tokio::spawn(run_actor(core, rx, shutdown.clone()));

        shutdown.cancel();
        actor.await.expect("actor stops");

        let err = handle
            .status(StatusQuery::default())
            .await
            .expect_err("no actor");
        assert!(matches!(err, CoreError::Unavailable));
        assert!(handle.is_closed());
    }

    /// `attempt.started` + `attempt.finished{status}` for a brand-new attempt of `agent`.
    ///
    /// The status is the caller's because it decides which branch of `core::loop` the attempt takes
    /// when a test lets a turn run: `succeeded` starts a reviewer, `cancelled` is the one terminal
    /// state the loop deliberately does nothing about.
    fn finish_attempt(
        core: &mut Core,
        run: &RunId,
        agent: AgentId,
        status: AttemptStatus,
    ) -> AttemptId {
        let attempt = AttemptId::new_v4();
        core.registry
            .append(
                run,
                EventPayload::AttemptStarted {
                    attempt_id: attempt,
                    agent_id: agent,
                    attempt_kind: crate::core::types::AttemptKind::Fresh,
                    dir: core.state_dir.join("attempt"),
                    argv: vec!["claude".to_string()],
                    cwd: core.repo_root.clone(),
                    pid: 4242,
                    pgid: 4242,
                    start_time: "Sat Aug 23 00:00:00 2026".to_string(),
                    pre_sha: "0".repeat(40),
                    timeout_sec: 900,
                    spawn_budget_usd: 2.0,
                },
            )
            .expect("attempt.started");
        core.registry
            .append(
                run,
                EventPayload::AttemptFinished {
                    attempt_id: attempt,
                    status,
                    exit_code: Some(0),
                    signal: None,
                    post_sha: Some("0".repeat(40)),
                    duration_ms: 10,
                    error: None,
                },
            )
            .expect("attempt.finished");
        attempt
    }

    /// A crash between `attempt.finished` and the branch's own events: the log shows a strike (17b
    /// got that far) but no `loop.dispatched`, so the repair attempt the branch owes was never
    /// started. The restarted actor must run the branch again.
    #[tokio::test]
    async fn a_partly_dispatched_branch_is_re_driven_on_restart() {
        let dir = TempDir::new().expect("tempdir");
        let (mut first, _rx) = core(&dir);
        let (run, agent) = seed(&mut first);
        let attempt = finish_attempt(&mut first, &run, agent, AttemptStatus::Succeeded);

        // Everything 17b writes *before* it resumes the builder — and nothing after.
        first
            .registry
            .append(
                &run,
                EventPayload::LineageStrike {
                    lineage_id: LineageId::new_v4(),
                    agent_id: agent,
                    reason: "the review failed".to_string(),
                    strikes: 1,
                },
            )
            .expect("lineage.strike");
        first
            .registry
            .append(
                &run,
                EventPayload::LoopStateChanged {
                    state: LoopState::Repairing,
                    builder_agent_id: Some(agent),
                    attempt_no: 1,
                    strikes: 1,
                },
            )
            .expect("loop.state");
        assert_eq!(loop_dispatch(&first.registry, &attempt), None);
        drop(first);

        let (mut restarted, _rx) = core(&dir);
        assert_eq!(
            loop_dispatch(&restarted.registry, &attempt),
            None,
            "a strike is not a finished branch"
        );
        assert_eq!(
            restarted.sweep_finished(),
            vec![attempt],
            "the branch never reached its marker, so it is owed a second run"
        );
        assert!(
            restarted.sweep_finished().is_empty(),
            "and only a second one"
        );
    }

    /// A branch that ends without appending its marker — because it failed part-way, or because
    /// (today) there is no branch at all — must be swept again by the **same** actor on the next
    /// tick, not left until somebody restarts the daemon.
    ///
    /// The version this replaced marked every swept attempt `dispatched` up front, so a branch that
    /// died after a partial side effect was never retried in that process's lifetime (Codex review
    /// of T33, round 3, finding 1).
    #[tokio::test]
    async fn a_branch_that_never_reaches_its_marker_is_swept_again() {
        let dir = TempDir::new().expect("tempdir");
        let (mut core, _rx) = core(&dir);
        let (run, agent) = seed(&mut core);
        // `cancelled` is the branch that writes nothing: a human ended this attempt, so the loop
        // has no next step to record and the attempt stays owed rather than marked.
        let attempt = finish_attempt(&mut core, &run, agent, AttemptStatus::Cancelled);

        // One whole turn: the sweep hands the attempt over, and the branch ends without a marker.
        core.handle_command(Command::Tick).await;
        assert!(
            !core.dispatched.contains(&attempt),
            "no marker, so nothing is done"
        );
        assert!(
            core.in_flight.is_empty(),
            "the guard is released whether the branch succeeded or not"
        );

        // …so the next sweep offers it again.
        assert_eq!(core.sweep_finished(), vec![attempt], "still owed");
        assert!(
            core.sweep_finished().is_empty(),
            "but only once while it is in flight"
        );
        core.finish_dispatch(&attempt);
        assert_eq!(core.sweep_finished(), vec![attempt], "and again after that");

        // Now the branch completes: its last append is the marker.
        core.registry
            .append(
                &run,
                EventPayload::LoopDispatched {
                    attempt_id: attempt,
                    branch: LoopBranch::Resume,
                },
            )
            .expect("loop.dispatched");
        core.finish_dispatch(&attempt);

        assert!(core.dispatched.contains(&attempt));
        assert!(core.in_flight.is_empty());
        core.handle_command(Command::Tick).await;
        assert!(
            core.sweep_finished().is_empty(),
            "a completed branch is never swept again"
        );
    }

    /// The same log with the marker on the end: the branch completed, so nothing is owed.
    #[tokio::test]
    async fn a_marked_attempt_is_not_re_driven_on_restart() {
        let dir = TempDir::new().expect("tempdir");
        let (mut first, _rx) = core(&dir);
        let (run, agent) = seed(&mut first);
        let attempt = finish_attempt(&mut first, &run, agent, AttemptStatus::Succeeded);
        first
            .registry
            .append(
                &run,
                EventPayload::LoopDispatched {
                    attempt_id: attempt,
                    branch: LoopBranch::Review,
                },
            )
            .expect("loop.dispatched");
        assert_eq!(
            loop_dispatch(&first.registry, &attempt),
            Some(LoopBranch::Review)
        );
        drop(first);

        let (mut restarted, _rx) = core(&dir);
        assert_eq!(
            loop_dispatch(&restarted.registry, &attempt),
            Some(LoopBranch::Review),
            "the marker survives the replay"
        );
        assert!(
            restarted.sweep_finished().is_empty(),
            "a marked attempt must not be driven a second time"
        );
    }

    #[tokio::test]
    async fn last_events_bounds_the_response_not_each_run() {
        let dir = TempDir::new().expect("tempdir");
        let (mut core, _rx) = core(&dir);
        for _ in 0..3 {
            let (run, agent) = seed(&mut core);
            // `seed` already appended two; top each run up to 100.
            for n in 0..98u32 {
                core.registry
                    .append(
                        &run,
                        EventPayload::LoopStateChanged {
                            state: LoopState::Building,
                            builder_agent_id: Some(agent),
                            attempt_no: n,
                            strikes: 0,
                        },
                    )
                    .expect("loop.state");
            }
        }

        let status = core.status(&StatusQuery {
            run_id: None,
            agent_id: None,
            last_events: 20,
        });
        assert_eq!(status.runs.len(), 3);
        assert_eq!(
            status.events.len(),
            20,
            "three runs of 100 events must still answer exactly `lastEvents`"
        );
        // The cap keeps the newest, and the merge is ordered.
        let mut ordered = status.events.clone();
        ordered.sort_by(|a, b| {
            a.base
                .ts
                .cmp(&b.base.ts)
                .then_with(|| a.base.run_id.as_uuid().cmp(b.base.run_id.as_uuid()))
                .then_with(|| a.base.seq.cmp(&b.base.seq))
        });
        assert_eq!(ordered, status.events, "the merged tail is sorted");
    }

    /// The documented escalation for an unwritable event log: no `run.status{blocked}` — recording
    /// is the thing that is broken — but a stop, after which every door reports `Unavailable`.
    ///
    /// The half that *sets* `fatal` is pinned in `core::supervisor`
    /// (`a_report_that_cannot_be_appended_stalls_after_its_budget`); this pins what the actor does
    /// once it is set.
    #[tokio::test]
    async fn a_fatal_log_failure_stops_the_actor_and_every_door_reports_unavailable() {
        let dir = TempDir::new().expect("tempdir");
        let (mut core, rx) = core(&dir);
        let handle = core.handle();
        core.fatal = Some("the event log is unwritable after 5 tries".to_string());

        let actor = tokio::spawn(run_actor(core, rx, CancellationToken::new()));

        // The turn that notices the fault still answers — nothing is dropped mid-flight.
        assert!(handle.status(StatusQuery::default()).await.is_ok());
        actor.await.expect("the actor stopped on its own");

        let err = handle
            .status(StatusQuery::default())
            .await
            .expect_err("the actor is gone");
        assert!(matches!(err, CoreError::Unavailable));
        assert!(handle.is_closed());
    }

    #[test]
    fn untrusted_text_is_clamped_and_flattened() {
        let clamped = clamp_untrusted("a\nb\tc", 200);
        assert_eq!(clamped, "a b c");
        let long: String = "é".repeat(300);
        let clamped = clamp_untrusted(&long, LAST_MESSAGE_CHARS);
        assert_eq!(clamped.chars().count(), LAST_MESSAGE_CHARS + 1);
        assert!(clamped.ends_with('…'));
    }
}
