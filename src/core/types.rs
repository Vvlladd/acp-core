//! Shared types: typed id newtypes, the `Event` union and the terminal-state enums. No I/O.
//! Implemented in T07/T11 (`reports/03-design.md` § Data Model).
//!
//! Every serialized type carries `#[serde(rename_all = "camelCase")]`, so the on-disk JSON is
//! byte-identical to the shape the design specifies (design, § Components: "Every serialized struct
//! carries `#[serde(rename_all = "camelCase")]`").
//!
//! Hazard: this module lives under `core`, which shadows the standard library's `core` crate inside
//! this crate — the std crate must be spelled `::core::` here. It appears nowhere in the code today.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use uuid::Uuid;

use crate::core::team::Effort;

// ---------------------------------------------------------------------------
// Typed id newtypes
// ---------------------------------------------------------------------------

/// Declares a `Uuid`-backed id newtype so that, e.g., a `GateId` can never be passed where an
/// `AgentId` is expected (design, § `src/core/types.rs`).
///
/// `serde` and `schemars` are implemented by hand rather than derived: the `uuid` dependency is
/// pinned to `features = ["v4"]` (no `serde`, no `schemars` bridge), and the design fixes the
/// dependency set. On the wire an id is a plain lowercase hyphenated UUID string.
macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        pub struct $name(Uuid);

        impl $name {
            /// A fresh random (v4) id.
            #[must_use]
            pub fn new_v4() -> Self {
                Self(Uuid::new_v4())
            }

            /// Wraps an existing uuid.
            #[must_use]
            pub const fn from_uuid(u: Uuid) -> Self {
                Self(u)
            }

            /// The underlying uuid.
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0.hyphenated(), f)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut buf = Uuid::encode_buffer();
                serializer.serialize_str(self.0.hyphenated().encode_lower(&mut buf))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                Uuid::parse_str(&s).map(Self).map_err(de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn inline_schema() -> bool {
                true
            }

            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> Cow<'static, str> {
                concat!(module_path!(), "::", stringify!($name)).into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                json_schema!({ "type": "string", "format": "uuid" })
            }
        }
    };
}

typed_id!(
    /// Identifies one run — a task, its worktrees, agents, gates and event log.
    RunId
);
typed_id!(
    /// Identifies one worker session (a role-scoped agent), which may span several attempts.
    AgentId
);
typed_id!(
    /// Identifies one spawn of a provider CLI on behalf of an agent.
    AttemptId
);
typed_id!(
    /// Identifies one human gate.
    GateId
);
typed_id!(
    /// Identifies one lineage — a worktree and the chain of agents that have written in it.
    LineageId
);

// ---------------------------------------------------------------------------
// Wire-literal booleans
// ---------------------------------------------------------------------------

/// A literal `true` on the wire: `HandoffEnvelope.untrusted` is always `true`, and the type makes
/// that unforgeable rather than merely conventional (design, § Data Model: `pub untrusted: True`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct True;

/// A literal `false` on the wire: a retired worktree is never resumable (design, § Event union:
/// `worktree.retired { …, resumable: False }`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct False;

macro_rules! wire_bool {
    ($name:ident, $value:literal) => {
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bool($value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let b = bool::deserialize(deserializer)?;
                if b == $value {
                    Ok($name)
                } else {
                    Err(de::Error::invalid_value(
                        de::Unexpected::Bool(b),
                        &stringify!($value),
                    ))
                }
            }
        }

        impl JsonSchema for $name {
            fn inline_schema() -> bool {
                true
            }

            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> Cow<'static, str> {
                concat!(module_path!(), "::", stringify!($name)).into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                json_schema!({ "type": "boolean", "const": $value })
            }
        }
    };
}

wire_bool!(True, true);
wire_bool!(False, false);

// ---------------------------------------------------------------------------
// Closed enums
// ---------------------------------------------------------------------------

/// Which provider CLI backs a role. Closed set — an unknown value fails to deserialize.
// `Ord` is derived so a `BTreeMap<ProviderName, _>` can key the provider catalog: the ordering is
// the declaration order, which is what puts `claude` before `codex` in every serialized catalog.
// Kept out of the doc comment on purpose — that text ships to workers inside the generated schema.
#[derive(
    Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug,
)]
#[serde(rename_all = "lowercase")]
pub enum ProviderName {
    Claude,
    Codex,
}

/// The roles the control plane knows. `Lead` is the caller (or, since A5, a spawned
/// conversational session); `Builder`/`Reviewer`/`Verifier`/`Security` are workers. `Verifier` (B1) is only
/// ever started by the control plane itself, between a builder's success and the review — it is
/// deliberately absent from `DelegatableRole` on both doors, as is the optional Security check.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum RoleName {
    Lead,
    Builder,
    Reviewer,
    Verifier,
    Security,
}

/// The speaker carried by an `agent.message` event. Closed: accepting arbitrary strings here
/// would turn a fixed wire contract into provider-authored data.
///
/// `Assistant` is the lead's streamed prose (A5). `User` is the human's follow-up turn to a lead,
/// recorded by the socket's `send_message` the moment it is accepted — without it the durable log
/// held only half of every conversation, and the app's transcript could not show what the human
/// said (B3 walkthrough fix). A `User` turn carries `src_line: 0`: no provider line produced it.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    Assistant,
    User,
}

/// Display-only assembly metadata for a long assistant block. Identity is scoped to its
/// attempt and source line; it conveys no authority and is absent on older/small messages.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MessagePart {
    pub block: u32,
    pub index: u32,
    pub count: u32,
    pub truncated: bool,
}

/// Lifecycle of a run.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Completed,
    AwaitingGate,
    Blocked,
    Integrated,
    Cancelled,
    Failed,
}

/// Where the builder→reviewer→repair loop currently sits.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LoopState {
    Building,
    // B1: the verify step between a builder's success and the review. Placed in loop order;
    // `LoopState` derives no `Ord` and serializes by name, so declaration order is inert here.
    Verifying,
    Reviewing,
    SecurityReviewing,
    AwaitingGate,
    Repairing,
    Retrying,
    Replacing,
    Blocked,
    Done,
}

/// Lifecycle of one worker session.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Starting,
    Running,
    Idle,
    Lost,
    Cancelled,
    Closed,
}

/// Terminal (and running) states of one attempt.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStatus {
    Running,
    Succeeded,
    Failed,
    InvalidOutput,
    Timeout,
    Cancelled,
    Lost,
    SpawnFailed,
    NoSession,
    Escalate,
}

/// Why an attempt failed, in terms the lead can act on.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    ProviderMissing,
    ProviderUnauthenticated,
    ResumeTargetMissing,
    SpawnError,
    SchemaInvalid,
    MaxTurns,
    BudgetHit,
    ProviderError,
    // A builder exited cleanly and changed nothing: the frozen diff is empty, so there is nothing
    // to review and nothing to integrate (Rev 25). A `///` comment here would make schemars render
    // the enum as a `oneOf` of consts instead of one flat `enum` list, so the rationale stays in a
    // `//` comment (CLAUDE.md § schemas).
    NoChangedFiles,
    // A reviewer's `diffHash` is missing or names a diff other than the one it was shown, so its
    // verdict cannot authorise an integration (Rev 25).
    DiffHashMismatch,
    // A git operation on the attempt's worktree failed, so the attempt could not be *verified*:
    // the changed-file set, the denylist check or the frozen diff is missing. Nothing about the
    // worker is being asserted — the control plane could not do its own job, and fails closed.
    WorkspaceError,
}

/// What a human gate is asking the human to decide.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum GateKind {
    Integrate,
    Escalate,
    Plan,
}

/// Lifecycle of a gate. `Resolving` is the in-flight window while the commit helper runs.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum GateStatus {
    Pending,
    Resolving,
    Approved,
    Denied,
}

/// A rule a worker broke. Recorded on the attempt and in the event log; never fatal by itself.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    WorkerCommitted,
    DenylistHit,
    BudgetExceeded,
    UnsafeArgv,
    PermissionDenials,
    // The worktree holds an untracked symlink whose contents the diff refused to read. A worker
    // that plants one is probing for a file its kernel sandbox denies it (Rev 25).
    SymlinkPlanted,
    // The worker ran `git add` and never committed. Only the control plane stages, and only the
    // paths a reviewer passed, so an index left dirty is both a rule broken and a wedge: every
    // approval of that worktree afterwards refuses on `assert_index_clean` until it is cleared
    // (round-4 review, finding 4). Remediated exactly like `worker_committed` — `reset --mixed` to
    // the attempt's `preSha`, which unstages without touching a byte on disk.
    WorkerStaged,
}

/// Who asked for an agent or a gate: the lead over MCP, or the control plane's own loop.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    Lead,
    ControlPlane,
}

/// Whether an attempt starts a new provider session or resumes an existing one.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum AttemptKind {
    Fresh,
    Resume,
}

/// Severity of one reviewer finding. `Blocking` findings drive the repair loop.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Blocking,
    Suggestion,
}

/// Codex's sandbox setting for a role (Claude's sandbox is expressed as `--settings` JSON instead).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxMode {
    ReadOnly,
    WorkspaceWrite,
}

/// Which checked-in schema a role's final message must validate against — or `FreeText`, the
/// lead's contract: a conversational turn is validated against nothing, and the log says so
/// instead of borrowing the builder's document (B3 walkthrough: a lead's every result read
/// "build-result — invalid structured result").
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum SchemaName {
    BuildResult,
    ReviewVerdict,
    VerifyReport,
    FreeText,
}

/// Whether a cost figure came from the provider itself or from our rate table.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum CostSource {
    Provider,
    RateTable,
}

/// Who requested a cancellation.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum CancelBy {
    Lead,
    Cli,
    Timeout,
}

/// A reviewer's verdict. The casing matches the provider fixtures (`{"verdict":"PASS"}`).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Pass,
    Fail,
}

/// What a `run.delegated` linkage points at (T84): a worker run a lead-origin `delegate` spawned
/// or attached to, or the plan container run a lead-origin `submit_plan` minted. Closed rather
/// than inferred from `role`'s presence, so a reader never has to guess the shape from a `null`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum DelegatedTarget {
    Worker,
    Plan,
}

/// Which branch of the loop reacted to a finished attempt (design, § Data Flow step 17).
///
/// It is the payload of `loop.dispatched`, the durable marker that says "the branch table already
/// ran for this attempt". The wire strings are the design's own step numbers, so a human reading
/// `events.jsonl` sees the branch named exactly as the document names it.
///
/// The design's review sketched this field as a `String` with a closed set written in a comment.
/// It is an enum because every other enumerated field of `EventPayload` is one and because
/// CLAUDE.md makes closed enums a hard rule — the wire values are identical either way.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum LoopBranch {
    #[serde(rename = "audit")]
    Audit,
    /// A conversational lead turn ended; it becomes idle and awaits a human follow-up.
    #[serde(rename = "lead")]
    Lead,
    /// 17a — an environment failure. No strike; the run is blocked until a human fixes the CLI.
    #[serde(rename = "17a")]
    Environment,
    /// 17b — a resumable failure: strike, then repair the same session.
    #[serde(rename = "17b")]
    Resume,
    /// 17c — a non-resumable failure: strike, then a fresh session in the same worktree.
    #[serde(rename = "17c")]
    RetryFresh,
    /// 17d — the lineage is out of strikes: close it and replace it, or escalate.
    #[serde(rename = "17d")]
    Replace,
    /// Steps 13-14 — the builder succeeded and a reviewer was started.
    #[serde(rename = "review")]
    Review,
    /// Steps 11/16 — a gate was opened (integrate after a PASS, or escalate).
    #[serde(rename = "gate")]
    Gate,
    /// B1 — a verify-step decision: a verifier was started for a builder's success, or a
    /// finished verifier attempt was acted on (report recorded, reviewer started, builder
    /// struck, replacement verifier started — or, with review disabled (B3), the integrate
    /// gate opened directly). Appended for wire stability.
    #[serde(rename = "verify")]
    Verify,
}

/// Who drove a state change through a door: the MCP channel, or a socket client (the human path).
///
/// Wire form is a bare string — `"mcp"` for the MCP channel, otherwise the socket client's
/// `clientName` (default `"cli"`, `"acp-mac"` for the macOS app) — which keeps the log
/// wire-compatible with the earlier `"mcp" | "cli"` values (design, § Local IPC contract).
/// Deserialization is therefore total: any string other than `"mcp"` is a socket client name.
///
/// Declared here rather than in `core/mod.rs` (where the design's actor sketch shows it) because
/// `Gate.resolved_by` and the `gate.*` events need it; `core/mod.rs` re-exports it.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Actor {
    Mcp,
    Socket { client_name: String },
}

impl Actor {
    /// The wire string for this actor.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Actor::Mcp => "mcp",
            Actor::Socket { client_name } => client_name,
        }
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Actor {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Actor {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "mcp" {
            Ok(Actor::Mcp)
        } else {
            Ok(Actor::Socket { client_name: s })
        }
    }
}

impl JsonSchema for Actor {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "Actor".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::Actor").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "string", "minLength": 1 })
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// The unit of work a lead delegates. MCP-facing input, so the schema is closed.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Task {
    pub id: String,
    pub title: String,
    pub description: String,
    pub files: Vec<String>,
    pub acceptance: Vec<String>,
}

/// The optional-step switches a run was created with (B3 role subsets).
///
/// Not `deny_unknown_fields`: this rides inside events a future build may extend, and each field
/// defaults to `true` because absence has always meant "the full chain".
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RunSteps {
    /// Added in team v3: old runs never acquire a security step implicitly.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub security: bool,
    #[serde(default = "default_step")]
    pub verify: bool,
    #[serde(default = "default_step")]
    pub review: bool,
}

impl Default for RunSteps {
    fn default() -> Self {
        RunSteps {
            security: false,
            verify: true,
            review: true,
        }
    }
}

fn default_step() -> bool {
    true
}

/// Execution intent is explicit in version-3 teams. Old teams retain build semantics.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    #[default]
    Build,
    Plan,
    Audit,
}

/// Choices captured before a run announces any worker. Saved-team edits apply only to later
/// runs; automatic replacement uses this record. A human-confirmed `run.recovered` event can
/// change its builder assignment while preserving all selected checks and their settings.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunExecution {
    /// Human-selected input for a conversational audit lead. Separate from `audit_selection`,
    /// which marks a concrete snapshot workflow and is driven by the audit state machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_audit_selection: Option<crate::workspace::git::audit::Selection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_selection: Option<crate::workspace::git::audit::Selection>,
    pub steps: RunSteps,
    pub version: u32,
    pub mode: RunMode,
    pub assignments: std::collections::BTreeMap<String, crate::core::team::Assignment>,
}

/// A run: one task, its base commit, its agents, gates and lineages.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<RunExecution>,
    pub run_id: RunId,
    pub repo_root: PathBuf,
    pub state_dir: PathBuf,
    pub base_ref: String,
    pub base_sha: String,
    pub task: Task,
    pub status: RunStatus,
    pub blocked_reason: Option<String>,
    pub loop_state: LoopState,
    pub created_at: String,
    pub spend_usd: f64,
    pub agent_ids: Vec<AgentId>,
    pub gate_ids: Vec<GateId>,
    pub integrated_sha: Option<String>,
    pub lineages: Vec<LineageState>,
    pub last_seq: u64,
    /// The step switches captured at creation (B3), or `None` on pre-B3 runs — both `true` then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steps: Option<RunSteps>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditRecord {
    pub snapshot: crate::workspace::git::audit::Snapshot,
    pub checks: Vec<AuditCheck>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome { Pass, Fail, NothingToRun }

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditCheck {
    pub attempt_id: AttemptId,
    pub role: RoleName,
    pub diff_hash: String,
    pub outcome: AuditOutcome,
    pub summary: String,
}

/// One worktree and the chain of agents that have written in it, with its strike count.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LineageState {
    pub lineage_id: LineageId,
    pub agent_ids: Vec<AgentId>,
    pub worktree: PathBuf,
    pub strikes: u8,
    pub closed: bool,
    pub closed_reason: Option<String>,
}

/// One provider session. Worker agents carry a lineage; a conversational lead deliberately does
/// not. Once the provider identifies the session it may be resumable for follow-up turns.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AgentHandle {
    pub agent_id: AgentId,
    pub run_id: RunId,
    pub role: RoleName,
    pub provider: ProviderName,
    pub model: String,
    /// Present only for worker agents. A conversational lead has no worktree lineage.
    pub lineage_id: Option<LineageId>,
    pub depth: u8,
    pub parent_agent_id: Option<AgentId>,
    pub origin: Origin,
    pub writes: bool,
    pub worktree: Option<PathBuf>,
    pub cwd: PathBuf,
    pub session_id: Option<String>,
    pub status: AgentStatus,
    pub resumable: bool,
    pub attempt_ids: Vec<AttemptId>,
    pub created_at: String,
}

/// One spawn of a provider CLI: its process identity, its accounting and its parsed result.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Attempt {
    pub attempt_id: AttemptId,
    pub agent_id: AgentId,
    pub run_id: RunId,
    pub kind: AttemptKind,
    pub dir: PathBuf,
    pub pid: Option<i32>,
    pub pgid: Option<i32>,
    pub start_time: Option<String>,
    pub status: AttemptStatus,
    pub error: Option<AttemptError>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub pre_sha: String,
    pub post_sha: Option<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub cost_usd: f64,
    pub tokens: Option<TokenUsage>,
    pub src_line: u64,
    pub byte_offset: u64,
    pub timeout_sec: u64,
    pub spawn_budget_usd: f64,
    pub result_path: Option<PathBuf>,
    pub structured_valid: Option<bool>,
    pub structured: Option<Value>,
    pub violations: Vec<PolicyViolation>,
    pub diff_path: Option<PathBuf>,
}

/// Token counts for one attempt, as reported by the provider.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct TokenUsage {
    pub input: u64,
    pub cached_input: u64,
    pub output: u64,
    pub reasoning: Option<u64>,
}

/// Why an attempt failed.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AttemptError {
    pub code: ErrorCode,
    pub message: String,
}

/// A rule a worker broke, with the evidence needed to explain it to a human.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PolicyViolation {
    pub kind: ViolationKind,
    pub detail: String,
    pub files: Option<Vec<String>>,
    pub pre_sha: Option<String>,
    pub post_sha: Option<String>,
}

/// One finding from a reviewer worker.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
// `deny_unknown_fields` also emits `additionalProperties: false` — the OpenAI backend refuses a
// structured-output schema whose object nodes lack it (live gate, 2026-08-27: invalid_json_schema).
// Every string is `maxLength`-bounded so `schemas/review-verdict.json` is fully bounded (design,
// § `schemas/`: "every string `maxLength`-bounded"). The bounds land on the nullable fields too —
// `maxLength` constrains strings and ignores `null`, so `None` stays valid.
pub struct ReviewFinding {
    pub severity: Severity,
    #[schemars(length(max = 400))]
    pub file: Option<String>,
    pub line: Option<u32>,
    #[schemars(length(max = 4000))]
    pub problem: String,
    #[schemars(length(max = 4000))]
    pub fix: Option<String>,
}

/// What an approved gate will commit, captured in `gate.resolving` **before** any git call.
///
/// It duplicates three fields out of the gate's `<gateId>.payload.json` on purpose. Once the
/// resolution window is open the payload file stops being load-bearing: finishing the commit and
/// reconciling a crashed one read this instead, so both depend only on the event log — the design's
/// "only durable truth" — and survive a payload file that `acp gc`, a half-finished restore or a
/// careless human removed while the commit was in flight. Without it a commit could exist in the
/// repository, carrying its `Acp-Gate-Id` trailer, with no event anywhere recording it.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CommitTarget {
    /// Absolute path of the worktree the commit is made in, and the one the trailer lookup for
    /// this gate is run in on replay.
    pub worktree: PathBuf,
    /// The subject line the commit will carry, already sanitized to what git will keep.
    pub subject: String,
    /// The reviewed change set. **This is what gets staged** — not the worktree as it stands when a
    /// human finally approves.
    pub files: Vec<String>,
    /// `diff.frozen{diffHash}` of the diff the reviewer passed (Rev 25). The commit helper
    /// re-freezes the worktree immediately before committing and refuses to commit unless the bytes
    /// still hash to this, so an approval can only ever integrate the diff it was shown. `None`
    /// only on a `gate.resolving` written before this field existed, which is refused rather than
    /// committed.
    #[serde(default)]
    pub diff_hash: Option<String>,
    /// The commit the frozen diff was taken against. The re-freeze is meaningless if HEAD has moved
    /// (`git diff HEAD` would compare against something else), so this is checked first and names
    /// the exact discrepancy when it fails.
    #[serde(default)]
    pub pre_sha: Option<String>,
    /// Where the reviewed diff was written. The verification writes its own copy beside it rather
    /// than over it, so the artifact a human reads is never rewritten by an approval.
    #[serde(default)]
    pub diff_path: Option<PathBuf>,
}

/// A human gate. Only an approval over the local socket can flip `status` to `Approved`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Gate {
    pub gate_id: GateId,
    pub run_id: RunId,
    pub kind: GateKind,
    pub status: GateStatus,
    pub summary: String,
    pub payload_path: PathBuf,
    pub requested_by: Origin,
    pub created_at: String,
    pub resolved_at: Option<String>,
    /// `"mcp"` or the socket client's name (design, § Local IPC contract).
    pub resolved_by: Option<Actor>,
    pub approve: Option<bool>,
    pub feedback: Option<String>,
    pub sha: Option<String>,
    /// What an approval of this gate commits, projected from `gate.resolving`. Set when the
    /// resolution window opens — not when it closes — so a crash inside the window still leaves it
    /// here for reconciliation. `None` while the gate is pending, and on a denial, which commits
    /// nothing.
    pub commit: Option<CommitTarget>,
}

/// One entry of `roles/roles.json`: the closed configuration of a role.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RoleSpec {
    pub role: RoleName,
    pub provider: ProviderName,
    pub models: Vec<String>,
    pub default_model: String,
    pub writes: bool,
    pub prompt_file: Option<String>,
    pub prompt_sha256: Option<String>,
    pub description: Option<String>,
    pub tools: Option<Vec<String>>,
    pub sandbox_mode: Option<SandboxMode>,
    pub max_turns: u32,
    pub spawn_budget_usd: f64,
    pub result_schema: SchemaName,
    pub allowed_delegations: Vec<RoleName>,
}

/// Whether a role's workers must run inside the provider's kernel sandbox (B1).
///
/// `writes` conflates three meanings elsewhere — sandbox attachment, chokepoint requirement, and
/// writer accounting (own worktree, one-writer rule, finalize freeze). This predicate is the first
/// two only: a **verifier** builds and runs tests in the *builder's* worktree, so it needs the
/// sandbox without being a writer. Everything about worktree ownership keeps keying on `writes`.
///
/// A free function on purpose: the spawn path applies it to the `(role, writes)` pair recorded in
/// the durable log (`agent.created`), never to a freshly loaded `RoleSpec` — a roles-file edit
/// between restarts must not be able to strip a recorded writer of its sandbox.
#[must_use]
pub fn requires_sandbox(role: RoleName, writes: bool) -> bool {
    writes || role == RoleName::Verifier
}

impl RoleSpec {
    /// [`requires_sandbox`] over this spec's own fields — the shape `validate_team` consults, so a
    /// provider without a sandbox plan cannot be assigned a verifier any more than a builder.
    #[must_use]
    pub fn requires_sandbox(&self) -> bool {
        requires_sandbox(self.role, self.writes)
    }
}

/// `roles/roles.json` in full: the closed role set plus the defaults, limits and rates every
/// policy check reads (design, § Security: `roles/roles.json`).
///
/// It lives here rather than in `roles/loader.rs` (where the design sketches it) because
/// `core::policy` takes `&RolesConfig` in every signature and `core` must not depend on `roles`:
/// the loader is still the only thing that *builds* one, this module only declares its shape
/// (T20 — the choice T31 is told to expect).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RolesConfig {
    pub version: u32,
    pub rates_updated: String,
    pub gates: GatesConfig,
    pub limits: Limits,
    pub defaults: Defaults,
    /// Model id → price card, used to price a turn the provider did not price itself.
    pub rates: HashMap<String, Rate>,
    /// The closed role set, keyed by the role's own name.
    pub roles: HashMap<RoleName, RoleSpec>,
    /// What each provider offers (Rev 26): the closed model and effort allowlists a
    /// [`Team`](crate::core::team::Team) is checked against.
    pub providers: ProviderCatalog,
}

/// The `providers` block of `roles/roles.json`, keyed by provider (Rev 26).
///
/// A `BTreeMap` rather than a `HashMap` because it is re-serialized verbatim by
/// [`roles_list`](crate::core::team::roles_list): the order a client sees must not depend on a
/// hash seed.
pub type ProviderCatalog = BTreeMap<ProviderName, ProviderSpec>;

/// What one provider accepts. Both lists are **closed allowlists**: a team naming a model or an
/// effort that is not here is rejected, so the set of values that can ever reach a provider's argv
/// is fixed by this file rather than by whoever wrote `team.json`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProviderSpec {
    /// Wire model ids, e.g. `["gpt-5.5", "gpt-5.3-codex-spark"]`.
    pub models: Vec<String>,
    /// The reasoning efforts this provider takes; empty for a provider that takes none (claude),
    /// which is also what makes `effort` on a claude assignment an error rather than a no-op.
    pub efforts: Vec<Effort>,
    /// Revision 28: a model's own effort list where it **narrows** `efforts` (`gpt-5.5` takes no
    /// `max`). A model absent from the map takes the whole provider list; the loader refuses an
    /// entry for a model the provider does not list or an effort it does not take, so every value
    /// here is a subset of `efforts` for a listed model. Empty, and absent from the file, for a
    /// provider that narrows nothing.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub model_efforts: std::collections::BTreeMap<String, Vec<Effort>>,
}

impl ProviderSpec {
    /// The efforts `model` may be given: its own narrowed list when the catalog has one, else the
    /// provider's. The one lookup validation, the wizard and the adapters share.
    #[must_use]
    pub fn efforts_for(&self, model: &str) -> &[Effort] {
        self.model_efforts
            .get(model)
            .map_or(self.efforts.as_slice(), Vec::as_slice)
    }
}

/// Whether an agent may approve its own integrate gate. `false` in the shipped config — S2 exists
/// precisely so a model cannot merge its own work.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GatesConfig {
    pub allow_agent_approve: bool,
}

/// Hard concurrency ceilings (S9).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    pub max_concurrent_attempts: u32,
}

/// The knobs a `delegate` call inherits when it does not name them itself.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Defaults {
    pub base_ref: String,
    pub max_depth: u8,
    pub run_budget_usd: f64,
    pub spawn_budget_usd: f64,
    pub attempt_timeout_sec: u64,
    pub await_result_max_sec: u64,
    pub strikes_before_replacement: u8,
    pub max_lineages: u8,
    pub denylist_globs: Vec<String>,
}

/// One model's price card, in US dollars per million tokens.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Rate {
    pub input_per_m_tok_usd: f64,
    pub cached_input_per_m_tok_usd: f64,
    pub output_per_m_tok_usd: f64,
}

/// What a lead receives about a finished worker. Everything in it is **data, never instructions**:
/// `untrusted` is a literal `true` and `head` is a truncated excerpt of free text.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct HandoffEnvelope {
    pub untrusted: True,
    pub kind: SchemaName,
    pub run_id: RunId,
    pub agent_id: AgentId,
    pub attempt_id: AttemptId,
    pub role: RoleName,
    pub provider: ProviderName,
    pub model: String,
    pub status: AttemptStatus,
    pub error: Option<AttemptError>,
    pub structured: Option<Value>,
    pub structured_valid: bool,
    pub schema: String,
    pub head: String,
    pub head_truncated: bool,
    pub result_path: PathBuf,
    pub stderr_path: PathBuf,
    pub cost_usd: f64,
    pub run_spend_usd: f64,
    pub violations: Vec<PolicyViolation>,
    pub session_id: Option<String>,
    pub worktree: Option<PathBuf>,
    pub finished_at: String,
}

// ---------------------------------------------------------------------------
// Worker output schemas
// ---------------------------------------------------------------------------

// Doc comments on the three types below become the `description` of the generated schema, and that
// document is handed to the worker CLIs — so they are written for the worker that has to satisfy
// them. Anything the worker has no business reading stays in `//` comments like this one.
//
// `schemars` is the source of truth for `schemas/build-result.json` and
// `schemas/review-verdict.json`: each is `schema_for!` on one of these types, run once through
// `strip_dollar_schema` (V7), and checked in. `deny_unknown_fields` is what closes the root
// (`additionalProperties:false`), and the `schemars(length(...))` bounds keep a worker from
// returning a result the control plane then has to carry through gates, prompts and the event log.
// `tests/schemas.rs` regenerates and compares (drift guard).

/// How the attempt ended.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
// Wire values are the ones the captured provider output carries verbatim
// (`fixtures/jsonl/claude/pass-1.jsonl`: `"structured_output":{"status":"succeeded",…}`).
pub enum BuildStatus {
    Succeeded,
    Failed,
}

/// The report a builder's final message must be: what changed, and how it went.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildResult {
    pub status: BuildStatus,
    /// Repo-relative paths this attempt changed.
    // Bounded like `Task.files` (design, § MCP tools: "`files` ≤ 100 entries of 1–400 chars").
    #[schemars(length(max = 100), inner(length(min = 1, max = 400)))]
    pub files_changed: Vec<String>,
    /// What changed and why, for the human reviewing it.
    // Ends up in the integrate-gate summary, which the design bounds at 4 000 characters.
    #[schemars(length(min = 1, max = 4000))]
    pub summary: String,
}

/// The report a reviewer's final message must be: one verdict, plus every finding behind it.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
// Casing matches the captured fixture verbatim (`fixtures/jsonl/codex/review-pass-1.jsonl`:
// `{"verdict":"PASS","findings":[]}`); `Verdict` is `UPPERCASE` on the wire for that reason.
pub struct ReviewVerdict {
    pub verdict: Verdict,
    #[schemars(length(max = 100))]
    pub findings: Vec<ReviewFinding>,
    /// Copy the `diffHash` from your task prompt verbatim. A verdict that does not echo it is
    /// discarded: it cannot be shown to have reviewed the diff you were given.
    // Rev 25: the control plane compares it against `diff.frozen.diffHash`, so a PASS can only ever
    // open an integrate gate for the exact diff the reviewer was shown.
    #[schemars(regex(pattern = r"^[0-9a-f]{64}$"))]
    pub diff_hash: String,
}

/// What one verify attempt found (B1). `nothing-to-run` is a first-class answer: a repo with no
/// discoverable build/test command must never fail verification for it, and a verifier must never
/// invent a command to have something to report.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum VerifyStatus {
    Pass,
    Fail,
    NothingToRun,
}

/// The verifier's schema-bound report (B1, `schemas/verify-report.json`). Every string is
/// worker-authored and untrusted; the bounds here are the wire contract, enforced by the same
/// `jsonschema` validation as the other worker results.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyReport {
    pub status: VerifyStatus,
    #[schemars(length(min = 1, max = 4000))]
    pub summary: String,
    /// The build/test commands actually run, for the human and the reviewer — never re-executed.
    #[schemars(length(max = 20), inner(length(min = 1, max = 500)))]
    pub commands: Vec<String>,
    /// Failing test names / the top build error. Empty unless `status` is `fail`.
    #[schemars(length(max = 50), inner(length(min = 1, max = 1000)))]
    pub failures: Vec<String>,
    /// Copy the `diffHash` from your task prompt verbatim. A report that does not echo it is
    /// discarded: it cannot be shown to be about the state you were asked to verify.
    #[schemars(regex(pattern = r"^[0-9a-f]{64}$"))]
    pub diff_hash: String,
}

/// Removes the top-level `$schema` key from a generated schema document, leaving `$defs`/`$ref`
/// untouched; anything that is not a JSON object is returned unchanged (V7).
///
/// `claude --json-schema` **rejects** schemars 1.x output while that key is present ("no schema
/// with key or ref https://json-schema.org/draft/2020-12/schema"); Codex accepts either form. So
/// the stripped document is the single artifact — written to `schemas/*.json`, handed to both
/// CLIs, and compiled by `jsonschema` — with no divergence between them (design, § `schemas/`).
#[must_use]
pub fn strip_dollar_schema(mut v: Value) -> Value {
    if let Some(obj) = v.as_object_mut() {
        obj.remove("$schema");
    }
    v
}

/// Adds every property key of every object node to that node's `required` list (live gate,
/// 2026-08-27). The OpenAI structured-output backend refuses a schema whose `required` omits any
/// key in `properties` ("'required' is required … including every key"); optionality is expressed
/// as nullability instead, which schemars already emits for `Option<T>` (`"type": [.., "null"]`).
/// Purely widens `required`, so every document the old schema accepted with all keys present is
/// still accepted, and the local validator stays byte-for-byte the artifact both CLIs see.
///
/// Worker **result** schemas only — MCP tool *input* schemas keep genuinely optional arguments.
#[must_use]
pub fn require_all_properties(mut v: Value) -> Value {
    fn walk(node: &mut Value) {
        match node {
            Value::Object(obj) => {
                if let Some(Value::Object(props)) = obj.get("properties") {
                    let all: Vec<Value> = props.keys().cloned().map(Value::String).collect();
                    obj.insert("required".to_string(), Value::Array(all));
                }
                for child in obj.values_mut() {
                    walk(child);
                }
            }
            Value::Array(items) => {
                for child in items {
                    walk(child);
                }
            }
            _ => {}
        }
    }
    walk(&mut v);
    v
}

// ---------------------------------------------------------------------------
// Event union
// ---------------------------------------------------------------------------

/// Every `kind` tag the `Event` union carries, in design order (`reports/03-design.md` § Event
/// union). The exhaustive `kind_tag` match in this module's tests keeps this list from drifting.
pub const EVENT_KINDS: &[&str] = &[
    "run.created",
    "run.status",
    "loop.state",
    "worktree.created",
    "worktree.retired",
    "agent.created",
    "agent.session",
    "agent.status",
    "attempt.started",
    "agent.progress",
    "attempt.usage",
    "attempt.result",
    "attempt.cancel_requested",
    "attempt.finished",
    "policy.violation",
    "diff.frozen",
    "review.verdict",
    "lineage.strike",
    "lineage.closed",
    "gate.created",
    "gate.resolving",
    "gate.resolved",
    "integrate.committed",
    // Appended rather than slotted next to `attempt.finished`, which is where it belongs by
    // meaning: `EVENT_KINDS` order is also the wire-fixture order in `tests/types_roundtrip.rs`,
    // and inserting in the middle would renumber every fixture after it for no gain.
    "loop.dispatched",
    // A5 W4: append-only for the same reason as `loop.dispatched` above.
    "agent.message",
    // B1: append-only for the same reason as `loop.dispatched` above.
    "verify.report",
    // B3 (T75): the plan conductor's two kinds — the validated document, then per-item progress.
    "plan.created",
    "plan.item",
    // T84: append-only for the same reason as `loop.dispatched` above.
    "run.delegated",
    "audit.prepared",
    "audit.checked",
    "security.verdict",
    "run.recovered",
];

/// The envelope every event carries; the registry assigns `seq` and `ts` on append.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EventBase {
    pub seq: u64,
    pub ts: String,
    pub run_id: RunId,
}

/// A durable event: `{seq, ts, runId, kind, …payload}`, discriminated by `kind`.
///
/// `deny_unknown_fields` is **intentionally not applied**: it is incompatible with `flatten`, and
/// it would break forward compatibility for a newer daemon's events read by an older tool (design,
/// § Event union). The byte-equal round-trip test over the checked-in fixtures is the drift guard.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    #[serde(flatten)]
    pub base: EventBase,
    #[serde(flatten)]
    pub payload: EventPayload,
}

/// An event minus its envelope — the shape `Registry::append(run, e)` accepts.
pub type NewEvent = EventPayload;

/// Everything that can happen in a run, internally tagged by `kind`.
///
/// `rename_all_fields` is what puts the *fields* of each variant in camelCase (`rename_all` alone
/// renames only the variants, which the explicit `rename` tags below already fix).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum EventPayload {
    #[serde(rename = "run.recovered")]
    RunRecovered { recovery: crate::core::recovery::Record },
    /// A dedicated security verdict; never counted as ordinary code review.
    #[serde(rename = "security.verdict")]
    SecurityVerdict {
        attempt_id: AttemptId,
        builder_attempt_id: AttemptId,
        verdict: Verdict,
        findings: Vec<ReviewFinding>,
        diff_hash: String,
    },
    #[serde(rename = "audit.prepared")]
    AuditPrepared { snapshot: crate::workspace::git::audit::Snapshot },
    #[serde(rename = "audit.checked")]
    AuditChecked { check: AuditCheck },
    #[serde(rename = "run.created")]
    RunCreated {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        execution: Option<RunExecution>,
        repo_root: PathBuf,
        state_dir: PathBuf,
        base_ref: String,
        base_sha: String,
        task: Task,
        version: u32,
        /// The lead responsible for this run, as `"<provider>:<model>"`: either an informational
        /// team assignment on a delegated run or the default spawned lead on an A5 conversation.
        lead: Option<String>,
        /// The name of the `team.json` in force when the run was created (Rev 26), or `None` when
        /// no team file existed and the roles config's own defaults were used.
        team_name: Option<String>,
        /// Which optional steps the team enabled when this run was created (B3). Captured here so
        /// a `team.json` edit mid-run can never change a running run's shape — the same
        /// log-sourced discipline as the B1 sandbox predicate. Absent on pre-B3 logs and on
        /// v1 teams' runs, which means everything runs.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        steps: Option<RunSteps>,
    },
    #[serde(rename = "run.status")]
    RunStatus_ {
        status: RunStatus,
        reason: Option<String>,
    },
    #[serde(rename = "loop.state")]
    LoopStateChanged {
        state: LoopState,
        builder_agent_id: Option<AgentId>,
        attempt_no: u32,
        strikes: u8,
    },
    #[serde(rename = "worktree.created")]
    WorktreeCreated {
        agent_id: AgentId,
        lineage_id: LineageId,
        path: PathBuf,
        branch: String,
        base_sha: String,
    },
    #[serde(rename = "worktree.retired")]
    WorktreeRetired {
        path: PathBuf,
        reason: String,
        resumable: False,
    },
    #[serde(rename = "agent.created")]
    AgentCreated {
        agent_id: AgentId,
        role: RoleName,
        provider: ProviderName,
        model: String,
        /// Present only for worker agents. A conversational lead mints no lineage.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lineage_id: Option<LineageId>,
        depth: u8,
        parent_agent_id: Option<AgentId>,
        origin: Origin,
        writes: bool,
        cwd: PathBuf,
        worktree: Option<PathBuf>,
    },
    #[serde(rename = "agent.session")]
    AgentSession {
        agent_id: AgentId,
        attempt_id: AttemptId,
        session_id: String,
        src_line: u64,
    },
    #[serde(rename = "agent.status")]
    AgentStatusChanged {
        agent_id: AgentId,
        status: AgentStatus,
        reason: Option<String>,
    },
    #[serde(rename = "attempt.started")]
    AttemptStarted {
        attempt_id: AttemptId,
        agent_id: AgentId,
        /// `kind2` on the wire: `kind` is taken by the union's own tag.
        #[serde(rename = "kind2")]
        attempt_kind: AttemptKind,
        dir: PathBuf,
        argv: Vec<String>,
        cwd: PathBuf,
        pid: i32,
        pgid: i32,
        start_time: String,
        pre_sha: String,
        timeout_sec: u64,
        spawn_budget_usd: f64,
    },
    #[serde(rename = "agent.progress")]
    AgentProgress {
        attempt_id: AttemptId,
        src_line: u64,
        phase: String,
        note: Option<String>,
    },
    #[serde(rename = "attempt.usage")]
    AttemptUsage {
        attempt_id: AttemptId,
        src_line: u64,
        cost_usd: f64,
        tokens: TokenUsage,
        source: CostSource,
    },
    #[serde(rename = "attempt.result")]
    AttemptResult {
        attempt_id: AttemptId,
        src_line: u64,
        result_path: PathBuf,
        schema: String,
        structured_valid: bool,
        structured: Option<Value>,
    },
    #[serde(rename = "attempt.cancel_requested")]
    AttemptCancelRequested { attempt_id: AttemptId, by: CancelBy },
    #[serde(rename = "attempt.finished")]
    AttemptFinished {
        attempt_id: AttemptId,
        status: AttemptStatus,
        exit_code: Option<i32>,
        signal: Option<String>,
        post_sha: Option<String>,
        duration_ms: u64,
        error: Option<AttemptError>,
    },
    #[serde(rename = "policy.violation")]
    PolicyViolated {
        attempt_id: Option<AttemptId>,
        agent_id: Option<AgentId>,
        violation: PolicyViolation,
    },
    #[serde(rename = "diff.frozen")]
    DiffFrozen {
        attempt_id: AttemptId,
        diff_path: PathBuf,
        /// sha256 hex of the frozen diff file — stated in the reviewer's prompt, echoed back in
        /// `review.verdict.diffHash`, and compared before a PASS may open a gate (Rev 25).
        diff_hash: String,
        files: Vec<String>,
        added: u64,
        deleted: u64,
    },
    #[serde(rename = "review.verdict")]
    ReviewVerdict {
        attempt_id: AttemptId,
        builder_attempt_id: AttemptId,
        verdict: Verdict,
        findings: Vec<ReviewFinding>,
        /// The hash the reviewer echoed. `None` when it echoed nothing; a `PASS` is only honoured
        /// when this equals the `diffHash` of the `diff.frozen` it was shown (Rev 25).
        diff_hash: Option<String>,
    },
    #[serde(rename = "lineage.strike")]
    LineageStrike {
        lineage_id: LineageId,
        agent_id: AgentId,
        reason: String,
        strikes: u8,
    },
    #[serde(rename = "lineage.closed")]
    LineageClosed {
        lineage_id: LineageId,
        reason: String,
    },
    #[serde(rename = "gate.created")]
    GateCreated {
        gate_id: GateId,
        /// `gkind` on the wire: `kind` is taken by the union's own tag.
        #[serde(rename = "gkind")]
        gate_kind: GateKind,
        summary: String,
        payload_path: PathBuf,
        requested_by: Origin,
    },
    #[serde(rename = "gate.resolving")]
    GateResolving {
        gate_id: GateId,
        approve: bool,
        feedback: Option<String>,
        by: Actor,
        /// What the approval will commit, or `None` for a denial. Written here rather than left in
        /// the gate's payload file so that finalization and crash reconciliation never depend on a
        /// file that may be gone by the time the commit lands (see [`CommitTarget`]).
        commit: Option<CommitTarget>,
    },
    #[serde(rename = "gate.resolved")]
    GateResolved {
        gate_id: GateId,
        status: GateStatus,
        sha: Option<String>,
        feedback: Option<String>,
    },
    #[serde(rename = "integrate.committed")]
    IntegrateCommitted {
        gate_id: GateId,
        worktree: PathBuf,
        sha: String,
        subject: String,
        files: Vec<String>,
    },
    /// The loop has finished reacting to `attempt_id`'s `attempt.finished`.
    ///
    /// It is a **marker, not a decision**: it carries no state the projection needs, and the
    /// reducer ignores it. Its only reader is the restart path, which uses it to tell an attempt
    /// the branch table already ran for from one that finished a moment before the daemon died and
    /// is still owed its reviewer, its strike or its gate (Codex review of T33, round 2).
    ///
    /// Appended by `on_attempt_finished` as the **last** action of whichever branch it took, so
    /// its presence means every side effect of that branch is already durable.
    #[serde(rename = "loop.dispatched")]
    LoopDispatched {
        attempt_id: AttemptId,
        branch: LoopBranch,
    },
    /// One turn of a lead conversation. `role: assistant` is one untrusted text block streamed
    /// by a spawned lead — builder and reviewer prose never reaches this kind, and the supervisor
    /// bounds both each message and the attempt total. `role: user` (T82) is the human's follow-up
    /// as the socket accepted it: `src_line` 0, text whole (the door bounds it), outside the
    /// supervisor's per-attempt cap.
    #[serde(rename = "agent.message")]
    AgentMessage {
        attempt_id: AttemptId,
        src_line: u64,
        role: MessageRole,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        part: Option<MessagePart>,
    },
    /// B1: what the verify step found, emitted between the builder's success and the review.
    /// `summary`/`failures` are worker-authored untrusted text, clamped by the emitter.
    #[serde(rename = "verify.report")]
    VerifyReport {
        attempt_id: AttemptId,
        builder_attempt_id: AttemptId,
        status: VerifyStatus,
        summary: String,
        failures: Vec<String>,
    },
    /// B3: the validated plan document, verbatim, on the container run's log — the durable
    /// original every later `plan.item` is read against.
    #[serde(rename = "plan.created")]
    PlanCreated { plan: crate::core::plan::Plan },
    /// B3: one item's progress. The conductor is the only writer; restart re-drive keys on the
    /// latest status per item, the same `*_since` discipline as every other marker.
    #[serde(rename = "plan.item")]
    PlanItem {
        item_id: String,
        status: crate::core::plan::PlanItemStatus,
        /// The run a started `work` item became. `itemRunId` on the wire: the flattened
        /// envelope already owns `runId` (the container run), and the two must never collide.
        #[serde(default, skip_serializing_if = "Option::is_none", rename = "itemRunId")]
        run_id: Option<RunId>,
        /// The gate a started `human` item minted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gate_id: Option<GateId>,
    },
    /// T84: recorded on the **lead's own run**, once, for every run its delegation caused — a
    /// worker a lead-origin `delegate` spawned or attached to, or the plan container a lead-origin
    /// `submit_plan` minted. Emitted only after `delegatedRunId`'s own `run.created` is durable, so
    /// the linkage never points at a run that does not exist; never emitted for a caller that
    /// failed the daemon's strict-equality attribution check (`core::loop::validated_caller_run`),
    /// including every terminal lead (no `ACP_LEAD_RUN_ID`, hence no caller run to write to).
    #[serde(rename = "run.delegated")]
    RunDelegated {
        delegated_run_id: RunId,
        /// The delegated role, for a worker target. `None` for a plan container, which mints no
        /// single role of its own.
        role: Option<RoleName>,
        target: DelegatedTarget,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task() -> Task {
        Task {
            id: "T07".into(),
            title: "core/types.rs".into(),
            description: "data model, typed ids, Event union".into(),
            files: vec!["src/core/types.rs".into()],
            acceptance: vec!["cargo build exits 0".into()],
        }
    }

    fn tokens() -> TokenUsage {
        TokenUsage {
            input: 1200,
            cached_input: 800,
            output: 340,
            reasoning: Some(64),
        }
    }

    /// Exhaustive by construction: adding a variant to `EventPayload` stops this file compiling,
    /// which forces `EVENT_KINDS` (and `tests/types_roundtrip.rs`) to be updated alongside it.
    fn kind_tag(p: &EventPayload) -> &'static str {
        match p {
            EventPayload::RunRecovered { .. } => "run.recovered",
            EventPayload::AuditPrepared { .. } => "audit.prepared",
            EventPayload::AuditChecked { .. } => "audit.checked",
            EventPayload::SecurityVerdict { .. } => "security.verdict",
            EventPayload::RunCreated { .. } => "run.created",
            EventPayload::RunStatus_ { .. } => "run.status",
            EventPayload::LoopStateChanged { .. } => "loop.state",
            EventPayload::WorktreeCreated { .. } => "worktree.created",
            EventPayload::WorktreeRetired { .. } => "worktree.retired",
            EventPayload::AgentCreated { .. } => "agent.created",
            EventPayload::AgentSession { .. } => "agent.session",
            EventPayload::AgentStatusChanged { .. } => "agent.status",
            EventPayload::AttemptStarted { .. } => "attempt.started",
            EventPayload::AgentProgress { .. } => "agent.progress",
            EventPayload::AttemptUsage { .. } => "attempt.usage",
            EventPayload::AttemptResult { .. } => "attempt.result",
            EventPayload::AttemptCancelRequested { .. } => "attempt.cancel_requested",
            EventPayload::AttemptFinished { .. } => "attempt.finished",
            EventPayload::PolicyViolated { .. } => "policy.violation",
            EventPayload::DiffFrozen { .. } => "diff.frozen",
            EventPayload::ReviewVerdict { .. } => "review.verdict",
            EventPayload::LineageStrike { .. } => "lineage.strike",
            EventPayload::LineageClosed { .. } => "lineage.closed",
            EventPayload::GateCreated { .. } => "gate.created",
            EventPayload::GateResolving { .. } => "gate.resolving",
            EventPayload::GateResolved { .. } => "gate.resolved",
            EventPayload::IntegrateCommitted { .. } => "integrate.committed",
            EventPayload::LoopDispatched { .. } => "loop.dispatched",
            EventPayload::AgentMessage { .. } => "agent.message",
            EventPayload::VerifyReport { .. } => "verify.report",
            EventPayload::PlanCreated { .. } => "plan.created",
            EventPayload::PlanItem { .. } => "plan.item",
            EventPayload::RunDelegated { .. } => "run.delegated",
        }
    }

    /// One instance of every variant, in `EVENT_KINDS` order.
    fn all_payloads() -> Vec<EventPayload> {
        let agent = AgentId::new_v4();
        let attempt = AttemptId::new_v4();
        let gate = GateId::new_v4();
        let lineage = LineageId::new_v4();
        vec![
            EventPayload::RunCreated {
                execution: None,
                repo_root: PathBuf::from("/repo"),
                state_dir: PathBuf::from("/state"),
                base_ref: "main".into(),
                base_sha: "a".repeat(40),
                task: task(),
                version: 1,
                lead: Some("claude".into()),
                team_name: Some("phase-1".into()),
                steps: None,
            },
            EventPayload::RunStatus_ {
                status: RunStatus::Running,
                reason: None,
            },
            EventPayload::LoopStateChanged {
                state: LoopState::Building,
                builder_agent_id: Some(agent),
                attempt_no: 1,
                strikes: 0,
            },
            EventPayload::WorktreeCreated {
                agent_id: agent,
                lineage_id: lineage,
                path: PathBuf::from("/repo/.acp/worktrees/r/a"),
                branch: "acp/r/a".into(),
                base_sha: "a".repeat(40),
            },
            EventPayload::WorktreeRetired {
                path: PathBuf::from("/repo/.acp/worktrees/r/a"),
                reason: "lineage closed".into(),
                resumable: False,
            },
            EventPayload::AgentCreated {
                agent_id: agent,
                role: RoleName::Builder,
                provider: ProviderName::Claude,
                model: "claude-haiku".into(),
                lineage_id: Some(lineage),
                depth: 1,
                parent_agent_id: None,
                origin: Origin::Lead,
                writes: true,
                cwd: PathBuf::from("/repo/.acp/worktrees/r/a"),
                worktree: Some(PathBuf::from("/repo/.acp/worktrees/r/a")),
            },
            EventPayload::AgentSession {
                agent_id: agent,
                attempt_id: attempt,
                session_id: "sess-1".into(),
                src_line: 1,
            },
            EventPayload::AgentStatusChanged {
                agent_id: agent,
                status: AgentStatus::Running,
                reason: None,
            },
            EventPayload::AttemptStarted {
                attempt_id: attempt,
                agent_id: agent,
                attempt_kind: AttemptKind::Fresh,
                dir: PathBuf::from("/state/attempts/x"),
                argv: vec!["claude".into(), "-p".into()],
                cwd: PathBuf::from("/repo/.acp/worktrees/r/a"),
                pid: 4242,
                pgid: 4242,
                start_time: "Sat Aug 22 22:00:00 2026".into(),
                pre_sha: "a".repeat(40),
                timeout_sec: 900,
                spawn_budget_usd: 1.5,
            },
            EventPayload::AgentProgress {
                attempt_id: attempt,
                src_line: 12,
                phase: "tool_use".into(),
                note: Some("Edit".into()),
            },
            EventPayload::AttemptUsage {
                attempt_id: attempt,
                src_line: 30,
                cost_usd: 0.0421,
                tokens: tokens(),
                source: CostSource::RateTable,
            },
            EventPayload::AttemptResult {
                attempt_id: attempt,
                src_line: 31,
                result_path: PathBuf::from("/state/attempts/x/result.txt"),
                schema: "build-result".into(),
                structured_valid: true,
                structured: Some(serde_json::json!({ "status": "succeeded" })),
            },
            EventPayload::AttemptCancelRequested {
                attempt_id: attempt,
                by: CancelBy::Lead,
            },
            EventPayload::AttemptFinished {
                attempt_id: attempt,
                status: AttemptStatus::Succeeded,
                exit_code: Some(0),
                signal: None,
                post_sha: Some("b".repeat(40)),
                duration_ms: 12_345,
                error: None,
            },
            EventPayload::PolicyViolated {
                attempt_id: Some(attempt),
                agent_id: Some(agent),
                violation: PolicyViolation {
                    kind: ViolationKind::WorkerCommitted,
                    detail: "worker ran git commit".into(),
                    files: Some(vec!["src/lib.rs".into()]),
                    pre_sha: Some("a".repeat(40)),
                    post_sha: Some("b".repeat(40)),
                },
            },
            EventPayload::DiffFrozen {
                attempt_id: attempt,
                diff_path: PathBuf::from("/state/runs/r/diffs/x.patch"),
                diff_hash: "d".repeat(64),
                files: vec!["src/lib.rs".into()],
                added: 12,
                deleted: 3,
            },
            EventPayload::ReviewVerdict {
                attempt_id: attempt,
                builder_attempt_id: AttemptId::new_v4(),
                verdict: Verdict::Fail,
                findings: vec![ReviewFinding {
                    severity: Severity::Blocking,
                    file: Some("src/lib.rs".into()),
                    line: Some(10),
                    problem: "unhandled error".into(),
                    fix: Some("propagate it".into()),
                }],
                diff_hash: Some("d".repeat(64)),
            },
            EventPayload::LineageStrike {
                lineage_id: lineage,
                agent_id: agent,
                reason: "invalid output".into(),
                strikes: 1,
            },
            EventPayload::LineageClosed {
                lineage_id: lineage,
                reason: "strikes exhausted".into(),
            },
            EventPayload::GateCreated {
                gate_id: gate,
                gate_kind: GateKind::Integrate,
                summary: "integrate T07".into(),
                payload_path: PathBuf::from("/state/runs/r/gates/g.payload.json"),
                requested_by: Origin::ControlPlane,
            },
            EventPayload::GateResolving {
                gate_id: gate,
                approve: true,
                feedback: None,
                by: Actor::Socket {
                    client_name: "cli".into(),
                },
                commit: Some(CommitTarget {
                    worktree: PathBuf::from("/repo/.acp/worktrees/r/a"),
                    subject: "acp: integrate T07".into(),
                    files: vec!["src/adder.ts".into()],
                    diff_hash: Some("d".repeat(64)),
                    pre_sha: Some("a".repeat(40)),
                    diff_path: Some(PathBuf::from("/state/runs/r/diffs/a.patch")),
                }),
            },
            EventPayload::GateResolved {
                gate_id: gate,
                status: GateStatus::Approved,
                sha: Some("c".repeat(40)),
                feedback: None,
            },
            EventPayload::IntegrateCommitted {
                gate_id: gate,
                worktree: PathBuf::from("/repo/.acp/worktrees/r/a"),
                sha: "c".repeat(40),
                subject: "core/types.rs".into(),
                files: vec!["src/core/types.rs".into()],
            },
            EventPayload::LoopDispatched {
                attempt_id: attempt,
                branch: LoopBranch::Review,
            },
            EventPayload::AgentMessage {
                attempt_id: attempt,
                src_line: 19,
                role: MessageRole::Assistant,
                text: "I inspected the repository and found the failing boundary.".into(),
                part: None,
            },
            EventPayload::VerifyReport {
                // Distinct on purpose: an id transposition must not round-trip invisibly.
                attempt_id: AttemptId::new_v4(),
                builder_attempt_id: attempt,
                status: VerifyStatus::Fail,
                summary: "cargo test: 1 failing".into(),
                failures: vec!["types::round_trip".into()],
            },
            EventPayload::PlanCreated {
                plan: crate::core::plan::Plan {
                    version: 1,
                    name: "p".to_string(),
                    items: vec![],
                },
            },
            EventPayload::PlanItem {
                item_id: "a".to_string(),
                status: crate::core::plan::PlanItemStatus::Started,
                run_id: None,
                gate_id: None,
            },
            EventPayload::RunDelegated {
                delegated_run_id: RunId::new_v4(),
                role: Some(RoleName::Builder),
                target: DelegatedTarget::Worker,
            },
            EventPayload::AuditPrepared { snapshot: crate::workspace::git::audit::Snapshot {
                version: 1, selection: crate::workspace::git::audit::Selection { base_ref: "main".into(),
                    target: crate::workspace::git::audit::Target::WorkingTree {} },
                base_sha: "a".repeat(40), tree_sha: "b".repeat(40), worktree: "/repo/audit".into(),
                diff_path: "/state/audit.diff".into(), diff_hash: "c".repeat(64), files: vec!["a.txt".into()],
                manifest_path: "/state/tracked-files.json".into(), manifest_hash: "e".repeat(64), source_hash: "d".repeat(64),
            } },
            EventPayload::AuditChecked { check: AuditCheck { attempt_id: attempt, role: RoleName::Verifier,
                diff_hash: "c".repeat(64), outcome: AuditOutcome::NothingToRun, summary: "No test command".into() } },
            EventPayload::SecurityVerdict { attempt_id: attempt, builder_attempt_id: attempt,
                verdict: Verdict::Pass, findings: vec![], diff_hash: "c".repeat(64) },
            EventPayload::RunRecovered { recovery: crate::core::recovery::Record {
                request: crate::core::recovery::Request { run_id: RunId::new_v4(), source_agent_id: agent,
                    expected_seq: 10, request_id: uuid::Uuid::new_v4(),
                    builder: crate::core::team::Assignment { provider: ProviderName::Codex, model: "gpt-5.5".into(), effort: None },
                    feedback: "Continue from this draft".into() }, agent_id: AgentId::new_v4(),
                by: Actor::Socket { client_name: "acp-mac".into() }, gate_ids: vec![gate],
            } },
        ]
    }

    fn event(payload: EventPayload) -> Event {
        Event {
            base: EventBase {
                seq: 7,
                ts: "2026-08-22T22:00:00.000Z".into(),
                run_id: RunId::new_v4(),
            },
            payload,
        }
    }

    /// B1: the sandbox requirement is `writes || verifier`, and nothing else. A verifier is
    /// sandboxed without being a writer; every other role follows its `writes` flag.
    #[test]
    fn requires_sandbox_is_writes_or_verifier() {
        let spec = |role, writes| RoleSpec {
            role,
            provider: ProviderName::Claude,
            models: vec!["haiku".into()],
            default_model: "haiku".into(),
            writes,
            prompt_file: None,
            prompt_sha256: None,
            description: None,
            tools: None,
            sandbox_mode: None,
            max_turns: 1,
            spawn_budget_usd: 1.0,
            result_schema: SchemaName::BuildResult,
            allowed_delegations: Vec::new(),
        };
        assert!(spec(RoleName::Builder, true).requires_sandbox());
        assert!(!spec(RoleName::Reviewer, false).requires_sandbox());
        assert!(!spec(RoleName::Lead, false).requires_sandbox());
        assert!(spec(RoleName::Verifier, false).requires_sandbox());
        // Belt-and-braces: a verifier that somehow claimed `writes` stays sandboxed.
        assert!(spec(RoleName::Verifier, true).requires_sandbox());
    }

    #[test]
    fn event_kinds_const_lists_every_variant_in_design_order() {
        let tags: Vec<&str> = all_payloads().iter().map(kind_tag).collect();
        assert_eq!(tags, EVENT_KINDS);
        assert_eq!(EVENT_KINDS.first(), Some(&"run.created"));
        // The design's 23 kinds end at `integrate.committed`; later kinds stay append-only.
        assert_eq!(EVENT_KINDS[22], "integrate.committed");
        assert_eq!(EVENT_KINDS[23], "loop.dispatched");
        assert_eq!(EVENT_KINDS[24], "agent.message");
        assert_eq!(EVENT_KINDS[28], "run.delegated");
        assert_eq!(EVENT_KINDS.last(), Some(&"run.recovered"));
        assert_eq!(EVENT_KINDS.len(), 33);
    }

    #[test]
    fn serialized_kind_tag_matches_the_design_list() {
        for payload in all_payloads() {
            let json = serde_json::to_value(&payload).expect("serialize payload");
            let kind = json["kind"].as_str().expect("kind tag is a string");
            assert_eq!(kind, kind_tag(&payload));
            assert!(
                EVENT_KINDS.contains(&kind),
                "{kind} missing from EVENT_KINDS"
            );
        }
    }

    #[test]
    fn every_event_round_trips_through_serde_json() {
        for payload in all_payloads() {
            let original = event(payload);
            let json = serde_json::to_string(&original).expect("serialize event");
            let back: Event = serde_json::from_str(&json).expect("deserialize event");
            assert_eq!(back, original);
            assert_eq!(serde_json::to_string(&back).expect("re-serialize"), json);
        }
    }

    #[test]
    fn event_json_is_flat_and_camel_case() {
        let run_id = RunId::new_v4();
        let e = Event {
            base: EventBase {
                seq: 1,
                ts: "2026-08-22T22:00:00.000Z".into(),
                run_id,
            },
            payload: EventPayload::RunCreated {
                execution: None,
                repo_root: PathBuf::from("/repo"),
                state_dir: PathBuf::from("/state"),
                base_ref: "main".into(),
                base_sha: "a".repeat(40),
                task: task(),
                version: 1,
                lead: None,
                team_name: None,
                steps: None,
            },
        };
        let v = serde_json::to_value(&e).expect("serialize");
        assert_eq!(v["seq"], 1);
        assert_eq!(v["runId"], run_id.to_string());
        assert_eq!(v["kind"], "run.created");
        assert_eq!(v["repoRoot"], "/repo");
        assert_eq!(v["stateDir"], "/state");
        assert_eq!(v["baseRef"], "main");
        assert!(v["lead"].is_null(), "None serializes as null, not omitted");
    }

    #[test]
    fn wire_renames_avoid_the_kind_tag() {
        let started = serde_json::to_value(&all_payloads()[8]).expect("serialize");
        assert_eq!(started["kind"], "attempt.started");
        assert_eq!(started["kind2"], "fresh");
        assert_eq!(started["startTime"], "Sat Aug 22 22:00:00 2026");

        let created = serde_json::to_value(&all_payloads()[19]).expect("serialize");
        assert_eq!(created["kind"], "gate.created");
        assert_eq!(created["gkind"], "integrate");
        assert_eq!(created["requestedBy"], "control-plane");
    }

    #[test]
    fn unknown_fields_are_tolerated_on_events() {
        let run_id = RunId::new_v4();
        let json = format!(
            r#"{{"seq":1,"ts":"2026-08-22T22:00:00.000Z","runId":"{run_id}","kind":"run.status","status":"running","reason":null,"futureField":true}}"#
        );
        let e: Event = serde_json::from_str(&json).expect("forward-compatible deserialize");
        assert_eq!(e.base.run_id, run_id);
        assert_eq!(
            e.payload,
            EventPayload::RunStatus_ {
                status: RunStatus::Running,
                reason: None
            }
        );
    }

    #[test]
    fn typed_ids_are_uuid_strings_on_the_wire() {
        let id = GateId::new_v4();
        let json = serde_json::to_string(&id).expect("serialize id");
        assert_eq!(json, format!("\"{id}\""));
        assert_eq!(
            serde_json::from_str::<GateId>(&json).expect("round-trip"),
            id
        );
        assert_eq!(GateId::from_str(&id.to_string()).expect("parse"), id);
        assert!(serde_json::from_str::<GateId>("\"not-a-uuid\"").is_err());
        assert_eq!(GateId::from_uuid(*id.as_uuid()), id);
    }

    #[test]
    fn actor_serializes_as_a_bare_string() {
        assert_eq!(
            serde_json::to_string(&Actor::Mcp).expect("serialize"),
            "\"mcp\""
        );
        assert_eq!(
            serde_json::to_string(&Actor::Socket {
                client_name: "acp-mac".into()
            })
            .expect("serialize"),
            "\"acp-mac\""
        );
        assert_eq!(
            serde_json::from_str::<Actor>("\"mcp\"").expect("deserialize"),
            Actor::Mcp
        );
        assert_eq!(
            serde_json::from_str::<Actor>("\"cli\"").expect("deserialize"),
            Actor::Socket {
                client_name: "cli".into()
            }
        );
    }

    #[test]
    fn wire_literal_booleans_reject_the_wrong_value() {
        assert_eq!(serde_json::to_string(&True).expect("serialize"), "true");
        assert_eq!(serde_json::to_string(&False).expect("serialize"), "false");
        assert!(serde_json::from_str::<True>("true").is_ok());
        assert!(serde_json::from_str::<True>("false").is_err());
        assert!(serde_json::from_str::<False>("true").is_err());
    }

    #[test]
    fn enum_wire_values_are_the_design_strings() {
        let cases = [
            (serde_json::to_value(ProviderName::Codex), "codex"),
            (serde_json::to_value(RoleName::Reviewer), "reviewer"),
            (
                serde_json::to_value(RunStatus::AwaitingGate),
                "awaiting_gate",
            ),
            (
                serde_json::to_value(LoopState::AwaitingGate),
                "awaiting_gate",
            ),
            (serde_json::to_value(AgentStatus::Closed), "closed"),
            (
                serde_json::to_value(AttemptStatus::InvalidOutput),
                "invalid_output",
            ),
            (
                serde_json::to_value(AttemptStatus::SpawnFailed),
                "spawn_failed",
            ),
            (
                serde_json::to_value(ErrorCode::ProviderUnauthenticated),
                "provider_unauthenticated",
            ),
            (serde_json::to_value(GateKind::Integrate), "integrate"),
            (serde_json::to_value(GateStatus::Resolving), "resolving"),
            (
                serde_json::to_value(ViolationKind::DenylistHit),
                "denylist_hit",
            ),
            (serde_json::to_value(Origin::ControlPlane), "control-plane"),
            (serde_json::to_value(AttemptKind::Resume), "resume"),
            (serde_json::to_value(LoopBranch::Lead), "lead"),
            (serde_json::to_value(LoopBranch::Verify), "verify"),
            (serde_json::to_value(Severity::Blocking), "blocking"),
            (
                serde_json::to_value(SandboxMode::WorkspaceWrite),
                "workspace-write",
            ),
            (
                serde_json::to_value(SchemaName::ReviewVerdict),
                "review-verdict",
            ),
            (serde_json::to_value(CostSource::RateTable), "rate-table"),
            (serde_json::to_value(CancelBy::Timeout), "timeout"),
            (serde_json::to_value(Verdict::Pass), "PASS"),
        ];
        for (got, want) in cases {
            assert_eq!(got.expect("serialize enum"), Value::from(want));
        }
        assert!(serde_json::from_value::<RunStatus>(Value::from("awaitingGate")).is_err());
    }

    #[test]
    fn records_round_trip_through_serde_json() {
        let envelope = HandoffEnvelope {
            untrusted: True,
            kind: SchemaName::BuildResult,
            run_id: RunId::new_v4(),
            agent_id: AgentId::new_v4(),
            attempt_id: AttemptId::new_v4(),
            role: RoleName::Builder,
            provider: ProviderName::Claude,
            model: "claude-haiku".into(),
            status: AttemptStatus::Succeeded,
            error: None,
            structured: Some(serde_json::json!({ "status": "succeeded" })),
            structured_valid: true,
            schema: "build-result".into(),
            head: "done".into(),
            head_truncated: false,
            result_path: PathBuf::from("/state/attempts/x/result.txt"),
            stderr_path: PathBuf::from("/state/attempts/x/stderr.log"),
            cost_usd: 0.04,
            run_spend_usd: 0.12,
            violations: vec![],
            session_id: Some("sess-1".into()),
            worktree: Some(PathBuf::from("/repo/.acp/worktrees/r/a")),
            finished_at: "2026-08-22T22:00:00.000Z".into(),
        };
        let json = serde_json::to_value(&envelope).expect("serialize envelope");
        assert_eq!(json["untrusted"], true);
        assert_eq!(json["kind"], "build-result");
        assert_eq!(json["structuredValid"], true);
        assert_eq!(json["runSpendUsd"], 0.12);
        let back: HandoffEnvelope = serde_json::from_value(json).expect("deserialize envelope");
        assert_eq!(back, envelope);

        let round_tripped: Task =
            serde_json::from_value(serde_json::to_value(task()).expect("serialize task"))
                .expect("deserialize task");
        assert_eq!(round_tripped, task());
        assert!(
            serde_json::from_str::<Task>(
                r#"{"id":"a","title":"t","description":"d","files":[],"acceptance":[],"extra":1}"#
            )
            .is_err(),
            "Task is an MCP input: unknown fields are denied"
        );
    }
}
