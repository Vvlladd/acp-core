//! Human gates: creation, resolution and the socket-only approval rule (`impl Core`).
//! Implemented in T28 (`reports/03-design.md` § `src/core/gates.rs`).
//!
//! **Shape of this module vs the design.** The design writes this as an `impl Core` block, but
//! `Core` does not exist until T33. So everything here is a **free function over
//! `&mut Registry` / `&RolesConfig`**, in the design's order and with the design's names:
//! T33 wires them in as thin `impl Core` methods (`self.registry`, `self.roles`) that *call* these
//! functions — it does **not** reimplement them. The `Core` method bodies are one line each:
//!
//! ```text
//! impl Core {
//!     pub fn create_gate(&mut self, run: &RunId, g: NewGate) -> Result<Gate, CoreError> {
//!         gates::create_gate(&mut self.registry, run, g)
//!     }
//!     pub fn begin_resolve(&mut self, id: &GateId, approve: bool, feedback: Option<String>,
//!                          by: Actor) -> Result<ResolveOutcome, CoreError> {
//!         gates::begin_resolve(&mut self.registry, id, approve, feedback, by, &self.roles)
//!     }
//!     // finish_commit, pending_gates, reconcile_gate — same.
//! }
//! ```
//!
//! [`CoreError`] is declared here for the same reason `RolesConfig` is declared in `core::types`:
//! this is the first module that needs it and T33 does not own this file. T33 re-exports it
//! (`pub use crate::core::gates::CoreError;`) — the [`CoreError::Unavailable`] variant exists for
//! its `CoreHandle` methods, which have no other way to say "the actor is gone".
//!
//! The two invariants this module exists to hold:
//!
//! - **Approval authority (S2)** — every resolution goes through [`policy::check_gate_resolve`]
//!   *before* anything is written, so an MCP `resolve_gate{approve:true}` on an `integrate` gate is
//!   rejected `AgentApproveNotAllowed` (unless `gates.allowAgentApprove`) with **no** side effects.
//!   A denial from either door is always allowed, and `Actor::Socket{..}` — `acp gate approve`, the
//!   menu-bar app — may always approve.
//! - **Exactly-once commit** — `gate.resolving` is appended **before any git call**, and it is the
//!   last fallible thing [`begin_resolve`] does before handing the caller a [`CommitPlan`]. A
//!   second resolution from either door then observes a non-`Pending` gate and returns
//!   [`GateResolution::AlreadyResolved`] *while the first commit is still running* — one commit,
//!   one `integrate.committed`, whichever door raced.
//!
//! **The commit path reads the payload file exactly once**, by [`begin_resolve`], and only while
//! the gate is still `pending`. What the commit needs — worktree, subject, files — is copied into the
//! `gate.resolving` event as a [`CommitTarget`] before any git call, and every later step reads it
//! back from the projection. So a `<gateId>.payload.json` deleted or corrupted *after* the window
//! opened (an `acp gc`, a partial restore) cannot strand a commit that exists in the repository
//! with no event recording it, and cannot stop reconciliation finding it by trailer. A denied
//! gate's downstream advisory context may read the payload again to attribute feedback to its
//! exact frozen diff; a missing or invalid payload simply carries no such context and never
//! affects commit reconciliation.
//!
//! Slow I/O is deliberately **not** done here: [`begin_resolve`] returns the [`CommitPlan`] and the
//! actor runs [`run_commit`] in a helper task, posting `Command::CommitDone` back into the mailbox
//! (design, decision 11 — a mailbox turn never awaits). [`reconcile_gate`] is the one exception: it
//! runs once per `resolving` gate at open time, off the mailbox's hot path.
//!
//! **Must NOT know**: providers, processes. There is no inbox directory and no staleness rule
//! (design, Revision 23).

use std::fs::{DirBuilder, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::task::JoinHandle;

use crate::core::policy::{self, PolicyError};
use crate::core::registry::{Registry, RegistryError};
use crate::core::types::{
    Actor, AgentStatus, AttemptId, AttemptStatus, CommitTarget, EventPayload, ExternalCommandStatus,
    ExternalVerificationEvidence, Gate, GateId, GateKind, GateStatus, Origin, RolesConfig, RunId,
    RunStatus, VerifyStatus,
};
use crate::workspace::git::{self, CommitMessage, GitError, MAX_SUBJECT_BYTES};

/// The trailer that binds a commit to the gate that authorized it. This is what makes a retried
/// commit idempotent: [`reconcile_gate`] looks the sha back up by it after a crash.
pub const TRAILER_GATE_ID: &str = "Acp-Gate-Id";

/// The trailer that binds a commit to its run.
pub const TRAILER_RUN_ID: &str = "Acp-Run-Id";

/// `<state_dir>/runs/` — mirrors `registry`'s private constant; the two paths must agree.
const RUNS_DIR: &str = "runs";

/// `<state_dir>/runs/<runId>/gates/` — one payload file per gate (design, § On-disk layout).
const GATES_DIR: &str = "gates";
const MAX_GATE_PAYLOAD_BYTES: u64 = 1_048_576;

/// Subject prefix of every commit the control plane makes, so `git log` shows at a glance which
/// commits are the daemon's.
const SUBJECT_PREFIX: &str = "acp: ";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every way a `Core` operation fails. Declared here (see the module comment) and re-exported by
/// `core/mod.rs` in T33.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("{reason}")]
    Lifecycle { code: &'static str, reason: String },
    /// No gate with this id in the projection — a stale id from a door, or a different state dir.
    #[error("unknown gate {0}")]
    UnknownGate(GateId),

    /// No run with this id in the projection.
    #[error("unknown run {0}")]
    UnknownRun(RunId),

    /// A policy check said no. The [`PolicyCode`](crate::core::policy::PolicyCode) inside is what
    /// the door reports and what `audit.jsonl` records.
    #[error(transparent)]
    Policy(#[from] PolicyError),

    /// The event log could not be written. Nothing downstream may be assumed to have happened.
    #[error(transparent)]
    Registry(#[from] RegistryError),

    /// A git call failed outside the commit helper (the helper's failure arrives as the `Err` half
    /// of [`finish_commit`]'s argument instead).
    #[error(transparent)]
    Git(#[from] GitError),

    /// The gate's `<gateId>.payload.json` could not be written, read back or parsed.
    #[error("gate {gate} payload {path}: {problem}")]
    GatePayload {
        gate: GateId,
        path: PathBuf,
        problem: String,
    },

    /// There is nothing to commit: the gate's payload named no worktree — raised by
    /// [`begin_resolve`] *before* `gate.resolving`, so the gate stays `pending` — or the gate
    /// reached `resolving` with no [`CommitTarget`] recorded, which only a hand-written log does.
    #[error("gate {0} cannot be approved: no worktree to commit")]
    NoWorktree(GateId),

    /// The actor is gone: its mailbox is closed, or it dropped the reply channel. Only `CoreHandle`
    /// (T33) can observe this; no function in this module returns it.
    #[error("the control plane actor is not running")]
    Unavailable,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// How a gate ended up, as reported back through the door that resolved it.
///
/// `AlreadyResolved` is the exactly-once answer: the gate was not `Pending` when this resolution
/// arrived, so nothing was written and nothing was committed.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GateResolution {
    /// `sha` is the integration commit for an `integrate` gate; a `plan` or `escalate` approval
    /// commits nothing and carries `None`.
    Approved {
        #[serde(skip_serializing_if = "Option::is_none")]
        sha: Option<String>,
    },
    Denied {
        feedback: Option<String>,
    },
    AlreadyResolved,
}

/// What [`begin_resolve`] (or [`reconcile_gate`]) decided, and therefore what the caller must do.
#[derive(Debug)]
pub enum ResolveOutcome {
    /// The gate is `resolving` and `gate.resolving` is already on disk. Run [`run_commit`] with
    /// this plan in a helper task and post the result back through [`finish_commit`].
    Commit(Box<CommitPlan>),
    /// Nothing left to do — the gate is terminal, or just became terminal in this call. Answer the
    /// door with this resolution.
    Settled(GateResolution),
}

/// Everything the commit helper needs, built before `gate.resolving` was appended so that a missing
/// worktree or an unreadable payload can still leave the gate `pending`.
///
/// `target` is the durable half — it is what goes into `gate.resolving` and comes back out of the
/// projection — and `message` is derived from it plus the gate's summary.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CommitPlan {
    pub gate_id: GateId,
    pub run_id: RunId,
    /// The worktree, subject and files, exactly as recorded on the gate.
    pub target: CommitTarget,
    /// `message.title` is [`CommitTarget::subject`], pre-sanitized (one line, no control
    /// characters, ≤ [`MAX_SUBJECT_BYTES`]) so `git.rs`'s own sanitizer is a no-op on it and the
    /// `integrate.committed{subject}` event names the real commit subject.
    pub message: CommitMessage,
}

impl CommitPlan {
    /// The two identity trailers, owned because
    /// [`commit_all`](crate::workspace::git::commit_all) borrows them as `&str`.
    #[must_use]
    pub fn trailers(&self) -> [(String, String); 2] {
        [
            (TRAILER_GATE_ID.to_string(), self.gate_id.to_string()),
            (TRAILER_RUN_ID.to_string(), self.run_id.to_string()),
        ]
    }
}

/// What the gate is asking about, written to `<state_dir>/runs/<runId>/gates/<gateId>.payload.json`
/// (design, § Data Flow step 16). Every field is optional on read-back so an older payload — or one
/// from a gate kind that has no worktree — still loads.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct GatePayload {
    /// The worktree an approval commits. Required to approve; absent for a gate that only asks a
    /// question (`escalate`).
    pub worktree: Option<PathBuf>,
    pub diff_path: Option<PathBuf>,
    /// sha256 of the diff at `diff_path` — the hash the reviewer echoed (Rev 25), and the one an
    /// approval re-computes against the worktree before it commits.
    pub diff_hash: Option<String>,
    pub files: Vec<String>,
    pub build_result_path: Option<PathBuf>,
    pub verdict_path: Option<PathBuf>,
    pub pre_sha: Option<String>,
    pub spend_usd: f64,
    /// The line the integrate commit's subject is made from — the task (`<id>: <title>`), so
    /// the summary's first line (a review sentence, loud by design) becomes the body instead of a
    /// 72-byte subject that pushes the task out. Absent on payloads written before it existed,
    /// which keep deriving the subject from the summary.
    pub subject: Option<String>,
    /// Present only on a socket-created `external-verification` gate.
    pub external_verification: Option<ExternalVerificationEvidence>,
}

/// A denied integration gate whose human feedback applies to a later builder attempt in the same
/// run. This is prompt context only: it carries no approval or publishing authority.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct IntegrationGateRepair {
    pub gate_id: GateId,
    pub builder_attempt_id: AttemptId,
    pub denied_diff_hash: String,
    pub feedback: String,
    pub resolved_by: Actor,
}

/// Selects the newest attributable human integration-gate repair before `builder_attempt`.
///
/// Selection is entirely from the run's durable log and gate payloads. Matching the payload's
/// diff path and hash back to `diff.frozen` keeps feedback tied to the exact gate evidence it
/// amended; requiring the later attempt's `attempt.started` sequence keeps feedback from a
/// different run, a future denial, or an unrelated pending gate out. MCP denials remain advisory:
/// they are skipped while selecting the newest socket-resolved denial and cannot supersede its
/// repair criterion. Once selected, however, a newer socket denial with absent feedback or broken
/// binding supersedes an older socket denial and yields no criterion rather than reviving stale
/// instructions.
pub(crate) fn current_integration_repair(
    reg: &Registry,
    run: &RunId,
    builder_attempt: AttemptId,
) -> Option<IntegrationGateRepair> {
    // These are sparse replay-built indexes rather than a suffix of the run log: normal progress
    // noise cannot age out an applicable human criterion, and reconstruction does no actor-thread
    // file I/O or unbounded event cloning.
    let started_seq = reg.attempt_started_seq(run, &builder_attempt)?;
    let (_gate_seq, gate_id, feedback, target) =
        reg.human_integration_denial_before(run, started_seq)?;
    let gate = reg.gate(&gate_id)?;
    let feedback = feedback.filter(|text| !text.trim().is_empty())?;
    let resolved_by = gate.resolved_by.clone()?;
    let target = target?;
    let builder_attempt_id = target.builder_attempt_id;
    let denied_builder = reg.agent(&reg.attempt(&builder_attempt_id)?.agent_id)?;
    let current_builder = reg.agent(&reg.attempt(&builder_attempt)?.agent_id)?;
    if denied_builder.run_id != *run
        || current_builder.run_id != *run
        || denied_builder.lineage_id != Some(target.lineage_id)
        || current_builder.lineage_id != Some(target.lineage_id)
    {
        return None;
    }
    Some(IntegrationGateRepair {
        gate_id,
        builder_attempt_id,
        denied_diff_hash: target.diff_hash.clone(),
        feedback: feedback.to_owned(),
        resolved_by,
    })
}

/// A gate to create. The id, the payload path and the timestamps are the control plane's to mint.
#[derive(Clone, PartialEq, Debug)]
pub struct NewGate {
    pub kind: GateKind,
    pub summary: String,
    pub requested_by: Origin,
    pub payload: GatePayload,
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Writes the gate's payload, then appends `gate.created`, and returns the projected [`Gate`].
///
/// The payload file is written **before** the event that names it, so no subscriber can be told
/// about a `payloadPath` that is not yet on disk.
///
/// # Errors
/// [`CoreError::UnknownRun`] for a run the projection has never seen (`gate.created` is dropped by
/// the reducer for an unknown run, so this would otherwise silently do nothing);
/// [`CoreError::GatePayload`] if the payload cannot be written; [`CoreError::Registry`] if the
/// event cannot be appended.
pub fn create_gate(reg: &mut Registry, run: &RunId, g: NewGate) -> Result<Gate, CoreError> {
    create_gate_inner(reg, run, g, false)
}

/// Core-actor-only half of the socket host-evidence flow. The caller has captured `inventory_hash`
/// while retaining the worktree lock through this append sequence.
#[doc(hidden)]
pub fn create_external_verification_gate(
    reg: &mut Registry,
    run: &RunId,
    g: NewGate,
    inventory_hash: &str,
) -> Result<Gate, CoreError> {
    let evidence = g.payload.external_verification.as_ref().ok_or_else(|| {
        policy::PolicyError::new(policy::PolicyCode::DelegationNotAllowed, "external-verification gate has no evidence record")
    })?;
    if g.kind != GateKind::ExternalVerification || evidence.source_inventory_after_hash != inventory_hash {
        return Err(policy::PolicyError::new(
            policy::PolicyCode::DelegationNotAllowed,
            "external verification does not match the daemon-captured inventory",
        ).into());
    }
    create_gate_inner(reg, run, g, true)
}

fn create_gate_inner(
    reg: &mut Registry,
    run: &RunId,
    g: NewGate,
    allow_external: bool,
) -> Result<Gate, CoreError> {
    if reg.run(run).is_none() {
        return Err(CoreError::UnknownRun(*run));
    }

    if g.kind == GateKind::Integrate && reg.run(run).and_then(|r| r.execution.as_ref())
        .is_some_and(|e| e.mode != crate::core::types::RunMode::Build) {
        return Err(policy::PolicyError::new(policy::PolicyCode::DelegationNotAllowed,
            "planning and audit tasks cannot create an integration gate").into());
    }
    if g.kind == GateKind::ExternalVerification {
        if !allow_external {
            return Err(policy::PolicyError::new(
                policy::PolicyCode::AgentApproveNotAllowed,
                "external verification must be prepared by the socket-only host evidence route",
            ).into());
        }
        validate_external_verification(reg, run, &g.payload, None)?;
    } else if g.payload.external_verification.is_some() {
        return Err(policy::PolicyError::new(
            policy::PolicyCode::DelegationNotAllowed,
            "external verification evidence requires an external-verification gate",
        ).into());
    }
    let gate_id = GateId::new_v4();
    let payload_path = payload_path(reg.state_dir(), run, &gate_id);
    write_payload(&payload_path, gate_id, &g.payload)?;

    if let Some(evidence) = g.payload.external_verification.clone() {
        // This event is the authority for approval. It is appended before the gate is exposed,
        // and contains the inventory identity the daemon checked during socket submission.
        reg.append(
            run,
            EventPayload::ExternalVerificationPrepared {
                gate_id,
                daemon_captured_inventory_hash: evidence.source_inventory_after_hash.clone(),
                evidence,
            },
        )?;
    }

    let repair_binding = (g.kind == GateKind::Integrate).then(|| {
        reg.gate_repair_binding(run, g.payload.diff_path.as_deref(), g.payload.diff_hash.as_deref())
    });
    reg.append(
        run,
        EventPayload::GateCreated {
            gate_id,
            gate_kind: g.kind,
            summary: g.summary,
            payload_path,
            repair_binding,
            requested_by: g.requested_by,
        },
    )?;

    reg.gate(&gate_id)
        .cloned()
        .ok_or(CoreError::UnknownGate(gate_id))
}

/// Starts resolving a gate: checks S2, then opens the exactly-once window.
///
/// Order matters and is the whole point of the function:
///
/// 1. a gate that is not `Pending` — terminal *or* already `Resolving` — returns
///    [`GateResolution::AlreadyResolved`] having written nothing and run no git;
/// 2. [`policy::check_gate_resolve`] runs next, so a rejection has no side effects at all (S2);
/// 3. an approval's [`CommitPlan`] is built next — reading the payload can still fail here, and the
///    gate is still `pending` when it does;
/// 4. **then** `gate.resolving` is appended. Everything after this point is idempotent-by-trailer,
///    because the commit that follows carries [`TRAILER_GATE_ID`].
///
/// A denial never calls git: `gate.resolving` is appended anyway — it is the *only* event the
/// reducer takes `resolvedBy` and `approve` from, so skipping it would lose who denied the gate —
/// and `gate.resolved{denied}` follows immediately, in the same turn.
///
/// # Errors
/// [`CoreError::UnknownGate`], [`CoreError::Policy`] (`AgentApproveNotAllowed`),
/// [`CoreError::NoWorktree`] or [`CoreError::GatePayload`] for an unapprovable gate, and
/// [`CoreError::Registry`] if an event cannot be appended.
pub fn begin_resolve(
    reg: &mut Registry,
    id: &GateId,
    approve: bool,
    feedback: Option<String>,
    by: Actor,
    cfg: &RolesConfig,
) -> Result<ResolveOutcome, CoreError> {
    begin_resolve_inner(reg, id, approve, feedback, by, cfg, None)
}

/// Only the actor's locked host capture can settle a pending external-evidence approval.
/// The inventory is computed by ACP, never taken from an approval request on either door.
pub fn approve_external_with_inventory(
    reg: &mut Registry, id: &GateId, by: Actor, cfg: &RolesConfig, inventory: &str,
    _guard: &tokio::sync::OwnedMutexGuard<()>,
) -> Result<ResolveOutcome, CoreError> {
    if reg.gate(id).ok_or(CoreError::UnknownGate(*id))?.kind != GateKind::ExternalVerification {
        return Err(policy::PolicyError::new(policy::PolicyCode::DelegationNotAllowed,
            "a host inventory can settle only an external-verification gate").into());
    }
    begin_resolve_inner(reg, id, true, None, by, cfg, Some(inventory))
}

fn begin_resolve_inner(
    reg: &mut Registry, id: &GateId, approve: bool, feedback: Option<String>, by: Actor,
    cfg: &RolesConfig, captured_inventory: Option<&str>,
) -> Result<ResolveOutcome, CoreError> {
    let gate = reg.gate(id).cloned().ok_or(CoreError::UnknownGate(*id))?;

    // (1) The exactly-once boundary, read side. `Resolving` counts: the first commit may still be
    // in flight, and its trailer is what makes the eventual retry idempotent — not a second call.
    if gate.status != GateStatus::Pending {
        return Ok(ResolveOutcome::Settled(GateResolution::AlreadyResolved));
    }

    if approve && !matches!(gate.kind, GateKind::Plan | GateKind::ExternalVerification) && reg.run(&gate.run_id).and_then(|r| r.execution.as_ref())
        .is_some_and(|e| e.mode != crate::core::types::RunMode::Build) {
        return Err(policy::PolicyError::new(policy::PolicyCode::DelegationNotAllowed,
            "planning and audit tasks cannot integrate changes").into());
    }

    // (2) S2. Pure, and before any write: a rejection leaves no trace in the run log.
    policy::check_gate_resolve(&gate, approve, &by, cfg)?;

    let accepted_external = if approve && gate.kind == GateKind::ExternalVerification {
        if matches!(by, Actor::Mcp) {
            return Err(policy::PolicyError::new(
                policy::PolicyCode::AgentApproveNotAllowed,
                "external verification is a socket-only human action",
            ).into());
        }
        let payload = read_payload(&gate.payload_path, gate.gate_id)?;
        validate_external_verification(reg, &gate.run_id, &payload, Some(gate.gate_id))?;
        let submitted = payload.external_verification.ok_or_else(|| {
            policy::PolicyError::new(policy::PolicyCode::DelegationNotAllowed,
                "external-verification gate has no evidence record")
        })?;
        let prepared = prepared_external_verification(reg, &gate.run_id, gate.gate_id)
            .ok_or_else(|| policy::PolicyError::new(
                policy::PolicyCode::DelegationNotAllowed,
                "external-verification gate has no immutable prepared evidence",
            ))?;
        if prepared != submitted {
            return Err(policy::PolicyError::new(
                policy::PolicyCode::DelegationNotAllowed,
                "external-verification payload diverges from immutable prepared evidence",
            ).into());
        }
        if captured_inventory != Some(prepared.source_inventory_after_hash.as_str()) {
            return Err(policy::PolicyError::new(policy::PolicyCode::DelegationNotAllowed,
                "external approval requires a fresh locked checkout inventory matching the prepared evidence").into());
        }
        Some(prepared)
    } else { None };

    // (3) The one place the payload file is read, while the gate is still `pending`. A `plan`
    // approval commits nothing — it answers a question — so it alone skips the payload read.
    // An `escalate` approval still goes through `plan_from_payload` and is refused there for
    // its missing worktree: that refusal is pinned behavior (an escalation is answered with
    // deny-and-feedback, and "approving" one has no defined meaning).
    let plan = if approve && !matches!(gate.kind, GateKind::Plan | GateKind::ExternalVerification) {
        Some(Box::new(plan_from_payload(&gate)?))
    } else {
        None
    };

    // A manually requested gate must not bypass a selected security check. Bind the recorded
    // PASS to the same builder attempt/artifact as this gate before gate.resolving is durable.
    if let Some(plan) = &plan {
        if reg.run(&gate.run_id).and_then(|r| r.execution.as_ref()).is_some_and(|e| e.steps.security) {
            let builder_attempt = reg.events(&gate.run_id, None, usize::MAX).iter().rev().find_map(|e| match &e.payload {
                EventPayload::DiffFrozen { attempt_id, diff_path, diff_hash, .. }
                    if Some(diff_path) == plan.target.diff_path.as_ref()
                        && Some(diff_hash) == plan.target.diff_hash.as_ref() => Some(*attempt_id),
                _ => None,
            });
            let passed = builder_attempt.zip(plan.target.diff_hash.as_deref()).and_then(|(attempt, hash)| {
                if !crate::core::r#loop::security::predecessors_passed(reg, &gate.run_id, attempt, hash) { return None; }
                crate::core::r#loop::security::passed_attempt(reg, &gate.run_id, attempt, hash)
            });
            if passed.is_none() {
                return Err(policy::PolicyError::new(policy::PolicyCode::DelegationNotAllowed,
                    "the selected security review has not passed for this gate's frozen diff").into());
            }
        }
    }

    // (4) Write-then-act. Nothing above this line has touched the log; nothing below it calls git.
    //     The target rides along, so nothing after this point needs the payload file again.
    reg.append(
        &gate.run_id,
        EventPayload::GateResolving {
            gate_id: gate.gate_id,
            approve,
            feedback: feedback.clone(),
            by,
            commit: plan.as_ref().map(|p| p.target.clone()),
            external_verification: accepted_external,
        },
    )?;

    match (plan, approve) {
        (Some(plan), _) => Ok(ResolveOutcome::Commit(plan)),
        (None, true) => {
            // A commit-less approval settles in the same call. The window between its two
            // appends is real — a crash there leaves the gate `resolving` — and is closed by
            // `reconcile_gate`'s commit-less arm, not by `finish_commit`.
            resolve_approved_without_commit(reg, &gate)?;
            Ok(ResolveOutcome::Settled(GateResolution::Approved {
                sha: None,
            }))
        }
        (None, false) => {
            resolve_denied(reg, &gate, feedback.clone())?;
            Ok(ResolveOutcome::Settled(GateResolution::Denied { feedback }))
        }
    }
}

/// Returns only the append-only evidence accepted for an approved gate. The mutable gate payload
/// is deliberately not consulted after approval.
pub(crate) fn accepted_external_evidence(
    reg: &Registry,
    run: &RunId,
    builder_attempt: crate::core::types::AttemptId,
    diff_hash: &str,
) -> Option<ExternalVerificationEvidence> {
    reg.events(run, None, usize::MAX).iter().rev().find_map(|event| match &event.payload {
        EventPayload::GateResolving { gate_id, external_verification: Some(evidence), .. }
            if evidence.builder_attempt_id == builder_attempt
                && evidence.diff_hash == diff_hash
                && evidence.validate_attestation().is_ok()
                && reg.gate(gate_id).is_some_and(|gate| gate.status == GateStatus::Approved) =>
        {
            Some(evidence.clone())
        }
        _ => None,
    })
}

/// Appends the `gate.resolved{approved}` half of a commit-less approval (`plan`/`escalate`).
fn resolve_approved_without_commit(reg: &mut Registry, gate: &Gate) -> Result<(), CoreError> {
    reg.append(
        &gate.run_id,
        EventPayload::GateResolved {
            gate_id: gate.gate_id,
            status: GateStatus::Approved,
            sha: None,
            feedback: None,
        },
    )?;
    Ok(())
}

/// Closes the window [`begin_resolve`] opened, from `Command::CommitDone`.
///
/// `Ok(sha)` → `integrate.committed` then `gate.resolved{approved, sha}`, in that order: the commit
/// is a fact about the repository and is recorded before the gate's own verdict, so a log truncated
/// between the two still names the sha that exists.
///
/// `Err(e)` → the gate is left `resolving` and the run is blocked with the reason. That is the
/// [`GitError::Timeout`] case: a human retries, and because the failed attempt may in fact have
/// committed, [`reconcile_gate`] resolves the ambiguity by trailer rather than by guessing.
///
/// Returns the resolution to hand to `on_gate_resolved`, or `None` when the run was blocked
/// instead. (The design writes this as `-> ()`; the actor needs the value, and a `Core` wrapper is
/// free to drop it.)
///
/// # Errors
/// [`CoreError::UnknownGate`], [`CoreError::GatePayload`] / [`CoreError::NoWorktree`] if the
/// payload no longer describes a committable gate, or [`CoreError::Registry`].
pub fn finish_commit(
    reg: &mut Registry,
    id: &GateId,
    result: Result<String, GitError>,
) -> Result<Option<GateResolution>, CoreError> {
    let gate = reg.gate(id).cloned().ok_or(CoreError::UnknownGate(*id))?;

    match result {
        Ok(sha) => {
            let target = commit_target(&gate)?;
            reg.append(
                &gate.run_id,
                EventPayload::IntegrateCommitted {
                    gate_id: gate.gate_id,
                    worktree: target.worktree,
                    sha: sha.clone(),
                    subject: target.subject,
                    files: target.files,
                },
            )?;
            reg.append(
                &gate.run_id,
                EventPayload::GateResolved {
                    gate_id: gate.gate_id,
                    status: GateStatus::Approved,
                    sha: Some(sha.clone()),
                    feedback: None,
                },
            )?;
            Ok(Some(GateResolution::Approved { sha: Some(sha) }))
        }
        Err(err) => {
            reg.append(
                &gate.run_id,
                EventPayload::RunStatus_ {
                    status: RunStatus::Blocked,
                    reason: Some(format!("gate {} commit failed: {err}", gate.gate_id)),
                },
            )?;
            Ok(None)
        }
    }
}

/// Reconciles one gate left `resolving` by a crash, at Registry-open or first-use time.
///
/// The trailer is the arbiter: `git log --all --grep='^Acp-Gate-Id: <gateId>$'` either finds the
/// commit the lost helper made — finish as integrated with that sha, **no second commit** — or it
/// does not, in which case the caller is handed the [`CommitPlan`] again and the commit is retried.
/// A denial caught inside the two-event window in [`begin_resolve`] is simply finished.
///
/// A pre-change `gate.resolving` — written before [`CommitTarget`] existed, so carrying none — is
/// **healed** rather than refused: the target is rebuilt from the payload file if it is still
/// there and re-appended as a repair `gate.resolving`, so the projection is whole from then on. If
/// even that is impossible the run is blocked with a reason instead of erroring, because a human
/// can still find the commit by its trailer.
///
/// Returns `None` when nothing was reconciled — the gate did not need it, or it could not be
/// reconciled and the run was blocked. Either way a caller can sweep every gate without aborting.
///
/// # Errors
/// [`CoreError::UnknownGate`], [`CoreError::Git`] if the lookup itself fails, or
/// [`CoreError::Registry`].
pub async fn reconcile_gate(
    reg: &mut Registry,
    id: &GateId,
) -> Result<Option<ResolveOutcome>, CoreError> {
    let gate = reg.gate(id).cloned().ok_or(CoreError::UnknownGate(*id))?;
    if gate.status != GateStatus::Resolving {
        return Ok(None);
    }

    // `approve` is recorded by `gate.resolving`; a gate that reached `Resolving` without it is a
    // hand-written log, and refusing to commit on a missing intent is the fail-closed reading.
    if gate.approve != Some(true) {
        let feedback = gate.feedback.clone();
        resolve_denied(reg, &gate, feedback.clone())?;
        return Ok(Some(ResolveOutcome::Settled(GateResolution::Denied {
            feedback,
        })));
    }

    // A commit-less kind caught between its two appends (T75-T79 review, finding 2): nothing was
    // ever going to be committed, so the approval is simply finished. Without this arm the heal
    // path below would demand the worktree a `plan` gate never had and block the run for ever.
    // `commit.is_none()` is load-bearing (round-2 N1): `gate.commit` is the durable record that a
    // commit was *intended*, and a gate carrying one — whatever its kind ever becomes — must go
    // through the trailer lookup below, never be waved through as approved-without-commit.
    if gate.kind != GateKind::Integrate && gate.commit.is_none() {
        resolve_approved_without_commit(reg, &gate)?;
        return Ok(Some(ResolveOutcome::Settled(GateResolution::Approved {
            sha: None,
        })));
    }

    // From the projection, never from the payload file — except for one case: a `gate.resolving`
    // written before `commit` existed carries none, and erroring out here would strand the gate
    // forever with a possible unrecorded commit behind it. So heal it first, then proceed exactly
    // as if it had been there all along.
    let target = match gate.commit.clone() {
        Some(target) => target,
        None => match heal_commit_target(reg, &gate)? {
            Some(target) => target,
            None => {
                // Neither a recorded target nor a payload to rebuild one from: this gate cannot be
                // reconciled by the daemon. Blocking is the honest answer — a human can find the
                // commit by its trailer and finish by hand — and it is not an `Err`, because a
                // sweep over every gate must not abort on the one it cannot fix.
                reg.append(
                    &gate.run_id,
                    EventPayload::RunStatus_ {
                        status: RunStatus::Blocked,
                        reason: Some(format!(
                            "gate {} resolving without commit target",
                            gate.gate_id
                        )),
                    },
                )?;
                return Ok(None);
            }
        },
    };

    let plan = plan(&gate, target);
    match git::find_commit_by_trailer(
        &plan.target.worktree,
        TRAILER_GATE_ID,
        &gate.gate_id.to_string(),
    )
    .await?
    {
        Some(sha) => {
            let resolution = finish_commit(reg, id, Ok(sha))?;
            Ok(resolution.map(ResolveOutcome::Settled))
        }
        None => Ok(Some(ResolveOutcome::Commit(Box::new(plan)))),
    }
}

/// Every gate still awaiting a human, oldest first — the whole state dir, or one run.
///
/// Ordered by `(createdAt, gateId)` rather than by `HashMap` iteration, so two processes replaying
/// the same log list them identically.
#[must_use]
pub fn pending_gates<'a>(reg: &'a Registry, run: Option<&RunId>) -> Vec<&'a Gate> {
    let mut gates: Vec<&Gate> = reg
        .state()
        .gates
        .values()
        .filter(|g| g.status == GateStatus::Pending)
        .filter(|g| run.is_none_or(|r| g.run_id == *r))
        .collect();
    gates.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.gate_id.to_string().cmp(&b.gate_id.to_string()))
    });
    gates
}

/// Runs the integrate commit for `plan`, and only if the index it is about to commit **is** the diff
/// a reviewer passed.
///
/// This is the whole git side of the gate path, and it runs off the actor in the commit helper. The
/// order is the security property (Codex review of T35, round 2, finding 1):
///
/// 1. the target names a reviewed diff at all — an unbindable gate never commits;
/// 2. HEAD is still the commit that diff was taken against;
/// 3. **the index is empty**, so nothing already staged can ride along;
/// 4. the reviewed paths are staged, and nothing else is;
/// 5. the **staged** content is re-frozen by the same rules the reviewer's copy was, and hashed —
///    if it does not match, nothing is committed;
/// 6. `git commit` writes that index, with no staging of its own.
///
/// Verifying the worktree and then committing the index would leave a window between the two; here
/// the object that is measured in (5) is the object that is written in (6), and `lock` — one mutex
/// per worktree, held across all six steps — keeps a second approval or a retry out of that
/// worktree while it happens.
///
/// A refusal unstages what it staged: the worktree belongs to a human, and a decision not to commit
/// should leave no trace in their index.
///
/// The lock is taken **owned** so that it can outlive this future: an interrupted approval unstages
/// from a `Drop`, and that cleanup has to hold the worktree too (see [`StagedPaths`]).
///
/// # Errors
/// [`GitError::Failed`] with `op: "verify_frozen_diff"` or `op: "verify_index"` for a refusal, and
/// whatever `commit_staged` returns otherwise — [`finish_commit`] turns any of them into
/// `run.status{blocked}`.
pub async fn run_commit(plan: &CommitPlan, lock: Arc<Mutex<()>>) -> Result<String, GitError> {
    let serialized = lock.lock_owned().await;
    let target = &plan.target;

    let refused = |message: String| GitError::Failed {
        op: "verify_frozen_diff",
        status: "refused".to_string(),
        message,
    };
    let (Some(expected), Some(pre_sha), Some(diff_path)) = (
        target.diff_hash.as_deref(),
        target.pre_sha.as_deref(),
        target.diff_path.as_deref(),
    ) else {
        return Err(refused(
            "this gate records no reviewed diff, so nothing can be committed under its approval"
                .to_string(),
        ));
    };

    let head = git::head_sha(&target.worktree).await?;
    if head != pre_sha {
        return Err(refused(format!(
            "HEAD moved since review: expected {pre_sha} got {head}"
        )));
    }
    git::assert_index_clean(&target.worktree).await?;

    // Armed **before** the first `git add` and disarmed only by a commit: whatever this helper
    // stages, it takes back on every way out — a refusal, an error, or the future being dropped
    // mid-staging by a cancelled task (round-3 review, finding 3). It takes the worktree lock with
    // it, so the cleanup runs inside the same exclusion the staging did.
    let mut staged = StagedPaths::arm(&target.worktree, &target.files, serialized);

    // Staging first, through the guard, then the check the staging exists for.
    let verified = match staged.stage().await {
        Ok(()) => staged_matches_review(target, expected, pre_sha, diff_path).await,
        Err(err) => Err(err),
    };
    match verified {
        Ok(()) => {}
        Err(err) => {
            // Unstage first: the discriminator below re-freezes the **worktree**, and a freeze of a
            // worktree with things staged in it is a different document (a staged addition is no
            // longer untracked). With the index clean again the two are comparable.
            staged.unstage_now().await;
            return Err(name_the_disagreement(target, expected, diff_path, err).await);
        }
    }

    let trailers = plan.trailers();
    let borrowed: Vec<(&str, &str)> = trailers
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    match git::commit_staged(
        &target.worktree,
        &plan.message,
        &borrowed,
        pre_sha,
        &target.files,
    )
    .await
    {
        // The commit consumed the index; there is nothing left to take back.
        Ok(sha) => {
            staged.disarm();
            Ok(sha)
        }
        Err(err) => {
            staged.unstage_now().await;
            Err(err)
        }
    }
}

/// The paths one approval staged, and the promise to take them back.
///
/// `Drop` is the cancellation half. Everything before the commit is `await`ed, so the future can be
/// dropped at any of those points — a cancelled task, a `select!` losing a race, a timeout wrapped
/// around the helper — and a dropped future runs no more of its own code. Without this the index
/// would be left holding the reviewed paths, which is exactly the state
/// [`git::assert_index_clean`] refuses, and the gate would be unable to commit for ever.
///
/// The normal paths call [`StagedPaths::unstage_now`] instead, which does the same work `await`ed
/// and in order — still inside the caller's per-worktree lock, so it cannot interleave with the
/// next approval. `Drop` cannot await, so it hands the cleanup to the runtime and says so.
///
/// **The guard owns the worktree lock**, and hands it to that spawned cleanup. Releasing the lock
/// when the future is dropped and unstaging afterwards left the one moment the lock exists for
/// unprotected: the next approval could take the worktree, pass `assert_index_clean`, stage its own
/// paths, and then have this cleanup `git reset` them out from under it (round-4 review, finding 5).
struct StagedPaths {
    worktree: PathBuf,
    files: Vec<String>,
    armed: bool,
    /// The `git add` this approval started, while it is still running. `None` once it has been
    /// joined — which the ordinary path does before it returns, and the cleanup does before it
    /// unstages.
    staging: Option<JoinHandle<Result<(), GitError>>>,
    /// The per-worktree lock, held for exactly as long as an unstage can still be owed.
    serialized: Option<OwnedMutexGuard<()>>,
}

impl StagedPaths {
    fn arm(worktree: &Path, files: &[String], serialized: OwnedMutexGuard<()>) -> Self {
        Self {
            worktree: worktree.to_path_buf(),
            files: files.to_vec(),
            armed: true,
            staging: None,
            serialized: Some(serialized),
        }
    }

    /// Stages the reviewed paths **in a task of its own**, and waits for that task.
    ///
    /// The spawn is the fix, not an optimization. `git add` is the one call here that *writes* the
    /// index, and it does so under `.git/index.lock`. A `tokio::process::Command` is
    /// `kill_on_drop`, so an approval whose future was dropped mid-staging — a cancelled task, a
    /// lost `select!` — SIGKILLed that `git add` between the lock being taken and the new index
    /// being renamed over the old one. The index survived; the **lock file** did not go away, and a
    /// stale `index.lock` fails every later index write in that worktree, including the cleanup's
    /// own `git reset` and anything the human types (round-4 review, follow-up to finding 5).
    ///
    /// A task is not cancelled by dropping its `JoinHandle`, so the `git add` runs to completion
    /// however the approval ends, and there is no orphaned lock to clean up. That is why this is
    /// preferred over detecting a stale lock and deleting it: `index.lock` records no pid and no
    /// owner, so "stale" can only ever be inferred — and a human running `git add` in their own
    /// worktree at that moment matches every inference available. Not creating the mess is the only
    /// version of this that cannot corrupt someone else's git.
    ///
    /// The handle is awaited **through `&mut`**, so a drop at this `await` leaves it in `self` for
    /// [`Drop`] to wait on. No outer timeout, for the reason `spawn_commit_helper` gives: every git
    /// call inside is individually bounded by `GIT_OP_TIMEOUT` and there is a finite number of them.
    async fn stage(&mut self) -> Result<(), GitError> {
        let (worktree, files) = (self.worktree.clone(), self.files.clone());
        self.staging = Some(tokio::spawn(async move {
            git::stage_paths(&worktree, &files).await
        }));
        let joined = self
            .staging
            .as_mut()
            .expect("the staging task was just stored")
            .await;
        self.staging = None;
        match joined {
            Ok(result) => result,
            // The task panicked or the runtime is going down; either way nothing can be said about
            // what is staged, and the caller's refusal path unstages.
            Err(err) => Err(GitError::Io {
                op: "stage_paths",
                source: io::Error::other(format!("the staging task did not finish: {err}")),
            }),
        }
    }

    /// The ordinary path: put the index back now, before returning. The lock is still held by
    /// `self` throughout, and released when the caller drops it.
    async fn unstage_now(&mut self) {
        self.armed = false;
        if let Err(err) = git::unstage_paths(&self.worktree, &self.files).await {
            tracing::warn!(%err, "the refused approval could not unstage what it staged");
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagedPaths {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let (worktree, files) = (self.worktree.clone(), std::mem::take(&mut self.files));
        let (staging, serialized) = (self.staging.take(), self.serialized.take());
        tracing::warn!(
            worktree = %worktree.display(),
            "an approval was interrupted mid-staging; unstaging what it staged"
        );
        // A `Drop` cannot await, so the cleanup is handed to the runtime — with the worktree lock
        // moved into it, so the exclusion ends when the unstage does and not a moment earlier.
        // Outside a runtime — a test that dropped the future on a bare thread — there is nothing to
        // hand it to, and the index is left as found with the warning above as the record.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                // The `git add` is still running — deliberately, see `StagedPaths::stage` — and it
                // holds `.git/index.lock` while it writes. Unstaging across it would fail on that
                // lock and leave the reviewed paths staged, which is the state that wedges the
                // gate. So the cleanup waits for the staging it is cleaning up after.
                if let Some(staging) = staging {
                    if let Err(err) = staging.await {
                        tracing::warn!(%err, "the interrupted approval's staging did not finish");
                    }
                }
                if let Err(err) = git::unstage_paths(&worktree, &files).await {
                    tracing::warn!(%err, "the interrupted approval could not unstage what it staged");
                }
                drop(serialized);
            });
        }
    }
}

/// Proves the index — which [`StagedPaths::stage`] has just filled with the reviewed paths — holds
/// exactly the reviewed diff.
///
/// The re-freeze is written **beside** the reviewed diff (`<diffPath>.verify`), never over it: the
/// artifact a human opens from the gate payload is the one the reviewer saw.
async fn staged_matches_review(
    target: &CommitTarget,
    expected: &str,
    pre_sha: &str,
    diff_path: &Path,
) -> Result<(), GitError> {
    let refused = |message: String| GitError::Failed {
        op: "verify_frozen_diff",
        status: "refused".to_string(),
        message,
    };

    let out = verify_path(diff_path);
    let staged = git::frozen_diff_cached(&target.worktree, pre_sha, &out).await?;
    if staged.files != target.files {
        return Err(refused(format!(
            "the staged change set is not the reviewed one: expected {:?} got {:?}",
            target.files, staged.files
        )));
    }
    // The freeze hashes the exact bounded bytes as it writes them; no second whole-file read is
    // needed, and this is the digest of the artifact at `out`.
    let got = staged.diff_hash;
    if got != expected {
        return Err(refused(format!(
            "worktree changed since review: expected {expected} got {got}"
        )));
    }
    Ok(())
}

/// Says *why* the staged content did not match, when it can tell cheaply.
///
/// "Worktree changed since review" is the obvious reading of a hash mismatch and usually the right
/// one — but it is a lie when the worktree is untouched and the disagreement is git's own doing: a
/// `.gitattributes` rule or a `filter.*.clean` driver that rewrites bytes on the way into the
/// repository, or a file large enough that the two freezes truncate at different points. Re-freezing
/// the (now unstaged) worktree separates the two cases, costs one diff on a path that has already
/// decided to refuse, and turns a false accusation against the worker into a fact about the
/// repository's configuration.
async fn name_the_disagreement(
    target: &CommitTarget,
    expected: &str,
    diff_path: &Path,
    err: GitError,
) -> GitError {
    let GitError::Failed {
        op: "verify_frozen_diff",
        ref message,
        ..
    } = err
    else {
        return err;
    };
    if !message.starts_with("worktree changed since review") {
        return err;
    }

    let out = worktree_check_path(diff_path);
    let Ok(worktree) = git::frozen_diff(&target.worktree, &out).await else {
        return err;
    };
    // Only claim normalization when the gate's own path set is the whole change set. A target that
    // covers less than the worktree does disagrees for a much simpler reason, and saying
    // "normalization" about it would send a human to their `.gitattributes` for nothing.
    if worktree.files != target.files {
        return err;
    }
    if worktree.diff_hash != expected {
        return err;
    }
    GitError::Failed {
        op: "verify_frozen_diff",
        status: "refused".to_string(),
        message: format!(
            "the worktree still matches the review, but git stores it differently than the \
             review recorded ({message}); check .gitattributes and any filter.*.clean driver \
             for these paths, then re-run the review"
        ),
    }
}

/// `<diffPath>.worktree-check` — the discriminator's own file, beside the reviewed one.
fn worktree_check_path(diff_path: &Path) -> PathBuf {
    let mut name = diff_path.as_os_str().to_os_string();
    name.push(".worktree-check");
    PathBuf::from(name)
}

/// `<diffPath>.verify` — the re-freeze's own file, beside the reviewed one.
fn verify_path(diff_path: &Path) -> PathBuf {
    let mut name = diff_path.as_os_str().to_os_string();
    name.push(".verify");
    PathBuf::from(name)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Appends the `gate.resolved{denied}` half of a denial. Split out because both [`begin_resolve`]
/// and [`reconcile_gate`] end a denial the same way.
fn resolve_denied(
    reg: &mut Registry,
    gate: &Gate,
    feedback: Option<String>,
) -> Result<(), CoreError> {
    reg.append(
        &gate.run_id,
        EventPayload::GateResolved {
            gate_id: gate.gate_id,
            status: GateStatus::Denied,
            sha: None,
            feedback,
        },
    )?;
    Ok(())
}

/// Reads the gate's payload file and turns it into the plan the commit helper runs. Called from
/// [`begin_resolve`] only — after that the plan's [`CommitTarget`] is on the gate.
fn plan_from_payload(gate: &Gate) -> Result<CommitPlan, CoreError> {
    let payload = read_payload(&gate.payload_path, gate.gate_id)?;
    let worktree = payload
        .worktree
        .ok_or(CoreError::NoWorktree(gate.gate_id))?;
    Ok(plan(
        gate,
        CommitTarget {
            worktree,
            subject: subject_for(payload.subject.as_deref().unwrap_or(&gate.summary)),
            files: payload.files,
            diff_hash: payload.diff_hash,
            pre_sha: payload.pre_sha,
            diff_path: payload.diff_path,
        },
    ))
}

/// Rebuilds the [`CommitTarget`] of a gate whose `gate.resolving` predates the field, and appends a
/// repair `gate.resolving` so the projection carries it from now on.
///
/// Returns `None` — not an error — when the payload file is gone or names no worktree: the caller
/// blocks the run rather than failing the whole sweep. Self-limiting, because once the repair is
/// appended `Gate.commit` is `Some` and no later reconcile reaches this path.
fn heal_commit_target(reg: &mut Registry, gate: &Gate) -> Result<Option<CommitTarget>, CoreError> {
    let Ok(payload) = read_payload(&gate.payload_path, gate.gate_id) else {
        return Ok(None);
    };
    let Some(worktree) = payload.worktree else {
        return Ok(None);
    };
    // A payload that cannot say which diff was reviewed cannot authorise a commit: the whole point
    // of healing is to finish a resolution the old code started, and the old code committed the
    // worktree as it stood. Refusing here blocks the run and leaves the commit to a human, which is
    // the fail-closed reading of "a PASS integrates the diff it was shown" (Rev 25).
    if payload.diff_hash.is_none() || payload.pre_sha.is_none() || payload.diff_path.is_none() {
        tracing::warn!(
            gate = %gate.gate_id,
            "the gate payload names no reviewed diff; the commit cannot be bound to one"
        );
        return Ok(None);
    }
    let target = CommitTarget {
        worktree,
        subject: subject_for(payload.subject.as_deref().unwrap_or(&gate.summary)),
        files: payload.files,
        diff_hash: payload.diff_hash,
        pre_sha: payload.pre_sha,
        diff_path: payload.diff_path,
    };

    // `resolved_by` comes from the very `gate.resolving` that put this gate in `Resolving`, so it
    // is always present; the fallback names the reconciler rather than impersonating a resolver.
    let by = gate.resolved_by.clone().unwrap_or(Actor::Socket {
        client_name: "acp-reconcile".into(),
    });
    reg.append(
        &gate.run_id,
        EventPayload::GateResolving {
            gate_id: gate.gate_id,
            approve: true,
            feedback: gate.feedback.clone(),
            by,
            commit: Some(target.clone()),
            external_verification: None,
        },
    )?;
    Ok(Some(target))
}

/// The target recorded when this gate's resolution window opened.
fn commit_target(gate: &Gate) -> Result<CommitTarget, CoreError> {
    gate.commit
        .clone()
        .ok_or(CoreError::NoWorktree(gate.gate_id))
}

fn plan(gate: &Gate, target: CommitTarget) -> CommitPlan {
    let body = body_for(&gate.summary, &target.subject);
    CommitPlan {
        gate_id: gate.gate_id,
        run_id: gate.run_id,
        message: CommitMessage {
            title: target.subject.clone(),
            body,
        },
        target,
    }
}

/// `<state_dir>/runs/<runId>/gates/<gateId>.payload.json`.
pub(super) fn payload_path(state_dir: &Path, run: &RunId, gate: &GateId) -> PathBuf {
    state_dir
        .join(RUNS_DIR)
        .join(run.to_string())
        .join(GATES_DIR)
        .join(format!("{gate}.payload.json"))
}

/// Writes the payload 0600 under a 0700 directory — the state dir's own permissions (design,
/// § On-disk layout), because a payload names the worktree an approval will commit.
fn write_payload(path: &Path, gate: GateId, payload: &GatePayload) -> Result<(), CoreError> {
    let fail = |problem: String| CoreError::GatePayload {
        gate,
        path: path.to_path_buf(),
        problem,
    };

    if let Some(parent) = path.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e: io::Error| fail(format!("create_dir: {e}")))?;
    }
    let json = serde_json::to_vec_pretty(payload).map_err(|e| fail(format!("encode: {e}")))?;
    if json.len() as u64 > MAX_GATE_PAYLOAD_BYTES {
        return Err(fail(format!("payload exceeds {MAX_GATE_PAYLOAD_BYTES} bytes")));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| fail(format!("open: {e}")))?;
    file.write_all(&json)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.flush())
        .map_err(|e| fail(format!("write: {e}")))
}

/// Reads a payload back. Both halves of the failure — I/O and parse — are one variant, because the
/// caller's only recourse is the same either way: refuse to commit and leave the gate pending.
fn read_payload(path: &Path, gate: GateId) -> Result<GatePayload, CoreError> {
    let fail = |problem: String| CoreError::GatePayload {
        gate,
        path: path.to_path_buf(),
        problem,
    };
    let file = std::fs::File::open(path).map_err(|e| fail(format!("open: {e}")))?;
    let mut bytes = Vec::new();
    std::io::Read::take(file, MAX_GATE_PAYLOAD_BYTES + 1).read_to_end(&mut bytes)
        .map_err(|e| fail(format!("read: {e}")))?;
    if bytes.len() as u64 > MAX_GATE_PAYLOAD_BYTES {
        return Err(fail(format!("payload exceeds {MAX_GATE_PAYLOAD_BYTES} bytes")));
    }
    serde_json::from_slice(&bytes).map_err(|e| fail(format!("parse: {e}")))
}

fn validate_external_verification(
    reg: &Registry,
    run_id: &RunId,
    payload: &GatePayload,
    approving_gate: Option<GateId>,
) -> Result<(), CoreError> {
    let reject = |reason: String| -> CoreError {
        policy::PolicyError::new(policy::PolicyCode::DelegationNotAllowed, reason).into()
    };
    let evidence = payload.external_verification.as_ref().ok_or_else(|| {
        reject("external-verification gate has no evidence record".into())
    })?;
    evidence.validate_attestation().map_err(reject)?;
    let run = reg.run(run_id).ok_or(CoreError::UnknownRun(*run_id))?;
    if run.audit.is_some() || run.execution.as_ref().is_some_and(|e| e.mode != crate::core::types::RunMode::Build) {
        return Err(reject("external verification applies only to builder runs".into()));
    }
    if approving_gate.is_none() && run.last_seq != evidence.expected_run_seq {
        return Err(reject(format!(
            "stale run state: expected seq {}, current seq {}",
            evidence.expected_run_seq, run.last_seq
        )));
    }
    if !matches!(run.status, RunStatus::Blocked | RunStatus::Running) {
        return Err(reject(format!("run is {:?}; external verification is no longer applicable", run.status)));
    }
    if reg.state().agents.values().filter(|a| a.run_id == *run_id).any(|a| {
        matches!(a.status, AgentStatus::Starting | AgentStatus::Running)
            || a.attempt_ids.iter().any(|id| reg.attempt(id).is_some_and(|x| x.status == AttemptStatus::Running))
    }) {
        return Err(reject("an attempt is active or still finalizing for this run".into()));
    }
    if reg.state().gates.values().any(|g| {
        g.run_id == *run_id
            && matches!(g.status, GateStatus::Pending | GateStatus::Resolving)
            && Some(g.gate_id) != approving_gate
    }) {
        return Err(reject("another gate is pending or resolving for this run".into()));
    }
    let events = reg.events(run_id, None, usize::MAX);
    if let Some(gate_id) = approving_gate {
        let newest = events.last().map(|e| (&e.payload, e.base.seq));
        if !matches!(newest, Some((EventPayload::GateCreated { gate_id: id, .. }, _)) if *id == gate_id) {
            return Err(reject("run state changed after external evidence was recorded".into()));
        }
    }
    let current = events.iter().rev().find_map(|e| match &e.payload {
        EventPayload::DiffFrozen { attempt_id, diff_hash, source_inventory_hash, .. } => Some((*attempt_id, diff_hash.as_str(), source_inventory_hash.as_deref())),
        _ => None,
    });
    if current.as_ref().map(|(attempt, hash, _)| (*attempt, *hash))
        != Some((evidence.builder_attempt_id, evidence.diff_hash.as_str())) {
        return Err(reject("builder attempt or frozen diff hash is stale or mismatched".into()));
    }
    if current.and_then(|(_, _, hash)| hash) != Some(evidence.source_inventory_after_hash.as_str()) {
        return Err(reject("host evidence does not match the source inventory captured with the frozen diff".into()));
    }
    let blocked = events.iter().rev().find_map(|e| match &e.payload {
        EventPayload::VerifyReport { builder_attempt_id, status, commands, blockers, .. }
            if *builder_attempt_id == evidence.builder_attempt_id => Some((*status, commands, blockers)),
        _ => None,
    });
    let Some((VerifyStatus::Blocked, required_commands, blockers)) = blocked else {
        return Err(reject("the exact builder attempt has no environment-blocked verifier report".into()));
    };
    if required_commands.is_empty() || blockers.is_empty() {
        return Err(reject("the blocked verifier record has no bounded command/capability evidence".into()));
    }
    if evidence.source_inventory_before_hash != evidence.source_inventory_after_hash {
        return Err(reject("source inventory changed while host checks ran".into()));
    }
    if evidence.commands.is_empty()
        || evidence.commands.iter().any(|c| {
            c.argv.is_empty()
                || c.status != ExternalCommandStatus::Passed
                || c.exit_status != Some(0)
        })
    {
        return Err(reject("every recorded host check must have run and passed with exit status 0".into()));
    }
    let mut required: Vec<_> = required_commands.iter().map(String::as_str).collect();
    let mut supplied: Vec<_> = evidence.commands.iter().map(|c| c.worker_command.as_str()).collect();
    required.sort_unstable();
    supplied.sort_unstable();
    if required != supplied {
        return Err(reject("external evidence must cover exactly the blocked verifier command occurrences".into()));
    }
    Ok(())
}

fn prepared_external_verification(
    reg: &Registry,
    run_id: &RunId,
    gate_id: GateId,
) -> Option<ExternalVerificationEvidence> {
    reg.events(run_id, None, usize::MAX).iter().rev().find_map(|event| match &event.payload {
        EventPayload::ExternalVerificationPrepared {
            gate_id: id,
            evidence,
            daemon_captured_inventory_hash,
        } if *id == gate_id
            && daemon_captured_inventory_hash == &evidence.source_inventory_after_hash =>
        {
            Some(evidence.clone())
        }
        _ => None,
    })
}

/// Resolve the only worktree eligible for an inventory capture. This check runs both before and
/// after the helper so a stale sequence, finalization, cancellation or replacement cannot borrow
/// an inventory captured for an earlier state.
pub(crate) fn external_inventory_target(
    reg: &Registry,
    request: &crate::core::types::SourceInventoryRequest,
) -> Result<(PathBuf, String), CoreError> {
    inventory_target(reg, request, None)
}

/// Resolve the worktree from immutable preparation, never from mutable gate payload or caller
/// input. Recheck this target after the helper returns; only this one pending gate is allowed.
pub(crate) fn pending_external_target(reg: &Registry, id: GateId) -> Result<(PathBuf, String), CoreError> {
    let gate = reg.gate(&id).ok_or(CoreError::UnknownGate(id))?;
    let reject = |reason| policy::PolicyError::new(policy::PolicyCode::DelegationNotAllowed, reason);
    if gate.kind != GateKind::ExternalVerification || gate.status != GateStatus::Pending {
        return Err(reject("external-verification gate is no longer pending").into());
    }
    let prepared = prepared_external_verification(reg, &gate.run_id, id)
        .ok_or_else(|| reject("external-verification gate has no immutable prepared evidence"))?;
    let run = reg.run(&gate.run_id).ok_or(CoreError::UnknownRun(gate.run_id))?;
    let expected_run_seq = run.last_seq;
    let req = crate::core::types::SourceInventoryRequest { run_id: gate.run_id,
        builder_attempt_id: prepared.builder_attempt_id, diff_hash: prepared.diff_hash.clone(), expected_run_seq };
    validate_external_verification(reg, &gate.run_id, &GatePayload {
        external_verification: Some(prepared), ..GatePayload::default()
    }, Some(id))?;
    inventory_target(reg, &req, Some(id))
}

fn inventory_target(reg: &Registry, request: &crate::core::types::SourceInventoryRequest,
    allowed_gate: Option<GateId>) -> Result<(PathBuf, String), CoreError> {
    let reject = |reason: String| -> CoreError {
        policy::PolicyError::new(policy::PolicyCode::DelegationNotAllowed, reason).into()
    };
    let run = reg.run(&request.run_id).ok_or(CoreError::UnknownRun(request.run_id))?;
    if run.last_seq != request.expected_run_seq {
        return Err(reject(format!("stale run state: expected seq {}, current seq {}", request.expected_run_seq, run.last_seq)));
    }
    if !matches!(run.status, RunStatus::Blocked | RunStatus::Running) {
        return Err(reject(format!("run is {:?}; source inventory is no longer applicable", run.status)));
    }
    if reg.state().agents.values().filter(|agent| agent.run_id == request.run_id).any(|agent| {
        matches!(agent.status, AgentStatus::Starting | AgentStatus::Running)
            || agent.attempt_ids.iter().any(|id| reg.attempt(id).is_some_and(|attempt| attempt.status == AttemptStatus::Running))
    }) {
        return Err(reject("an attempt is active or still finalizing for this run".into()));
    }
    if reg.state().gates.values().any(|gate| gate.run_id == request.run_id && Some(gate.gate_id) != allowed_gate
        && matches!(gate.status, GateStatus::Pending | GateStatus::Resolving)) {
        return Err(reject("a gate is pending or resolving for this run".into()));
    }
    let events = reg.events(&request.run_id, None, usize::MAX);
    let current = events.iter().rev().find_map(|event| match &event.payload {
        EventPayload::DiffFrozen { attempt_id, diff_hash, source_inventory_hash, .. } =>
            Some((*attempt_id, diff_hash, source_inventory_hash.as_ref())),
        _ => None,
    });
    if current.map(|(attempt, hash, _)| (attempt, hash)) != Some((request.builder_attempt_id, &request.diff_hash)) {
        return Err(reject("builder attempt or frozen diff hash is stale or mismatched".into()));
    }
    let frozen_inventory = current.and_then(|(_, _, hash)| hash).ok_or_else(||
        reject("the frozen diff has no complete source inventory; legacy or uncapturable source cannot accept host evidence".into()))?;
    let blocked = events.iter().rev().find_map(|event| match &event.payload {
        EventPayload::VerifyReport { builder_attempt_id, status, commands, blockers, .. }
            if *builder_attempt_id == request.builder_attempt_id => Some((*status, commands, blockers)),
        _ => None,
    });
    if !matches!(blocked, Some((VerifyStatus::Blocked, commands, blockers)) if !commands.is_empty() && !blockers.is_empty()) {
        return Err(reject("the exact builder attempt has no complete environment-blocked verifier report".into()));
    }
    let attempt = reg.attempt(&request.builder_attempt_id)
        .ok_or_else(|| reject("builder attempt is absent from the current projection".into()))?;
    let agent = reg.agent(&attempt.agent_id)
        .ok_or_else(|| reject("builder agent is absent from the current projection".into()))?;
    let worktree = agent.worktree.clone().ok_or_else(|| reject("builder attempt has no recorded worktree".into()))?;
    Ok((worktree, frozen_inventory.clone()))
}

/// The commit subject for a gate, pre-sanitized to exactly what `git.rs` would keep: the first line
/// of `source` — the payload's `subject` when the loop named one, else the gate summary — with
/// control characters neutralized, trimmed, prefixed, and truncated to [`MAX_SUBJECT_BYTES`] on a
/// UTF-8 char boundary (slicing mid-codepoint panics).
///
/// Doing the cut here rather than leaving it to `commit_all` is what lets `integrate.committed`
/// carry the real subject without reading the commit back out of git inside a mailbox turn.
fn subject_for(source: &str) -> String {
    let first = source.split(['\n', '\r']).next().unwrap_or_default();
    let cleaned: String = first
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut subject = SUBJECT_PREFIX.to_string();
    subject.push_str(cleaned.trim());
    truncate_on_char_boundary(subject.trim_end(), MAX_SUBJECT_BYTES)
        .trim_end()
        .to_string()
}

/// The commit body: the full summary, unless the subject already carries all of it (a one-line,
/// untruncated summary with no payload subject of its own — the pre-T83 shape). With a task-line
/// subject the summary is always the body, review sentence first. Worker-authored text goes in
/// here, and `commit_all` strips any forged `Acp-*-Id:` line out of it (S7).
fn body_for(summary: &str, subject: &str) -> String {
    let trimmed = summary.trim();
    if subject.len() == SUBJECT_PREFIX.len() + trimmed.len() && subject.ends_with(trimmed) {
        String::new()
    } else {
        trimmed.to_string()
    }
}

/// The longest prefix of `s` that is at most `max` bytes and ends on a UTF-8 char boundary.
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = 0;
    for (i, c) in s.char_indices() {
        let next = i + c.len_utf8();
        if next > max {
            break;
        }
        end = next;
    }
    &s[..end]
}
