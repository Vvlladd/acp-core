//! Peer process identity and per-run delegation of gate decisions.

use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::policy::{PolicyCode, PolicyError};
use super::types::{
    AgentStatus, AttemptId, AttemptStatus, EventPayload, GateId, GateKind, RoleName, RunId,
    RunMode, RunStatus,
};
use super::{Core, CoreError};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProcessIdentity {
    pid: i32,
    started: (u64, u64),
}

#[derive(Clone, Debug)]
pub struct PeerProcess(Vec<(ProcessIdentity, String)>);

impl PeerProcess {
    /// Call with the peer PID supplied by the kernel, never with a request argument.
    pub fn from_pid(mut pid: i32) -> Option<Self> {
        let mut chain = Vec::new();
        for _ in 0..32 {
            let Some((identity, parent, name)) = process_info(pid) else {
                break;
            };
            chain.push((identity, name));
            if parent <= 1 || parent == pid {
                break;
            }
            pid = parent;
        }
        (!chain.is_empty()).then_some(Self(chain))
    }

    fn includes(&self, owner: ProcessIdentity) -> bool {
        self.0.iter().any(|(identity, _)| *identity == owner)
            && process_info(owner.pid).is_some_and(|(identity, _, _)| identity == owner)
    }

    pub fn is_live(&self) -> bool {
        self.0.first().is_some_and(|(owner, _)| {
            process_info(owner.pid).is_some_and(|(identity, _, _)| identity == *owner)
        })
    }

    fn terminal_host(&self) -> Option<ProcessIdentity> {
        self.0.iter().find_map(|(identity, name)| {
            (matches!(
                name.as_str(),
                "codex" | "claude" | "codex-cli" | "Codex" | "Claude"
            ) || is_versioned_claude(identity.pid))
            .then_some(*identity)
        })
    }
}

#[cfg(target_os = "macos")]
fn is_versioned_claude(pid: i32) -> bool {
    const COMPONENTS: &[u8] = b"/claude/versions/";
    let mut path = [0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // The kernel writes at most the supplied buffer size. The return value bounds the slice.
    let read = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
    usize::try_from(read)
        .ok()
        .and_then(|length| path.get(..length))
        .is_some_and(|path| {
            path.windows(COMPONENTS.len())
                .any(|part| part == COMPONENTS)
        })
}

#[cfg(target_os = "linux")]
fn is_versioned_claude(pid: i32) -> bool {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .is_ok_and(|path| path.to_string_lossy().contains("/claude/versions/"))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn is_versioned_claude(_pid: i32) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn process_info(pid: i32) -> Option<(ProcessIdentity, i32, String)> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
    // The kernel fills the supplied buffer. Read it only when the entire record arrived.
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if read != size {
        return None;
    }
    let info = unsafe { info.assume_init() };
    let name = info
        .pbi_name
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect::<Vec<_>>();
    let identity = ProcessIdentity {
        pid,
        started: (info.pbi_start_tvsec, info.pbi_start_tvusec),
    };
    Some((
        identity,
        i32::try_from(info.pbi_ppid).ok()?,
        String::from_utf8_lossy(&name).into_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn process_info(pid: i32) -> Option<(ProcessIdentity, i32, String)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = stat.split_once(" (")?;
    let (name, fields) = rest.rsplit_once(") ")?;
    let mut fields = fields.split_ascii_whitespace();
    let parent = fields.nth(1)?.parse().ok()?;
    let started = fields.nth(17)?.parse().ok()?;
    Some((
        ProcessIdentity {
            pid,
            started: (started, 0),
        },
        parent,
        name.to_owned(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn process_info(_pid: i32) -> Option<(ProcessIdentity, i32, String)> {
    None
}

#[derive(Debug, Default)]
pub(super) struct LeadAuthority {
    attempts: HashMap<AttemptId, ProcessIdentity>,
}

#[derive(Deserialize, Serialize)]
struct TerminalBinding {
    owner: ProcessIdentity,
    claim_hash: [u8; 32],
}

/// Reads a small owner-private local file without following links or waiting on a FIFO.
pub fn read_private_regular(path: &std::path::Path, limit: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    // `geteuid` takes no arguments and returns the effective process UID directly.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != uid
        || metadata.len() > limit
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the claim must be a small owner-private regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the claim file exceeded its size bound",
        ));
    }
    Ok(bytes)
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeadDecision {
    pub gate_id: GateId,
    pub approve: bool,
    pub feedback: Option<String>,
    pub diff_hash: Option<String>,
    pub builder_attempt_id: Option<AttemptId>,
    pub terminal_claim: Option<uuid::Uuid>,
}

impl std::fmt::Debug for LeadDecision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LeadDecision")
            .field("gate_id", &self.gate_id)
            .field("approve", &self.approve)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeadAuthorized {
    pub run_id: RunId,
    pub lead_approved: bool,
}

pub(super) fn refusal(reason: &'static str) -> CoreError {
    PolicyError::new(PolicyCode::AgentApproveNotAllowed, reason).into()
}

impl Core {
    pub(super) fn register_managed_process(&mut self, id: AttemptId, pid: i32) {
        if let Some((identity, _, _)) = process_info(pid) {
            self.lead_authority.attempts.insert(id, identity);
        }
    }

    fn managed_peer(&self, peer: &PeerProcess) -> bool {
        self.lead_authority
            .attempts
            .values()
            .any(|&owner| peer.includes(owner))
            || self.registry.state().attempts.values().any(|attempt| {
                attempt.status == AttemptStatus::Running
                    && attempt
                        .pid
                        .is_some_and(|pid| peer.0.iter().any(|(identity, _)| identity.pid == pid))
            })
    }

    pub(super) fn authorize_human_peer(&self, peer: Option<&PeerProcess>) -> Result<(), CoreError> {
        if peer.is_none_or(|p| self.managed_peer(p)) {
            return Err(refusal("a managed agent cannot request human confirmation; a person must request it from the ACP Mac app or their terminal"));
        }
        Ok(())
    }

    pub(super) fn authorize_human_gate_peer(
        &self,
        gate: GateId,
        peer: Option<&PeerProcess>,
    ) -> Result<(), CoreError> {
        if let Some(peer) = peer {
            self.authorize_human_peer(Some(peer))?;
        }
        if let Some(run) = self
            .registry
            .gate(&gate)
            .and_then(|g| self.registry.run(&g.run_id))
        {
            if self.lead_approval_root(&run.run_id).is_none() {
                if let Some(execution) = &run.execution {
                    let root = execution.lead_owner_run_id.unwrap_or(run.run_id);
                    self.refuse_same_terminal(root, peer)?;
                }
            }
        }
        Ok(())
    }

    fn refuse_same_terminal(
        &self,
        root: RunId,
        peer: Option<&PeerProcess>,
    ) -> Result<(), CoreError> {
        if self
            .terminal_binding(root)
            .zip(peer)
            .is_some_and(|(binding, peer)| peer.includes(binding.owner))
        {
            return Err(refusal(
                "a human must confirm this run in the ACP Mac app or a separate terminal",
            ));
        }
        Ok(())
    }

    pub(super) fn authenticated_spawned_lead(&self, peer: Option<&PeerProcess>) -> Option<RunId> {
        let peer = peer?;
        let agent = self
            .live_lead_agent()
            .and_then(|id| self.registry.agent(&id))?;
        let attempt = agent
            .attempt_ids
            .last()
            .and_then(|id| self.registry.attempt(id))?;
        if attempt.status != AttemptStatus::Running {
            return None;
        }
        let owner = self.lead_authority.attempts.get(&attempt.attempt_id)?;
        peer.includes(*owner).then_some(agent.run_id)
    }

    pub(super) fn terminal_candidate(
        &self,
        peer: Option<&PeerProcess>,
    ) -> Result<ProcessIdentity, CoreError> {
        peer.filter(|p| !self.managed_peer(p)).and_then(PeerProcess::terminal_host)
            .ok_or_else(|| refusal("a terminal lead claim must originate from a connected Claude Code or Codex host"))
    }

    fn terminal_binding_path(&self, run: RunId) -> std::path::PathBuf {
        self.state_dir
            .join("runs")
            .join(run.to_string())
            .join("terminal-lead.json")
    }

    pub(super) fn record_terminal_lead(
        &self,
        owner: ProcessIdentity,
        run: RunId,
    ) -> Result<uuid::Uuid, CoreError> {
        use std::io::Write as _;
        let claim = uuid::Uuid::new_v4();
        let record = TerminalBinding {
            owner,
            claim_hash: Sha256::digest(claim.as_bytes()).into(),
        };
        let path = self.terminal_binding_path(run);
        let save = || -> std::io::Result<()> {
            let parent = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
            std::fs::create_dir_all(parent)?;
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(&serde_json::to_vec(&record)?)?;
            file.sync_all()
        };
        save().map_err(|_| refusal("could not record the terminal claim for this run"))?;
        Ok(claim)
    }

    fn terminal_binding(&self, root: RunId) -> Option<TerminalBinding> {
        let bytes = read_private_regular(&self.terminal_binding_path(root), 4096).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub(super) fn terminal_candidate_is_live(&self, run: RunId) -> bool {
        self.terminal_binding(run).is_some_and(|binding| {
            process_info(binding.owner.pid)
                .is_some_and(|(identity, _, _)| identity == binding.owner)
        })
    }

    pub(super) fn lead_approval_root(&self, run: &RunId) -> Option<RunId> {
        let own = self.registry.run(run)?.execution.as_ref()?;
        let root = own.lead_owner_run_id.unwrap_or(*run);
        self.registry
            .run(&root)?
            .execution
            .as_ref()?
            .lead_approval_run_id
            .filter(|id| *id == root)
    }

    pub(super) fn lead_authorization_prompt(
        &self,
        run: RunId,
        peer: Option<&PeerProcess>,
    ) -> Result<Option<crate::ipc::human_confirmation::Prompt>, CoreError> {
        use crate::ipc::human_confirmation::{preview, Prompt};
        self.authorize_human_peer(peer)?;
        let task = self.registry.run(&run).ok_or(CoreError::UnknownRun(run))?;
        if let Some(root) = self.lead_approval_root(&run) {
            if root == run {
                return Ok(None);
            }
        }
        let execution = task
            .execution
            .as_ref()
            .ok_or_else(|| refusal("this run has no recorded lead assignment"))?;
        if execution
            .lead_owner_run_id
            .is_some_and(|owner| owner != run)
            || execution.mode == RunMode::Audit
            || matches!(
                task.status,
                RunStatus::Cancelled
                    | RunStatus::Integrated
                    | RunStatus::Completed
                    | RunStatus::Failed
            )
        {
            return Err(refusal("this run cannot receive a lead authorization"));
        }
        let spawned = task
            .agent_ids
            .iter()
            .filter_map(|agent| self.registry.agent(agent))
            .any(|agent| {
                agent.role == RoleName::Lead
                    && (matches!(agent.status, AgentStatus::Starting | AgentStatus::Running)
                        || agent.resumable)
            });
        let terminal = self.terminal_candidate_is_live(run);
        if !spawned && !terminal {
            return Err(refusal(
                "this run has no designated spawned lead or connected native terminal lead",
            ));
        }
        let repo = preview(&self.repo_root.to_string_lossy(), 180);
        Prompt::new("authorize_lead", &(&self.repo_root, run), "ACP — Allow lead decisions?", format!(
            "Repository: {repo}\nRun: {run}\n\nThe designated lead can decide plans and authorize the exact checked patch for a local commit in the task worktree. Escalations still require human confirmation."
        ), "Allow lead decisions").map(Some)
    }

    pub(super) fn authorize_lead_run(
        &mut self,
        run: RunId,
        peer: Option<&PeerProcess>,
        proof: Option<crate::ipc::human_confirmation::Proof>,
    ) -> Result<LeadAuthorized, CoreError> {
        if let Some(prompt) = self.lead_authorization_prompt(run, peer)? {
            crate::ipc::human_confirmation::require(proof, &prompt)?;
            self.registry
                .append(&run, EventPayload::RunLeadAuthorized)?;
        }
        Ok(LeadAuthorized {
            run_id: run,
            lead_approved: true,
        })
    }

    pub(super) fn authorize_lead_decision(
        &self,
        decision: &LeadDecision,
        peer: Option<&PeerProcess>,
    ) -> Result<(), CoreError> {
        let refused = || refusal("this caller has no lead authority for the requested gate");
        let gate = self.registry.gate(&decision.gate_id).ok_or_else(refused)?;
        let root = self.lead_approval_root(&gate.run_id).ok_or_else(refused)?;
        let spawned = self.authenticated_spawned_lead(peer) == Some(root);
        let terminal = decision
            .terminal_claim
            .zip(peer)
            .and_then(|(claim, peer)| {
                let binding = self.terminal_binding(root)?;
                let digest: [u8; 32] = Sha256::digest(claim.as_bytes()).into();
                let matches = digest
                    .iter()
                    .zip(binding.claim_hash)
                    .fold(0, |mismatch, (left, right)| mismatch | (left ^ right))
                    == 0;
                (matches && !self.managed_peer(peer) && peer.includes(binding.owner)).then_some(())
            })
            .is_some();
        if !spawned && !terminal {
            return Err(refused());
        }
        if gate.kind == GateKind::ExternalVerification {
            return Err(refusal("external verification requires a human attestation"));
        }
        if gate.kind == GateKind::Escalate {
            return Err(refusal("an escalation requires a human decision"));
        }
        if gate.kind == GateKind::Integrate
            && (self
                .pending_spawn
                .values()
                .any(|pending| pending.run() == gate.run_id)
                || self
                    .pending_worktree
                    .values()
                    .any(|pending| pending.run() == gate.run_id))
        {
            return Err(refusal(
                "the work changed while the integration decision was pending",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "lead_authority_tests.rs"]
mod tests;
