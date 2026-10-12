//! Session ownership and shutdown admission (T85). No timers or process knowledge live in a
//! skill. The actor supplies work state; the ingress mutex serializes the final idle check with
//! acceptance of socket connections and requests, including socket-only team operations.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const LEASE_TTL: Duration = Duration::from_secs(120);
pub const IDLE_GRACE: Duration = Duration::from_secs(300);
const MAX_SESSIONS: usize = 256;

#[derive(Default, Debug)]
struct Admission {
    connections: usize,
    requests: usize,
    revision: u64,
    closed: bool,
}

#[derive(Default, Debug)]
pub struct Ingress(Mutex<Admission>);

impl Ingress {
    fn lock(&self) -> MutexGuard<'_, Admission> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn connection(self: &Arc<Self>) -> Option<ActivityGuard> {
        self.enter(true)
    }

    pub fn request(self: &Arc<Self>) -> Option<ActivityGuard> {
        self.enter(false)
    }

    fn enter(self: &Arc<Self>, connection: bool) -> Option<ActivityGuard> {
        let mut state = self.lock();
        if state.closed {
            return None;
        }
        if connection {
            state.connections += 1;
        } else {
            state.requests += 1;
        }
        state.revision = state.revision.wrapping_add(1);
        Some(ActivityGuard {
            ingress: Arc::clone(self),
            connection,
        })
    }
}

#[derive(Debug)]
pub struct ActivityGuard {
    ingress: Arc<Ingress>,
    connection: bool,
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        let mut state = self.ingress.lock();
        if self.connection {
            state.connections -= 1;
        } else {
            state.requests -= 1;
        }
        state.revision = state.revision.wrapping_add(1);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopMode {
    WhenIdle,
    CancelWork,
    DaemonOnly,
    KeepRunning,
}

#[derive(Debug)]
pub enum Request {
    Status,
    Acquire { label: String },
    /// A lease bound to a host process; see [`OwnerProcess`].
    AcquireOwned { label: String, owner: OwnerProcess },
    Renew { instance: Uuid, session: Uuid },
    /// `stop_if_unneeded`: the releasing owner is exiting. A managed daemon then skips the idle
    /// grace — but only once nothing else needs it (no lease, no connected client, no work),
    /// checked atomically at the tick like the ordinary idle transition. Manual/stdio owners are
    /// never converted.
    Release { instance: Uuid, session: Uuid, stop_if_unneeded: bool },
    Stop { mode: StopMode },
}

/// Keep host ownership bounded independently of renewable per-turn leases.
const MAX_OWNED_SESSIONS: usize = 16;

/// Identity verified by the socket's process helper, outside the actor. The watcher reports only
/// a confirmed exit or identity change; probe errors never manufacture a closed session.
#[derive(Debug, Clone)]
pub struct OwnerProcess {
    pub pid: i32,
    pub start_time: String,
    pub exited: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveTask {
    pub run_id: super::types::RunId,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub instance_id: Uuid,
    pub managed: bool,
    pub lease_ttl_sec: u64,
    pub idle_grace_sec: u64,
    pub sessions: usize,
    pub connected_clients: usize,
    pub busy_reasons: Vec<String>,
    pub stop_requested: Option<StopMode>,
    pub stopping: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_tasks: Vec<ActiveTask>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
}

#[derive(Debug)]
pub struct LifecycleError {
    pub code: &'static str,
    pub reason: String,
}

impl LifecycleError {
    fn new(code: &'static str, reason: &str) -> Self {
        Self {
            code,
            reason: reason.to_string(),
        }
    }
}

pub struct Lifecycle {
    pub ingress: Arc<Ingress>,
    instance: Uuid,
    managed: bool,
    leases: HashMap<Uuid, Instant>,
    grace: Duration,
    ttl: Duration,
    idle_since: Option<(Instant, u64)>,
    requested: Option<StopMode>,
    failure: Option<String>,
    stop_signal: CancellationToken,
    /// An exiting owner requested cleanup once existing activity drains; a new owner or
    /// Keep running withdraws it. This never bypasses the idle predicate.
    exit_requested: bool,
    /// Leases bound to a host process: exempt from TTL expiry, reaped when the process is gone.
    owners: HashMap<Uuid, OwnerProcess>,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            ingress: Arc::default(),
            instance: Uuid::new_v4(),
            managed: false,
            leases: HashMap::new(),
            grace: IDLE_GRACE,
            ttl: LEASE_TTL,
            idle_since: None,
            requested: None,
            failure: None,
            stop_signal: CancellationToken::new(),
            exit_requested: false,
            owners: HashMap::new(),
        }
    }
}

impl Lifecycle {
    pub fn configure(&mut self, managed: bool, signal: CancellationToken) {
        self.managed = managed;
        self.stop_signal = signal;
    }

    pub fn draining(&self) -> bool {
        self.requested.is_some()
    }

    pub fn cancelling(&self) -> bool {
        self.requested == Some(StopMode::CancelWork)
    }

    pub fn fail_stop(&mut self, reason: String) {
        if self.failure.is_none() {
            self.failure = Some(reason);
        }
    }

    pub fn request(
        &mut self,
        request: Request,
        busy: Vec<String>,
        now: Instant,
    ) -> Result<Status, LifecycleError> {
        self.expire(now);
        let mut session_id = None;
        let mut owner = match &request {
            Request::AcquireOwned { owner, .. } => Some(owner.clone()),
            _ => None,
        };
        match request {
            Request::Status => {}
            Request::Acquire { label } | Request::AcquireOwned { label, .. } => {
                if self.draining() {
                    return Err(LifecycleError::new("daemon_draining", "the daemon is waiting to stop; cancel the stop request before starting a session"));
                }
                if label.is_empty()
                    || label.chars().count() > 80
                    || label.chars().any(char::is_control)
                {
                    return Err(LifecycleError::new(
                        "invalid_session",
                        "session label must be 1–80 printable characters",
                    ));
                }
                if self.leases.len() >= MAX_SESSIONS {
                    return Err(LifecycleError::new(
                        "session_limit",
                        "too many live sessions",
                    ));
                }
                if owner.is_some() && self.owners.len() >= MAX_OWNED_SESSIONS {
                    return Err(LifecycleError::new(
                        "session_limit",
                        "too many process-bound sessions",
                    ));
                }
                let id = Uuid::new_v4();
                self.leases.insert(id, now + self.ttl);
                if let Some(owner) = owner.take() {
                    self.owners.insert(id, owner);
                }
                session_id = Some(id);
                self.idle_since = None;
                self.exit_requested = false;
            }
            Request::Renew { instance, session } => {
                self.check_instance(instance)?;
                let Some(expiry) = self.leases.get_mut(&session) else {
                    return Err(LifecycleError::new(
                        "session_expired",
                        "session is absent or expired; acquire a new session",
                    ));
                };
                *expiry = now + self.ttl;
                session_id = Some(session);
            }
            Request::Release {
                instance,
                session,
                stop_if_unneeded,
            } => {
                self.check_instance(instance)?;
                // An idempotent retry can release only the opaque handle it already possessed.
                let released = self.leases.remove(&session).is_some();
                self.owners.remove(&session);
                // Retries and unknown handles cannot initiate shutdown. Keep a real exit request
                // while existing work/clients drain; a new owner or Keep running withdraws it.
                if released && stop_if_unneeded && self.managed {
                    self.exit_requested = true;
                }
            }
            Request::Stop {
                mode: StopMode::KeepRunning,
            } => {
                self.requested = None;
                self.exit_requested = false;
                self.idle_since = None;
            }
            Request::Stop { mode } => {
                self.requested = Some(mode);
                self.idle_since = None;
            }
        }
        let ingress = self.ingress.lock();
        Ok(Status {
            instance_id: self.instance,
            managed: self.managed,
            lease_ttl_sec: self.ttl.as_secs(),
            idle_grace_sec: self.grace.as_secs(),
            sessions: self.leases.len(),
            connected_clients: ingress.connections,
            busy_reasons: busy,
            stop_requested: self.requested,
            stopping: ingress.closed,
            stop_error: self.failure.clone(),
            active_tasks: Vec::new(),
            session_id,
        })
    }

    fn check_instance(&self, instance: Uuid) -> Result<(), LifecycleError> {
        if instance == self.instance {
            Ok(())
        } else {
            Err(LifecycleError::new(
                "daemon_restarted",
                "session belongs to another daemon instance",
            ))
        }
    }

    fn expire(&mut self, now: Instant) {
        let owners = &self.owners;
        self.leases
            .retain(|id, expiry| owners.contains_key(id) || *expiry > now);
    }

    /// No I/O in the actor: the bounded asynchronous watcher marks verified host exits.
    fn reap_owners(&mut self) {
        let gone: Vec<Uuid> = self.owners.iter()
            .filter(|(_, owner)| owner.exited.load(Ordering::Acquire))
            .map(|(id, _)| *id).collect();
        if gone.is_empty() { return; }
        for id in &gone {
            self.owners.remove(id);
            self.leases.remove(id);
        }
        tracing::info!(count = gone.len(), "session host exited; ownership released");
        if self.managed { self.exit_requested = true; }
    }

    /// Called only on actor ticks, after reconciliation/finalization. A stop request is answered
    /// before the next tick, so its response can reach the socket outbox before shutdown begins.
    pub fn tick(&mut self, busy: bool, now: Instant) {
        self.reap_owners();
        self.expire(now);
        let mut ingress = self.ingress.lock();
        if ingress.closed {
            return;
        }
        let manual = self.requested.is_some();
        let force = self.requested == Some(StopMode::DaemonOnly);
        let eligible = ingress.requests == 0
            && (force
                || (!busy
                    && self.failure.is_none()
                    && (manual
                        || (self.managed && self.leases.is_empty() && ingress.connections == 0))));
        if !eligible {
            self.idle_since = None;
            return;
        }
        // Work, leases, connections and requests were checked above, under the ingress lock.
        let expedited = !manual && self.exit_requested;
        let (since, revision) = *self.idle_since.get_or_insert((now, ingress.revision));
        if expedited {
            ingress.closed = true;
            self.stop_signal.cancel();
            return;
        }
        if revision != ingress.revision && !manual {
            self.idle_since = Some((now, ingress.revision));
            return;
        }
        if !manual && now.duration_since(since) < self.grace {
            return;
        }
        // Holding this mutex closes the race with both accept() and request dispatch. Existing
        // requests have drained for safe stop; daemon-only deliberately retains C3 semantics.
        ingress.closed = true;
        self.stop_signal.cancel();
    }
}

impl super::Core {
    pub fn lifecycle_busy_reasons(&self) -> Vec<String> {
        use super::plan::PlanItemStatus;
        use super::types::{GateStatus, RunStatus};
        let state = self.registry.state();
        let mut reasons = Vec::new();
        if !self.local_checks.is_empty() { reasons.push("A local code review is running".into()); }
        if let Some(failure) = &self.lifecycle.failure {
            reasons.push(failure.clone());
        }
        if self.supervisor.pending_finalize_count() > 0
            || !self.pending_worktree.is_empty()
            || !self.pending_spawn.is_empty()
            || !self.pending_retry.is_empty()
            || !self.pending_audit.is_empty()
            || !self.in_flight.is_empty()
            || !self.gate_waiters.is_empty()
            || !self.settled.is_empty()
        {
            reasons.push("Preparing, finalizing or integrating work".into());
        }
        if !self.supervisor.active_attempts().is_empty()
            || state
                .attempts
                .values()
                .any(|a| !super::is_terminal(a.status))
        {
            reasons.push("Workers are still active".into());
        }
        if state
            .gates
            .values()
            .any(|g| matches!(g.status, GateStatus::Pending | GateStatus::Resolving))
        {
            reasons.push("Human approvals are unresolved".into());
        }
        if self.registry.runs().any(|r| {
            (!r.lineages.is_empty() || r.execution.as_ref().is_some_and(|e| e.audit_selection.is_some()))
                && matches!(
                    r.status,
                    RunStatus::Running | RunStatus::AwaitingGate | RunStatus::Blocked
                )
        }) {
            reasons.push("A work run still needs completion or cancellation".into());
        }
        if state.plans.values().any(|p| {
            p.items
                .values()
                .any(|i| matches!(i.status, PlanItemStatus::Pending | PlanItemStatus::Started))
        }) {
            reasons.push("A plan has unfinished items".into());
        }
        reasons
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed() -> (Lifecycle, CancellationToken, Instant) {
        let signal = CancellationToken::new();
        let mut lifecycle = Lifecycle::default();
        lifecycle.configure(true, signal.clone());
        (lifecycle, signal, Instant::now())
    }

    fn exit_release(session: &Status) -> Request {
        Request::Release {
            instance: session.instance_id,
            session: session.session_id.unwrap(),
            stop_if_unneeded: true,
        }
    }

    fn acquire(lifecycle: &mut Lifecycle, label: &str, now: Instant) -> Status {
        lifecycle
            .request(Request::Acquire { label: label.into() }, vec![], now)
            .unwrap()
    }

    fn owner(pid: i32) -> OwnerProcess {
        OwnerProcess { pid, start_time: "start".into(), exited: Arc::new(AtomicBool::new(false)) }
    }

    #[test]
    fn bound_host_survives_turns_and_exit_drains_existing_work_without_grace() {
        let (mut lifecycle, signal, now) = managed();
        let host = owner(100);
        let request = || Request::AcquireOwned { label: "host".into(), owner: host.clone() };
        let first = lifecycle.request(request(), vec![], now).unwrap();
        let again = lifecycle.request(request(), vec![], now).unwrap();
        assert_ne!(first.session_id, again.session_id, "conversations in one host retain separate ownership");
        lifecycle.request(exit_release(&first), vec![], now).unwrap();
        lifecycle.tick(false, now);
        assert!(!signal.is_cancelled(), "one conversation cannot release another's lease");
        lifecycle.tick(false, now + LEASE_TTL * 10);
        assert_eq!(lifecycle.request(Request::Status, vec![], now).unwrap().sessions, 1);
        let client = lifecycle.ingress.connection().unwrap();
        host.exited.store(true, Ordering::Release);
        lifecycle.tick(true, now + LEASE_TTL * 11);
        assert!(!signal.is_cancelled());
        drop(client);
        lifecycle.tick(true, now + LEASE_TTL * 20);
        assert!(!signal.is_cancelled());
        lifecycle.tick(false, now + LEASE_TTL * 20);
        assert!(signal.is_cancelled());
    }

    #[test]
    fn unknown_release_cannot_expedite_and_new_owner_withdraws_exit() {
        let (mut lifecycle, signal, now) = managed();
        lifecycle.request(Request::Release { instance: lifecycle.instance, session: Uuid::new_v4(), stop_if_unneeded: true }, vec![], now).unwrap();
        lifecycle.tick(false, now);
        assert!(!signal.is_cancelled());
        let first = acquire(&mut lifecycle, "first", now);
        lifecycle.request(exit_release(&first), vec![], now).unwrap();
        let second = acquire(&mut lifecycle, "second", now);
        lifecycle.request(Request::Release { instance: second.instance_id, session: second.session_id.unwrap(), stop_if_unneeded: false }, vec![], now).unwrap();
        lifecycle.tick(false, now);
        assert!(!signal.is_cancelled());
        lifecycle.tick(false, now + IDLE_GRACE);
        assert!(signal.is_cancelled());
    }

    #[test]
    fn bound_sessions_are_capped_and_manual_hosts_never_auto_stop() {
        let now = Instant::now();
        let mut lifecycle = Lifecycle::default();
        let hosts: Vec<_> = (2..18).map(owner).collect();
        for host in &hosts {
            lifecycle.request(Request::AcquireOwned { label: "host".into(), owner: host.clone() }, vec![], now).unwrap();
        }
        let err = lifecycle.request(Request::AcquireOwned { label: "extra".into(), owner: owner(20) }, vec![], now).unwrap_err();
        assert_eq!(err.code, "session_limit");
        for host in hosts { host.exited.store(true, Ordering::Release); }
        lifecycle.tick(false, now);
        lifecycle.tick(false, now + IDLE_GRACE * 3);
        assert!(!lifecycle.stop_signal.is_cancelled());
        assert_eq!(lifecycle.request(Request::Status, vec![], now).unwrap().sessions, 0);
    }

    #[test]
    fn exiting_owner_stops_only_once_nothing_else_needs_the_daemon() {
        let (mut lifecycle, signal, now) = managed();
        let app = acquire(&mut lifecycle, "acp-mac", now);
        let claude = acquire(&mut lifecycle, "claude", now);
        lifecycle.request(exit_release(&app), vec![], now).unwrap();
        // Idempotent: a retried release of the same handle is harmless.
        lifecycle.request(exit_release(&app), vec![], now).unwrap();
        lifecycle.tick(false, now);
        assert!(!signal.is_cancelled(), "another live session still owns the daemon");
        lifecycle.request(exit_release(&claude), vec![], now).unwrap();
        // A connected client (an MCP proxy, another app) keeps the daemon running.
        let client = lifecycle.ingress.connection().unwrap();
        lifecycle.tick(false, now);
        assert!(!signal.is_cancelled(), "a connected client still needs the daemon");
        drop(client);
        lifecycle.tick(true, now);
        assert!(!signal.is_cancelled(), "active work or a pending gate keeps it running");
        lifecycle.tick(false, now);
        assert!(signal.is_cancelled(), "nothing needs it: no idle grace for an exiting owner");
        assert!(lifecycle.ingress.connection().is_none(), "admission closed atomically");
    }

    #[test]
    fn ownership_expiry_grace_and_admission_are_one_lifecycle() {
        let (mut lifecycle, signal, now) = managed();
        let a = lifecycle
            .request(
                Request::Acquire {
                    label: "codex".into(),
                },
                vec![],
                now,
            )
            .unwrap();
        let b = lifecycle
            .request(
                Request::Acquire {
                    label: "claude".into(),
                },
                vec![],
                now,
            )
            .unwrap();
        lifecycle
            .request(
                Request::Release {
                    instance: a.instance_id,
                    session: a.session_id.unwrap(),
                    stop_if_unneeded: false,
                },
                vec![],
                now,
            )
            .unwrap();
        lifecycle.tick(false, now + IDLE_GRACE);
        assert!(!signal.is_cancelled()); // b expired now; the grace starts now, not on acquisition.
        lifecycle.tick(false, now + IDLE_GRACE * 2);
        assert!(signal.is_cancelled());
        assert!(lifecycle.ingress.connection().is_none());
        assert!(lifecycle.ingress.request().is_none());
        assert_ne!(a.session_id, b.session_id);
    }

    #[test]
    fn shared_clients_work_and_inflight_requests_hold_the_daemon() {
        for blocker in 0..3 {
            let (mut lifecycle, signal, now) = managed();
            let guard = match blocker {
                0 => lifecycle.ingress.connection(),
                1 => lifecycle.ingress.request(),
                _ => None,
            };
            lifecycle.tick(blocker == 2, now);
            lifecycle.tick(blocker == 2, now + IDLE_GRACE * 2);
            assert!(!signal.is_cancelled());
            drop(guard);
            lifecycle.tick(false, now + IDLE_GRACE * 2);
            lifecycle.tick(false, now + IDLE_GRACE * 3);
            assert!(signal.is_cancelled());
        }
    }

    #[test]
    fn activity_between_ticks_restarts_the_grace() {
        let (mut lifecycle, signal, now) = managed();
        lifecycle.tick(false, now);
        drop(lifecycle.ingress.request().unwrap());
        lifecycle.tick(false, now + IDLE_GRACE);
        assert!(!signal.is_cancelled());
        lifecycle.tick(false, now + IDLE_GRACE * 2);
        assert!(signal.is_cancelled());
    }

    #[test]
    fn external_daemon_and_restart_identity_are_preserved() {
        let mut lifecycle = Lifecycle::default();
        let now = Instant::now();
        lifecycle.tick(false, now);
        lifecycle.tick(false, now + IDLE_GRACE * 5);
        assert!(!lifecycle.stop_signal.is_cancelled());
        let err = lifecycle
            .request(
                Request::Renew {
                    instance: Uuid::new_v4(),
                    session: Uuid::new_v4(),
                },
                vec![],
                now,
            )
            .unwrap_err();
        assert_eq!(err.code, "daemon_restarted");
    }

    #[test]
    fn daemon_only_waits_for_its_response_but_not_live_work() {
        let (mut lifecycle, signal, now) = managed();
        let request = lifecycle.ingress.request().unwrap();
        lifecycle
            .request(
                Request::Stop {
                    mode: StopMode::DaemonOnly,
                },
                vec![],
                now,
            )
            .unwrap();
        lifecycle.tick(true, now);
        assert!(!signal.is_cancelled());
        drop(request);
        lifecycle.tick(true, now);
        assert!(signal.is_cancelled());
    }

    #[test]
    fn explicit_safe_stop_drains_but_does_not_cancel_work() {
        let (mut lifecycle, signal, now) = managed();
        let client = lifecycle.ingress.connection().unwrap();
        lifecycle
            .request(
                Request::Stop {
                    mode: StopMode::WhenIdle,
                },
                vec!["pending gate".into()],
                now,
            )
            .unwrap();
        lifecycle.tick(true, now + IDLE_GRACE);
        assert!(!signal.is_cancelled());
        assert!(lifecycle
            .request(
                Request::Acquire {
                    label: "new".into()
                },
                vec![],
                now
            )
            .is_err());
        lifecycle.tick(false, now + IDLE_GRACE * 2);
        assert!(signal.is_cancelled());
        drop(client);
    }
}
