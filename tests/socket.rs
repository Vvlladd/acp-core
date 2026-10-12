//! T40: the local IPC door, driven over a **real Unix socket** by a raw NDJSON client —
//! `reports/03-design.md` § Test Strategy, row `ipc/socket.rs`, and § "Local IPC contract".
//!
//! Nothing here calls a handler directly. Every assertion goes through `serve_socket`, a real
//! `UnixStream`, and lines a hand-written client writes and parses — because the thing under test
//! *is* a wire contract, and the Swift app on the other end of it (`apps/acp-mac/ACPProtocol`)
//! decodes exactly these field names.
//!
//! **Two kinds of core sit behind the door.** Most of the contract — framing, the error codes, the
//! three pinned subscription semantics, backpressure — is transport behaviour, and driving it
//! through a whole loop would only make it slower and less precise. Those tests wire a
//! [`CoreHandle`] to a hand-answered mailbox ([`FakeCore`]), which is what lets a test *inject an
//! event in the middle of a `subscribe` backfill* or flood the broadcast buffer at will. The one
//! test that has to be end to end — a human's approval producing a real commit — runs the whole
//! production stack from `tests/common` with the fake provider CLIs.
//!
//! **The socket path must be short.** macOS `sun_path` is 104 bytes and `$TMPDIR` on this platform
//! is a ~50-byte `/var/folders/…` path, so `tempfile::tempdir()` plus `/acp.sock` lands close to
//! the limit. Every door here is bound under `/tmp/<8 chars>` and [`short_dir`] asserts the byte
//! length, so a test can never fail for a reason the code under test is right about.
//!
//! **What is not tested, and why.** `authenticate` rejects a peer whose uid is not ours; a test
//! cannot produce one without another uid to run as (root, or a second account), so the check is
//! covered by construction — it is on the only path that accepts a connection — and by the unit
//! test of its error shape. The same goes for the 0600 mode being *load-bearing*: the design says
//! the 0700 parent directory is the control, and that is what this file asserts.

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use agent_control_plane::core::registry::EVENT_CHANNEL_CAPACITY;
use agent_control_plane::core::types::{
    Actor, AgentId, AgentStatus, AttemptId, AttemptStatus, Event, EventBase, EventPayload, GateId,
    GateKind, GateStatus, LoopState, MessageRole, Run, RunId, RunStatus,
};
use agent_control_plane::core::{
    channel, human_action, AwaitOut, Command, CoreHandle, DelegateOut, GateOut, GateResolution,
    LeadStartOut, PlanStartOut, Reply, StatusOut, StatusQuery, STATUS_SCHEMA_VERSION,
};
use agent_control_plane::ipc::socket::{
    serve_socket, IpcError, ServerIdentity, MAX_LINE_BYTES, MAX_SOCKET_PATH_BYTES, PROTOCOL_VERSION,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use common::{
    configure_fakes, embedded_roles, head_sha, loop_task, pick, quiesce, start_actor, ActorOpts,
    LoopWorld, TICK,
};

/// How long any single wire round trip may take before the test calls it a hang. A failure
/// detector, never a timing assertion — the same 60 s `tests/common` uses, for the same reason.
const LIMIT: Duration = Duration::from_secs(60);

/// The bound on the one test that drives real (fake) provider processes.
///
/// Longer than `common::LIMIT` on purpose. Spawning the fake CLIs on this platform has a **bimodal**
/// cost that predates this file: the same work takes ~1.5 s warm and ~40-50 s in a cold run, and
/// `tests/loop_pass.rs` shows exactly the same spread (measured: 2.0 s / 42.9 s / 1.7 s for
/// `pass_reaches_an_integrate_gate_…`). A 60 s bound sits inside that spread, so this test polls the
/// durable log itself rather than borrowing one that would make a slow machine look like a broken
/// daemon.
const LIVE_LIMIT: Duration = Duration::from_secs(240);

// ---------------------------------------------------------------------------
// A door
// ---------------------------------------------------------------------------

/// A temp directory under `/tmp`, short enough that `<dir>/acp.sock` fits in `sun_path`.
///
/// `tempfile::tempdir()` honours `$TMPDIR`, which is `/var/folders/<2>/<28>/T/` on macOS — 49
/// bytes before the directory's own name. That is under the 100-byte limit but leaves no room for
/// the nesting some of these tests do, and a test that failed *because its path was too long*
/// would be indistinguishable from the bug this file exists to catch.
fn short_dir() -> TempDir {
    let dir = tempfile::Builder::new()
        .prefix("acp")
        .rand_bytes(5)
        .tempdir_in("/tmp")
        .expect("a short temp dir under /tmp");
    let socket = dir.path().join("acp.sock").into_os_string();
    assert!(
        socket.len() <= MAX_SOCKET_PATH_BYTES,
        "the fixture path is {} bytes, over the limit the daemon enforces",
        socket.len()
    );
    // `$ACP_STATE_DIR` is created 0700 by the daemon (design, § On-disk layout: "mode 0700, umask
    // 0077"); `tempfile` honours the process umask instead, so the fixture sets it here. The
    // directory mode is the load-bearing control and the socket's own 0600 is belt and braces, so a
    // test that asserted the daemon's chmod over a 0755 directory would be asserting the wrong
    // thing.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("0700 on the fixture state dir");
    dir
}

/// One running `serve_socket`, with the directory it is bound in.
struct Door {
    dir: TempDir,
    shutdown: CancellationToken,
    task: JoinHandle<Result<(), IpcError>>,
}

impl Door {
    /// Serves `core` on a fresh short path.
    fn start(core: CoreHandle, identity: ServerIdentity) -> Self {
        Self::start_in(short_dir(), core, identity)
    }

    fn start_in(dir: TempDir, core: CoreHandle, identity: ServerIdentity) -> Self {
        let shutdown = CancellationToken::new();
        let path = dir.path().join("acp.sock");
        let token = shutdown.clone();
        let task = tokio::spawn(async move { serve_socket(&path, core, identity, token).await });
        Self {
            dir,
            shutdown,
            task,
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("acp.sock")
    }

    /// Stops the door and takes its result, so a bind failure surfaces as a test failure rather
    /// than as a connect timeout.
    async fn stop(self) -> Result<(), IpcError> {
        self.shutdown.cancel();
        tokio::time::timeout(LIMIT, self.task)
            .await
            .expect("serve_socket stopped")
            .expect("the socket task did not panic")
    }
}

/// The identity a door with no repository behind it answers `hello` with.
fn fixture_identity() -> ServerIdentity {
    ServerIdentity::new(
        PathBuf::from("/fixture/repo"),
        PathBuf::from("/fixture/state"),
    )
}

// ---------------------------------------------------------------------------
// A raw client
// ---------------------------------------------------------------------------

/// One NDJSON connection, written and parsed by hand — no client library between the test and the
/// bytes.
struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next_id: i64,
    /// Notifications read while waiting for a reply, in arrival order.
    notes: Vec<Value>,
    /// How long one frame may take. [`LIMIT`] for the transport tests, [`LIVE_LIMIT`] for the one
    /// whose round trips wait on real processes and git.
    limit: Duration,
}

impl Client {
    /// Connects, retrying until the door's `bind` has happened (it runs in a spawned task).
    async fn connect(path: &Path) -> Self {
        let deadline = Instant::now() + LIMIT;
        loop {
            match UnixStream::connect(path).await {
                Ok(stream) => {
                    let (reader, writer) = stream.into_split();
                    return Self {
                        reader: BufReader::new(reader),
                        writer,
                        next_id: 1,
                        notes: Vec::new(),
                        limit: LIMIT,
                    };
                }
                Err(err) => {
                    assert!(
                        Instant::now() < deadline,
                        "never connected to {}: {err}",
                        path.display()
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// The same client, willing to wait as long as a real loop takes.
    fn patient(mut self) -> Self {
        self.limit = LIVE_LIMIT;
        self
    }

    async fn write_line(&mut self, line: &str) {
        self.writer
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("write a frame");
    }

    /// The next frame, or `None` at EOF.
    async fn frame(&mut self) -> Option<Value> {
        let mut line = String::new();
        let read = tokio::time::timeout(self.limit, self.reader.read_line(&mut line))
            .await
            .expect("a frame arrived within the limit")
            .expect("read a frame");
        if read == 0 {
            return None;
        }
        Some(
            serde_json::from_str(&line)
                .unwrap_or_else(|err| panic!("frame is JSON: {err}: {line}")),
        )
    }

    /// The next frame, failing the test if the connection ended instead.
    async fn frame_now(&mut self) -> Value {
        self.frame().await.expect("the connection is open")
    }

    /// Sends a raw line and reads frames until the reply with `id`, keeping notifications.
    async fn reply_to(&mut self, id: i64, line: &str) -> Result<Value, Value> {
        self.write_line(line).await;
        self.read_reply(id).await
    }

    /// Reads frames until the reply with `id`, keeping notifications. Split from the write so a
    /// test can do something — append an event — *inside* the window the call is open.
    async fn read_reply(&mut self, id: i64) -> Result<Value, Value> {
        loop {
            let frame = self.frame_now().await;
            if frame.get("id").and_then(Value::as_i64) == Some(id) {
                if let Some(error) = frame.get("error") {
                    return Err(error.clone());
                }
                return Ok(frame.get("result").cloned().unwrap_or(Value::Null));
            }
            self.notes.push(frame);
        }
    }

    /// One JSON-RPC call: `Ok(result)` or `Err(error object)`.
    async fn call(&mut self, method: &str, params: Value) -> Result<Value, Value> {
        let id = self.next_id;
        self.next_id += 1;
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.reply_to(id, &line.to_string()).await
    }

    /// Waits until a frame matching `pred` has been **seen** — including one already collected
    /// while waiting for an earlier reply.
    ///
    /// That distinction is the contract's, not a convenience: the door emits a `subscribe`'s
    /// backfill *before* the subscribe reply (the fan-out is the single writer, so the history is
    /// queued before the answer that describes it), so by the time a `call` returns, the frames a
    /// test is about to wait for may already be in hand.
    async fn read_until(&mut self, what: &str, mut pred: impl FnMut(&Value) -> bool) -> Value {
        if let Some(seen) = self.notes.iter().find(|note| pred(note)) {
            return seen.clone();
        }
        let deadline = Instant::now() + self.limit;
        loop {
            let frame = self.frame_now().await;
            let matched = pred(&frame);
            self.notes.push(frame.clone());
            if matched {
                return frame;
            }
            assert!(Instant::now() < deadline, "{what} never arrived");
        }
    }

    /// Every `acp.event` seen so far, as `(seq, kind)`.
    fn events(&self) -> Vec<(u64, String)> {
        self.notes
            .iter()
            .filter(|note| note["method"] == json!("acp.event"))
            .map(|note| {
                assert_eq!(
                    note["params"]["protocolVersion"],
                    json!(PROTOCOL_VERSION),
                    "every notification names the protocol it speaks: {note}"
                );
                let event = &note["params"]["event"];
                (
                    event["seq"].as_u64().expect("seq"),
                    event["kind"].as_str().expect("kind").to_string(),
                )
            })
            .collect()
    }

    fn seqs(&self) -> Vec<u64> {
        self.events().into_iter().map(|(seq, _)| seq).collect()
    }

    /// One run's seqs in **first-sighting** order — what a client that dedupes by a monotonic
    /// per-run cursor actually keeps. A repeat is dropped; an out-of-order arrival shows up as a
    /// missing seq, which is the loss the contract forbids.
    fn kept_seqs_of(&self, run: RunId) -> Vec<u64> {
        let wanted = json!(run.to_string());
        let mut kept: Vec<u64> = Vec::new();
        for note in &self.notes {
            if note["method"] != json!("acp.event") || note["params"]["event"]["runId"] != wanted {
                continue;
            }
            let seq = note["params"]["event"]["seq"].as_u64().expect("seq");
            if kept.last().is_none_or(|last| seq > *last) {
                kept.push(seq);
            }
        }
        kept
    }
}

// ---------------------------------------------------------------------------
// A core with a hand-answered mailbox
// ---------------------------------------------------------------------------

/// What the fake core was asked to do.
#[derive(Clone, PartialEq, Debug)]
enum Seen {
    Status(StatusQuery),
    CreateGate {
        kind: GateKind,
        files: Vec<String>,
        /// Whether anything that decides *what an approval commits* reached the core.
        commits_something: bool,
    },
    ResolveGate {
        gate: GateId,
        approve: bool,
        feedback: Option<String>,
        by: Actor,
    },
    AwaitResult(AgentId),
    /// T84: what `delegate`/`plan.start` handed the core, once decoded off the wire.
    Delegate { caller_run_id: Option<RunId> },
    StartPlan { caller_run_id: Option<RunId> },
    Other(&'static str),
}

/// A [`CoreHandle`] with no actor behind it: this test answers its mailbox.
///
/// It is the only way to drive the two races the contract pins — an event appended *during* a
/// `subscribe` backfill, and a broadcast buffer overrun — without a real run producing thousands of
/// events first.
struct FakeCore {
    handle: CoreHandle,
    events: broadcast::Sender<Arc<Event>>,
    /// Broadcast from inside the `Status` command, before it is answered: the backfill window.
    inject_on_status: Arc<Mutex<Vec<Arc<Event>>>>,
    /// Snapshots to hold open. A `Status` command takes one and waits on it before answering, so a
    /// test can act while a `subscribe` is provably mid-flight.
    held_snapshots: Arc<Mutex<Vec<oneshot::Receiver<()>>>>,
    seen: Arc<Mutex<Vec<Seen>>>,
    /// `await_result` replies the fake parked, exactly as the real actor parks a `Waiter`.
    parked: Arc<Mutex<Vec<Reply<AwaitOut>>>>,
    task: JoinHandle<()>,
}

impl FakeCore {
    fn start(status: StatusOut) -> Self {
        let (tx, mut rx) = channel();
        let (events, _keepalive) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let handle = CoreHandle::new(tx, events.clone());
        let status = Arc::new(Mutex::new(status));
        let inject_on_status: Arc<Mutex<Vec<Arc<Event>>>> = Arc::new(Mutex::new(Vec::new()));
        let held_snapshots: Arc<Mutex<Vec<oneshot::Receiver<()>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let parked = Arc::new(Mutex::new(Vec::new()));

        let task = {
            let (status, inject, held, seen, parked, events) = (
                Arc::clone(&status),
                Arc::clone(&inject_on_status),
                Arc::clone(&held_snapshots),
                Arc::clone(&seen),
                Arc::clone(&parked),
                events.clone(),
            );
            tokio::spawn(async move {
                while let Some(command) = rx.recv().await {
                    let (command, _admission) = command.into_unwrapped();
                    match command {
                        Command::Status { query, reply } => {
                            // Recorded *before* the hold, so a test can use it as the barrier that
                            // says "the subscribe is inside its snapshot now".
                            note(&seen, Seen::Status(query));
                            let held = lock(&held).pop();
                            if let Some(held) = held {
                                let _ = held.await;
                            }
                            // The backfill window: everything here is appended after the door
                            // attached its receiver and before it sees the snapshot.
                            for event in lock(&inject).drain(..) {
                                let _ = events.send(event);
                            }
                            let answer = lock(&status).clone();
                            let _ = reply.send(Ok(answer));
                        }
                        Command::ResolveGate {
                            gate,
                            approve,
                            feedback,
                            by,
                            reply,
                        } => {
                            note(
                                &seen,
                                Seen::ResolveGate {
                                    gate,
                                    approve,
                                    feedback: feedback.clone(),
                                    by,
                                },
                            );
                            let _ = reply.send(Ok(GateResolution::Denied { feedback }));
                        }
                        Command::AwaitResult { agent, reply } => {
                            note(&seen, Seen::AwaitResult(agent));
                            lock(&parked).push(reply);
                        }
                        Command::CreateGate { req, reply } => {
                            let payload = &req.gate.payload;
                            note(
                                &seen,
                                Seen::CreateGate {
                                    kind: req.gate.kind,
                                    files: payload.files.clone(),
                                    commits_something: payload.worktree.is_some()
                                        || payload.diff_hash.is_some()
                                        || payload.diff_path.is_some()
                                        || payload.pre_sha.is_some(),
                                },
                            );
                            let gate_id = GateId::new_v4();
                            let _ = reply.send(Ok(GateOut {
                                gate_id,
                                status: GateStatus::Pending,
                                human_action: human_action(&gate_id),
                            }));
                        }
                        Command::Delegate { req, reply } => {
                            note(
                                &seen,
                                Seen::Delegate {
                                    caller_run_id: req.caller_run_id,
                                },
                            );
                            let _ = reply.send(Ok(DelegateOut {
                                agent_id: AgentId::new_v4(),
                                run_id: req.run_id.unwrap_or_else(RunId::new_v4),
                                attempt_id: AttemptId::new_v4(),
                                status: RunStatus::Running,
                                worktree: PathBuf::from("/tmp/acp-fake-worktree"),
                            }));
                        }
                        Command::StartPlan {
                            caller_run_id,
                            reply,
                            ..
                        } => {
                            note(&seen, Seen::StartPlan { caller_run_id });
                            let _ = reply.send(Ok(PlanStartOut {
                                run_id: RunId::new_v4(),
                            }));
                        }
                        Command::LeadStart { reply, .. } => {
                            note(&seen, Seen::Other("lead.start"));
                            let _ = reply.send(Ok(LeadStartOut {
                                run_id: RunId::new_v4(),
                                agent_id: AgentId::new_v4(),
                            }));
                        }
                        Command::SendMessage { .. } => note(&seen, Seen::Other("send_message")),
                        Command::Cancel { .. } => note(&seen, Seen::Other("cancel")),
                        _ => note(&seen, Seen::Other("other")),
                    }
                }
            })
        };

        Self {
            handle,
            events,
            inject_on_status,
            held_snapshots,
            seen,
            parked,
            task,
        }
    }

    fn seen(&self) -> Vec<Seen> {
        lock(&self.seen).clone()
    }

    /// Holds the next `get_status` open. Send on the returned half to let it answer.
    fn hold_next_snapshot(&self) -> oneshot::Sender<()> {
        let (release, held) = oneshot::channel();
        lock(&self.held_snapshots).push(held);
        release
    }

    /// Waits until a `get_status` for `run` has reached the core — the barrier that says a
    /// `subscribe` is inside its snapshot and therefore delivering nothing.
    async fn await_snapshot_of(&self, run: Option<RunId>) {
        let deadline = Instant::now() + LIMIT;
        while !self
            .seen()
            .iter()
            .any(|seen| matches!(seen, Seen::Status(query) if query.run_id == run))
        {
            assert!(
                Instant::now() < deadline,
                "no get_status for {run:?} reached the core"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// One event onto the live stream, as `Registry::append` would.
    fn append(&self, run: RunId, seq: u64) {
        let _ = self.events.send(Arc::new(event(run, seq)));
    }

    async fn stop(self) {
        drop(self.handle);
        let _ = tokio::time::timeout(LIMIT, self.task).await;
    }
}

fn lock<T>(cell: &Arc<Mutex<T>>) -> std::sync::MutexGuard<'_, T> {
    cell.lock().unwrap_or_else(PoisonError::into_inner)
}

fn note(seen: &Arc<Mutex<Vec<Seen>>>, what: Seen) {
    lock(seen).push(what);
}

/// One event of `run`, with a payload cheap enough to mint two thousand of.
fn event(run: RunId, seq: u64) -> Event {
    Event {
        base: EventBase {
            seq,
            ts: format!("2026-08-24T00:00:{:02}Z", seq % 60),
            run_id: run,
        },
        payload: EventPayload::RunStatus_ {
            status: RunStatus::Running,
            reason: Some(format!("event {seq}")),
        },
    }
}

/// A `get_status` projection naming one run and the events `seqs`.
fn canned_status(run: RunId, seqs: &[u64]) -> StatusOut {
    StatusOut {
        schema_version: STATUS_SCHEMA_VERSION,
        runs: vec![Run {
            audit: None,
            execution: None,
            run_id: run,
            repo_root: PathBuf::from("/fixture/repo"),
            state_dir: PathBuf::from("/fixture/state"),
            base_ref: "HEAD".to_string(),
            base_sha: "0".repeat(40),
            task: loop_task("T40"),
            status: RunStatus::Running,
            blocked_reason: None,
            loop_state: LoopState::Building,
            created_at: "2026-08-24T00:00:00Z".to_string(),
            spend_usd: 0.0,
            agent_ids: Vec::new(),
            gate_ids: Vec::new(),
            integrated_sha: None,
            lineages: Vec::new(),
            last_seq: seqs.iter().copied().max().unwrap_or(0),
            steps: None,
        }],
        agents: Vec::new(),
        attempts: Vec::new(),
        gates: Vec::new(),
        spend_usd: 0.0,
        run_budget_usd: 15.0,
        blocked_reason: None,
        events: seqs.iter().map(|seq| event(run, *seq)).collect(),
    }
}

/// The same projection, plus a second run and its events — the shape the macOS client subscribes
/// to one run at a time.
fn plus_run(mut status: StatusOut, run: RunId, seqs: &[u64]) -> StatusOut {
    let mut second = canned_status(run, seqs);
    status.runs.append(&mut second.runs);
    status.events.append(&mut second.events);
    status
}

// ---------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------

/// The design's on-disk control: mode 0600 on the socket, inside a 0700 directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_socket_is_0600_inside_a_0700_directory() {
    let fake = FakeCore::start(canned_status(RunId::new_v4(), &[]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;
    client.call("hello", json!({})).await.expect("hello");

    let socket = std::fs::metadata(door.path()).expect("the socket file exists");
    assert_eq!(
        socket.permissions().mode() & 0o777,
        0o600,
        "the socket is owner-only"
    );
    let parent = std::fs::metadata(door.dir.path()).expect("the state dir exists");
    assert_eq!(
        parent.permissions().mode() & 0o777,
        0o700,
        "inside an owner-only directory — the load-bearing control"
    );

    door.stop().await.expect("the door stopped cleanly");
    fake.stop().await;
}

/// A path over `sun_path` is refused **before** the bind, with the remedy in the message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_socket_path_over_100_bytes_is_refused_before_binding() {
    let fake = FakeCore::start(canned_status(RunId::new_v4(), &[]));
    let dir = short_dir();
    // Nested until the whole path is over the limit, which is how a real one gets there: a deep
    // `$ACP_STATE_DIR` under a home directory with a long name.
    let mut nested = dir.path().to_path_buf();
    while nested.join("acp.sock").into_os_string().len() <= MAX_SOCKET_PATH_BYTES {
        nested = nested.join("deeper-directory-name");
    }
    std::fs::create_dir_all(&nested).expect("create the nested dirs");
    let path = nested.join("acp.sock");

    let err = serve_socket(
        &path,
        fake.handle.clone(),
        fixture_identity(),
        CancellationToken::new(),
    )
    .await
    .expect_err("a path over the limit is refused");

    assert!(matches!(err, IpcError::PathTooLong { .. }), "{err:?}");
    let message = err.to_string();
    assert!(
        message.contains("ACP_STATE_DIR") && message.contains("104"),
        "the error names the remedy and the platform limit: {message}"
    );
    assert!(!path.exists(), "nothing was bound");
    fake.stop().await;
}

/// A socket file left behind by a previous daemon is unlinked and rebound, not treated as fatal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_socket_file_is_replaced_on_the_next_serve() {
    let fake = FakeCore::start(canned_status(RunId::new_v4(), &[]));
    let dir = short_dir();
    let path = dir.path().join("acp.sock");

    let first = Door::start_in(dir, fake.handle.clone(), fixture_identity());
    Client::connect(&path).await;
    let dir = {
        first.shutdown.cancel();
        tokio::time::timeout(LIMIT, first.task)
            .await
            .expect("the first door stopped")
            .expect("no panic")
            .expect("it served");
        first.dir
    };
    assert!(path.exists(), "the socket file outlives the daemon");

    let second = Door::start_in(dir, fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&path).await;
    let hello = client.call("hello", json!({})).await.expect("hello");
    assert_eq!(hello["protocolVersion"], json!(PROTOCOL_VERSION));

    second.stop().await.expect("the second door stopped");
    fake.stop().await;
}

// ---------------------------------------------------------------------------
// hello, and the actor it records
// ---------------------------------------------------------------------------

/// `hello` answers the five fields the Swift client decodes, and the `clientName` it carries is the
/// actor every later resolution from that connection is recorded as.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hello_names_the_daemon_and_pins_the_actor_for_the_connection() {
    let fake = FakeCore::start(canned_status(RunId::new_v4(), &[]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;

    let hello = client
        .call(
            "hello",
            json!({ "clientName": "acp-mac", "clientVersion": "0.1.0" }),
        )
        .await
        .expect("hello");
    assert_eq!(hello["protocolVersion"], json!(PROTOCOL_VERSION));
    assert_eq!(hello["repoRoot"], json!("/fixture/repo"));
    assert_eq!(hello["stateDir"], json!("/fixture/state"));
    assert_eq!(hello["serverVersion"], json!(env!("CARGO_PKG_VERSION")));
    assert_eq!(hello["pid"], json!(std::process::id()));

    let gate = GateId::new_v4();
    client
        .call(
            "gate.deny",
            json!({ "gateId": gate.to_string(), "feedback": "not yet" }),
        )
        .await
        .expect("gate.deny");

    assert!(
        fake.seen().contains(&Seen::ResolveGate {
            gate,
            approve: false,
            feedback: Some("not yet".to_string()),
            by: Actor::Socket {
                client_name: "acp-mac".to_string()
            },
        }),
        "the clientName reaches the core as the resolving actor: {:?}",
        fake.seen()
    );

    // A connection that never said hello is the CLI, which is the design's default.
    let mut anonymous = Client::connect(&door.path()).await;
    let other = GateId::new_v4();
    anonymous
        .call("gate.deny", json!({ "gateId": other.to_string() }))
        .await
        .expect("gate.deny");
    assert!(
        fake.seen().contains(&Seen::ResolveGate {
            gate: other,
            approve: false,
            feedback: None,
            by: Actor::Socket {
                client_name: "cli".to_string()
            },
        }),
        "the default actor is `cli`: {:?}",
        fake.seen()
    );

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

/// `Actor` is a bare string on the wire, so a socket client that called itself `"mcp"` would forge
/// the other door's identity in the durable log. Refused at the door.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_may_not_claim_to_be_the_mcp_channel() {
    let fake = FakeCore::start(canned_status(RunId::new_v4(), &[]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;

    let err = client
        .call("hello", json!({ "clientName": "mcp" }))
        .await
        .expect_err("refused");
    assert_eq!(err["code"], json!(-32602), "{err}");

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

// ---------------------------------------------------------------------------
// Framing and the error codes
// ---------------------------------------------------------------------------

/// The four rejections a client can provoke with one line each, and the connection surviving three
/// of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_error_codes_are_the_ones_the_contract_fixes() {
    let fake = FakeCore::start(canned_status(RunId::new_v4(), &[]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;

    let err = client
        .call("no_such_method", json!({}))
        .await
        .expect_err("unknown method");
    assert_eq!(err["code"], json!(-32601), "{err}");

    // Malformed JSON: answered `-32700` with a null id, and the connection keeps going.
    client.write_line("{not json").await;
    let frame = client.frame_now().await;
    assert_eq!(frame["error"]["code"], json!(-32700), "{frame}");
    assert_eq!(frame["id"], Value::Null);

    // A well-formed line that is not a JSON-RPC 2.0 request.
    client
        .write_line(r#"{"jsonrpc":"1.0","id":99,"method":"hello"}"#)
        .await;
    let frame = client.frame_now().await;
    assert_eq!(frame["error"]["code"], json!(-32600), "{frame}");
    assert_eq!(frame["id"], json!(99), "the id is echoed when there is one");

    // Params of the wrong shape.
    let err = client
        .call("get_status", json!({ "lastEvents": "twenty" }))
        .await
        .expect_err("invalid params");
    assert_eq!(err["code"], json!(-32602), "{err}");

    // A bound the projection enforces, reported as invalid params rather than silently clamped.
    let err = client
        .call("get_status", json!({ "lastEvents": 1000 }))
        .await
        .expect_err("over the bound");
    assert_eq!(err["code"], json!(-32602), "{err}");

    for message in [String::new(), "x".repeat(20_001)] {
        let err = client
            .call("lead.start", json!({ "message": message }))
            .await
            .expect_err("lead.start enforces the shared message bound at the socket");
        assert_eq!(err["code"], json!(-32602), "{err}");
    }
    for message in ["x".to_string(), "x".repeat(20_000)] {
        let answer = client
            .call("lead.start", json!({ "message": message }))
            .await
            .expect("the exact message boundaries are accepted");
        assert!(answer["runId"].as_str().is_some());
        assert!(answer["agentId"].as_str().is_some());
    }

    // Still alive after all four.
    let hello = client.call("hello", json!({})).await.expect("hello");
    assert_eq!(hello["protocolVersion"], json!(PROTOCOL_VERSION));

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

/// A line over 1 MiB is rejected by the codec while it streams: that connection is answered
/// `-32700` and closed, and **no other connection is affected**.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_over_long_line_closes_only_its_own_connection() {
    let fake = FakeCore::start(canned_status(RunId::new_v4(), &[]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut bystander = Client::connect(&door.path()).await;
    bystander.call("hello", json!({})).await.expect("hello");

    let mut flooder = Client::connect(&door.path()).await;
    let chunk = "x".repeat(64 * 1024);
    let mut written = 0usize;
    while written <= MAX_LINE_BYTES {
        // The daemon closes as soon as the limit is passed, so the tail of this write may fail with
        // EPIPE — which is the behaviour under test, not a failure of it.
        if flooder.writer.write_all(chunk.as_bytes()).await.is_err() {
            break;
        }
        written += chunk.len();
    }
    let _ = flooder.writer.write_all(b"\n").await;

    let refusal = flooder
        .read_until("the -32700 refusal", |frame| frame.get("error").is_some())
        .await;
    assert_eq!(refusal["error"]["code"], json!(-32700), "{refusal}");
    assert!(
        flooder.frame().await.is_none(),
        "and the connection is closed rather than kept with a megabyte of buffer"
    );

    let hello = bystander
        .call("hello", json!({ "clientName": "bystander" }))
        .await
        .expect("the other connection is untouched");
    assert_eq!(hello["protocolVersion"], json!(PROTOCOL_VERSION));

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

// ---------------------------------------------------------------------------
// subscribe — the three pinned semantics, and the one race
// ---------------------------------------------------------------------------

/// Semantics (3): `subscribe{runId: nil, sinceSeq: nil}` performs **no** backfill, and answers the
/// newest `seq` the daemon knows so the client can come back with a cursor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscribe_without_a_cursor_backfills_nothing() {
    let run = RunId::new_v4();
    let fake = FakeCore::start(canned_status(run, &[1, 2, 3]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;

    let subscribed = client
        .call("subscribe", json!({}))
        .await
        .expect("subscribe");
    assert_eq!(subscribed["ok"], json!(true));
    assert_eq!(subscribed["protocolVersion"], json!(PROTOCOL_VERSION));
    assert_eq!(subscribed["lastSeq"], json!(3));

    // Frames are written in order, so a backfill would have to precede this reply.
    client.call("hello", json!({})).await.expect("hello");
    assert!(
        client.events().is_empty(),
        "no history was replayed: {:?}",
        client.events()
    );

    // The live stream is attached all the same.
    fake.append(run, 4);
    client
        .read_until("the live event", |frame| {
            frame["method"] == json!("acp.event")
        })
        .await;
    assert_eq!(client.seqs(), vec![4]);

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

/// Semantics (1): `runId` scopes the **backfill** only — the live stream is every run's, so a
/// subscriber learns about runs that did not exist when it subscribed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_scoped_subscribe_still_sees_every_run_live() {
    let mine = RunId::new_v4();
    let other = RunId::new_v4();
    let mut status = canned_status(mine, &[1, 2, 3]);
    // A second run's events are in the same projection; only `mine` may be replayed.
    status.events.push(event(other, 7));
    let fake = FakeCore::start(status);
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;

    let subscribed = client
        .call(
            "subscribe",
            json!({ "runId": mine.to_string(), "sinceSeq": 1 }),
        )
        .await
        .expect("subscribe");
    assert_eq!(subscribed["lastSeq"], json!(3));

    client
        .read_until("the last backfilled event", |frame| {
            frame["params"]["event"]["seq"] == json!(3)
        })
        .await;
    assert_eq!(
        client.seqs(),
        vec![2, 3],
        "the backfill is scoped to the run and starts after the cursor"
    );

    // …and then a different run's event arrives on the same connection.
    let _ = fake.events.send(Arc::new(event(other, 8)));
    client
        .read_until("the other run's event", |frame| {
            frame["params"]["event"]["runId"] == json!(other.to_string())
        })
        .await;

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

/// **The one race the contract pins.** An event appended while the backfill snapshot is being taken
/// must be delivered — twice is allowed, lost is not.
///
/// The fake core broadcasts it from *inside* the `Status` command, which is exactly the window: the
/// door has attached its receiver, and the snapshot it is about to be handed does not contain the
/// event. A door that attached its receiver after the snapshot would drop it, and this test is the
/// only thing that can tell.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_event_appended_during_the_backfill_window_is_delivered() {
    let run = RunId::new_v4();
    let fake = FakeCore::start(canned_status(run, &[1, 2, 3]));
    lock(&fake.inject_on_status).push(Arc::new(event(run, 4)));

    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;

    client
        .call(
            "subscribe",
            json!({ "runId": run.to_string(), "sinceSeq": 1 }),
        )
        .await
        .expect("subscribe");

    client
        .read_until("the event appended during the backfill", |frame| {
            frame["params"]["event"]["seq"] == json!(4)
        })
        .await;

    let mut seqs = client.seqs();
    seqs.dedup();
    assert_eq!(
        seqs,
        vec![2, 3, 4],
        "the backfill comes first, in seq order, and the racing event follows it"
    );

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

/// Semantics (2): a second `subscribe` **replaces** this connection's receiver rather than adding
/// one — so `acp.lagged` recovery never doubles the stream — and nothing the replaced receiver was
/// holding is dropped on the way.
///
/// The fan-out has to be **stalled** for the second half to mean anything: while it is draining
/// freely, the receiver a replacement discards is always empty. So this client stops reading until
/// the connection's outbox and the kernel buffer are both full, which is what leaves events sitting
/// in the receiver the second `subscribe` is about to replace.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeated_subscribe_replaces_the_receiver_without_losing_events() {
    let run = RunId::new_v4();
    let fake = FakeCore::start(canned_status(run, &[]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;

    client.call("subscribe", json!({})).await.expect("first");
    // Enough to fill an 8 KiB socket buffer and a 32-line outbox several times over.
    let stalled = 400u64;
    for seq in 1..=stalled + 3 {
        fake.append(run, seq);
    }

    // The re-`subscribe` an `acp.lagged` recovery performs. Waiting for its reply is what starts
    // the client reading again, so the fan-out unblocks with the replacement already queued.
    client.call("subscribe", json!({})).await.expect("second");
    for seq in stalled + 4..=stalled + 6 {
        fake.append(run, seq);
    }

    client
        .read_until("the last event", |frame| {
            frame["params"]["event"]["seq"] == json!(stalled + 6)
        })
        .await;
    let mut seqs = client.seqs();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(
        seqs,
        (1..=stalled + 6).collect::<Vec<u64>>(),
        "nothing the replaced receiver was holding was dropped"
    );

    // And the connection holds **one** receiver, not two: the seam may duplicate an event, but a
    // second subscribe must not double the stream from then on.
    let deadline = Instant::now() + LIMIT;
    while fake.events.receiver_count() != 1 {
        assert!(
            Instant::now() < deadline,
            "the connection is holding {} receivers after two subscribes",
            fake.events.receiver_count()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

/// **The ordering the client's dedupe depends on.** A per-run `subscribe` on a connection that
/// already holds a receiver must not have its backfill overtaken by a *newer live event of the same
/// run* — the client dedupes with a monotonic per-run cursor, so an arrival order of `54, 51, 52,
/// 53` is not "delivered twice", it is `51-53` **lost**.
///
/// This is the macOS client's connect and lag-recovery path: `get_status`, then one `subscribe` per
/// run, with the live stream (which is not run-filtered) flowing the whole time.
///
/// The window is made deterministic rather than raced for: the fake core holds the `subscribe`'s
/// snapshot open, the test waits until that snapshot has provably been entered, and only then
/// appends `B:54`. With the door's subscribe served by the fan-out — the single writer — the event
/// cannot be delivered while the snapshot is in flight, so the backfill goes first. With it served
/// in the request task, the fan-out is free to deliver `54` in exactly that window (mutation-checked
/// in review: reverting the single writer turns this red).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backfill_is_never_overtaken_by_a_newer_live_event_of_the_same_run() {
    let a = RunId::new_v4();
    let b = RunId::new_v4();
    let fake = FakeCore::start(plus_run(canned_status(a, &[100]), b, &[51, 52, 53]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;

    // The connection already has a receiver — this is the app's *second* per-run subscribe.
    client
        .call(
            "subscribe",
            json!({ "runId": a.to_string(), "sinceSeq": 100 }),
        )
        .await
        .expect("subscribe A");

    let release = fake.hold_next_snapshot();
    client
        .write_line(
            &json!({
                "jsonrpc": "2.0",
                "id": 77,
                "method": "subscribe",
                "params": { "runId": b.to_string(), "sinceSeq": 50 },
            })
            .to_string(),
        )
        .await;
    fake.await_snapshot_of(Some(b)).await;

    // Inside the window: B:54 lands in the receiver this subscribe is about to replace.
    fake.append(b, 54);
    release.send(()).expect("release the snapshot");

    client.read_reply(77).await.expect("subscribe B");
    client
        .read_until("B:54", |frame| {
            frame["params"]["event"]["runId"] == json!(b.to_string())
                && frame["params"]["event"]["seq"] == json!(54)
        })
        .await;

    assert_eq!(
        client.kept_seqs_of(b),
        vec![51, 52, 53, 54],
        "the backfill arrived before the newer live event, so a client that dedupes by a \
         monotonic per-run cursor keeps all of it"
    );

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

/// The same ordering, across a real `acp.lagged` recovery: the client is dropped by the daemon,
/// re-`subscribe`s that run with the cursor from its own snapshot, and the replay must still not be
/// overtaken by a newer event of the same run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lag_recovery_resubscribe_is_not_overtaken_either() {
    let a = RunId::new_v4();
    let b = RunId::new_v4();
    let fake = FakeCore::start(plus_run(canned_status(a, &[100]), b, &[51, 52, 53]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;
    client
        .call("subscribe", json!({}))
        .await
        .expect("subscribe");

    // Stall, overrun the broadcast buffer, and be told.
    let flood = u64::try_from(EVENT_CHANNEL_CAPACITY).expect("capacity fits") * 2;
    for seq in 1..=flood {
        fake.append(a, seq);
    }
    client
        .read_until("acp.lagged", |frame| frame["method"] == json!("acp.lagged"))
        .await;
    // Drain the rest of the flood before the recovery, so the fan-out is not blocked on a full
    // outbox when the re-`subscribe` arrives — the tail of the flood is the barrier for that.
    client
        .read_until("the tail of the flood", |frame| {
            frame["params"]["event"]["runId"] == json!(a.to_string())
                && frame["params"]["event"]["seq"] == json!(flood)
        })
        .await;

    // The prescribed recovery: re-`get_status`, then re-`subscribe` per run from its cursor.
    let release = fake.hold_next_snapshot();
    client
        .write_line(
            &json!({
                "jsonrpc": "2.0",
                "id": 88,
                "method": "subscribe",
                "params": { "runId": b.to_string(), "sinceSeq": 50 },
            })
            .to_string(),
        )
        .await;
    fake.await_snapshot_of(Some(b)).await;
    fake.append(b, 54);
    release.send(()).expect("release the snapshot");

    client.read_reply(88).await.expect("subscribe B");
    client
        .read_until("B:54", |frame| {
            frame["params"]["event"]["runId"] == json!(b.to_string())
                && frame["params"]["event"]["seq"] == json!(54)
        })
        .await;
    assert_eq!(
        client.kept_seqs_of(b),
        vec![51, 52, 53, 54],
        "the recovery replay was not overtaken"
    );

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

/// Backpressure: a subscriber that stops reading is **lagged, not buffered**. It is told once, from
/// the newest `seq` it was actually given, and the connection stays up so it can recover.
///
/// The stall is real — this client simply does not read — so the kernel buffer fills, the
/// connection's outbox fills, the fan-out stops draining, and the daemon's 1 024-slot broadcast
/// buffer overruns. That is the whole backpressure chain, in order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_subscriber_is_lagged_and_keeps_its_connection() {
    let run = RunId::new_v4();
    let fake = FakeCore::start(canned_status(run, &[]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;
    client
        .call("subscribe", json!({}))
        .await
        .expect("subscribe");

    let flood = u64::try_from(EVENT_CHANNEL_CAPACITY).expect("capacity fits") * 2;
    for seq in 1..=flood {
        fake.append(run, seq);
    }

    let lagged = client
        .read_until("acp.lagged", |frame| frame["method"] == json!("acp.lagged"))
        .await;
    assert_eq!(
        lagged["params"]["protocolVersion"],
        json!(PROTOCOL_VERSION),
        "{lagged}"
    );
    let from_seq = lagged["params"]["fromSeq"].as_u64().expect("fromSeq");
    assert!(
        from_seq > 0 && from_seq < flood,
        "fromSeq is the newest seq this client was given: {from_seq}"
    );

    // The connection is not the casualty — dropping history is.
    let hello = client.call("hello", json!({})).await.expect("still alive");
    assert_eq!(hello["protocolVersion"], json!(PROTOCOL_VERSION));

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

// ---------------------------------------------------------------------------
// The doors themselves
// ---------------------------------------------------------------------------

/// `resolve_gate` over the socket is **deny-only**, exactly as over MCP: there is one approving
/// door in the system and it is called `gate.approve`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resolve_gate_over_the_socket_can_only_deny() {
    let fake = FakeCore::start(canned_status(RunId::new_v4(), &[]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;

    let gate = GateId::new_v4();
    let err = client
        .call(
            "resolve_gate",
            json!({ "gateId": gate.to_string(), "approve": true }),
        )
        .await
        .expect_err("an approval through resolve_gate is refused");
    assert_eq!(err["code"], json!(-32000), "{err}");
    assert_eq!(err["data"]["code"], json!("agent_approve_not_allowed"));
    assert!(
        fake.seen().is_empty(),
        "and nothing reached the core: a rejection has no side effects — {:?}",
        fake.seen()
    );

    // The same call denying is the door's job and goes straight through.
    let denied = client
        .call(
            "resolve_gate",
            json!({ "gateId": gate.to_string(), "approve": false, "feedback": "no" }),
        )
        .await
        .expect("a denial is allowed");
    assert_eq!(denied["status"], json!("denied"));

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

/// The gate payload a socket client may mint is **closed to `files`**.
///
/// `worktree`, `diffPath`, `diffHash` and `preSha` are what tell an approval *what to commit*, and
/// this is the door that can also approve. Only the control plane's own loop sets them, from a diff
/// it froze and a verdict bound to it; a caller that could name a worktree could mint an `integrate`
/// gate over a tree nobody reviewed and then approve it (adversarial review of T39). The MCP door
/// closes the same shape, so the two doors agree.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_gate_payload_a_client_may_mint_is_closed_to_files() {
    let run = RunId::new_v4();
    let fake = FakeCore::start(canned_status(run, &[]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;

    let request = |payload: Value| {
        json!({
            "runId": run.to_string(),
            "kind": "integrate",
            "summary": "please look at this",
            "payload": payload,
        })
    };

    // Anything that decides what an approval commits is not a field of this door's vocabulary.
    for forbidden in [
        json!({ "worktree": "/tmp/somebody-elses-tree" }),
        json!({ "diffHash": "0".repeat(64) }),
        json!({ "diffPath": "/tmp/a.diff" }),
        json!({ "preSha": "0".repeat(40) }),
        json!({ "spendUsd": 99.0 }),
        json!({ "files": ["src/a.ts"], "worktree": "/tmp/t" }),
    ] {
        let Err(err) = client
            .call("request_human_gate", request(forbidden.clone()))
            .await
        else {
            panic!("a payload naming what to commit was accepted: {forbidden}");
        };
        assert_eq!(err["code"], json!(-32602), "{forbidden} -> {err}");
    }

    // …and `files` itself is bounded and path-checked, like every other caller-supplied path list.
    let oversize: Vec<String> = (0..=100).map(|n| format!("src/f{n}.ts")).collect();
    for bad in [
        json!({ "files": oversize }),
        json!({ "files": ["../../etc/passwd"] }),
        json!({ "files": ["/etc/passwd"] }),
        json!({ "files": ["src/a\nb.ts"] }),
        json!({ "files": [""] }),
    ] {
        let Err(err) = client
            .call("request_human_gate", request(bad.clone()))
            .await
        else {
            panic!("an unbounded or escaping files list was accepted: {bad}");
        };
        assert_eq!(err["code"], json!(-32602), "{bad} -> {err}");
    }

    assert!(
        fake.seen().is_empty(),
        "every refusal happened at the door, with nothing reaching the core: {:?}",
        fake.seen()
    );

    // The shape that is allowed goes through, and reaches the core carrying `files` and nothing
    // that could authorise a commit.
    let out = client
        .call(
            "request_human_gate",
            request(json!({ "files": ["src/adder.ts"] })),
        )
        .await
        .expect("a files-only payload is accepted");
    assert_eq!(out["status"], json!("pending"), "{out}");
    assert!(out["humanAction"]
        .as_str()
        .is_some_and(|action| action.contains("gate approve")));
    assert_eq!(
        fake.seen(),
        vec![Seen::CreateGate {
            kind: GateKind::Integrate,
            files: vec!["src/adder.ts".to_string()],
            commits_something: false,
        }]
    );

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

/// A clean shutdown tells every live connection why, before the socket closes under it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clean_shutdown_notifies_every_connection() {
    let fake = FakeCore::start(canned_status(RunId::new_v4(), &[]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;
    client.call("hello", json!({})).await.expect("hello");
    let mut subscriber = Client::connect(&door.path()).await;
    subscriber
        .call("subscribe", json!({}))
        .await
        .expect("subscribe");

    door.shutdown.cancel();

    for (name, client) in [("plain", &mut client), ("subscribed", &mut subscriber)] {
        let notice = client
            .read_until("acp.shutdown", |frame| {
                frame["method"] == json!("acp.shutdown")
            })
            .await;
        assert_eq!(
            notice["params"]["protocolVersion"],
            json!(PROTOCOL_VERSION),
            "{name}: {notice}"
        );
        assert!(
            notice["params"]["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty()),
            "{name}: the notice says why: {notice}"
        );
        assert!(
            client.frame().await.is_none(),
            "{name}: and the connection then closes"
        );
    }

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

/// A client that disappears mid-`await_result` drops the `oneshot` receiver the actor parked, and
/// disturbs nothing else: the next connection is answered normally.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_disconnects_mid_await_result_disturbs_nothing() {
    let run = RunId::new_v4();
    let fake = FakeCore::start(canned_status(run, &[1]));
    let door = Door::start(fake.handle.clone(), fixture_identity());

    let agent = AgentId::new_v4();
    {
        let mut client = Client::connect(&door.path()).await;
        client
            .write_line(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "await_result",
                    "params": { "agentId": agent.to_string(), "timeoutSec": 300 },
                })
                .to_string(),
            )
            .await;
        // The fake parks the reply exactly as the actor parks a `Waiter`; then the client vanishes.
        let deadline = Instant::now() + LIMIT;
        while !fake.seen().contains(&Seen::AwaitResult(agent)) {
            assert!(Instant::now() < deadline, "the call never reached the core");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // The parked reply is released — the door's request task was aborted with the connection, which
    // is what drops the receiver the actor holds.
    let deadline = Instant::now() + LIMIT;
    loop {
        let closed = lock(&fake.parked).iter().all(Reply::is_closed);
        if closed && !lock(&fake.parked).is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the parked await_result reply outlived its connection"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut fresh = Client::connect(&door.path()).await;
    let status = fresh
        .call("get_status", json!({}))
        .await
        .expect("a fresh connection is answered normally");
    assert_eq!(status["schemaVersion"], json!(STATUS_SCHEMA_VERSION));
    assert_eq!(status["runs"][0]["runId"], json!(run.to_string()));

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

/// Every door answers `-32001` — never stale state — once the actor is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dead_core_is_minus_32001_on_every_door() {
    let fake = FakeCore::start(canned_status(RunId::new_v4(), &[]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;
    client.call("hello", json!({})).await.expect("hello");

    fake.task.abort();
    let _ = tokio::time::timeout(LIMIT, fake.task).await;

    let err = client
        .call("get_status", json!({}))
        .await
        .expect_err("the actor is gone");
    assert_eq!(err["code"], json!(-32001), "{err}");
    assert_eq!(err["data"]["code"], json!("core_unavailable"));

    // `hello` is the one method that does not need the core, and it still answers — which is what
    // lets a client tell "the daemon is wedged" from "there is no daemon".
    client.call("hello", json!({})).await.expect("hello");

    door.stop().await.expect("the door stopped");
}

// ---------------------------------------------------------------------------
// End to end: conversational lead and human approval, over the wire
// ---------------------------------------------------------------------------

/// The socket-only entry point preserves the human message in `run.created`, and the existing
/// `send_message` method resumes the same lead session after its first free-text turn succeeds.
#[test]
fn lead_start_echoes_the_human_message_and_send_message_resumes_the_lead() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("lead_chat", &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();
        let door = Door::start(
            handle.clone(),
            ServerIdentity::new(
                world.repo_root().to_path_buf(),
                world.state_dir().to_path_buf(),
            ),
        );
        let mut client = Client::connect(&door.path()).await.patient();
        client
            .call("hello", json!({ "clientName": "acp-mac" }))
            .await
            .expect("hello");

        let first_message = "Inspect this repository and coordinate the next safe step.";
        let started = client
            .call("lead.start", json!({ "message": first_message }))
            .await
            .expect("lead.start");
        assert_eq!(started.as_object().map(serde_json::Map::len), Some(2));
        let run: RunId = started["runId"]
            .as_str()
            .expect("runId")
            .parse()
            .expect("run UUID");
        let agent: AgentId = started["agentId"]
            .as_str()
            .expect("agentId")
            .parse()
            .expect("agent UUID");

        let first = poll_status(
            &handle,
            run,
            "the first lead turn to become idle",
            |status| {
                status.agents.iter().any(|summary| {
                    summary.agent_id == agent && summary.process_state == AgentStatus::Idle
                }) && status.attempts.iter().any(|attempt| {
                    attempt.agent_id == agent && attempt.status == AttemptStatus::Succeeded
                })
            },
        )
        .await;
        let run_view = first.runs.first().expect("lead run");
        assert_eq!(run_view.task.id, "lead");
        assert_eq!(run_view.task.title, "Lead conversation");
        assert_eq!(run_view.task.description, first_message);
        assert!(run_view.task.files.is_empty());
        assert!(run_view.task.acceptance.is_empty());

        // While another lead owns the slot, a follow-up to this idle session is refused too. The
        // slot is repository-wide, not merely a guard on `lead.start`.
        configure_fakes(world.repo_root(), "hang", &[]);
        let exercise_handle = handle.clone();
        let repo_root = world.repo_root().to_path_buf();
        let follow_up = "Now summarize the highest-priority unfinished item.".to_string();
        let follow_up_for_task = follow_up.clone();
        let exercise = tokio::spawn(async move {
            let competing = client
                .call("lead.start", json!({ "message": "Hold the lead slot." }))
                .await
                .expect("competing lead starts");
            let competing_run: RunId = competing["runId"].as_str().unwrap().parse().unwrap();
            let competing_agent: AgentId = competing["agentId"].as_str().unwrap().parse().unwrap();
            poll_status(
                &exercise_handle,
                competing_run,
                "the competing lead to run",
                |status| {
                    status.attempts.iter().any(|attempt| {
                        attempt.agent_id == competing_agent
                            && attempt.status == AttemptStatus::Running
                    })
                },
            )
            .await;
            let busy = client
                .call(
                    "send_message",
                    json!({ "agentId": agent.to_string(), "message": "overlap" }),
                )
                .await
                .expect_err("a follow-up cannot bypass the live-lead slot");
            assert_eq!(busy["data"]["code"], json!("lead_busy"), "{busy}");
            assert_eq!(
                client
                    .call("cancel", json!({ "agentId": competing_agent.to_string() }))
                    .await
                    .expect("cancel competing lead")["status"],
                json!("cancelled")
            );
            poll_status(
                &exercise_handle,
                competing_run,
                "the competing lead cancellation to finish",
                |status| {
                    status.attempts.iter().any(|attempt| {
                        attempt.agent_id == competing_agent
                            && attempt.status == AttemptStatus::Cancelled
                    })
                },
            )
            .await;

            configure_fakes(&repo_root, "lead_chat", &[]);
            let resumed = client
                .call(
                    "send_message",
                    json!({ "agentId": agent.to_string(), "message": follow_up_for_task }),
                )
                .await
                .expect("send_message accepts the idle lead once the slot is free");
            assert_eq!(resumed["accepted"], json!(true));
            assert!(resumed["attemptId"].as_str().is_some());
            poll_status(
                &exercise_handle,
                run,
                "the resumed lead turn to succeed",
                |status| {
                    status
                        .attempts
                        .iter()
                        .filter(|attempt| {
                            attempt.agent_id == agent && attempt.status == AttemptStatus::Succeeded
                        })
                        .count()
                        == 2
                },
            )
            .await;
        })
        .await;

        if exercise.is_ok() {
            let events = world.events(&run);
            let starts: Vec<&Vec<String>> = events
                .iter()
                .filter_map(|event| match &event.payload {
                    EventPayload::AttemptStarted { agent_id, argv, .. } if *agent_id == agent => {
                        Some(argv)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(starts.len(), 2, "one fresh turn and one resumed turn");
            assert_eq!(starts[0].get(1).map(String::as_str), Some(first_message));
            assert_eq!(
                starts[1].get(1).map(String::as_str),
                Some(follow_up.as_str())
            );
            assert!(starts[1].iter().any(|arg| arg == "--resume"));

            // The transcript's other half (B3 walkthrough fix): the accepted follow-up is a
            // durable `agent.message{role:"user"}` on the lead's run. The `lead_busy` refusal
            // recorded nothing, and the first message stays `run.created` alone.
            let user_turns: Vec<(&str, u64)> = events
                .iter()
                .filter_map(|event| match &event.payload {
                    EventPayload::AgentMessage {
                        role: MessageRole::User,
                        text,
                        src_line,
                        ..
                    } => Some((text.as_str(), *src_line)),
                    _ => None,
                })
                .collect();
            assert_eq!(
                user_turns,
                [(follow_up.as_str(), 0)],
                "exactly the accepted follow-up — never the refused overlap or the first message"
            );
        }

        quiesce(&handle).await;
        door.stop().await.expect("the door stopped");
        actor.stop().await;
        exercise.expect("lead-slot and follow-up assertions");
    });
}

/// Exactly one provider attempt may hold the conversational lead slot. The refusal identifies the
/// live agent, and the ordinary cancellation path releases the slot for a new run.
#[test]
fn a_running_lead_is_busy_until_cancel_releases_the_slot() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("hang", &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();
        let door = Door::start(
            handle.clone(),
            ServerIdentity::new(
                world.repo_root().to_path_buf(),
                world.state_dir().to_path_buf(),
            ),
        );
        let mut client = Client::connect(&door.path()).await.patient();

        // Keep cleanup outside the assertion task. If any assertion panics, its JoinError is held
        // until `quiesce` has terminated every detached fake provider this test started.
        let exercise_handle = handle.clone();
        let exercise = tokio::spawn(async move {
            let first = client
                .call(
                    "lead.start",
                    json!({ "message": "Coordinate the first turn." }),
                )
                .await
                .expect("first lead starts");
            let first_run: RunId = first["runId"].as_str().unwrap().parse().unwrap();
            let first_agent: AgentId = first["agentId"].as_str().unwrap().parse().unwrap();
            poll_status(
                &exercise_handle,
                first_run,
                "the first lead attempt to run",
                |status| {
                    status.attempts.iter().any(|attempt| {
                        attempt.agent_id == first_agent && attempt.status == AttemptStatus::Running
                    })
                },
            )
            .await;

            let busy = client
                .call("lead.start", json!({ "message": "Race a second lead." }))
                .await
                .expect_err("a live lead owns the repository slot");
            assert_eq!(busy["code"], json!(-32000), "{busy}");
            assert_eq!(busy["data"]["code"], json!("lead_busy"), "{busy}");
            assert_eq!(
                busy["data"]["agentId"],
                json!(first_agent.to_string()),
                "the refusal names the live lead"
            );

            let cancelled = client
                .call("cancel", json!({ "agentId": first_agent.to_string() }))
                .await
                .expect("cancel live lead");
            assert_eq!(cancelled["status"], json!("cancelled"));
            poll_status(
                &exercise_handle,
                first_run,
                "the cancelled attempt to become terminal",
                |status| {
                    status.attempts.iter().any(|attempt| {
                        attempt.agent_id == first_agent
                            && attempt.status == AttemptStatus::Cancelled
                    })
                },
            )
            .await;

            let next = client
                .call(
                    "lead.start",
                    json!({ "message": "Coordinate after cancellation." }),
                )
                .await
                .expect("the released slot accepts a new lead");
            let next_run: RunId = next["runId"].as_str().unwrap().parse().unwrap();
            let next_agent: AgentId = next["agentId"].as_str().unwrap().parse().unwrap();
            assert_ne!(next_agent, first_agent);
            poll_status(
                &exercise_handle,
                next_run,
                "the replacement lead attempt to run",
                |status| {
                    status.attempts.iter().any(|attempt| {
                        attempt.agent_id == next_agent && attempt.status == AttemptStatus::Running
                    })
                },
            )
            .await;
        })
        .await;

        quiesce(&handle).await;
        door.stop().await.expect("the door stopped");
        actor.stop().await;
        exercise.expect("busy/cancel assertions");
    });
}

/// The whole human path over the socket: `hello` → `subscribe` → `delegate` → the loop's own
/// reviewer and integrate gate → `resolve_gate{approve:true}` **refused** → `gate.approve`
/// **committing**.
///
/// This is the test that cannot be faked. `gates::run_commit` re-freezes the worktree and refuses
/// unless it still hashes to the `diffHash` the reviewer echoed, so a `sha` coming back over the
/// wire proves the whole chain agreed — and the `resolvedBy` in the durable log proves the daemon
/// recorded *which* human client did it.
#[test]
fn the_socket_drives_a_pass_loop_from_delegate_to_an_approved_commit() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();
        let door = Door::start(
            handle.clone(),
            ServerIdentity::new(
                world.repo_root().to_path_buf(),
                world.state_dir().to_path_buf(),
            ),
        );
        let mut client = Client::connect(&door.path()).await.patient();

        let hello = client
            .call(
                "hello",
                json!({ "clientName": "acp-mac", "clientVersion": "0.1.0" }),
            )
            .await
            .expect("hello");
        assert_eq!(hello["protocolVersion"], json!(PROTOCOL_VERSION));
        assert_eq!(hello["repoRoot"], json!(world.repo_root()));
        assert_eq!(hello["stateDir"], json!(world.state_dir()));

        // No cursor, so no backfill — and every event of every run from here on.
        let subscribed = client
            .call("subscribe", json!({}))
            .await
            .expect("subscribe");
        assert_eq!(subscribed["ok"], json!(true));

        let task = loop_task("T40-socket");
        let delegated = client
            .call(
                "delegate",
                json!({
                    "role": "builder",
                    "session": "fresh",
                    "task": {
                        "id": task.id,
                        "title": task.title,
                        "description": task.description,
                        "files": task.files,
                        "acceptance": task.acceptance,
                    },
                }),
            )
            .await
            .expect("delegate");
        assert_eq!(delegated["status"], json!("running"));
        let run: RunId = delegated["runId"]
            .as_str()
            .expect("runId")
            .parse()
            .expect("a uuid");
        let worktree = PathBuf::from(delegated["worktree"].as_str().expect("worktree"));

        // `get_status` over the wire is the projection a direct `CoreHandle` call answers with.
        // `delegate` answers *before* `run.created` — the worktree helper appends it — so the run
        // is waited for on the durable projection rather than assumed present.
        let direct = poll_status(&handle, run, "the run reaches the projection", |status| {
            !status.runs.is_empty()
        })
        .await;
        let over_socket = client
            .call("get_status", json!({ "runId": run.to_string() }))
            .await
            .expect("get_status");
        assert_eq!(over_socket["schemaVersion"], json!(STATUS_SCHEMA_VERSION));
        assert_eq!(
            over_socket["runs"][0]["runId"],
            json!(direct.runs[0].run_id.to_string())
        );
        assert_eq!(
            over_socket["runBudgetUsd"],
            json!(direct.run_budget_usd),
            "the same projection, not a re-derived one"
        );

        // The loop starts the reviewer and opens the gate by itself.
        let events = poll_log(&world, run, "gate.created{integrate}", |events| {
            !integrate_gates(events).is_empty()
        })
        .await;
        let gate = integrate_gates(&events)[0];

        // S2 over this transport too: the approving door is `gate.approve`, and only it.
        let refused = client
            .call(
                "resolve_gate",
                json!({ "gateId": gate.to_string(), "approve": true }),
            )
            .await
            .expect_err("resolve_gate may not approve");
        assert_eq!(refused["code"], json!(-32000), "{refused}");
        assert_eq!(refused["data"]["code"], json!("agent_approve_not_allowed"));
        let pending = handle
            .status(StatusQuery {
                run_id: Some(run),
                ..StatusQuery::default()
            })
            .await
            .expect("status");
        assert_eq!(
            pending.gates[0].status,
            GateStatus::Pending,
            "the refusal left the gate untouched"
        );

        let approved = client
            .call("gate.approve", json!({ "gateId": gate.to_string() }))
            .await
            .expect("gate.approve");
        assert_eq!(approved["status"], json!("approved"), "{approved}");
        let sha = approved["sha"].as_str().expect("the integration sha");

        assert_eq!(
            head_sha(&worktree),
            sha,
            "the reply carries the commit the approval made — it waited for the commit helper"
        );
        let events = world.events(&run);
        assert_eq!(
            pick(&events, |payload| match payload {
                EventPayload::IntegrateCommitted { sha, .. } => Some(sha.clone()),
                _ => None,
            }),
            vec![sha.to_string()],
            "exactly one integrate.committed, and it is the sha the socket answered with"
        );
        assert_eq!(
            pick(&events, |payload| match payload {
                EventPayload::GateResolving { by, .. } => Some(by.to_string()),
                _ => None,
            }),
            vec!["acp-mac".to_string()],
            "the log records which human client approved"
        );
        assert_eq!(
            pending_gate(&handle, run).await.resolved_by,
            Some(Actor::Socket {
                client_name: "acp-mac".to_string()
            }),
            "and the projection a later `get_status` answers with says the same"
        );

        // The subscriber was told about the commit on the stream as well as in the reply — the
        // notification is pushed, not polled for.
        client
            .read_until("integrate.committed on the event stream", |frame| {
                frame["params"]["event"]["kind"] == json!("integrate.committed")
            })
            .await;
        // And everything it was told arrived in `seq` order, each frame naming its protocol
        // version (asserted for every frame in `Client::events`).
        let seqs = client.seqs();
        assert!(!seqs.is_empty(), "the subscriber saw the run happen");
        assert!(
            seqs.windows(2).all(|pair| pair[0] < pair[1]),
            "events arrive in seq order: {seqs:?}"
        );

        quiesce(&handle).await;
        door.stop().await.expect("the door stopped");
        actor.stop().await;
    });
}

/// `common::wait_for_log` under [`LIVE_LIMIT`].
async fn poll_log(
    world: &LoopWorld,
    run: RunId,
    what: &str,
    mut pred: impl FnMut(&[Arc<Event>]) -> bool,
) -> Vec<Arc<Event>> {
    let deadline = Instant::now() + LIVE_LIMIT;
    loop {
        let events = world.events(&run);
        if pred(&events) {
            return events;
        }
        assert!(Instant::now() < deadline, "{what} never happened");
        tokio::time::sleep(TICK).await;
    }
}

/// `common::wait_for_status` under [`LIVE_LIMIT`].
async fn poll_status(
    handle: &CoreHandle,
    run: RunId,
    what: &str,
    mut pred: impl FnMut(&StatusOut) -> bool,
) -> StatusOut {
    let deadline = Instant::now() + LIVE_LIMIT;
    loop {
        let status = handle
            .status(StatusQuery {
                run_id: Some(run),
                ..StatusQuery::default()
            })
            .await
            .expect("get_status");
        if pred(&status) {
            return status;
        }
        assert!(Instant::now() < deadline, "{what} never happened");
        tokio::time::sleep(TICK).await;
    }
}

/// The run's one gate, from the projection.
async fn pending_gate(handle: &CoreHandle, run: RunId) -> agent_control_plane::core::types::Gate {
    let status = handle
        .status(StatusQuery {
            run_id: Some(run),
            ..StatusQuery::default()
        })
        .await
        .expect("get_status");
    status.gates.into_iter().next().expect("the run has a gate")
}

/// Every `gate.created{integrate}` in a log, in order.
fn integrate_gates(events: &[Arc<Event>]) -> Vec<GateId> {
    pick(events, |payload| match payload {
        EventPayload::GateCreated {
            gate_id, gate_kind, ..
        } if *gate_kind == GateKind::Integrate => Some(*gate_id),
        _ => None,
    })
}

/// B3 (T77): `plan.start`'s per-item task bounds are enforced at the door — before `core` — and
/// the refusal names the offending item, exactly as the MCP door's `submit_plan` does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plan_start_refuses_a_bad_work_item_task_at_the_door_naming_the_item() {
    let fake = FakeCore::start(canned_status(RunId::new_v4(), &[]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;

    let err = client
        .call(
            "plan.start",
            json!({ "plan": { "version": 1, "name": "p", "items": [
                { "id": "w1", "kind": "work",
                  "task": { "id": "bad id!", "title": "t",
                            "description": "a long enough description",
                            "files": [], "acceptance": ["done"] } }
            ] } }),
        )
        .await
        .expect_err("refused at the door");
    assert_eq!(err["code"], json!(-32000), "{err}");
    assert_eq!(err["data"]["code"], json!("invalid_task"), "{err}");
    assert!(
        err["data"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("item `w1`")),
        "the refusal names the item: {err}"
    );

    let err = client.call("audit.start", json!({
        "task":{"id":"bad id!","title":"Audit","description":"Inspect existing work",
            "files":[],"acceptance":["Report findings"]},
        "selection":{"baseRef":"HEAD","target":{"kind":"workingTree"}}
    })).await.expect_err("invalid audit task refused before core");
    assert_eq!(err["data"]["code"], "invalid_task");
    let err = client.call("audit.start", json!({
        "task":{"id":"audit","title":"Audit","description":"Inspect existing work",
            "files":[],"acceptance":["Report findings"]},
        "selection":{"baseRef":"HEAD","target":{"kind":"workingTree","approve":true}}
    })).await.expect_err("unknown audit input fields refused");
    assert_eq!(err["code"], -32602);

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

/// T84: `callerRunId` is accepted as an optional field on both `delegate` and `plan.start`, and
/// reaches the core exactly as decoded — the socket door's own half of the wire contract, whether
/// or not `acp mcp-proxy` ever sends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_run_id_is_optional_on_delegate_and_plan_start_and_reaches_the_core() {
    let fake = FakeCore::start(canned_status(RunId::new_v4(), &[]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;

    let caller = RunId::new_v4();
    let delegated = client
        .call(
            "delegate",
            json!({
                "role": "builder",
                "session": "fresh",
                "task": { "id": "T84", "title": "t",
                          "description": "a long enough description",
                          "files": [], "acceptance": ["done"] },
                "callerRunId": caller,
            }),
        )
        .await
        .expect("delegate with a callerRunId is accepted");
    assert!(delegated["runId"].as_str().is_some(), "{delegated}");

    let started = client
        .call(
            "plan.start",
            json!({
                "plan": { "version": 1, "name": "p", "items": [] },
                "callerRunId": caller,
            }),
        )
        .await
        .expect("plan.start with a callerRunId is accepted");
    assert!(started["runId"].as_str().is_some(), "{started}");

    // Omitting it entirely — every door before T84 — still works: the field is `#[serde(default)]`.
    let without = client
        .call(
            "delegate",
            json!({
                "role": "builder",
                "session": "fresh",
                "task": { "id": "T84-omit", "title": "t",
                          "description": "a long enough description",
                          "files": [], "acceptance": ["done"] },
            }),
        )
        .await
        .expect("delegate without a callerRunId is accepted, exactly as before T84");
    assert!(without["runId"].as_str().is_some(), "{without}");

    assert_eq!(
        fake.seen(),
        vec![
            Seen::Delegate {
                caller_run_id: Some(caller)
            },
            Seen::StartPlan {
                caller_run_id: Some(caller)
            },
            Seen::Delegate { caller_run_id: None },
        ]
    );

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}

/// The MCP tool schemas stay unchanged (T84 attaches `callerRunId` only on the socket request),
/// but the socket params objects are `deny_unknown_fields` like every other door struct — an
/// unrelated stray key is still refused exactly as it always was, proving the new optional field
/// did not loosen that guard.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delegate_and_plan_start_still_refuse_an_unrelated_unknown_field() {
    let fake = FakeCore::start(canned_status(RunId::new_v4(), &[]));
    let door = Door::start(fake.handle.clone(), fixture_identity());
    let mut client = Client::connect(&door.path()).await;

    let err = client
        .call(
            "delegate",
            json!({
                "role": "builder",
                "session": "fresh",
                "task": { "id": "T84-x", "title": "t",
                          "description": "a long enough description",
                          "files": [], "acceptance": ["done"] },
                "notAField": true,
            }),
        )
        .await
        .expect_err("an unknown field is refused");
    assert_eq!(err["code"], json!(-32602), "{err}");

    let err = client
        .call(
            "plan.start",
            json!({
                "plan": { "version": 1, "name": "p", "items": [] },
                "notAField": true,
            }),
        )
        .await
        .expect_err("an unknown field is refused");
    assert_eq!(err["code"], json!(-32602), "{err}");

    assert!(
        fake.seen().is_empty(),
        "a refused params object never reaches the core"
    );

    door.stop().await.expect("the door stopped");
    fake.stop().await;
}
