//! The Unix-socket JSON-RPC 2.0 (NDJSON) door at `$ACP_STATE_DIR/acp.sock`, `protocolVersion: 1` —
//! the human / GUI trust path (design, § `src/ipc/socket.rs` and § "Local IPC contract").
//!
//! This module is a **transport**: it binds, authenticates the peer, frames lines, parses one
//! JSON-RPC object per line, calls [`CoreHandle`] and fans the event stream out to subscribers.
//! Every decision — policy, gate authority, what a run does next — belongs to `core`. It knows
//! nothing about providers, git or argv.
//!
//! Three properties are load-bearing and are spelled out where they are implemented:
//!
//! * **`gate.approve` exists only here** (S2). It is the one approving door in the system, and it
//!   is unreachable over MCP, so an agent cannot approve its own integration. [`Connection::call`]
//!   is the whole method table — the security claim is checkable by reading one `match`.
//! * **`subscribe` attaches the broadcast receiver *before* it takes the `sinceSeq` backfill
//!   snapshot**, so an event appended during the backfill window is delivered twice rather than
//!   lost. Clients MUST dedupe by `seq`; that is a term of the contract, not an implementation
//!   detail — and because the dedupe is a *monotonic per-run cursor*, "not lost" also requires that
//!   nothing live overtakes a backfill. [`fan_out`] is therefore the single writer of the event
//!   stream and performs the whole `subscribe` itself.
//! * **A slow client is lagged, never buffered.** The per-connection outbox is bounded, so a client
//!   that stops reading stops the fan-out, the 1 024-slot broadcast buffer overruns, and the
//!   connection is told `acp.lagged{fromSeq}` and keeps running. The log on disk is the recoverable
//!   truth; the daemon never grows an unbounded per-client queue.
//!
//! **The accepted resource model.** A connection has no idle timeout and there is no cap on how
//! many may be open: the socket is 0600 inside a 0700 directory and every peer is checked to be our
//! own uid, so "too many connections" is a program the human ran, not an attacker — and a timeout
//! would break the one thing this channel exists for, a menu-bar app that holds one connection open
//! for days. What *is* bounded is the per-connection cost: one 32-line outbox, one broadcast
//! receiver, and a decode buffer that cannot exceed one line.
//!
//! # Deviations from the design sketch, and why
//!
//! * **[`ServerIdentity`] is a fourth parameter of [`serve_socket`].** The design writes
//!   `serve_socket(path, core, shutdown)`, but `hello` must answer `{repoRoot, stateDir}` and the
//!   Swift client treats both as authoritative ("`repoRoot` and `stateDir` here beat anything the
//!   app derived locally"). `CoreHandle` exposes no accessor for the two fields `Core` holds, and a
//!   transport must not *derive* them (guessing from the socket path, or asking git, is exactly the
//!   knowledge this module is forbidden). So the daemon — which resolved them in the first place —
//!   hands them in.
//! * **The `LinesCodec` is driven through [`Decoder`] rather than through `Framed`.** `Framed`'s
//!   `Stream`/`Sink` impls come from `futures-core`/`futures-sink`, and using them needs
//!   `futures-util`'s extension traits (`StreamExt::next`, `SinkExt::send`) — not a dependency of
//!   this package, and CLAUDE.md fixes the dependency list. The codec is the same `LinesCodec` with
//!   the same `new_with_max_length(MAX_LINE_BYTES)`, doing the same incremental length check while
//!   the line streams in; only the driving loop is hand-written.
//! * **`resolve_gate{approve:true}` is refused here for every gate kind**, not only for `integrate`
//!   under `gates.allowAgentApprove: false`. The design pins "`resolve_gate` over the socket behaves
//!   exactly as over MCP (deny-only), so there is exactly **one** approving door"; mirroring the
//!   *conditional* MCP rule would need the gate's kind and the roles config, neither of which a
//!   transport may read. Refusing outright costs a socket client nothing — `gate.approve` is
//!   available to it unconditionally — and makes "one approving door" structural rather than
//!   configuration-dependent.
//! * **The seven tool-equivalent methods carry their own params types.** The design's `DelegateArgs`
//!   and friends live in `mcp/server.rs`, which is a different door with a different framework
//!   (`schemars`-advertised input schemas, `rmcp`'s `Parameters`); depending on it from here would
//!   couple the human path to the agent path's tooling for the sake of five structs. The **bounds**
//!   are the shared thing, and they are named as constants below with the design section they come
//!   from, so a drift between the two doors is a visible edit rather than a silent one.
//! * **The `sinceSeq` backfill is bounded by the `get_status` projection** (100 events), because
//!   `CoreHandle`'s only read door is `status`. That is the shape the client uses it in: the app
//!   calls `get_status` and then `subscribe{runId, sinceSeq: <that run's lastSeq>}`, so the backfill
//!   only ever has to cover the gap between the snapshot and the subscribe. A client further behind
//!   than that must re-`get_status` — the same recovery `acp.lagged` prescribes.
//! * **The team layer (T49) is served without going through the core.** `roles.list`, `team.get`
//!   and `team.set` are projections of, and edits to, two things this module is *already* handed —
//!   the roles configuration and the state directory — and `CoreHandle` has no command for either.
//!   Routing them through the actor would put a file write in the mailbox turn for no gain; the
//!   authority they need is `core::team`'s [`validate_team`](crate::core::team::validate_team),
//!   which is a pure function over the config. The loop re-reads and re-validates `team.json` at
//!   every `delegate` (design Rev 26), so this door is a *convenience* over the file, never the
//!   thing that makes a team trustworthy. Its one transport-level cost is honest: `team.get` and
//!   `team.set` do a small blocking read/write in the request task, like `hello`'s `getpid`.
//! * **The two provider CLI names appear here** ([`provider_program`]), which is the one thing in
//!   this file that knows anything about providers. `roles.list.providers[p].available` is defined
//!   by the design as "the `PATH` probe `doctor` already does", and that probe
//!   (`providers::find_on_path`) needs a program name that `ProviderName` — a closed enum in
//!   `core` — does not carry. The match is exhaustive, so a third provider cannot be added without
//!   an edit here.

use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::io::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinSet;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::{Decoder as _, LinesCodec, LinesCodecError};
use tokio_util::sync::CancellationToken;

use crate::core::gates::{GatePayload, NewGate};
use crate::core::policy::{DelegateRequest, PolicyCode, PolicyError, SessionSpec};
use crate::core::team::{self, Team, TeamError, TeamIssue};
use crate::core::types::{
    Actor, AgentId, Event, GateId, GateKind, Origin, ProviderName, RoleName, RolesConfig, RunId,
    Task,
};
use crate::core::{
    CoreError, CoreHandle, GateRequest, SendResult, StatusQuery, DEFAULT_LAST_EVENTS,
    MAX_LAST_EVENTS,
};
use crate::providers::find_on_path;

// ---------------------------------------------------------------------------
// Contract constants
// ---------------------------------------------------------------------------

/// `acp.protocolVersion`. A client shown anything else must refuse to drive the daemon.
pub const PROTOCOL_VERSION: u32 = 1;

/// The framing ceiling, enforced incrementally by [`LinesCodec`] — never buffered whole.
pub const MAX_LINE_BYTES: usize = 1 << 20;

/// macOS `sun_path` is 104 bytes; `serve` and `doctor` fail loudly above this (V-probe,
/// `docs/research/2026-08-22-rust-probes.md`).
pub const MAX_SOCKET_PATH_BYTES: usize = 100;

/// The socket file's mode after bind. The 0700 state directory is the load-bearing control —
/// socket-file permission enforcement varies across BSD/Linux — and this is belt and braces.
const SOCKET_MODE: u32 = 0o600;

/// `hello`'s default `clientName` (design, § Local IPC contract).
const DEFAULT_CLIENT_NAME: &str = "cli";

/// Longest `clientName` accepted. It is written into the durable event log as the resolving actor,
/// so it is bounded and character-checked like any other untrusted input.
const MAX_CLIENT_NAME_CHARS: usize = 64;

/// `send_message.message` (design, § MCP tools).
const MAX_MESSAGE_CHARS: usize = 20_000;

/// `request_human_gate.summary` (design, § MCP tools).
const MAX_SUMMARY_CHARS: usize = 4_000;

/// `resolve_gate.feedback` / `gate.deny.feedback` (design, § MCP tools).
const MAX_FEEDBACK_CHARS: usize = 8_000;

/// `await_result.timeoutSec` bounds and default (design, § MCP tools: `1..=300 = 60`).
const MIN_AWAIT_SEC: u64 = 1;
const MAX_AWAIT_SEC: u64 = 300;
const DEFAULT_AWAIT_SEC: u64 = 60;

/// Task-shape bounds, mirrored from the design's § Interface Contracts. The MCP door's
/// `DelegateArgs::validate()` enforces the same set: `core::policy` deliberately does **not** check
/// the shape of caller input, so each door checks it, and the two must agree.
const MAX_TASK_ID_CHARS: usize = 64;
const MAX_TITLE_CHARS: usize = 200;
const MIN_DESCRIPTION_CHARS: usize = 10;
const MAX_DESCRIPTION_CHARS: usize = 20_000;
const MAX_FILES: usize = 100;
const MAX_FILE_CHARS: usize = 400;
const MAX_ACCEPTANCE: usize = 50;
const MAX_ACCEPTANCE_CHARS: usize = 1_000;

/// How many lines may be queued for one client before the daemon stops producing for it. Small on
/// purpose: this is the valve that turns "a client stopped reading" into `acp.lagged` instead of
/// into memory growth.
const OUTBOX_CAPACITY: usize = 32;

/// Bytes offered to each `read` call. The decode buffer therefore grows in chunks and never holds
/// more than one over-long line before the codec rejects it.
const READ_CHUNK_BYTES: usize = 8 * 1024;

/// How long a closing connection is given to flush what it has already queued (the `acp.shutdown`
/// notification, a pending reply) before the writer is abandoned.
const FLUSH_GRACE: Duration = Duration::from_secs(2);

/// How long the accept loop pauses after a failed `accept(2)`, so a persistent error (EMFILE) is a
/// warning per second rather than a busy loop.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The `reason` of the `acp.shutdown` a clean stop sends.
const SHUTDOWN_REASON: &str = "the daemon is shutting down";

// JSON-RPC 2.0 error codes (design, § Local IPC contract).
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const POLICY_REJECTED: i64 = -32000;
const CORE_UNAVAILABLE: i64 = -32001;

// Notification methods (no `id`), consumed by `ACPProtocol`'s `ACPNotification`.
const NOTIFY_EVENT: &str = "acp.event";
const NOTIFY_LAGGED: &str = "acp.lagged";
const NOTIFY_SHUTDOWN: &str = "acp.shutdown";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything that can stop the socket door from starting. Per-connection faults are not errors of
/// the server: they are logged and the connection is dropped.
#[derive(Debug, Error)]
pub enum IpcError {
    /// The absolute socket path does not fit in `sun_path`. Raised **before** any bind, and its
    /// message names the remedy because this is the one failure a human hits by configuration.
    #[error(
        "the socket path is {bytes} bytes, over the {MAX_SOCKET_PATH_BYTES}-byte limit \
         (macOS sun_path is 104): set $ACP_STATE_DIR to a shorter directory — {path}"
    )]
    PathTooLong { path: PathBuf, bytes: usize },

    /// A stale socket file could not be removed before binding.
    #[error("removing the stale socket {path}: {source}")]
    Unlink {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("binding the socket {path}: {source}")]
    Bind {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// The socket was bound but could not be restricted to 0600.
    #[error("setting mode 0600 on {path}: {source}")]
    Chmod {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// `getpeereid(2)` failed on an accepted connection.
    #[error("reading the peer's credentials: {0}")]
    PeerCred(#[source] io::Error),

    /// The peer is not us. The socket carries no authorization beyond "same uid" — that is the
    /// intended trust model for a single-user developer tool — so this is the whole check.
    #[error("refusing a connection from uid {peer}; this daemon serves uid {ours} only")]
    PeerUid { peer: u32, ours: u32 },
}

// ---------------------------------------------------------------------------
// Server identity
// ---------------------------------------------------------------------------

/// What `hello` answers with beyond the protocol version: the two paths the daemon resolved at
/// startup, and the build serving them.
///
/// The client treats these as authoritative — the macOS app compares `stateDir` against the one it
/// located itself and reports a mismatch rather than reading the wrong log — so they are passed in
/// by the daemon rather than inferred here.
///
/// It also carries the roles configuration the **team layer** is checked against, for the same
/// reason: the daemon may have been started against an external `$ACP_ROLES_FILE`, and a door that
/// loaded the embedded one itself would validate a `team.set` against a different allowlist than
/// the one the loop enforces at the next `delegate`.
#[derive(Clone, PartialEq, Debug)]
pub struct ServerIdentity {
    pub repo_root: PathBuf,
    pub state_dir: PathBuf,
    pub server_version: String,
    /// The config `roles.list` projects and `team.set` validates against — the **same `Arc` the
    /// core was built with**, or `None` for a door that does not offer the team layer at all.
    ///
    /// Optional so that a caller which has no config to give (a transport test) is not forced to
    /// invent one, and so that "this daemon has no team layer" is a state the client already knows
    /// how to be shown: the three methods are then simply not in the table, which is exactly what
    /// an older daemon looks like to a newer app (`roles.list` failing is a *fallback* to the
    /// app's bundled catalog, not an error — `apps/acp-mac/…/Catalog/CatalogModel.swift`).
    roles: Option<Arc<RolesConfig>>,
}

impl ServerIdentity {
    /// This build, over `repo_root` and `state_dir`, **without** the team layer.
    #[must_use]
    pub fn new(repo_root: PathBuf, state_dir: PathBuf) -> Self {
        Self {
            repo_root,
            state_dir,
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            roles: None,
        }
    }

    /// The same identity, offering the team layer over `roles`.
    ///
    /// The daemon passes the `Arc` it built its `Core` from; anything else would let the two
    /// disagree about what a role may be given.
    #[must_use]
    pub fn with_roles(mut self, roles: Arc<RolesConfig>) -> Self {
        self.roles = Some(roles);
        self
    }
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

/// Serves the socket at `path` until `shutdown` is cancelled.
///
/// Binding unlinks a stale path first, which is safe because the caller holds `serve.lock` — one
/// daemon per state dir, so nothing else can own the path we are about to take. The socket file is
/// then `chmod`ed to 0600 inside the 0700 state dir, and every accepted peer must be our own uid.
///
/// Connections are served concurrently; each gets `acp.shutdown` when the token fires and is given
/// [`FLUSH_GRACE`] to write what it has already queued.
///
/// The socket file is deliberately **not** removed on the way out: a crash cannot remove it either,
/// so the unlink-on-bind path above has to exist regardless, and leaving it is one code path
/// instead of two.
///
/// # Errors
/// [`IpcError::PathTooLong`] before any side effect at all, then [`IpcError::Unlink`],
/// [`IpcError::Bind`] or [`IpcError::Chmod`].
pub async fn serve_socket(
    path: &Path,
    core: CoreHandle,
    identity: ServerIdentity,
    shutdown: CancellationToken,
) -> Result<(), IpcError> {
    let listener = bind(path)?;
    if identity.roles.is_none() {
        // Said once, at startup, rather than per refused call: a daemon serving without a config to
        // check a team against is a wiring mistake, and this is the line that names it.
        tracing::warn!(
            "no roles configuration was handed to the socket; roles.list, team.get and team.set \
             are not offered on it"
        );
    }
    let identity = Arc::new(identity);
    tracing::info!(path = %path.display(), "the control plane socket is listening");

    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            // Reaping finished connections keeps the set from growing over a long-lived daemon.
            // Guarded: `join_next` on an empty set returns immediately and would spin.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => match accepted {
                Ok((stream, _addr)) => match authenticate(&stream) {
                    Ok(()) => {
                        connections.spawn(serve_connection(
                            stream,
                            core.clone(),
                            Arc::clone(&identity),
                            shutdown.clone(),
                        ));
                    }
                    Err(err) => tracing::warn!(%err, "rejected a socket connection"),
                },
                Err(err) => {
                    tracing::warn!(%err, "accept failed on the control plane socket");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            },
        }
    }

    // Every live connection has the same token, so each is already writing its `acp.shutdown`.
    let drained = tokio::time::timeout(FLUSH_GRACE, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        connections.shutdown().await;
    }
    tracing::info!(path = %path.display(), "the control plane socket has stopped");
    Ok(())
}

/// Unlink a stale path, bind, restrict to 0600.
fn bind(path: &Path) -> Result<UnixListener, IpcError> {
    let bytes = path.as_os_str().as_bytes().len();
    if bytes > MAX_SOCKET_PATH_BYTES {
        return Err(IpcError::PathTooLong {
            path: path.to_path_buf(),
            bytes,
        });
    }
    match std::fs::remove_file(path) {
        Ok(()) => tracing::debug!(path = %path.display(), "removed a stale socket file"),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(IpcError::Unlink {
                path: path.to_path_buf(),
                source,
            })
        }
    }
    let listener = UnixListener::bind(path).map_err(|source| IpcError::Bind {
        path: path.to_path_buf(),
        source,
    })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE)).map_err(
        |source| IpcError::Chmod {
            path: path.to_path_buf(),
            source,
        },
    )?;
    Ok(listener)
}

/// The peer must be the uid this daemon runs as.
///
/// This is the whole authorization model of the channel: any process the human can run may approve
/// a gate. The 0700 state directory and the builder sandbox's `denyWrite:["~/"]` are what keep a
/// worker out (V4) — a Unix socket needs *write* permission on the socket file to connect.
fn authenticate(stream: &UnixStream) -> Result<(), IpcError> {
    let mut peer: libc::uid_t = 0;
    let mut group: libc::gid_t = 0;
    // # Safety
    // `getpeereid(2)` reads the fd — borrowed from `stream`, so open for the whole call — and
    // writes one `uid_t` and one `gid_t` through the two out-pointers. Both point at live locals of
    // exactly those types, and nothing else is aliased.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut peer, &mut group) };
    if rc != 0 {
        return Err(IpcError::PeerCred(io::Error::last_os_error()));
    }
    // # Safety
    // `getuid(2)` takes no arguments, touches no memory and cannot fail (POSIX).
    let ours = unsafe { libc::getuid() };
    if peer != ours {
        return Err(IpcError::PeerUid { peer, ours });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// One connection
// ---------------------------------------------------------------------------

/// Why a connection's read loop ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ending {
    /// The client closed its half.
    Eof,
    /// The daemon is stopping; the client is owed an `acp.shutdown`.
    Shutdown,
    /// The line was unframable (over [`MAX_LINE_BYTES`], or not UTF-8). The client has been told
    /// `-32700` and the connection closes rather than retaining the buffer.
    Unframable,
    /// The socket faulted.
    Io,
}

/// Per-connection state shared by the reader, the request tasks and the fan-out.
struct Connection {
    core: CoreHandle,
    identity: Arc<ServerIdentity>,
    /// The `clientName` from `hello`, recorded as [`Actor::Socket`] on everything this connection
    /// resolves. A `Mutex` because request tasks run concurrently; the contract has clients call
    /// `hello` first and await its reply, so there is no ordering to race over.
    client: Mutex<String>,
    /// The bounded outbox. Full means the client is not reading, which is the backpressure that
    /// eventually produces `acp.lagged`.
    out: mpsc::Sender<String>,
    /// Hands a `subscribe` to the fan-out, which is the **only** writer of event lines.
    subscription: mpsc::Sender<SubscribeRequest>,
}

/// A `subscribe` for the fan-out to perform, and the channel its answer comes back on.
///
/// The request is handed over rather than served in the calling task on purpose: see
/// [`fan_out`]. The `reply` is a `oneshot`, so a caller that vanishes mid-call costs the fan-out a
/// dropped send and nothing else.
struct SubscribeRequest {
    run_id: Option<RunId>,
    since_seq: Option<u64>,
    reply: oneshot::Sender<Result<Value, RpcError>>,
}

async fn serve_connection(
    stream: UnixStream,
    core: CoreHandle,
    identity: Arc<ServerIdentity>,
    shutdown: CancellationToken,
) {
    let Some(_connection) = core.ingress().connection() else { return; };
    let (reader, writer) = stream.into_split();
    let (out_tx, out_rx) = mpsc::channel::<String>(OUTBOX_CAPACITY);
    let mut writer_task = tokio::spawn(write_lines(writer, out_rx));
    let (sub_tx, sub_rx) = mpsc::channel(1);
    let fan_out_task = tokio::spawn(fan_out(core.clone(), sub_rx, out_tx.clone()));

    let conn = Arc::new(Connection {
        core,
        identity,
        client: Mutex::new(DEFAULT_CLIENT_NAME.to_string()),
        out: out_tx,
        subscription: sub_tx,
    });

    let ending = read_loop(reader, &conn, &shutdown).await;
    if ending == Ending::Shutdown {
        conn.send(notification(
            NOTIFY_SHUTDOWN,
            &json!({ "protocolVersion": PROTOCOL_VERSION, "reason": SHUTDOWN_REASON }),
        ))
        .await;
    }
    tracing::debug!(?ending, "a socket connection ended");

    // The fan-out holds the last outbox sender apart from `conn`; both must go before the writer
    // can see the channel close and finish.
    fan_out_task.abort();
    drop(conn);
    if tokio::time::timeout(FLUSH_GRACE, &mut writer_task)
        .await
        .is_err()
    {
        writer_task.abort();
    }
}

/// Frames lines off the socket and dispatches each one.
///
/// Requests are handled in their own tasks, so one parked `await_result` cannot stop the client
/// from sending a `cancel` — and so a disconnect *aborts* the parked call, which drops the
/// `oneshot` receiver the actor is holding and disturbs nothing else.
async fn read_loop(
    mut reader: OwnedReadHalf,
    conn: &Arc<Connection>,
    shutdown: &CancellationToken,
) -> Ending {
    let mut codec = LinesCodec::new_with_max_length(MAX_LINE_BYTES);
    let mut buf = BytesMut::with_capacity(READ_CHUNK_BYTES);
    let mut requests = JoinSet::new();

    loop {
        // Everything already buffered, before asking for more bytes.
        loop {
            match codec.decode(&mut buf) {
                Ok(Some(line)) => {
                    let Some(admission) = conn.core.ingress().request() else {
                        return Ending::Shutdown;
                    };
                    requests.spawn(handle_line(Arc::clone(conn), line, admission));
                }
                Ok(None) => break,
                Err(err) => {
                    // `MaxLineLengthExceeded` fires *while* the line streams in, and a non-UTF-8
                    // line arrives here as an `Io` error. Either way the frame is unusable: answer
                    // `-32700` and close, rather than keep a megabyte of a client's noise.
                    let message = match err {
                        LinesCodecError::MaxLineLengthExceeded => format!(
                            "line exceeds the {MAX_LINE_BYTES}-byte limit; the connection is closing"
                        ),
                        LinesCodecError::Io(err) => format!("line is not valid UTF-8: {err}"),
                    };
                    conn.send(error_response(
                        &Value::Null,
                        &RpcError::new(PARSE_ERROR, message),
                    ))
                    .await;
                    return Ending::Unframable;
                }
            }
        }

        buf.reserve(READ_CHUNK_BYTES);
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ending::Shutdown,
            Some(_) = requests.join_next(), if !requests.is_empty() => {}
            read = reader.read_buf(&mut buf) => match read {
                Ok(0) => return Ending::Eof,
                Ok(_) => {}
                Err(err) => {
                    tracing::debug!(%err, "socket read failed");
                    return Ending::Io;
                }
            },
        }
    }
}

/// Drains the outbox onto the socket. One task, so writes are serialized and a line is never
/// interleaved with another.
async fn write_lines(mut writer: OwnedWriteHalf, mut out: mpsc::Receiver<String>) {
    while let Some(line) = out.recv().await {
        if let Err(err) = writer.write_all(line.as_bytes()).await {
            tracing::debug!(%err, "socket write failed");
            break;
        }
    }
    let _ = writer.shutdown().await;
}

impl Connection {
    /// Queues one framed line. `false` means the client is gone.
    async fn send(&self, mut line: String) -> bool {
        line.push('\n');
        self.out.send(line).await.is_ok()
    }

    /// The actor every resolution from this connection is recorded as.
    fn actor(&self) -> Actor {
        Actor::Socket {
            client_name: self
                .client
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        }
    }
}

/// Parses one line, calls the method, writes the answer.
async fn handle_line(
    conn: Arc<Connection>, line: String, _admission: crate::core::lifecycle::ActivityGuard,
) {
    let request = match parse_request(&line) {
        Ok(request) => request,
        Err((id, err)) => {
            conn.send(error_response(&id, &err)).await;
            return;
        }
    };

    let Request { id, method, params } = request;
    let answer = conn.call(&method, params).await;
    let Some(id) = id else {
        return; // a client notification: never answered
    };
    let line = match answer {
        Ok(result) => response(&id, &result),
        Err(err) => error_response(&id, &err),
    };
    conn.send(line).await;
}

// ---------------------------------------------------------------------------
// The method table
// ---------------------------------------------------------------------------

impl Connection {
    /// **The whole method table.** `gate.approve` appears here and nowhere else in the codebase:
    /// there is no MCP tool with this name and no other caller of `resolve_gate(approve: true)`
    /// from a door, which is what makes S2 ("an agent cannot approve its own integration") a
    /// structural property rather than a policy one.
    async fn call(&self, method: &str, params: Option<Value>) -> Result<Value, RpcError> {
        match method {
            "checks.start" => {
                let request: crate::checks::Request = parse_params(params)?;
                Ok(serde_json::to_value(self.core.check_start(request).await.map_err(RpcError::from_core)?).expect("serializable review"))
            }
            "checks.cancel" => {
                let p: CheckIdParams = parse_params(params)?;
                Ok(serde_json::to_value(self.core.check_cancel(p.id).await.map_err(RpcError::from_core)?).expect("serializable review"))
            }
            "checks.list" => {
                let p: CheckHistoryParams = parse_params(params)?;
                Ok(self.core.check_list(p.offset).await.map_err(RpcError::from_core)?)
            }
            "checks.result" => {
                let p: CheckPageParams = parse_params(params)?;
                let state = self.identity.state_dir.clone();
                tokio::task::spawn_blocking(move || {
                    let summary = crate::checks::read_summary(&state, p.id)?;
                    crate::checks::page(&state, &summary, p.offset)
                }).await.map_err(|e| RpcError::new(-32000,e.to_string()))?
                    .map_err(|e| RpcError::new(-32000,e))
            }
            "checks.source" => {
                let p: CheckSourceParams = parse_params(params)?;
                if p.file.len()>1024 {return Err(RpcError::new(-32602,"Source path is too long".into()));}
                let state = self.identity.state_dir.clone();
                tokio::task::spawn_blocking(move || {
                    let summary = crate::checks::read_summary(&state, p.id)?;
                    crate::checks::source(&state, &summary, &p.file, p.line)
                }).await.map_err(|e| RpcError::new(-32000,e.to_string()))?
                    .map_err(|e| RpcError::new(-32000,e))
            }
            "checks.catalog" => {
                let _: NoParams = parse_params(params)?;
                let availability = crate::checks::runner::helper();
                Ok(json!({"version":1,"available":availability.is_ok(),"reason":availability.err(),"rules":crate::checks::rules::RULES}))
            }
            "checks.prepareFix" => {
                let p: CheckFixParams = parse_params(params)?;
                let state = self.identity.state_dir.clone();
                let repo = self.identity.repo_root.clone();
                tokio::task::spawn_blocking(move || crate::checks::prepare_fix(&state, &repo, p.id, &p.indices))
                    .await.map_err(|e| RpcError::new(-32000,e.to_string()))?.map_err(|e| RpcError::new(-32000,e))
            }
            "daemon.status" => {
                let _: NoParams = parse_params(params)?;
                self.lifecycle(crate::core::lifecycle::Request::Status).await
            }
            "session.acquire" => {
                let p: SessionAcquireParams = parse_params(params)?;
                let request = match p.owner_pid {
                    None => crate::core::lifecycle::Request::Acquire { label: p.label },
                    // Identity comes from the daemon's own probe, off the actor's mailbox turn.
                    Some(pid) => {
                        let owner = crate::workspace::session::identify_owner(pid)
                            .await
                            .ok_or_else(|| RpcError::invalid_params(format!("ownerPid {pid} is not a running process a session can be bound to")))?;
                        crate::core::lifecycle::Request::AcquireOwned { label: p.label, owner }
                    }
                };
                self.lifecycle(request).await
            }
            "session.renew" | "session.release" => {
                let p: SessionHandleParams = parse_params(params)?;
                let request = if method == "session.renew" {
                    crate::core::lifecycle::Request::Renew { instance: p.instance_id, session: p.session_id }
                } else {
                    crate::core::lifecycle::Request::Release { instance: p.instance_id, session: p.session_id, stop_if_unneeded: p.stop_if_unneeded }
                };
                self.lifecycle(request).await
            }
            "daemon.stop" => {
                let p: DaemonStopParams = parse_params(params)?;
                self.lifecycle(crate::core::lifecycle::Request::Stop { mode: p.mode }).await
            }
            "hello" => self.hello(parse_params(params)?),
            "subscribe" => self.subscribe(parse_params(params)?).await,
            // Human-only entry point: deliberately absent from the seven MCP/proxy tools.
            "lead.start" => self.lead_start(parse_params(params)?).await,
            "delegate" => self.delegate(parse_params(params)?).await,
            // B3: socket plan entry — same task bounds as `delegate`, applied per work item.
            "plan.start" => self.plan_start(parse_params(params)?).await,
            "audit.start" => self.audit_start(parse_params(params)?).await,
            "send_message" => self.send_message(parse_params(params)?).await,
            "await_result" => self.await_result(parse_params(params)?).await,
            "get_status" => self.get_status(parse_params(params)?).await,
            "cancel" => self.cancel(parse_params(params)?).await,
            "request_human_gate" => self.request_human_gate(parse_params(params)?).await,
            "resolve_gate" => self.resolve_gate(parse_params(params)?).await,
            "gate.approve" => self.gate_approve(parse_params(params)?).await,
            "gate.deny" => self.gate_deny(parse_params(params)?).await,
            "run.recovery" => {
                let p: RecoveryPreviewParams = parse_params(params)?;
                to_value(&self.core.recovery_preview(p.run_id).await.map_err(RpcError::from_core)?)
            }
            "run.recover" => {
                let p: crate::core::recovery::Request = parse_params(params)?;
                to_value(&self.core.recover_run(p, self.actor()).await.map_err(RpcError::from_core)?)
            }
            // The three socket-only team methods (design Rev 26, § Team layer). They are **not**
            // MCP tools and must never become any: an agent that could re-team itself mid-run
            // could pick its own reviewer, and the shape of the team is the human's decision.
            "roles.list" => self.roles_list(parse_params(params)?),
            "team.get" => self.team_get(parse_params(params)?),
            "team.set" => self.team_set(parse_params(params)?),
            _ => Err(RpcError::unknown_method(method)),
        }
    }

    async fn lifecycle(&self, request: crate::core::lifecycle::Request) -> Result<Value, RpcError> {
        let out = self.core.lifecycle(request).await.map_err(RpcError::from_core)?;
        to_value(&out)
    }

    /// `hello` — the first line on every connection, and the only method that does not touch core.
    fn hello(&self, params: HelloParams) -> Result<Value, RpcError> {
        let name = params
            .client_name
            .unwrap_or_else(|| DEFAULT_CLIENT_NAME.to_string());
        let name = check_client_name(name)?;
        *self.client.lock().unwrap_or_else(PoisonError::into_inner) = name.clone();
        tracing::debug!(client = %name, version = params.client_version.as_deref().unwrap_or("?"),
                        "a socket client said hello");
        Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "serverVersion": self.identity.server_version,
            "repoRoot": self.identity.repo_root,
            "stateDir": self.identity.state_dir,
            "pid": std::process::id(),
        }))
    }

    /// `subscribe` — the event stream, with three semantics the macOS client relies on (design,
    /// § "Subscription semantics the macOS client relies on"):
    ///
    /// 1. `runId` does **not** filter the live stream. A subscriber sees every run's events,
    ///    including the `run.created` of runs that did not exist when it subscribed;
    ///    `runId`/`sinceSeq` scope the **backfill** only.
    /// 2. A repeated `subscribe` **replaces** this connection's receiver instead of adding one, and
    ///    the replaced receiver is drained after the backfill, so nothing already queued on it is
    ///    dropped and nothing on it can overtake the history the caller just asked for.
    /// 3. `subscribe{runId: nil, sinceSeq: nil}` performs no backfill at all.
    ///
    /// **The work is done by the fan-out, not here.** This method only hands the request over and
    /// waits for the answer, because the fan-out is the single writer of event lines and doing the
    /// attach / snapshot / backfill anywhere else re-opens the ordering race [`fan_out`] documents.
    async fn subscribe(&self, params: SubscribeParams) -> Result<Value, RpcError> {
        let (reply, answer) = oneshot::channel();
        let request = SubscribeRequest {
            run_id: params.run_id,
            since_seq: params.since_seq,
            reply,
        };
        if self.subscription.send(request).await.is_err() {
            return Err(RpcError::policy(
                "connection_closing",
                "this connection is shutting down".to_string(),
            ));
        }
        answer.await.unwrap_or_else(|_| {
            Err(RpcError::policy(
                "connection_closing",
                "this connection is shutting down".to_string(),
            ))
        })
    }

    async fn plan_start(&self, params: PlanStartParams) -> Result<Value, RpcError> {
        // The plan's own shape is the core's to refuse (`invalid_plan`); each work item's task
        // gets the same door bounds a `delegate` would — and the refusal names the item, exactly
        // as the MCP door's does, so the two entry points teach identically.
        for item in &params.plan.items {
            if let Some(task) = &item.task {
                if let Some(reason) = task_shape_error(task) {
                    return Err(RpcError::policy(
                        PolicyCode::InvalidTask.as_str(),
                        format!("item `{}`: {reason}", item.id),
                    ));
                }
            }
        }
        let out = self
            .core
            .start_plan(params.plan, params.caller_run_id)
            .await
            .map_err(RpcError::from_core)?;
        to_value(&out)
    }

    async fn audit_start(&self, params: AuditStartParams) -> Result<Value, RpcError> {
        check_task(&params.task)?;
        let out = self.core.start_audit(params.task, params.selection, params.caller_run_id)
            .await.map_err(RpcError::from_core)?;
        to_value(&out)
    }

    async fn delegate(&self, params: DelegateParams) -> Result<Value, RpcError> {
        let request = params.into_request()?;
        let out = self
            .core
            .delegate(request)
            .await
            .map_err(RpcError::from_core)?;
        to_value(&out)
    }

    /// `lead.start` — the socket-only human act that opens one conversational run. The synthetic
    /// task exists solely to echo the user's message in `run.created` for the app transcript; it
    /// invents no files or acceptance criteria.
    async fn lead_start(&self, params: LeadStartParams) -> Result<Value, RpcError> {
        check_chars("message", &params.message, 1, MAX_MESSAGE_CHARS)?;
        let task = Task {
            id: "lead".to_string(),
            title: "Lead conversation".to_string(),
            description: params.message.clone(),
            files: Vec::new(),
            acceptance: Vec::new(),
        };
        let out = self
            .core
            .start_lead_with_setup(task, params.message, crate::core::LeadSetup {
                audit_selection: params.audit_selection, expected_team: params.expected_team,
            })
            .await
            .map_err(RpcError::from_core)?;
        to_value(&out)
    }

    async fn send_message(&self, params: SendMessageParams) -> Result<Value, RpcError> {
        check_chars("message", &params.message, 1, MAX_MESSAGE_CHARS)?;
        match self
            .core
            .with_caller(params.caller_run_id)
            .send_message(params.agent_id, params.message)
            .await
            .map_err(RpcError::from_core)?
        {
            // A refusal is a *value* to the loop and an error to a door, exactly as over MCP.
            SendResult::Rejected { code, reason } => Err(RpcError::policy(code.as_str(), reason)),
            SendResult::Ok { attempt } => Ok(json!({ "accepted": true, "attemptId": attempt })),
        }
    }

    async fn await_result(&self, params: AwaitResultParams) -> Result<Value, RpcError> {
        let seconds = params.timeout_sec.unwrap_or(DEFAULT_AWAIT_SEC);
        if !(MIN_AWAIT_SEC..=MAX_AWAIT_SEC).contains(&seconds) {
            return Err(RpcError::invalid_params(format!(
                "timeoutSec must be {MIN_AWAIT_SEC}..={MAX_AWAIT_SEC}, got {seconds}"
            )));
        }
        let out = self
            .core
            .await_result(params.agent_id, Duration::from_secs(seconds))
            .await
            .map_err(RpcError::from_core)?;
        to_value(&out)
    }

    async fn get_status(&self, params: GetStatusParams) -> Result<Value, RpcError> {
        let last_events = params.last_events.unwrap_or(DEFAULT_LAST_EVENTS);
        if last_events > MAX_LAST_EVENTS {
            return Err(RpcError::invalid_params(format!(
                "lastEvents must be 0..={MAX_LAST_EVENTS}, got {last_events}"
            )));
        }
        let out = self
            .core
            .status(StatusQuery {
                run_id: params.run_id,
                agent_id: params.agent_id,
                last_events,
            })
            .await
            .map_err(RpcError::from_core)?;
        to_value(&out)
    }

    async fn cancel(&self, params: CancelParams) -> Result<Value, RpcError> {
        let out = self
            .core
            .with_caller(params.caller_run_id)
            .cancel(params.agent_id)
            .await
            .map_err(RpcError::from_core)?;
        to_value(&out)
    }

    async fn request_human_gate(&self, params: GateRequestParams) -> Result<Value, RpcError> {
        check_chars("summary", &params.summary, 1, MAX_SUMMARY_CHARS)?;
        let payload = params.payload.into_payload()?;
        let out = self
            .core
            .with_caller(params.caller_run_id)
            .request_gate(GateRequest {
                run_id: params.run_id,
                gate: NewGate {
                    kind: params.kind,
                    summary: params.summary,
                    requested_by: Origin::Lead,
                    payload,
                },
            })
            .await
            .map_err(RpcError::from_core)?;
        to_value(&out)
    }

    /// `resolve_gate` — **deny-only**, exactly as over MCP, so `gate.approve` is the one approving
    /// door in the system (S2). See this module's header for why the refusal is unconditional.
    async fn resolve_gate(&self, params: ResolveGateParams) -> Result<Value, RpcError> {
        if params.approve {
            return Err(RpcError::policy(
                PolicyCode::AgentApproveNotAllowed.as_str(),
                "resolve_gate can only deny; approving is a human action — call gate.approve"
                    .to_string(),
            ));
        }
        self.deny(params.gate_id, params.feedback, params.caller_run_id).await
    }

    /// `gate.approve` — **the only approving door**, reachable over this socket and nowhere else.
    ///
    /// The reply carries the integration commit, because `CoreHandle::resolve_gate` parks it in the
    /// actor until the commit helper reports back (`Command::CommitDone` → `finish_commit`): a
    /// `sha` here means the commit is durable and `integrate.committed` is already in the log.
    async fn gate_approve(&self, params: GateApproveParams) -> Result<Value, RpcError> {
        let resolution = self
            .core
            .resolve_gate(params.gate_id, true, None, self.actor())
            .await
            .map_err(RpcError::from_core)?;
        to_value(&resolution)
    }

    async fn gate_deny(&self, params: GateDenyParams) -> Result<Value, RpcError> {
        self.deny(params.gate_id, params.feedback, None).await
    }

    /// The denial both `resolve_gate` and `gate.deny` perform.
    async fn deny(&self, gate: GateId, feedback: Option<String>, caller: Option<RunId>) -> Result<Value, RpcError> {
        if let Some(feedback) = &feedback {
            check_chars("feedback", feedback, 0, MAX_FEEDBACK_CHARS)?;
        }
        let resolution = self
            .core
            .with_caller(caller)
            .resolve_gate(gate, false, feedback, self.actor())
            .await
            .map_err(RpcError::from_core)?;
        to_value(&resolution)
    }

    // -----------------------------------------------------------------------
    // The team layer (design Rev 26, § Team layer)
    // -----------------------------------------------------------------------

    /// The roles configuration the three team methods are answered from, or `-32601`.
    ///
    /// The trio is offered or withheld together, even though `team.get` could technically answer
    /// without a config: "does this daemon have a team layer?" must have one answer, not three.
    fn team_layer(&self) -> Result<&RolesConfig, RpcError> {
        self.identity.roles.as_deref().ok_or_else(|| {
            RpcError::new(
                METHOD_NOT_FOUND,
                "this daemon serves no team layer: it was started without a roles configuration \
                 for the socket"
                    .to_string(),
            )
        })
    }

    /// `roles.list` — the catalog a client composes a team from: every spawnable role with the
    /// closed model allowlist its picker is bounded by, and every provider with its models,
    /// efforts, and whether its CLI is on `PATH`.
    ///
    /// `available` is probed **per call**, not cached: it is a claim about this machine right now,
    /// and a client asks precisely because it may have changed since the daemon started.
    fn roles_list(&self, _params: NoParams) -> Result<Value, RpcError> {
        let cfg = self.team_layer()?;
        let available = cfg
            .providers
            .keys()
            .map(|provider| {
                (
                    *provider,
                    find_on_path(provider_program(*provider)).is_some(),
                )
            })
            .collect();
        to_value(&team::roles_list(cfg, &available))
    }

    /// `team.get` — the human's file, echoed back rather than re-derived, with the path the daemon
    /// reads it from (the authority for where a client should write it).
    ///
    /// A file that exists and cannot be trusted is an **error**, not `{team: null}`: reporting "no
    /// team" for a file the daemon will refuse to `delegate` against would be a lie, and the two
    /// remedies — "update acp" and "this file is broken" — stay distinguishable by `data.code`.
    fn team_get(&self, _params: NoParams) -> Result<Value, RpcError> {
        // Withheld with the other two, though it needs nothing from the config: see `team_layer`.
        self.team_layer()?;
        let state_dir = &self.identity.state_dir;
        let team = team::load_team(state_dir).map_err(RpcError::from_team)?;
        Ok(json!({ "team": team, "path": team::team_path(state_dir) }))
    }

    /// `team.set` — validate against the closed allowlists, then write.
    ///
    /// In that order, and that is the contract: a team with a single bad assignment writes
    /// **nothing**, and every issue is reported at once so a human sees the whole list rather than
    /// fixing one row per round trip. A role key this build does not spawn is not an issue — it is
    /// reported as `ignoredRoles` and the team is still written, so a team file shared with a
    /// daemon that knows more roles keeps working for the roles both sides share.
    ///
    /// The file takes effect at the **next spawn**, not on any run already under way: the loop
    /// re-reads and re-validates `team.json` at every `delegate` (`core::loop::valid_team`), and a
    /// resumed session keeps the provider and model it was started with.
    ///
    /// Nothing here bounds the team's `name` beyond the [`MAX_LINE_BYTES`] frame limit. The app can
    /// write this file directly, so a bound applied only here would be a bound in name only; the
    /// clamp that matters belongs where the name enters the durable log, on `run.created`.
    fn team_set(&self, params: TeamSetParams) -> Result<Value, RpcError> {
        let cfg = self.team_layer()?;
        let team = team::validate_team(cfg, &params.team).map_err(RpcError::team_invalid)?;
        team::save_team(&self.identity.state_dir, team.team()).map_err(RpcError::from_team)?;
        tracing::info!(
            client = %self.client.lock().unwrap_or_else(PoisonError::into_inner),
            roles = team.team().roles.len(),
            ignored = team.ignored_roles.len(),
            "a socket client set the team"
        );
        Ok(json!({ "ok": true, "ignoredRoles": team.ignored_roles }))
    }
}

/// The CLI a provider is spawned as — the `PROGRAM` constants of `providers::claude` and
/// `providers::codex`, which are private to those modules.
///
/// Exhaustive on a closed enum, so a provider cannot be added to the catalog without deciding what
/// `roles.list` should probe for it.
fn provider_program(provider: ProviderName) -> &'static str {
    match provider {
        ProviderName::Claude => "claude",
        ProviderName::Codex => "codex",
    }
}

// ---------------------------------------------------------------------------
// Params
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HelloParams {
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    client_version: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubscribeParams {
    #[serde(default)]
    run_id: Option<RunId>,
    #[serde(default)]
    since_seq: Option<u64>,
}

/// The roles a door may delegate to. A closed enum, so no string from a client can name a role the
/// config was never asked about (design, § Security: "closed enums").
#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
enum DelegatableRole {
    Builder,
    Reviewer,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DelegateParams {
    role: DelegatableRole,
    task: Task,
    #[serde(default)]
    run_id: Option<RunId>,
    #[serde(default = "fresh_session")]
    session: String,
    #[serde(default)]
    base_ref: Option<String>,
    /// T84: attached only by `acp mcp-proxy` when it was started as a spawned lead's MCP door
    /// (`ACP_LEAD_RUN_ID`). Optional and additive — protocol version stays 1 — and every other
    /// caller (app, CLI, terminal lead) simply omits it.
    #[serde(default)]
    caller_run_id: Option<RunId>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LeadStartParams {
    message: String,
    #[serde(default)]
    audit_selection: Option<crate::workspace::git::audit::Selection>,
    #[serde(default)]
    expected_team: Option<crate::core::team::Team>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanStartParams {
    plan: crate::core::plan::Plan,
    /// T84: same attestation as `DelegateParams.callerRunId`.
    #[serde(default)]
    caller_run_id: Option<RunId>,
}

fn fresh_session() -> String {
    "fresh".to_string()
}

impl DelegateParams {
    /// The door's own validation: the **shape** of caller input, which `core::policy` deliberately
    /// does not check (`policy.rs`: "`InvalidTask` is raised by the door — the shape of caller
    /// input is a parsing concern, not a state concern"). `baseRef` is checked by
    /// `policy::check_delegate`, so it is passed through untouched.
    fn into_request(self) -> Result<DelegateRequest, RpcError> {
        check_task(&self.task)?;
        let session = match self.session.as_str() {
            "fresh" => SessionSpec::Fresh,
            other => match other.strip_prefix("resume:") {
                Some(id) => SessionSpec::Resume(id.parse::<AgentId>().map_err(|_| {
                    RpcError::invalid_params(
                        "session must be \"fresh\" or \"resume:<agentId uuid>\"".to_string(),
                    )
                })?),
                None => {
                    return Err(RpcError::invalid_params(
                        "session must be \"fresh\" or \"resume:<agentId uuid>\"".to_string(),
                    ))
                }
            },
        };
        Ok(DelegateRequest {
            run_id: self.run_id,
            role: match self.role {
                DelegatableRole::Builder => RoleName::Builder,
                DelegatableRole::Reviewer => RoleName::Reviewer,
            },
            task: self.task,
            model: None,
            session,
            base_ref: self.base_ref,
            // A door never knows an existing worktree: the actor resolves it from the session.
            worktree: None,
            steps: None,
            caller_run_id: self.caller_run_id,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SendMessageParams {
    #[serde(default)]
    caller_run_id: Option<RunId>,
    agent_id: AgentId,
    message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuditStartParams {
    task: Task,
    selection: crate::workspace::git::audit::Selection,
    #[serde(default)]
    caller_run_id: Option<RunId>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AwaitResultParams {
    agent_id: AgentId,
    #[serde(default)]
    timeout_sec: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GetStatusParams {
    #[serde(default)]
    run_id: Option<RunId>,
    #[serde(default)]
    agent_id: Option<AgentId>,
    #[serde(default)]
    last_events: Option<usize>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CancelParams {
    #[serde(default)]
    caller_run_id: Option<RunId>,
    agent_id: AgentId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GateRequestParams {
    #[serde(default)]
    caller_run_id: Option<RunId>,
    run_id: RunId,
    kind: GateKind,
    summary: String,
    #[serde(default)]
    payload: GatePayloadArgs,
}

/// The **closed** gate payload a door accepts — `files`, and nothing else.
///
/// [`GatePayload`] is the core's own record and carries `worktree`, `diffPath`, `diffHash`,
/// `preSha` and `spendUsd`: the fields that tell an approval *what to commit*. Only the control
/// plane's own loop may set those, from a diff it froze and a verdict bound to it — a caller that
/// could name the worktree could mint an `integrate` gate over a tree nobody reviewed, and this is
/// the door that can then approve it. The MCP door closes the same shape (design, § MCP tools:
/// `payload = {}`); `deny_unknown_fields` is what makes the refusal explicit rather than silent
/// (adversarial review of T39).
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GatePayloadArgs {
    #[serde(default)]
    files: Vec<String>,
}

impl GatePayloadArgs {
    fn into_payload(self) -> Result<GatePayload, RpcError> {
        check_file_list("payload.files", &self.files).map_err(RpcError::invalid_params)?;
        Ok(GatePayload {
            files: self.files,
            ..GatePayload::default()
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResolveGateParams {
    #[serde(default)]
    caller_run_id: Option<RunId>,
    gate_id: GateId,
    approve: bool,
    #[serde(default)]
    feedback: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GateApproveParams {
    gate_id: GateId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryPreviewParams { run_id: RunId }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GateDenyParams {
    gate_id: GateId,
    #[serde(default)]
    feedback: Option<String>,
}

/// The params of a method that takes none — `roles.list` and `team.get`.
///
/// A braced empty struct rather than a unit one: the app encodes `{}` (`EmptyParams` in
/// `ACPMethods.swift`) and a unit struct would only accept `null`. `deny_unknown_fields` still
/// rejects a client that puts something in it, so a filter someone expected to work is an error
/// rather than a silently ignored argument.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckIdParams { id: uuid::Uuid }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckHistoryParams { #[serde(default)] offset: usize }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckPageParams { id: uuid::Uuid, #[serde(default)] offset: usize }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckSourceParams { id: uuid::Uuid, file: String, line: usize }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckFixParams { id: uuid::Uuid, indices: Vec<usize> }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionAcquireParams {
    label: String,
    /// Bind the lease to this host process: no renewal, and it ends when that process exits.
    #[serde(default)]
    owner_pid: Option<i32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionHandleParams {
    instance_id: uuid::Uuid,
    session_id: uuid::Uuid,
    /// `session.release` only: the owner is exiting; a managed daemon stops promptly once
    /// nothing else needs it. Ignored by `session.renew`.
    #[serde(default)]
    stop_if_unneeded: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DaemonStopParams { mode: crate::core::lifecycle::StopMode }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TeamSetParams {
    team: Team,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// `clientName` lands in the durable log as the resolving actor, so it is bounded, printable, and
/// **never `"mcp"`**: `Actor` serializes as a bare string and `"mcp"` is the MCP channel's own
/// spelling, so accepting it would let a socket client forge the other door's identity.
fn check_client_name(name: String) -> Result<String, RpcError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_CLIENT_NAME_CHARS {
        return Err(RpcError::invalid_params(format!(
            "clientName must be 1-{MAX_CLIENT_NAME_CHARS} characters"
        )));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(RpcError::invalid_params(
            "clientName must not contain control characters".to_string(),
        ));
    }
    if trimmed == Actor::Mcp.as_str() {
        return Err(RpcError::invalid_params(format!(
            "clientName must not be \"{}\" — that is the MCP channel's own actor",
            Actor::Mcp
        )));
    }
    Ok(trimmed.to_string())
}

fn check_chars(what: &str, value: &str, min: usize, max: usize) -> Result<(), RpcError> {
    let count = value.chars().count();
    if count < min || count > max {
        return Err(RpcError::invalid_params(format!(
            "{what} must be {min}-{max} characters, got {count}"
        )));
    }
    Ok(())
}

/// The bounds on a caller-supplied path list: how many, how long, and what a path may be.
///
/// Shared by `delegate`'s `task.files` and `request_human_gate`'s `payload.files`, because both are
/// untrusted path lists that end up in the durable log — and because two doors disagreeing about
/// what a path may contain is exactly the kind of drift a single function prevents. The caller
/// decides how to report it: `delegate` mirrors the MCP door's `invalid_task` `PolicyCode`, the gate
/// door reports invalid params (there is no `PolicyCode` for a gate payload, and every bound here
/// except the path shape is one JSON Schema can express).
fn check_file_list(what: &str, files: &[String]) -> Result<(), String> {
    if files.len() > MAX_FILES {
        return Err(format!("{what} must have at most {MAX_FILES} entries"));
    }
    for file in files {
        let chars = file.chars().count();
        if chars == 0 || chars > MAX_FILE_CHARS {
            return Err(format!(
                "each {what} entry must be 1-{MAX_FILE_CHARS} characters"
            ));
        }
        // Not expressible in JSON Schema, so it is enforced here and stated in the contract: a
        // repo-relative path with no escape, no NUL and no newline.
        if file.starts_with('/')
            || file.split('/').any(|part| part == "..")
            || file.contains('\0')
            || file.contains('\n')
        {
            return Err(format!(
                "{what} entries must be repo-relative with no `..` segment, NUL or newline"
            ));
        }
    }
    Ok(())
}

/// The task bounds the design fixes, raised as `invalid_task` — the same `PolicyCode` the MCP
/// door's `validate()` raises, so a lead sees one rejection whichever door it came through.
fn check_task(task: &Task) -> Result<(), RpcError> {
    match task_shape_error(task) {
        Some(reason) => Err(RpcError::policy(PolicyCode::InvalidTask.as_str(), reason)),
        None => Ok(()),
    }
}

/// The bounds themselves, door-agnostic — `submit_plan` on the MCP door runs the identical
/// checks per work item (B3) and wraps the reason in its own error shape.
pub(crate) fn task_shape_error(task: &Task) -> Option<String> {
    check_task_bounds(task).err()
}

fn check_task_bounds(task: &Task) -> Result<(), String> {
    let invalid = |reason: String| reason;
    if task.id.is_empty() || task.id.chars().count() > MAX_TASK_ID_CHARS {
        return Err(invalid(format!(
            "task.id must be 1-{MAX_TASK_ID_CHARS} characters"
        )));
    }
    if !task
        .id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(invalid("task.id must be [A-Za-z0-9._-] only".to_string()));
    }
    if task.title.is_empty() || task.title.chars().count() > MAX_TITLE_CHARS {
        return Err(invalid(format!(
            "task.title must be 1-{MAX_TITLE_CHARS} characters"
        )));
    }
    let description = task.description.chars().count();
    if !(MIN_DESCRIPTION_CHARS..=MAX_DESCRIPTION_CHARS).contains(&description) {
        return Err(invalid(format!(
            "task.description must be {MIN_DESCRIPTION_CHARS}-{MAX_DESCRIPTION_CHARS} characters"
        )));
    }
    if let Err(reason) = check_file_list("task.files", &task.files) {
        return Err(invalid(reason));
    }
    if task.acceptance.is_empty() || task.acceptance.len() > MAX_ACCEPTANCE {
        return Err(invalid(format!(
            "task.acceptance must have 1-{MAX_ACCEPTANCE} entries"
        )));
    }
    if task
        .acceptance
        .iter()
        .any(|line| line.chars().count() > MAX_ACCEPTANCE_CHARS)
    {
        return Err(invalid(format!(
            "each task.acceptance entry must be at most {MAX_ACCEPTANCE_CHARS} characters"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The fan-out
// ---------------------------------------------------------------------------

/// One task per connection: the **single writer of the event stream**, and the only thing that
/// performs a `subscribe`.
///
/// **Why the subscribe happens here.** A `subscribe` is three steps — attach a receiver, take the
/// `sinceSeq` snapshot, emit the backfill — and the middle one is a round trip to the actor. Doing
/// them in the calling task makes two tasks write event lines into one outbox, and then a live
/// event of run B, pulled off the *old* receiver while the snapshot is in flight, can land ahead of
/// B's backfill. The client's mandated dedupe is a per-run monotonic cursor, so it answers that
/// order by dropping the backfill — the contract's "delivered twice rather than lost" turned into
/// silent loss, on exactly the macOS client's connect and lag-recovery path (one `subscribe` per
/// run, adversarial review of T39). Serving the whole call here removes the second writer: while
/// this task is inside `core.status`, nothing is being delivered, so nothing can overtake the
/// backfill it is about to emit.
///
/// The order at the seam is therefore: **backfill** (seq-ordered), then whatever the **replaced**
/// receiver still held (semantics 2 — it is drained, never dropped), then the new receiver's live
/// stream. Duplicates are possible across the seam and are the client's to dedupe; gaps are not.
///
/// The one case no transport can repair: an event this connection was *already given* before the
/// `subscribe` for its run arrived. The client's cursor is then ahead of the history it asks for,
/// and it will drop what it has not seen. That is a property of "one unfiltered live stream plus
/// per-run cursors", not of this loop, and the recoverable truth stays the log on disk.
async fn fan_out(
    core: CoreHandle,
    mut inbox: mpsc::Receiver<SubscribeRequest>,
    out: mpsc::Sender<String>,
) {
    enum Step {
        Subscribe(SubscribeRequest),
        Event(Result<Arc<Event>, broadcast::error::RecvError>),
        Done,
    }

    let mut live: Option<broadcast::Receiver<Arc<Event>>> = None;
    // The newest `seq` this connection has been given, for `acp.lagged{fromSeq}`. Owned by this
    // task because this task is the only thing that delivers.
    let mut delivered: u64 = 0;

    loop {
        let step = match live.as_mut() {
            None => match inbox.recv().await {
                Some(request) => Step::Subscribe(request),
                None => Step::Done,
            },
            Some(current) => tokio::select! {
                biased;
                request = inbox.recv() => match request {
                    Some(request) => Step::Subscribe(request),
                    None => Step::Done,
                },
                // `broadcast::Receiver::recv` is cancel-safe: losing this race drops no event.
                event = current.recv() => Step::Event(event),
            },
        };

        match step {
            Step::Subscribe(request) => {
                if !subscribe(&core, request, &mut live, &out, &mut delivered).await {
                    return;
                }
            }
            Step::Event(Ok(event)) => {
                if !deliver(&event, &out, &mut delivered).await {
                    return;
                }
            }
            Step::Event(Err(broadcast::error::RecvError::Lagged(skipped))) => {
                if !lagged(skipped, &out, delivered).await {
                    return;
                }
            }
            // The core is gone. Keep the connection — every door will answer `-32001` — but stop
            // pretending to stream.
            Step::Event(Err(broadcast::error::RecvError::Closed)) => live = None,
            Step::Done => return,
        }
    }
}

/// One `subscribe`, start to finish, on the fan-out's own thread of control.
///
/// Returns `false` when the client is gone and the fan-out should stop.
async fn subscribe(
    core: &CoreHandle,
    request: SubscribeRequest,
    live: &mut Option<broadcast::Receiver<Arc<Event>>>,
    out: &mpsc::Sender<String>,
    delivered: &mut u64,
) -> bool {
    let SubscribeRequest {
        run_id,
        since_seq,
        reply,
    } = request;

    // (1) Attach FIRST. Everything appended from this instant is queued in the broadcast buffer
    //     while the snapshot below is taken, so an event that lands during the backfill window is
    //     delivered twice rather than lost. Clients dedupe by `seq`.
    let fresh = core.events();

    // (2) Then the snapshot. Bounded by the projection, which is what the client uses it for: the
    //     gap between its own `get_status` and this call.
    let status = match core
        .status(StatusQuery {
            run_id,
            agent_id: None,
            last_events: MAX_LAST_EVENTS,
        })
        .await
    {
        Ok(status) => status,
        Err(err) => {
            // The current subscription is untouched: a failed `subscribe` must not cost a client
            // the stream it already had.
            let _ = reply.send(Err(RpcError::from_core(err)));
            return true;
        }
    };
    let last_seq = status
        .runs
        .iter()
        .map(|run| run.last_seq)
        .max()
        .unwrap_or(0);

    // (3) The backfill, before anything else this task will ever write again.
    if let Some(since) = since_seq {
        let mut history: Vec<&Event> = status
            .events
            .iter()
            .filter(|event| {
                event.base.seq > since && run_id.is_none_or(|run| event.base.run_id == run)
            })
            .collect();
        history.sort_by_key(|event| event.base.seq);
        for event in history {
            if !deliver(event, out, delivered).await {
                return false;
            }
        }
    }

    // (4) Then the receiver this call replaces, drained rather than dropped (semantics 2), and only
    //     then the new one.
    if let Some(mut replaced) = live.replace(fresh) {
        if !drain(&mut replaced, out, delivered).await {
            return false;
        }
    }

    let _ = reply.send(Ok(json!({
        "ok": true,
        "protocolVersion": PROTOCOL_VERSION,
        "lastSeq": last_seq,
    })));
    true
}

/// Everything a replaced receiver had already buffered, before it is dropped.
async fn drain(
    replaced: &mut broadcast::Receiver<Arc<Event>>,
    out: &mpsc::Sender<String>,
    delivered: &mut u64,
) -> bool {
    loop {
        match replaced.try_recv() {
            Ok(event) => {
                if !deliver(&event, out, delivered).await {
                    return false;
                }
            }
            Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                if !lagged(skipped, out, *delivered).await {
                    return false;
                }
            }
            Err(broadcast::error::TryRecvError::Empty | broadcast::error::TryRecvError::Closed) => {
                return true
            }
        }
    }
}

async fn deliver(event: &Event, out: &mpsc::Sender<String>, delivered: &mut u64) -> bool {
    let mut line = event_notification(event);
    line.push('\n');
    if out.send(line).await.is_err() {
        return false;
    }
    *delivered = (*delivered).max(event.base.seq);
    true
}

/// The backpressure signal. `fromSeq` is the newest `seq` this connection was actually given: the
/// client re-`get_status`es and re-`subscribe`s per run from its own cursors, because a global gap
/// cannot say which run lost what.
async fn lagged(skipped: u64, out: &mpsc::Sender<String>, delivered: u64) -> bool {
    tracing::warn!(
        skipped,
        from_seq = delivered,
        "a socket subscriber fell behind"
    );
    let mut line = notification(
        NOTIFY_LAGGED,
        &json!({ "protocolVersion": PROTOCOL_VERSION, "fromSeq": delivered }),
    );
    line.push('\n');
    out.send(line).await.is_ok()
}

// ---------------------------------------------------------------------------
// JSON-RPC framing
// ---------------------------------------------------------------------------

/// One request, already classified.
#[derive(Debug)]
struct Request {
    /// `None` for a notification from the client, which is never answered.
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

/// One error object. `data` carries `{code, reason}` for a `-32000`, so the client can branch on the
/// `PolicyCode` rather than on prose.
#[derive(Debug)]
struct RpcError {
    code: i64,
    message: String,
    data: Option<Value>,
}

impl RpcError {
    fn new(code: i64, message: String) -> Self {
        Self {
            code,
            message,
            data: None,
        }
    }

    fn invalid_params(message: String) -> Self {
        Self::new(INVALID_PARAMS, message)
    }

    fn unknown_method(method: &str) -> Self {
        Self::new(METHOD_NOT_FOUND, format!("unknown method `{method}`"))
    }

    /// A rejection the caller can act on: `data.code` is a `PolicyCode`'s wire spelling, or one of
    /// the door-level codes in [`RpcError::from_core`] — one flat, closed-ish namespace, so a client
    /// never has to know which layer said no.
    fn policy(code: &str, reason: String) -> Self {
        Self {
            code: POLICY_REJECTED,
            message: reason.clone(),
            data: Some(json!({ "code": code, "reason": reason })),
        }
    }

    /// The same, with the structured evidence a [`PolicyError`] carried merged into `data` (the
    /// allowed models, the budget figures, `team.set`'s per-role `issues`).
    fn from_policy(err: PolicyError) -> Self {
        let mut error = Self::policy(err.code.as_str(), err.reason);
        if let (Some(Value::Object(data)), Some(Value::Object(detail))) =
            (error.data.as_mut(), err.detail)
        {
            for (key, value) in detail {
                data.entry(key).or_insert(value);
            }
        }
        error
    }

    /// A `team.set` refused by [`validate_team`](crate::core::team::validate_team): `data.issues`
    /// carries **every** failed assignment, in the shape `TeamSetIssue` decodes
    /// (`apps/acp-mac/…/Wire/ACPMethods.swift`), so the Team Builder can point at the exact rows a
    /// human has to fix instead of showing one flat message.
    ///
    /// `reason` renders the same list as prose, worded exactly as `core::loop`'s own `team_invalid`
    /// rejection, so a refusal reads the same whether it came from this door or from a `delegate`.
    fn team_invalid(issues: Vec<TeamIssue>) -> Self {
        let reason = issues
            .iter()
            .map(|issue| format!("{} {}: {}", issue.role, issue.code, issue.detail))
            .collect::<Vec<_>>()
            .join("; ");
        Self::from_policy(
            PolicyError::new(PolicyCode::TeamInvalid, reason)
                .with_detail(json!({ "issues": issues })),
        )
    }

    /// A [`TeamError`] as this door reports it.
    ///
    /// `team_unsupported_version` is its own code, never folded into `team_invalid`: one file is
    /// fine and this build is old, the other file is broken, and the client shows a different thing
    /// for each. `found`/`supported` ride along so it can say which.
    fn from_team(err: TeamError) -> Self {
        let reason = err.to_string();
        match err {
            TeamError::UnsupportedVersion { found, supported } => {
                let mut error = Self::policy("team_unsupported_version", reason);
                if let Some(Value::Object(data)) = error.data.as_mut() {
                    data.insert("found".to_string(), json!(found));
                    data.insert("supported".to_string(), json!(supported));
                }
                error
            }
            TeamError::Invalid(_) => Self::policy(PolicyCode::TeamInvalid.as_str(), reason),
            TeamError::Io(_) => Self::policy("team_io", reason),
        }
    }

    fn from_core(err: CoreError) -> Self {
        match err {
            CoreError::Unavailable => Self {
                code: CORE_UNAVAILABLE,
                message: err.to_string(),
                data: Some(json!({
                    "code": "core_unavailable",
                    "reason": "the control plane actor is not running",
                })),
            },
            CoreError::Policy(err) => Self::from_policy(err),
            CoreError::Lifecycle { code, reason } => Self::policy(code, reason),
            CoreError::UnknownGate(_) => Self::policy("unknown_gate", err.to_string()),
            CoreError::UnknownRun(_) => Self::policy("unknown_run", err.to_string()),
            CoreError::NoWorktree(_) => Self::policy("no_worktree", err.to_string()),
            CoreError::GatePayload { .. } => Self::policy("gate_payload", err.to_string()),
            CoreError::Registry(_) => Self::policy("registry_failed", err.to_string()),
            CoreError::Git(_) => Self::policy("git_failed", err.to_string()),
        }
    }
}

/// Classifies one line. `Err` carries the id to answer with — `null` when the line was too broken
/// to have one, as JSON-RPC requires.
fn parse_request(line: &str) -> Result<Request, (Value, RpcError)> {
    let value: Value = serde_json::from_str(line)
        .map_err(|err| (Value::Null, RpcError::new(PARSE_ERROR, err.to_string())))?;
    let Some(object) = value.as_object() else {
        return Err((
            Value::Null,
            RpcError::new(
                INVALID_REQUEST,
                "a JSON-RPC request must be an object".to_string(),
            ),
        ));
    };
    // An id that is not a string, number or null is not one this daemon will echo.
    let id = match object.get("id") {
        None | Some(Value::Null) => None,
        Some(id @ (Value::String(_) | Value::Number(_))) => Some(id.clone()),
        Some(_) => {
            return Err((
                Value::Null,
                RpcError::new(
                    INVALID_REQUEST,
                    "id must be a string or a number".to_string(),
                ),
            ))
        }
    };
    let for_error = id.clone().unwrap_or(Value::Null);
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err((
            for_error,
            RpcError::new(INVALID_REQUEST, "jsonrpc must be \"2.0\"".to_string()),
        ));
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Err((
            for_error,
            RpcError::new(INVALID_REQUEST, "method must be a string".to_string()),
        ));
    };
    Ok(Request {
        id,
        method: method.to_string(),
        params: object.get("params").cloned(),
    })
}

/// Typed params, or `-32602`. An absent or `null` `params` member is an empty object, so a method
/// whose fields are all optional can be called with no params at all.
fn parse_params<T: DeserializeOwned>(params: Option<Value>) -> Result<T, RpcError> {
    let value = match params {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(value) => value,
    };
    serde_json::from_value(value).map_err(|err| RpcError::invalid_params(err.to_string()))
}

/// A typed result as JSON. A serialization failure is the daemon's own bug, never the caller's.
fn to_value<T: Serialize>(value: &T) -> Result<Value, RpcError> {
    serde_json::to_value(value).map_err(|err| {
        tracing::error!(%err, "a socket result could not be serialized");
        RpcError::policy(
            "internal_error",
            format!("the result could not be encoded: {err}"),
        )
    })
}

fn response(id: &Value, result: &Value) -> String {
    encode(&json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn error_response(id: &Value, err: &RpcError) -> String {
    let mut error = json!({ "code": err.code, "message": err.message });
    if let (Some(object), Some(data)) = (error.as_object_mut(), err.data.clone()) {
        object.insert("data".to_string(), data);
    }
    encode(&json!({ "jsonrpc": "2.0", "id": id, "error": error }))
}

/// A notification: no `id`, never answered.
///
/// `protocolVersion` rides on all three, not only on `acp.event` as the contract's table shows: the
/// two clients ignore keys they do not know, and a line that names its own version can be rejected
/// by a client that does not speak it without having to remember which method carried it.
fn notification(method: &str, params: &Value) -> String {
    encode(&json!({ "jsonrpc": "2.0", "method": method, "params": params }))
}

/// `acp.event{protocolVersion, event}` — the `Event` exactly as written to `events.jsonl`.
fn event_notification(event: &Event) -> String {
    notification(
        NOTIFY_EVENT,
        &json!({ "protocolVersion": PROTOCOL_VERSION, "event": event }),
    )
}

/// One line of JSON. Only a daemon bug can fail here, and dropping the frame would strand the
/// caller, so the fallback is a well-formed internal error rather than a panic.
fn encode(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|err| {
        tracing::error!(%err, "a socket frame could not be encoded");
        String::from(
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"frame encoding failed","data":{"code":"internal_error","reason":"frame encoding failed"}}}"#,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_contract_constants_are_the_ones_the_design_fixes() {
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(MAX_LINE_BYTES, 1024 * 1024);
        assert_eq!(MAX_SOCKET_PATH_BYTES, 100);
    }

    #[test]
    fn a_path_over_the_limit_is_refused_before_anything_is_created() {
        let dir = tempfile::tempdir().expect("tempdir");
        let long = dir.path().join("x".repeat(MAX_SOCKET_PATH_BYTES + 1));
        let err = bind(&long).expect_err("the path is over the limit");
        assert!(matches!(err, IpcError::PathTooLong { .. }), "{err:?}");
        assert!(
            err.to_string().contains("ACP_STATE_DIR"),
            "the error names the remedy: {err}"
        );
        assert!(!long.exists(), "nothing was created");
    }

    #[test]
    fn a_client_may_not_call_itself_mcp() {
        assert!(check_client_name("mcp".to_string()).is_err());
        assert!(check_client_name(" acp-mac ".to_string()).is_ok());
        assert!(check_client_name("  ".to_string()).is_err());
        assert!(check_client_name("a\u{7}b".to_string()).is_err());
        assert!(check_client_name("x".repeat(MAX_CLIENT_NAME_CHARS + 1)).is_err());
    }

    #[test]
    fn parse_request_classifies_the_four_broken_shapes() {
        assert_eq!(
            parse_request("not json").expect_err("malformed").1.code,
            PARSE_ERROR
        );
        assert_eq!(
            parse_request("[1,2]").expect_err("not an object").1.code,
            INVALID_REQUEST
        );
        assert_eq!(
            parse_request(r#"{"jsonrpc":"1.0","id":1,"method":"hello"}"#)
                .expect_err("wrong version")
                .1
                .code,
            INVALID_REQUEST
        );
        assert_eq!(
            parse_request(r#"{"jsonrpc":"2.0","id":1}"#)
                .expect_err("no method")
                .1
                .code,
            INVALID_REQUEST
        );
        let request = parse_request(r#"{"jsonrpc":"2.0","method":"subscribe"}"#)
            .expect("a client notification is a request with no id");
        assert!(request.id.is_none());
        assert_eq!(request.method, "subscribe");
    }

    #[test]
    fn the_task_bounds_are_the_designs() {
        let ok = Task {
            id: "T39".to_string(),
            title: "socket".to_string(),
            description: "implement the socket door".to_string(),
            files: vec!["src/ipc/socket.rs".to_string()],
            acceptance: vec!["it binds".to_string()],
        };
        check_task(&ok).expect("a well-formed task");

        let mut escaping = ok.clone();
        escaping.files = vec!["../etc/passwd".to_string()];
        let err = check_task(&escaping).expect_err("a `..` segment is refused");
        assert_eq!(err.code, POLICY_REJECTED);

        let mut short = ok.clone();
        short.description = "too short".to_string();
        assert!(check_task(&short).is_err());

        let mut no_acceptance = ok.clone();
        no_acceptance.acceptance.clear();
        assert!(check_task(&no_acceptance).is_err());

        let mut bad_id = ok;
        bad_id.id = "T 39".to_string();
        assert!(check_task(&bad_id).is_err());
    }

    #[test]
    fn a_policy_rejection_carries_its_code_and_evidence() {
        let err = RpcError::from_core(CoreError::Policy(
            PolicyError::new(PolicyCode::BudgetRunExceeded, "out of money")
                .with_detail(json!({ "runBudgetUsd": 15.0 })),
        ));
        assert_eq!(err.code, POLICY_REJECTED);
        let data = err.data.expect("data");
        assert_eq!(data["code"], json!("budget_run_exceeded"));
        assert_eq!(data["reason"], json!("out of money"));
        assert_eq!(data["runBudgetUsd"], json!(15.0));
    }

    #[test]
    fn an_absent_core_is_minus_32001() {
        let err = RpcError::from_core(CoreError::Unavailable);
        assert_eq!(err.code, CORE_UNAVAILABLE);
        assert_eq!(err.data.expect("data")["code"], json!("core_unavailable"));
    }
}
