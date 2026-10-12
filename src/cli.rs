//! The `acp` command line (design, § `src/main.rs`, `src/cli.rs` and § Process model).
//!
//! Six subcommands, and the split between them is the design's trust model, not a convenience:
//!
//! * `serve` is the daemon. It binds **one** repository, owns `serve.lock`, and runs the MCP door
//!   on stdio and the socket door in the state dir. Nothing it does may reach stdout — that is the
//!   MCP channel — so everything it has to say goes to stderr or to `$ACP_STATE_DIR/acp.log`.
//! * `status` without `--follow` reads the durable log **read-only**: no socket, no lock, and
//!   therefore an answer even when no daemon is running.
//! * `status --follow`, `gate approve` and `gate deny` are socket clients. `gate approve` is *the*
//!   human approval path (S2): it exists on this transport and nowhere else, so an agent driving
//!   the MCP door can never approve its own integration.
//! * `team get`, `team set` and `team roles` are also socket clients. The daemon remains the
//!   authority that reads, validates and writes `team.json`; the CLI never edits it directly.
//! * `gc` and `doctor` are offline tools over the same log and the same config.
//!
//! This module is where `anyhow` lives. Every library module underneath it uses `thiserror`, so an
//! error arriving here already knows what it is; the job here is to add the context a human needs
//! and to choose the exit code.
//!
//! It is a module of the **binary** rather than of the library: the library is what the macOS app
//! and the tests link, and none of them want the CLI's argument parser or its `anyhow` chain.

use std::fs::{self, OpenOptions};
use std::io::{self, Seek as _, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::io::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_control_plane::core::r#loop::reattach_running;
use agent_control_plane::core::registry::{now_rfc3339, Registry};
use agent_control_plane::core::supervisor::{ProcessProbe as _, PsProbe, Supervisor};
use agent_control_plane::core::team::{self, validate_team};
use agent_control_plane::core::types::{
    AgentHandle, Attempt, Gate, GateId, GateStatus, ProviderName, RolesConfig, Run, RunId,
};
use agent_control_plane::core::{
    channel, human_action, run_actor, spawn_signal_forwarder, spawn_tick_task, Core, DEFAULT_TICK,
};
use agent_control_plane::ipc::socket::{
    serve_socket, ServerIdentity, MAX_SOCKET_PATH_BYTES, PROTOCOL_VERSION,
};
use agent_control_plane::mcp;
use agent_control_plane::providers::codex::SANDBOX_VERIFIED_VERSION;
use agent_control_plane::providers::{base_env, find_on_path, sandboxes_writes};
use agent_control_plane::roles::loader::load_roles;
use agent_control_plane::workspace::git;
use anyhow::{anyhow, bail, Context as _};
use rmcp::model::CallToolResult;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[path = "cli_entry.rs"]
mod entry;

#[path = "cli_app.rs"]
mod app_link;
use app_link::open_task_app;

// ---------------------------------------------------------------------------
// Contract constants
// ---------------------------------------------------------------------------

/// The three files `serve` owns inside the state dir (design, § On-disk layout).
const LOCK_FILE: &str = "serve.lock";
const SOCKET_FILE: &str = "acp.sock";
const LOG_FILE: &str = "acp.log";

/// The line `.git/info/exclude` must carry, and the forms of it this accepts.
const EXCLUDE_ENTRY: &str = ".acp/";
const EXCLUDE_FORMS: [&str; 4] = [".acp/", ".acp", "/.acp/", "/.acp"];

/// A second `serve` against a held lock (design, § Process model: "alive → exit 3 naming the
/// holder"). Distinct from 1 so a supervisor can tell "already running" from "failed to start".
const EXIT_LOCK_HELD: i32 = 3;
const EXIT_OK: i32 = 0;
const EXIT_FAILED: i32 = 1;

/// This client's name over the socket. It is recorded verbatim as the resolving actor, so the
/// durable log distinguishes a gate a human approved here from one the app approved.
const CLIENT_NAME: &str = "cli";
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// `serve --stop`: how long the holder is given to unlink its lock after `SIGTERM`, and how often
/// that is checked. The bound exists so a wedged daemon is reported rather than waited on forever.
const STOP_LIMIT: Duration = Duration::from_secs(15);
const STOP_POLL: Duration = Duration::from_millis(25);

/// How long each of `serve`'s tasks is given to finish after the shutdown token fires.
const SHUTDOWN_LIMIT: Duration = Duration::from_secs(10);

/// How long `doctor` waits for a `--version` from a provider CLI before calling it unresponsive.
///
/// Long enough for a cold first exec (Gatekeeper checks a freshly installed binary on macOS), short
/// enough that a wedged CLI is *reported* rather than waited on. Exceeding it is a warning, never a
/// failure: the binary is there, it just did not answer in time.
const VERSION_PROBE_LIMIT: Duration = Duration::from_secs(10);

/// How old `ratesUpdated` may be before `doctor` warns. Prices move; a stale card silently
/// mis-prices every run, which is a thing a human should be told once rather than discover in a
/// budget rejection.
const RATES_STALE_DAYS: i64 = 90;

/// Characters of `sha256(realpath(repoRoot))` in the default state dir name.
const STATE_HASH_CHARS: usize = 16;

/// The supervisor→actor signal channel. Wake-ups only (the durable events are already written when
/// one is sent), so the capacity only has to absorb a burst.
const SIGNAL_CAPACITY: usize = 64;

// ---------------------------------------------------------------------------
// The grammar
// ---------------------------------------------------------------------------

#[derive(clap::Parser, Debug)]
#[command(
    name = "acp",
    version,
    about = "agent-control-plane — delegate to role-scoped worker sessions, integrate behind a human gate"
)]
pub struct Cli {
    /// The repository to bind. Defaults to the working directory.
    #[arg(long, global = true, value_name = "PATH")]
    pub repo: Option<PathBuf>,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(clap::Subcommand, Debug)]
pub enum Cmd {
    /// Guided human setup: choose workers and start a task with the configured Claude lead.
    Start,
    /// Open this exact task in the macOS app; leaves coordination in the current host.
    App {
        run_id: uuid::Uuid,
        /// Print a local task link instead of opening the app.
        #[arg(long)]
        print: bool,
    },
    /// Run the control plane: the socket door, plus the MCP door on stdio unless disabled.
    Serve {
        /// Stop the running daemon instead: `SIGTERM` the lock holder and wait for it to go.
        #[arg(long)]
        stop: bool,
        /// Serve only the local socket and ignore stdin entirely.
        #[arg(long)]
        no_mcp: bool,
        /// Stop after all sessions, clients and work are gone for five minutes.
        #[arg(long, requires = "no_mcp")]
        managed: bool,
    },
    /// Serve the seven agent tools on stdio through the running daemon's local socket.
    McpProxy,
    /// Show what the event log says. Reads the log directly; no daemon needed.
    Status {
        /// Only this run.
        run_id: Option<String>,
        /// Stream events from a running daemon instead of printing a snapshot.
        #[arg(long)]
        follow: bool,
        /// Print JSON: one object for a snapshot, one line per event with `--follow`.
        #[arg(long)]
        json: bool,
    },
    /// Approve or deny a human gate. Approving is only ever done here (S2).
    #[command(subcommand)]
    Gate(GateCmd),
    /// Read or update the daemon's team, or show the role/provider catalog.
    #[command(subcommand)]
    Team(TeamCmd),
    /// Report — and with `--closed`, remove — the worktrees of closed lineages.
    Gc {
        /// Actually remove them.
        #[arg(long)]
        closed: bool,
    },
    /// Check the environment this control plane needs: CLIs, config, state dir, socket, lock.
    Doctor,
    /// Delegate one task to a worker role through the running daemon (socket `delegate`).
    Delegate {
        /// The role to spawn. A free string on purpose: the daemon's door is the one authority
        /// on what may be delegated, and this CLI never duplicates its validation.
        #[arg(long)]
        role: String,
        /// The task description (10–20 000 chars, enforced by the daemon).
        description: String,
        /// Task id, 1–64 of `[A-Za-z0-9._-]` (daemon-enforced). Default: `cli-<epoch-seconds>`.
        #[arg(long)]
        task_id: Option<String>,
        /// Task title. Default: the description's first 80 characters.
        #[arg(long)]
        title: Option<String>,
        /// A file the task expects to touch; repeatable.
        #[arg(long = "file", value_name = "PATH")]
        files: Vec<String>,
        /// An acceptance criterion; repeatable. At least one, because the daemon's task shape
        /// demands it — better refused by clap with a usage line than by a socket round-trip.
        #[arg(long = "accept", value_name = "TEXT", required = true)]
        acceptance: Vec<String>,
        /// Attach to an existing run instead of creating one.
        #[arg(long)]
        run_id: Option<String>,
        /// `fresh` (the daemon's default) or `resume:<agentId>`.
        #[arg(long)]
        session: Option<String>,
        /// Base ref for a new run's worktree.
        #[arg(long)]
        base_ref: Option<String>,
    },
    /// Start the daemon detached, or report the one already running. Idempotent: a live daemon
    /// answers exit 0, and the lock decides every race.
    Up {
        /// New daemon only: enable session-owned automatic cleanup; existing owners are unchanged.
        #[arg(long)]
        managed: bool,
    },
    /// Stop the running daemon (alias for `serve --stop`).
    Down,
    /// Stop when work and approvals finish. Ongoing coordination may continue until idle.
    Stop {
        /// Advanced: stop only the daemon, leaving workers alive for recovery.
        #[arg(long, conflicts_with_all = ["keep_running", "cancel_work"])]
        daemon_only: bool,
        /// Cancel this repository's work, then stop after workers and finalization end.
        #[arg(long, conflicts_with = "keep_running")]
        cancel_work: bool,
        /// Withdraw a scheduled stop.
        #[arg(long)]
        keep_running: bool,
    },
    /// Inspect daemon ownership or acquire, renew and release a session lease.
    #[command(subcommand)]
    Session(SessionCmd),
    /// Submit a B3 plan document to the running daemon (socket `plan.start`).
    Plan {
        /// A JSON file holding the plan: `{version, name, items: [{id, kind, …}]}`.
        file: PathBuf,
    },
    /// Audit existing changes with the selected checks and no builder or integration.
    Audit {
        /// JSON document: {task, selection: {baseRef, target: {kind, revision?}}}.
        file: PathBuf,
    },
    /// Local Swift/SwiftUI review. Requires a running daemon and no provider account.
    Review { #[command(subcommand)] action: ReviewAction },
    /// Wait for an agent's next result (socket `await_result`; one bounded call, no loop).
    Await {
        agent_id: String,
        /// 1..=300 (daemon-enforced). Default: the daemon's own (60).
        #[arg(long)]
        timeout_sec: Option<u64>,
    },
    /// Send one message to a live or resumable agent (socket `send_message`).
    Send { agent_id: String, message: String },
    /// Cancel an agent's running attempt (socket `cancel`).
    Cancel { agent_id: String },
}

/// `gate approve` carries no `--feedback` on purpose: the socket's `gate.approve` takes exactly
/// `{gateId}` (design, § Local IPC contract), and feedback only means something on the branch that
/// sends the builder back to work.
#[derive(clap::Subcommand, Debug)]
pub enum GateCmd {
    /// Approve the gate — for an `integrate` gate, this is what commits.
    Approve { gate_id: String },
    /// Deny the gate, optionally telling the builder why.
    Deny {
        gate_id: String,
        #[arg(long, value_name = "TEXT")]
        feedback: Option<String>,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum ReviewAction {
    Start {
        #[arg(long, default_value="project", value_parser=["project","changes","revision"])] scope: String,
        #[arg(long, default_value="HEAD")] base: String,
        #[arg(long)] revision: Option<String>,
    },
    List { #[arg(long,default_value_t=0)] offset: usize },
    Show { id: uuid::Uuid, #[arg(long,default_value_t=0)] offset: usize },
    Source { id: uuid::Uuid, file: String, line: usize },
    Cancel { id: uuid::Uuid },
    Catalog,
}

/// `team set` takes a document, not individual provider/model flags: the daemon validates the
/// whole team against one catalog and either atomically accepts it or writes nothing.
#[derive(clap::Subcommand, Debug)]
pub enum TeamCmd {
    /// Print the configured team, or `no team` when the daemon has no team file.
    Get,
    /// Ask the daemon to validate and atomically save a JSON team document.
    Set { file: PathBuf },
    /// Print the daemon's current role/provider catalog as JSON.
    Roles,
}

#[derive(clap::Subcommand, Debug)]
pub enum SessionCmd {
    Status,
    Acquire {
        #[arg(long, default_value = "terminal")]
        label: String,
        /// Bind the lease to the host session running this command — a recognized Claude Code or Codex ancestor process. It needs no renewal and ends when that
        /// process exits; a managed daemon then stops once nothing else needs it.
        #[arg(long, conflicts_with = "owner_pid")]
        bind_host: bool,
        /// Bind the lease to this process id instead.
        #[arg(long)]
        owner_pid: Option<i32>,
    },
    Renew { instance_id: uuid::Uuid, session_id: uuid::Uuid },
    Release {
        instance_id: uuid::Uuid,
        session_id: uuid::Uuid,
        /// This owner is exiting: stop a managed daemon promptly once no other session, client or
        /// work needs it. Manual and stdio owners are never stopped by a release.
        #[arg(long)]
        stop_if_unneeded: bool,
    },
}

/// Runs one subcommand and answers with the process's exit code.
///
/// # Errors
/// Anything the subcommand could not do. `main` prints it to stderr and exits 1; a code returned in
/// `Ok` is a *result*, not a failure — `serve` answering [`EXIT_LOCK_HELD`] is the clearest case.
pub async fn run(cli: Cli) -> anyhow::Result<i32> {
    let repo = cli.repo.as_deref();
    match cli.cmd {
        Cmd::Serve {
            stop: false,
            no_mcp,
            managed,
        } => serve(repo, no_mcp, managed).await,
        Cmd::Serve { stop: true, .. } => stop_serve(repo).await,
        Cmd::McpProxy => mcp_proxy(repo).await,
        Cmd::Status {
            run_id,
            follow,
            json,
        } => {
            let run = parse_run(run_id.as_deref())?;
            let places = Places::locate(repo).await?;
            if follow {
                follow_status(&places.state_dir, run, json).await
            } else {
                print_status(&places.state_dir, run, json)
            }
        }
        Cmd::Gate(gate) => resolve_gate(repo, gate).await,
        Cmd::Team(team) => manage_team(repo, team).await,
        Cmd::Gc { closed } => gc(repo, closed).await,
        Cmd::Doctor => doctor(repo).await,
        Cmd::Delegate {
            role,
            description,
            task_id,
            title,
            files,
            acceptance,
            run_id,
            session,
            base_ref,
        } => {
            let params = delegate_params(
                role,
                description,
                task_id,
                title,
                files,
                acceptance,
                run_id,
                session,
                base_ref,
            );
            call_socket(repo, "delegate", params).await
        }
        Cmd::Start => start(repo).await,
        Cmd::App { run_id, print } => open_task_app(repo, run_id, print).await,
        Cmd::Up { managed } => up(repo, managed).await,
        Cmd::Down => stop_serve(repo).await,
        Cmd::Session(command) => manage_session(repo, command).await,
        Cmd::Stop { daemon_only, keep_running, cancel_work } => {
            let mode = if keep_running { "keep_running" } else if daemon_only { "daemon_only" } else if cancel_work { "cancel_work" } else { "when_idle" };
            call_socket(repo, "daemon.stop", serde_json::json!({"mode": mode})).await
        }
        Cmd::Plan { file } => {
            let bytes = fs::read(&file)
                .with_context(|| format!("reading the plan document {}", file.display()))?;
            let plan: Value = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing the plan document {}", file.display()))?;
            call_socket(repo, "plan.start", json!({ "plan": plan })).await
        }
        Cmd::Review { action } => {
            let (method,params)=match action {
                ReviewAction::Start{scope,base,revision}=> ("checks.start",json!({"id":uuid::Uuid::new_v4(),"scope":scope,"baseRef":base,"revision":revision})),
                ReviewAction::List{offset}=>("checks.list",json!({"offset":offset})),
                ReviewAction::Show{id,offset}=>("checks.result",json!({"id":id,"offset":offset})),
                ReviewAction::Cancel{id}=>("checks.cancel",json!({"id":id})),
                ReviewAction::Source{id,file,line}=>("checks.source",json!({"id":id,"file":file,"line":line})),
                ReviewAction::Catalog=>("checks.catalog",json!({})),
            };
            call_socket(repo,method,params).await
        }
        Cmd::Audit { file } => {
            let bytes = fs::read(&file).with_context(|| format!("reading audit setup {}", file.display()))?;
            let args: mcp::server::AuditArgs = serde_json::from_slice(&bytes).context("parsing audit setup")?;
            call_socket(repo, "audit.start", serde_json::to_value(args)?).await
        }
        Cmd::Await {
            agent_id,
            timeout_sec,
        } => {
            let mut params = json!({ "agentId": agent_id });
            if let Some(seconds) = timeout_sec {
                params["timeoutSec"] = json!(seconds);
            }
            call_socket(repo, "await_result", params).await
        }
        Cmd::Send { agent_id, message } => {
            call_socket(
                repo,
                "send_message",
                json!({ "agentId": agent_id, "message": message }),
            )
            .await
        }
        Cmd::Cancel { agent_id } => {
            call_socket(repo, "cancel", json!({ "agentId": agent_id })).await
        }
    }
}

// ---------------------------------------------------------------------------
// Socket verbs (Track E)
// ---------------------------------------------------------------------------

/// One socket round-trip, printed as JSON: the shape every Track E verb shares. Validation is
/// deliberately absent — the daemon's doors are the single authority for roles, task shape,
/// message bounds and await bounds, and [`Client::call`] already surfaces their policy codes.
async fn call_socket(repo: Option<&Path>, method: &str, params: Value) -> anyhow::Result<i32> {
    let places = Places::locate(repo).await?;
    let mut client = Client::connect(&places.state_dir.join(SOCKET_FILE)).await?;
    let result = client.call(method, params).await?;
    print_json(&result)?;
    Ok(EXIT_OK)
}

/// Interactive human setup only. Host skills keep their existing conversation as lead and use
/// the narrower commands; this wizard never infers a host/model from process names.
async fn start(repo: Option<&Path>) -> anyhow::Result<i32> {
    use std::io::IsTerminal as _;
    if !io::stdin().is_terminal() {
        bail!("acp start needs an interactive terminal; in Codex or Claude use the ACP skill");
    }
    let root = git::repo_root(&cwd(repo)?).await?;
    println!("Project: {}", root.display());
    let prompt = ask_entry("Describe the task", None)?;
    if prompt.chars().count() < 10 || prompt.chars().count() > 20_000 {
        bail!("the task must contain 10–20,000 characters");
    }
    let managed = ask_entry_yes_no("Stop automatically after work finishes?", true)?;
    up(Some(&root), managed).await?;
    let places = Places::locate(Some(&root)).await?;
    let mut client = Client::connect(&places.state_dir.join(SOCKET_FILE)).await?;
    let lifetime = client.call("daemon.status", json!({})).await?;
    let actual_managed = lifetime["managed"].as_bool().unwrap_or(false);
    let catalog: team::RolesListResult = serde_json::from_value(client.call("roles.list", json!({})).await?)?;
    let saved = client.call("team.get", json!({})).await?;
    let previous: Option<team::Team> = saved.get("team").filter(|v| !v.is_null())
        .map(|v| serde_json::from_value(v.clone())).transpose()?;
    let setup = entry::collect(&catalog, previous.as_ref())?;
    println!("Daemon lifetime: {}", if actual_managed {
        "automatic cleanup after sessions, clients, work and approvals finish"
    } else { "keep running — manual/shared owner" });
    if actual_managed != managed { println!("The existing owner's lifetime is preserved; your requested policy applies only to a new daemon."); }
    if !ask_entry_yes_no("Save these choices and start the task?", false)? {
        println!("Setup cancelled. No task started.");
        return Ok(EXIT_OK);
    }
    client.call("team.set", json!({"team": setup.team})).await?;
    let mut params = json!({"message": prompt, "expectedTeam": setup.team});
    if let Some(selection) = setup.audit_selection { params["auditSelection"] = json!(selection); }
    let result = client.call("lead.start", params).await?;
    print_json(&result)?;
    println!("Watch progress with acp status --follow. Human approval remains in acp-mac or acp gate approve.");
    Ok(EXIT_OK)
}

fn ask_entry_yes_no(label: &str, default: bool) -> anyhow::Result<bool> {
    loop {
        match ask_entry(label, Some(if default { "yes" } else { "no" }))?.to_ascii_lowercase().as_str() {
            "yes" | "y" => return Ok(true),
            "no" | "n" => return Ok(false),
            _ => println!("Choose yes or no."),
        }
    }
}

fn ask_entry(label: &str, default: Option<&str>) -> anyhow::Result<String> {
    match default { Some(value) => print!("{label} [{value}]: "), None => print!("{label}: ") }
    io::stdout().flush()?;
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer)? == 0 { bail!("setup ended before confirmation"); }
    let answer = answer.trim();
    Ok(if answer.is_empty() { default.unwrap_or("").to_string() } else { answer.to_string() })
}

/// Walks past transient shells and execution wrappers to a recognized host process.
/// Unknown hosts fail closed; explicit --owner-pid supports other hosts. Its identity is
/// then checked by the daemon's own probe.
fn host_owner(start: i32, parent_of: impl Fn(i32) -> Option<(i32, String)>) -> Option<i32> {
    let mut pid = start;
    for _ in 0..16 {
        if pid <= 1 {
            return None;
        }
        let (parent, command) = parent_of(pid)?;
        let name = command.rsplit('/').next().unwrap_or(&command).trim_start_matches('-');
        if matches!(name, "codex" | "Codex" | "claude" | "Claude")
            || command.contains("/claude/versions/") {
            return Some(pid);
        }
        pid = parent;
    }
    None
}

/// `ps -o ppid= -o comm= -p <pid>` → (parent pid, command).
async fn bound_host_owner(start: i32) -> Option<i32> {
    let mut entries = std::collections::HashMap::new();
    let mut pid = start;
    for _ in 0..16 {
        if pid <= 1 { break; }
        let fields = agent_control_plane::workspace::session::process_fields(pid, true).await?;
        let (parent, command) = fields.split_once(char::is_whitespace)?;
        let parent = parent.trim().parse::<i32>().ok()?;
        entries.insert(pid, (parent, command.trim().to_string()));
        if let Some(host) = host_owner(start, |id| entries.get(&id).cloned()) { return Some(host); }
        pid = parent;
    }
    None
}

#[cfg(test)]
mod host_owner_tests {
    use super::host_owner;

    #[test]
    fn host_owner_skips_shells_and_stops_at_the_host() {
        let table = |pid: i32| match pid {
            40 => Some((30, "/bin/zsh".to_string())),
            30 => Some((20, "-bash".to_string())),
            20 => Some((1, "/Users/me/.local/share/claude/versions/2.1.0".to_string())),
            _ => None,
        };
        assert_eq!(host_owner(40, table), Some(20));
        assert_eq!(host_owner(20, table), Some(20));
        let only_shells = |pid: i32| Some((pid - 1, "sh".to_string()));
        assert_eq!(host_owner(5, only_shells), None, "never binds to launchd/init");
        assert_eq!(host_owner(99, table), None);
    }
}

async fn manage_session(repo: Option<&Path>, command: SessionCmd) -> anyhow::Result<i32> {
    let (method, params) = match command {
        SessionCmd::Status => ("daemon.status", json!({})),
        SessionCmd::Acquire { label, bind_host, owner_pid } => {
            let owner = if bind_host {
                let start = i32::try_from(std::os::unix::process::parent_id())?;
                Some(bound_host_owner(start).await.context("no Claude/Codex host process found; pass --owner-pid with the actual session process id")?)
            } else {
                owner_pid
            };
            let mut params = json!({"label": label});
            if let Some(pid) = owner {
                params["ownerPid"] = json!(pid);
            }
            ("session.acquire", params)
        }
        SessionCmd::Renew { instance_id, session_id } => ("session.renew", json!({"instanceId": instance_id, "sessionId": session_id})),
        SessionCmd::Release { instance_id, session_id, stop_if_unneeded } => (
            "session.release",
            if stop_if_unneeded {
                json!({"instanceId": instance_id, "sessionId": session_id, "stopIfUnneeded": true})
            } else {
                json!({"instanceId": instance_id, "sessionId": session_id})
            },
        ),
    };
    call_socket(repo, method, params).await
}

/// Builds the socket `delegate` params. Optional keys are omitted rather than sent null: the
/// door's structs are `deny_unknown_fields` with server-side defaults (`session` → `"fresh"`).
#[allow(clippy::too_many_arguments)]
fn delegate_params(
    role: String,
    description: String,
    task_id: Option<String>,
    title: Option<String>,
    files: Vec<String>,
    acceptance: Vec<String>,
    run_id: Option<String>,
    session: Option<String>,
    base_ref: Option<String>,
) -> Value {
    let task_id = task_id.unwrap_or_else(|| {
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        format!("cli-{epoch}")
    });
    let title = title.unwrap_or_else(|| description.chars().take(80).collect());
    let mut params = json!({
        "role": role,
        "task": {
            "id": task_id,
            "title": title,
            "description": description,
            "files": files,
            "acceptance": acceptance,
        },
    });
    if let Some(run_id) = run_id {
        params["runId"] = json!(run_id);
    }
    if let Some(session) = session {
        params["session"] = json!(session);
    }
    if let Some(base_ref) = base_ref {
        params["baseRef"] = json!(base_ref);
    }
    params
}

// ---------------------------------------------------------------------------
// MCP socket proxy
// ---------------------------------------------------------------------------

/// A backend for the shared nine-tool router that opens one socket connection per call.
#[derive(Clone)]
struct SocketBackend {
    socket: PathBuf,
    /// T84: this proxy child's own `ACP_LEAD_RUN_ID`, read once at `mcp-proxy` startup — set only
    /// when `spawn_lead` put one in this process's environment, i.e. this proxy is a spawned
    /// lead's MCP door. `None` for every other caller of `acp mcp-proxy` (there are none in
    /// practice; the door is daemon-internal), and — critically — for `SocketBackend` never at
    /// all outside `mcp-proxy`, since nothing else constructs one.
    lead_run_id: Option<RunId>,
}

/// Mutating socket methods carry the spawned lead's identity for attribution and mode policy.
/// Kept as a
/// closed list rather than an `is_delegate_like(&str)` predicate so a new attributable method is
/// a one-line addition here, not a heuristic to get right at each call site.
const CALLER_ATTRIBUTED_METHODS: [&str; 7] = ["delegate", "plan.start", "audit.start", "send_message", "cancel", "request_human_gate", "resolve_gate"];

impl SocketBackend {
    async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: impl Serialize,
    ) -> Result<T, CallToolResult> {
        let params = serde_json::to_value(params).map_err(|err| {
            mcp::server::backend_failure(None, &format!("could not encode {method}: {err}"))
        })?;
        self.call_value(method, params).await
    }

    /// Same as [`Self::call`], but — only for [`CALLER_ATTRIBUTED_METHODS`], and only when this
    /// proxy child has its own `ACP_LEAD_RUN_ID` — attaches `callerRunId` to the serialized
    /// params before they go over the wire (T84). The MCP tool arg structs (`DelegateArgs`,
    /// `SubmitPlanArgs`) never carry this field; it exists solely on the socket request this
    /// method builds, which is why the injection happens here and not in either struct.
    async fn call_attributed<T: DeserializeOwned>(
        &self,
        method: &str,
        params: impl Serialize,
    ) -> Result<T, CallToolResult> {
        debug_assert!(CALLER_ATTRIBUTED_METHODS.contains(&method));
        let mut params = serde_json::to_value(params).map_err(|err| {
            mcp::server::backend_failure(None, &format!("could not encode {method}: {err}"))
        })?;
        if let Some(lead_run_id) = self.lead_run_id {
            if let Value::Object(map) = &mut params {
                map.insert("callerRunId".to_string(), json!(lead_run_id));
            }
        }
        self.call_value(method, params).await
    }

    async fn call_value<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, CallToolResult> {
        let mut client = Client::connect(&self.socket)
            .await
            .map_err(|err| mcp::server::backend_failure(None, &err.to_string()))?;
        let value = client
            .call_structured(method, params)
            .await
            .map_err(|err| {
                let (code, reason) = match &err {
                    ClientCallError::Rpc { message, data, .. } => (
                        data.as_ref()
                            .and_then(|data| data["code"].as_str())
                            .map(str::to_string),
                        data.as_ref()
                            .and_then(|data| data["reason"].as_str())
                            .unwrap_or(message)
                            .to_string(),
                    ),
                    ClientCallError::Transport(err) => (None, err.to_string()),
                };
                mcp::server::backend_failure(code.as_deref(), &reason)
            })?;
        serde_json::from_value(value).map_err(|err| {
            mcp::server::backend_failure(
                None,
                &format!("the daemon returned an invalid {method} result: {err}"),
            )
        })
    }
}

impl mcp::server::Backend for SocketBackend {
    async fn audit_existing(&self, args: mcp::server::AuditArgs) -> Result<agent_control_plane::core::PlanStartOut, CallToolResult> {
        self.call_attributed("audit.start", args).await
    }
    async fn check_connection(&self) -> Result<(), String> {
        Client::connect(&self.socket)
            .await
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    async fn delegate(
        &self,
        args: mcp::server::DelegateArgs,
    ) -> Result<agent_control_plane::core::DelegateOut, CallToolResult> {
        self.call_attributed("delegate", args).await
    }

    async fn submit_plan(
        &self,
        args: mcp::server::SubmitPlanArgs,
    ) -> Result<agent_control_plane::core::PlanStartOut, CallToolResult> {
        self.call_attributed("plan.start", args).await
    }

    async fn send_message(
        &self,
        args: mcp::server::SendMessageArgs,
    ) -> Result<mcp::server::SendMessageOut, CallToolResult> {
        self.call_attributed("send_message", args).await
    }

    async fn await_result(
        &self,
        mut args: mcp::server::AwaitResultArgs,
        timeout: Duration,
    ) -> Result<mcp::server::AwaitResultOut, CallToolResult> {
        args.timeout_sec = timeout.as_secs();
        self.call("await_result", args).await
    }

    async fn get_status(
        &self,
        args: mcp::server::GetStatusArgs,
    ) -> Result<mcp::server::GetStatusOut, CallToolResult> {
        self.call("get_status", args).await
    }

    async fn cancel(
        &self,
        args: mcp::server::CancelArgs,
    ) -> Result<mcp::server::CancelOutcome, CallToolResult> {
        self.call_attributed("cancel", args).await
    }

    async fn request_human_gate(
        &self,
        args: mcp::server::RequestHumanGateArgs,
    ) -> Result<mcp::server::RequestHumanGateOut, CallToolResult> {
        self.call_attributed("request_human_gate", args).await
    }

    async fn resolve_gate(
        &self,
        args: mcp::server::ResolveGateArgs,
    ) -> Result<mcp::server::ResolveGateOut, CallToolResult> {
        self.call_attributed("resolve_gate", args).await
    }
}

async fn mcp_proxy(repo: Option<&Path>) -> anyhow::Result<i32> {
    let places = Places::locate(repo).await?;
    let roles = load_roles(roles_file().as_deref()).context("loading the roles config")?;
    let backend = SocketBackend {
        socket: places.state_dir.join(SOCKET_FILE),
        // T84: present only when `spawn_lead` put it here (`lead_mcp_config`'s `env` block) — a
        // malformed or absent value is silently `None`, not a startup error: this proxy still
        // works as every other door's (unattributed) MCP door either way.
        lead_run_id: std::env::var("ACP_LEAD_RUN_ID")
            .ok()
            .and_then(|value| value.parse().ok()),
    };
    mcp::server::serve_backend(backend, roles).await?;
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// Where things are
// ---------------------------------------------------------------------------

/// The two paths every subcommand starts from.
///
/// The repository is a `Result` rather than an `Option` because `doctor` has to *report* why it
/// could not be resolved, and because `$ACP_STATE_DIR` makes a repository optional for the
/// commands that only read the log: a state dir handed over directly is enough to render it.
struct Places {
    repo: Result<PathBuf, String>,
    state_dir: PathBuf,
}

impl Places {
    async fn locate(repo: Option<&Path>) -> anyhow::Result<Self> {
        let cwd = cwd(repo)?;
        let root = git::repo_root(&cwd)
            .await
            .map_err(|err| format!("{}: {err}", cwd.display()));
        let state_dir = match state_dir_env() {
            Some(dir) => dir,
            None => {
                let root = root.as_ref().map_err(|err| {
                    anyhow!("not a git repository, and $ACP_STATE_DIR is not set — {err}")
                })?;
                default_state_dir(root)?
            }
        };
        Ok(Self {
            repo: root,
            state_dir,
        })
    }
}

/// `--repo`, or this process's working directory.
fn cwd(repo: Option<&Path>) -> anyhow::Result<PathBuf> {
    match repo {
        Some(path) => Ok(path.to_path_buf()),
        None => std::env::current_dir().context("reading the working directory"),
    }
}

fn state_dir_env() -> Option<PathBuf> {
    std::env::var_os("ACP_STATE_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn roles_file() -> Option<PathBuf> {
    std::env::var_os("ACP_ROLES_FILE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// `~/.acp/<sha256(realpath(repoRoot))[:16]>/` (design, § Process model).
///
/// The **real** path is hashed, so two paths that reach the same repository through different
/// symlinks share one state dir rather than silently forking the log in two.
fn default_state_dir(repo_root: &Path) -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("$HOME is not set: pass $ACP_STATE_DIR instead"))?;
    let real = fs::canonicalize(repo_root)
        .with_context(|| format!("resolving the real path of {}", repo_root.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(real.as_os_str().as_bytes());
    let digest = hasher.finalize();
    let mut name = String::with_capacity(STATE_HASH_CHARS);
    for byte in digest.iter().take(STATE_HASH_CHARS.div_ceil(2)) {
        use std::fmt::Write as _;
        let _ = write!(name, "{byte:02x}");
    }
    name.truncate(STATE_HASH_CHARS);
    Ok(PathBuf::from(home).join(".acp").join(name))
}

/// A directory the design's 0700 rule applies to, created if it is missing.
fn create_dir_0700(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting mode 0700 on {}", path.display()))
}

fn parse_run(run_id: Option<&str>) -> anyhow::Result<Option<RunId>> {
    run_id
        .map(|id| {
            id.parse::<RunId>()
                .with_context(|| format!("{id:?} is not a run id"))
        })
        .transpose()
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

/// Why `serve` stopped. Only one of these is a failure.
enum Stop {
    Managed,
    /// `SIGINT` or `SIGTERM` — the C3 exit path.
    Signal(&'static str),
    /// The MCP transport ended, which for a stdio server means the lead closed stdin (C3).
    Mcp,
    /// The actor stopped by itself: the event log could not be written, and the design's answer is
    /// to stop rather than serve state that is not on disk.
    Actor,
}

/// Drain the actor unless its completion was the branch that selected the daemon's stop reason.
async fn drain_actor(stop: &Stop, actor: &mut tokio::task::JoinHandle<()>) {
    // A Tokio join handle panics when polled again after returning `Ready`.
    if matches!(stop, Stop::Actor) {
        return;
    }
    if tokio::time::timeout(SHUTDOWN_LIMIT, actor).await.is_err() {
        tracing::warn!("the core actor did not stop within the shutdown limit");
    }
}

/// The daemon.
///
/// The order of the preflight is deliberate. The `.git/info/exclude` entry is added when missing
/// (Revision 27) and the socket path is checked **before** the lock is taken, so a refusal never
/// leaves a lock file behind for the next start to reason about.
///
/// Workers are not touched on the way out (C3): they run in their own process groups, so a restart
/// finds them alive — and re-adopts them, because [`reattach_running`] runs over the replayed log
/// before the actor starts. A worker that outlived its daemon is tailed from the byte offset the
/// log records, bounded by its original deadline, and finalized normally; the actor separately
/// re-drives the intents the log shows were never carried out (`Core::new` → `reconcile_intents`).
async fn serve(repo: Option<&Path>, no_mcp: bool, managed: bool) -> anyhow::Result<i32> {
    // # Safety
    // `umask(2)` swaps one `mode_t` in the calling process and returns the old one. It touches no
    // memory, cannot fail, and is called here before any task exists — so no other thread can
    // observe the intermediate value. Everything this process creates from here is 0700/0600
    // (design, § Process model).
    unsafe { libc::umask(0o077) };

    let cwd = cwd(repo)?;
    let repo_root = git::repo_root(&cwd)
        .await
        .with_context(|| format!("{} is not inside a git repository", cwd.display()))?;
    let state_dir = match state_dir_env() {
        Some(dir) => dir,
        None => default_state_dir(&repo_root)?,
    };

    ensure_excluded(&repo_root).await?;
    let socket_path = state_dir.join(SOCKET_FILE);
    check_socket_path(&socket_path)?;
    create_dir_0700(&state_dir)?;

    let lock_path = state_dir.join(LOCK_FILE);
    let guard = match take_lock(&lock_path, &socket_path, &repo_root)? {
        Lock::Taken(guard) => guard,
        Lock::Held(Some(holder)) => {
            eprintln!(
                "acp serve is already running for {}: pid {}, started {} (lock {})",
                holder.repo_root.display(),
                holder.pid,
                holder.started_at,
                lock_path.display()
            );
            return Ok(EXIT_LOCK_HELD);
        }
        // The winner had not written its record yet. It holds the lock all the same.
        Lock::Held(None) => {
            eprintln!(
                "acp serve is already running: another process holds {}",
                lock_path.display()
            );
            return Ok(EXIT_LOCK_HELD);
        }
    };
    // From here on stdout is reserved for MCP when that door is enabled. Everything this process
    // says goes to the log file in either mode.
    let _logging = init_logging(&state_dir)?;

    let roles = load_roles(roles_file().as_deref()).context("loading the roles config")?;
    let registry = Registry::open(&state_dir)
        .with_context(|| format!("replaying the event log in {}", state_dir.display()))?;

    let (tx, rx) = channel();
    let (signals_tx, signals) = mpsc::channel(SIGNAL_CAPACITY);
    let mut supervisor = Supervisor::new(DEFAULT_TICK, Arc::new(PsProbe), signals_tx);
    let tick = supervisor.tick_interval();
    // The restart path, before the actor owns the supervisor: every attempt the replayed log still
    // calls `running` belongs to a worker that outlived the last daemon, and re-adopting it is what
    // makes "workers survive; a restart re-attaches" true (C3).
    reattach_running(&mut supervisor, &registry, &roles);
    let mut core = Core::new(
        registry,
        supervisor,
        Arc::clone(&roles),
        repo_root.clone(),
        state_dir.clone(),
        tx,
    );
    let requested_stop = CancellationToken::new();
    core.lifecycle.configure(managed, requested_stop.clone());
    let handle = core.handle();
    let mailbox = core.mailbox();
    let shutdown = CancellationToken::new();

    let forwarder = spawn_signal_forwarder(signals, mailbox.clone());
    let mut actor = tokio::spawn(run_actor(core, rx, shutdown.clone()));
    let ticker = spawn_tick_task(mailbox, tick, shutdown.clone());
    let socket = tokio::spawn({
        let path = socket_path.clone();
        let core = handle.clone();
        // The socket's team layer is offered over the very `Arc` the core was built from, so the
        // two can never disagree about what a role may be given.
        let identity = ServerIdentity::new(repo_root.clone(), state_dir.clone())
            .with_roles(Arc::clone(&roles));
        let token = shutdown.clone();
        async move { serve_socket(&path, core, identity, token).await }
    });
    let mut door = (!no_mcp).then(|| tokio::spawn(mcp::server::serve(handle, Arc::clone(&roles))));

    let mut sigint = signal(SignalKind::interrupt()).context("listening for SIGINT")?;
    let mut sigterm = signal(SignalKind::terminate()).context("listening for SIGTERM")?;
    tracing::info!(
        repo = %repo_root.display(),
        state = %state_dir.display(),
        pid = std::process::id(),
        "acp serve is up"
    );

    let stop = tokio::select! {
        _ = requested_stop.cancelled() => Stop::Managed,
        _ = sigint.recv() => Stop::Signal("SIGINT"),
        _ = sigterm.recv() => Stop::Signal("SIGTERM"),
        ended = async {
            match door.as_mut() {
                Some(door) => door.await,
                None => std::future::pending().await,
            }
        } => {
            match ended {
                Ok(Ok(())) => tracing::info!("the MCP transport ended"),
                Ok(Err(err)) => tracing::info!(%err, "the MCP transport ended"),
                Err(err) => tracing::warn!(%err, "the MCP task did not join"),
            }
            Stop::Mcp
        }
        _ = &mut actor => Stop::Actor,
    };
    match stop {
        Stop::Managed => tracing::info!("session lifecycle requested shutdown"),
        Stop::Signal(name) => tracing::info!(signal = name, "shutting down"),
        Stop::Mcp => tracing::info!("stdin closed; shutting down"),
        Stop::Actor => tracing::error!("the core actor stopped; shutting down"),
    }

    // C3, in order: the socket door tells every client `acp.shutdown` and stops accepting, the
    // actor drains what is parked, and only then are the lock and the socket file unlinked.
    shutdown.cancel();
    match tokio::time::timeout(SHUTDOWN_LIMIT, socket).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(err))) => tracing::warn!(%err, "the socket door stopped with an error"),
        Ok(Err(err)) => tracing::warn!(%err, "the socket task did not join"),
        Err(_) => tracing::warn!("the socket door did not stop within the shutdown limit"),
    }
    // The select branch already polled `actor` to completion for `Stop::Actor`; the other paths
    // still owe it a bounded drain after cancellation.
    drain_actor(&stop, &mut actor).await;
    if tokio::time::timeout(SHUTDOWN_LIMIT, ticker).await.is_err() {
        tracing::warn!("the tick task did not stop within the shutdown limit");
    }
    // Neither of these can be waited for: the forwarder's receiver stays open as long as a deadline
    // ladder task holds a sender (up to `attemptTimeoutSec`, deliberately — the ladder must outlive
    // the actor), and the MCP task, when present, is parked on a `read` of stdin that may never
    // return.
    forwarder.abort();
    if let Some(door) = door {
        door.abort();
    }

    drop(guard);
    tracing::info!("acp serve is down");
    Ok(match stop {
        Stop::Actor => EXIT_FAILED,
        Stop::Signal(_) | Stop::Mcp | Stop::Managed => EXIT_OK,
    })
}

/// `serve --stop`: `SIGTERM` the holder and wait for its lock to go.
///
/// The wait is on the **lock file**, not on the process: the holder unlinks it as the last thing it
/// does (C3), so its disappearance means the socket is gone and the log is flushed — which is what
/// a caller about to start another daemon needs to know.
async fn stop_serve(repo: Option<&Path>) -> anyhow::Result<i32> {
    let places = Places::locate(repo).await?;
    let lock_path = places.state_dir.join(LOCK_FILE);
    if !lock_path.exists() {
        bail!("no acp serve running: there is no {}", lock_path.display());
    }

    // The kernel, not the record, decides whether a daemon is running: a crashed one leaves its
    // file behind, and the pid in it may since have been recycled.
    if !lock_is_held(&lock_path) {
        fs::remove_file(&lock_path)
            .with_context(|| format!("removing the stale {}", lock_path.display()))?;
        println!(
            "removed a stale lock: nothing holds {}",
            lock_path.display()
        );
        return Ok(EXIT_OK);
    }

    let Some(holder) = read_lock(&lock_path) else {
        bail!(
            "a daemon holds {}, but the file does not say which process; \
             stop it by hand (it is the `acp serve` for {})",
            lock_path.display(),
            places.state_dir.display()
        );
    };
    // A signal goes out only on a *proof* of identity — pid plus start time. A lock that is held
    // while its record cannot be matched to a live process is reported, never signalled: the pid in
    // it could by then belong to anything.
    if !holder_is_alive(&holder) {
        bail!(
            "a daemon holds {}, but its record (pid {}, started {}) does not match a running \
             process; refusing to signal pid {} on a record that cannot be verified",
            lock_path.display(),
            holder.pid,
            holder.started_at,
            holder.pid
        );
    }

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(holder.pid),
        nix::sys::signal::Signal::SIGTERM,
    )
    .with_context(|| format!("signalling pid {}", holder.pid))?;

    let deadline = tokio::time::Instant::now() + STOP_LIMIT;
    while lock_path.exists() {
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "acp serve (pid {}) did not stop within {}s; its lock is still {}",
                holder.pid,
                STOP_LIMIT.as_secs(),
                lock_path.display()
            );
        }
        tokio::time::sleep(STOP_POLL).await;
    }
    println!("stopped acp serve (pid {})", holder.pid);
    Ok(EXIT_OK)
}

/// `acp up` — the one-command daemon start (B3/D1, design § 3).
///
/// The same preflight as `serve`, then: a live holder is "already running" and exit 0 — the
/// answer, not an error — while a free (or stale) lock gets a **detached** `serve --no-mcp`
/// child in its own process group. The child's pre-logging stderr goes to
/// `<state>/serve.err` (everything before `init_logging` is otherwise invisible), and readiness
/// is the same oracle the tests use: the lock is held and the socket answers `hello`.
async fn up(repo: Option<&Path>, managed: bool) -> anyhow::Result<i32> {
    let repo_root = git::repo_root(&cwd(repo)?)
        .await
        .context("acp up needs a git repository")?;
    let state_dir = match state_dir_env() {
        Some(dir) => dir,
        None => default_state_dir(&repo_root)?,
    };
    ensure_excluded(&repo_root).await?;
    let socket = state_dir.join(SOCKET_FILE);
    check_socket_path(&socket)?;
    create_dir_0700(&state_dir)?;

    let lock = state_dir.join(LOCK_FILE);
    if lock_is_held(&lock) {
        // A held lock IS a running daemon — the kernel's flock, not the record, is the authority
        // (T75-T79 review): an unverifiable `lstart` must not turn idempotence into a failure.
        return match read_lock(&lock) {
            Some(holder) => {
                if holder.repo_root != repo_root {
                    bail!("the state directory belongs to {}, not {}", holder.repo_root.display(), repo_root.display());
                }
                tokio::time::timeout(UP_READINESS_LIMIT, Client::connect(&socket))
                    .await.context("the existing daemon did not answer hello in time")??;
                println!("already running (pid {})", holder.pid);
                Ok(EXIT_OK)
            }
            None => bail!(
                "the lock at {} is held by a process that has not written its record yet; \
                 retry in a moment",
                lock.display()
            ),
        };
    }

    let exe = std::env::current_exe().context("resolving the acp binary for the child")?;
    let out_path = state_dir.join("serve.out");
    let err_path = state_dir.join("serve.err");
    let stdout = std::fs::File::create(&out_path)
        .with_context(|| format!("creating {}", out_path.display()))?;
    let stderr = std::fs::File::create(&err_path)
        .with_context(|| format!("creating {}", err_path.display()))?;
    let mut command = std::process::Command::new(exe);
    command
        .arg("--repo")
        .arg(&repo_root)
        .args(["serve", "--no-mcp"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if managed { command.arg("--managed"); }
    // Its own process group: the daemon's lifetime is the lock's, never this command's — the
    // honest answer to D13's "a GUI crash must never be the daemon's crash".
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let child = command.spawn().context("starting the detached daemon")?;
    let pid = child.pid_i32();

    let deadline = std::time::Instant::now() + UP_READINESS_LIMIT;
    loop {
        if lock_is_held(&lock) && Client::connect(&socket).await.is_ok() {
            println!(
                "started acp serve (pid {pid}); logs: {}",
                err_path.display()
            );
            return Ok(EXIT_OK);
        }
        if std::time::Instant::now() >= deadline {
            let tail = std::fs::read_to_string(&err_path).unwrap_or_default();
            let tail: String = tail.chars().rev().take(2000).collect::<String>();
            let tail: String = tail.chars().rev().collect();
            bail!(
                "the daemon did not become ready within {UP_READINESS_LIMIT:?}; \
                 its stderr ({}):\n{tail}",
                err_path.display()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// How long `acp up` waits for the child's lock + `hello` before reporting its stderr.
const UP_READINESS_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

/// The one conversion `up` needs from a spawned child, kept off the readiness loop's hot path.
trait ChildPid {
    fn pid_i32(&self) -> i32;
}

impl ChildPid for std::process::Child {
    fn pid_i32(&self) -> i32 {
        i32::try_from(self.id()).unwrap_or(i32::MAX)
    }
}

/// Where git keeps the exclude file for `repo_root`, and whether it already carries an accepted
/// form of [`EXCLUDE_ENTRY`]. Read-only: `doctor` reports from this and [`ensure_excluded`]
/// decides from it. The file is read lossily: a Latin-1 comment elsewhere in it must not hide
/// an entry that is there, or every start would add another.
async fn exclude_status(repo_root: &Path) -> anyhow::Result<(PathBuf, bool)> {
    let path = git::git_path(repo_root, "info/exclude")
        .await
        .with_context(|| {
            format!(
                "asking git where {} keeps info/exclude",
                repo_root.display()
            )
        })?;
    let excluded = fs::read(&path).is_ok_and(|bytes| {
        String::from_utf8_lossy(&bytes)
            .lines()
            .any(|line| EXCLUDE_FORMS.contains(&line.trim()))
    });
    Ok((path, excluded))
}

/// Makes sure `.acp/` is excluded, appending the entry when it is missing (design Revision 27).
///
/// Only `<repoRoot>/.acp/worktrees/` lives inside the repository, and it must never show up as an
/// untracked change in a human's `git status` — nor in the frozen diff a reviewer reads. The file
/// is the one `git rev-parse --git-path info/exclude` names: in a **linked worktree** `.git` is a
/// file and the exclude git reads lives in the main git dir. That file sits inside `.git/`, is
/// never committed and never diffed, so writing it is not a working-tree change. Everything
/// already in the file is kept, the entry starts on a line of its own (a file without a final
/// newline gets one first), and a file or `info/` directory that does not exist yet is created.
/// Only a failed write refuses the start, naming the file and the by-hand remedy.
async fn ensure_excluded(repo_root: &Path) -> anyhow::Result<()> {
    let (path, excluded) = exclude_status(repo_root).await?;
    if excluded {
        return Ok(());
    }
    let append = || -> io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        // One `O_APPEND` write for the whole line: nothing serializes two doors starting the
        // same repository at once (this runs before the lock), so the worst case must be a
        // harmless duplicate line, never two half-lines interleaved into `.acp/.acp/`.
        let mut line = String::new();
        if fs::read(&path).is_ok_and(|bytes| !bytes.is_empty() && !bytes.ends_with(b"\n")) {
            line.push('\n');
        }
        line.push_str(EXCLUDE_ENTRY);
        line.push('\n');
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?
            .write_all(line.as_bytes())
    };
    append().with_context(|| {
        format!(
            "adding {EXCLUDE_ENTRY} to {path}, which keeps the control plane's worktrees \
             ({repo}/.acp/worktrees/) out of git status; add it by hand: \
             printf '{EXCLUDE_ENTRY}\\n' >> {path}",
            path = path.display(),
            repo = repo_root.display()
        )
    })
}

/// The `sun_path` limit, checked before anything is created.
///
/// [`serve_socket`] raises the same refusal, and would raise it before binding — this exists so the
/// refusal happens before the lock is taken and before the log is opened, with the same remedy.
fn check_socket_path(path: &Path) -> anyhow::Result<()> {
    let bytes = path.as_os_str().as_bytes().len();
    if bytes > MAX_SOCKET_PATH_BYTES {
        bail!(
            "the socket path is {bytes} bytes, over the {MAX_SOCKET_PATH_BYTES}-byte limit \
             (macOS sun_path is 104): set $ACP_STATE_DIR to a shorter directory — {}",
            path.display()
        );
    }
    Ok(())
}

/// Logs to `$ACP_STATE_DIR/acp.log`, never to stdout (`CLAUDE.md`; stdout is the MCP channel).
///
/// The returned guard flushes the non-blocking writer when it is dropped, so it has to outlive
/// `serve` itself — dropping it early loses the last lines, which are the interesting ones.
fn init_logging(state_dir: &Path) -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard> {
    let (writer, guard) =
        tracing_appender::non_blocking(tracing_appender::rolling::never(state_dir, LOG_FILE));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).context("installing the log subscriber")?;
    Ok(guard)
}

// ---------------------------------------------------------------------------
// The lock
// ---------------------------------------------------------------------------

/// `$ACP_STATE_DIR/serve.lock` (design, § Process model).
///
/// The record is what `doctor` and `serve --stop` *report*; it is not what makes the lock a lock.
/// That is the `flock(2)` the daemon holds on this file for its whole life.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct LockRecord {
    pid: i32,
    started_at: String,
    /// `ps -o lstart=` for `pid` when the lock was taken. Identity, not decoration: a pid alone is
    /// recycled, so nothing signals this process without matching it first.
    lstart: String,
    repo_root: PathBuf,
    version: String,
}

/// What taking the lock produced. `Held` carries the holder's record when it could be read — a
/// racer can arrive between the winner's `flock` and its write, and losing that race must still
/// exit 3 rather than invent a holder.
enum Lock {
    Taken(ServeFiles),
    Held(Option<LockRecord>),
}

/// What `serve` owns for as long as it runs: the **open, flocked** lock file, and the two paths
/// unlinked on the way out.
///
/// Dropping this releases the kernel lock (by closing the file) and unlinks both paths, so the C3
/// exit path holds for an error return and a panic as much as for a signal.
struct ServeFiles {
    /// Held open **only** for its `flock`. Closing it is what releases the lock, so it must not be
    /// dropped before the daemon is done.
    file: fs::File,
    lock: PathBuf,
    socket: PathBuf,
}

impl Drop for ServeFiles {
    fn drop(&mut self) {
        // Order matters: unlink while the lock is still held, so a racer that opened this path
        // before the unlink cannot acquire the lock and *then* find its file still in place —
        // it either loses the flock (we still hold it) or wins one on an inode that is no longer
        // the path, which `take_lock`'s identity check rejects.
        let _ = fs::remove_file(&self.lock);
        let _ = fs::remove_file(&self.socket);
        let _ = &self.file;
    }
}

/// Takes the daemon's lock — the `flock`, not the file.
///
/// **Why not `create_new`.** File *existence* cannot be a mutex here, because the exit path unlinks
/// the file: two starts can both read a stale record, both judge the holder dead, and both unlink
/// and re-create — the second deleting the first's live lock, which puts two daemons on one event
/// log. `flock(LOCK_EX|LOCK_NB)` is decided by the kernel, so exactly one of any number of racers
/// wins, and the loser learns it without touching anything.
///
/// **The unlink race `flock` alone still has**, and how this closes it: a departing daemon may
/// unlink the path after a racer opened it, leaving that racer holding a lock on an inode no longer
/// reachable by name, while a third start creates a fresh file and locks *that*. So after winning,
/// the path is `stat`ed and compared with the `fstat` of the fd actually locked; a mismatch means
/// the file was replaced underneath and the whole attempt is retried. This is the standard
/// flock-with-unlink protocol, and [`ATTEMPTS`] bounds it.
///
/// The record is then written (truncated first — the file may carry a dead daemon's record), and
/// exists purely so `doctor` and `--stop` can name the holder.
fn take_lock(lock: &Path, socket: &Path, repo_root: &Path) -> anyhow::Result<Lock> {
    /// How many times the identity check may send us round again. Each round needs another process
    /// to have replaced the file in the window, so more than a couple is not a race any more.
    const ATTEMPTS: usize = 8;

    for _ in 0..ATTEMPTS {
        let previous = read_lock(lock);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(lock)
            .with_context(|| format!("opening {}", lock.display()))?;

        if !flock_exclusive(&file)? {
            return Ok(Lock::Held(settled_record(lock)));
        }
        // We hold the kernel lock. Is the file we hold it on still the one at this path?
        if !same_file(&file, lock) {
            continue; // A departing daemon unlinked it; take the new one.
        }

        let pid = i32::try_from(std::process::id()).unwrap_or(-1);
        let record = LockRecord {
            pid,
            started_at: now_rfc3339(),
            lstart: PsProbe.start_time(pid).unwrap_or_default(),
            repo_root: repo_root.to_path_buf(),
            version: VERSION.to_string(),
        };
        if let Some(previous) = previous.filter(|p| p.pid != pid) {
            eprintln!(
                "acp: retaking {}: it was left by pid {}, which no longer holds it",
                lock.display(),
                previous.pid
            );
        }
        let files = ServeFiles {
            file,
            lock: lock.to_path_buf(),
            socket: socket.to_path_buf(),
        };
        write_record(&files.file, &record)
            .with_context(|| format!("writing {}", lock.display()))?;
        return Ok(Lock::Taken(files));
    }
    bail!(
        "{} was replaced {ATTEMPTS} times while starting; start one daemon at a time",
        lock.display()
    )
}

/// `flock(LOCK_EX|LOCK_NB)`: `true` when we now hold it, `false` when someone else does.
fn flock_exclusive(file: &fs::File) -> anyhow::Result<bool> {
    // # Safety
    // `flock(2)` takes a borrowed fd — `file` outlives the call — and an int. It touches no memory
    // and the lock it takes is released by the kernel when the last descriptor for the open file
    // description is closed, which is what makes `ServeFiles` owning the handle the whole story.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EWOULDBLOCK) => Ok(false),
        _ => Err(err).context("locking the serve lock"),
    }
}

/// Whether `file` is still the file at `path` — the `flock`-with-unlink identity check.
fn same_file(file: &fs::File, path: &Path) -> bool {
    let (Ok(held), Ok(named)) = (file.metadata(), fs::metadata(path)) else {
        return false;
    };
    held.dev() == named.dev() && held.ino() == named.ino()
}

fn write_record(mut file: &fs::File, record: &LockRecord) -> io::Result<()> {
    let line = serde_json::to_string(record).unwrap_or_default();
    file.set_len(0)?;
    file.seek(io::SeekFrom::Start(0))?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()
}

/// The holder's record, giving the winner a moment to finish writing it.
///
/// A loser can arrive between the winner's `flock` and its `write`, so an empty file here means
/// "too early", not "no holder"; the wait is bounded and its absence only costs a vaguer message.
fn settled_record(lock: &Path) -> Option<LockRecord> {
    const TRIES: usize = 20;
    for _ in 0..TRIES {
        if let Some(record) = read_lock(lock) {
            return Some(record);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

fn read_lock(path: &Path) -> Option<LockRecord> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(text.trim()).ok()
}

/// Whether a **daemon still holds** this lock, asked of the kernel rather than of a pid.
///
/// This is the question `doctor` and `--stop` actually have, and `flock` is the only thing that
/// answers it truthfully: the file's existence means nothing (a crash leaves it behind), and the
/// recorded pid is only as good as the `ps` that produced it. Taking the lock to answer is safe —
/// it is released the moment `file` is dropped, and a daemon that *does* hold it is never disturbed
/// because the probe is non-blocking.
fn lock_is_held(path: &Path) -> bool {
    let Ok(file) = OpenOptions::new().read(true).write(true).open(path) else {
        return false; // No file (or no permission): nothing is holding it.
    };
    !matches!(flock_exclusive(&file), Ok(true))
}

/// Whether the recorded holder is *provably* the process that is running now.
///
/// Deliberately **not** fail-open: an empty `lstart` — the `ps` at write time failed — is not a
/// proof, so this answers `false` and no signal is ever sent on the strength of a bare pid, which
/// could by then belong to anything. Callers that need "is a daemon running" ask [`lock_is_held`];
/// this one only decides whether `record.pid` may be signalled.
fn holder_is_alive(holder: &LockRecord) -> bool {
    !holder.lstart.is_empty() && PsProbe.is_alive(holder.pid, &holder.lstart)
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

/// What `acp status` renders, and what `--json` prints verbatim.
///
/// It is not `core::StatusOut`: that projection is built by the actor, and building one here would
/// mean constructing a `Core` — which reconciles the log's open intents and spawns helper tasks.
/// `status` must be able to look at a log without touching it, so it reads the replayed projection
/// directly.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot<'a> {
    state_dir: &'a Path,
    runs: Vec<&'a Run>,
    agents: Vec<&'a AgentHandle>,
    attempts: Vec<&'a Attempt>,
    gates: Vec<&'a Gate>,
}

impl<'a> Snapshot<'a> {
    fn of(registry: &'a Registry, run: Option<RunId>) -> Self {
        let keep = |id: RunId| run.is_none_or(|wanted| wanted == id);
        let state = registry.state();

        let runs: Vec<&Run> = registry.runs().filter(|r| keep(r.run_id)).collect();
        let mut agents: Vec<&AgentHandle> =
            state.agents.values().filter(|a| keep(a.run_id)).collect();
        agents.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.agent_id.as_uuid().cmp(b.agent_id.as_uuid()))
        });
        let mut attempts: Vec<&Attempt> =
            state.attempts.values().filter(|a| keep(a.run_id)).collect();
        attempts.sort_by(|a, b| {
            a.started_at
                .cmp(&b.started_at)
                .then_with(|| a.attempt_id.as_uuid().cmp(b.attempt_id.as_uuid()))
        });
        let mut gates: Vec<&Gate> = state.gates.values().filter(|g| keep(g.run_id)).collect();
        gates.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.gate_id.as_uuid().cmp(b.gate_id.as_uuid()))
        });

        Self {
            state_dir: registry.state_dir(),
            runs,
            agents,
            attempts,
            gates,
        }
    }

    /// One block per run: the run, its agents, its gates, and the command that approves a pending
    /// one — which is the only line here a human has to act on.
    fn render(&self, out: &mut impl io::Write) -> io::Result<()> {
        writeln!(out, "state {}", self.state_dir.display())?;
        if self.runs.is_empty() {
            return writeln!(out, "no runs recorded");
        }
        for run in &self.runs {
            writeln!(
                out,
                "run {id} status={status} loop={loop_state} spend=${spend:.4} task={task} {title:?}",
                id = run.run_id,
                status = word(&run.status),
                loop_state = word(&run.loop_state),
                spend = run.spend_usd,
                task = run.task.id,
                title = run.task.title,
            )?;
            if let Some(reason) = &run.blocked_reason {
                writeln!(out, "  blocked: {reason}")?;
            }
            for agent in self.agents.iter().filter(|a| a.run_id == run.run_id) {
                writeln!(
                    out,
                    "  agent {id} {role}/{provider}:{model} {status} attempts={n}",
                    id = agent.agent_id,
                    role = word(&agent.role),
                    provider = word(&agent.provider),
                    model = agent.model,
                    status = word(&agent.status),
                    n = agent.attempt_ids.len(),
                )?;
            }
            for gate in self.gates.iter().filter(|g| g.run_id == run.run_id) {
                writeln!(
                    out,
                    "  gate {id} {kind} {status}",
                    id = gate.gate_id,
                    kind = word(&gate.kind),
                    status = word(&gate.status),
                )?;
                if gate.status == GateStatus::Pending {
                    writeln!(out, "    {}", human_action(&gate.gate_id))?;
                }
            }
        }
        Ok(())
    }
}

/// The wire spelling of a closed enum, so this module never re-spells one and drifts from the log.
fn word<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(word)) => word,
        Ok(other) => other.to_string(),
        Err(_) => "?".to_string(),
    }
}

/// `acp status` — read-only, no socket, no lock (design, § Process model).
fn print_status(state_dir: &Path, run: Option<RunId>, as_json: bool) -> anyhow::Result<i32> {
    let registry = Registry::open(state_dir)
        .with_context(|| format!("reading the event log in {}", state_dir.display()))?;
    let snapshot = Snapshot::of(&registry, run);
    let mut out = io::stdout().lock();
    if as_json {
        let line = serde_json::to_string(&snapshot).context("encoding the status snapshot")?;
        writeln!(out, "{line}")?;
    } else {
        snapshot.render(&mut out)?;
    }
    Ok(EXIT_OK)
}

/// `acp status --follow` — a socket client, one line per event.
///
/// No `sinceSeq` is sent, so there is no backfill: this streams what happens from now on
/// (design, § "Subscription semantics", (3)). `runId` is passed along and *also* filtered here,
/// because the contract is explicit that it scopes the backfill only — the live stream carries
/// every run, by design, so that a client sees new runs appear.
async fn follow_status(state_dir: &Path, run: Option<RunId>, as_json: bool) -> anyhow::Result<i32> {
    let mut client = Client::connect(&state_dir.join(SOCKET_FILE)).await?;
    client
        .call("subscribe", json!({ "runId": run }))
        .await
        .context("subscribing")?;

    let mut out = io::stdout().lock();
    while let Some(frame) = client.frame().await? {
        match frame.get("method").and_then(Value::as_str) {
            Some("acp.event") => {
                let event = &frame["params"]["event"];
                let of_run = event["runId"]
                    .as_str()
                    .and_then(|id| id.parse::<RunId>().ok());
                if run.is_some() && run != of_run {
                    continue;
                }
                if as_json {
                    writeln!(out, "{event}")?;
                } else {
                    writeln!(
                        out,
                        "#{seq} {ts} {kind} run={run}",
                        seq = event["seq"],
                        ts = event["ts"].as_str().unwrap_or("?"),
                        kind = event["kind"].as_str().unwrap_or("?"),
                        run = event["runId"].as_str().unwrap_or("?"),
                    )?;
                }
            }
            // Both of these are the client's problem to know about and neither belongs in the
            // stream on stdout, which is one line per event and nothing else.
            Some("acp.lagged") => eprintln!(
                "acp: fell behind the event stream from seq {}; re-run to resynchronise",
                frame["params"]["fromSeq"]
            ),
            Some("acp.shutdown") => {
                eprintln!(
                    "acp: the daemon is shutting down ({})",
                    frame["params"]["reason"]
                        .as_str()
                        .unwrap_or("no reason given")
                );
                return Ok(EXIT_OK);
            }
            _ => {}
        }
    }
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// gate
// ---------------------------------------------------------------------------

/// `acp gate approve|deny` — the human's door, and for `approve` the only one there is (S2).
async fn resolve_gate(repo: Option<&Path>, cmd: GateCmd) -> anyhow::Result<i32> {
    let places = Places::locate(repo).await?;
    let (method, params) = match &cmd {
        GateCmd::Approve { gate_id } => (
            "gate.approve",
            json!({ "gateId": parse_gate(gate_id)?.to_string() }),
        ),
        GateCmd::Deny { gate_id, feedback } => (
            "gate.deny",
            json!({ "gateId": parse_gate(gate_id)?.to_string(), "feedback": feedback }),
        ),
    };

    let mut client = Client::connect(&places.state_dir.join(SOCKET_FILE)).await?;
    let result = client.call(method, params).await?;
    let status = result["status"].as_str().unwrap_or("?");
    match result["sha"].as_str() {
        Some(sha) => println!("{status} {sha}"),
        None => println!("{status}"),
    }
    Ok(EXIT_OK)
}

fn parse_gate(gate_id: &str) -> anyhow::Result<GateId> {
    gate_id
        .parse::<GateId>()
        .with_context(|| format!("{gate_id:?} is not a gate id"))
}

// ---------------------------------------------------------------------------
// team
// ---------------------------------------------------------------------------

/// `acp team get|set|roles` — thin clients of the daemon-owned team layer.
///
/// In particular, `set` only reads and decodes the selected document locally. Validation and the
/// atomic write both happen behind `team.set`, so this process cannot disagree with the running
/// daemon's role catalog or overwrite a newer/corrupt file behind its back.
async fn manage_team(repo: Option<&Path>, cmd: TeamCmd) -> anyhow::Result<i32> {
    let places = Places::locate(repo).await?;
    let (method, params) = match &cmd {
        TeamCmd::Get => ("team.get", json!({})),
        TeamCmd::Set { file } => {
            let bytes = fs::read(file)
                .with_context(|| format!("reading the team document {}", file.display()))?;
            let team: Value = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing the team document {}", file.display()))?;
            ("team.set", json!({ "team": team }))
        }
        TeamCmd::Roles => ("roles.list", json!({})),
    };

    let mut client = Client::connect(&places.state_dir.join(SOCKET_FILE)).await?;
    let result = client.call(method, params).await?;
    match cmd {
        TeamCmd::Get => match result.get("team") {
            Some(Value::Null) => println!("no team"),
            Some(team) => print_json(team)?,
            None => bail!("team.get returned no `team` field"),
        },
        TeamCmd::Set { .. } | TeamCmd::Roles => print_json(&result)?,
    }
    Ok(EXIT_OK)
}

fn print_json(value: &Value) -> anyhow::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value).context("encoding the daemon response")?;
    writeln!(out)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// gc
// ---------------------------------------------------------------------------

/// A worktree `gc --closed` may remove.
struct Prunable {
    repo_root: PathBuf,
    path: PathBuf,
    reason: String,
}

/// `acp gc [--closed]`.
///
/// The candidate set is deliberately narrow: a worktree is prunable only when its lineage is
/// **closed** *and* the log carries the `worktree.retired{resumable:false}` that says nothing will
/// ever write in it again *and* no live writer still holds it. A resumable worktree is never
/// touched — Claude's `--resume` is cwd-scoped, so removing one destroys the session with it.
///
/// Without `--closed` this only reports. Removal is a human decision because a retired worktree
/// still holds the work of the strikes that closed it.
async fn gc(repo: Option<&Path>, closed: bool) -> anyhow::Result<i32> {
    let places = Places::locate(repo).await?;
    let registry = Registry::open(&places.state_dir)
        .with_context(|| format!("reading the event log in {}", places.state_dir.display()))?;
    let candidates = prunable(&registry);

    if candidates.is_empty() {
        println!(
            "gc: no retired worktrees of closed lineages in {}",
            places.state_dir.display()
        );
        return Ok(EXIT_OK);
    }
    if !closed {
        for candidate in &candidates {
            println!(
                "would prune {} ({})",
                candidate.path.display(),
                candidate.reason
            );
        }
        println!(
            "gc: {} retired worktree(s) of closed lineages; pass --closed to remove them",
            candidates.len()
        );
        return Ok(EXIT_OK);
    }

    let mut failures = 0;
    for candidate in &candidates {
        match git::remove_worktree(&candidate.repo_root, &candidate.path, true).await {
            Ok(()) => println!("pruned {}", candidate.path.display()),
            Err(err) => {
                failures += 1;
                eprintln!("acp: could not prune {}: {err}", candidate.path.display());
            }
        }
    }
    println!(
        "gc: pruned {} of {} worktree(s)",
        candidates.len() - failures,
        candidates.len()
    );
    Ok(if failures == 0 { EXIT_OK } else { EXIT_FAILED })
}

fn prunable(registry: &Registry) -> Vec<Prunable> {
    let mut out = Vec::new();
    for run in registry.runs() {
        let retired: Vec<PathBuf> = registry
            .events(&run.run_id, None, usize::MAX)
            .iter()
            .filter_map(|event| match &event.payload {
                agent_control_plane::core::types::EventPayload::WorktreeRetired {
                    path, ..
                } => Some(path.clone()),
                _ => None,
            })
            .collect();
        let worktrees = run.repo_root.join(".acp").join("worktrees");
        for lineage in run.lineages.iter().filter(|l| l.closed) {
            if !retired.contains(&lineage.worktree)
                || !lineage.worktree.starts_with(&worktrees)
                || !lineage.worktree.exists()
                || !registry.live_writers(&lineage.worktree).is_empty()
            {
                continue;
            }
            out.push(Prunable {
                repo_root: run.repo_root.clone(),
                path: lineage.worktree.clone(),
                reason: lineage
                    .closed_reason
                    .clone()
                    .unwrap_or_else(|| "the lineage is closed".to_string()),
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Level {
    Ok,
    Warn,
    Fail,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Warn => "warn",
            Level::Fail => "fail",
        }
    }
}

struct Check {
    level: Level,
    name: &'static str,
    detail: String,
}

impl Check {
    /// One check, one line: a multi-line detail (a git error can span several) is flattened, so
    /// the report stays greppable.
    fn new(level: Level, name: &'static str, detail: impl Into<String>) -> Self {
        let detail: String = detail.into();
        Self {
            level,
            name,
            detail: detail.split_whitespace().collect::<Vec<_>>().join(" "),
        }
    }
}

/// `acp doctor` — everything a start depends on, in one pass, in the order a start needs it.
///
/// Exits 1 when any check fails, so it is usable as a preflight in a script; the lines themselves
/// are the report a human reads.
async fn doctor(repo: Option<&Path>) -> anyhow::Result<i32> {
    let places = Places::locate(repo).await?;
    let mut checks = Vec::new();

    match &places.repo {
        Ok(root) => {
            checks.push(Check::new(Level::Ok, "repo", root.display().to_string()));
            // Reported, never written: `doctor` looks, `acp up` / `acp serve` add the entry.
            checks.push(match exclude_status(root).await {
                Ok((_, true)) => Check::new(
                    Level::Ok,
                    "exclude",
                    format!("{EXCLUDE_ENTRY} is excluded in .git/info/exclude"),
                ),
                Ok((path, false)) => Check::new(
                    Level::Warn,
                    "exclude",
                    format!(
                        "{EXCLUDE_ENTRY} is not yet in {} — acp up or acp serve adds it before starting",
                        path.display()
                    ),
                ),
                Err(err) => Check::new(Level::Fail, "exclude", format!("{err}")),
            });
        }
        Err(err) => {
            checks.push(Check::new(Level::Fail, "repo", err.clone()));
            checks.push(Check::new(
                Level::Warn,
                "exclude",
                "not checked: no repository",
            ));
        }
    }

    checks.push(check_state_dir(&places.state_dir));
    let socket_path = places.state_dir.join(SOCKET_FILE);
    checks.push(check_socket_length(&socket_path));
    checks.push(check_socket(&socket_path));
    checks.push(check_lock(&places.state_dir.join(LOCK_FILE)));
    for provider in [ProviderName::Claude, ProviderName::Codex] {
        checks.push(check_provider(provider).await);
    }

    match load_roles(roles_file().as_deref()) {
        Ok(cfg) => {
            checks.push(check_roles(&cfg));
            checks.push(check_sandbox(&cfg));
            checks.push(check_rates(&cfg));
            checks.push(check_team(&places.state_dir, &cfg));
        }
        Err(err) => {
            checks.push(Check::new(Level::Fail, "roles", format!("{err}")));
            for name in ["sandbox", "rates", "team"] {
                checks.push(Check::new(
                    Level::Warn,
                    name,
                    "not checked: no roles config",
                ));
            }
        }
    }

    let mut out = io::stdout().lock();
    for check in &checks {
        writeln!(
            out,
            "{level:<4}  {name:<9}  {detail}",
            level = check.level.as_str(),
            name = check.name,
            detail = check.detail
        )?;
    }
    let failed = checks.iter().filter(|c| c.level == Level::Fail).count();
    let warned = checks.iter().filter(|c| c.level == Level::Warn).count();
    writeln!(
        out,
        "doctor: {} checks, {failed} failed, {warned} warning(s)",
        checks.len()
    )?;
    Ok(if failed == 0 { EXIT_OK } else { EXIT_FAILED })
}

fn check_state_dir(state_dir: &Path) -> Check {
    match fs::metadata(state_dir) {
        Ok(meta) if !meta.is_dir() => Check::new(
            Level::Fail,
            "state dir",
            format!("{} is not a directory", state_dir.display()),
        ),
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            let level = if mode == 0o700 {
                Level::Ok
            } else {
                Level::Warn
            };
            Check::new(
                level,
                "state dir",
                format!("{} (mode {mode:04o})", state_dir.display()),
            )
        }
        Err(err) => Check::new(
            Level::Warn,
            "state dir",
            format!(
                "{}: {err} — the first serve creates it",
                state_dir.display()
            ),
        ),
    }
}

fn check_socket_length(socket: &Path) -> Check {
    let bytes = socket.as_os_str().as_bytes().len();
    match check_socket_path(socket) {
        Ok(()) => Check::new(
            Level::Ok,
            "sock path",
            format!("{bytes} bytes of the {MAX_SOCKET_PATH_BYTES} allowed"),
        ),
        Err(err) => Check::new(Level::Fail, "sock path", format!("{err}")),
    }
}

fn check_socket(socket: &Path) -> Check {
    match fs::metadata(socket) {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            let level = if mode == 0o600 {
                Level::Ok
            } else {
                Level::Warn
            };
            Check::new(
                level,
                "socket",
                format!("{} (mode {mode:04o})", socket.display()),
            )
        }
        Err(_) => Check::new(
            Level::Warn,
            "socket",
            format!("no {} — no acp serve running", socket.display()),
        ),
    }
}

/// The lock, as the kernel sees it and as the record describes it.
///
/// The two can disagree, and each disagreement is worth a different line: a held lock is a running
/// daemon, a file nothing holds is a crash's leftover, and a held lock whose record does not match
/// a live process is the one case `--stop` will refuse to signal.
fn check_lock(lock: &Path) -> Check {
    let held = lock_is_held(lock);
    let record = read_lock(lock);
    let age = fs::metadata(lock)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|at| at.elapsed().ok())
        .map_or_else(
            || "unknown".to_string(),
            |age| format!("{}s", age.as_secs()),
        );

    match (held, record) {
        (false, _) if !lock.exists() => {
            Check::new(Level::Ok, "lock", "not held — no acp serve running")
        }
        (false, _) => Check::new(
            Level::Warn,
            "lock",
            format!(
                "stale: nothing holds {} (age {age}) — the next serve retakes it",
                lock.display()
            ),
        ),
        (true, Some(holder)) if holder_is_alive(&holder) => Check::new(
            Level::Ok,
            "lock",
            format!(
                "held by pid {} since {} (age {age}), acp {}",
                holder.pid, holder.started_at, holder.version
            ),
        ),
        (true, Some(holder)) => Check::new(
            Level::Warn,
            "lock",
            format!(
                "held, but its record (pid {}, started {}, age {age}) does not match a running \
                 process; `acp serve --stop` will refuse to signal it",
                holder.pid, holder.started_at
            ),
        ),
        (true, None) => Check::new(
            Level::Warn,
            "lock",
            format!(
                "held (age {age}), but {} does not say by which process",
                lock.display()
            ),
        ),
    }
}

/// The provider CLI a role of this provider is spawned with. Its name on `PATH` is its wire name,
/// which is where this takes it from rather than spelling it a second time.
async fn check_provider(provider: ProviderName) -> Check {
    let name: &'static str = match provider {
        ProviderName::Claude => "claude",
        ProviderName::Codex => "codex",
    };
    let Some(bin) = find_on_path(name) else {
        return Check::new(
            Level::Fail,
            name,
            "missing: not found on PATH (only absolute PATH entries are searched)",
        );
    };
    match probe_version(&bin).await {
        Some(version) => {
            // C1: the workspace-write verdict table is measured per codex version; an upgrade
            // can silently re-add /tmp or change the .git exclusion. Warn — never fail — and
            // name the accepted residuals so the human re-verifies with open eyes.
            if provider == ProviderName::Codex
                && version.split_whitespace().last() != Some(SANDBOX_VERIFIED_VERSION)
            {
                return Check::new(
                    Level::Warn,
                    name,
                    format!(
                        "{} ({version}) — the workspace-write sandbox verdicts were measured at \
                         codex-cli {SANDBOX_VERIFIED_VERSION}; re-verify before trusting codex \
                         writers (residuals: CODEX_HOME/memories stays writable; project-local \
                         codex config is not covered by --ignore-user-config)",
                        bin.display(),
                    ),
                );
            }
            Check::new(Level::Ok, name, format!("{} ({version})", bin.display()))
        }
        None => Check::new(
            Level::Warn,
            name,
            format!("{} — no answer to --version", bin.display()),
        ),
    }
}

async fn probe_version(bin: &Path) -> Option<String> {
    let output = tokio::time::timeout(
        VERSION_PROBE_LIMIT,
        tokio::process::Command::new(bin)
            .arg("--version")
            .env_clear()
            .envs(base_env())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let first = text.lines().next()?.trim();
    (!first.is_empty()).then(|| first.to_string())
}

/// The roles config as `load_roles` returns it — which means every prompt already matched its
/// pinned `promptSha256` (S8), so this reports the pins rather than re-checking them.
fn check_roles(cfg: &RolesConfig) -> Check {
    let mut pinned: Vec<String> = cfg
        .roles
        .iter()
        .filter_map(|(role, spec)| {
            let sha = spec.prompt_sha256.as_ref()?;
            Some(format!("{}:{}", word(role), &sha[..sha.len().min(12)]))
        })
        .collect();
    pinned.sort();
    Check::new(
        Level::Ok,
        "roles",
        format!(
            "v{} — {} roles, prompts pinned [{}]",
            cfg.version,
            cfg.roles.len(),
            pinned.join(" ")
        ),
    )
}

/// The price card: how old it is, and whether it covers the models this config can actually spawn.
///
/// An unpriced model is not an error — a turn the provider priced itself is used verbatim — but it
/// is the difference between a budget that binds and one that silently does not, so it is said out
/// loud rather than discovered in a run that never hits its cap.
fn check_rates(cfg: &RolesConfig) -> Check {
    let mut unpriced: Vec<String> = cfg
        .providers
        .values()
        .flat_map(|provider| provider.models.iter())
        .filter(|model| !cfg.rates.contains_key(*model))
        .cloned()
        .collect();
    unpriced.sort();
    unpriced.dedup();

    let age = days_since(&cfg.rates_updated);
    let stale = age.is_none_or(|days| days > RATES_STALE_DAYS);
    let when = match age {
        Some(days) => format!("priced {} ({days} days ago)", cfg.rates_updated),
        None => format!("ratesUpdated {:?} is not a date", cfg.rates_updated),
    };
    if unpriced.is_empty() && !stale {
        return Check::new(
            Level::Ok,
            "rates",
            format!("{} model rate(s), {when}", cfg.rates.len()),
        );
    }
    let mut detail = format!("{} model rate(s), {when}", cfg.rates.len());
    if !unpriced.is_empty() {
        detail.push_str(&format!(
            "; no rate card for {} (a turn the provider prices itself still counts): {}",
            unpriced.len(),
            unpriced.join(", ")
        ));
    }
    Check::new(Level::Warn, "rates", detail)
}

/// Every **sandboxed** role (a writer, or the B1 verifier) must be assigned to a provider that
/// can be confined to its worktree.
///
/// The spawn chokepoint refuses the pairing (V4, `SandboxMissing`) and `validate_team` refuses to
/// save one (`provider_cannot_write`), so a config that pairs them is a run that fails at its first
/// `delegate` — worth a line here rather than a surprise then. Same predicate as both of those
/// (`RoleSpec::requires_sandbox`), so the three human-facing surfaces cannot disagree.
fn check_sandbox(cfg: &RolesConfig) -> Check {
    let mut unconfined: Vec<String> = cfg
        .roles
        .values()
        .filter(|spec| spec.requires_sandbox() && !sandboxes_writes(spec.provider))
        .map(|spec| format!("{}/{}", word(&spec.role), word(&spec.provider)))
        .collect();
    unconfined.sort();

    if unconfined.is_empty() {
        let mut sandboxed: Vec<String> = cfg
            .roles
            .values()
            .filter(|spec| spec.requires_sandbox())
            .map(|spec| format!("{}/{}", word(&spec.role), word(&spec.provider)))
            .collect();
        sandboxed.sort();
        return Check::new(
            Level::Ok,
            "sandbox",
            format!("every sandboxed role is confined [{}]", sandboxed.join(" ")),
        );
    }
    Check::new(
        Level::Warn,
        "sandbox",
        format!(
            "{} sandboxed role(s) on a provider with no sandbox; every spawn of them is refused: {}",
            unconfined.len(),
            unconfined.join(", ")
        ),
    )
}

fn check_team(state_dir: &Path, cfg: &RolesConfig) -> Check {
    match team::load_team(state_dir) {
        Ok(None) => Check::new(
            Level::Ok,
            "team",
            format!(
                "no {} — the roles config's own defaults are in force",
                team::team_path(state_dir).display()
            ),
        ),
        Ok(Some(found)) => match validate_team(cfg, &found) {
            Ok(valid) => {
                let mut detail = format!(
                    "{:?}: valid, {} assignment(s)",
                    valid.name(),
                    valid.team().roles.len()
                );
                if !valid.ignored_roles.is_empty() {
                    detail.push_str(&format!(" (ignored: {})", valid.ignored_roles.join(", ")));
                }
                Check::new(Level::Ok, "team", detail)
            }
            Err(issues) => Check::new(
                Level::Fail,
                "team",
                issues
                    .iter()
                    .map(|issue| format!("{}: {} — {}", issue.role, issue.code, issue.detail))
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
        },
        Err(err) => Check::new(Level::Fail, "team", format!("{err}")),
    }
}

/// Whole days between a `YYYY-MM-DD` (or RFC 3339) date and today, UTC.
///
/// Hand-rolled for the same reason `registry::now_rfc3339` is: the dependency set has no date
/// crate. Today comes straight from the epoch (seconds / 86 400 *is* the day number), so only the
/// civil→days direction has to exist.
fn days_since(date: &str) -> Option<i64> {
    let mut parts = date.get(..10)?.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let today =
        i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() / 86_400)
            .ok()?;
    Some(today - days_from_civil(year, month, day))
}

/// Howard Hinnant's `days_from_civil`: the proleptic-Gregorian date → days-since-1970 conversion,
/// the exact inverse of the `civil_from_days` the registry renders timestamps with.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400; // [0, 399]
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1; // [0, 365]
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

// ---------------------------------------------------------------------------
// The socket client
// ---------------------------------------------------------------------------

/// One NDJSON JSON-RPC connection to `$ACP_STATE_DIR/acp.sock`.
///
/// It says `hello` before anything else and refuses to drive a daemon whose `protocolVersion` it
/// does not know — the contract's rule for clients, and the reason a future daemon can change the
/// wire without an old `acp` corrupting anything.
struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next_id: i64,
}

#[derive(Debug)]
enum ClientCallError {
    Rpc {
        method: String,
        message: String,
        data: Option<Value>,
    },
    Transport(anyhow::Error),
}

impl From<anyhow::Error> for ClientCallError {
    fn from(err: anyhow::Error) -> Self {
        Self::Transport(err)
    }
}

impl Client {
    async fn connect(path: &Path) -> anyhow::Result<Self> {
        let stream = UnixStream::connect(path).await.map_err(|err| {
            anyhow!(
                "no acp serve running: cannot connect to {} ({err})",
                path.display()
            )
        })?;
        let (reader, writer) = stream.into_split();
        let mut client = Self {
            reader: BufReader::new(reader),
            writer,
            next_id: 1,
        };
        let hello = client
            .call(
                "hello",
                json!({ "clientName": CLIENT_NAME, "clientVersion": VERSION }),
            )
            .await
            .context("saying hello")?;
        let spoken = hello["protocolVersion"].as_u64();
        if spoken != Some(u64::from(PROTOCOL_VERSION)) {
            bail!(
                "the daemon speaks protocol {}, this acp speaks {PROTOCOL_VERSION}: \
                 refusing to drive it",
                hello["protocolVersion"]
            );
        }
        Ok(client)
    }

    /// One call. A JSON-RPC error becomes this module's error, with the policy code when there is
    /// one — that code is the actionable half of a rejection.
    async fn call(&mut self, method: &str, params: Value) -> anyhow::Result<Value> {
        match self.call_structured(method, params).await {
            Ok(value) => Ok(value),
            Err(ClientCallError::Rpc {
                method,
                message,
                data,
            }) => match data.as_ref().and_then(|data| data["code"].as_str()) {
                Some(code) => Err(anyhow!("{method} rejected ({code}): {message}")),
                None => Err(anyhow!("{method} rejected: {message}")),
            },
            Err(ClientCallError::Transport(err)) => Err(err),
        }
    }

    /// The same call with the socket error object preserved for the MCP proxy's structured-error
    /// mapping. Frames with another id — including `acp.lagged` and `acp.shutdown`
    /// notifications — are deliberately swallowed.
    async fn call_structured(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Value, ClientCallError> {
        let id = self.next_id;
        self.next_id += 1;
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.writer
            .write_all(format!("{line}\n").as_bytes())
            .await
            .with_context(|| format!("sending {method}"))?;

        loop {
            let frame = self
                .frame()
                .await?
                .ok_or_else(|| anyhow!("the daemon closed the connection during {method}"))?;
            if frame.get("id").and_then(Value::as_i64) != Some(id) {
                continue; // A notification, or an answer to something else.
            }
            if let Some(error) = frame.get("error") {
                let message = error["message"].as_str().unwrap_or("rejected");
                return Err(ClientCallError::Rpc {
                    method: method.to_string(),
                    message: message.to_string(),
                    data: error.get("data").cloned(),
                });
            }
            return Ok(frame.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    /// The next frame, or `None` at EOF.
    async fn frame(&mut self) -> anyhow::Result<Option<Value>> {
        let mut line = String::new();
        if self
            .reader
            .read_line(&mut line)
            .await
            .context("reading from the daemon")?
            == 0
        {
            return Ok(None);
        }
        serde_json::from_str(&line)
            .map(Some)
            .with_context(|| format!("the daemon sent a line that is not JSON: {line:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Socket-only mode has no MCP task to end first, so the actor itself may be the selected stop
    /// reason. Its completed join handle must not be polled a second time during cleanup.
    #[tokio::test]
    async fn an_actor_stop_is_not_joined_twice() {
        let mut actor = tokio::spawn(async {});
        (&mut actor).await.expect("the actor task");

        drain_actor(&Stop::Actor, &mut actor).await;
    }

    /// The process environment is read, never written: `$HOME` is whatever cargo set, because a
    /// test that mutated it would be mutating it for every other test in this binary too.
    #[test]
    fn the_state_dir_is_the_hash_of_the_real_repo_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = PathBuf::from(std::env::var_os("HOME").expect("cargo sets HOME"));

        let first = default_state_dir(dir.path()).expect("a state dir");
        let again = default_state_dir(dir.path()).expect("a state dir");
        assert_eq!(first, again, "the same repo hashes to the same state dir");
        let name = first
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .to_string();
        assert_eq!(name.len(), STATE_HASH_CHARS);
        assert!(
            name.chars().all(|c| c.is_ascii_hexdigit()),
            "the state dir name is hex: {name}"
        );
        assert_eq!(first.parent().expect("parent"), home.join(".acp"));

        let other = tempfile::tempdir().expect("tempdir");
        assert_ne!(
            first,
            default_state_dir(other.path()).expect("a state dir"),
            "two repositories never share a state dir"
        );
    }

    #[tokio::test]
    async fn the_exclude_check_adds_the_entry_when_it_is_missing() {
        let repo = tempfile::tempdir().expect("tempdir");
        git(repo.path(), &["init", "-q", "--initial-branch=main"]);
        // Where git says it keeps the file, which is the only place worth writing to.
        let exclude = git_output(repo.path(), &["rev-parse", "--git-path", "info/exclude"]);
        let exclude = repo.path().join(exclude);

        // No exclude file, not even its directory: both are created and the entry is the file.
        let _ = fs::remove_file(&exclude);
        let _ = fs::remove_dir(exclude.parent().expect("info dir"));
        ensure_excluded(repo.path())
            .await
            .expect("adds the entry to a repository that has no exclude file");
        assert_eq!(fs::read_to_string(&exclude).expect("read"), ".acp/\n");

        // A near miss is not the entry: the entry is appended, nothing else is touched, and a
        // file without a final newline still gets the entry on a line of its own.
        fs::write(&exclude, "# comment\n.acp-backup/").expect("write");
        ensure_excluded(repo.path())
            .await
            .expect("appends the entry");
        assert_eq!(
            fs::read_to_string(&exclude).expect("read"),
            "# comment\n.acp-backup/\n.acp/\n"
        );

        // Already there, in any accepted form and with whitespace around it: byte-identical after.
        for form in EXCLUDE_FORMS {
            let text = format!("# comment\n  {form}  \n");
            fs::write(&exclude, &text).expect("write");
            ensure_excluded(repo.path())
                .await
                .expect("already excluded");
            assert_eq!(
                fs::read_to_string(&exclude).expect("read"),
                text,
                "{form} satisfies the check and the file is left alone"
            );
        }

        // A byte that is not UTF-8 (a Latin-1 comment, a Latin-1 path) must not hide an entry
        // that is there — or every start would append another line — and must not stop the
        // entry from being added once.
        let latin1 = b"# caf\xe9\n.acp/\n";
        fs::write(&exclude, latin1).expect("write");
        ensure_excluded(repo.path())
            .await
            .expect("already excluded, whatever the encoding");
        assert_eq!(fs::read(&exclude).expect("read"), latin1);
        fs::write(&exclude, b"# caf\xe9\n").expect("write");
        for _ in 0..2 {
            ensure_excluded(repo.path())
                .await
                .expect("adds the entry once");
            assert_eq!(fs::read(&exclude).expect("read"), b"# caf\xe9\n.acp/\n");
        }

        // `doctor` only looks: it reports the missing entry and writes nothing.
        fs::write(&exclude, "# comment\n").expect("write");
        let (reported, excluded) = exclude_status(repo.path())
            .await
            .expect("status");
        assert_eq!(reported, exclude, "the status names the file git reads");
        assert!(!excluded, "not excluded yet");
        assert_eq!(fs::read_to_string(&exclude).expect("read"), "# comment\n");
    }

    /// The one refusal left: a write that cannot happen names the file and the by-hand remedy.
    #[tokio::test]
    async fn a_failed_exclude_write_refuses_with_the_by_hand_remedy() {
        // Root ignores directory modes, so there would be nothing to refuse.
        // # Safety
        // `geteuid(2)` reads one id from the process and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let repo = tempfile::tempdir().expect("tempdir");
        git(repo.path(), &["init", "-q", "--initial-branch=main"]);
        let exclude = git_output(repo.path(), &["rev-parse", "--git-path", "info/exclude"]);
        let exclude = repo.path().join(exclude);
        let info = exclude.parent().expect("info dir").to_path_buf();
        let _ = fs::remove_file(&exclude);
        fs::create_dir_all(&info).expect("info dir");
        fs::set_permissions(&info, fs::Permissions::from_mode(0o500)).expect("read-only info dir");

        let err = ensure_excluded(repo.path())
            .await
            .expect_err("the file cannot be created");
        fs::set_permissions(&info, fs::Permissions::from_mode(0o700)).expect("restore the mode");

        let text = format!("{err:#}");
        assert!(
            text.contains(&exclude.display().to_string())
                && text.contains("printf '.acp/\\n' >>"),
            "the refusal names the file and the by-hand remedy: {text}"
        );
        assert!(!exclude.exists(), "nothing was written");
    }

    /// In a **linked worktree** `.git` is a file, so the exclude git reads is the main repository's.
    /// The check must find it there — and the remedy it prints must be that same path.
    #[tokio::test]
    async fn the_exclude_check_follows_a_linked_worktree_to_the_file_git_reads() {
        let repo = tempfile::tempdir().expect("tempdir");
        git(repo.path(), &["init", "-q", "--initial-branch=main"]);
        git(repo.path(), &["config", "user.name", "acp test"]);
        git(
            repo.path(),
            &["config", "user.email", "acp@example.invalid"],
        );
        git(
            repo.path(),
            &["commit", "-q", "--allow-empty", "-m", "init"],
        );
        let linked = repo.path().join("linked");
        git(
            repo.path(),
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "side",
                linked.to_str().expect("utf-8"),
            ],
        );
        assert!(
            linked.join(".git").is_file(),
            "a linked worktree's .git is a file"
        );

        // From inside the worktree, the entry lands in the file git reads: the main repository's.
        let main_exclude = repo.path().join(".git").join("info").join("exclude");
        let _ = fs::remove_file(&main_exclude);
        ensure_excluded(&linked)
            .await
            .expect("adds the entry from inside the worktree");
        assert!(
            fs::read_to_string(&main_exclude)
                .expect("the main repository's exclude")
                .lines()
                .any(|line| line.trim() == EXCLUDE_ENTRY),
            "the entry went into the main git dir"
        );
        assert!(
            linked.join(".git").is_file(),
            "the worktree's .git file is untouched — no directory was invented beside it"
        );
        ensure_excluded(&linked)
            .await
            .expect("the worktree is excluded now");
    }

    fn git(cwd: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap_or_else(|err| panic!("git {args:?}: {err}"));
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn git_output(cwd: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap_or_else(|err| panic!("git {args:?}: {err}"));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[test]
    fn an_over_long_socket_path_is_refused_with_the_remedy() {
        let long = PathBuf::from(format!(
            "/tmp/{}/acp.sock",
            "x".repeat(MAX_SOCKET_PATH_BYTES)
        ));
        let err = check_socket_path(&long).expect_err("over the limit");
        assert!(format!("{err}").contains("ACP_STATE_DIR"), "{err}");
        assert!(check_socket_path(Path::new("/tmp/acp/acp.sock")).is_ok());
    }

    #[test]
    fn days_from_civil_matches_the_known_epochs() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1969, 12, 31), -1, "before the epoch");
        assert_eq!(days_from_civil(1900, 3, 1), -25_508, "a non-leap century");
        // The leap day the naive `year * 365` conversions get wrong, and the shipped
        // `ratesUpdated` — the two dates this is actually asked about.
        assert_eq!(days_from_civil(2024, 2, 29), 19_782);
        assert_eq!(days_from_civil(2026, 8, 22), 20_687);
        assert_eq!(days_since("not-a-date"), None);
        assert!(days_since("1970-01-01").expect("a date") > 20_000);
    }

    #[test]
    fn the_lock_is_the_flock_and_the_record_only_describes_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = dir.path().join(LOCK_FILE);
        let socket = dir.path().join(SOCKET_FILE);

        let files = match take_lock(&lock, &socket, dir.path()).expect("take the lock") {
            Lock::Taken(files) => files,
            Lock::Held(_) => panic!("a fresh path cannot be held"),
        };
        let held = read_lock(&lock).expect("a record");
        assert_eq!(held.pid, i32::try_from(std::process::id()).expect("pid"));
        assert_eq!(held.repo_root, dir.path());
        assert!(holder_is_alive(&held), "we are the holder and we are alive");
        assert!(lock_is_held(&lock), "the kernel says it is held");

        // A second take is refused while the first `ServeFiles` lives — even in this very process,
        // because `flock` is per open file description, not per process.
        match take_lock(&lock, &socket, dir.path()).expect("second take") {
            Lock::Held(Some(holder)) => assert_eq!(holder.pid, held.pid),
            Lock::Held(None) => panic!("the record was written before the lock was reported held"),
            Lock::Taken(_) => panic!("a held lock was stolen"),
        }

        drop(files);
        assert!(!lock.exists(), "the guard unlinks the lock");
        assert!(!lock_is_held(&lock), "and releases it");

        // A file left behind by a crash is not a lock: nothing holds it, and it is retaken.
        fs::write(&lock, serde_json::to_string(&held).expect("encode")).expect("write");
        assert!(!lock_is_held(&lock), "a leftover file holds nothing");
        match take_lock(&lock, &socket, dir.path()).expect("retake") {
            Lock::Taken(_) => {}
            Lock::Held(_) => panic!("a leftover file must not block a start"),
        }
    }

    /// A record whose start time cannot be matched is never signalled — the pid may since have been
    /// recycled — and an *empty* `lstart` is not a match either.
    #[test]
    fn an_unverifiable_holder_is_never_treated_as_signallable() {
        let mine = i32::try_from(std::process::id()).expect("pid");
        let record = |lstart: &str| LockRecord {
            pid: mine,
            started_at: now_rfc3339(),
            lstart: lstart.to_string(),
            repo_root: PathBuf::from("/repo"),
            version: VERSION.to_string(),
        };
        assert!(
            holder_is_alive(&record(&PsProbe.start_time(mine).expect("our own lstart"))),
            "our own pid and start time"
        );
        assert!(
            !holder_is_alive(&record("")),
            "an empty start time is not a proof of anything"
        );
        assert!(
            !holder_is_alive(&record("Thu Jan  1 00:00:00 1970")),
            "and neither is one that does not match"
        );
    }

    #[test]
    fn word_is_the_wire_spelling() {
        use agent_control_plane::core::types::RunStatus;
        assert_eq!(word(&RunStatus::AwaitingGate), "awaiting_gate");
        assert_eq!(word(&ProviderName::Claude), "claude");
    }
}
