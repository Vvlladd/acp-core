//! T57-T59: the spawnable lead path, its human socket entry point, and restart behavior through the
//! real socket-only daemon. Every provider is the fake Claude CLI; no test in this file spends a
//! token or runs an ignored live probe.

mod common;

use std::fs::{self, File};
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_control_plane::core::registry::Registry;
use agent_control_plane::core::supervisor::{ProcessProbe, PsProbe, Supervisor};
use agent_control_plane::core::types::{
    AgentId, AgentStatus, AttemptId, AttemptKind, AttemptStatus, EventPayload, LoopBranch, Origin,
    ProviderName, RoleName, RunId, Task,
};
use agent_control_plane::core::{
    channel, spawn_signal_forwarder, CancelOut, Command, Core, CoreError, StatusQuery,
};
use agent_control_plane::roles::loader::role_prompt;
use nix::sys::signal::{kill, killpg, Signal};
use nix::unistd::Pid;
use serde_json::{json, Value};
use tempfile::TempDir;

use common::{
    configure_fakes, embedded_roles, install_fake_clis, quiesce, start_actor, temp_git_repo,
    wait_for_log, wait_for_status, ActorOpts, LoopWorld, LIMIT, TICK,
};
use tokio::sync::{mpsc, oneshot};

const ACP: &str = env!("CARGO_BIN_EXE_acp");
/// Real daemon/provider subprocess startup is bimodal on the macOS test host; match the existing
/// whole-loop CLI bound rather than treating a cold executable scan as a product failure.
const E2E_LIMIT: Duration = Duration::from_secs(300);

fn short_state() -> TempDir {
    let state = tempfile::Builder::new()
        // The inline MCP config is checked by the conservative argv denylist. A random
        // capital C after a trailing hyphen would look like the forbidden -C flag.
        .prefix("acp-l")
        .rand_bytes(5)
        .tempdir_in("/tmp")
        .expect("short lead state dir");
    assert!(
        state
            .path()
            .join("acp.sock")
            .as_os_str()
            .as_encoded_bytes()
            .len()
            <= 100,
        "the test socket path must fit macOS sun_path"
    );
    state
}

fn daemon_repo() -> TempDir {
    let repo = temp_git_repo();
    fs::write(repo.path().join(".git/info/exclude"), ".acp/\n").expect("exclude daemon worktrees");
    repo
}

fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + E2E_LIMIT;
    while !condition() {
        assert!(Instant::now() < deadline, "{what} never happened");
        std::thread::sleep(TICK);
    }
}

struct SocketOnlyDaemon {
    child: Child,
    state: PathBuf,
    reaped: bool,
}

impl SocketOnlyDaemon {
    fn start(state: &Path, repo: &Path) -> Self {
        let stdout = File::options()
            .create(true)
            .append(true)
            .open(state.join("serve.stdout"))
            .expect("open daemon stdout");
        let stderr = File::options()
            .create(true)
            .append(true)
            .open(state.join("serve.stderr"))
            .expect("open daemon stderr");
        let child = ProcessCommand::new(ACP)
            .args(["serve", "--no-mcp"])
            .current_dir(repo)
            .env("ACP_STATE_DIR", state)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn socket-only daemon");
        let mut daemon = Self {
            child,
            state: state.to_path_buf(),
            reaped: false,
        };
        let deadline = Instant::now() + E2E_LIMIT;
        loop {
            if let Some(status) = daemon.child.try_wait().expect("probe daemon") {
                daemon.reaped = true;
                panic!(
                    "socket-only daemon exited {status}: stderr={} log={}",
                    fs::read_to_string(state.join("serve.stderr")).unwrap_or_default(),
                    fs::read_to_string(state.join("acp.log")).unwrap_or_default()
                );
            }
            if SocketWire::try_connect(&daemon.socket()).is_some() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "socket-only daemon readiness never happened: stderr={} log={}",
                fs::read_to_string(state.join("serve.stderr")).unwrap_or_default(),
                fs::read_to_string(state.join("acp.log")).unwrap_or_default()
            );
            std::thread::sleep(TICK);
        }
        daemon
    }

    fn socket(&self) -> PathBuf {
        self.state.join("acp.sock")
    }

    fn stop(&mut self) {
        kill(Pid::from_raw(self.pid()), Signal::SIGTERM).expect("signal socket-only daemon");
        let deadline = Instant::now() + E2E_LIMIT;
        loop {
            if self.child.try_wait().expect("wait on daemon").is_some() {
                self.reaped = true;
                return;
            }
            assert!(
                Instant::now() < deadline,
                "socket-only daemon did not stop: {}",
                fs::read_to_string(self.state.join("serve.stderr")).unwrap_or_default()
            );
            std::thread::sleep(TICK);
        }
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).expect("daemon pid fits i32")
    }
}

impl Drop for SocketOnlyDaemon {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct SocketWire {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: i64,
}

impl SocketWire {
    fn try_connect(path: &Path) -> Option<Self> {
        let stream = UnixStream::connect(path).ok()?;
        stream.set_read_timeout(Some(E2E_LIMIT)).ok()?;
        stream.set_write_timeout(Some(E2E_LIMIT)).ok()?;
        let reader = BufReader::new(stream.try_clone().ok()?);
        let mut wire = Self {
            reader,
            writer: stream,
            next_id: 1,
        };
        let hello = wire
            .call("hello", json!({ "clientName": "lead-e2e" }))
            .ok()?;
        (hello["protocolVersion"] == json!(1)).then_some(wire)
    }

    fn connect(path: &Path) -> Self {
        Self::try_connect(path)
            .unwrap_or_else(|| panic!("connect to socket-only daemon at {}", path.display()))
    }

    fn call(&mut self, method: &str, params: Value) -> Result<Value, Value> {
        let id = self.next_id;
        self.next_id += 1;
        writeln!(
            self.writer,
            "{}",
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
        )
        .expect("write socket request");
        loop {
            let frame = self.read_frame();
            if frame.get("id").and_then(Value::as_i64) != Some(id) {
                continue;
            }
            return match frame.get("error") {
                Some(error) => Err(error.clone()),
                None => Ok(frame.get("result").cloned().unwrap_or(Value::Null)),
            };
        }
    }

    fn next_event(&mut self, run: RunId) -> Value {
        loop {
            let frame = self.read_frame();
            if frame["method"] == json!("acp.event")
                && frame["params"]["event"]["runId"] == json!(run.to_string())
            {
                return frame["params"]["event"].clone();
            }
        }
    }

    fn read_frame(&mut self) -> Value {
        let mut line = String::new();
        let read = self.reader.read_line(&mut line).expect("read socket frame");
        assert!(read > 0, "socket closed before the expected frame");
        serde_json::from_str(&line).expect("socket frame is JSON")
    }
}

struct WorkerSweep {
    state: PathBuf,
}

impl WorkerSweep {
    fn new(state: &Path) -> Self {
        Self {
            state: state.to_path_buf(),
        }
    }

    fn assert_clear(&self) {
        let registry = Registry::open(&self.state).expect("reopen final lead registry");
        let probe = PsProbe;
        for attempt in registry.state().attempts.values() {
            assert_ne!(attempt.status, AttemptStatus::Running, "{attempt:?}");
            if let (Some(pid), Some(start_time)) = (attempt.pid, attempt.start_time.as_deref()) {
                assert!(
                    !probe.is_alive(pid, start_time),
                    "provider pid {pid} survived its terminal record"
                );
            }
        }
    }
}

impl Drop for WorkerSweep {
    fn drop(&mut self) {
        let Ok(registry) = Registry::open(&self.state) else {
            return;
        };
        let probe = PsProbe;
        for attempt in registry
            .state()
            .attempts
            .values()
            .filter(|attempt| attempt.status == AttemptStatus::Running)
        {
            if let (Some(pid), Some(pgid), Some(start_time)) =
                (attempt.pid, attempt.pgid, attempt.start_time.as_deref())
            {
                if probe.is_alive(pid, start_time) {
                    let _ = killpg(Pid::from_raw(pgid), Signal::SIGKILL);
                }
            }
        }
    }
}

fn collect_through_finished(
    subscriber: &mut SocketWire,
    run: RunId,
    events: &mut Vec<Value>,
    wanted: usize,
) {
    while events
        .iter()
        .filter(|event| event["kind"] == json!("attempt.finished"))
        .count()
        < wanted
    {
        events.push(subscriber.next_event(run));
    }
}

fn flag_values<'a>(argv: &'a [String], flag: &str, next_flag: &str) -> &'a [String] {
    let start = argv
        .iter()
        .position(|token| token == flag)
        .unwrap_or_else(|| panic!("missing {flag}: {argv:?}"))
        + 1;
    let end = argv[start..]
        .iter()
        .position(|token| token == next_flag)
        .map_or(argv.len(), |offset| start + offset);
    &argv[start..end]
}

fn lead_task(message: &str) -> Task {
    Task {
        id: "lead".to_string(),
        title: "Lead conversation".to_string(),
        description: message.to_string(),
        files: Vec::new(),
        acceptance: Vec::new(),
    }
}

async fn cancel_command(core: &mut Core, agent: AgentId) -> CancelOut {
    let (reply, answer) = oneshot::channel();
    core.handle_command(Command::Cancel { agent, reply }).await;
    answer.await.expect("cancel reply").expect("cancel answer")
}

async fn next_spawn(core: &mut Core, commands: &mut mpsc::Receiver<Command>) -> AttemptId {
    let command = tokio::time::timeout(LIMIT, commands.recv())
        .await
        .expect("spawn helper completion timeout")
        .expect("spawn helper completion");
    let attempt = match &command {
        Command::SpawnReady { attempt, .. } => *attempt,
        other => panic!("expected SpawnReady, got {other:?}"),
    };
    core.handle_command(command).await;
    attempt
}

async fn drive_cancelled(
    core: &mut Core,
    commands: &mut mpsc::Receiver<Command>,
    attempt: AttemptId,
) {
    let deadline = Instant::now() + LIMIT;
    loop {
        if core
            .registry
            .attempt(&attempt)
            .is_some_and(|attempt| attempt.status == AttemptStatus::Cancelled)
        {
            assert!(!core.supervisor.is_running(&attempt));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "pending cancellation never finished"
        );
        tokio::select! {
            command = commands.recv() => {
                core.handle_command(command.expect("actor mailbox stays open")).await;
            }
            () = tokio::time::sleep(TICK) => {
                core.handle_command(Command::Tick).await;
            }
        }
    }
}

/// A cancellation can race the spawn helper before `attempt.started`. The actor keeps the pending
/// context, durably marks the agent cancelled, adopts any child that wins the race, and immediately
/// terminates it; only after that terminal record may another lead take the repository slot.
#[test]
fn cancelling_a_pending_lead_adopts_and_kills_it_before_releasing_the_slot() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("hang", &[]);
        let (tx, mut commands) = channel();
        let (signals_tx, signals) = mpsc::channel(64);
        let mut core = Core::new(
            Registry::open(world.state_dir()).expect("registry"),
            Supervisor::new(TICK, Arc::new(PsProbe), signals_tx),
            embedded_roles(),
            world.repo_root().to_path_buf(),
            world.state_dir().to_path_buf(),
            tx,
        );
        let forwarder = spawn_signal_forwarder(signals, core.mailbox());

        // A replay may contain an overlap produced by an older daemon. The newest attempt being
        // terminal must not hide an older one that is still running.
        let replay_run = RunId::new_v4();
        let replay_agent = AgentId::new_v4();
        let older = AttemptId::new_v4();
        let newer = AttemptId::new_v4();
        core.registry
            .append(
                &replay_run,
                EventPayload::RunCreated {
                    execution: None,
                    repo_root: world.repo_root().to_path_buf(),
                    state_dir: world.state_dir().to_path_buf(),
                    base_ref: String::new(),
                    base_sha: String::new(),
                    task: lead_task("replayed overlap"),
                    version: 1,
                    lead: None,
                    team_name: None,
                    steps: None,
                },
            )
            .expect("replay run");
        core.registry
            .append(
                &replay_run,
                EventPayload::AgentCreated {
                    agent_id: replay_agent,
                    role: RoleName::Lead,
                    provider: ProviderName::Claude,
                    model: "haiku".to_string(),
                    lineage_id: None,
                    depth: 0,
                    parent_agent_id: None,
                    origin: Origin::Lead,
                    writes: false,
                    cwd: world.repo_root().to_path_buf(),
                    worktree: None,
                },
            )
            .expect("replay lead");
        for attempt in [older, newer] {
            core.registry
                .append(
                    &replay_run,
                    EventPayload::AttemptStarted {
                        attempt_id: attempt,
                        agent_id: replay_agent,
                        attempt_kind: AttemptKind::Fresh,
                        dir: world.state_dir().join(attempt.to_string()),
                        argv: vec!["claude".to_string()],
                        cwd: world.repo_root().to_path_buf(),
                        pid: 42,
                        pgid: 42,
                        start_time: "replayed".to_string(),
                        pre_sha: String::new(),
                        timeout_sec: 60,
                        spawn_budget_usd: 2.0,
                    },
                )
                .expect("replay attempt");
        }
        core.registry
            .append(
                &replay_run,
                EventPayload::AttemptFinished {
                    attempt_id: newer,
                    status: AttemptStatus::Succeeded,
                    exit_code: Some(0),
                    signal: None,
                    post_sha: None,
                    duration_ms: 1,
                    error: None,
                },
            )
            .expect("newer terminal");
        let hidden = core.spawn_lead(lead_task("must stay busy"), "must stay busy".to_string());
        if let Ok((_run, agent)) = hidden.as_ref() {
            assert_eq!(
                cancel_command(&mut core, *agent).await,
                CancelOut::Cancelled
            );
            let leaked_attempt = next_spawn(&mut core, &mut commands).await;
            drive_cancelled(&mut core, &mut commands, leaked_attempt).await;
        }
        assert!(
            matches!(hidden, Err(CoreError::Policy(ref err)) if err.code.as_str() == "lead_busy"),
            "the older running attempt still owns the lead slot: {hidden:?}"
        );
        core.registry
            .append(
                &replay_run,
                EventPayload::AttemptFinished {
                    attempt_id: older,
                    status: AttemptStatus::Cancelled,
                    exit_code: None,
                    signal: Some("SIGTERM".to_string()),
                    post_sha: None,
                    duration_ms: 1,
                    error: None,
                },
            )
            .expect("older terminal");

        let first_message = "Coordinate a turn that is cancelled before adoption.";
        let first = core
            .spawn_lead(lead_task(first_message), first_message.to_string())
            .expect("first pending lead");
        let busy = core
            .spawn_lead(lead_task("race"), "race".to_string())
            .expect_err("the pending lead owns the slot");
        assert!(matches!(busy, CoreError::Policy(ref err) if err.code.as_str() == "lead_busy"));

        let pending_cancel = cancel_command(&mut core, first.1).await;
        let durable_cancel = core.registry.agent(&first.1).expect("lead").status;
        let first_attempt = next_spawn(&mut core, &mut commands).await;
        // A deliberately broken pending-cancel implementation still reaches cleanup: once the
        // process is adopted, issue the ordinary cancellation before surfacing the assertion.
        if pending_cancel != CancelOut::Cancelled {
            assert_eq!(
                cancel_command(&mut core, first.1).await,
                CancelOut::Cancelled
            );
        }
        drive_cancelled(&mut core, &mut commands, first_attempt).await;
        assert_eq!(pending_cancel, CancelOut::Cancelled);
        assert_eq!(
            durable_cancel,
            AgentStatus::Cancelled,
            "the restart guard is durable before SpawnReady"
        );

        let second_message = "Coordinate after the cancelled process is gone.";
        let second = core
            .spawn_lead(lead_task(second_message), second_message.to_string())
            .expect("the terminal cancellation releases the slot");
        assert_ne!(second.1, first.1);
        assert_eq!(
            cancel_command(&mut core, second.1).await,
            CancelOut::Cancelled
        );
        let second_attempt = next_spawn(&mut core, &mut commands).await;
        drive_cancelled(&mut core, &mut commands, second_attempt).await;

        forwarder.abort();
    });
}

#[tokio::test]
async fn a_spawned_lead_runs_at_the_repo_root_without_a_worktree_lineage_or_schema() {
    let world = LoopWorld::new("lead_chat", &[]);
    let roles = embedded_roles();
    let actor = start_actor(&world, roles.clone(), ActorOpts::default());
    let message = "Please inspect the current state and coordinate the next task.";
    let task = Task {
        id: "lead".to_string(),
        title: "Lead conversation".to_string(),
        description: message.to_string(),
        files: Vec::new(),
        acceptance: vec!["Coordinate the request through ACP.".to_string()],
    };

    let started = actor
        .handle
        .start_lead(task.clone(), message.to_string())
        .await
        .expect("the embedded lead starts");
    let events = wait_for_log(
        &world,
        &started.run_id,
        "the free-text lead turn to finish",
        |events| {
            events
                .iter()
                .any(|event| matches!(&event.payload, EventPayload::AttemptFinished { .. }))
        },
    )
    .await;
    let terminal = events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::AttemptFinished { status, .. } => Some(*status),
            _ => None,
        })
        .expect("lead terminal status");
    assert_eq!(
        terminal,
        AttemptStatus::Succeeded,
        "free text is accepted without a structured result schema"
    );

    let run = world
        .reopen()
        .run(&started.run_id)
        .expect("lead run")
        .clone();
    assert_eq!(run.task, task, "run.created preserves the human message");
    assert!(run.base_sha.is_empty(), "no worktree base was resolved");
    assert!(
        run.lineages.is_empty(),
        "a lead creates no projected lineage"
    );
    assert!(
        !world.repo_root().join(".acp/worktrees").exists(),
        "the lead must not mint even an empty worktree directory"
    );
    assert!(!events.iter().any(|event| matches!(
        &event.payload,
        EventPayload::WorktreeCreated { .. }
            | EventPayload::LineageStrike { .. }
            | EventPayload::LineageClosed { .. }
    )));
    let created = events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::AgentCreated {
                agent_id,
                role,
                lineage_id,
                writes,
                cwd,
                worktree,
                ..
            } if *agent_id == started.agent_id => Some((*role, lineage_id, *writes, cwd, worktree)),
            _ => None,
        })
        .expect("lead agent.created");
    assert_eq!(created.0, RoleName::Lead);
    assert!(created.1.is_none(), "agent.created carries no lineageId");
    assert!(!created.2);
    assert_eq!(created.3, world.repo_root());
    assert!(created.4.is_none(), "a lead handle carries no worktree");

    let (argv, cwd) = events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::AttemptStarted {
                agent_id,
                argv,
                cwd,
                ..
            } if *agent_id == started.agent_id => Some((argv, cwd)),
            _ => None,
        })
        .expect("lead attempt.started");
    assert_eq!(cwd, world.repo_root());
    assert_eq!(argv.first().map(String::as_str), Some("-p"));
    assert_eq!(argv.get(1).map(String::as_str), Some(message));
    assert!(!argv.iter().any(|token| token == "--settings"));
    assert!(!argv.iter().any(|token| token == "--json-schema"));
    assert_eq!(
        flag_values(argv, "--disallowedTools", "--strict-mcp-config"),
        [
            "Bash(git commit:*)",
            "Bash(git push:*)",
            "Bash(git reset:*)",
            "Bash(git add:*)"
        ]
    );

    let config_index = argv
        .iter()
        .position(|token| token == "--mcp-config")
        .expect("--mcp-config");
    let config: Value = serde_json::from_str(&argv[config_index + 1]).expect("MCP config JSON");
    let acp = &config["mcpServers"]["acp"];
    assert_eq!(
        Path::new(acp["command"].as_str().expect("absolute acp command")),
        std::env::current_exe().expect("current executable")
    );
    assert_eq!(
        acp["args"],
        serde_json::json!(["mcp-proxy", "--repo", world.repo_root()])
    );
    // The scrubbed worker env drops $ACP_STATE_DIR, so the proxy child must be handed the
    // daemon's state dir explicitly or it resolves the default one and misses the socket.
    assert_eq!(
        acp["env"]["ACP_STATE_DIR"],
        serde_json::json!(world.state_dir())
    );
    // T84: the minted lead run rides alongside it, so `acp mcp-proxy` can later attach
    // `callerRunId` to this lead's own `delegate`/`plan.start` calls.
    assert_eq!(
        acp["env"]["ACP_LEAD_RUN_ID"],
        serde_json::json!(started.run_id)
    );
    assert_eq!(
        config["mcpServers"].as_object().map(serde_json::Map::len),
        Some(1)
    );

    let agents_index = argv
        .iter()
        .position(|token| token == "--agents")
        .expect("--agents");
    let agents: Value = serde_json::from_str(&argv[agents_index + 1]).expect("agents JSON");
    assert_eq!(
        agents["lead"]["prompt"].as_str(),
        Some(role_prompt(&roles, RoleName::Lead).expect("pinned lead prompt"))
    );
    assert_eq!(agents["lead"]["tools"].as_array().map(Vec::len), Some(9));

    let result = events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::AttemptResult {
                result_path,
                structured_valid,
                structured,
                ..
            } => Some((result_path, structured_valid, structured)),
            _ => None,
        })
        .expect("lead free-text result");
    assert!(!result.1, "no structured result was invented");
    assert!(result.2.is_none());
    assert_eq!(
        std::fs::read_to_string(result.0).expect("result.txt"),
        "Ready."
    );

    let status = wait_for_status(
        &actor.handle,
        StatusQuery {
            run_id: Some(started.run_id),
            ..StatusQuery::default()
        },
        "the lead to become idle",
        |status| {
            status.agents.iter().any(|agent| {
                agent.agent_id == started.agent_id
                    && agent.role == RoleName::Lead
                    && agent.process_state == AgentStatus::Idle
            })
        },
    )
    .await;
    let lead = status
        .agents
        .iter()
        .find(|agent| agent.agent_id == started.agent_id)
        .expect("lead summary");
    assert_eq!(lead.role, RoleName::Lead);
    let dispatched = world
        .events(&started.run_id)
        .iter()
        .filter(|event| {
            matches!(
                &event.payload,
                EventPayload::LoopDispatched {
                    branch: LoopBranch::Lead,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        dispatched, 1,
        "the conversational terminal branch is durable once"
    );

    quiesce(&actor.handle).await;
    actor.stop().await;
}

#[test]
fn socket_only_daemon_streams_a_complete_fake_lead_and_follow_up() {
    common::with_shared_env(|| async {
        install_fake_clis();
        let state = short_state();
        let repo = daemon_repo();
        let repo_root = fs::canonicalize(repo.path()).expect("canonical daemon repo");
        let record_path = state.path().join("fake-record.jsonl");
        let record = record_path.display().to_string();
        configure_fakes(
            repo.path(),
            "lead_messages",
            &[("ACP_FAKE_RECORD", record.as_str())],
        );
        let sweep = WorkerSweep::new(state.path());
        let mut daemon = SocketOnlyDaemon::start(state.path(), repo.path());
        let mut subscriber = SocketWire::connect(&daemon.socket());
        subscriber
            .call("subscribe", json!({}))
            .expect("subscribe before the lead exists");
        let mut commands = SocketWire::connect(&daemon.socket());

        let first_message = "Inspect the repository, use the ACP status tool, and coordinate.";
        let started = commands
            .call("lead.start", json!({ "message": first_message }))
            .expect("start fake lead through the socket-only daemon");
        let run: RunId = started["runId"].as_str().unwrap().parse().unwrap();
        let agent: AgentId = started["agentId"].as_str().unwrap().parse().unwrap();
        let mut streamed = Vec::new();
        collect_through_finished(&mut subscriber, run, &mut streamed, 1);

        wait_for("the first lead turn to become idle", || {
            commands
                .call("get_status", json!({ "runId": run.to_string() }))
                .ok()
                .and_then(|status| status["agents"].as_array().cloned())
                .is_some_and(|agents| {
                    agents.iter().any(|entry| {
                        entry["agentId"] == json!(agent.to_string())
                            && entry["processState"] == json!("idle")
                    })
                })
        });

        // Two lines on purpose: the human's own words reach the transcript verbatim, newline
        // included — a follow-up is a prompt, not a status line to be flattened.
        let follow_up = "Now summarize the safest next action.\nKeep it to one paragraph.";
        let resumed = commands
            .call(
                "send_message",
                json!({ "agentId": agent.to_string(), "message": follow_up }),
            )
            .expect("resume the same fake lead through the existing method");
        assert_eq!(resumed["accepted"], json!(true));
        collect_through_finished(&mut subscriber, run, &mut streamed, 2);
        wait_for("the follow-up result to be durable", || {
            Registry::open(state.path())
                .ok()
                .map(|registry| {
                    registry
                        .state()
                        .attempts
                        .values()
                        .filter(|attempt| {
                            attempt.agent_id == agent && attempt.status == AttemptStatus::Succeeded
                        })
                        .count()
                        == 2
                })
                .unwrap_or(false)
        });

        daemon.stop();
        sweep.assert_clear();

        // The transcript is the whole conversation (B3 walkthrough fix): the accepted follow-up
        // is streamed and made durable as its own `agent.message{role:"user"}` between the two
        // lead turns. The first message is already `run.created` and gets no second bubble.
        let streamed_messages: Vec<(&str, &str)> = streamed
            .iter()
            .filter(|event| event["kind"] == json!("agent.message"))
            .filter_map(|event| Some((event["role"].as_str()?, event["text"].as_str()?)))
            .collect();
        assert_eq!(
            streamed_messages,
            [
                ("assistant", "First lead answer."),
                ("assistant", "Second lead answer."),
                ("user", follow_up),
                ("assistant", "First lead answer."),
                ("assistant", "Second lead answer."),
            ],
            "two text blocks from one provider line stay uncoalesced on both turns, with the \
             human's follow-up between them"
        );
        let user_turn = streamed
            .iter()
            .find(|event| event["kind"] == json!("agent.message") && event["role"] == json!("user"))
            .expect("the follow-up is a durable user turn");
        assert_eq!(
            user_turn["attemptId"], resumed["attemptId"],
            "the user turn is bound to the attempt its send opened"
        );
        assert_eq!(
            user_turn["srcLine"],
            json!(0),
            "a human turn has no provider source line"
        );
        assert_eq!(
            streamed
                .iter()
                .filter(|event| {
                    event["kind"] == json!("agent.progress") && event["phase"] == json!("text")
                })
                .count(),
            2,
            "each assistant line keeps the existing coarse activity marker"
        );
        // The fake lead's final line carries structured output that *would* validate as a
        // build-result — which is exactly why the third field has teeth: free text carries none.
        let results: Vec<(&str, bool, bool)> = streamed
            .iter()
            .filter(|event| event["kind"] == json!("attempt.result"))
            .filter_map(|event| {
                Some((
                    event["schema"].as_str()?,
                    event["structuredValid"].as_bool()?,
                    event["structured"].is_null(),
                ))
            })
            .collect();
        assert_eq!(
            results,
            [("free-text", false, true), ("free-text", false, true)],
            "each socket turn records its provider result, and a lead's result is free text — it \
             never claims the builder's schema and never carries a structured artifact"
        );

        let registry = Registry::open(state.path()).expect("reopen lead e2e log");
        let projected = registry.run(&run).expect("lead run");
        assert_eq!(projected.task.description, first_message);
        assert!(projected.task.files.is_empty() && projected.task.acceptance.is_empty());
        assert!(projected.lineages.is_empty());
        assert!(!repo_root.join(".acp/worktrees").exists());
        assert!(
            !repo_root.join("src/adder.ts").exists(),
            "the read-only fake lead never performs a builder side effect"
        );
        let events = registry.events(&run, None, usize::MAX);
        let starts: Vec<(&Vec<String>, &PathBuf)> = events
            .iter()
            .filter_map(|event| match &event.payload {
                EventPayload::AttemptStarted {
                    agent_id,
                    argv,
                    cwd,
                    ..
                } if *agent_id == agent => Some((argv, cwd)),
                _ => None,
            })
            .collect();
        assert_eq!(starts.len(), 2);
        assert_eq!(starts[0].0.get(1).map(String::as_str), Some(first_message));
        assert_eq!(starts[1].0.get(1).map(String::as_str), Some(follow_up));
        assert!(starts[1].0.iter().any(|arg| arg == "--resume"));
        let roles = embedded_roles();
        for (argv, cwd) in &starts {
            assert_eq!(argv.first().map(String::as_str), Some("-p"));
            assert_eq!(*cwd, &repo_root);
            assert!(!argv.iter().any(|arg| arg == "--settings"));
            assert!(!argv.iter().any(|arg| arg == "--json-schema"));
            assert!(argv.iter().any(|arg| arg == "--strict-mcp-config"));
            assert!(argv.windows(2).any(|pair| pair == ["--agent", "lead"]));
            assert_eq!(
                flag_values(argv, "--disallowedTools", "--strict-mcp-config"),
                [
                    "Bash(git commit:*)",
                    "Bash(git push:*)",
                    "Bash(git reset:*)",
                    "Bash(git add:*)"
                ],
                "the full daemon path preserves the lead's git mutation block"
            );
            let index = argv
                .iter()
                .position(|arg| arg == "--mcp-config")
                .expect("lead mcp config");
            let config: Value = serde_json::from_str(&argv[index + 1]).expect("mcp config JSON");
            let acp = &config["mcpServers"]["acp"];
            assert_eq!(Path::new(acp["command"].as_str().unwrap()), Path::new(ACP));
            assert_eq!(acp["args"], json!(["mcp-proxy", "--repo", repo_root]));
            // Through the real daemon too: the proxy child only finds this custom state dir
            // because the plan's env block carries it past the scrubbed worker environment.
            assert_eq!(acp["env"]["ACP_STATE_DIR"], json!(state.path()));
            assert_eq!(
                config["mcpServers"].as_object().map(serde_json::Map::len),
                Some(1)
            );
            let agents_index = argv
                .iter()
                .position(|arg| arg == "--agents")
                .expect("lead agents config");
            let agents: Value =
                serde_json::from_str(&argv[agents_index + 1]).expect("agents config JSON");
            assert_eq!(
                agents["lead"]["prompt"].as_str(),
                Some(role_prompt(&roles, RoleName::Lead).expect("pinned lead prompt"))
            );
            assert_eq!(agents["lead"]["tools"].as_array().map(Vec::len), Some(9));
        }

        let invocations: Vec<Value> = fs::read_to_string(&record_path)
            .expect("fake invocation record")
            .lines()
            .map(|line| serde_json::from_str(line).expect("fake record JSON"))
            .filter(|entry: &Value| entry["argv"][0] == json!("-p"))
            .collect();
        assert_eq!(invocations.len(), 2, "fresh and resume reached fake Claude");
        assert_eq!(invocations[0]["argv"][1], json!(first_message));
        assert_eq!(invocations[1]["argv"][1], json!(follow_up));
        assert_eq!(invocations[0]["cwd"], json!(repo_root));
        assert_eq!(invocations[1]["cwd"], json!(repo_root));
    });
}

#[test]
fn a_running_lead_is_reattached_after_socket_daemon_restart() {
    common::with_shared_env(|| async {
        install_fake_clis();
        let state = short_state();
        let repo = daemon_repo();
        let release_path = state.path().join("replacement-ready");
        let release = release_path.display().to_string();
        configure_fakes(
            repo.path(),
            "lead_messages",
            &[("ACP_FAKE_WAIT_FILE", release.as_str())],
        );
        let sweep = WorkerSweep::new(state.path());
        let mut first = SocketOnlyDaemon::start(state.path(), repo.path());
        let mut client = SocketWire::connect(&first.socket());
        let started = client
            .call(
                "lead.start",
                json!({ "message": "Stay alive while the socket daemon restarts." }),
            )
            .expect("start restart lead");
        let run: RunId = started["runId"].as_str().unwrap().parse().unwrap();
        let agent: AgentId = started["agentId"].as_str().unwrap().parse().unwrap();
        let mut running = None;
        wait_for("the lead session before daemon shutdown", || {
            let Ok(registry) = Registry::open(state.path()) else {
                return false;
            };
            let Some(handle) = registry.agent(&agent) else {
                return false;
            };
            let Some(attempt) = handle
                .attempt_ids
                .iter()
                .find_map(|id| registry.attempt(id))
                .filter(|attempt| attempt.status == AttemptStatus::Running)
            else {
                return false;
            };
            if handle.session_id.is_none() {
                return false;
            }
            running = Some((
                attempt.attempt_id,
                attempt.pid.expect("running pid"),
                attempt.pgid.expect("running pgid"),
            ));
            true
        });
        let (attempt, pid, pgid) = running.expect("captured running lead");
        assert!(
            !release_path.exists(),
            "the fake lead is still behind its barrier"
        );

        first.stop();
        assert!(
            kill(Pid::from_raw(pid), None).is_ok(),
            "the provider survives the daemon that started it"
        );
        assert_eq!(pgid, pid, "the provider remains its process-group leader");
        let between = Registry::open(state.path()).expect("replay between daemons");
        assert_eq!(
            between.attempt(&attempt).unwrap().status,
            AttemptStatus::Running
        );

        let mut second = SocketOnlyDaemon::start(state.path(), repo.path());
        // `serve` calls reattach_running before it binds this socket, so reaching readiness makes
        // it safe to let the orphaned provider emit its remaining assistant/result lines.
        fs::write(&release_path, "replacement daemon is ready\n").expect("release fake lead");
        wait_for("the reattached lead to finish", || {
            Registry::open(state.path())
                .ok()
                .and_then(|registry| registry.attempt(&attempt).cloned())
                .is_some_and(|attempt| attempt.status == AttemptStatus::Succeeded)
        });
        second.stop();
        sweep.assert_clear();

        let registry = Registry::open(state.path()).expect("reopen restarted lead");
        let handle = registry.agent(&agent).expect("same lead survives restart");
        assert_eq!(
            handle.attempt_ids,
            vec![attempt],
            "restart never spawns a replacement"
        );
        let events = registry.events(&run, None, usize::MAX);
        let messages: Vec<&str> = events
            .iter()
            .filter_map(|event| match &event.payload {
                EventPayload::AgentMessage { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(messages, ["First lead answer.", "Second lead answer."]);
        assert!(events.iter().any(|event| matches!(
            &event.payload,
            EventPayload::AttemptResult { attempt_id, .. } if *attempt_id == attempt
        )));
        assert!(events.iter().any(|event| matches!(
            &event.payload,
            EventPayload::AttemptFinished {
                attempt_id,
                status: AttemptStatus::Succeeded,
                ..
            } if *attempt_id == attempt
        )));
    });
}

fn codex_planning_team() -> Value {
    json!({"version":3,"mode":"plan","name":"Codex planning",
        "lead":{"provider":"codex","model":"gpt-5.5","effort":"high"},"roles":{}})
}

#[test]
fn codex_lead_recovers_and_resumes_its_recorded_profile_after_team_change() {
    common::with_shared_env(|| async {
        install_fake_clis();
        let state = short_state();
        let repo = daemon_repo();
        let release = state.path().join("release-lead");
        configure_fakes(repo.path(), "pass", &[("ACP_FAKE_VERSION", "codex-cli 0.153.0"),
            ("ACP_FAKE_WAIT_FILE", release.to_str().unwrap())]);
        fs::write(state.path().join("team.json"), codex_planning_team().to_string()).unwrap();
        let sweep = WorkerSweep::new(state.path());
        let mut first = SocketOnlyDaemon::start(state.path(), repo.path());
        let mut wire = SocketWire::connect(&first.socket());
        let catalog = wire.call("roles.list", json!({})).unwrap();
        assert!(catalog["lead"]["models"].as_array().unwrap().contains(&json!("gpt-5.5")));
        let started = wire.call("lead.start", json!({"message":"Plan without writing."})).unwrap();
        let run: RunId = started["runId"].as_str().unwrap().parse().unwrap();
        let agent: AgentId = started["agentId"].as_str().unwrap().parse().unwrap();
        wait_for("a Codex session before restart", || Registry::open(state.path()).ok()
            .and_then(|r| r.agent(&agent).cloned()).is_some_and(|a| a.session_id.is_some()));
        let original = Registry::open(state.path()).unwrap().agent(&agent).unwrap().clone();
        assert_eq!(original.provider, ProviderName::Codex);
        assert!(!original.writes && original.worktree.is_none() && original.lineage_id.is_none());
        first.stop();
        drop(wire);
        // Saving a different valid team cannot reconfigure the old lead or turn planning into build.
        fs::write(state.path().join("team.json"), json!({"version":3,"mode":"build","name":"Changed",
            "lead":{"provider":"claude","model":"haiku"},
            "roles":{"builder":{"provider":"claude","model":"sonnet"}}}).to_string()).unwrap();
        let mut second = SocketOnlyDaemon::start(state.path(), repo.path());
        fs::write(&release, "ready").unwrap();
        let finished = |count| {
            let registry = Registry::open(state.path()).unwrap();
            registry.agent(&agent).is_some_and(|a| a.attempt_ids.len()==count && a.attempt_ids.iter()
                .all(|id| registry.attempt(id).is_some_and(|at| at.status==AttemptStatus::Succeeded)))
        };
        wait_for("reattached Codex answer", || finished(1));
        let mut wire = SocketWire::connect(&second.socket());
        let followed = wire.call("send_message", json!({"agentId":agent,"message":"Clarify the plan."})).unwrap();
        assert_eq!(followed["accepted"], true);
        wait_for("resumed Codex answer", || finished(2));
        second.stop();
        sweep.assert_clear();
        let registry = Registry::open(state.path()).unwrap();
        let handle = registry.agent(&agent).unwrap();
        assert_eq!(handle.session_id, original.session_id);
        let execution = registry.run(&run).unwrap().execution.as_ref().unwrap();
        assert_eq!(execution.mode, agent_control_plane::core::types::RunMode::Plan);
        assert_eq!(execution.assignments["lead"].effort, Some(agent_control_plane::core::team::Effort::High));
        let events = registry.events(&run, None, usize::MAX);
        let mut messages = Vec::new();
        let mut argv = Vec::new();
        for e in &events { match &e.payload {
            EventPayload::AgentMessage { text, .. } => messages.push(text.as_str()),
            EventPayload::AttemptStarted { argv: args, .. } => argv.push(args),
            EventPayload::WorktreeCreated { .. } | EventPayload::GateCreated { .. } => panic!("planning created work/gate"),
            _ => {}
        }}
        assert_eq!(messages, ["Codex planning answer.", "Clarify the plan.", "Codex follow-up answer."]);
        assert_eq!(argv.len(), 2);
        assert_eq!(&argv[1][..2], ["exec", "resume"]);
        for args in argv {
            assert!(args.iter().any(|s| s=="model_reasoning_effort=\"high\""));
            assert!(args.iter().any(|s| s=="gpt-5.5"));
            assert!(args.iter().any(|s| s.starts_with("mcp_servers=") && s.contains(&run.to_string())));
        }
        assert!(!repo.path().join(".acp/worktrees").exists());

        // Simulate power loss after only RunCreated + AgentCreated. The new state's saved team
        // is different, but replay must issue exactly the recorded lead intent with its effort.
        let prefix = short_state();
        let mut recovered = Registry::open(prefix.path()).unwrap();
        for event in events.iter().take(2) {
            let mut payload = event.payload.clone();
            if let EventPayload::RunCreated { state_dir, .. } = &mut payload { *state_dir=prefix.path().into(); }
            recovered.append(&run, payload).unwrap();
        }
        drop(recovered);
        fs::copy(state.path().join("team.json"), prefix.path().join("team.json")).unwrap();
        let prefix_sweep = WorkerSweep::new(prefix.path());
        let mut third = SocketOnlyDaemon::start(prefix.path(), repo.path());
        wait_for("the unstarted lead intent", || {
            let r = Registry::open(prefix.path()).unwrap();
            r.agent(&agent).is_some_and(|a| a.attempt_ids.len()==1 && a.attempt_ids.iter()
                .all(|id| r.attempt(id).is_some_and(|at| at.status==AttemptStatus::Succeeded)))
        });
        third.stop();
        prefix_sweep.assert_clear();
        let r = Registry::open(prefix.path()).unwrap();
        let a = r.agent(&agent).unwrap();
        assert_eq!(a.provider, ProviderName::Codex);
        let replayed = r.events(&run, None, usize::MAX);
        let args = replayed.iter().find_map(|e| match &e.payload {
            EventPayload::AttemptStarted { argv, .. } => Some(argv), _ => None }).unwrap();
        assert!(args.iter().any(|v| v=="model_reasoning_effort=\"high\""));
        assert!(args.iter().any(|v| v.starts_with("mcp_servers=") && v.contains(&run.to_string())
            && v.contains(prefix.path().to_str().unwrap())));
    });
}

#[test]
fn codex_lead_refuses_an_unmeasured_cli_before_starting_a_model_turn() {
    common::with_shared_env(|| async {
        install_fake_clis();
        let state = short_state();
        let repo = daemon_repo();
        let record = state.path().join("calls.jsonl");
        configure_fakes(repo.path(), "pass", &[("ACP_FAKE_VERSION", "codex-cli 0.999.0"),
            ("ACP_FAKE_RECORD", record.to_str().unwrap())]);
        fs::write(state.path().join("team.json"), codex_planning_team().to_string()).unwrap();
        let sweep = WorkerSweep::new(state.path());
        let mut daemon = SocketOnlyDaemon::start(state.path(), repo.path());
        let mut wire = SocketWire::connect(&daemon.socket());
        let started = wire.call("lead.start", json!({"message":"This version must not start."})).unwrap();
        let agent: AgentId = started["agentId"].as_str().unwrap().parse().unwrap();
        wait_for("version rejection", || Registry::open(state.path()).ok().is_some_and(|r|
            r.agent(&agent).is_some_and(|a| a.attempt_ids.iter().any(|id| r.attempt(id)
                .is_some_and(|at| at.status != AttemptStatus::Running)))));
        daemon.stop();
        sweep.assert_clear();
        let calls: Vec<Value> = fs::read_to_string(record).unwrap().lines().map(|s| serde_json::from_str(s).unwrap()).collect();
        assert!(!calls.is_empty());
        assert!(calls.iter().all(|c| c["argv"] == json!(["--version"])));
        let registry = Registry::open(state.path()).unwrap();
        assert!(registry.agent(&agent).unwrap().session_id.is_none());
        let failures = registry.state().attempts.values().filter_map(|a| a.error.as_ref())
            .map(|e| e.message.as_str()).collect::<Vec<_>>();
        assert!(failures.iter().any(|s| s.contains("requires codex-cli 0.153.0")), "{failures:?}");
    });
}

#[test]
fn spawned_lead_selection_is_versioned_and_worker_delegation_cannot_resume_it() {
    common::with_shared_env(|| async {
        for (version, requested_provider, requested_model, actual_provider, actual_model) in [
            (1, "codex", "gpt-5.5", ProviderName::Claude, "haiku"),
            (2, "codex", "gpt-5.5", ProviderName::Claude, "haiku"),
            (3, "claude", "opus", ProviderName::Claude, "opus"),
            (3, "codex", "gpt-5.5", ProviderName::Codex, "gpt-5.5"),
        ] {
            let world = LoopWorld::new("lead_messages", &[("ACP_FAKE_VERSION", "codex-cli 0.153.0")]);
            let barrier = world.state_dir().join("release");
            configure_fakes(world.repo_root(), "lead_messages", &[("ACP_FAKE_VERSION", "codex-cli 0.153.0"),
                ("ACP_FAKE_WAIT_FILE", barrier.to_str().unwrap())]);
            let mut team = json!({"version":version,"name":"Lead selection",
                "lead":{"provider":requested_provider,"model":requested_model},
                "roles":{"builder":{"provider":"claude","model":"sonnet"},
                         "reviewer":{"provider":"codex","model":"gpt-5.5"}}});
            if version==3 { team["mode"]=json!("build"); }
            fs::write(world.state_dir().join("team.json"), team.to_string()).unwrap();
            let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
            let started = actor.handle.start_lead(lead_task("coordinate"), "coordinate".into()).await.unwrap();
            wait_for_log(&world, &started.run_id, "lead session", |es| es.iter().any(|e|
                matches!(e.payload, EventPayload::AgentSession { .. }))).await;
            let registry = world.reopen();
            let lead = registry.agent(&started.agent_id).unwrap();
            assert_eq!(lead.provider, actual_provider);
            assert_eq!(lead.model, actual_model);
            assert_eq!(registry.run(&started.run_id).unwrap().execution.as_ref().unwrap()
                .assignments["lead"].provider, actual_provider);
            let mut req = common::delegate_builder(common::loop_task("lead-is-not-worker"));
            req.role = RoleName::Reviewer;
            req.session = agent_control_plane::core::policy::SessionSpec::Resume(started.agent_id);
            let rejected = actor.handle.delegate(req.clone()).await.unwrap_err();
            assert!(matches!(rejected, CoreError::Policy(ref e) if e.code.as_str()=="delegation_not_allowed"));
            fs::write(barrier, "done").unwrap();
            wait_for_log(&world, &started.run_id, "lead ended", |es| es.iter().any(|e|
                matches!(e.payload, EventPayload::AttemptFinished { status: AttemptStatus::Succeeded, .. }))).await;
            assert!(actor.handle.delegate(req).await.is_err(), "idle leads are not workers either");
            assert_eq!(world.reopen().agent(&started.agent_id).unwrap().attempt_ids.len(), 1);
            if version==3 && actual_provider==ProviderName::Codex {
                // A delayed lead request still uses its captured Build team after a new Plan
                // team is saved; both worker and plan inheritance revalidate the lead field.
                fs::write(world.state_dir().join("team.json"), codex_planning_team().to_string()).unwrap();
                configure_fakes(world.repo_root(), "pass", &[]);
                let mut child = common::delegate_builder(common::loop_task("inherited-build"));
                child.caller_run_id=Some(started.run_id);
                let child = actor.handle.delegate(child).await.unwrap();
                wait_for_log(&world, &child.run_id, "inherited worker gate", |es| es.iter()
                    .any(|e| matches!(e.payload, EventPayload::GateCreated { .. }))).await;
                let child_execution = world.reopen().run(&child.run_id).unwrap().execution.clone().unwrap();
                assert_eq!(child_execution.assignments["lead"].provider, ProviderName::Codex);
                assert_eq!(child_execution.mode, agent_control_plane::core::types::RunMode::Build);
                let plan = serde_json::from_value(json!({"version":1,"name":"Inherited decision",
                    "items":[{"id":"decide","kind":"human","summary":"Choose next work","after":[]}]})).unwrap();
                let plan = actor.handle.start_plan(plan, Some(started.run_id)).await.unwrap();
                let e = world.reopen().run(&plan.run_id).unwrap().execution.clone().unwrap();
                assert_eq!(e.assignments["lead"], child_execution.assignments["lead"]);
            }
            quiesce(&actor.handle).await;
            actor.stop().await;
        }
    });
}

#[test]
fn audit_lead_prefix_recovery_preserves_human_input_and_rebuilds_its_prompt() {
    common::with_shared_env(|| async {
        install_fake_clis();
        let state = short_state();
        let repo = daemon_repo();
        configure_fakes(repo.path(), "lead_messages", &[]);
        let team = json!({"version":3,"mode":"audit","name":"Human comparison",
            "lead":{"provider":"claude","model":"haiku"},
            "roles":{"reviewer":{"provider":"codex","model":"gpt-5.5"}}});
        fs::write(state.path().join("team.json"), team.to_string()).unwrap();
        let selection = json!({"baseRef":"HEAD","target":{"kind":"revision","revision":"HEAD"}});
        let sweep = WorkerSweep::new(state.path());
        let mut first = SocketOnlyDaemon::start(state.path(), repo.path());
        let mut wire = SocketWire::connect(&first.socket());
        let started = wire.call("lead.start", json!({"message":"Inspect the comparison I selected.",
            "expectedTeam":team,"auditSelection":selection})).unwrap();
        let run: RunId = started["runId"].as_str().unwrap().parse().unwrap();
        let agent: AgentId = started["agentId"].as_str().unwrap().parse().unwrap();
        wait_for("first audit lead", || Registry::open(state.path()).ok().is_some_and(|r|
            r.agent(&agent).is_some_and(|a| a.attempt_ids.iter().any(|id| r.attempt(id)
                .is_some_and(|a| a.status==AttemptStatus::Succeeded)))));
        first.stop();
        sweep.assert_clear();
        let registry = Registry::open(state.path()).unwrap();
        let prefix = short_state();
        let mut recovered = Registry::open(prefix.path()).unwrap();
        for event in registry.events(&run, None, usize::MAX).iter().take(2) {
            let mut payload = event.payload.clone();
            if let EventPayload::RunCreated { state_dir, .. } = &mut payload { *state_dir=prefix.path().into(); }
            recovered.append(&run, payload).unwrap();
        }
        drop(recovered);
        fs::write(prefix.path().join("team.json"), codex_planning_team().to_string()).unwrap();
        let sweep = WorkerSweep::new(prefix.path());
        let mut second = SocketOnlyDaemon::start(prefix.path(), repo.path());
        wait_for("recovered audit lead", || Registry::open(prefix.path()).ok().is_some_and(|r|
            r.agent(&agent).is_some_and(|a| a.attempt_ids.iter().any(|id| r.attempt(id)
                .is_some_and(|a| a.status==AttemptStatus::Succeeded)))));
        let mut wire = SocketWire::connect(&second.socket());
        assert!(wire.call("audit.start", json!({"callerRunId":run,"task":lead_task("Inspect this selection"),
            "selection":{"baseRef":"main","target":{"kind":"workingTree"}}})).is_err());
        second.stop();
        sweep.assert_clear();
        let registry = Registry::open(prefix.path()).unwrap();
        let events = registry.events(&run, None, usize::MAX);
        let argv = events.iter().find_map(|e| match &e.payload {
            EventPayload::AttemptStarted { argv, .. } => Some(argv), _ => None }).unwrap();
        assert!(argv[1].contains(&selection.to_string()), "recorded selection was missing: {}", argv[1]);
        assert!(argv[1].contains("Call audit_existing"));
        assert_eq!(registry.state().runs.len(), 1, "mismatched audit created no child");
        let execution = registry.run(&run).unwrap().execution.as_ref().unwrap();
        assert!(execution.audit_selection.is_none());
        assert_eq!(serde_json::to_value(&execution.authorized_audit_selection).unwrap(), selection);
    });
}
