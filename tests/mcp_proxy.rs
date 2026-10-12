//! T55: the stdio MCP proxy, driven through the real binary and Unix-socket protocol.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_control_plane::core::types::RolesConfig;
use agent_control_plane::core::{StatusQuery, DEFAULT_LAST_EVENTS};
use agent_control_plane::ipc::socket::{serve_socket, ServerIdentity, PROTOCOL_VERSION};
use agent_control_plane::mcp::server::AcpServer;
use agent_control_plane::roles::loader::load_roles;
use rmcp::ServiceExt;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{
    AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, DuplexStream, ReadHalf, WriteHalf,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use common::{
    configure_fakes, embedded_roles, install_fake_clis, quiesce, start_actor, temp_git_repo,
    wait_for_status, ActorOpts, LoopWorld, LIMIT,
};

const ACP: &str = env!("CARGO_BIN_EXE_acp");
const MCP_PROTOCOL: &str = "2025-11-25";

fn short_state() -> TempDir {
    tempfile::Builder::new()
        .prefix("acp-proxy-")
        .rand_bytes(5)
        .tempdir_in("/tmp")
        .expect("short proxy state dir")
}

fn world(scenario: &str) -> LoopWorld {
    install_fake_clis();
    let world = LoopWorld {
        state: short_state(),
        repo: temp_git_repo(),
    };
    configure_fakes(world.repo_root(), scenario, &[]);
    world
}

struct SocketDoor {
    shutdown: CancellationToken,
    task: JoinHandle<()>,
}

impl SocketDoor {
    async fn start(
        world: &LoopWorld,
        core: agent_control_plane::core::CoreHandle,
        roles: Arc<RolesConfig>,
    ) -> Self {
        let path = world.state_dir().join("acp.sock");
        let shutdown = CancellationToken::new();
        let task = tokio::spawn({
            let path = path.clone();
            let identity = ServerIdentity::new(
                world.repo_root().to_path_buf(),
                world.state_dir().to_path_buf(),
            )
            .with_roles(roles);
            let shutdown = shutdown.clone();
            async move {
                serve_socket(&path, core, identity, shutdown)
                    .await
                    .expect("serve test socket");
            }
        });
        let deadline = Instant::now() + LIMIT;
        loop {
            if UnixStream::connect(&path).await.is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "socket was never ready");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Self { shutdown, task }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        tokio::time::timeout(LIMIT, self.task)
            .await
            .expect("socket stop timeout")
            .expect("socket task join");
    }
}

struct ProxyPeer {
    child: Child,
    reader: BufReader<ChildStdout>,
    writer: Option<ChildStdin>,
    next_id: i64,
}

impl ProxyPeer {
    async fn start(state: &Path, repo: &Path, roles: Option<&Path>) -> Self {
        Self::start_as(state, repo, roles, None).await
    }

    /// Same as [`Self::start`], but — when `lead_run_id` is `Some` — the child is given
    /// `ACP_LEAD_RUN_ID`, exactly as `spawn_lead`'s `--mcp-config` would (T84): what proves the
    /// proxy is standing in for a spawned lead's own MCP door.
    async fn start_as(
        state: &Path,
        repo: &Path,
        roles: Option<&Path>,
        lead_run_id: Option<agent_control_plane::core::types::RunId>,
    ) -> Self {
        let mut command = Command::new(ACP);
        command
            .args(["mcp-proxy", "--repo"])
            .arg(repo)
            .env("ACP_STATE_DIR", state)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(roles) = roles {
            command.env("ACP_ROLES_FILE", roles);
        }
        if let Some(lead_run_id) = lead_run_id {
            command.env("ACP_LEAD_RUN_ID", lead_run_id.to_string());
        }
        let mut child = command.spawn().expect("spawn acp mcp-proxy");
        let reader = BufReader::new(child.stdout.take().expect("proxy stdout"));
        let writer = child.stdin.take().expect("proxy stdin");
        Self {
            child,
            reader,
            writer: Some(writer),
            next_id: 0,
        }
    }

    async fn send(&mut self, value: &Value) {
        let writer = self.writer.as_mut().expect("proxy stdin is open");
        writer
            .write_all(format!("{value}\n").as_bytes())
            .await
            .expect("write proxy request");
        writer.flush().await.expect("flush proxy request");
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
            .await;
        let deadline = Instant::now() + LIMIT;
        loop {
            let mut line = String::new();
            let read = tokio::time::timeout(LIMIT, self.reader.read_line(&mut line))
                .await
                .expect("proxy answer timeout")
                .expect("read proxy answer");
            assert_ne!(read, 0, "proxy closed before answering {method}");
            let frame: Value = serde_json::from_str(&line).expect("proxy emitted JSON");
            if frame["id"] == json!(id) {
                return frame;
            }
            assert!(Instant::now() < deadline, "no answer for {method}");
        }
    }

    async fn initialize(&mut self) -> Value {
        self.request(
            "initialize",
            json!({
                "protocolVersion": MCP_PROTOCOL,
                "capabilities": {},
                "clientInfo": { "name": "proxy-test", "version": "0" },
            }),
        )
        .await
    }

    async fn initialized(&mut self) {
        self.send(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }))
        .await;
    }

    async fn tools(&mut self) -> Vec<Value> {
        self.request("tools/list", json!({})).await["result"]["tools"]
            .as_array()
            .expect("tools array")
            .clone()
    }

    async fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )
        .await
    }

    async fn close(mut self) {
        self.writer.take();
        tokio::time::timeout(LIMIT, self.child.wait())
            .await
            .expect("proxy exit timeout")
            .expect("wait for proxy");
    }
}

impl Drop for ProxyPeer {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

async fn local_tools(
    core: agent_control_plane::core::CoreHandle,
    roles: Arc<RolesConfig>,
) -> Vec<Value> {
    let (client, server) = tokio::io::duplex(1 << 20);
    let door = AcpServer::new(core, roles);
    let task = tokio::spawn(async move {
        let service = door.serve(server).await.expect("serve local MCP door");
        service.waiting().await.expect("wait local MCP door");
    });
    let (read, mut write) = tokio::io::split(client);
    let mut read = BufReader::new(read);
    async fn exchange(
        read: &mut BufReader<ReadHalf<DuplexStream>>,
        write: &mut WriteHalf<DuplexStream>,
        id: i64,
        method: &str,
        params: Value,
    ) -> Value {
        write
            .write_all(
                format!(
                    "{}\n",
                    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
                )
                .as_bytes(),
            )
            .await
            .expect("write local MCP request");
        let mut line = String::new();
        read.read_line(&mut line)
            .await
            .expect("read local MCP answer");
        serde_json::from_str(&line).expect("local MCP emitted JSON")
    }
    let initialized = exchange(
        &mut read,
        &mut write,
        1,
        "initialize",
        json!({
            "protocolVersion": MCP_PROTOCOL,
            "capabilities": {},
            "clientInfo": { "name": "local-test", "version": "0" },
        }),
    )
    .await;
    assert!(initialized["result"]["capabilities"]["tools"].is_object());
    write
        .write_all(
            format!(
                "{}\n",
                json!({ "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} })
            )
            .as_bytes(),
        )
        .await
        .expect("write initialized notification");
    let tools = exchange(&mut read, &mut write, 2, "tools/list", json!({})).await["result"]
        ["tools"]
        .as_array()
        .expect("local tools array")
        .clone();
    drop(write);
    drop(read);
    tokio::time::timeout(LIMIT, task)
        .await
        .expect("local door timeout")
        .expect("local door task");
    tools
}

fn delegate_args() -> Value {
    json!({
        "role": "builder",
        "task": {
            "id": "T55",
            "title": "Add src/adder.ts exporting add(a, b).",
            "description": "Add src/adder.ts exporting add(a, b).",
            "files": ["src/adder.ts"],
            "acceptance": ["add(1, 2) === 3"],
        },
    })
}

fn refusal(answer: &Value) -> &Value {
    let result = &answer["result"];
    assert_eq!(result["isError"], json!(true), "{answer}");
    assert_eq!(result["structuredContent"]["ok"], json!(false), "{answer}");
    &result["structuredContent"]
}

async fn socket_call(path: &Path, method: &str, params: Value) -> Result<Value, Value> {
    tokio::time::timeout(LIMIT, async {
        let stream = UnixStream::connect(path)
            .await
            .expect("connect socket client");
        let (read, mut write) = stream.into_split();
        let mut read = BufReader::new(read);

        async fn exchange(
            read: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
            write: &mut tokio::net::unix::OwnedWriteHalf,
            id: i64,
            method: &str,
            params: Value,
        ) -> Value {
            write
                .write_all(
                    format!(
                        "{}\n",
                        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
                    )
                    .as_bytes(),
                )
                .await
                .expect("write socket request");
            loop {
                let mut line = String::new();
                let bytes = read
                    .read_line(&mut line)
                    .await
                    .expect("read socket response");
                assert_ne!(bytes, 0, "socket closed before response id {id}");
                let frame: Value = serde_json::from_str(&line).expect("socket response JSON");
                if frame.get("id").and_then(Value::as_i64) == Some(id) {
                    return frame;
                }
            }
        }

        let hello = exchange(
            &mut read,
            &mut write,
            1,
            "hello",
            json!({ "clientName": "lead-proxy-e2e" }),
        )
        .await;
        assert_eq!(hello["result"]["protocolVersion"], json!(PROTOCOL_VERSION));
        let answer = exchange(&mut read, &mut write, 2, method, params).await;
        match answer.get("error") {
            Some(error) => Err(error.clone()),
            None => Ok(answer.get("result").cloned().unwrap_or(Value::Null)),
        }
    })
    .await
    .expect("socket call timeout")
}

#[test]
fn proxy_tools_are_byte_identical_to_the_in_process_door() {
    common::with_shared_env(|| async {
        let world = world("pass");
        let roles = embedded_roles();
        let actor = start_actor(&world, Arc::clone(&roles), ActorOpts::default());
        let socket = SocketDoor::start(&world, actor.handle.clone(), Arc::clone(&roles)).await;
        let local = local_tools(actor.handle.clone(), Arc::clone(&roles)).await;

        let mut proxy = ProxyPeer::start(world.state_dir(), world.repo_root(), None).await;
        let init = proxy.initialize().await;
        assert!(init["result"]["instructions"].as_str().is_some());
        proxy.initialized().await;
        let through_socket = proxy.tools().await;

        assert_eq!(
            through_socket.len(),
            9,
            "nine coordination tools; lead.start remains human-only"
        );
        assert!(
            through_socket
                .iter()
                .all(|tool| tool["name"] != json!("lead.start")),
            "the human-only lead.start method must not cross the MCP proxy"
        );

        assert_eq!(
            serde_json::to_vec(&through_socket).expect("encode proxy tools"),
            serde_json::to_vec(&local).expect("encode local tools"),
            "the proxy and in-process door advertise byte-identical tool schemas"
        );

        proxy.close().await;
        socket.stop().await;
        actor.stop().await;
    });
}

#[test]
fn delegate_round_trips_and_socket_errors_stay_structured() {
    common::with_shared_env(|| async {
        let world = world("pass");
        let roles = embedded_roles();
        let actor = start_actor(&world, Arc::clone(&roles), ActorOpts::default());
        let socket = SocketDoor::start(&world, actor.handle.clone(), Arc::clone(&roles)).await;
        let mut proxy = ProxyPeer::start(world.state_dir(), world.repo_root(), None).await;
        assert!(proxy.initialize().await["result"].is_object());
        proxy.initialized().await;

        let delegated = proxy.call("delegate", delegate_args()).await;
        assert_eq!(delegated["result"]["isError"], json!(false), "{delegated}");
        let structured = &delegated["result"]["structuredContent"];
        let agent = structured["agentId"].as_str().expect("agent id");
        assert!(structured["runId"].as_str().is_some());

        let status = wait_for_status(
            &actor.handle,
            StatusQuery {
                run_id: None,
                agent_id: Some(agent.parse().expect("agent uuid")),
                last_events: DEFAULT_LAST_EVENTS,
            },
            "the proxy-created agent to enter the projection",
            |status| status.agents.len() == 1,
        )
        .await;
        assert_eq!(status.agents.len(), 1, "the proxy reached the daemon actor");

        let unknown = proxy
            .call(
                "resolve_gate",
                json!({
                    "gateId": "00000000-0000-0000-0000-000000000001",
                    "approve": false,
                }),
            )
            .await;
        assert_eq!(refusal(&unknown)["code"], json!("unknown_gate"));

        quiesce(&actor.handle).await;
        proxy.close().await;
        socket.stop().await;
        actor.stop().await;
    });
}

async fn fake_socket(
    path: PathBuf,
    protocol: u32,
    observed: tokio::sync::mpsc::Sender<Value>,
    shutdown: CancellationToken,
) {
    let _ = fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind fake socket");
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.expect("accept fake client");
                let observed = observed.clone();
                tokio::spawn(async move {
                    let (read, mut write) = stream.into_split();
                    let mut read = BufReader::new(read);
                    let mut line = String::new();
                    if read.read_line(&mut line).await.ok() != Some(0) {
                        let hello: Value = serde_json::from_str(&line).expect("fake hello");
                        for method in ["acp.lagged", "acp.shutdown"] {
                            write.write_all(format!("{}\n", json!({
                                "jsonrpc": "2.0", "method": method,
                                "params": { "protocolVersion": protocol }
                            })).as_bytes()).await.expect("fake notification");
                        }
                        write.write_all(format!("{}\n", json!({
                            "jsonrpc": "2.0", "id": hello["id"],
                            "result": { "protocolVersion": protocol }
                        })).as_bytes()).await.expect("fake hello answer");
                    }
                    line.clear();
                    if read.read_line(&mut line).await.ok().filter(|n| *n > 0).is_some() {
                        let request: Value = serde_json::from_str(&line).expect("fake request");
                        let _ = observed.send(request.clone()).await;
                        write.write_all(format!("{}\n", json!({
                            "jsonrpc": "2.0", "method": "acp.lagged",
                            "params": { "protocolVersion": protocol, "dropped": 1 }
                        })).as_bytes()).await.expect("fake lag notification");
                        write.write_all(format!("{}\n", json!({
                            "jsonrpc": "2.0", "id": request["id"],
                            "result": { "status": "running", "lastEvent": null }
                        })).as_bytes()).await.expect("fake method answer");
                    }
                });
            }
        }
    }
}

#[test]
fn protocol_mismatch_is_a_clean_initialize_error() {
    common::with_shared_env(|| async {
        let state = short_state();
        let repo = temp_git_repo();
        let path = state.path().join("acp.sock");
        let shutdown = CancellationToken::new();
        let (observed, _rx) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(fake_socket(path.clone(), 999, observed, shutdown.clone()));
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let mut proxy = ProxyPeer::start(state.path(), repo.path(), None).await;
        let answer = proxy.initialize().await;
        assert_eq!(answer["error"]["code"], json!(-32603), "{answer}");
        assert!(
            answer["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("protocol 999")),
            "the initialize error explains the socket version mismatch: {answer}"
        );

        proxy.close().await;
        shutdown.cancel();
        task.await.expect("fake socket task");
    });
}

fn copy_roles_with(path: &Path, await_max: u64, allow_approve: bool) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("roles");
    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).expect("create roles fixture directory");
        for entry in fs::read_dir(source).expect("read roles fixture source") {
            let entry = entry.expect("roles fixture entry");
            let target = destination.join(entry.file_name());
            if entry.path().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).expect("copy roles fixture file");
            }
        }
    }
    copy_tree(&source, path);
    let config = path.join("roles.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&config).expect("read roles config"))
        .expect("parse roles config");
    value["defaults"]["awaitResultMaxSec"] = json!(await_max);
    value["gates"]["allowAgentApprove"] = json!(allow_approve);
    fs::write(
        &config,
        serde_json::to_vec_pretty(&value).expect("encode roles"),
    )
    .expect("write roles config");
    config
}

#[test]
fn notifications_are_swallowed_and_the_roles_await_clamp_reaches_the_socket() {
    common::with_shared_env(|| async {
        let state = short_state();
        let repo = temp_git_repo();
        let path = state.path().join("acp.sock");
        let shutdown = CancellationToken::new();
        let (observed, mut rx) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(fake_socket(
            path.clone(),
            PROTOCOL_VERSION,
            observed,
            shutdown.clone(),
        ));
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let roles_dir = state.path().join("roles-fixture");
        let roles = copy_roles_with(&roles_dir, 7, false);

        let mut proxy = ProxyPeer::start(state.path(), repo.path(), Some(&roles)).await;
        assert!(proxy.initialize().await["result"].is_object());
        proxy.initialized().await;
        let answer = proxy
            .call(
                "await_result",
                json!({
                    "agentId": "00000000-0000-0000-0000-000000000001",
                    "timeoutSec": 300,
                }),
            )
            .await;
        assert_eq!(answer["result"]["isError"], json!(false), "{answer}");
        let request = tokio::time::timeout(LIMIT, rx.recv())
            .await
            .expect("observed request timeout")
            .expect("observed request");
        assert_eq!(request["method"], json!("await_result"));
        assert_eq!(request["params"]["timeoutSec"], json!(7));

        proxy.close().await;
        shutdown.cancel();
        task.await.expect("fake socket task");
    });
}

/// T84: a proxy child standing in for a spawned lead's own MCP door (`ACP_LEAD_RUN_ID` set)
/// attaches `callerRunId` to every mutation, including follow-ups and gate denials which may
/// resume a writer. Read-only status does not need attribution.
#[test]
fn a_lead_run_id_env_attaches_caller_run_id_to_all_mutations() {
    common::with_shared_env(|| async {
        let state = short_state();
        let repo = temp_git_repo();
        let path = state.path().join("acp.sock");
        let shutdown = CancellationToken::new();
        let (observed, mut rx) = tokio::sync::mpsc::channel(8);
        let task = tokio::spawn(fake_socket(
            path.clone(),
            PROTOCOL_VERSION,
            observed,
            shutdown.clone(),
        ));
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let lead_run: agent_control_plane::core::types::RunId =
            "99999999-9999-4999-8999-999999999999"
                .parse()
                .expect("fixture lead run id");

        let mut proxy = ProxyPeer::start_as(state.path(), repo.path(), None, Some(lead_run)).await;
        assert!(proxy.initialize().await["result"].is_object());
        proxy.initialized().await;

        let _ = proxy.call("delegate", delegate_args()).await;
        let request = tokio::time::timeout(LIMIT, rx.recv())
            .await
            .expect("observed delegate timeout")
            .expect("observed delegate");
        assert_eq!(request["method"], json!("delegate"));
        assert_eq!(request["params"]["callerRunId"], json!(lead_run));

        let plan_args = json!({ "plan": { "version": 1, "name": "t84", "items": [] } });
        let _ = proxy.call("submit_plan", plan_args).await;
        let request = tokio::time::timeout(LIMIT, rx.recv())
            .await
            .expect("observed plan.start timeout")
            .expect("observed plan.start");
        assert_eq!(request["method"], json!("plan.start"));
        assert_eq!(request["params"]["callerRunId"], json!(lead_run));

        let _ = proxy.call("audit_existing", json!({
            "task": delegate_args()["task"],
            "selection": {"baseRef":"HEAD", "target":{"kind":"workingTree"}}
        })).await;
        let request = tokio::time::timeout(LIMIT, rx.recv()).await.unwrap().unwrap();
        assert_eq!(request["method"], "audit.start");
        assert_eq!(request["params"]["callerRunId"], json!(lead_run));

        for (method, args) in [
            ("send_message", json!({"agentId": lead_run, "message": "follow up"})),
            ("cancel", json!({"agentId": lead_run})),
            ("request_human_gate", json!({"runId": lead_run, "kind": "plan", "summary": "decide"})),
            ("resolve_gate", json!({"gateId": lead_run, "approve": false, "feedback": "repair"})),
        ] {
            let _ = proxy.call(method, args).await;
            let request = tokio::time::timeout(LIMIT, rx.recv()).await.unwrap().unwrap();
            assert_eq!(request["method"], method);
            assert_eq!(request["params"]["callerRunId"], json!(lead_run));
        }
        // Reads do not carry mutation authority.
        let _ = proxy
            .call("get_status", json!({ "lastEvents": 0 }))
            .await;
        let request = tokio::time::timeout(LIMIT, rx.recv())
            .await
            .expect("observed get_status timeout")
            .expect("observed get_status");
        assert_eq!(request["method"], json!("get_status"));
        assert!(
            request["params"].get("callerRunId").is_none(),
            "get_status must never be attributed: {request}"
        );

        proxy.close().await;
        shutdown.cancel();
        task.await.expect("fake socket task");
    });
}

/// The complement: without `ACP_LEAD_RUN_ID` (every door but a spawned lead's own proxy — the
/// app, the CLI, a terminal lead's user-level registration), `delegate` and `plan.start` are
/// forwarded byte-identical to how they always were — no `callerRunId` key at all, not merely a
/// `null` one.
#[test]
fn no_lead_run_id_env_leaves_delegate_and_plan_start_unattributed() {
    common::with_shared_env(|| async {
        let state = short_state();
        let repo = temp_git_repo();
        let path = state.path().join("acp.sock");
        let shutdown = CancellationToken::new();
        let (observed, mut rx) = tokio::sync::mpsc::channel(8);
        let task = tokio::spawn(fake_socket(
            path.clone(),
            PROTOCOL_VERSION,
            observed,
            shutdown.clone(),
        ));
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let mut proxy = ProxyPeer::start(state.path(), repo.path(), None).await;
        assert!(proxy.initialize().await["result"].is_object());
        proxy.initialized().await;

        let _ = proxy.call("delegate", delegate_args()).await;
        let request = tokio::time::timeout(LIMIT, rx.recv())
            .await
            .expect("observed delegate timeout")
            .expect("observed delegate");
        assert_eq!(request["method"], json!("delegate"));
        assert!(
            request["params"].get("callerRunId").is_none(),
            "no ACP_LEAD_RUN_ID means no callerRunId key at all: {request}"
        );

        let plan_args = json!({ "plan": { "version": 1, "name": "t84", "items": [] } });
        let _ = proxy.call("submit_plan", plan_args).await;
        let request = tokio::time::timeout(LIMIT, rx.recv())
            .await
            .expect("observed plan.start timeout")
            .expect("observed plan.start");
        assert_eq!(request["method"], json!("plan.start"));
        assert!(
            request["params"].get("callerRunId").is_none(),
            "no ACP_LEAD_RUN_ID means no callerRunId key at all: {request}"
        );

        proxy.close().await;
        shutdown.cancel();
        task.await.expect("fake socket task");
    });
}

#[test]
fn socket_backstop_denies_approval_even_when_proxy_roles_allow_it() {
    common::with_shared_env(|| async {
        let world = world("pass");
        let roles = embedded_roles();
        let actor = start_actor(&world, Arc::clone(&roles), ActorOpts::default());
        let socket = SocketDoor::start(&world, actor.handle.clone(), roles).await;
        let roles_dir = world.state_dir().join("roles-fixture");
        let proxy_roles = copy_roles_with(&roles_dir, 300, true);
        assert!(
            load_roles(Some(&proxy_roles))
                .expect("load proxy roles fixture")
                .gates
                .allow_agent_approve,
            "the proxy-side guard is deliberately open so the socket backstop is exercised"
        );
        let mut proxy =
            ProxyPeer::start(world.state_dir(), world.repo_root(), Some(&proxy_roles)).await;
        assert!(proxy.initialize().await["result"].is_object());
        proxy.initialized().await;

        let answer = proxy
            .call(
                "resolve_gate",
                json!({
                    "gateId": "00000000-0000-0000-0000-000000000001",
                    "approve": true,
                }),
            )
            .await;
        assert_eq!(
            refusal(&answer)["code"],
            json!("agent_approve_not_allowed"),
            "the socket is the structural deny-only backstop: {answer}"
        );

        proxy.close().await;
        socket.stop().await;
        actor.stop().await;
    });
}

#[test]
fn daemon_spawned_lead_reads_status_but_cannot_approve_through_its_proxy() {
    common::with_shared_env(|| async {
        let world = world("hang");
        let roles = embedded_roles();
        let actor = start_actor(&world, Arc::clone(&roles), ActorOpts::default());
        let handle = actor.handle.clone();
        let socket = SocketDoor::start(&world, handle.clone(), roles).await;
        let socket_path = world.state_dir().join("acp.sock");
        let state_dir = world.state_dir().to_path_buf();
        let repo_root = world.repo_root().to_path_buf();
        let roles_dir = world.state_dir().join("lead-proxy-roles");
        let proxy_roles = copy_roles_with(&roles_dir, 300, true);
        assert!(
            load_roles(Some(&proxy_roles))
                .expect("load lead proxy roles")
                .gates
                .allow_agent_approve,
            "the proxy-side deny is open so this exercise must reach the socket backstop"
        );

        // Assertions run in a child task so quiesce/socket/actor cleanup always happens before a
        // failure is surfaced. ProxyPeer's Drop kills its stdio child on the same path.
        let exercise_handle = handle.clone();
        let exercise = tokio::spawn(async move {
            let started = socket_call(
                &socket_path,
                "lead.start",
                json!({ "message": "Inspect ACP status, but never approve a gate." }),
            )
            .await
            .expect("socket lead.start");
            let run = started["runId"].as_str().expect("run id").to_string();
            let agent = started["agentId"]
                .as_str()
                .expect("agent id")
                .parse()
                .expect("agent UUID");
            wait_for_status(
                &exercise_handle,
                StatusQuery {
                    agent_id: Some(agent),
                    ..StatusQuery::default()
                },
                "the daemon-spawned lead to run",
                |status| {
                    status.attempts.iter().any(|attempt| {
                        attempt.agent_id == agent
                            && attempt.status
                                == agent_control_plane::core::types::AttemptStatus::Running
                    })
                },
            )
            .await;

            let mut proxy = ProxyPeer::start(&state_dir, &repo_root, Some(&proxy_roles)).await;
            assert!(proxy.initialize().await["result"].is_object());
            proxy.initialized().await;
            let status = proxy.call("get_status", json!({ "runId": run })).await;
            assert_eq!(status["result"]["isError"], json!(false), "{status}");
            let projected = &status["result"]["structuredContent"];
            assert_eq!(projected["runs"][0]["runId"], json!(run));
            assert_eq!(projected["agents"][0]["role"], json!("lead"));

            let denied = proxy
                .call(
                    "resolve_gate",
                    json!({
                        "gateId": "00000000-0000-0000-0000-000000000001",
                        "approve": true,
                    }),
                )
                .await;
            assert_eq!(
                refusal(&denied)["code"],
                json!("agent_approve_not_allowed"),
                "the socket backstop denies the daemon-spawned lead: {denied}"
            );
            proxy.close().await;
        })
        .await;

        quiesce(&handle).await;
        socket.stop().await;
        actor.stop().await;
        exercise.expect("lead proxy assertions");
    });
}
