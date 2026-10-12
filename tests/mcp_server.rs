//! T42: the MCP door, driven over a real rmcp connection —
//! `reports/03-design.md` § Test Strategy, row `mcp/server.rs`.
//!
//! **How the client is built, and why it is hand-rolled JSON-RPC.** The design asks for "an
//! in-process `rmcp` client over a duplex transport". The *server* half here is exactly that: a
//! real [`AcpServer`] served by rmcp over a `tokio::io::duplex` pair, so the initialize handshake,
//! the tool router, the schema advertisement and the `structuredContent`/`isError` framing are all
//! production code. The *client* half is a raw JSON-RPC line peer rather than `rmcp`'s typed
//! client, for two reasons: rmcp's client role is behind the `client` cargo feature, which is not
//! in the dependency set `CLAUDE.md` fixes (it would pull `tokio-stream` into the lock file); and
//! every assertion in this file is about **the bytes on the wire** — that `$schema` is absent,
//! that `outputSchema` is present, that a refusal carries `structuredContent{ok:false}` with
//! `isError:true`, that a success payload has no `ok` key. A typed client would deserialize those
//! into rmcp's model types and normalize away the very thing under test.
//!
//! **Two kinds of core.** A [`spy_core`] is a [`CoreHandle`] whose mailbox nobody drains: a call
//! the door refuses must leave that mailbox **empty**, which is how "rejected before reaching
//! `core`" is asserted rather than assumed. The live tests wire the door to a real actor over the
//! `tests/common` harness and the fake CLIs, so `delegate` reaches `core::loop`, a worktree, an
//! argv and a process.
//!
//! **Process hygiene.** Every worker started here is ended before its test returns
//! (`common::quiesce`); after a run `ps -eo command | grep -F 'Add src/adder.ts' | grep -vc grep`
//! must print `0`.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_control_plane::core::types::{AgentId, GateId, RolesConfig};
use agent_control_plane::core::{channel, Command as CoreCommand, CoreHandle, StatusQuery};
use agent_control_plane::mcp::server::AcpServer;
use rmcp::ServiceExt;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use common::{
    embedded_roles, loop_task, quiesce, start_actor, wait_for_status, ActorOpts, LoopWorld, LIMIT,
};

/// The nine implemented tools, sorted. `roles.list`, `team.get` and `team.set` are
/// socket-only (Rev 26) and `gate.approve` is socket-only (S2): none of them may appear here.
const TOOLS: [&str; 9] = [
    "audit_existing",
    "await_result",
    "cancel",
    "delegate",
    "get_status",
    "request_human_gate",
    "resolve_gate",
    "send_message",
    "submit_plan",
];

/// How long a call the door refuses by itself may take. Everything on that path is in-process, so
/// this is a failure detector, not a timing assertion — see [`Peer::call_refused`].
const REFUSED_LIMIT: Duration = Duration::from_secs(10);

/// The protocol version this client negotiates. Pinned rather than "latest" so a future rmcp
/// default cannot silently change what the handshake under test is.
const PROTOCOL_VERSION: &str = "2025-11-25";

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// A raw JSON-RPC peer talking to an [`AcpServer`] over an in-process duplex pair.
struct Peer {
    reader: BufReader<ReadHalf<DuplexStream>>,
    writer: WriteHalf<DuplexStream>,
    next_id: i64,
    server: JoinHandle<()>,
}

impl Peer {
    /// Connects to a door over the shipped roles, and completes the initialize handshake.
    async fn connect(core: CoreHandle) -> Self {
        Self::connect_with(core, embedded_roles()).await
    }

    async fn connect_with(core: CoreHandle, roles: Arc<RolesConfig>) -> Self {
        let (client, server) = tokio::io::duplex(1 << 20);
        let door = AcpServer::new(core, roles);
        let task = tokio::spawn(async move {
            match door.serve(server).await {
                Ok(running) => {
                    let _ = running.waiting().await;
                }
                Err(err) => panic!("serve the MCP door: {err}"),
            }
        });
        let (reader, writer) = tokio::io::split(client);
        let mut peer = Self {
            reader: BufReader::new(reader),
            writer,
            next_id: 0,
            server: task,
        };
        peer.initialize().await;
        peer
    }

    async fn initialize(&mut self) {
        let answer = self
            .request(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "acp-door-test", "version": "0" },
                }),
            )
            .await;
        assert!(
            answer["result"]["capabilities"]["tools"].is_object(),
            "the door advertises the tools capability: {answer}"
        );
        self.notify("notifications/initialized").await;
    }

    async fn send(&mut self, message: &Value) {
        let line = format!("{message}\n");
        self.writer
            .write_all(line.as_bytes())
            .await
            .expect("write a JSON-RPC line");
        self.writer.flush().await.expect("flush the duplex");
    }

    async fn notify(&mut self, method: &str) {
        self.send(&json!({ "jsonrpc": "2.0", "method": method, "params": {} }))
            .await;
    }

    /// Sends one request and waits for its answer.
    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.dispatch(method, params).await;
        self.answer(id).await
    }

    /// Sends one request and returns its id **without** waiting — for the two calls that have to
    /// be in flight at once.
    async fn dispatch(&mut self, method: &str, params: Value) -> i64 {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
            .await;
        id
    }

    /// A call the door must refuse **by itself**.
    ///
    /// A [`spy_core`] never answers anything, so a door that forwarded this call would wait
    /// forever. The short bound turns that regression into a named failure in seconds instead of
    /// a minute of silence — and [`core_was_not_called`] then says which command got through.
    async fn call_refused(&mut self, tool: &str, arguments: Value) -> Value {
        let id = self
            .dispatch(
                "tools/call",
                json!({ "name": tool, "arguments": arguments }),
            )
            .await;
        self.answer_within(
            id,
            REFUSED_LIMIT,
            "the door forwarded a call it should have refused",
        )
        .await
    }

    /// Reads until the answer to `id` arrives, skipping notifications.
    async fn answer(&mut self, id: i64) -> Value {
        self.answer_within(id, LIMIT, "the door never answered")
            .await
    }

    async fn answer_within(&mut self, id: i64, limit: Duration, what: &str) -> Value {
        let read = tokio::time::timeout(limit, async {
            loop {
                let mut line = String::new();
                let read = self
                    .reader
                    .read_line(&mut line)
                    .await
                    .expect("read a JSON-RPC line");
                assert!(read > 0, "the MCP door closed the connection");
                let message: Value = serde_json::from_str(&line)
                    .unwrap_or_else(|err| panic!("not JSON-RPC: {err}: {line}"));
                if message.get("id").and_then(Value::as_i64) == Some(id) {
                    return message;
                }
            }
        })
        .await;
        read.unwrap_or_else(|_| panic!("{what}: no answer to request {id} within {limit:?}"))
    }

    async fn tools(&mut self) -> Vec<Value> {
        let answer = self.request("tools/list", json!({})).await;
        answer["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("tools/list answered no tool array: {answer}"))
            .clone()
    }

    async fn call(&mut self, tool: &str, arguments: Value) -> Value {
        self.request(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        )
        .await
    }

    /// Stops the served door. Dropping the client end is what ends `serve`; the abort is for the
    /// case where a test left a request in flight.
    async fn close(self) {
        drop(self.writer);
        drop(self.reader);
        self.server.abort();
    }
}

// ---------------------------------------------------------------------------
// Reading an answer
// ---------------------------------------------------------------------------

/// The `result` of a `tools/call` that succeeded: `structuredContent`, with `isError:false`.
fn success(answer: &Value) -> &Value {
    assert!(
        answer.get("error").is_none(),
        "expected a tool result, got a JSON-RPC error: {answer}"
    );
    let result = &answer["result"];
    assert_eq!(
        result["isError"],
        json!(false),
        "a success carries isError:false: {answer}"
    );
    let structured = &result["structuredContent"];
    assert!(
        structured.is_object(),
        "a success carries structuredContent: {answer}"
    );
    assert!(
        structured.get("ok").is_none(),
        "no success payload carries an `ok` field — `isError:false` already said so: {structured}"
    );
    structured
}

/// The `structuredContent` of a `tools/call` the door refused: `{ok:false, code, reason}` with
/// `isError:true`.
fn refusal(answer: &Value) -> &Value {
    assert!(
        answer.get("error").is_none(),
        "a refusal is a tool result, not a JSON-RPC error: {answer}"
    );
    let result = &answer["result"];
    assert_eq!(
        result["isError"],
        json!(true),
        "a refusal carries isError:true: {answer}"
    );
    let structured = &result["structuredContent"];
    assert_eq!(
        structured["ok"],
        json!(false),
        "a refusal carries ok:false: {answer}"
    );
    assert!(
        structured["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "a refusal carries a reason a human can act on: {structured}"
    );
    structured
}

/// The text of a `tools/call` whose *arguments* did not parse: `isError:true`, a text block, and
/// no `structuredContent` at all.
fn parse_error(answer: &Value) -> String {
    assert!(
        answer.get("error").is_none(),
        "rmcp reports a bad argument object as a tool result, not a JSON-RPC error: {answer}"
    );
    let result = &answer["result"];
    assert_eq!(result["isError"], json!(true), "{answer}");
    assert!(
        result.get("structuredContent").is_none(),
        "an unparsed argument object decided nothing, so it carries no structured payload: {answer}"
    );
    let text = result["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("a parse failure carries its message as text: {answer}"))
        .to_string();
    assert!(
        text.starts_with("failed to deserialize parameters:"),
        "{text}"
    );
    text
}

/// The `code` of a refusal.
fn code(answer: &Value) -> String {
    refusal(answer)["code"]
        .as_str()
        .unwrap_or_else(|| panic!("a refusal's code is a string: {answer}"))
        .to_string()
}

fn tool<'a>(tools: &'a [Value], name: &str) -> &'a Value {
    tools
        .iter()
        .find(|t| t["name"] == json!(name))
        .unwrap_or_else(|| panic!("no `{name}` in tools/list"))
}

/// Every place a `$schema` key appears in `value`, by JSON pointer.
fn dollar_schema_keys(value: &Value, path: &str, found: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "$schema" {
                    found.push(format!("{path}/{key}"));
                }
                dollar_schema_keys(child, &format!("{path}/{key}"), found);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                dollar_schema_keys(child, &format!("{path}/{index}"), found);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Cores
// ---------------------------------------------------------------------------

/// A [`CoreHandle`] whose mailbox nobody drains.
///
/// The receiver **is** the spy: after a call the door refused, `try_recv` must find the mailbox
/// empty, which proves no [`CoreCommand`] was ever posted — no worktree, no policy check, no
/// audit entry, no side effect of any kind.
fn spy_core() -> (CoreHandle, mpsc::Receiver<CoreCommand>) {
    let (tx, rx) = channel();
    let (events, _) = broadcast::channel(16);
    (CoreHandle::new(tx, events), rx)
}

fn core_was_not_called(rx: &mut mpsc::Receiver<CoreCommand>) {
    match rx.try_recv() {
        Err(mpsc::error::TryRecvError::Empty) => {}
        Ok(command) => panic!("the door reached core with {command:?}"),
        Err(err) => panic!("the spy mailbox is gone: {err}"),
    }
}

/// A valid `delegate` argument object, for the tests that vary one field of it.
fn delegate_args() -> Value {
    json!({
        "role": "builder",
        "task": {
            "id": "T42",
            "title": "Add src/adder.ts exporting add(a, b).",
            "description": "Add src/adder.ts exporting add(a, b).",
            "files": ["src/adder.ts"],
            "acceptance": ["add(1, 2) === 3"],
        },
    })
}

// ---------------------------------------------------------------------------
// The surface
// ---------------------------------------------------------------------------

/// The tool list is the design's seven, and nothing else — in particular none of the socket-only
/// methods, because a tool that is not registered is unreachable rather than merely refused.
#[test]
fn tools_list_is_exactly_the_seven_the_design_fixes() {
    common::with_shared_env(|| async {
        let (core, _spy) = spy_core();
        let mut peer = Peer::connect(core).await;

        let tools = peer.tools().await;
        let mut names: Vec<String> = tools
            .iter()
            .map(|t| t["name"].as_str().expect("a tool name").to_string())
            .collect();
        names.sort();
        assert_eq!(names, TOOLS, "the nine tools, and only those");

        for socket_only in [
            "roles.list",
            "team.get",
            "team.set",
            "gate.approve",
            "hello",
        ] {
            assert!(
                !names.iter().any(|name| name == socket_only),
                "{socket_only} is socket-only and must not be reachable over MCP"
            );
        }
        peer.close().await;
    });
}

/// Every tool advertises **both** schemas, and neither carries a `$schema` key anywhere (V7).
#[test]
fn every_tool_advertises_an_input_and_an_output_schema_free_of_dollar_schema() {
    common::with_shared_env(|| async {
        let (core, _spy) = spy_core();
        let mut peer = Peer::connect(core).await;
        let tools = peer.tools().await;

        for name in TOOLS {
            let advertised = tool(&tools, name);
            assert_eq!(
                advertised["inputSchema"]["type"],
                json!("object"),
                "{name} advertises an object inputSchema"
            );
            assert_eq!(
                advertised["outputSchema"]["type"],
                json!("object"),
                "{name} advertises an object outputSchema"
            );
            assert!(
                advertised["description"]
                    .as_str()
                    .is_some_and(|d| d.len() > 40),
                "{name} tells the lead what it does"
            );
        }

        let mut found = Vec::new();
        dollar_schema_keys(&json!(tools), "", &mut found);
        assert!(
            found.is_empty(),
            "schemars' top-level `$schema` must be stripped from every advertised schema (V7): \
             found at {found:?}"
        );
        peer.close().await;
    });
}

/// The drift test: every bound `DelegateArgs`/`TaskArgs` declare in `#[schemars(...)]` is in the
/// schema the lead is actually shown, and the objects are closed.
#[test]
fn the_delegate_input_schema_carries_every_mirrored_bound() {
    common::with_shared_env(|| async {
        let (core, _spy) = spy_core();
        let mut peer = Peer::connect(core).await;
        let tools = peer.tools().await;
        let schema = tool(&tools, "delegate")["inputSchema"].clone();

        assert_eq!(
            schema["additionalProperties"],
            json!(false),
            "the argument object is closed (deny_unknown_fields)"
        );
        assert_eq!(
            schema["properties"]["session"]["pattern"],
            json!(r"^(fresh|resume:[0-9a-f-]{36})$")
        );
        assert_eq!(schema["properties"]["session"]["default"], json!("fresh"));
        assert_eq!(
            schema["properties"]["baseRef"]["pattern"],
            json!(r"^[A-Za-z0-9._/-]+$")
        );
        assert_eq!(schema["properties"]["baseRef"]["minLength"], json!(1));
        assert_eq!(schema["properties"]["baseRef"]["maxLength"], json!(200));
        assert_eq!(
            schema["properties"]["role"]["$ref"],
            json!("#/$defs/DelegatableRole")
        );
        assert_eq!(
            schema["$defs"]["DelegatableRole"]["enum"],
            json!(["builder", "reviewer"]),
            "the role is a closed enum, never a free string"
        );

        let task = &schema["$defs"]["TaskArgs"];
        assert_eq!(task["additionalProperties"], json!(false));
        assert_eq!(task["properties"]["id"]["minLength"], json!(1));
        assert_eq!(task["properties"]["id"]["maxLength"], json!(64));
        assert_eq!(
            task["properties"]["id"]["pattern"],
            json!(r"^[A-Za-z0-9._-]+$")
        );
        assert_eq!(task["properties"]["title"]["minLength"], json!(1));
        assert_eq!(task["properties"]["title"]["maxLength"], json!(200));
        assert_eq!(task["properties"]["description"]["minLength"], json!(10));
        assert_eq!(
            task["properties"]["description"]["maxLength"],
            json!(20_000)
        );
        assert_eq!(task["properties"]["files"]["maxItems"], json!(100));
        assert_eq!(task["properties"]["files"]["items"]["minLength"], json!(1));
        assert_eq!(
            task["properties"]["files"]["items"]["maxLength"],
            json!(400)
        );
        assert_eq!(task["properties"]["acceptance"]["minItems"], json!(1));
        assert_eq!(task["properties"]["acceptance"]["maxItems"], json!(50));
        assert_eq!(
            task["properties"]["acceptance"]["items"]["maxLength"],
            json!(1_000)
        );

        // The bounds JSON Schema cannot state are stated in the description instead.
        let description = tool(&tools, "delegate")["description"]
            .as_str()
            .expect("a description");
        for stated in ["`..` segment", "NUL", "newline", "resume:<agentId>"] {
            assert!(
                description.contains(stated),
                "the delegate description states the unexpressible bound {stated:?}: {description}"
            );
        }
        peer.close().await;
    });
}

/// `await_result` and `get_status` advertise the numeric bounds this door owns.
#[test]
fn the_numeric_bounds_this_door_owns_are_advertised() {
    common::with_shared_env(|| async {
        let (core, _spy) = spy_core();
        let mut peer = Peer::connect(core).await;
        let tools = peer.tools().await;

        let await_schema = &tool(&tools, "await_result")["inputSchema"];
        assert_eq!(
            await_schema["properties"]["timeoutSec"]["minimum"],
            json!(1)
        );
        assert_eq!(
            await_schema["properties"]["timeoutSec"]["maximum"],
            json!(300),
            "the ≤300 s await_result bound is this door's, and it is advertised"
        );
        assert_eq!(
            await_schema["properties"]["timeoutSec"]["default"],
            json!(60)
        );

        let status_schema = &tool(&tools, "get_status")["inputSchema"];
        assert_eq!(
            status_schema["properties"]["lastEvents"]["minimum"],
            json!(0)
        );
        assert_eq!(
            status_schema["properties"]["lastEvents"]["maximum"],
            json!(100)
        );
        assert_eq!(
            status_schema["properties"]["lastEvents"]["default"],
            json!(20)
        );
        peer.close().await;
    });
}

/// S2 is documented where a lead will read it, not only enforced.
#[test]
fn the_resolve_gate_description_names_the_human_approval_path() {
    common::with_shared_env(|| async {
        let (core, _spy) = spy_core();
        let mut peer = Peer::connect(core).await;
        let tools = peer.tools().await;

        let description = tool(&tools, "resolve_gate")["description"]
            .as_str()
            .expect("a description");
        for stated in [
            "HUMAN",
            "acp gate approve",
            "menu-bar app",
            "agent_approve_not_allowed",
        ] {
            assert!(
                description.contains(stated),
                "resolve_gate's description names the human approval path ({stated:?}): \
                 {description}"
            );
        }

        // The socket-only integrate path is stated on the tools a lead reaches for first, too.
        for named in ["delegate", "request_human_gate"] {
            let description = tool(&tools, named)["description"]
                .as_str()
                .expect("a description");
            assert!(
                description.contains("acp gate approve"),
                "{named}'s description names the socket-only approval path: {description}"
            );
        }
        peer.close().await;
    });
}

// ---------------------------------------------------------------------------
// Rejected before `core`
// ---------------------------------------------------------------------------

/// Every mirrored bound is *enforced*, not merely advertised — `schemars` generates schemas and
/// validates nothing — and enforcing it costs `core` nothing: the mailbox stays empty.
#[test]
fn arguments_outside_the_advertised_bounds_are_refused_before_core_is_reached() {
    common::with_shared_env(|| async {
        let (core, mut spy) = spy_core();
        let mut peer = Peer::connect(core).await;

        let cases: Vec<(&str, Value, &str)> = vec![
            (
                "a task id with a space",
                {
                    let mut args = delegate_args();
                    args["task"]["id"] = json!("T 42");
                    args
                },
                "invalid_task",
            ),
            (
                "a task id past 64 characters",
                {
                    let mut args = delegate_args();
                    args["task"]["id"] = json!("T".repeat(65));
                    args
                },
                "invalid_task",
            ),
            (
                "a title past 200 characters",
                {
                    let mut args = delegate_args();
                    args["task"]["title"] = json!("t".repeat(201));
                    args
                },
                "invalid_task",
            ),
            (
                "a description under 10 characters",
                {
                    let mut args = delegate_args();
                    args["task"]["description"] = json!("too short");
                    args
                },
                "invalid_task",
            ),
            (
                "an empty acceptance list",
                {
                    let mut args = delegate_args();
                    args["task"]["acceptance"] = json!([]);
                    args
                },
                "invalid_task",
            ),
            (
                "a file path with a `..` segment",
                {
                    let mut args = delegate_args();
                    args["task"]["files"] = json!(["../../etc/passwd"]);
                    args
                },
                "invalid_task",
            ),
            (
                "an absolute file path",
                {
                    let mut args = delegate_args();
                    args["task"]["files"] = json!(["/etc/passwd"]);
                    args
                },
                "invalid_task",
            ),
            (
                "a file path with a newline",
                {
                    let mut args = delegate_args();
                    args["task"]["files"] = json!(["src/adder.ts\nrm -rf /"]);
                    args
                },
                "invalid_task",
            ),
            (
                "a session that is neither fresh nor a uuid",
                {
                    let mut args = delegate_args();
                    args["session"] = json!("resume:not-a-uuid");
                    args
                },
                "invalid_task",
            ),
            (
                "a baseRef that looks like a flag",
                {
                    let mut args = delegate_args();
                    args["baseRef"] = json!("--upload-pack=touch /tmp/pwned");
                    args
                },
                "invalid_base_ref",
            ),
            (
                "a baseRef with a `..` segment",
                {
                    let mut args = delegate_args();
                    args["baseRef"] = json!("refs/../../heads/main");
                    args
                },
                "invalid_base_ref",
            ),
        ];

        for (what, arguments, expected) in cases {
            if expected == "invalid_task" && !what.contains("session") {
                let audit = json!({"task":arguments["task"],
                    "selection":{"baseRef":"HEAD","target":{"kind":"workingTree"}}});
                let answer = peer.call_refused("audit_existing", audit).await;
                assert_eq!(code(&answer), expected, "audit: {what}");
                core_was_not_called(&mut spy);
            }
            let answer = peer.call_refused("delegate", arguments).await;
            assert_eq!(code(&answer), expected, "{what} is refused");
            core_was_not_called(&mut spy);
        }

        // B3 (T77): `submit_plan` runs the identical task bounds per work item, before `core`,
        // and its refusal names the offending item.
        let answer = peer
            .call_refused(
                "submit_plan",
                json!({ "plan": { "version": 1, "name": "p", "items": [
                    { "id": "w1", "kind": "work",
                      "task": { "id": "bad id!", "title": "t",
                                "description": "a long enough description",
                                "files": [], "acceptance": ["done"] } }
                ] } }),
            )
            .await;
        assert_eq!(code(&answer), "invalid_task", "{answer}");
        assert!(
            answer.to_string().contains("item `w1`"),
            "the refusal names the item: {answer}"
        );
        core_was_not_called(&mut spy);
        peer.close().await;
    });
}

/// The bounds on the other six tools are enforced too, and equally cheaply.
#[test]
fn the_other_tools_enforce_their_bounds_before_core_is_reached() {
    common::with_shared_env(|| async {
        let (core, mut spy) = spy_core();
        let mut peer = Peer::connect(core).await;
        let agent = AgentId::new_v4().to_string();

        let answer = peer
            .call_refused(
                "send_message",
                json!({ "agentId": agent, "message": "x".repeat(20_001) }),
            )
            .await;
        assert_eq!(code(&answer), "invalid_task", "a message past 20 000");
        core_was_not_called(&mut spy);

        let answer = peer
            .call_refused(
                "await_result",
                json!({ "agentId": agent, "timeoutSec": 301 }),
            )
            .await;
        assert_eq!(code(&answer), "invalid_task", "a wait past the 300 s bound");
        core_was_not_called(&mut spy);

        let answer = peer
            .call_refused("get_status", json!({ "lastEvents": 101 }))
            .await;
        assert_eq!(code(&answer), "invalid_task", "lastEvents past 100");
        core_was_not_called(&mut spy);

        let answer = peer
            .call_refused(
                "request_human_gate",
                json!({
                    "runId": AgentId::new_v4().to_string(),
                    "kind": "escalate",
                    "summary": "s".repeat(4_001),
                }),
            )
            .await;
        assert_eq!(code(&answer), "invalid_task", "a summary past 4 000");
        core_was_not_called(&mut spy);

        let answer = peer
            .call_refused(
                "resolve_gate",
                json!({
                    "gateId": GateId::new_v4().to_string(),
                    "approve": false,
                    "feedback": "f".repeat(8_001),
                }),
            )
            .await;
        assert_eq!(code(&answer), "invalid_task", "feedback past 8 000");
        core_was_not_called(&mut spy);

        peer.close().await;
    });
}

/// A malformed argument *object* never reaches a tool body: `deny_unknown_fields` and the closed
/// enums fail at deserialization.
///
/// rmcp answers that with `isError:true` and the parse error as **text** rather than with a
/// JSON-RPC `-32602`, on purpose — the model is meant to read what it got wrong and retry
/// (`into_tool_argument_error`, rmcp 3.1.4). It is the one failure on this surface that is not
/// `{ok:false, code, reason}`; what matters for the door is that it is also the one that decides
/// the least, and the spy proves it.
#[test]
fn a_malformed_argument_object_is_refused_at_parse_time() {
    common::with_shared_env(|| async {
        let (core, mut spy) = spy_core();
        let mut peer = Peer::connect(core).await;

        let mut unknown = delegate_args();
        unknown["model"] = json!("gpt-5.5");
        let answer = peer.call_refused("delegate", unknown).await;
        assert!(
            parse_error(&answer).contains("unknown field `model`"),
            "an unknown argument is refused — no flag passthrough: {answer}"
        );
        core_was_not_called(&mut spy);

        let mut bad_role = delegate_args();
        bad_role["role"] = json!("lead");
        let answer = peer.call_refused("delegate", bad_role).await;
        assert!(
            parse_error(&answer).contains("unknown variant `lead`"),
            "a role outside the closed enum is refused: {answer}"
        );
        core_was_not_called(&mut spy);

        let mut missing = delegate_args();
        missing["task"]
            .as_object_mut()
            .expect("a task")
            .remove("id");
        let answer = peer.call_refused("delegate", missing).await;
        assert!(
            parse_error(&answer).contains("id"),
            "a missing required field is refused: {answer}"
        );
        core_was_not_called(&mut spy);

        let answer = peer
            .call_refused(
                "request_human_gate",
                json!({
                    "runId": AgentId::new_v4().to_string(),
                    "kind": "integrate",
                    "summary": "commit my own worktree",
                    "payload": { "worktree": "/tmp/anywhere" },
                }),
            )
            .await;
        assert!(
            parse_error(&answer).contains("unknown field `worktree`"),
            "a lead cannot hand a gate a commit target: {answer}"
        );
        core_was_not_called(&mut spy);

        peer.close().await;
    });
}

/// S2 at the door: `approve:true` is refused with `agent_approve_not_allowed`, and the actor never
/// hears about it — an attempted self-approval touches no state at all.
#[test]
fn resolve_gate_cannot_approve_and_core_never_hears_about_the_attempt() {
    common::with_shared_env(|| async {
        let (core, mut spy) = spy_core();
        let mut peer = Peer::connect(core).await;
        let gate = GateId::new_v4().to_string();

        let answer = peer
            .call_refused(
                "resolve_gate",
                json!({ "gateId": gate, "approve": true, "feedback": "looks good to me" }),
            )
            .await;
        assert_eq!(code(&answer), "agent_approve_not_allowed");
        assert!(
            refusal(&answer)["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("acp gate approve")),
            "the refusal tells the lead what to relay: {answer}"
        );
        core_was_not_called(&mut spy);

        peer.close().await;
    });
}

/// The other half of the same door: a **denial** is not refused here — it is a legitimate MCP
/// call, so it reaches `core` (which answers `unknown_gate` for this made-up id).
#[test]
fn resolve_gate_can_deny_and_that_call_does_reach_core() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("hang", &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let mut peer = Peer::connect(actor.handle.clone()).await;

        let answer = peer
            .call(
                "resolve_gate",
                json!({
                    "gateId": GateId::new_v4().to_string(),
                    "approve": false,
                    "feedback": "the diff does not build",
                }),
            )
            .await;
        assert_eq!(
            code(&answer),
            "unknown_gate",
            "the deny went to core, which owns the gate log: {answer}"
        );

        peer.close().await;
        actor.stop().await;
    });
}

// ---------------------------------------------------------------------------
// Against a live core
// ---------------------------------------------------------------------------

/// A rejection `core` made — not the door — comes back in the same shape: `isError:true` with
/// `structuredContent{ok:false, code}`.
#[test]
fn a_core_policy_rejection_is_structured_content_with_is_error() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("hang", &[]);

        // A run budget of zero: `policy::check_delegate` refuses before a worktree exists, so this
        // is a real policy rejection with no process behind it.
        let mut broke = (*embedded_roles()).clone();
        broke.defaults.run_budget_usd = 0.0;
        let actor = start_actor(&world, Arc::new(broke), ActorOpts::default());
        let mut peer = Peer::connect(actor.handle.clone()).await;

        let answer = peer.call("delegate", delegate_args()).await;
        assert_eq!(code(&answer), "budget_run_exceeded", "{answer}");

        // And a rejection the actor raises about an id it has never seen.
        let answer = peer
            .call(
                "await_result",
                json!({ "agentId": AgentId::new_v4().to_string(), "timeoutSec": 1 }),
            )
            .await;
        assert_eq!(code(&answer), "resume_target_missing", "{answer}");

        peer.close().await;
        actor.stop().await;
    });
}

/// `delegate` over MCP starts a real worker: the answer is a `DelegateOut` — with no `ok` field —
/// and `get_status` sees the run it names.
#[test]
fn delegate_over_mcp_reaches_the_loop_and_get_status_sees_the_run() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("hang", &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let mut peer = Peer::connect(actor.handle.clone()).await;

        let mut args = delegate_args();
        args["task"] = json!(loop_task("T42-mcp"));
        let answer = peer.call("delegate", args).await;
        let out = success(&answer).clone();

        assert_eq!(out["status"], json!("running"));
        for id in ["agentId", "runId", "attemptId"] {
            assert!(
                out[id]
                    .as_str()
                    .is_some_and(|value| value.parse::<AgentId>().is_ok()),
                "{id} is a uuid: {out}"
            );
        }
        assert!(
            out["worktree"]
                .as_str()
                .is_some_and(|path| path.contains("worktrees")),
            "the answer names the worktree the worker writes in: {out}"
        );

        let run = out["runId"].as_str().expect("a runId").to_string();
        let agent: AgentId = out["agentId"]
            .as_str()
            .expect("an agentId")
            .parse()
            .unwrap();

        // Wait on the durable projection, not on a timer: `delegate` answers before the worktree
        // helper has appended `agent.created`.
        wait_for_status(
            &actor.handle,
            StatusQuery {
                agent_id: Some(agent),
                ..StatusQuery::default()
            },
            "the delegated worker is running",
            |status| !status.attempts.is_empty(),
        )
        .await;

        let answer = peer
            .call("get_status", json!({ "runId": run, "lastEvents": 5 }))
            .await;
        let status = success(&answer).clone();
        assert_eq!(
            status["schemaVersion"],
            json!(1),
            "the Rev 25 projection carries its own version: {status}"
        );
        assert_eq!(status["runs"][0]["runId"], json!(run));
        assert!(
            status["agents"][0]["recommendedNext"].is_string(),
            "each agent summary carries recommendedNext: {status}"
        );
        assert!(
            status["agents"][0]["processState"].is_string()
                && status["agents"][0]["turnState"].is_string(),
            "…and both state machines: {status}"
        );
        assert!(
            status["events"]
                .as_array()
                .is_some_and(|events| !events.is_empty() && events.len() <= 5),
            "lastEvents is honoured: {status}"
        );

        quiesce(&actor.handle).await;
        peer.close().await;
        actor.stop().await;
    });
}

/// `defaults.awaitResultMaxSec` caps the wait *under* the advertised ceiling: a schema-valid
/// `timeoutSec:300` is clamped, not refused, because an expired wait is not an error.
#[test]
fn the_configured_await_ceiling_caps_a_schema_valid_wait() {
    common::with_shared_env(|| async {
        /// Well under the advertised 300 s, so a door that ignored the configuration would hang
        /// this test rather than fail it — which the bound below turns into a named failure.
        const CAP: u64 = 2;

        let world = LoopWorld::new("hang", &[]);
        let mut capped = (*embedded_roles()).clone();
        capped.defaults.await_result_max_sec = CAP;
        let capped = Arc::new(capped);

        let actor = start_actor(&world, Arc::clone(&capped), ActorOpts::default());
        let mut peer = Peer::connect_with(actor.handle.clone(), capped).await;

        let mut args = delegate_args();
        args["task"] = json!(loop_task("T42-cap"));
        let out = success(&peer.call("delegate", args).await).clone();
        let agent: AgentId = out["agentId"]
            .as_str()
            .expect("an agentId")
            .parse()
            .unwrap();

        wait_for_status(
            &actor.handle,
            StatusQuery {
                agent_id: Some(agent),
                ..StatusQuery::default()
            },
            "the worker is running and has produced an event",
            |status| !status.attempts.is_empty() && !status.events.is_empty(),
        )
        .await;

        let started = Instant::now();
        let id = peer
            .dispatch(
                "tools/call",
                json!({
                    "name": "await_result",
                    "arguments": { "agentId": agent.to_string(), "timeoutSec": 300 },
                }),
            )
            .await;
        let answer = peer
            .answer_within(
                id,
                REFUSED_LIMIT,
                "the door waited past defaults.awaitResultMaxSec",
            )
            .await;

        assert_eq!(success(&answer)["status"], json!("running"));
        assert!(
            started.elapsed() >= Duration::from_secs(CAP),
            "…after waiting the configured cap"
        );

        quiesce(&actor.handle).await;
        peer.close().await;
        actor.stop().await;
    });
}

/// An expired `await_result` answers `{status:"running", lastEvent}` rather than an error — and
/// the actor is **not blocked** while it waits: a second connection's `get_status` is answered
/// long before the wait expires.
#[test]
fn an_expired_await_result_answers_running_without_blocking_a_concurrent_get_status() {
    common::with_shared_env(|| async {
        /// The wait under test. Long enough that answering `get_status` "meanwhile" is a fact
        /// about the actor rather than about scheduling luck.
        const WAIT: u64 = 4;
        /// How long a projection may take while a waiter is parked. Two orders of magnitude more
        /// than a mailbox turn needs, and still a quarter of `WAIT`.
        const MEANWHILE: Duration = Duration::from_secs(1);

        let world = LoopWorld::new("hang", &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let mut waiting = Peer::connect(actor.handle.clone()).await;
        let mut watching = Peer::connect(actor.handle.clone()).await;

        let mut args = delegate_args();
        args["task"] = json!(loop_task("T42-await"));
        let out = success(&waiting.call("delegate", args).await).clone();
        let agent: AgentId = out["agentId"]
            .as_str()
            .expect("an agentId")
            .parse()
            .unwrap();

        wait_for_status(
            &actor.handle,
            StatusQuery {
                agent_id: Some(agent),
                ..StatusQuery::default()
            },
            "the worker is running and has produced an event",
            |status| !status.attempts.is_empty() && !status.events.is_empty(),
        )
        .await;

        let started = Instant::now();
        let parked = waiting
            .dispatch(
                "tools/call",
                json!({
                    "name": "await_result",
                    "arguments": { "agentId": agent.to_string(), "timeoutSec": WAIT },
                }),
            )
            .await;

        let meanwhile = tokio::time::timeout(
            MEANWHILE,
            watching.call("get_status", json!({ "agentId": agent.to_string() })),
        )
        .await
        .expect("the actor answered get_status while an await_result waiter was parked");
        assert_eq!(success(&meanwhile)["schemaVersion"], json!(1));
        assert!(
            started.elapsed() < Duration::from_secs(WAIT),
            "…and answered it before the wait even expired"
        );

        let answer = waiting.answer(parked).await;
        let out = success(&answer).clone();
        assert_eq!(
            out["status"],
            json!("running"),
            "an expired wait is not an error: {out}"
        );
        assert!(
            out["lastEvent"]["kind"].is_string(),
            "…and it carries the last event of the still-running attempt: {out}"
        );
        assert!(
            out.get("envelope").is_none(),
            "a running answer carries no envelope: {out}"
        );
        assert!(
            started.elapsed() >= Duration::from_secs(WAIT),
            "the door waited the full bound it was given"
        );

        quiesce(&actor.handle).await;
        waiting.close().await;
        watching.close().await;
        actor.stop().await;
    });
}
