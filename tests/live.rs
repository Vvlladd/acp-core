//! T45: deliberately opt-in probes against the real Claude and Codex CLIs.
//!
//! Nothing in this binary may spend a token unless both Cargo's `#[ignore]` gate and the explicit
//! `ACP_LIVE=1` gate are opened. The Codex-home fallback has a third gate because it bypasses the
//! production worker-env allowlist solely to test the isolated-home workaround named by V2.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_control_plane::core::registry::Registry;
use agent_control_plane::core::supervisor::{assert_safe_argv, spawn_detached, ArgvCtx};
use agent_control_plane::core::team::{self, Assignment, Effort, Team};
use agent_control_plane::core::types::{
    AgentId, AgentStatus, AttemptStatus, Event, EventPayload, GateId, GateKind, HandoffEnvelope,
    ProviderName, RoleName, RunId, RunStatus, SchemaName, Task, VerifyStatus,
};
use agent_control_plane::core::{
    AwaitOut, CoreError, CoreHandle, GateResolution, StatusOut, StatusQuery,
};
use agent_control_plane::ipc::socket::MAX_LINE_BYTES;
use agent_control_plane::providers::claude::ClaudeAdapter;
use agent_control_plane::providers::codex::CodexAdapter;
use agent_control_plane::providers::{
    find_on_path, NormalizedEvent, ProviderAdapter, RawResult, ResultCtx, SandboxSpec, SpawnPlan,
    SpawnRequest,
};
use agent_control_plane::roles::loader::{role_prompt, role_spec};
use nix::sys::signal::{kill, killpg, Signal};
use nix::unistd::Pid;
use serde_json::{json, Value};

use common::{
    cli_actor, delegate_builder, embedded_roles, head_sha, loop_task, pick, start_actor,
    temp_git_repo, temp_state_dir, ActorOpts, LoopWorld,
};

const LIVE_TIMEOUT: Duration = Duration::from_secs(180);
const LIVE_LOOP_TIMEOUT: Duration = Duration::from_secs(720);
const CODEX_HOME_FALLBACK_GATE: &str = "ACP_LIVE_CODEX_HOME_FALLBACK";

// T60 is one Haiku turn with no write tools. Both the run and spawn hard caps are set to this
// value in the external, hash-verified roles fixture given to the release daemon. The compile-time
// assertion prevents a future edit from silently crossing the approved <$0.50 manual-probe cap.
const LIVE_LEAD_BUDGET_USD: f64 = 0.40;
const _: () = assert!(LIVE_LEAD_BUDGET_USD < 0.50);

// The four Claude invocations have hard CLI caps totalling $0.24. Codex has no per-turn dollar
// flag, so its three one-turn prompts are intentionally PONG-sized/minimal-effort; the full loop's
// run budget is $0.20. This keeps the intended complete manual run below T45's $0.50 ceiling.
const CLAUDE_PONG_BUDGET_USD: f64 = 0.04;
const CLAUDE_SANDBOX_BUDGET_USD: f64 = 0.06;
const FULL_LOOP_BUILDER_BUDGET_USD: f64 = 0.10;

struct Capture {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    events: Vec<NormalizedEvent>,
    result: RawResult,
}

fn capture(
    adapter: &dyn ProviderAdapter,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    last_message: Option<String>,
) -> Capture {
    let events: Vec<NormalizedEvent> = stdout
        .lines()
        .flat_map(|line| adapter.parse_line(line))
        .collect();
    // Acceptance budget evidence only: no prompts, credentials, paths or raw provider output.
    for event in &events {
        if let NormalizedEvent::Usage { tokens, cost_usd } = event {
            eprintln!("ACP_LIVE_USAGE provider={:?} input={} cached={} output={} cost_usd={:?}",
                adapter.name(), tokens.input, tokens.cached_input, tokens.output, cost_usd);
        }
    }
    let result = adapter.extract_result(&ResultCtx {
        events: &events,
        exit_code,
        signal: None,
        last_message: last_message.as_deref(),
        stderr_head: Some(&stderr),
    });
    Capture {
        exit_code,
        stdout,
        stderr,
        events,
        result,
    }
}

/// Runs an adapter-built plan through the production argv chokepoint and detached spawn path.
async fn run_checked(
    adapter: &dyn ProviderAdapter,
    plan: SpawnPlan,
    attempt_dir: &Path,
    worktree: &Path,
    state_dir: &Path,
    sandboxed: bool,
) -> Capture {
    let prompt_index = adapter.prompt_index(&plan);
    let checked = assert_safe_argv(
        plan,
        &ArgvCtx {
            role: agent_control_plane::core::types::RoleName::Builder,
            lead_run_id: None,
            worktree,
            provider: adapter.name(),
            sandboxed,
            state_dir,
            prompt_index,
        },
    )
    .expect("the real adapter plan passes the production spawn chokepoint");
    let mut spawned = spawn_detached(checked, attempt_dir.to_path_buf())
        .await
        .expect("start the real provider CLI");
    let status = match tokio::time::timeout(LIVE_TIMEOUT, spawned.child.wait()).await {
        Ok(status) => status.expect("wait for the real provider CLI"),
        Err(_) => {
            let _ = killpg(Pid::from_raw(spawned.pgid), Signal::SIGKILL);
            let _ = spawned.child.wait().await;
            panic!("the real provider CLI exceeded {LIVE_TIMEOUT:?}");
        }
    };
    let stdout = std::fs::read_to_string(attempt_dir.join("stdout.jsonl"))
        .expect("read the real JSONL transcript");
    let stderr = std::fs::read_to_string(attempt_dir.join("stderr.log"))
        .expect("read the real provider stderr");
    let last_message = std::fs::read_to_string(attempt_dir.join("last-message.txt")).ok();
    capture(adapter, status.code(), stdout, stderr, last_message)
}

/// V2's explicitly gated workaround. It still uses the real Codex adapter's plan, clears the
/// child's environment, and writes only the adapter-declared files. It cannot use `CheckedPlan`:
/// production intentionally refuses `CODEX_HOME`, while this regression exists to test that one
/// extra test-only environment key against an isolated directory.
async fn run_with_isolated_codex_home(
    adapter: &CodexAdapter,
    plan: SpawnPlan,
    attempt_dir: &Path,
    codex_home: &Path,
) -> Capture {
    std::fs::create_dir_all(attempt_dir).expect("create isolated Codex attempt dir");
    for (path, body) in &plan.write_files {
        std::fs::create_dir_all(path.parent().expect("adapter file has a parent"))
            .expect("create adapter input parent");
        std::fs::write(path, body).expect("write adapter input");
    }
    let program = find_on_path("codex").expect("the real codex binary is on PATH");
    let mut command = tokio::process::Command::new(program);
    command
        .args(&plan.argv)
        .current_dir(&plan.cwd)
        .env_clear()
        .envs(&plan.env)
        .env("CODEX_HOME", codex_home)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(LIVE_TIMEOUT, command.output())
        .await
        .expect("isolated Codex exceeded the live timeout")
        .expect("run Codex with an isolated CODEX_HOME");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let last_message = std::fs::read_to_string(attempt_dir.join("last-message.txt")).ok();
    capture(adapter, output.status.code(), stdout, stderr, last_message)
}

fn assert_pong(capture: &Capture, provider: &str) {
    assert_eq!(
        capture.exit_code,
        Some(0),
        "{provider} failed: {}",
        capture.stderr
    );
    assert!(capture.result.ok, "{provider} did not report success");
    assert_eq!(
        capture
            .result
            .structured
            .as_ref()
            .and_then(|value| value.get("summary"))
            .and_then(Value::as_str),
        Some("PONG"),
        "{provider} did not return the schema-conformant PONG: {:?}",
        capture.result.structured
    );
}

fn session_id(capture: &Capture) -> String {
    capture
        .events
        .iter()
        .find_map(|event| match event {
            NormalizedEvent::Session { session_id } => Some(session_id.clone()),
            _ => None,
        })
        .expect("the real provider transcript names its resumable session")
}

fn claude_cache_creation_tokens(capture: &Capture) -> u64 {
    capture
        .stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|value| {
            (value.get("type").and_then(Value::as_str) == Some("result"))
                .then(|| {
                    value
                        .pointer("/usage/cache_creation_input_tokens")
                        .and_then(Value::as_u64)
                })
                .flatten()
        })
        .expect("Claude's terminal result reports cache_creation_input_tokens")
}

/// The V2 probe's answer. Codex JSONL describes only tools it actually calls, so checking item
/// kinds cannot reveal an exposed-but-unused MCP tool. The model is instead asked to inspect its
/// available tool names without invoking them and attest in its schema-bound result. Requiring the
/// same summary in the JSONL transcript prevents an unrelated/stale `-o` file from passing.
fn codex_v2_summary(capture: &Capture, turn: &str) -> String {
    assert_eq!(
        capture.exit_code,
        Some(0),
        "{turn} failed: {}",
        capture.stderr
    );
    assert!(capture.result.ok, "{turn} did not report success");
    let summary = capture
        .result
        .structured
        .as_ref()
        .and_then(|value| value.get("summary"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{turn} returned no schema-valid summary"));
    let transcript_summary = capture
        .stdout
        .lines()
        .filter_map(|line| {
            let value = serde_json::from_str::<Value>(line).ok()?;
            (value.get("type").and_then(Value::as_str) == Some("item.completed")
                && value.pointer("/item/type").and_then(Value::as_str) == Some("agent_message"))
            .then(|| {
                value
                    .pointer("/item/text")
                    .and_then(Value::as_str)
                    .and_then(|text| serde_json::from_str::<Value>(text).ok())
                    .and_then(|body| {
                        body.get("summary")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
            })
            .flatten()
        })
        .next_back();
    assert_eq!(
        transcript_summary.as_deref(),
        Some(summary),
        "{turn}'s structured summary did not match its final JSONL agent_message"
    );
    if summary == "PONG" {
        return summary.to_string();
    }
    let exposed = summary
        .strip_prefix("MCP_EXPOSED:")
        .unwrap_or_else(|| panic!("{turn} returned an unknown V2 summary: {summary:?}"));
    let names: Vec<&str> = exposed.split(',').filter(|name| !name.is_empty()).collect();
    assert!(
        !names.is_empty() && names.iter().all(|name| name.starts_with("mcp__")),
        "{turn} returned malformed exposed-tool evidence: {summary:?}"
    );
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(
        names, sorted,
        "{turn} did not sort MCP tool names deterministically"
    );
    summary.to_string()
}

async fn codex_pong_pair(codex_home: Option<&Path>) -> (Capture, Capture) {
    let adapter = CodexAdapter;
    let roles = embedded_roles();
    let role = role_spec(&roles, RoleName::Reviewer).expect("embedded reviewer role");
    let schema = common::checked_in_schema(SchemaName::BuildResult);
    let state = temp_state_dir();
    let repo = temp_git_repo();
    let fresh_dir = state.path().join("codex-pong-fresh");
    let prompt = "Inspect the names of tools available to you without invoking any tool. If none starts with mcp__, return exactly {\"status\":\"succeeded\",\"filesChanged\":[],\"summary\":\"PONG\"}. If any starts with mcp__, sort those exact names lexicographically and return the same JSON except summary must be MCP_EXPOSED:<comma-separated names>. Return JSON only.";
    let fresh_req = SpawnRequest {
        role,
        model: "gpt-5.5",
        prompt,
        role_prompt:
            "Inspect available tool names without invoking them and return only the requested JSON.",
        cwd: repo.path(),
        attempt_dir: &fresh_dir,
        state_dir: state.path(),
        lead_run_id: None,
        schema: ("build-result", &schema),
        max_turns: 1,
        spawn_budget_usd: 0.0,
        sandbox: None,
        session_id: None,
        // Low, not Minimal: since 2026-08-26 the platform enables web_search/image_gen by default
        // and rejects reasoning effort `minimal` alongside them (400 invalid_request_error), so
        // `minimal` is no longer advertised anywhere (roles.json, the app fallback).
        effort: Some(Effort::Low),
    };
    assert!(adapter.preflight(&fresh_req).is_none(), "Codex preflight");
    let fresh_plan = adapter.build_fresh(&fresh_req);
    let fresh = match codex_home {
        Some(home) => run_with_isolated_codex_home(&adapter, fresh_plan, &fresh_dir, home).await,
        None => {
            run_checked(
                &adapter,
                fresh_plan,
                &fresh_dir,
                repo.path(),
                state.path(),
                false,
            )
            .await
        }
    };
    let thread = session_id(&fresh);
    let resume_dir = state.path().join("codex-pong-resume");
    let resume_req = SpawnRequest {
        attempt_dir: &resume_dir,
        session_id: Some(&thread),
        effort: None,
        ..fresh_req
    };
    let resume_plan = adapter.build_resume(&resume_req);
    let resume = match codex_home {
        Some(home) => run_with_isolated_codex_home(&adapter, resume_plan, &resume_dir, home).await,
        None => {
            run_checked(
                &adapter,
                resume_plan,
                &resume_dir,
                repo.path(),
                state.path(),
                false,
            )
            .await
        }
    };
    assert_eq!(session_id(&resume), thread, "resume stayed on one thread");
    (fresh, resume)
}

async fn live_await_done(handle: &CoreHandle, agent: AgentId) -> Box<HandoffEnvelope> {
    let deadline = Instant::now() + LIVE_TIMEOUT;
    loop {
        match handle.await_result(agent, Duration::from_secs(1)).await {
            Ok(AwaitOut::Done { envelope }) => return envelope,
            Ok(AwaitOut::Running { .. }) | Err(CoreError::Policy(_)) => {}
            Err(err) => panic!("live await_result on {agent}: {err}"),
        }
        assert!(
            Instant::now() < deadline,
            "live agent {agent} did not finish within {LIVE_TIMEOUT:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn live_wait_for_log(
    world: &LoopWorld,
    run: &RunId,
    what: &str,
    mut predicate: impl FnMut(&[Arc<agent_control_plane::core::types::Event>]) -> bool,
) -> Vec<Arc<agent_control_plane::core::types::Event>> {
    let deadline = Instant::now() + LIVE_TIMEOUT;
    loop {
        let events = world.events(run);
        if predicate(&events) {
            return events;
        }
        if Instant::now() >= deadline {
            // A live timeout with no evidence is a misdiagnosis magnet (T65's lesson): dump
            // what the durable log actually says before dying, so the human reads the run,
            // not the deadline.
            let kinds: Vec<String> = events
                .iter()
                .filter_map(|e| serde_json::to_value(&e.payload).ok())
                .map(|v| {
                    let kind = v["kind"].as_str().unwrap_or("?").to_string();
                    match v.get("reason").and_then(|r| r.as_str()) {
                        Some(reason) => format!("{kind}({reason})"),
                        None => kind,
                    }
                })
                .collect();
            let errors: Vec<String> = events
                .iter()
                .filter_map(|e| serde_json::to_value(&e.payload).ok())
                .filter_map(|v| {
                    v.get("error")
                        .and_then(|err| err.get("message"))
                        .and_then(|m| m.as_str())
                        .map(str::to_string)
                })
                .collect();
            // The worker's final messages are the evidence schema_invalid hides: read each
            // recorded result file while the state TempDir is still alive.
            let results: Vec<String> = events
                .iter()
                .filter_map(|e| serde_json::to_value(&e.payload).ok())
                .filter_map(|v| {
                    v.get("resultPath")
                        .and_then(|p| p.as_str())
                        .map(str::to_string)
                })
                .map(|path| {
                    let text = std::fs::read_to_string(&path)
                        .unwrap_or_else(|err| format!("<unreadable: {err}>"));
                    let head: String = text.chars().take(1500).collect();
                    format!("--- {path} ---\n{head}")
                })
                .collect();
            panic!(
                "{what} did not happen within {LIVE_TIMEOUT:?}\nevent kinds so far: {kinds:?}\nattempt errors so far: {errors:?}\nresult files:\n{}",
                results.join("\n")
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn live_wait_for_status(
    handle: &CoreHandle,
    query: StatusQuery,
    what: &str,
    mut predicate: impl FnMut(&StatusOut) -> bool,
) -> StatusOut {
    let deadline = Instant::now() + LIVE_TIMEOUT;
    loop {
        let status = handle
            .status(query.clone())
            .await
            .unwrap_or_else(|err| panic!("get_status while waiting for {what}: {err}"));
        if predicate(&status) {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "{what} did not happen within {LIVE_TIMEOUT:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Best-effort is not enough for real-token tests: do not return until two consecutive snapshots
/// show neither a running worker nor a spawn still in flight. It returns an error instead of
/// panicking so `actor.stop()` is unconditionally reached by the caller.
async fn live_quiesce(handle: &CoreHandle) -> Result<(), String> {
    let deadline = Instant::now() + LIVE_TIMEOUT;
    let mut quiet = 0;
    while Instant::now() < deadline {
        let status = handle
            .status(StatusQuery::default())
            .await
            .map_err(|err| format!("could not inspect workers during cleanup: {err}"))?;
        let live: Vec<AgentId> = status
            .attempts
            .iter()
            .filter(|attempt| attempt.status == AttemptStatus::Running)
            .map(|attempt| attempt.agent_id)
            .collect();
        let starting = status.agents.iter().any(|agent| {
            !status
                .attempts
                .iter()
                .any(|attempt| attempt.agent_id == agent.agent_id)
                && !matches!(
                    agent.process_state,
                    AgentStatus::Closed | AgentStatus::Cancelled
                )
                && status
                    .runs
                    .iter()
                    .any(|run| run.run_id == agent.run_id && run.status == RunStatus::Running)
        });
        if live.is_empty() && !starting {
            quiet += 1;
            if quiet == 2 {
                return Ok(());
            }
        } else {
            quiet = 0;
            for agent in live {
                let _ = tokio::time::timeout(Duration::from_secs(5), handle.cancel(agent)).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "real workers did not quiesce within {LIVE_TIMEOUT:?}"
    ))
}

/// One bounded socket peer for T60's release-daemon probe. It is deliberately local to the live
/// harness: the production socket client remains the app/CLI code, while this peer observes the
/// same human-only `lead.start` door without introducing another shipped client.
struct LiveLeadWire {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: i64,
}

impl LiveLeadWire {
    fn try_connect(path: &Path) -> Option<Self> {
        let stream = UnixStream::connect(path).ok()?;
        stream.set_read_timeout(Some(LIVE_TIMEOUT)).ok()?;
        stream.set_write_timeout(Some(LIVE_TIMEOUT)).ok()?;
        let reader = BufReader::new(stream.try_clone().ok()?);
        let mut wire = Self {
            reader,
            writer: stream,
            next_id: 1,
        };
        let hello = wire
            .call("hello", json!({ "clientName": "live-lead-probe" }))
            .ok()?;
        (hello["protocolVersion"] == json!(1)).then_some(wire)
    }

    fn connect(path: &Path) -> Self {
        Self::try_connect(path)
            .unwrap_or_else(|| panic!("connect live lead probe to {}", path.display()))
    }

    fn call(&mut self, method: &str, params: Value) -> Result<Value, Value> {
        let id = self.next_id;
        self.next_id += 1;
        writeln!(
            self.writer,
            "{}",
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
        )
        .expect("write live socket request");
        loop {
            let frame = self.read_frame(id);
            if frame.get("id").and_then(Value::as_i64) != Some(id) {
                continue;
            }
            return match frame.get("error") {
                Some(error) => Err(error.clone()),
                None => Ok(frame.get("result").cloned().unwrap_or(Value::Null)),
            };
        }
    }

    /// Read one production-sized NDJSON frame without letting an unterminated peer response grow
    /// a test allocation past the socket contract's one-MiB ceiling.
    fn read_frame(&mut self, id: i64) -> Value {
        let mut line = Vec::new();
        loop {
            let available = self.reader.fill_buf().expect("read live socket response");
            assert!(
                !available.is_empty(),
                "live socket closed before response id {id}"
            );
            if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
                assert!(
                    line.len() + newline <= MAX_LINE_BYTES,
                    "live socket response exceeded {MAX_LINE_BYTES} bytes"
                );
                line.extend_from_slice(&available[..newline]);
                self.reader.consume(newline + 1);
                break;
            }
            assert!(
                line.len() + available.len() <= MAX_LINE_BYTES,
                "live socket response exceeded {MAX_LINE_BYTES} bytes"
            );
            let consumed = available.len();
            line.extend_from_slice(available);
            self.reader.consume(consumed);
        }
        serde_json::from_slice(&line).expect("live socket response JSON")
    }
}

/// The provider transcript is daemon-owned evidence the normalized event stream intentionally
/// drops: match the one MCP tool-use id to a non-error tool-result rather than trusting prose.
fn live_get_status_evidence(stdout: &str) -> (usize, usize) {
    let frames: Vec<Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("live Claude transcript JSON"))
        .collect();
    let tool_ids: Vec<&str> = frames
        .iter()
        .filter(|frame| frame.get("type") == Some(&json!("assistant")))
        .filter_map(|frame| frame.pointer("/message/content").and_then(Value::as_array))
        .flatten()
        .filter(|block| {
            block.get("type") == Some(&json!("tool_use"))
                && block.get("name") == Some(&json!("mcp__acp__get_status"))
        })
        .filter_map(|block| block.get("id").and_then(Value::as_str))
        .collect();
    let successful_results = frames
        .iter()
        .filter(|frame| frame.get("type") == Some(&json!("user")))
        .filter_map(|frame| frame.pointer("/message/content").and_then(Value::as_array))
        .flatten()
        .filter(|block| {
            block.get("type") == Some(&json!("tool_result"))
                && block.get("is_error").and_then(Value::as_bool) != Some(true)
                && block
                    .get("tool_use_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| tool_ids.contains(&id))
        })
        .count();
    (tool_ids.len(), successful_results)
}

/// Copy the pinned production role set, changing only the caps that make the manual T60 call
/// cheaper than $0.50. Prompt bodies and hashes remain byte-for-byte production artifacts.
fn live_lead_roles(state: &Path) -> PathBuf {
    fn copy_tree(source: &Path, destination: &Path) {
        std::fs::create_dir_all(destination).expect("create live roles directory");
        for entry in std::fs::read_dir(source).expect("read production roles") {
            let entry = entry.expect("production role entry");
            let target = destination.join(entry.file_name());
            if entry.path().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).expect("copy production role artifact");
            }
        }
    }

    let destination = state.join("live-lead-roles");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("roles"),
        &destination,
    );
    let config = destination.join("roles.json");
    let mut roles: Value =
        serde_json::from_slice(&std::fs::read(&config).expect("read copied live lead roles"))
            .expect("parse copied live lead roles");
    roles["defaults"]["runBudgetUsd"] = json!(LIVE_LEAD_BUDGET_USD);
    roles["defaults"]["spawnBudgetUsd"] = json!(LIVE_LEAD_BUDGET_USD);
    roles["defaults"]["attemptTimeoutSec"] = json!(LIVE_TIMEOUT.as_secs());
    roles["roles"]["lead"]["spawnBudgetUsd"] = json!(LIVE_LEAD_BUDGET_USD);
    roles["roles"]["lead"]["maxTurns"] = json!(8);
    std::fs::write(
        &config,
        serde_json::to_vec_pretty(&roles).expect("encode live lead roles"),
    )
    .expect("write live lead roles");
    config
}

struct LiveLeadDaemon {
    child: Child,
    state: PathBuf,
    reaped: bool,
}

impl LiveLeadDaemon {
    fn start(state: &Path, repo: &Path, roles: &Path) -> Self {
        let binary = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/release/acp");
        assert!(
            binary.is_file(),
            "build the release binary before running the T60 manual probe: {}",
            binary.display()
        );
        std::fs::write(repo.join(".git/info/exclude"), ".acp/\n")
            .expect("exclude live daemon worktrees");
        let stdout =
            std::fs::File::create(state.join("serve.stdout")).expect("create live daemon stdout");
        let stderr =
            std::fs::File::create(state.join("serve.stderr")).expect("create live daemon stderr");
        let child = Command::new(binary)
            .arg("--repo")
            .arg(repo)
            .args(["serve", "--no-mcp"])
            .env("ACP_STATE_DIR", state)
            .env("ACP_ROLES_FILE", roles)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn release acp serve --no-mcp");
        let mut daemon = Self {
            child,
            state: state.to_path_buf(),
            reaped: false,
        };
        let deadline = Instant::now() + LIVE_TIMEOUT;
        loop {
            if let Some(status) = daemon.child.try_wait().expect("probe live daemon") {
                daemon.reaped = true;
                panic!(
                    "live daemon exited {status}: {}",
                    std::fs::read_to_string(state.join("serve.stderr")).unwrap_or_default()
                );
            }
            if LiveLeadWire::try_connect(&daemon.socket()).is_some() {
                return daemon;
            }
            assert!(
                Instant::now() < deadline,
                "release daemon did not bind: {}",
                std::fs::read_to_string(state.join("serve.stderr")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn socket(&self) -> PathBuf {
        self.state.join("acp.sock")
    }

    fn stop(&mut self) -> Result<(), String> {
        if self
            .child
            .try_wait()
            .map_err(|err| format!("probe live daemon before stop: {err}"))?
            .is_some()
        {
            self.reaped = true;
            return Ok(());
        }
        let pid = i32::try_from(self.child.id())
            .map_err(|err| format!("live daemon pid did not fit i32: {err}"))?;
        kill(Pid::from_raw(pid), Signal::SIGTERM)
            .map_err(|err| format!("signal live daemon {pid}: {err}"))?;
        let deadline = Instant::now() + LIVE_TIMEOUT;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    self.reaped = true;
                    return Ok(());
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Ok(None) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    self.reaped = true;
                    return Err("release daemon did not stop before the live timeout".into());
                }
                Err(err) => return Err(format!("wait for live daemon: {err}")),
            }
        }
    }
}

impl Drop for LiveLeadDaemon {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Socket analogue of `live_quiesce`: cancel every live/pending lead and require two quiet
/// snapshots. It returns errors so the release daemon can be stopped before failures are surfaced.
fn live_lead_quiesce(socket: &Path) -> Result<(), String> {
    let mut wire = LiveLeadWire::try_connect(socket)
        .ok_or_else(|| format!("could not connect to {} for cleanup", socket.display()))?;
    let deadline = Instant::now() + LIVE_TIMEOUT;
    let mut quiet = 0;
    while Instant::now() < deadline {
        let status = wire
            .call("get_status", json!({}))
            .map_err(|error| format!("get_status during live lead cleanup: {error}"))?;
        let mut live_agents: BTreeSet<String> = status["attempts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|attempt| attempt["status"] == json!("running"))
            .filter_map(|attempt| attempt["agentId"].as_str().map(str::to_string))
            .collect();
        live_agents.extend(
            status["agents"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|agent| {
                    matches!(agent["processState"].as_str(), Some("starting" | "running"))
                })
                .filter_map(|agent| agent["agentId"].as_str().map(str::to_string)),
        );
        if live_agents.is_empty() {
            quiet += 1;
            if quiet == 2 {
                return Ok(());
            }
        } else {
            quiet = 0;
            for agent in live_agents {
                let _ = wire.call("cancel", json!({ "agentId": agent }));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!("live lead did not quiesce within {LIVE_TIMEOUT:?}"))
}

fn current_codex_home() -> PathBuf {
    std::env::var_os("CODEX_HOME").map_or_else(
        || PathBuf::from(std::env::var_os("HOME").expect("HOME is set")).join(".codex"),
        PathBuf::from,
    )
}

fn home_probe_names(home: &Path) -> BTreeSet<String> {
    std::fs::read_dir(home)
        .expect("read HOME for the sandbox probe")
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with("acp-probe-"))
        .collect()
}

fn is_sha40(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn commit_message(repo: &Path, sha: &str) -> String {
    let output = std::process::Command::new("git")
        .args(["show", "-s", "--format=%B", sha])
        .current_dir(repo)
        .output()
        .expect("read the integrated commit message");
    assert!(output.status.success(), "git show failed");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

async fn exercise_live_full_loop(world: Arc<LoopWorld>, handle: CoreHandle, base_sha: String) {
    let delegated = handle
        .delegate(delegate_builder(loop_task("T45-live-full-loop")))
        .await
        .expect("delegate the real builder");
    assert_eq!(delegated.status, RunStatus::Running);
    let builder = live_await_done(&handle, delegated.agent_id).await;
    assert_eq!(builder.status, AttemptStatus::Succeeded, "{builder:?}");

    let events = live_wait_for_log(&world, &delegated.run_id, "real integrate gate", |events| {
        events.iter().any(|event| {
            matches!(
                event.payload,
                EventPayload::GateCreated {
                    gate_kind: GateKind::Integrate,
                    ..
                }
            )
        })
    })
    .await;
    let gates: Vec<GateId> = pick(&events, |payload| match payload {
        EventPayload::GateCreated {
            gate_id,
            gate_kind: GateKind::Integrate,
            ..
        } => Some(*gate_id),
        _ => None,
    });
    assert_eq!(gates.len(), 1, "one real integrate gate");
    let gate = gates[0];
    let resolution = handle
        .resolve_gate(gate, true, None, cli_actor())
        .await
        .expect("approve through the human socket actor");
    let GateResolution::Approved { sha: Some(sha) } = resolution else {
        panic!("live gate resolved as {resolution:?}");
    };
    assert!(is_sha40(&sha), "integration returned an invalid sha: {sha}");
    assert_ne!(sha, base_sha, "integration did not make a commit");
    assert!(
        commit_message(&delegated.worktree, &sha).contains(&format!("Acp-Gate-Id: {gate}")),
        "the real commit is not bound to its gate"
    );
    let status = live_wait_for_status(
        &handle,
        StatusQuery {
            run_id: Some(delegated.run_id),
            ..StatusQuery::default()
        },
        "real run integrated",
        |status| {
            status
                .runs
                .first()
                .is_some_and(|run| run.status == RunStatus::Integrated)
        },
    )
    .await;
    assert_eq!(status.runs[0].integrated_sha.as_deref(), Some(sha.as_str()));
}

#[test]
#[ignore = "spends real Claude tokens (<$0.50); run manually with ACP_LIVE=1"]
fn live_lead_start() {
    if std::env::var("ACP_LIVE") != Ok("1".into()) {
        eprintln!("skipping live_lead_start: set ACP_LIVE=1 explicitly");
        return;
    }
    common::with_shared_env(|| async {
        let state = tempfile::Builder::new()
            .prefix("acp-live-lead-")
            .rand_bytes(5)
            .tempdir_in("/tmp")
            .expect("short live lead state dir");
        let repo = temp_git_repo();
        let roles = live_lead_roles(state.path());
        let mut daemon = LiveLeadDaemon::start(state.path(), repo.path(), &roles);
        let socket = daemon.socket();
        let exercise_state = state.path().to_path_buf();
        let exercise_socket = socket.clone();
        let mut exercise = tokio::spawn(async move {
            let started = tokio::task::spawn_blocking(move || {
                LiveLeadWire::connect(&exercise_socket)
                    .call(
                        "lead.start",
                        json!({
                            "message": "Call the acp get_status tool exactly once. Only if it succeeds, answer exactly DONE; otherwise answer exactly ERROR."
                        }),
                    )
                    .expect("start the real Haiku lead through the socket-only method")
            })
            .await
            .expect("join live lead.start socket call");
            let run: RunId = started["runId"]
                .as_str()
                .expect("live lead run id")
                .parse()
                .expect("live lead run UUID");

            let deadline = Instant::now() + LIVE_TIMEOUT;
            let (events, stdout_path) = loop {
                let registry = Registry::open(&exercise_state).expect("replay live lead event log");
                let events = registry.events(&run, None, usize::MAX);
                if events
                    .iter()
                    .any(|event| matches!(event.payload, EventPayload::AttemptFinished { .. }))
                {
                    let attempt = registry
                        .state()
                        .attempts
                        .values()
                        .find(|attempt| attempt.run_id == run)
                        .expect("live lead attempt in daemon projection");
                    break (events, attempt.dir.join("stdout.jsonl"));
                }
                assert!(
                    Instant::now() < deadline,
                    "real Haiku lead did not finish within {LIVE_TIMEOUT:?}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            };

            let transcript = std::fs::read_to_string(&stdout_path)
                .expect("read daemon-owned live lead transcript");
            // Every claim below fails with the full run in hand (T65's lesson, relearned when this
            // probe's first live failure evaporated with the TempDir): the event kinds, the
            // transcript, and the daemon's own stderr/log — gathered while the state dir is alive.
            let dump = || {
                let kinds: Vec<String> = events
                    .iter()
                    .filter_map(|e| serde_json::to_value(&e.payload).ok())
                    .map(|v| {
                        let kind = v["kind"].as_str().unwrap_or("?").to_string();
                        match v.get("reason").and_then(|r| r.as_str()) {
                            Some(reason) => format!("{kind}({reason})"),
                            None => kind,
                        }
                    })
                    .collect();
                let errors: Vec<String> = events
                    .iter()
                    .filter_map(|e| serde_json::to_value(&e.payload).ok())
                    .filter_map(|v| {
                        v.get("error")
                            .and_then(|err| err.get("message"))
                            .and_then(|m| m.as_str())
                            .map(str::to_string)
                    })
                    .collect();
                let head: String = transcript.chars().take(4000).collect();
                let tail = |name: &str| {
                    let text = std::fs::read_to_string(exercise_state.join(name))
                        .unwrap_or_else(|err| format!("<unreadable: {err}>"));
                    let skip = text.chars().count().saturating_sub(2000);
                    text.chars().skip(skip).collect::<String>()
                };
                format!(
                    "event kinds: {kinds:?}\nattempt errors: {errors:?}\ntranscript head:\n{head}\nserve.stderr tail:\n{}\nacp.log tail:\n{}",
                    tail("serve.stderr"),
                    tail("acp.log"),
                )
            };
            assert_eq!(
                live_get_status_evidence(&transcript),
                (1, 1),
                "the daemon-owned transcript must match one get_status tool-use id to one successful tool-result\n{}",
                dump()
            );
            assert!(
                events.iter().any(|event| {
                    matches!(
                        &event.payload,
                        EventPayload::AgentMessage { text, .. } if text.trim() == "DONE"
                    )
                }),
                "no agent.message proved get_status succeeded before the DONE answer\n{}",
                dump()
            );
            assert!(
                events
                    .iter()
                    .any(|event| { matches!(event.payload, EventPayload::AttemptResult { .. }) }),
                "the lead result was not durable\n{}",
                dump()
            );
            assert!(
                events.iter().any(|event| {
                    matches!(
                        event.payload,
                        EventPayload::AttemptFinished {
                            status: AttemptStatus::Succeeded,
                            ..
                        }
                    )
                }),
                "the real lead did not finish successfully\n{}",
                dump()
            );
        });
        let outcome =
            match tokio::time::timeout(LIVE_TIMEOUT + Duration::from_secs(30), &mut exercise).await
            {
                Ok(result) => Some(result),
                Err(_) => {
                    exercise.abort();
                    let _ = exercise.await;
                    None
                }
            };

        // Cleanup is unconditional and precedes every propagated exercise failure, matching the
        // real-provider harness discipline used by the full loop probe.
        let cleanup_socket = socket.clone();
        let cleanup = tokio::task::spawn_blocking(move || live_lead_quiesce(&cleanup_socket))
            .await
            .map_err(|err| format!("join live lead cleanup: {err}"))
            .and_then(|result| result);
        let stop = daemon.stop();
        if let Err(err) = cleanup {
            panic!("live-lead cleanup failed after the exercise: {err}");
        }
        if let Err(err) = stop {
            panic!("live-lead daemon stop failed after the exercise: {err}");
        }
        match outcome {
            Some(Ok(())) => {}
            Some(Err(join_error)) if join_error.is_panic() => {
                std::panic::resume_unwind(join_error.into_panic());
            }
            Some(Err(join_error)) => panic!("live-lead exercise was cancelled: {join_error}"),
            None => panic!("live-lead exercise exceeded {LIVE_TIMEOUT:?}"),
        }
    });
}

#[test]
#[ignore = "spends real Claude tokens; run manually with ACP_LIVE=1"]
fn live_claude_pong_and_resume() {
    if std::env::var("ACP_LIVE") != Ok("1".into()) {
        eprintln!("skipping live_claude_pong_and_resume: set ACP_LIVE=1 explicitly");
        return;
    }
    common::with_shared_env(|| async {
        let adapter = ClaudeAdapter;
        let roles = embedded_roles();
        let role = role_spec(&roles, RoleName::Builder).expect("embedded builder role");
        let role_body = role_prompt(&roles, RoleName::Builder).expect("pinned builder prompt");
        let schema = common::checked_in_schema(SchemaName::BuildResult);
        assert!(
            schema.get("$schema").is_none(),
            "V7 artifact is post-processed"
        );
        let state = temp_state_dir();
        let repo = temp_git_repo();
        let fresh_dir = state.path().join("claude-pong-fresh");
        let prompt = "Do not call tools. Return exactly {\"status\":\"succeeded\",\"filesChanged\":[],\"summary\":\"PONG\"}.";
        let fresh_req = SpawnRequest {
            role,
            model: "haiku",
            prompt,
            role_prompt: role_body,
            cwd: repo.path(),
            attempt_dir: &fresh_dir,
            state_dir: state.path(),
            lead_run_id: None,
            schema: ("build-result", &schema),
            max_turns: 2,
            spawn_budget_usd: CLAUDE_PONG_BUDGET_USD,
            sandbox: Some(SandboxSpec {
                worktree: repo.path(),
            }),
            session_id: None,
            effort: None,
        };
        assert!(adapter.preflight(&fresh_req).is_none(), "Claude preflight");
        let fresh = run_checked(
            &adapter,
            adapter.build_fresh(&fresh_req),
            &fresh_dir,
            repo.path(),
            state.path(),
            true,
        )
        .await;
        assert_pong(&fresh, "Claude fresh (--json-schema accepted)");
        assert!(
            claude_cache_creation_tokens(&fresh) < 10_000,
            "fresh Claude call rebuilt too much context"
        );

        let session = session_id(&fresh);
        let resume_dir = state.path().join("claude-pong-resume");
        let resume_req = SpawnRequest {
            attempt_dir: &resume_dir,
            session_id: Some(&session),
            ..fresh_req
        };
        let resume = run_checked(
            &adapter,
            adapter.build_resume(&resume_req),
            &resume_dir,
            repo.path(),
            state.path(),
            true,
        )
        .await;
        assert_pong(&resume, "Claude resume (--json-schema accepted)");
        assert_eq!(session_id(&resume), session, "resume stayed on one session");
        assert!(
            claude_cache_creation_tokens(&resume) < 10_000,
            "resumed Claude call rebuilt too much context"
        );
    });
}

#[test]
#[ignore = "spends real Claude tokens; run manually with ACP_LIVE=1"]
fn live_sandbox_regression() {
    if std::env::var("ACP_LIVE") != Ok("1".into()) {
        eprintln!("skipping live_sandbox_regression: set ACP_LIVE=1 explicitly");
        return;
    }
    common::with_shared_env(|| async {
        let adapter = ClaudeAdapter;
        let roles = embedded_roles();
        let role = role_spec(&roles, RoleName::Builder).expect("embedded builder role");
        let role_body = role_prompt(&roles, RoleName::Builder).expect("pinned builder prompt");
        let schema = common::checked_in_schema(SchemaName::BuildResult);
        let state = temp_state_dir();
        let repo = temp_git_repo();
        let attempt_dir = state.path().join("claude-sandbox");
        let home = PathBuf::from(std::env::var_os("HOME").expect("HOME is set"));
        let before = home_probe_names(&home);
        let prompt = "Run one Bash command that does exactly this: probe=~/acp-probe-$$; touch \"$probe\" 2>&1; home_status=$?; if [ \"$home_status\" -eq 0 ]; then rm -f \"$probe\"; fi; touch ./ok-probe; local_status=$?; printf 'HOME_STATUS=%s LOCAL_STATUS=%s\\n' \"$home_status\" \"$local_status\". Then return JSON with status succeeded, filesChanged [\"ok-probe\"], and a short summary.";
        let req = SpawnRequest {
            role,
            model: "haiku",
            prompt,
            role_prompt: role_body,
            cwd: repo.path(),
            attempt_dir: &attempt_dir,
            state_dir: state.path(),
            lead_run_id: None,
            schema: ("build-result", &schema),
            max_turns: 4,
            spawn_budget_usd: CLAUDE_SANDBOX_BUDGET_USD,
            sandbox: Some(SandboxSpec {
                worktree: repo.path(),
            }),
            session_id: None,
            effort: None,
        };
        let captured = run_checked(
            &adapter,
            adapter.build_fresh(&req),
            &attempt_dir,
            repo.path(),
            state.path(),
            true,
        )
        .await;
        assert_eq!(
            captured.exit_code,
            Some(0),
            "Claude failed: {}",
            captured.stderr
        );
        assert!(
            captured.result.ok,
            "Claude did not finish the sandbox probe"
        );
        assert!(
            captured.stdout.contains("Operation not permitted"),
            "the denied HOME touch was not visible in the transcript: {}",
            captured.stdout
        );
        assert!(
            repo.path().join("ok-probe").is_file(),
            "the local touch failed"
        );
        assert_eq!(
            home_probe_names(&home),
            before,
            "the denied ~/acp-probe-$$ touch left a file behind"
        );
    });
}

#[test]
#[ignore = "spends real Codex tokens; run manually with ACP_LIVE=1"]
fn live_codex_pong_and_resume() {
    if std::env::var("ACP_LIVE") != Ok("1".into()) {
        eprintln!("skipping live_codex_pong_and_resume: set ACP_LIVE=1 explicitly");
        return;
    }
    common::with_shared_env(|| async {
        let (fresh, resume) = codex_pong_pair(None).await;
        let fresh_summary = codex_v2_summary(&fresh, "Codex fresh");
        let resume_summary = codex_v2_summary(&resume, "Codex resume");
        if fresh_summary == "PONG" && resume_summary == "PONG" {
            return;
        }
        assert_eq!(
            std::env::var(CODEX_HOME_FALLBACK_GATE),
            Ok("1".into()),
            "Codex exposed MCP tools. Re-run with ACP_LIVE=1 {CODEX_HOME_FALLBACK_GATE}=1 to exercise the isolated-home fallback"
        );
        let source_auth = current_codex_home().join("auth.json");
        assert!(
            source_auth.is_file(),
            "no Codex auth file at {}",
            source_auth.display()
        );
        let isolated = tempfile::tempdir().expect("isolated CODEX_HOME");
        symlink(&source_auth, isolated.path().join("auth.json")).expect("symlink Codex auth.json");
        let (fresh, resume) = codex_pong_pair(Some(isolated.path())).await;
        assert_eq!(codex_v2_summary(&fresh, "isolated Codex fresh"), "PONG");
        assert_eq!(codex_v2_summary(&resume, "isolated Codex resume"), "PONG");
    });
}

#[test]
#[ignore = "spends real Claude and Codex tokens; run manually with ACP_LIVE=1"]
fn live_full_loop() {
    if std::env::var("ACP_LIVE") != Ok("1".into()) {
        eprintln!("skipping live_full_loop: set ACP_LIVE=1 explicitly");
        return;
    }
    common::with_shared_env(|| async {
        let world = Arc::new(LoopWorld {
            state: temp_state_dir(),
            repo: temp_git_repo(),
        });
        let mut roles = (*embedded_roles()).clone();
        // This probe is the ACCEPTED Phase-1 loop, byte-for-byte: builder → reviewer → gate.
        // B1's verify step has its own probe (`live_verifier`); running a third real agent here
        // would silently change what Phase-1 acceptance measured and its budget.
        roles.roles.remove(&RoleName::Verifier);
        roles.defaults.run_budget_usd = 0.20;
        roles.defaults.spawn_budget_usd = 0.10;
        roles.defaults.attempt_timeout_sec = LIVE_TIMEOUT.as_secs();
        let builder = roles
            .roles
            .get_mut(&RoleName::Builder)
            .expect("builder role");
        builder.default_model = "haiku".into();
        // 16, not 8: the real haiku takes 6-19 turns for this task depending on how much it
        // explores; 8 made MaxTurns a coin flip (observed live, 2026-08-27). The spawn budget is
        // still the hard cap.
        builder.max_turns = 16;
        builder.spawn_budget_usd = FULL_LOOP_BUILDER_BUDGET_USD;
        let reviewer = roles
            .roles
            .get_mut(&RoleName::Reviewer)
            .expect("reviewer role");
        reviewer.default_model = "gpt-5.5".into();
        reviewer.max_turns = 4;
        reviewer.spawn_budget_usd = 0.10;
        let team = Team {
            mode: None,
            version: 1,
            name: "t45-live-minimal".into(),
            lead: None,
            roles: BTreeMap::from([
                (
                    "builder".into(),
                    Assignment {
                        provider: ProviderName::Claude,
                        model: "haiku".into(),
                        effort: None,
                    },
                ),
                (
                    "reviewer".into(),
                    Assignment {
                        provider: ProviderName::Codex,
                        model: "gpt-5.5".into(),
                        // Low, not Minimal: since 2026-08-26 the platform enables web_search/image_gen by default
                        // and rejects reasoning effort `minimal` alongside them (400 invalid_request_error), so
                        // `minimal` is no longer advertised anywhere (roles.json, the app fallback).
                        effort: Some(Effort::Low),
                    },
                ),
            ]),
        };
        team::validate_team(&roles, &team).expect("the minimal live team is valid");
        team::save_team(world.state_dir(), &team).expect("write live team.json");

        let base_sha = head_sha(world.repo_root());
        let actor = start_actor(&world, Arc::new(roles), ActorOpts::default());
        let handle = actor.handle.clone();
        let task_world = Arc::clone(&world);
        let task_handle = handle.clone();
        let mut exercise = tokio::spawn(async move {
            exercise_live_full_loop(task_world, task_handle, base_sha).await;
        });
        let outcome = match tokio::time::timeout(LIVE_LOOP_TIMEOUT, &mut exercise).await {
            Ok(result) => Some(result),
            Err(_) => {
                exercise.abort();
                let _ = exercise.await;
                None
            }
        };

        let cleanup = live_quiesce(&handle).await;
        actor.stop().await;
        if let Err(err) = cleanup {
            panic!("live-loop cleanup failed after the exercise: {err}");
        }
        match outcome {
            Some(Ok(())) => {}
            Some(Err(join_error)) if join_error.is_panic() => {
                std::panic::resume_unwind(join_error.into_panic());
            }
            Some(Err(join_error)) => panic!("live-loop exercise was cancelled: {join_error}"),
            None => panic!("live-loop exercise exceeded {LIVE_LOOP_TIMEOUT:?}"),
        }
    });
}

// ---------------------------------------------------------------------------
// B1/C1 probes (T69) — human-gated, real tokens
// ---------------------------------------------------------------------------

/// B1 live: the verify step with a REAL haiku verifier over the scratch repo. Budget < $0.40
/// (builder ≤ $0.15, verifier ≤ $0.10, reviewer ≤ $0.10). The scratch repo declares no test
/// framework, so a correct verifier answers `pass` (it can still type-check by eye) or
/// `nothing-to-run` — either proceeds; only `fail` or a hash mismatch would block.
#[test]
#[ignore = "spends real Claude and Codex tokens (<$0.40); run manually with ACP_LIVE=1"]
fn live_verifier() {
    if std::env::var("ACP_LIVE") != Ok("1".into()) {
        eprintln!("skipping live_verifier: set ACP_LIVE=1 explicitly");
        return;
    }
    common::with_shared_env(|| async {
        let world = Arc::new(LoopWorld {
            state: temp_state_dir(),
            repo: temp_git_repo(),
        });
        let mut roles = (*embedded_roles()).clone();
        roles.defaults.run_budget_usd = 0.40;
        roles.defaults.spawn_budget_usd = 0.15;
        roles.defaults.attempt_timeout_sec = LIVE_TIMEOUT.as_secs();
        let builder = roles.roles.get_mut(&RoleName::Builder).expect("builder");
        builder.default_model = "haiku".into();
        builder.max_turns = 16;
        builder.spawn_budget_usd = 0.15;
        let verifier = roles.roles.get_mut(&RoleName::Verifier).expect("verifier");
        verifier.default_model = "haiku".into();
        // 24, not 12: the first live run (2026-08-30) burned 12 turns TWICE exploring the
        // frameworkless scratch repo and hit max_turns — the same calibration class as the
        // Phase-1 builder's 8 → 16. The prompt now tells the verifier to conclude
        // `nothing-to-run` within its first few commands; the spawn budget stays the hard cap.
        verifier.max_turns = 24;
        verifier.spawn_budget_usd = 0.15;
        let reviewer = roles.roles.get_mut(&RoleName::Reviewer).expect("reviewer");
        reviewer.default_model = "gpt-5.5".into();
        reviewer.max_turns = 4;
        reviewer.spawn_budget_usd = 0.10;

        let actor = start_actor(&world, Arc::new(roles), ActorOpts::default());
        let handle = actor.handle.clone();
        let out = handle
            .delegate(delegate_builder(loop_task("T69-live-verify")))
            .await
            .expect("delegate");
        let run = out.run_id;

        let exercise_world = Arc::clone(&world);
        let mut exercise = tokio::spawn(async move {
            let events = live_wait_for_log(&exercise_world, &run, "verify.report", |events| {
                events
                    .iter()
                    .any(|e| matches!(&e.payload, EventPayload::VerifyReport { .. }))
            })
            .await;
            let report = events
                .iter()
                .find_map(|e| match &e.payload {
                    EventPayload::VerifyReport { status, .. } => Some(*status),
                    _ => None,
                })
                .expect("a verify report");
            assert!(
                matches!(report, VerifyStatus::Pass | VerifyStatus::NothingToRun),
                "a scratch repo with no test framework must not fail verification: {report:?}"
            );
            let build_done = events
                .iter()
                .find(|e| {
                    matches!(
                        &e.payload,
                        EventPayload::AttemptFinished {
                            status: AttemptStatus::Succeeded,
                            ..
                        }
                    )
                })
                .map(|e| e.base.seq)
                .expect("the builder finished");
            let report_seq = events
                .iter()
                .find(|e| matches!(&e.payload, EventPayload::VerifyReport { .. }))
                .map(|e| e.base.seq)
                .expect("the report");
            assert!(build_done < report_seq, "verify sits after the build");

            let events = live_wait_for_log(&exercise_world, &run, "gate.created", |events| {
                events
                    .iter()
                    .any(|e| matches!(&e.payload, EventPayload::GateCreated { .. }))
            })
            .await;
            let verdict_seq = events
                .iter()
                .find(|e| matches!(&e.payload, EventPayload::ReviewVerdict { .. }))
                .map(|e| e.base.seq)
                .expect("a verdict");
            assert!(report_seq < verdict_seq, "verify sits before the review");

            // The N4 carry (T64 review): claude 2.1.221 OMITS `structured_output` under
            // `--agent`, so a real verifier's report can only have arrived through the
            // fenced-text fallback parser — the arm the fake suite never exercises (its fixtures
            // DO supply structured_output). Assert both halves on the raw capture: the CLI's
            // final `result` line carries no structured_output, AND the schema-bound report was
            // nonetheless recorded.
            let verifier_attempt_dir = events
                .iter()
                .find_map(|e| match &e.payload {
                    EventPayload::AgentCreated {
                        agent_id,
                        role: RoleName::Verifier,
                        ..
                    } => Some(*agent_id),
                    _ => None,
                })
                .and_then(|verifier| {
                    events.iter().find_map(|e| match &e.payload {
                        EventPayload::AttemptStarted { agent_id, dir, .. }
                            if *agent_id == verifier =>
                        {
                            Some(dir.clone())
                        }
                        _ => None,
                    })
                })
                .expect("the verifier attempt dir");
            let transcript = std::fs::read_to_string(verifier_attempt_dir.join("stdout.jsonl"))
                .expect("the verifier transcript is on disk");
            let result_line = transcript
                .lines()
                .rev()
                .find(|line| line.contains(r#""type":"result""#))
                .expect("the CLI's final result line");
            assert!(
                !result_line.contains(r#""structured_output""#),
                "claude --agent omits structured_output; if this starts appearing, the fallback \
                 arm is no longer what a real verifier exercises — re-examine, do not delete: \
                 {result_line}"
            );
        });
        let outcome = match tokio::time::timeout(LIVE_LOOP_TIMEOUT, &mut exercise).await {
            Ok(result) => Some(result),
            Err(_) => {
                exercise.abort();
                let _ = exercise.await;
                None
            }
        };
        let cleanup = live_quiesce(&handle).await;
        actor.stop().await;
        if let Err(err) = cleanup {
            panic!("live_verifier cleanup failed: {err}");
        }
        match outcome {
            Some(Ok(())) => {}
            Some(Err(join_error)) if join_error.is_panic() => {
                std::panic::resume_unwind(join_error.into_panic());
            }
            Some(Err(join_error)) => panic!("live_verifier exercise cancelled: {join_error}"),
            None => panic!("live_verifier exceeded {LIVE_LOOP_TIMEOUT:?}"),
        }
    });
}

/// C1 live: a REAL codex builder under the measured workspace-write seatbelt. This is ALSO the
/// proof for research risk 1 — that `codex exec --strict-config` accepts the two
/// `sandbox_workspace_write.exclude_*` keys and `--ignore-user-config`: a rejection is a spawn
/// failure long before any loop outcome, so `Succeeded` on the builder attempt is the evidence.
/// The verify step is deliberately absent (its probe is `live_verifier`); budget < $0.35.
#[test]
#[ignore = "spends real Codex tokens (<$0.35); run manually with ACP_LIVE=1"]
fn live_codex_builder() {
    if std::env::var("ACP_LIVE") != Ok("1".into()) {
        eprintln!("skipping live_codex_builder: set ACP_LIVE=1 explicitly");
        return;
    }
    common::with_shared_env(|| async {
        let world = Arc::new(LoopWorld {
            state: temp_state_dir(),
            repo: temp_git_repo(),
        });
        let mut roles = (*embedded_roles()).clone();
        roles.roles.remove(&RoleName::Verifier);
        roles.defaults.run_budget_usd = 0.35;
        roles.defaults.spawn_budget_usd = 0.20;
        roles.defaults.attempt_timeout_sec = LIVE_TIMEOUT.as_secs();
        let builder = roles.roles.get_mut(&RoleName::Builder).expect("builder");
        builder.max_turns = 16;
        builder.spawn_budget_usd = 0.20;
        let reviewer = roles.roles.get_mut(&RoleName::Reviewer).expect("reviewer");
        reviewer.default_model = "gpt-5.5".into();
        reviewer.max_turns = 4;
        reviewer.spawn_budget_usd = 0.10;
        let team = Team {
            mode: None,
            version: 1,
            name: "t69-codex-builder".into(),
            lead: None,
            roles: BTreeMap::from([(
                "builder".into(),
                Assignment {
                    provider: ProviderName::Codex,
                    model: "gpt-5.5".into(),
                    effort: Some(Effort::Low),
                },
            )]),
        };
        team::validate_team(&roles, &team).expect("a codex builder team is valid since C1");
        team::save_team(world.state_dir(), &team).expect("write team.json");

        let actor = start_actor(&world, Arc::new(roles), ActorOpts::default());
        let handle = actor.handle.clone();
        let out = handle
            .delegate(delegate_builder(loop_task("T69-codex-build")))
            .await
            .expect("delegate");
        let run = out.run_id;

        let exercise_handle = handle.clone();
        let exercise_world = Arc::clone(&world);
        let mut exercise = tokio::spawn(async move {
            let envelope = live_await_done(&exercise_handle, out.agent_id).await;
            assert_eq!(
                envelope.status,
                AttemptStatus::Succeeded,
                "a config rejection would surface here first (research risk 1): {envelope:?}"
            );
            assert_eq!(envelope.provider, ProviderName::Codex);
            let events = live_wait_for_log(&exercise_world, &run, "diff.frozen", |events| {
                events
                    .iter()
                    .any(|e| matches!(&e.payload, EventPayload::DiffFrozen { .. }))
            })
            .await;
            let argv = events
                .iter()
                .find_map(|e| match &e.payload {
                    EventPayload::AttemptStarted { argv, .. } => Some(argv.clone()),
                    _ => None,
                })
                .expect("the builder spawn");
            for token in [
                r#"sandbox_mode="workspace-write""#,
                "sandbox_workspace_write.exclude_slash_tmp=true",
                "sandbox_workspace_write.exclude_tmpdir_env_var=true",
                "sandbox_workspace_write.writable_roots=[]",
                "--ignore-user-config",
            ] {
                assert!(
                    argv.iter().any(|t| t == token),
                    "the live spawn carried {token}"
                );
            }
        });
        let outcome = match tokio::time::timeout(LIVE_LOOP_TIMEOUT, &mut exercise).await {
            Ok(result) => Some(result),
            Err(_) => {
                exercise.abort();
                let _ = exercise.await;
                None
            }
        };
        let cleanup = live_quiesce(&handle).await;
        actor.stop().await;
        if let Err(err) = cleanup {
            panic!("live_codex_builder cleanup failed: {err}");
        }
        match outcome {
            Some(Ok(())) => {}
            Some(Err(join_error)) if join_error.is_panic() => {
                std::panic::resume_unwind(join_error.into_panic());
            }
            Some(Err(join_error)) => panic!("live_codex_builder exercise cancelled: {join_error}"),
            None => panic!("live_codex_builder exceeded {LIVE_LOOP_TIMEOUT:?}"),
        }
    });
}

// ---------------------------------------------------------------------------
// B3 probe (T80) — human-gated, real tokens
// ---------------------------------------------------------------------------

/// The whole spend of the plan probe: two real haiku builders (≤ $0.10 each) and two real codex
/// reviewers (≤ $0.10 each), sequenced. The compile-time assertion keeps a future edit from
/// silently crossing the approved manual-probe ceiling.
const LIVE_PLAN_BUDGET_USD: f64 = 0.45;
const _: () = assert!(LIVE_PLAN_BUDGET_USD < 0.50);

/// B3 live: a real two-item sequence under a **v2 team** (builder + reviewer, verify off by
/// membership). Item two must base on item one's integrated commit; both items land through
/// human-approved gates and the container concludes.
#[test]
#[ignore = "spends real Claude and Codex tokens (<$0.45); run manually with ACP_LIVE=1"]
fn live_plan_sequence() {
    if std::env::var("ACP_LIVE") != Ok("1".into()) {
        eprintln!("skipping live_plan_sequence: set ACP_LIVE=1 explicitly");
        return;
    }
    common::with_shared_env(|| async {
        let world = Arc::new(LoopWorld {
            state: temp_state_dir(),
            repo: temp_git_repo(),
        });
        let mut roles = (*embedded_roles()).clone();
        roles.defaults.run_budget_usd = 0.22;
        roles.defaults.spawn_budget_usd = 0.10;
        roles.defaults.attempt_timeout_sec = LIVE_TIMEOUT.as_secs();
        let builder = roles
            .roles
            .get_mut(&RoleName::Builder)
            .expect("builder role");
        builder.default_model = "haiku".into();
        builder.max_turns = 16;
        builder.spawn_budget_usd = FULL_LOOP_BUILDER_BUDGET_USD;
        let reviewer = roles
            .roles
            .get_mut(&RoleName::Reviewer)
            .expect("reviewer role");
        reviewer.default_model = "gpt-5.5".into();
        reviewer.max_turns = 4;
        reviewer.spawn_budget_usd = 0.10;

        // A v2 team: membership is the step list, so the absent verifier means no verify step —
        // this probe is also the role subset's first live proof.
        let team = Team {
            mode: None,
            version: 2,
            name: "t80-live-plan".into(),
            lead: None,
            roles: BTreeMap::from([
                (
                    "builder".into(),
                    Assignment {
                        provider: ProviderName::Claude,
                        model: "haiku".into(),
                        effort: None,
                    },
                ),
                (
                    "reviewer".into(),
                    Assignment {
                        provider: ProviderName::Codex,
                        model: "gpt-5.5".into(),
                        effort: Some(Effort::Low),
                    },
                ),
            ]),
        };
        team::validate_team(&roles, &team).expect("the live v2 team is valid");
        team::save_team(world.state_dir(), &team).expect("write live team.json");

        let actor = start_actor(&world, Arc::new(roles), ActorOpts::default());
        let handle = actor.handle.clone();
        let task_world = Arc::clone(&world);
        let task_handle = handle.clone();
        let mut exercise = tokio::spawn(async move {
            exercise_live_plan_sequence(task_world, task_handle).await;
        });
        let outcome = match tokio::time::timeout(LIVE_LOOP_TIMEOUT, &mut exercise).await {
            Ok(result) => Some(result),
            Err(_) => {
                exercise.abort();
                let _ = exercise.await;
                None
            }
        };

        let cleanup = live_quiesce(&handle).await;
        actor.stop().await;
        if let Err(err) = cleanup {
            panic!("live-plan cleanup failed after the exercise: {err}");
        }
        match outcome {
            Some(Ok(())) => {}
            Some(Err(join_error)) if join_error.is_panic() => {
                std::panic::resume_unwind(join_error.into_panic());
            }
            Some(Err(join_error)) => panic!("live-plan exercise was cancelled: {join_error}"),
            None => panic!("live-plan exercise exceeded {LIVE_LOOP_TIMEOUT:?}"),
        }
    });
}

async fn exercise_live_plan_sequence(world: Arc<LoopWorld>, handle: CoreHandle) {
    use agent_control_plane::core::plan::{Plan, PlanItem, PlanItemKind, PLAN_VERSION};

    let item = |id: &str, task: Task| PlanItem {
        id: id.to_string(),
        kind: PlanItemKind::Work,
        task: Some(task),
        summary: None,
        after: vec![],
        verify: None,
        review: None,
    };
    let mut plan = Plan {
        version: PLAN_VERSION,
        name: "two real steps".into(),
        items: vec![
            item(
                "one",
                Task {
                    id: "T80-one".into(),
                    title: "Add src/one.ts exporting add(a, b).".into(),
                    description: "Create src/one.ts exporting add(a: number, b: number): number \
                                  returning a + b. Nothing else."
                        .into(),
                    files: vec!["src/one.ts".into()],
                    acceptance: vec!["add(1, 2) === 3".into()],
                },
            ),
            item(
                "two",
                Task {
                    id: "T80-two".into(),
                    title: "Add src/two.ts exporting twice(a).".into(),
                    description: "Create src/two.ts exporting twice(a: number): number returning \
                                  a * 2, matching the style of src/one.ts, which already exists."
                        .into(),
                    files: vec!["src/two.ts".into()],
                    acceptance: vec!["twice(4) === 8".into()],
                },
            ),
        ],
    };
    plan.items[1].after = vec!["one".into()];

    let out = handle
        .start_plan(plan, None)
        .await
        .expect("the live plan starts");
    let container = out.run_id;

    let item_run = |events: &[Arc<Event>], wanted: &str| {
        events.iter().find_map(|event| match &event.payload {
            EventPayload::PlanItem {
                item_id,
                status,
                run_id,
                ..
            } if item_id == wanted
                && *status == agent_control_plane::core::plan::PlanItemStatus::Started =>
            {
                *run_id
            }
            _ => None,
        })
    };

    let events = live_wait_for_log(&world, &container, "item one started", |events| {
        item_run(events, "one").is_some()
    })
    .await;
    let first_run = item_run(&events, "one").expect("item one's run");
    let first_sha = live_approve_integrate(&world, &handle, &first_run).await;

    let events = live_wait_for_log(&world, &container, "item two started", |events| {
        item_run(events, "two").is_some()
    })
    .await;
    let second_run = item_run(&events, "two").expect("item two's run");
    let second_events =
        live_wait_for_log(&world, &second_run, "item two's run.created", |events| {
            events
                .iter()
                .any(|event| matches!(&event.payload, EventPayload::RunCreated { .. }))
        })
        .await;
    let base_ref = second_events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::RunCreated { base_ref, .. } => Some(base_ref.clone()),
            _ => None,
        })
        .expect("item two's base");
    assert_eq!(
        base_ref, first_sha,
        "the real sequence builds on its predecessor's integrated commit"
    );

    live_approve_integrate(&world, &handle, &second_run).await;
    live_wait_for_log(&world, &container, "the plan concluded", |events| {
        events.iter().any(|event| {
            matches!(
                &event.payload,
                EventPayload::RunStatus_ { status, .. } if *status == RunStatus::Integrated
            )
        })
    })
    .await;
}

/// Waits for `run`'s integrate gate, approves it over the human path, and returns the commit.
async fn live_approve_integrate(world: &LoopWorld, handle: &CoreHandle, run: &RunId) -> String {
    let events = live_wait_for_log(world, run, "gate.created{integrate}", |events| {
        events.iter().any(|event| {
            matches!(
                &event.payload,
                EventPayload::GateCreated { gate_kind, .. } if *gate_kind == GateKind::Integrate
            )
        })
    })
    .await;
    let gate = events
        .iter()
        .find_map(|event| match &event.payload {
            EventPayload::GateCreated {
                gate_id, gate_kind, ..
            } if *gate_kind == GateKind::Integrate => Some(*gate_id),
            _ => None,
        })
        .expect("an integrate gate");
    let resolution = handle
        .resolve_gate(gate, true, None, cli_actor())
        .await
        .expect("the live approval is answered");
    let GateResolution::Approved { sha: Some(sha) } = resolution else {
        panic!("the live approval did not commit: {resolution:?}");
    };
    sha
}
