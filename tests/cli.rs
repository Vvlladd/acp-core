//! T44: the `acp` binary, driven as a human drives it — `reports/03-design.md` § Test Strategy,
//! row `cli.rs`, and § Process model.
//!
//! Every assertion here goes through `env!("CARGO_BIN_EXE_acp")` as a **subprocess**. Nothing calls
//! `cli::run` directly, because what is under test is the contract a human and a launchd job see:
//! the exit codes (3 for a held lock), the files that exist while a daemon runs and are gone after
//! it stops, the refusals that must happen before anything is created, and the lines the reports
//! print.
//!
//! **Three rules this file keeps.**
//!
//! * *Short paths.* macOS `sun_path` is 104 bytes and `$TMPDIR` here is a ~50-byte `/var/folders/…`,
//!   so every state dir is made under `/tmp` by [`short_dir`], which asserts the socket path fits.
//!   A test failing because *its own fixture* was too long would be indistinguishable from the bug
//!   the length check exists to catch.
//! * *Bounded polls, never sleeps.* [`wait_for`] polls a predicate — a file appearing, a child
//!   exiting, a gate reaching the log — against a deadline. The deadline is a failure detector, not
//!   a timing assertion.
//! * *Every child is reaped.* [`Daemon`] and [`Follower`] kill and wait on drop, so a failing
//!   assertion cannot strand a daemon holding a lock (or a worker holding a worktree) behind it.
//!
//! **The stdin pipe is load-bearing in the default mode.** `acp serve` runs the MCP server on
//! stdio, and the design's C3 exit path is "SIGINT/SIGTERM **or MCP stdin EOF**". [`Daemon`] gives
//! that mode a pipe and holds the write end for as long as it is meant to live. The explicit
//! `--no-mcp` fixture instead uses `Stdio::null()` to prove the socket-only mode ignores stdin.

mod common;

use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agent_control_plane::core::registry::Registry;
use agent_control_plane::core::types::{
    AgentId, AgentStatus, EventPayload, False, LineageId, Origin, ProviderName, RoleName, RunId,
};
use agent_control_plane::ipc::socket::MAX_SOCKET_PATH_BYTES;
use serde_json::{json, Value};
use tempfile::TempDir;

use common::{configure_fakes, head_sha, install_fake_clis, loop_task, temp_git_repo};

/// The binary under test. Resolves only because `acp` is a `[[bin]]` of this package.
const ACP: &str = env!("CARGO_BIN_EXE_acp");

/// How long any single step may take before the test calls it a hang.
const LIMIT: Duration = Duration::from_secs(60);

/// The bound on the one test that drives real (fake) provider processes through a real daemon.
/// Longer on purpose: spawning the fake CLIs on this platform is bimodal (~2 s warm, ~45 s cold),
/// exactly as `tests/loop_pass.rs` and `tests/socket.rs` record.
const LOOP_LIMIT: Duration = Duration::from_secs(300);

const POLL: Duration = Duration::from_millis(25);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A state dir short enough that `<dir>/acp.sock` fits in `sun_path`, created 0700 as the daemon
/// would create it.
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
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
        .expect("0700 on the fixture state dir");
    dir
}

/// A scratch repository `serve` will actually start in: `.acp/` excluded, as the daemon demands.
fn repo_with_exclude() -> TempDir {
    let repo = temp_git_repo();
    exclude_acp(repo.path());
    repo
}

fn exclude_acp(repo: &Path) {
    let path = repo.join(".git").join("info").join("exclude");
    fs::create_dir_all(path.parent().expect("info dir")).expect("mkdir .git/info");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap_or_else(|err| panic!("open {}: {err}", path.display()));
    writeln!(file, ".acp/").expect("append the exclude entry");
}

/// One `acp …` invocation against `state`, run in `repo`.
fn acp(state: &Path, repo: &Path, args: &[&str]) -> Output {
    let out = Command::new(ACP)
        .args(args)
        .current_dir(repo)
        .env("ACP_STATE_DIR", state)
        .output()
        .unwrap_or_else(|err| panic!("run acp {args:?}: {err}"));
    Output {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// What one invocation said.
struct Output {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Output {
    fn ok(&self, what: &str) -> &Self {
        assert_eq!(
            self.code,
            Some(0),
            "{what} exited {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code,
            self.stdout,
            self.stderr
        );
        self
    }
}

/// Polls `ready` until it answers, or fails naming what never happened.
fn wait_for(what: &str, limit: Duration, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !ready() {
        assert!(Instant::now() < deadline, "{what} never happened");
        std::thread::sleep(POLL);
    }
}

// ---------------------------------------------------------------------------
// A running daemon
// ---------------------------------------------------------------------------

/// One `acp serve` child, its stdin pipe held open, ready to be talked to.
struct Daemon {
    child: Child,
    state: PathBuf,
    /// Set once the child has been waited on, so `Drop` does not try to reap it twice.
    reaped: bool,
}

impl Daemon {
    /// Starts a daemon and waits until its socket answers a `hello`.
    ///
    /// The environment is inherited so the child resolves `git` — and, in the loop tests, the
    /// wrapper `claude`/`codex` — through the same `PATH` the test process has.
    fn start(state: &Path, repo: &Path) -> Self {
        Self::start_at(state, repo)
    }

    /// The same, naming the working directory explicitly — which is how a daemon is started inside
    /// a **linked worktree**, where the cwd is not the main repository.
    fn start_at(state: &Path, cwd: &Path) -> Self {
        Self::start_mode(state, cwd, false)
    }

    /// Starts the socket-only mode with a closed stdin — the launchd-shaped case T54 exists for.
    fn start_no_mcp(state: &Path, cwd: &Path) -> Self {
        Self::start_mode(state, cwd, true)
    }

    fn start_mode(state: &Path, cwd: &Path, no_mcp: bool) -> Self {
        Self::start_with_lifetime(state, cwd, no_mcp, false)
    }

    fn start_with_lifetime(state: &Path, cwd: &Path, no_mcp: bool, managed: bool) -> Self {
        let mut command = Command::new(ACP);
        command.arg("serve");
        if managed { command.arg("--managed"); }
        if no_mcp {
            command.arg("--no-mcp");
        }
        let child = command
            .current_dir(cwd)
            .env("ACP_STATE_DIR", state)
            .stdin(if no_mcp {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(Stdio::from(file(&state.join("serve.stdout"))))
            .stderr(Stdio::from(file(&state.join("serve.stderr"))))
            .spawn()
            .unwrap_or_else(|err| panic!("spawn acp serve: {err}"));
        let mut daemon = Self {
            child,
            state: state.to_path_buf(),
            reaped: false,
        };
        wait_for("the daemon bound its socket", LIMIT, || {
            daemon.lock().exists() && Wire::try_connect(&daemon.socket()).is_some()
        });
        assert!(
            daemon.child.try_wait().expect("probe daemon").is_none(),
            "the daemon exited immediately after binding\n--- stderr ---\n{}",
            daemon.stderr()
        );
        daemon
    }

    fn socket(&self) -> PathBuf {
        self.state.join("acp.sock")
    }

    fn lock(&self) -> PathBuf {
        self.state.join("serve.lock")
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).expect("a pid fits in i32")
    }

    fn signal(&self, signal: nix::sys::signal::Signal) {
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(self.pid()), signal)
            .unwrap_or_else(|err| panic!("signalling the daemon: {err}"));
    }

    /// Waits for the child to exit and returns its code.
    fn wait(&mut self, what: &str) -> Option<i32> {
        let deadline = Instant::now() + LIMIT;
        loop {
            match self.child.try_wait().expect("wait on the daemon") {
                Some(status) => {
                    self.reaped = true;
                    return status.code();
                }
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "{what}: the daemon never exited\n--- stderr ---\n{}",
                        self.stderr()
                    );
                    std::thread::sleep(POLL);
                }
            }
        }
    }

    fn stderr(&self) -> String {
        read(&self.state.join("serve.stderr"))
    }

    fn stdout(&self) -> String {
        read(&self.state.join("serve.stdout"))
    }

    /// Closes the stdin pipe — the MCP peer hanging up, which is the other half of the C3 trigger
    /// (design, § Process model: "`tokio::signal` SIGINT/SIGTERM **and MCP stdin EOF**").
    fn close_stdin(&mut self) {
        drop(self.child.stdin.take().expect("the daemon's stdin pipe"));
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // A failed assertion must never leave a daemon holding a lock (and, in the loop test,
        // workers holding worktrees) behind it.
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// One `acp status --follow --json` child, writing to a file the test polls.
struct Follower {
    child: Child,
    out: PathBuf,
}

impl Follower {
    fn start(state: &Path, repo: &Path) -> Self {
        let out = state.join("follow.jsonl");
        let child = Command::new(ACP)
            .args(["status", "--follow", "--json"])
            .current_dir(repo)
            .env("ACP_STATE_DIR", state)
            .stdin(Stdio::null())
            .stdout(Stdio::from(file(&out)))
            .stderr(Stdio::from(file(&state.join("follow.err"))))
            .spawn()
            .unwrap_or_else(|err| panic!("spawn acp status --follow: {err}"));
        Self { child, out }
    }

    /// Every line printed so far, parsed. A partial last line (the writer is mid-`write`) is
    /// dropped rather than failed on.
    fn events(&self) -> Vec<Value> {
        read(&self.out)
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect()
    }
}

impl Drop for Follower {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn file(path: &Path) -> fs::File {
    fs::File::create(path).unwrap_or_else(|err| panic!("create {}: {err}", path.display()))
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// A raw socket client
// ---------------------------------------------------------------------------

/// One blocking NDJSON connection, so a test can put a real run behind the CLI's gate commands.
struct Wire {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: i64,
}

impl Wire {
    fn try_connect(path: &Path) -> Option<Self> {
        let stream = UnixStream::connect(path).ok()?;
        stream
            .set_read_timeout(Some(LIMIT))
            .expect("a read timeout");
        let reader = BufReader::new(stream.try_clone().expect("clone the socket"));
        let mut wire = Self {
            reader,
            writer: stream,
            next_id: 1,
        };
        let hello = wire
            .call("hello", json!({ "clientName": "cli-test" }))
            .expect("hello");
        assert_eq!(hello["protocolVersion"], json!(1), "{hello}");
        Some(wire)
    }

    fn connect(path: &Path) -> Self {
        Self::try_connect(path).unwrap_or_else(|| panic!("connect to {}", path.display()))
    }

    fn call(&mut self, method: &str, params: Value) -> Result<Value, Value> {
        let id = self.next_id;
        self.next_id += 1;
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(self.writer, "{line}").expect("write a frame");
        loop {
            let mut got = String::new();
            let read = self.reader.read_line(&mut got).expect("read a frame");
            assert!(read > 0, "the daemon closed the connection during {method}");
            let frame: Value =
                serde_json::from_str(&got).unwrap_or_else(|err| panic!("frame is JSON: {err}"));
            if frame.get("id").and_then(Value::as_i64) != Some(id) {
                continue;
            }
            return match frame.get("error") {
                Some(error) => Err(error.clone()),
                None => Ok(frame.get("result").cloned().unwrap_or(Value::Null)),
            };
        }
    }
}

// ---------------------------------------------------------------------------
// status, with no daemon at all
// ---------------------------------------------------------------------------

/// `acp status` against a hand-populated state dir: no socket, no lock, no daemon.
///
/// The log is written through `Registry` rather than by hand so the fixture is the real on-disk
/// format by construction — the same replay path `status` reads it back with.
#[test]
fn status_renders_a_fixture_log_with_no_daemon_running() {
    let state = short_dir();
    let repo = temp_git_repo();
    let run = fixture_run(state.path(), repo.path(), "T44-status");

    let human = acp(state.path(), repo.path(), &["status"]);
    human.ok("acp status");
    assert!(
        human.stdout.contains(&run.to_string()),
        "the run is named: {}",
        human.stdout
    );
    assert!(
        human.stdout.contains("status=running") && human.stdout.contains("T44-status"),
        "the run's state and task are rendered: {}",
        human.stdout
    );

    let json = acp(state.path(), repo.path(), &["status", "--json"]);
    json.ok("acp status --json");
    let snapshot: Value = serde_json::from_str(json.stdout.trim())
        .unwrap_or_else(|err| panic!("--json prints one JSON object: {err}: {}", json.stdout));
    assert_eq!(snapshot["runs"][0]["runId"], json!(run.to_string()));
    assert_eq!(snapshot["agents"][0]["role"], json!("builder"));
    assert_eq!(snapshot["stateDir"], json!(state.path()));

    // Scoping to another run empties the snapshot rather than failing.
    let other = RunId::new_v4().to_string();
    let scoped = acp(state.path(), repo.path(), &["status", "--json", &other]);
    scoped.ok("acp status --json <unknown run>");
    let scoped: Value = serde_json::from_str(scoped.stdout.trim()).expect("JSON");
    assert_eq!(
        scoped["runs"],
        json!([]),
        "a run that does not exist is simply empty"
    );

    assert!(
        !state.path().join("acp.sock").exists() && !state.path().join("serve.lock").exists(),
        "a read-only status neither binds a socket nor takes a lock"
    );
}

/// A run with one builder agent and one worktree, written the way the daemon writes it.
fn fixture_run(state: &Path, repo: &Path, task_id: &str) -> RunId {
    let mut registry = Registry::open(state).expect("open the fixture state dir");
    let run = RunId::new_v4();
    let agent = AgentId::new_v4();
    let lineage = LineageId::new_v4();
    let worktree = repo.join(".acp/worktrees").join(run.to_string()).join("b");

    registry
        .append(
            &run,
            EventPayload::RunCreated {
                execution: None,
                repo_root: repo.to_path_buf(),
                state_dir: state.to_path_buf(),
                base_ref: "HEAD".to_string(),
                base_sha: head_sha(repo),
                task: loop_task(task_id),
                version: 1,
                lead: None,
                team_name: None,
                steps: None,
            },
        )
        .expect("append run.created");
    registry
        .append(
            &run,
            EventPayload::AgentCreated {
                agent_id: agent,
                role: RoleName::Builder,
                provider: ProviderName::Claude,
                model: "fable".to_string(),
                lineage_id: Some(lineage),
                depth: 1,
                parent_agent_id: None,
                origin: Origin::Lead,
                writes: true,
                cwd: worktree.clone(),
                worktree: Some(worktree.clone()),
            },
        )
        .expect("append agent.created");
    registry
        .append(
            &run,
            EventPayload::WorktreeCreated {
                agent_id: agent,
                lineage_id: lineage,
                path: worktree,
                branch: format!("acp/{run}/b"),
                base_sha: head_sha(repo),
            },
        )
        .expect("append worktree.created");
    run
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

/// A `PATH` with no `claude` and no `codex` reports both as missing, and the report fails.
#[test]
fn doctor_reports_a_missing_provider_cli_and_exits_non_zero() {
    let state = short_dir();
    let repo = repo_with_exclude();

    // A directory of its own plus the system directories git lives in: the two provider CLIs are
    // the only things deliberately absent.
    let empty = tempfile::tempdir().expect("an empty bin dir");
    let out = Command::new(ACP)
        .arg("doctor")
        .current_dir(repo.path())
        .env_clear()
        .env("ACP_STATE_DIR", state.path())
        .env("PATH", format!("{}:/usr/bin:/bin", empty.path().display()))
        .env("HOME", state.path())
        .output()
        .expect("run acp doctor");
    let report = String::from_utf8_lossy(&out.stdout).to_string();

    assert_eq!(
        out.status.code(),
        Some(1),
        "a missing provider CLI fails the report: {report}"
    );
    for name in ["claude", "codex"] {
        let line = line_for(&report, name);
        assert!(
            line.starts_with("fail") && line.contains("missing"),
            "{name} is reported missing: {line:?}"
        );
    }
    assert!(
        line_for(&report, "roles").starts_with("ok"),
        "the embedded roles config is still valid: {report}"
    );
}

/// Against a running daemon, `doctor` reports the holder and the socket the design says it does.
#[test]
fn doctor_reports_the_lock_holder_and_the_socket() {
    let state = short_dir();
    let repo = repo_with_exclude();
    let bins = common::fixture_bin_dir();
    let mut daemon = Daemon::start(state.path(), repo.path());

    let out = Command::new(ACP)
        .arg("doctor")
        .current_dir(repo.path())
        .env_clear()
        .env("ACP_STATE_DIR", state.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bins.path().display()))
        .env("HOME", state.path())
        .output()
        .expect("run acp doctor");
    let report = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(out.status.code(), Some(0), "a healthy setup: {report}");

    let lock = line_for(&report, "lock");
    assert!(
        lock.starts_with("ok") && lock.contains(&format!("pid {}", daemon.pid())),
        "the lock names its holder: {lock:?}"
    );
    assert!(lock.contains("age "), "and how old the lock is: {lock:?}");

    let socket = line_for(&report, "socket");
    assert!(
        socket.starts_with("ok") && socket.contains("mode 0600"),
        "the socket's mode is reported: {socket:?}"
    );
    let length = line_for(&report, "sock path");
    assert!(
        length.starts_with("ok") && length.contains(&format!("of the {MAX_SOCKET_PATH_BYTES}")),
        "the socket path's length is reported against the limit: {length:?}"
    );
    // Resolution is what this asserts. Whether the CLI *answers* `--version` inside the probe's
    // bound is a property of the machine's load — a cold first exec of a freshly built binary is
    // seconds on this platform — and it is a `warn`, never a `fail`, precisely because it is.
    for name in ["claude", "codex"] {
        let line = line_for(&report, name);
        assert!(
            !line.starts_with("fail") && line.contains(&bins.path().display().to_string()),
            "{name} resolved to the fake on PATH: {line:?}"
        );
    }

    daemon.signal(nix::sys::signal::Signal::SIGTERM);
    assert_eq!(daemon.wait("after doctor"), Some(0));
}

/// The `doctor` line for one check.
fn line_for(report: &str, name: &str) -> String {
    report
        .lines()
        .find(|line| {
            line.split_whitespace().nth(1) == Some(name) || line.contains(&format!("  {name}  "))
        })
        .unwrap_or_else(|| panic!("no {name} line in:\n{report}"))
        .to_string()
}

/// C1 (T67): the codex version pin. A `--version` answer whose trailing token differs from
/// `SANDBOX_VERIFIED_VERSION` turns the codex row into a WARN — never a FAIL (doctor must stay
/// usable on an upgraded machine) — naming the measured version and the accepted residuals.
#[test]
fn doctor_warns_when_the_codex_version_drifts_from_the_sandbox_pin() {
    let state = common::temp_state_dir();
    let repo = temp_git_repo();
    exclude_acp(repo.path());
    let bins = common::fixture_bin_dir();

    let out = std::process::Command::new(ACP)
        .args(["doctor"])
        .current_dir(repo.path())
        .env("ACP_STATE_DIR", state.path())
        .env("PATH", common::prepend_path(bins.path()))
        .env("ACP_FAKE_VERSION", "codex-cli 0.133.0")
        .output()
        .expect("run acp doctor");
    let report = String::from_utf8_lossy(&out.stdout).to_string();

    let codex = line_for(&report, "codex");
    assert!(
        codex.starts_with("warn"),
        "a drifted codex version is a WARN: {codex:?}"
    );
    assert!(
        codex.contains("0.132.0") && codex.contains("CODEX_HOME/memories"),
        "the warn names the measured version and the residuals: {codex:?}"
    );
    // `ok`, not merely not-fail: if the provider guard were dropped, EVERY row would warn and a
    // not-fail assertion would still pass — this one catches exactly that regression.
    let claude = line_for(&report, "claude");
    assert!(
        claude.starts_with("ok"),
        "the claude row is untouched by the codex pin: {claude:?}"
    );
    // T67's literal AC: the drift never fails doctor.
    assert_eq!(out.status.code(), Some(0), "warn is advisory: {report}");
}

// ---------------------------------------------------------------------------
// The lock and the C3 exit path
// ---------------------------------------------------------------------------

/// A second `serve` against a live lock exits 3 and names the holder — and takes nothing over.
#[test]
fn a_second_serve_against_a_held_lock_exits_3() {
    let state = short_dir();
    let repo = repo_with_exclude();
    let mut daemon = Daemon::start(state.path(), repo.path());
    let before = read(&daemon.lock());

    let second = acp(state.path(), repo.path(), &["serve"]);
    assert_eq!(second.code, Some(3), "stderr: {}", second.stderr);
    assert!(
        second.stderr.contains(&format!("pid {}", daemon.pid())),
        "the refusal names the holder: {}",
        second.stderr
    );
    assert_eq!(
        read(&daemon.lock()),
        before,
        "the refused start left the holder's lock untouched"
    );

    daemon.signal(nix::sys::signal::Signal::SIGTERM);
    assert_eq!(daemon.wait("after the refused second serve"), Some(0));
}

/// C3: `SIGTERM` → the lock and the socket file are unlinked, and the process exits 0.
#[test]
fn sigterm_unlinks_the_lock_and_the_socket_and_exits_0() {
    let state = short_dir();
    let repo = repo_with_exclude();
    let mut daemon = Daemon::start(state.path(), repo.path());
    let (lock, socket) = (daemon.lock(), daemon.socket());
    assert!(lock.exists() && socket.exists());
    assert_eq!(
        fs::metadata(&socket).expect("socket").permissions().mode() & 0o777,
        0o600,
        "the socket is 0600 while it is served"
    );

    daemon.signal(nix::sys::signal::Signal::SIGTERM);
    let code = daemon.wait("after SIGTERM");

    assert_eq!(code, Some(0), "a signalled shutdown is a clean one");
    assert!(!lock.exists(), "the lock is unlinked");
    assert!(!socket.exists(), "the socket file is unlinked");
    assert!(
        state.path().join("acp.log").exists(),
        "the log stays: it is where a daemon's output goes"
    );
    assert!(
        read(&state.path().join("serve.stdout")).is_empty(),
        "nothing but MCP may ever be written to stdout"
    );
}

/// `acp serve --stop` against a running daemon: the lock clears, the socket goes, the child exits.
#[test]
fn serve_stop_clears_the_lock_and_unlinks_the_socket() {
    let state = short_dir();
    let repo = repo_with_exclude();
    let mut daemon = Daemon::start(state.path(), repo.path());
    let (lock, socket) = (daemon.lock(), daemon.socket());

    let stop = acp(state.path(), repo.path(), &["serve", "--stop"]);
    stop.ok("acp serve --stop");
    assert!(
        stop.stdout.contains(&format!("pid {}", daemon.pid())),
        "--stop names what it stopped: {}",
        stop.stdout
    );
    assert!(!lock.exists() && !socket.exists());
    assert_eq!(daemon.wait("after --stop"), Some(0));

    // With nothing running, `--stop` is an error rather than a silent success.
    let again = acp(state.path(), repo.path(), &["serve", "--stop"]);
    assert_eq!(again.code, Some(1));
    assert!(
        again.stderr.contains("no acp serve running"),
        "{}",
        again.stderr
    );
}

/// A lock whose holder is gone is unlinked and retaken, rather than blocking every future start.
#[test]
fn a_stale_lock_is_retaken() {
    let state = short_dir();
    let repo = repo_with_exclude();
    let lock = state.path().join("serve.lock");

    // A pid that has already been reaped, with a start time that can never match even if the
    // number is recycled — the identity check is pid **and** `lstart`.
    let dead = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .spawn()
        .expect("spawn a short-lived child");
    let dead_pid = i32::try_from(dead.id()).expect("a pid");
    let mut dead = dead;
    dead.wait().expect("reap it");

    fs::write(
        &lock,
        serde_json::to_string(&json!({
            "pid": dead_pid,
            "startedAt": "2020-01-01T00:00:00.000Z",
            "lstart": "Wed Jan  1 00:00:00 2020",
            "repoRoot": repo.path(),
            "version": "0.0.0-stale",
        }))
        .expect("encode a stale lock"),
    )
    .expect("write a stale lock");

    let mut daemon = Daemon::start(state.path(), repo.path());
    let record: Value = serde_json::from_str(read(&lock).trim()).expect("the retaken lock is JSON");
    assert_eq!(
        record["pid"],
        json!(daemon.pid()),
        "the stale lock was unlinked and retaken"
    );
    assert!(
        daemon.stderr().contains("retaking"),
        "and the retake was announced: {}",
        daemon.stderr()
    );

    daemon.signal(nix::sys::signal::Signal::SIGTERM);
    assert_eq!(daemon.wait("after the stale-lock retake"), Some(0));
}

// ---------------------------------------------------------------------------
// The preflight that runs before anything is created: the exclude entry (written since T91),
// then the socket-path refusal
// ---------------------------------------------------------------------------

/// No `.acp/` in `.git/info/exclude` → `serve` appends the entry to the file git reads, then
/// starts. Everything else in the file is kept, and a second start leaves it byte-identical.
/// `doctor` only reports the missing entry; it never writes.
#[test]
fn serve_adds_the_exclude_entry_it_needs() {
    let state = short_dir();
    let repo = temp_git_repo(); // deliberately without the entry
    let exclude = repo.path().join(".git").join("info").join("exclude");
    fs::write(&exclude, "# kept\nbuild/\n").expect("seed the exclude");

    let looked = acp(state.path(), repo.path(), &["doctor"]);
    assert!(
        looked
            .stdout
            .lines()
            .any(|line| line.starts_with("warn") && line.contains("exclude")),
        "doctor warns about the missing entry: {}",
        looked.stdout
    );
    assert_eq!(
        looked.code,
        Some(0),
        "the warning is advisory, like every other doctor warning: {}",
        looked.stdout
    );
    assert_eq!(
        fs::read_to_string(&exclude).expect("read"),
        "# kept\nbuild/\n",
        "doctor is read-only"
    );

    let mut daemon = Daemon::start(state.path(), repo.path());
    daemon.signal(nix::sys::signal::Signal::SIGTERM);
    assert_eq!(daemon.wait("after the first start"), Some(0));
    assert_eq!(
        fs::read_to_string(&exclude).expect("read"),
        "# kept\nbuild/\n.acp/\n",
        "the entry is appended and nothing else changes"
    );

    let mut daemon = Daemon::start(state.path(), repo.path());
    daemon.signal(nix::sys::signal::Signal::SIGTERM);
    assert_eq!(daemon.wait("after the second start"), Some(0));
    assert_eq!(
        fs::read_to_string(&exclude).expect("read"),
        "# kept\nbuild/\n.acp/\n",
        "a second start leaves the file alone"
    );
    let ok = acp(state.path(), repo.path(), &["doctor"]);
    assert!(
        ok.stdout
            .lines()
            .any(|line| line.starts_with("ok") && line.contains("exclude")),
        "doctor is satisfied now: {}",
        ok.stdout
    );
}

/// `acp up` runs the same preflight as `serve` — the Mac app's door, which can run nothing else:
/// a repository with no exclude file at all gets the entry and a detached daemon.
#[test]
fn up_adds_the_exclude_entry_it_needs() {
    // Shared, like its twin `up_lifecycle`: the daemon this spawns inherits `PATH`, which an
    // exclusive-env test may not rewrite underneath it.
    common::with_shared_env(|| async { up_exclude_entry() });
}

fn up_exclude_entry() {
    let state = short_dir();
    let repo = temp_git_repo(); // deliberately without the entry
    let exclude = repo.path().join(".git").join("info").join("exclude");
    let _ = fs::remove_file(&exclude);

    /// An early panic must not strand the detached daemon: `down` runs whatever happens.
    struct DownGuard(std::path::PathBuf, std::path::PathBuf);
    impl Drop for DownGuard {
        fn drop(&mut self) {
            let _ = Command::new(ACP)
                .args(["down"])
                .current_dir(&self.1)
                .env("ACP_STATE_DIR", &self.0)
                .output();
        }
    }
    let _guard = DownGuard(state.path().to_path_buf(), repo.path().to_path_buf());

    let up = acp(state.path(), repo.path(), &["up", "--managed"]);
    up.ok("acp up --managed");
    assert!(
        up.stdout.starts_with("started acp serve (pid "),
        "{}",
        up.stdout
    );
    assert_eq!(
        fs::read_to_string(&exclude).expect("the exclude file up created"),
        ".acp/\n",
        "up wrote the entry before starting the daemon"
    );
    wait_for("the detached daemon answers hello", LIMIT, || {
        Wire::try_connect(&state.path().join("acp.sock")).is_some()
    });

    let down = acp(state.path(), repo.path(), &["down"]);
    down.ok("acp down");
}

/// A state dir whose socket path would not fit in `sun_path` → refuse, naming the remedy.
#[test]
fn serve_refuses_a_socket_path_over_the_limit() {
    let repo = repo_with_exclude();
    let root = short_dir();
    let long = root.path().join("x".repeat(MAX_SOCKET_PATH_BYTES));
    fs::create_dir_all(&long).expect("a deliberately over-long state dir");
    assert!(long.join("acp.sock").as_os_str().len() > MAX_SOCKET_PATH_BYTES);

    let refused = acp(&long, repo.path(), &["serve"]);
    assert_eq!(refused.code, Some(1), "stdout: {}", refused.stdout);
    assert!(
        refused.stderr.contains("ACP_STATE_DIR") && refused.stderr.contains("bytes"),
        "the refusal names the limit and the remedy: {}",
        refused.stderr
    );
    assert!(
        !long.join("serve.lock").exists(),
        "the refusal happens before the lock is taken"
    );
}

// ---------------------------------------------------------------------------
// gc
// ---------------------------------------------------------------------------

/// `gc` prunes the retired worktree of a closed lineage — and only that one.
///
/// The second lineage is the control: it is still open and still resumable, which is exactly the
/// worktree that must never be removed (Claude's `--resume` is cwd-scoped, so removing it destroys
/// the session with it).
#[test]
fn gc_prunes_only_the_retired_worktree_of_a_closed_lineage() {
    let state = short_dir();
    let repo = repo_with_exclude();
    let (run, closed, open) = fixture_lineages(state.path(), repo.path());
    assert!(closed.is_dir() && open.is_dir(), "both worktrees exist");

    let dry = acp(state.path(), repo.path(), &["gc"]);
    dry.ok("acp gc");
    assert!(
        dry.stdout.contains(&closed.display().to_string()),
        "the closed lineage's worktree is offered: {}",
        dry.stdout
    );
    assert!(
        !dry.stdout.contains(&open.display().to_string()),
        "the resumable one is not: {}",
        dry.stdout
    );
    assert!(closed.is_dir(), "a dry run removes nothing");

    let pruned = acp(state.path(), repo.path(), &["gc", "--closed"]);
    pruned.ok("acp gc --closed");
    assert!(
        pruned.stdout.contains("pruned 1 of 1"),
        "one worktree, pruned: {}",
        pruned.stdout
    );
    assert!(!closed.exists(), "the retired worktree is gone");
    assert!(open.is_dir(), "the resumable worktree is untouched");
    assert!(
        !acp(
            state.path(),
            repo.path(),
            &["status", "--json", &run.to_string()]
        )
        .stdout
        .is_empty(),
        "the log is still readable afterwards"
    );

    // Nothing left to do, and saying so is not an error.
    let empty = acp(state.path(), repo.path(), &["gc", "--closed"]);
    empty.ok("acp gc --closed, twice");
    assert!(
        empty.stdout.contains("no retired worktrees"),
        "{}",
        empty.stdout
    );
}

/// Two real git worktrees and the log that describes them: one lineage closed and retired, one
/// still open.
fn fixture_lineages(state: &Path, repo: &Path) -> (RunId, PathBuf, PathBuf) {
    let mut registry = Registry::open(state).expect("open the fixture state dir");
    let run = RunId::new_v4();
    let base = head_sha(repo);
    registry
        .append(
            &run,
            EventPayload::RunCreated {
                execution: None,
                repo_root: repo.to_path_buf(),
                state_dir: state.to_path_buf(),
                base_ref: "HEAD".to_string(),
                base_sha: base.clone(),
                task: loop_task("T44-gc"),
                version: 1,
                lead: None,
                team_name: None,
                steps: None,
            },
        )
        .expect("append run.created");

    let mut make = |short: &str| {
        let agent = AgentId::new_v4();
        let lineage = LineageId::new_v4();
        let path = repo
            .join(".acp/worktrees")
            .join(run.to_string())
            .join(short);
        let branch = format!("acp/{run}/{short}");
        let out = Command::new("git")
            .args(["worktree", "add", "-b", &branch])
            .arg(&path)
            .arg(&base)
            .current_dir(repo)
            .output()
            .expect("git worktree add");
        assert!(
            out.status.success(),
            "git worktree add: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        registry
            .append(
                &run,
                EventPayload::AgentCreated {
                    agent_id: agent,
                    role: RoleName::Builder,
                    provider: ProviderName::Claude,
                    model: "fable".to_string(),
                    lineage_id: Some(lineage),
                    depth: 1,
                    parent_agent_id: None,
                    origin: Origin::Lead,
                    writes: true,
                    cwd: path.clone(),
                    worktree: Some(path.clone()),
                },
            )
            .expect("append agent.created");
        registry
            .append(
                &run,
                EventPayload::WorktreeCreated {
                    agent_id: agent,
                    lineage_id: lineage,
                    path: path.clone(),
                    branch,
                    base_sha: base.clone(),
                },
            )
            .expect("append worktree.created");
        (agent, lineage, path)
    };

    let (closed_agent, closed_lineage, closed) = make("closed");
    let (_, _, open) = make("open");

    registry
        .append(
            &run,
            EventPayload::LineageClosed {
                lineage_id: closed_lineage,
                reason: "out of strikes after 2".to_string(),
            },
        )
        .expect("append lineage.closed");
    registry
        .append(
            &run,
            EventPayload::WorktreeRetired {
                path: closed.clone(),
                reason: "the lineage was closed after 2 strikes".to_string(),
                resumable: False,
            },
        )
        .expect("append worktree.retired");
    registry
        .append(
            &run,
            EventPayload::AgentStatusChanged {
                agent_id: closed_agent,
                status: AgentStatus::Closed,
                reason: Some("the lineage is out of strikes".to_string()),
            },
        )
        .expect("append agent.status");

    (run, closed, open)
}

// ---------------------------------------------------------------------------
// End to end: delegate over the socket, follow, approve from the CLI
// ---------------------------------------------------------------------------

/// The whole human path through the binary: a real daemon, a real loop against the fake provider
/// CLIs, `acp status --follow --json` streaming it, `acp gate approve` committing it, and
/// `acp serve --stop` taking the daemon down.
///
/// This is the test that cannot be faked: `gates::run_commit` re-freezes the worktree and refuses
/// unless it still hashes to the `diffHash` the reviewer echoed, so a sha printed by
/// `acp gate approve` proves the whole chain agreed — over the socket, from a separate process.
///
/// It is one test rather than three because a `pass` loop costs seconds to minutes; the pieces it
/// asserts (the follow stream, the approval, the stop) all need the same run behind them.
#[test]
fn the_cli_drives_a_pass_loop_from_delegate_to_an_approved_commit() {
    // `install_fake_clis` puts the wrapper CLIs on this process's `PATH`, which the daemon child
    // inherits; the shared guard is the harness's rule for touching the process environment.
    common::with_shared_env(|| async { pass_loop() });
}

fn pass_loop() {
    let state = short_dir();
    let repo = repo_with_exclude();
    install_fake_clis();
    configure_fakes(repo.path(), "pass", &[]);

    let mut daemon = Daemon::start(state.path(), repo.path());
    let follower = Follower::start(state.path(), repo.path());

    let task = loop_task("T44-cli");
    let mut wire = Wire::connect(&daemon.socket());
    let delegated = wire
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
        .unwrap_or_else(|err| panic!("delegate: {err}"));
    let run = delegated["runId"].as_str().expect("runId").to_string();
    let worktree = PathBuf::from(delegated["worktree"].as_str().expect("worktree"));

    // The loop starts the reviewer and opens the integrate gate by itself; `acp status --json` is
    // how a human watches that happen, and it works against a live daemon because it only reads.
    let mut gate = String::new();
    wait_for("the loop opened an integrate gate", LOOP_LIMIT, || {
        let status = acp(state.path(), repo.path(), &["status", "--json", &run]);
        let Ok(snapshot) = serde_json::from_str::<Value>(status.stdout.trim()) else {
            return false;
        };
        let found = snapshot["gates"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|g| g["kind"] == json!("integrate") && g["status"] == json!("pending"))
            .and_then(|g| g["gateId"].as_str().map(str::to_string));
        if let Some(found) = found {
            gate = found;
        }
        !gate.is_empty()
    });

    let approved = acp(state.path(), repo.path(), &["gate", "approve", &gate]);
    approved.ok("acp gate approve");
    let mut words = approved.stdout.split_whitespace();
    assert_eq!(words.next(), Some("approved"), "{}", approved.stdout);
    let sha = words.next().expect("the integration sha").to_string();
    assert_eq!(sha.len(), 40, "a full sha: {sha}");
    assert_eq!(
        head_sha(&worktree),
        sha,
        "the approval waited for the commit helper, and the commit is in the worktree"
    );

    let run_id: RunId = run.parse().expect("a run id");
    let committed = Registry::open(state.path())
        .expect("reopen the log")
        .events(&run_id, None, usize::MAX)
        .iter()
        .filter_map(|event| match &event.payload {
            EventPayload::IntegrateCommitted { sha, .. } => Some(sha.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        committed,
        vec![sha.clone()],
        "exactly one integrate.committed, and it is the sha the CLI printed"
    );

    // The follower has been streaming the whole time: every line is one event, and the commit is
    // among them.
    wait_for("the follower streamed integrate.committed", LIMIT, || {
        follower
            .events()
            .iter()
            .any(|event| event["kind"] == json!("integrate.committed"))
    });
    let streamed = follower.events();
    assert!(
        streamed
            .iter()
            .all(|event| event["kind"].is_string() && event["seq"].is_u64()),
        "every line is a whole event: {streamed:?}"
    );
    assert!(
        streamed
            .iter()
            .any(|event| event["kind"] == json!("gate.created")
                && event["gkind"] == json!("integrate")),
        "including the gate that was approved from another process"
    );
    drop(follower);

    let stop = acp(state.path(), repo.path(), &["serve", "--stop"]);
    stop.ok("acp serve --stop");
    assert_eq!(daemon.wait("after the loop"), Some(0));
    assert!(
        !state.path().join("acp.sock").exists() && !state.path().join("serve.lock").exists(),
        "the daemon cleaned up after itself"
    );
}

// ---------------------------------------------------------------------------
// Team configuration — every operation goes through the running daemon
// ---------------------------------------------------------------------------

/// The CLI is deliberately only a transport for the daemon-owned team layer: `get`, `set`, and
/// `roles` all require a live socket; validation and the atomic `team.json` write happen there.
/// This covers the human-facing rendering as well as the three wire method names.
#[test]
fn team_get_set_and_roles_are_thin_socket_clients() {
    let state = short_dir();
    let repo = repo_with_exclude();
    let mut daemon = Daemon::start(state.path(), repo.path());

    let empty = acp(state.path(), repo.path(), &["team", "get"]);
    empty.ok("acp team get without a team");
    assert_eq!(empty.stdout, "no team\n");

    let roles = acp(state.path(), repo.path(), &["team", "roles"]);
    roles.ok("acp team roles");
    let roles: Value = serde_json::from_str(&roles.stdout).expect("the catalog is JSON");
    assert!(
        roles["roles"]
            .as_array()
            .is_some_and(|roles| roles.iter().any(|role| role["name"] == json!("builder"))),
        "the daemon's spawnable roles are present: {roles}"
    );
    for provider in ["claude", "codex"] {
        assert!(roles["providers"][provider]["models"].is_array(), "{roles}");
        assert!(
            roles["providers"][provider]["available"].is_boolean(),
            "availability is probed on this call: {roles}"
        );
    }

    let candidate = state.path().join("candidate-team.json");
    let team = json!({
        "version": 1,
        "name": "T50 team",
        "lead": { "provider": "codex", "model": "gpt-5.5", "effort": "high" },
        "roles": {
            "builder": { "provider": "claude", "model": "sonnet" },
            "reviewer": { "provider": "codex", "model": "gpt-5.5", "effort": "xhigh" },
            "future_role": { "provider": "claude", "model": "haiku" }
        }
    });
    fs::write(
        &candidate,
        serde_json::to_vec_pretty(&team).expect("encode the candidate"),
    )
    .expect("write the candidate team");
    let candidate_arg = candidate.to_str().expect("UTF-8 fixture path");

    let set = acp(state.path(), repo.path(), &["team", "set", candidate_arg]);
    set.ok("acp team set");
    let set: Value = serde_json::from_str(&set.stdout).expect("the set result is JSON");
    assert_eq!(set["ok"], json!(true));
    assert_eq!(set["ignoredRoles"], json!(["future_role"]));
    assert!(
        state.path().join("team.json").is_file(),
        "the daemon wrote the file"
    );

    let get = acp(state.path(), repo.path(), &["team", "get"]);
    get.ok("acp team get");
    let got: Value = serde_json::from_str(&get.stdout).expect("the team is JSON");
    assert_eq!(got, team, "get echoes the daemon's persisted team");

    // Semantic issues come back from `team.set` as `team_invalid`, with every issue in the
    // server's message. The accepted file stays byte-for-byte untouched.
    let before = fs::read(state.path().join("team.json")).expect("the accepted team");
    let mut invalid = team.clone();
    invalid["roles"]["reviewer"]["model"] = json!("not-a-model");
    fs::write(
        &candidate,
        serde_json::to_vec_pretty(&invalid).expect("encode the invalid candidate"),
    )
    .expect("write the invalid candidate");
    let refused = acp(state.path(), repo.path(), &["team", "set", candidate_arg]);
    assert_eq!(refused.code, Some(1), "{}", refused.stdout);
    assert!(
        refused.stderr.contains("team_invalid")
            && refused.stderr.contains("model_not_in_provider")
            && refused.stderr.contains("model_not_allowed_for_role"),
        "the actionable issues reach stderr: {}",
        refused.stderr
    );
    assert_eq!(
        fs::read(state.path().join("team.json")).expect("the old team remains"),
        before,
        "a rejected set writes nothing"
    );

    // An existing newer or malformed file is never reported as "no team". These bytes emulate a
    // direct write by the app, which is why the bound/error checks cannot live only in the CLI.
    fs::write(state.path().join("team.json"), br#"{"version":4}"#).expect("write a newer team");
    let newer = acp(state.path(), repo.path(), &["team", "get"]);
    assert_eq!(newer.code, Some(1));
    assert!(
        newer.stderr.contains("team_unsupported_version") && newer.stderr.contains("version 4"),
        "the newer-version remedy is preserved: {}",
        newer.stderr
    );
    assert!(!newer.stdout.contains("no team"));

    fs::write(state.path().join("team.json"), b"{").expect("write malformed JSON");
    let malformed = acp(state.path(), repo.path(), &["team", "get"]);
    assert_eq!(malformed.code, Some(1));
    assert!(
        malformed.stderr.contains("team_invalid"),
        "a malformed existing file is an error: {}",
        malformed.stderr
    );
    assert!(!malformed.stdout.contains("no team"));

    fs::remove_file(state.path().join("team.json")).expect("remove the malformed fixture");
    fs::create_dir(state.path().join("team.json")).expect("put an unreadable object at team.json");
    let unreadable = acp(state.path(), repo.path(), &["team", "get"]);
    assert_eq!(unreadable.code, Some(1));
    assert!(
        unreadable.stderr.contains("team_io"),
        "I/O failures keep their wire code: {}",
        unreadable.stderr
    );

    daemon.signal(nix::sys::signal::Signal::SIGTERM);
    assert_eq!(daemon.wait("after the team commands"), Some(0));
}

// ---------------------------------------------------------------------------
// The other half of C3, and the client's version gate
// ---------------------------------------------------------------------------

/// Socket-only mode has no MCP lifetime to inherit: closed stdin is inert, while the existing
/// signal, lock and human stop paths remain exactly the daemon's normal ones.
#[test]
fn no_mcp_ignores_closed_stdin_preserves_the_lock_and_stops_both_ways() {
    let state = short_dir();
    let repo = repo_with_exclude();
    let mut daemon = Daemon::start_no_mcp(state.path(), repo.path());
    let (lock, socket) = (daemon.lock(), daemon.socket());

    let second = acp(state.path(), repo.path(), &["serve"]);
    assert_eq!(second.code, Some(3), "{}", second.stderr);
    assert!(
        second.stderr.contains("already running"),
        "the shared serve lock still arbitrates both modes: {}",
        second.stderr
    );

    daemon.signal(nix::sys::signal::Signal::SIGTERM);
    assert_eq!(daemon.wait("after SIGTERM in --no-mcp mode"), Some(0));
    assert!(!lock.exists() && !socket.exists());
    assert!(
        daemon.stdout().is_empty(),
        "socket-only mode never writes to stdout: {}",
        daemon.stdout()
    );

    let mut daemon = Daemon::start_no_mcp(state.path(), repo.path());
    let (lock, socket) = (daemon.lock(), daemon.socket());
    acp(state.path(), repo.path(), &["serve", "--stop"]).ok("serve --stop against --no-mcp");
    assert_eq!(daemon.wait("after serve --stop in --no-mcp mode"), Some(0));
    assert!(!lock.exists() && !socket.exists());
    assert!(
        daemon.stdout().is_empty(),
        "socket-only mode never writes to stdout: {}",
        daemon.stdout()
    );
}

/// MCP stdin EOF is the second C3 trigger: the lead hung up, so the daemon stops.
///
/// This is the branch a signal test cannot reach. `serve` runs the MCP server on stdio, and when
/// that transport ends there is no lead left to serve — the design puts it beside SIGINT/SIGTERM
/// ("`tokio::signal` SIGINT/SIGTERM **and** MCP stdin EOF both trigger a `CancellationToken`"), and
/// it must clean up exactly the same way.
#[test]
fn closing_the_mcp_stdin_shuts_the_daemon_down_cleanly() {
    let state = short_dir();
    let repo = repo_with_exclude();
    let mut daemon = Daemon::start(state.path(), repo.path());
    let (lock, socket) = (daemon.lock(), daemon.socket());
    assert!(lock.exists() && socket.exists());

    daemon.close_stdin();

    assert_eq!(
        daemon.wait("after the MCP peer hung up"),
        Some(0),
        "stdin EOF is a clean stop, not a failure"
    );
    assert!(
        !lock.exists(),
        "the lock is unlinked on the stdin-EOF path too"
    );
    assert!(!socket.exists(), "and so is the socket file");
}

/// A daemon speaking a protocol this build does not know is refused, not guessed at.
///
/// The contract says so in as many words ("a client that receives an unknown version must refuse to
/// drive the daemon rather than guess"), and the only way to test it is to *be* such a daemon: a
/// hand-written listener on the socket path that answers `hello` with a version from the future.
#[test]
fn a_client_refuses_a_daemon_whose_protocol_it_does_not_know() {
    let state = short_dir();
    let repo = repo_with_exclude();
    let socket = state.path().join("acp.sock");

    for args in [
        vec!["status", "--follow", "--json"],
        vec!["gate", "approve", "00000000-0000-4000-8000-000000000000"],
        vec!["team", "roles"],
    ] {
        let _ = fs::remove_file(&socket);
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind a fake daemon");
        let server = std::thread::spawn(move || {
            // One connection is all the test makes; answering it and hanging up is the whole server.
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let request: Value = serde_json::from_str(&line).expect("the client sent JSON");
            assert_eq!(
                request["method"],
                json!("hello"),
                "hello comes first: {request}"
            );
            assert_eq!(
                request["params"]["clientName"],
                json!("cli"),
                "every CLI socket command identifies the human door"
            );
            let mut writer = stream;
            let reply = json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": { "protocolVersion": 999, "serverVersion": "9.9.9", "pid": 1 },
            });
            let _ = writeln!(writer, "{reply}");
        });

        let refused = acp(state.path(), repo.path(), &args);
        assert_eq!(refused.code, Some(1), "{args:?}: {}", refused.stdout);
        assert!(
            refused.stderr.contains("999") && refused.stderr.contains("refusing to drive"),
            "{args:?} names the version it will not speak: {}",
            refused.stderr
        );
        assert!(
            refused.stdout.is_empty(),
            "{args:?} printed nothing it could not stand behind: {}",
            refused.stdout
        );
        server.join().expect("the fake future daemon did not panic");
    }
}

// ---------------------------------------------------------------------------
// One daemon per state dir, under contention
// ---------------------------------------------------------------------------

/// Many starts at once, exactly one daemon.
///
/// The lock is a `flock`, not a file that exists: the kernel picks one winner out of any number of
/// simultaneous racers. The previous shape — `create_new` plus a liveness check on the recorded pid
/// — could not survive this, because two starts can both read a stale record, both judge it dead,
/// and both unlink and re-create, with the second deleting the first's *live* lock. That leaves two
/// daemons appending to one event log, which is the failure this test exists to make impossible.
#[test]
fn eighty_simultaneous_starts_leave_exactly_one_daemon() {
    const RACERS: usize = 80;

    let state = short_dir();
    let repo = repo_with_exclude();
    let lock = state.path().join("serve.lock");

    let mut racers: Vec<Child> = (0..RACERS)
        .map(|n| {
            Command::new(ACP)
                .arg("serve")
                .current_dir(repo.path())
                .env("ACP_STATE_DIR", state.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::from(file(&state.path().join(format!("r{n}.out")))))
                .stderr(Stdio::from(file(&state.path().join(format!("r{n}.err")))))
                .spawn()
                .unwrap_or_else(|err| panic!("spawn racer {n}: {err}"))
        })
        .collect();

    // Everyone but the winner must be gone, and gone with code 3.
    let mut alive: Vec<usize> = Vec::new();
    wait_for("all but one racer exited", LIMIT, || {
        alive = racers
            .iter_mut()
            .enumerate()
            .filter_map(|(n, child)| {
                child
                    .try_wait()
                    .expect("wait on a racer")
                    .is_none()
                    .then_some(n)
            })
            .collect();
        alive.len() <= 1
    });
    assert_eq!(alive.len(), 1, "exactly one racer is still running");
    let winner = alive[0];

    for (n, child) in racers.iter_mut().enumerate() {
        if n == winner {
            continue;
        }
        let code = child
            .try_wait()
            .expect("wait")
            .expect("already exited")
            .code();
        assert_eq!(
            code,
            Some(3),
            "racer {n} lost the lock and must say so with 3, not {code:?}: {}",
            read(&state.path().join(format!("r{n}.err")))
        );
    }

    // The survivor is the process the lock file names, and it is really serving.
    wait_for("the winner wrote its record", LIMIT, || {
        read(&lock).contains("pid")
    });
    let record: Value = serde_json::from_str(read(&lock).trim()).expect("a lock record");
    assert_eq!(
        record["pid"],
        json!(racers[winner].id()),
        "the lock names the one daemon that is running"
    );
    assert!(Wire::try_connect(&state.path().join("acp.sock")).is_some());

    // And it stops cleanly, releasing what it held.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(racers[winner].id()).expect("a pid")),
        nix::sys::signal::Signal::SIGTERM,
    )
    .expect("signal the winner");
    let status = racers[winner].wait().expect("reap the winner");
    assert_eq!(status.code(), Some(0));
    assert!(!lock.exists(), "the winner unlinked its lock");
}

// ---------------------------------------------------------------------------
// A linked worktree
// ---------------------------------------------------------------------------

/// `serve` starts in a **linked worktree**, where `.git` is a file.
///
/// The exclude entry is found — and, since T91, written — through `git rev-parse --git-path`, so
/// it lands in the file git itself reads — the main repository's — instead of a
/// `<worktree>/.git/info/exclude` that does not exist. Before `--git-path`, the start refused here
/// unconditionally, with a remedy pointing at a path no git command would ever consult.
#[test]
fn serve_starts_inside_a_linked_worktree() {
    let state = short_dir();
    let main = temp_git_repo();
    let linked = main.path().join("side");
    let out = Command::new("git")
        .args(["worktree", "add", "-q", "-b", "side"])
        .arg(&linked)
        .current_dir(main.path())
        .output()
        .expect("git worktree add");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        linked.join(".git").is_file(),
        "a linked worktree's .git is a file"
    );

    // Without the entry, serve writes it into the file git reads — the *main* repo's — and
    // then runs bound to the worktree.
    let main_exclude = main.path().join(".git").join("info").join("exclude");
    let mut daemon = Daemon::start_at(state.path(), &linked);
    assert!(
        fs::read_to_string(&main_exclude)
            .expect("the main repository's exclude")
            .lines()
            .any(|line| line.trim() == ".acp/"),
        "the entry went into the main git dir"
    );
    assert!(
        linked.join(".git").is_file(),
        "the worktree's .git is still a file: nothing was invented beside it"
    );
    let mut wire = Wire::connect(&daemon.socket());
    let hello = wire.call("hello", json!({})).expect("hello");
    assert_eq!(
        hello["repoRoot"].as_str().map(PathBuf::from),
        Some(fs::canonicalize(&linked).expect("canonical worktree")),
        "the daemon bound the worktree it was started in, not the main repository"
    );

    daemon.signal(nix::sys::signal::Signal::SIGTERM);
    assert_eq!(daemon.wait("after the worktree run"), Some(0));
}

// ---------------------------------------------------------------------------
// Restart: a worker that outlived its daemon
// ---------------------------------------------------------------------------

/// A daemon stopped mid-attempt, a worker that keeps running, and a second daemon that picks it up.
///
/// This is the design's central restart claim end to end, across two real processes: "workers
/// survive; a restart re-attaches". The first daemon is signalled while its builder is still
/// streaming; the worker — a detached process in its own process group — carries on writing into
/// `stdout.jsonl`. The second daemon replays the log, finds an attempt still marked `running`, and
/// re-adopts it: tails from the recorded offset, re-arms the deadline, finalizes it, and drives the
/// rest of the loop to the integrate gate.
///
/// Without the re-attach the second daemon serves happily and that attempt stays `running`
/// **forever** — untailed, untimed, never finalized — and the run behind it never moves again. The
/// assertions below are ordered so that a vacuous pass is impossible: the attempt is proved still
/// running (and its worker still alive) *after* the first daemon is gone, before the second starts.
#[test]
fn a_second_daemon_re_attaches_a_worker_that_outlived_the_first() {
    common::with_shared_env(|| async { restart_re_attach() });
}

fn restart_re_attach() {
    let state = short_dir();
    let repo = repo_with_exclude();
    install_fake_clis();
    // Slow enough that the builder is provably mid-stream when its daemon is stopped, and still
    // quick enough to finish the whole loop inside the bound.
    configure_fakes(repo.path(), "pass", &[("ACP_FAKE_DELAY_MS", "1200")]);

    let mut first = Daemon::start(state.path(), repo.path());
    let task = loop_task("T44-restart");
    let mut wire = Wire::connect(&first.socket());
    let delegated = wire
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
        .unwrap_or_else(|err| panic!("delegate: {err}"));
    let run = delegated["runId"].as_str().expect("runId").to_string();
    let attempt = delegated["attemptId"]
        .as_str()
        .expect("attemptId")
        .to_string();
    drop(wire);

    // The worker is up: the log knows its pid.
    let mut worker = 0;
    wait_for("the builder attempt started", LIMIT, || {
        worker = running_attempt_pid(state.path(), repo.path(), &run, &attempt).unwrap_or(0);
        worker > 0
    });

    first.signal(nix::sys::signal::Signal::SIGTERM);
    assert_eq!(first.wait("the first daemon"), Some(0));
    assert!(
        !state.path().join("serve.lock").exists(),
        "the first daemon released its lock, so a second can start"
    );

    // The two facts the restart depends on, checked while nothing is serving.
    assert_eq!(
        running_attempt_pid(state.path(), repo.path(), &run, &attempt),
        Some(worker),
        "the attempt is still `running` in the log — a finished one would make this test vacuous"
    );
    assert!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(worker), None).is_ok(),
        "the worker outlived the daemon that started it (C3: workers survive)"
    );

    let mut second = Daemon::start(state.path(), repo.path());
    let mut gate = String::new();
    wait_for(
        "the re-attached attempt finished and the loop reached an integrate gate",
        LOOP_LIMIT,
        || {
            let status = acp(state.path(), repo.path(), &["status", "--json", &run]);
            let Ok(snapshot) = serde_json::from_str::<Value>(status.stdout.trim()) else {
                return false;
            };
            if let Some(found) = snapshot["gates"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|g| g["kind"] == json!("integrate") && g["status"] == json!("pending"))
                .and_then(|g| g["gateId"].as_str().map(str::to_string))
            {
                gate = found;
            }
            !gate.is_empty()
        },
    );

    // The re-attached attempt was finalized from its own transcript, not abandoned.
    let snapshot = acp(state.path(), repo.path(), &["status", "--json", &run]);
    let snapshot: Value = serde_json::from_str(snapshot.stdout.trim()).expect("JSON");
    let builder = snapshot["attempts"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["attemptId"] == json!(attempt))
        .expect("the first attempt is still in the log");
    assert_eq!(
        builder["status"],
        json!("succeeded"),
        "the second daemon read the rest of the transcript: {builder}"
    );
    assert!(
        second.stderr().is_empty() || !second.stderr().contains("panic"),
        "the second daemon did not panic: {}",
        second.stderr()
    );

    let approved = acp(state.path(), repo.path(), &["gate", "approve", &gate]);
    approved.ok("acp gate approve, after a restart");
    assert!(
        approved.stdout.starts_with("approved "),
        "and the work is integrable: {}",
        approved.stdout
    );

    let stop = acp(state.path(), repo.path(), &["serve", "--stop"]);
    stop.ok("acp serve --stop");
    assert_eq!(second.wait("the second daemon"), Some(0));
}

/// The pid of `attempt` while the log still calls it `running`, read through the CLI itself.
fn running_attempt_pid(state: &Path, repo: &Path, run: &str, attempt: &str) -> Option<i32> {
    let status = acp(state, repo, &["status", "--json", run]);
    let snapshot: Value = serde_json::from_str(status.stdout.trim()).ok()?;
    let found = snapshot["attempts"]
        .as_array()?
        .iter()
        .find(|a| a["attemptId"] == json!(attempt))?;
    (found["status"] == json!("running"))
        .then(|| {
            found["pid"]
                .as_i64()
                .and_then(|pid| i32::try_from(pid).ok())
        })
        .flatten()
}

// ---------------------------------------------------------------------------
// Track E — the four socket verbs (T70/T71)
// ---------------------------------------------------------------------------

/// `delegate` → polled `await` → `cancel` on a finished agent, all through the shell verbs. One
/// test for the same reason as the pass loop above: the pieces need one live loop behind them.
#[test]
fn delegate_and_await_drive_the_loop_and_cancel_reports_already_finished() {
    common::with_shared_env(|| async { verbs_pass_loop() });
}

fn verbs_pass_loop() {
    let state = short_dir();
    let repo = repo_with_exclude();
    install_fake_clis();
    configure_fakes(repo.path(), "pass", &[]);
    let mut _daemon = Daemon::start(state.path(), repo.path());

    // Every task field travels: the flags are the wire task, nothing invented downstream.
    let delegated = acp(
        state.path(),
        repo.path(),
        &[
            "delegate",
            "--role",
            "builder",
            "--task-id",
            "T70-verbs",
            "--title",
            "Add src/adder.ts exporting add(a, b).",
            "--file",
            "src/adder.ts",
            "--accept",
            "add(1, 2) === 3",
            "Add src/adder.ts exporting add(a, b).",
        ],
    );
    delegated.ok("acp delegate");
    let out: Value = serde_json::from_str(delegated.stdout.trim()).expect("delegate JSON");
    let agent = out["agentId"].as_str().expect("agentId").to_string();
    assert!(out["runId"].is_string(), "runId in {out}");
    assert!(out["attemptId"].is_string(), "attemptId in {out}");
    assert!(out["worktree"].is_string(), "worktree in {out}");

    // `await` is one bounded socket call; the loop is the caller's. Right after `delegate` the
    // daemon may still be preparing the worktree and recording the attempt, so
    // `resume_target_missing` is a transient answer here — the same retry the skill documents.
    // `running` is valid on the way; `done` carries the envelope.
    let mut envelope = Value::Null;
    wait_for("await reached the builder's envelope", LOOP_LIMIT, || {
        let waited = acp(
            state.path(),
            repo.path(),
            &["await", &agent, "--timeout-sec", "30"],
        );
        if waited.code != Some(0) {
            assert!(
                waited.stderr.contains("resume_target_missing"),
                "await failed for a non-transient reason: {}",
                waited.stderr
            );
            return false;
        }
        let value: Value = serde_json::from_str(waited.stdout.trim()).expect("await JSON");
        match value["status"].as_str() {
            Some("done") => {
                envelope = value["envelope"].clone();
                true
            }
            Some("running") => false,
            other => panic!("await answered {other:?}: {value}"),
        }
    });
    assert_eq!(
        envelope["agentId"].as_str(),
        Some(agent.as_str()),
        "the envelope names the awaited agent: {envelope}"
    );

    // The builder's attempt is finished, whatever the wider loop is doing — cancel says so
    // rather than pretending to have stopped anything.
    let cancelled = acp(state.path(), repo.path(), &["cancel", &agent]);
    cancelled.ok("acp cancel");
    let cancel_out: Value = serde_json::from_str(cancelled.stdout.trim()).expect("cancel JSON");
    assert_eq!(cancel_out["status"], json!("already_finished"));
}

/// The deterministic half, against a hanging builder: `await` answers `running`, `cancel`
/// actually cancels, a follow-up `send` to the now-idle resumable agent is **accepted** (the
/// design's send round-trip), and a second `cancel` cleans that attempt up too. Cancelled is
/// `Branch::None` — no strike, no auto-resume — so nothing survives the test. `send` is never
/// raced against a running attempt on purpose: builders have no in-flight send guard
/// (`check_send_message` scopes the busy refusal to leads), so ordering after `cancel` is the
/// only deterministic shape.
#[test]
fn cancel_cancels_the_hanging_builder_and_send_resumes_it() {
    common::with_shared_env(|| async { verbs_hang() });
}

fn verbs_hang() {
    let state = short_dir();
    let repo = repo_with_exclude();
    install_fake_clis();
    configure_fakes(repo.path(), "hang", &[]);
    let mut _daemon = Daemon::start(state.path(), repo.path());

    let delegated = acp(
        state.path(),
        repo.path(),
        &[
            "delegate",
            "--role",
            "builder",
            "--accept",
            "add(1, 2) === 3",
            "Add src/adder.ts exporting add(a, b).",
        ],
    );
    delegated.ok("acp delegate (hang)");
    let out: Value = serde_json::from_str(delegated.stdout.trim()).expect("delegate JSON");
    let agent = out["agentId"].as_str().expect("agentId").to_string();
    let run_id = out["runId"].as_str().expect("runId").to_string();

    // Poll through the transient post-delegate window (`resume_target_missing` while the daemon
    // prepares the worktree and records the attempt), then the hanging attempt answers `running`
    // deterministically.
    wait_for(
        "await answered `running` for the hanging builder",
        LIMIT,
        || {
            let waited = acp(
                state.path(),
                repo.path(),
                &["await", &agent, "--timeout-sec", "1"],
            );
            if waited.code != Some(0) {
                assert!(
                    waited.stderr.contains("resume_target_missing"),
                    "await failed for a non-transient reason: {}",
                    waited.stderr
                );
                return false;
            }
            let value: Value = serde_json::from_str(waited.stdout.trim()).expect("await JSON");
            assert_eq!(value["status"], json!("running"), "{value}");
            true
        },
    );

    // Before anything is cancelled, wait until the worker's `system/init` line has been drained
    // and the session id is on record: a worker killed mid-startup would never become resumable,
    // and the later `send` would burn its whole bound on a refusal that is not transient at all.
    wait_for("the builder's provider session is on record", LIMIT, || {
        let status = acp(state.path(), repo.path(), &["status", "--json"]);
        let Ok(snapshot) = serde_json::from_str::<Value>(status.stdout.trim()) else {
            return false;
        };
        snapshot["agents"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|a| a["agentId"] == json!(agent) && a["resumable"] == json!(true))
    });

    let cancelled = acp(state.path(), repo.path(), &["cancel", &agent]);
    cancelled.ok("acp cancel (hanging)");
    let cancel_out: Value = serde_json::from_str(cancelled.stdout.trim()).expect("cancel JSON");
    assert_eq!(cancel_out["status"], json!("cancelled"));
    wait_for("the cancelled attempt is durable", LIMIT, || {
        cancelled_attempts(state.path(), repo.path(), &run_id) == 1
    });

    // With the session recorded and the agent idle, `send` is one hard call: accepted, resumed.
    let sent = acp(
        state.path(),
        repo.path(),
        &["send", &agent, "One more thing."],
    );
    sent.ok("acp send (resumable)");
    let resumed: Value = serde_json::from_str(sent.stdout.trim()).expect("send JSON");
    assert_eq!(resumed["accepted"], json!(true), "{resumed}");
    assert!(resumed["attemptId"].is_string(), "{resumed}");

    // The resumed hang is a second live worker; cancel it too, so the log ends with exactly two
    // cancelled attempts and no survivor.
    wait_for("the resumed attempt was cancelled", LIMIT, || {
        let cancelled = acp(state.path(), repo.path(), &["cancel", &agent]);
        cancelled.ok("acp cancel (resumed)");
        let out: Value = serde_json::from_str(cancelled.stdout.trim()).expect("cancel JSON");
        // `already_finished` here means the resume has not started yet — cancel again once it has.
        out["status"] == json!("cancelled")
            || cancelled_attempts(state.path(), repo.path(), &run_id) == 2
    });
    wait_for("both cancellations are durable", LIMIT, || {
        cancelled_attempts(state.path(), repo.path(), &run_id) == 2
    });
}

/// How many of the run's attempts the durable log calls `cancelled`, via the CLI itself.
fn cancelled_attempts(state: &Path, repo: &Path, run_id: &str) -> usize {
    let status = acp(state, repo, &["status", "--json"]);
    let Ok(snapshot) = serde_json::from_str::<Value>(status.stdout.trim()) else {
        return 0;
    };
    snapshot["attempts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|a| a["runId"] == json!(run_id) && a["status"] == json!("cancelled"))
        .count()
}

/// Every refusal reaches the shell as a code and a non-zero exit — and no daemon at all is its
/// own honest error, naming the socket that is not there.
#[test]
fn the_verbs_surface_refusal_codes_and_a_missing_daemon() {
    common::with_shared_env(|| async { verbs_refusals() });
}

fn verbs_refusals() {
    let state = short_dir();
    let repo = repo_with_exclude();
    install_fake_clis();
    let mut _daemon = Daemon::start(state.path(), repo.path());
    let nobody = "aaaaaaaa-1111-4a11-8a11-aaaaaaaaaaaa";

    // A role outside the door's closed enum dies in params parsing, naming the stranger.
    let role = acp(
        state.path(),
        repo.path(),
        &[
            "delegate",
            "--role",
            "scribe",
            "--accept",
            "never spawns",
            "This delegation must be refused by the role enum.",
        ],
    );
    assert_ne!(role.code, Some(0));
    assert!(role.stderr.contains("scribe"), "{}", role.stderr);

    // A malformed task id is a policy refusal with its code.
    let task_id = acp(
        state.path(),
        repo.path(),
        &[
            "delegate",
            "--role",
            "builder",
            "--task-id",
            "bad id!",
            "--accept",
            "never spawns",
            "This delegation must be refused by the task id shape.",
        ],
    );
    assert_ne!(task_id.code, Some(0));
    assert!(
        task_id.stderr.contains("rejected (invalid_task)"),
        "{}",
        task_id.stderr
    );

    // The await bound is the daemon's, verbatim.
    let bound = acp(
        state.path(),
        repo.path(),
        &["await", nobody, "--timeout-sec", "0"],
    );
    assert_ne!(bound.code, Some(0));
    assert!(
        bound.stderr.contains("timeoutSec must be"),
        "{}",
        bound.stderr
    );

    // A send to an agent the log has never heard of is a policy refusal with its code.
    let stranger = acp(
        state.path(),
        repo.path(),
        &["send", nobody, "Anyone there?"],
    );
    assert_ne!(stranger.code, Some(0));
    assert!(
        stranger.stderr.contains("rejected (agent_not_resumable)"),
        "{}",
        stranger.stderr
    );

    // Zero `--accept` never reaches the socket: clap refuses with a usage line.
    let usage = acp(
        state.path(),
        repo.path(),
        &[
            "delegate",
            "--role",
            "builder",
            "This delegation must be refused before any socket traffic.",
        ],
    );
    assert_ne!(usage.code, Some(0));
    assert!(usage.stderr.contains("--accept"), "{}", usage.stderr);

    // And with no daemon: the connect error names what is missing.
    let empty = short_dir();
    let missing = acp(empty.path(), repo.path(), &["cancel", nobody]);
    assert_ne!(missing.code, Some(0));
    assert!(
        missing.stderr.contains("no acp serve running"),
        "{}",
        missing.stderr
    );
}

// ---------------------------------------------------------------------------
// B3 — `acp up` / `acp down` (T78/T79)
// ---------------------------------------------------------------------------

/// One lifecycle, four claims: `up` starts a daemon that outlives it, a second `up` is the
/// idempotent "already running" answer, a stale lock left by a dead process does not stop it,
/// and `down` stops what `up` started, unlinking the lock and the socket.
#[test]
fn up_starts_a_detached_daemon_idempotently_and_down_stops_it() {
    common::with_shared_env(|| async { up_lifecycle() });
}

fn up_lifecycle() {
    let state = short_dir();
    let repo = repo_with_exclude();
    install_fake_clis();

    /// An early panic must not strand the detached daemon: `down` runs whatever happens.
    struct DownGuard(std::path::PathBuf, std::path::PathBuf);
    impl Drop for DownGuard {
        fn drop(&mut self) {
            let _ = Command::new(ACP)
                .args(["down"])
                .current_dir(&self.1)
                .env("ACP_STATE_DIR", &self.0)
                .output();
        }
    }
    let _guard = DownGuard(state.path().to_path_buf(), repo.path().to_path_buf());

    // A stale lock — a file nothing holds, whatever its record claims — must not stop `up`.
    fs::write(
        state.path().join("serve.lock"),
        br#"{"pid":99999999,"startedAt":"then","lstart":"then","repoRoot":"/x","version":"0"}"#,
    )
    .expect("write a stale lock");

    let first = acp(state.path(), repo.path(), &["up", "--managed"]);
    first.ok("acp up");
    assert!(
        first.stdout.starts_with("started acp serve (pid "),
        "{}",
        first.stdout
    );

    // The daemon is not `up`'s child: `up` has exited, and the socket still answers.
    wait_for("the detached daemon answers hello", LIMIT, || {
        Wire::try_connect(&state.path().join("acp.sock")).is_some()
    });

    let lifecycle = acp(state.path(), repo.path(), &["session", "status"]);
    lifecycle.ok("managed status");
    assert_eq!(serde_json::from_str::<Value>(&lifecycle.stdout).unwrap()["managed"], true);
    let again = acp(state.path(), repo.path(), &["up"]);
    again.ok("acp up, again");
    assert!(
        again.stdout.starts_with("already running (pid "),
        "{}",
        again.stdout
    );

    let down = acp(state.path(), repo.path(), &["down"]);
    down.ok("acp down");
    assert!(down.stdout.contains("stopped acp serve"), "{}", down.stdout);
    assert!(
        !state.path().join("serve.lock").exists(),
        "the lock survived `down`"
    );
    assert!(
        !state.path().join("acp.sock").exists(),
        "the socket survived `down`"
    );
}

/// B3 (T77): `acp plan` — a cyclic document is refused with `invalid_plan`, and a well-formed
/// one starts a container run through the same socket the app uses.
#[test]
fn plan_submits_a_document_and_refuses_a_cycle() {
    common::with_shared_env(|| async { plan_door() });
}

#[test]
fn audit_cli_captures_existing_work_and_finishes_without_integration() {
    common::with_shared_env(|| async {
        let state = short_dir();
        let repo = repo_with_exclude();
        install_fake_clis();
        configure_fakes(repo.path(), "pass", &[]);
        fs::write(repo.path().join(".git/info/exclude"), ".acp/\n.acp-fake-*\n").unwrap();
        fs::write(repo.path().join("existing.txt"), "selected existing change\n").unwrap();
        let before = head_sha(repo.path());
        let mut daemon = Daemon::start_no_mcp(state.path(), repo.path());
        let team = state.path().join("chosen-team.json");
        fs::write(&team, serde_json::to_vec(&json!({"version":3,"mode":"audit","name":"Audit",
            "roles":{"verifier":{"provider":"claude","model":"haiku"},
                     "reviewer":{"provider":"codex","model":"gpt-5.5"}}})).unwrap()).unwrap();
        acp(state.path(), repo.path(), &["team", "set", team.to_str().unwrap()]).ok("set audit team");
        let input = state.path().join("audit-input.json");
        fs::write(&input, serde_json::to_vec(&json!({"task":loop_task("cli-audit"),
            "selection":{"baseRef":"HEAD","target":{"kind":"workingTree"}}})).unwrap()).unwrap();
        let output = acp(state.path(), repo.path(), &["audit", input.to_str().unwrap()]);
        output.ok("acp audit");
        let result: Value = serde_json::from_str(&output.stdout).unwrap();
        let run: RunId = result["runId"].as_str().unwrap().parse().unwrap();
        wait_for("audit terminal", LOOP_LIMIT, || {
            Registry::open(state.path()).unwrap().run(&run).is_some_and(|r|
                r.status != agent_control_plane::core::types::RunStatus::Running)
        });
        let reg = Registry::open(state.path()).unwrap();
        let record = reg.run(&run).unwrap();
        assert_eq!(record.status, agent_control_plane::core::types::RunStatus::Completed);
        assert_eq!(record.audit.as_ref().unwrap().checks.len(), 2);
        assert!(record.gate_ids.is_empty());
        assert!(record.lineages.is_empty());
        assert_eq!(head_sha(repo.path()), before);
        assert_eq!(fs::read_to_string(repo.path().join("existing.txt")).unwrap(), "selected existing change\n");
        acp(state.path(), repo.path(), &["stop"]).ok("safe stop after audit");
        assert_eq!(daemon.wait("audit owner stops"), Some(0));
        assert!(!daemon.socket().exists());
        assert!(!daemon.lock().exists());
    });
}

fn plan_door() {
    let state = short_dir();
    let repo = repo_with_exclude();
    install_fake_clis();
    configure_fakes(repo.path(), "pass", &[]);
    let mut _daemon = Daemon::start(state.path(), repo.path());

    let cyclic = state.path().join("cyclic-plan.json");
    fs::write(
        &cyclic,
        serde_json::to_vec(&serde_json::json!({
            "version": 1, "name": "cycle", "items": [
                { "id": "a", "kind": "work", "after": ["b"],
                  "task": { "id": "Ta", "title": "t", "description": "a long enough description",
                            "files": [], "acceptance": ["done"] } },
                { "id": "b", "kind": "work", "after": ["a"],
                  "task": { "id": "Tb", "title": "t", "description": "a long enough description",
                            "files": [], "acceptance": ["done"] } }
            ]
        }))
        .expect("encode"),
    )
    .expect("write the cyclic plan");
    let refused = acp(
        state.path(),
        repo.path(),
        &["plan", cyclic.to_str().expect("utf8")],
    );
    assert_ne!(refused.code, Some(0));
    assert!(
        refused.stderr.contains("rejected (invalid_plan)") && refused.stderr.contains("cycle"),
        "{}",
        refused.stderr
    );

    let good = state.path().join("good-plan.json");
    fs::write(
        &good,
        serde_json::to_vec(&serde_json::json!({
            "version": 1, "name": "one step", "items": [
                { "id": "only", "kind": "work",
                  "task": { "id": "T77-plan", "title": "Add src/adder.ts exporting add(a, b).",
                            "description": "Add src/adder.ts exporting add(a, b).",
                            "files": ["src/adder.ts"], "acceptance": ["add(1, 2) === 3"] } }
            ]
        }))
        .expect("encode"),
    )
    .expect("write the plan");
    let accepted = acp(
        state.path(),
        repo.path(),
        &["plan", good.to_str().expect("utf8")],
    );
    accepted.ok("acp plan");
    let out: Value = serde_json::from_str(accepted.stdout.trim()).expect("plan JSON");
    let container = out["runId"]
        .as_str()
        .expect("a container run id")
        .to_string();

    // The container is a real run the human can watch; its item reaches an integrate gate that
    // `acp gate approve` lands, exactly like any other run.
    let mut gate = String::new();
    wait_for("the item's integrate gate opened", LOOP_LIMIT, || {
        let status = acp(state.path(), repo.path(), &["status", "--json"]);
        let Ok(snapshot) = serde_json::from_str::<Value>(status.stdout.trim()) else {
            return false;
        };
        let found = snapshot["gates"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|g| g["kind"] == json!("integrate") && g["status"] == json!("pending"))
            .and_then(|g| g["gateId"].as_str().map(str::to_string));
        if let Some(found) = found {
            gate = found;
        }
        !gate.is_empty()
    });
    acp(state.path(), repo.path(), &["gate", "approve", &gate]).ok("approve the item");
    wait_for("the container concluded", LOOP_LIMIT, || {
        let status = acp(state.path(), repo.path(), &["status", "--json", &container]);
        let Ok(snapshot) = serde_json::from_str::<Value>(status.stdout.trim()) else {
            return false;
        };
        snapshot["runs"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|r| r["runId"] == json!(container) && r["status"] == json!("integrated"))
    });
}


#[test]
fn session_handles_and_safe_stop_roundtrip_without_converting_external_owner() {
    common::with_shared_env(|| async {
        let state = short_dir();
        let repo = repo_with_exclude();
        let mut daemon = Daemon::start(state.path(), repo.path());
        acp(state.path(), repo.path(), &["up", "--managed"]).ok("attach managed to external");
        let mut wire = Wire::connect(&daemon.socket());
        let a = wire.call("session.acquire", json!({"label":"codex"})).unwrap();
        let b = wire.call("session.acquire", json!({"label":"claude"})).unwrap();
        assert_eq!(a["managed"], false, "external lifetime must remain unchanged");
        assert_ne!(a["sessionId"], b["sessionId"]);
        assert_eq!(b["sessions"], 2);
        let handle = json!({"instanceId":a["instanceId"], "sessionId":a["sessionId"]});
        wire.call("session.renew", handle.clone()).unwrap();
        wire.call("session.release", handle.clone()).unwrap();
        wire.call("session.release", handle.clone()).unwrap();
        let err = wire.call("session.renew", handle).unwrap_err();
        assert_eq!(err["data"]["code"], "session_expired");
        let wrong = json!({"instanceId":uuid::Uuid::new_v4().to_string(), "sessionId":b["sessionId"]});
        assert_eq!(wire.call("session.release", wrong).unwrap_err()["data"]["code"], "daemon_restarted");
        let stop = acp(state.path(), repo.path(), &["stop"]);
        stop.ok("safe stop returns its acknowledgement");
        assert!(stop.stdout.contains("when_idle"));
        assert_eq!(daemon.wait("safe stop"), Some(0));
        assert!(!daemon.socket().exists());
        assert!(!daemon.lock().exists());
    });
}

#[test]
fn closing_last_host_stops_managed_owner_and_preserves_history_across_restart() {
    common::with_shared_env(|| async {
        let state = short_dir();
        let repo = repo_with_exclude();
        let mut daemon = Daemon::start_with_lifetime(state.path(), repo.path(), true, true);
        // This empty audit produces durable history without any provider process.
        let team = state.path().join("chosen-team.json");
        fs::write(&team, serde_json::to_vec(&json!({"version":3,"mode":"audit","name":"History",
            "roles":{"reviewer":{"provider":"codex","model":"gpt-5.5"}}})).unwrap()).unwrap();
        acp(state.path(), repo.path(), &["team", "set", team.to_str().unwrap()]).ok("set team");
        let input = state.path().join("input.json");
        fs::write(&input, serde_json::to_vec(&json!({"task":loop_task("close-history"),
            "selection":{"baseRef":"HEAD","target":{"kind":"workingTree"}}})).unwrap()).unwrap();
        let run = acp(state.path(), repo.path(), &["audit", input.to_str().unwrap()]);
        run.ok("empty audit");
        let run: Value = serde_json::from_str(&run.stdout).unwrap();
        let run_id: RunId = run["runId"].as_str().unwrap().parse().unwrap();
        wait_for("history is complete", LIMIT, || Registry::open(state.path()).unwrap().run(&run_id)
            .is_some_and(|r| r.status == agent_control_plane::core::types::RunStatus::Completed));
        let mut host = Command::new("/bin/sleep").arg("60").spawn().unwrap();
        let handle = acp(state.path(), repo.path(), &["session", "acquire", "--owner-pid", &host.id().to_string()]);
        handle.ok("bind actual host");
        let mut observer = Wire::connect(&daemon.socket());
        host.kill().unwrap(); host.wait().unwrap();
        wait_for("host ownership ends", Duration::from_secs(15), || observer.call("daemon.status", json!({})).unwrap()["sessions"] == 0);
        assert!(daemon.child.try_wait().unwrap().is_none(), "other clients retain supervision");
        drop(observer);
        wait_for("managed owner exits promptly", Duration::from_secs(15), || daemon.child.try_wait().unwrap().is_some());
        assert_eq!(daemon.wait("host closed"), Some(0));
        assert!(!daemon.socket().exists()); assert!(!daemon.lock().exists());
        let before = acp(state.path(), repo.path(), &["status", run_id.to_string().as_str(), "--json"]);
        before.ok("offline history");
        let mut restarted = Daemon::start_no_mcp(state.path(), repo.path());
        let after = acp(state.path(), repo.path(), &["status", run_id.to_string().as_str(), "--json"]);
        after.ok("replayed history");
        assert_eq!(serde_json::from_str::<Value>(&before.stdout).unwrap()["runs"], serde_json::from_str::<Value>(&after.stdout).unwrap()["runs"]);
        acp(state.path(), repo.path(), &["stop"]).ok("stop test owner");
        restarted.wait("cleanup");
    });
}

#[test]
fn process_bound_session_ends_when_its_host_process_exits() {
    common::with_shared_env(|| async {
        let state = short_dir();
        let repo = repo_with_exclude();
        let mut daemon = Daemon::start(state.path(), repo.path());
        let mut wire = Wire::connect(&daemon.socket());
        let mut host = std::process::Command::new("/bin/sleep").arg("60").spawn().unwrap();
        let pid = i32::try_from(host.id()).unwrap();
        let bound = wire.call("session.acquire", json!({"label":"claude", "ownerPid": pid})).unwrap();
        assert_eq!(bound["sessions"], 1);
        // A pid with no process cannot own a session.
        assert!(wire.call("session.acquire", json!({"label":"claude", "ownerPid": 999_999})).is_err());
        host.kill().unwrap();
        host.wait().unwrap();
        wait_for("the dead host's lease is reaped", Duration::from_secs(15), || {
            wire.call("daemon.status", json!({})).unwrap()["sessions"] == 0
        });
        acp(state.path(), repo.path(), &["down"]).ok("stop the test daemon");
        daemon.wait("down");
    });
}


#[test]
fn cancel_work_stop_drains_preparing_and_running_workers_before_exit() {
    common::with_shared_env(|| async {
        install_fake_clis();
        for wait_for_spawn in [false, true] {
            let state = short_dir();
            let repo = repo_with_exclude();
            configure_fakes(repo.path(), "hang", &[]);
            let mut daemon = Daemon::start(state.path(), repo.path());
            let mut wire = Wire::connect(&daemon.socket());
            let task = loop_task("cancel-stop");
            let delegated = wire.call("delegate", json!({
                "role":"builder", "session":"fresh", "task":task
            })).unwrap();
            let run = delegated["runId"].as_str().unwrap();
            let attempt = delegated["attemptId"].as_str().unwrap();
            let mut worker = None;
            if wait_for_spawn {
                wait_for("the worker starts before cancel-and-stop", LIMIT, || {
                    worker = running_attempt_pid(state.path(), repo.path(), run, attempt);
                    worker.is_some()
                });
            }
            let stopped = acp(state.path(), repo.path(), &["stop", "--cancel-work"]);
            stopped.ok("cancel-and-stop acknowledgement");
            let status: Value = serde_json::from_str(&stopped.stdout).unwrap();
            assert_eq!(status["stopRequested"], "cancel_work");
            assert!(status["stopError"].is_null(), "{status}");
            assert_eq!(daemon.wait("cancel-and-stop drains"), Some(0));
            assert!(!daemon.socket().exists());
            assert!(!daemon.lock().exists());
            let registry = Registry::open(state.path()).unwrap();
            let run_id: RunId = run.parse().unwrap();
            let recorded = registry.run(&run_id).unwrap();
            assert_eq!(recorded.status, agent_control_plane::core::types::RunStatus::Cancelled);
            assert!(registry.state().attempts.values().all(|a| {
                a.status == agent_control_plane::core::types::AttemptStatus::Cancelled
            }));
            assert!(registry.state().gates.is_empty(), "cancellation must not dispatch repairs or approval");
            for lineage in &recorded.lineages { assert!(lineage.worktree.exists()); }
            if let Some(worker) = worker {
                wait_for("the cancelled worker has exited", LIMIT, || {
                    nix::sys::signal::kill(nix::unistd::Pid::from_raw(worker), None).is_err()
                });
            }
        }
    });
}
