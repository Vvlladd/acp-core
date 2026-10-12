//! Self-check for `src/bin/fake-claude.rs` (T04): every scenario the fake replays or side-effects,
//! driven through the binary itself rather than through the supervisor.
//!
//! `env!("CARGO_BIN_EXE_fake-claude")` resolves only because `fake-claude` is a `[[bin]]` target of
//! *this* package (`src/bin/` is auto-discovered). It breaks the day the repo becomes a cargo
//! workspace (`reports/03-design.md` § Migration, `apps/acp-mac/`) unless the fakes stay in the
//! package the tests live in.
//!
//! Fixtures are read from the checked-in files with `fs::read_to_string`, never `include_str!`, so a
//! copy-paste drift in the binary's embedded copy cannot make these assertions pass.
//!
//! `hang` is deliberately not covered here — it blocks until it is signalled, so it is exercised
//! against a timeout in the supervisor tests.

use std::env;
use std::fs;
use std::io::{BufRead as _, BufReader, Read as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_fake-claude");

/// The only `ACP_*` keys `run` puts in the child's environment.
const CONTROL_KEYS: [&str; 3] = ["ACP_FAKE_RECORD", "ACP_FAKE_SCENARIO", "ACP_FAKE_STATE"];

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/jsonl/claude")
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// The `Write` tool_use input a transcript replays, read out of the checked-in fixture so the
/// binary's embedded copy of the worker's change cannot drift from it.
fn written_source(name: &str) -> (String, String) {
    fixture(name)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["type"] == "assistant")
        .flat_map(|event| {
            event["message"]["content"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .find(|block| block["name"] == "Write")
        .map(|block| {
            (
                block["input"]["file_path"].as_str().unwrap_or_default().to_string(),
                block["input"]["content"].as_str().unwrap_or_default().to_string(),
            )
        })
        .expect("fixture carries a Write tool_use")
}

/// Runs the fake in `dir` with a cleared environment, so `envSubset.acpEnvKeys` is exactly what the
/// test asks for. The record and state files always live in `dir`.
fn run(scenario: &str, dir: &Path, args: &[&str], extra: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.current_dir(dir)
        .args(args)
        .env_clear()
        .env("ACP_FAKE_SCENARIO", scenario)
        .env("ACP_FAKE_RECORD", record_path(dir))
        .env("ACP_FAKE_STATE", state_path(dir));
    for (key, value) in extra {
        cmd.env(key, value);
    }
    cmd.output().expect("spawn fake-claude")
}

fn record_path(dir: &Path) -> PathBuf {
    dir.join("record.jsonl")
}

fn state_path(dir: &Path) -> PathBuf {
    dir.join("state.json")
}

fn record_lines(dir: &Path) -> Vec<Value> {
    fs::read_to_string(record_path(dir))
        .expect("read record file")
        .lines()
        .map(|line| serde_json::from_str(line).expect("record line is JSON"))
        .collect()
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is utf-8")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is utf-8")
}

#[test]
fn pass_replays_the_transcript_and_records_the_call() {
    let dir = TempDir::new().unwrap();
    let cwd = fs::canonicalize(dir.path()).unwrap();
    let args = ["-p", "build the adder", "--model", "claude-sonnet-4-5"];

    let output = run(
        "pass",
        dir.path(),
        &args,
        &[
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "remote.origin.url"),
            ("GIT_CONFIG_VALUE_0", ""),
        ],
    );

    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert_eq!(stdout_of(&output), fixture("pass-1.jsonl"));

    let lines = record_lines(dir.path());
    assert_eq!(lines.len(), 1, "one call must append exactly one line");
    let entry = &lines[0];
    assert_eq!(entry["argv"], serde_json::json!(args));
    assert_eq!(entry["cwd"], cwd.display().to_string());
    assert!(entry["invocation"].as_u64().unwrap() > 0);
    // Push suppression travels as `GIT_CONFIG_*`, with an empty value that must stay distinguishable
    // from an absent key (design § Worker environment).
    assert_eq!(entry["envSubset"]["gitConfigCount"], "1");
    assert_eq!(entry["envSubset"]["gitConfigKey0"], "remote.origin.url");
    assert_eq!(entry["envSubset"]["gitConfigValue0"], "");
    assert_eq!(entry["envSubset"]["acpEnvKeys"], serde_json::json!(CONTROL_KEYS));

    assert_eq!(
        serde_json::from_str::<Value>(&fs::read_to_string(state_path(dir.path())).unwrap()).unwrap(),
        serde_json::json!({ "claude:pass": 1 }),
    );
}

#[test]
fn record_line_lists_every_acp_env_key_it_can_see() {
    let dir = TempDir::new().unwrap();

    let output = run("pass", dir.path(), &["-p", "build the adder"], &[("ACP_FAKE_X", "1")]);

    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    let entry = record_lines(dir.path()).remove(0);
    let mut keys = CONTROL_KEYS.to_vec();
    keys.push("ACP_FAKE_X");
    keys.sort_unstable();
    assert_eq!(entry["envSubset"]["acpEnvKeys"], serde_json::json!(keys));
    // Nothing else about the environment leaks into the record line.
    assert_eq!(entry["envSubset"]["gitConfigCount"], Value::Null);
}

#[test]
fn the_state_counter_counts_calls_per_scenario() {
    let dir = TempDir::new().unwrap();

    for _ in 0..2 {
        let output = run("pass", dir.path(), &["-p", "build the adder"], &[]);
        assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    }

    assert_eq!(record_lines(dir.path()).len(), 2);
    assert_eq!(
        serde_json::from_str::<Value>(&fs::read_to_string(state_path(dir.path())).unwrap()).unwrap(),
        serde_json::json!({ "claude:pass": 2 }),
    );
}

#[test]
fn resume_argv_is_recorded_verbatim() {
    let dir = TempDir::new().unwrap();
    let args = ["-p", "address the findings", "--resume", "aaaaaaaa-1111-4a11-8a11-aaaaaaaaaaaa"];

    let output = run("pass", dir.path(), &args, &[]);

    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert_eq!(record_lines(dir.path()).remove(0)["argv"], serde_json::json!(args));
}

#[test]
fn worker_commits_commits_in_a_repo_with_no_configured_identity() {
    let dir = TempDir::new().unwrap();
    let repo = dir.path();
    git(repo, &["init", "-q"]);
    // Without this git invents an identity from the gecos field on a developer machine and the test
    // would prove nothing: the fake must supply its own.
    git(repo, &["config", "user.useConfigOnly", "true"]);
    git(
        repo,
        &["-c", "user.name=Base", "-c", "user.email=base@example.invalid", "commit", "-q", "--allow-empty", "-m", "base"],
    );
    let before = git(repo, &["rev-parse", "HEAD"]);

    let path = env::var("PATH").unwrap_or_default();
    let output = run("worker_commits", repo, &["-p", "build the adder"], &git_env(&path));

    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert_eq!(stdout_of(&output), fixture("worker_commits-1.jsonl"));
    assert_ne!(git(repo, &["rev-parse", "HEAD"]), before);
    assert_eq!(git(repo, &["log", "-1", "--format=%s"]), "fake-worker-commit");
}

#[test]
fn denylist_writes_app_xcconfig_then_replays_pass() {
    let dir = TempDir::new().unwrap();

    let output = run("denylist", dir.path(), &["-p", "build the adder"], &[]);

    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert_eq!(stdout_of(&output), fixture("pass-1.jsonl"));
    assert_eq!(fs::read_to_string(dir.path().join("App.xcconfig")).unwrap(), "x");
}

#[test]
fn split_line_stdout_reassembles_into_the_fixture() {
    let dir = TempDir::new().unwrap();

    let output = run("split_line", dir.path(), &["-p", "build the adder"], &[]);

    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    // The two writes of line 2 are not observable once the pipe is drained; byte-equality with the
    // fixture is the observable post-condition. That the tailer sees the partial line is asserted
    // against the supervisor (C6).
    assert_eq!(stdout_of(&output), fixture("split_line-1.jsonl"));
}

#[test]
fn lead_messages_replays_two_text_blocks_and_a_tool_call_without_writing() {
    let dir = TempDir::new().unwrap();
    let output = run(
        "lead_messages",
        dir.path(),
        &["-p", "coordinate the repository"],
        &[],
    );

    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert_eq!(stdout_of(&output), fixture("lead-messages-1.jsonl"));
    let assistant: Value = serde_json::from_str(
        fixture("lead-messages-1.jsonl")
            .lines()
            .nth(1)
            .expect("assistant fixture line"),
    )
    .expect("assistant fixture JSON");
    let content = assistant["message"]["content"]
        .as_array()
        .expect("assistant content blocks");
    assert_eq!(
        content
            .iter()
            .filter(|block| block["type"] == "text")
            .count(),
        2
    );
    assert!(content.iter().any(|block| {
        block["type"] == "tool_use" && block["name"] == "Read"
    }));
    assert!(!dir.path().join("src/adder.ts").exists());
}

#[test]
fn invalid_replays_the_malformed_transcript_and_still_exits_0() {
    let dir = TempDir::new().unwrap();

    let output = run("invalid", dir.path(), &["-p", "build the adder"], &[]);

    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert_eq!(stdout_of(&output), fixture("invalid-1.jsonl"));
}

#[test]
fn no_session_exits_1_without_a_single_line() {
    let dir = TempDir::new().unwrap();

    let output = run("no_session", dir.path(), &["-p", "build the adder"], &[]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout: {}", stdout_of(&output));
    // The call is still recorded: the supervisor must be able to see that the CLI ran at all.
    assert_eq!(record_lines(dir.path()).len(), 1);
}

#[test]
fn auth_fail_exits_1_and_mentions_authentication_on_stderr() {
    let dir = TempDir::new().unwrap();

    let output = run("auth_fail", dir.path(), &["-p", "build the adder"], &[]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout: {}", stdout_of(&output));
    assert!(stderr_of(&output).contains("auth"), "stderr: {}", stderr_of(&output));
}

#[test]
fn dirty_retry_leaves_an_uncommitted_file_and_exits_1() {
    let dir = TempDir::new().unwrap();

    let output = run("dirty_retry", dir.path(), &["-p", "build the adder"], &[]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout: {}", stdout_of(&output));
    assert_eq!(fs::read_to_string(dir.path().join("dirty.txt")).unwrap(), "uncommitted");
}

#[test]
fn replaying_a_transcript_makes_the_worktree_change_it_describes() {
    let dir = TempDir::new().unwrap();
    let (fixture_path, contents) = written_source("pass-1.jsonl");

    let output = run("pass", dir.path(), &["-p", "build the adder"], &[]);

    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    // The fixture writes into the `/tmp/acp-fixture-worktree` placeholder; the fake writes the same
    // relative path under its own cwd, creating `src/`.
    assert!(fixture_path.ends_with("/src/adder.ts"), "fixture path: {fixture_path}");
    let written = dir.path().join("src/adder.ts");
    assert_eq!(
        fs::read_to_string(&written).unwrap_or_else(|err| panic!("read {}: {err}", written.display())),
        contents,
    );
}

#[test]
fn split_line_makes_the_same_worktree_change() {
    let dir = TempDir::new().unwrap();
    let (_, contents) = written_source("pass-1.jsonl");

    // `split_line-1.jsonl` is trimmed to two lines and carries no `Write` block of its own, but it
    // replays the same task, so the loop still needs a changed file to diff.
    let output = run("split_line", dir.path(), &["-p", "build the adder"], &[]);

    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert_eq!(fs::read_to_string(dir.path().join("src/adder.ts")).unwrap(), contents);
}

#[test]
fn version_is_answered_without_counting_as_a_call_of_the_scenario() {
    let dir = TempDir::new().unwrap();

    let session = run("pass", dir.path(), &["-p", "build the adder"], &[]);
    assert!(session.status.success(), "stderr: {}", stderr_of(&session));
    let probe = run("pass", dir.path(), &["--version"], &[]);

    assert!(probe.status.success(), "stderr: {}", stderr_of(&probe));
    assert_eq!(stdout_of(&probe), "2.1.221 (Claude Code)\n");
    // The probe is recorded like any other call, but it replays nothing and leaves the counter alone.
    assert_eq!(record_lines(dir.path()).len(), 2);
    assert_eq!(
        serde_json::from_str::<Value>(&fs::read_to_string(state_path(dir.path())).unwrap()).unwrap(),
        serde_json::json!({ "claude:pass": 1 }),
    );
}

#[test]
fn lead_messages_can_pause_after_session_until_a_restart_releases_them() {
    let dir = TempDir::new().unwrap();
    let release = dir.path().join("replacement-daemon-ready");
    let expected = fixture("lead-messages-1.jsonl");
    let expected_init = expected.lines().next().expect("fixture init").to_string() + "\n";
    let mut child = Command::new(BIN)
        .current_dir(dir.path())
        .args(["-p", "coordinate the repository"])
        .env_clear()
        .env("ACP_FAKE_SCENARIO", "lead_messages")
        .env("ACP_FAKE_WAIT_FILE", &release)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn waiting fake lead");
    let stdout = child.stdout.take().expect("fake stdout");
    let (line_tx, line_rx) = std::sync::mpsc::sync_channel(1);
    let (rest_tx, rest_rx) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        let mut init = String::new();
        let read = stdout.read_line(&mut init);
        let _ = line_tx.send((read, init));
        let mut rest = String::new();
        let read = stdout.read_to_string(&mut rest);
        let _ = rest_tx.send((read, rest));
    });
    let init = line_rx.recv_timeout(Duration::from_secs(60));
    let probe_deadline = Instant::now() + Duration::from_millis(500);
    let mut was_waiting = true;
    let mut probe_error = None;
    while Instant::now() < probe_deadline {
        match child.try_wait() {
            Ok(Some(_)) => {
                was_waiting = false;
                break;
            }
            Ok(None) => {}
            Err(err) => {
                probe_error = Some(err);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Release and reap before surfacing any assertion, so a deliberately broken test mutation
    // cannot leave the fake provider behind. Every read and process wait is explicitly bounded.
    let release_result = fs::write(&release, "ready\n");
    let rest = rest_rx.recv_timeout(Duration::from_secs(60));
    let exit_deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < exit_deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                break child.wait();
            }
            Err(err) => break Err(err),
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    let reader_result = reader.join();

    let (init_read, init) = init.expect("system/init timeout");
    init_read.expect("read system/init");
    let (rest_read, rest) = rest.expect("remaining transcript timeout");
    rest_read.expect("read remaining transcript");
    release_result.expect("release fake lead");
    assert!(reader_result.is_ok(), "join stdout reader");
    assert!(probe_error.is_none(), "probe fake lead: {probe_error:?}");
    let status = status.expect("wait for fake lead");

    assert_eq!(init, expected_init, "the restart barrier follows system/init");
    assert!(
        was_waiting,
        "the provider remains alive until the replacement daemon is ready"
    );
    assert!(status.success());
    assert_eq!(format!("{init}{rest}"), expected);
}

/// `PATH` (so the fake can find `git`) and a git that can reach no global or system config, so the
/// only identity in play is the one the fake passes inline.
fn git_env(path: &str) -> [(&'static str, &str); 3] {
    [
        ("PATH", path),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_SYSTEM", "/dev/null"),
    ]
}

fn git(repo: &Path, args: &[&str]) -> String {
    let path = env::var("PATH").unwrap_or_default();
    let mut cmd = Command::new("git");
    cmd.args(args).current_dir(repo).env_clear().envs(git_env(&path));
    let output = cmd.output().expect("spawn git");
    assert!(output.status.success(), "git {args:?}: {}", stderr_of(&output));
    stdout_of(&output).trim().to_string()
}

// ---------------------------------------------------------------------------
// B1: the verifier branch (T65 review M1) — selected by argv, steered by its own env
// ---------------------------------------------------------------------------

/// The last stdout line of a completed replay — the `result` object.
fn result_line(output: &Output) -> Value {
    let stdout = stdout_of(output);
    let line = stdout.lines().last().expect("a final line");
    serde_json::from_str(line).expect("the result line is JSON")
}

const A_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn verify_fail_then_pass_replays_fail_then_pass_and_echoes_the_hash() {
    let dir = TempDir::new().unwrap();
    let args = ["-p", "verify the change", "--agent", "verifier"];
    let extra = [
        ("ACP_FAKE_VERIFY_HASH", A_HASH),
        ("ACP_FAKE_VERIFY_SCENARIO", "verify_fail_then_pass"),
    ];

    let first = run("pass", dir.path(), &args, &extra);
    assert!(first.status.success());
    let result = result_line(&first);
    assert_eq!(result["structured_output"]["status"], "fail");
    assert_eq!(result["structured_output"]["diffHash"], A_HASH);
    // Both substitution forms: the plain one above, and the escaped one inside the `result`
    // string — the document a real CLI would surface when structured_output is absent.
    let embedded: Value = serde_json::from_str(result["result"].as_str().expect("a result string"))
        .expect("the result string is a JSON document");
    assert_eq!(embedded["diffHash"], A_HASH);

    let second = run("pass", dir.path(), &args, &extra);
    assert!(second.status.success());
    let result = result_line(&second);
    assert_eq!(result["structured_output"]["status"], "pass");
    assert_eq!(result["structured_output"]["diffHash"], A_HASH);
}

/// A verifier call must not consume the BUILDER scenario's replay counter (or
/// `fail_then_pass`-style sequencing would shift).
#[test]
fn a_verifier_call_does_not_shift_the_builder_counter() {
    let dir = TempDir::new().unwrap();
    let verify_args = ["-p", "verify", "--agent", "verifier"];
    let build_args = ["-p", "build the adder", "--agent", "builder"];

    let _ = run("pass", dir.path(), &verify_args, &[("ACP_FAKE_VERIFY_HASH", A_HASH)]);
    let build = run("pass", dir.path(), &build_args, &[]);
    assert!(build.status.success());
    // The state file holds the per-scenario counters directly: the verifier consumed its OWN
    // key, and the builder's key still reads 1 — sequencing like `fail_then_pass` cannot shift.
    let state: Value = serde_json::from_str(
        &fs::read_to_string(state_path(dir.path())).expect("state file"),
    )
    .expect("state is JSON");
    assert_eq!(state["claude:verify_pass"], 1);
    assert_eq!(state["claude:pass"], 1);
}

#[test]
fn verify_crash_exits_1_without_a_line() {
    let dir = TempDir::new().unwrap();
    // No hash on purpose: the crash must short-circuit BEFORE the empty-hash die(2), so this
    // also pins the ordering of the two guards.
    let output = run(
        "pass",
        dir.path(),
        &["-p", "verify", "--agent", "verifier"],
        &[("ACP_FAKE_VERIFY_SCENARIO", "verify_crash")],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout_of(&output), "", "no session line, ever");
}

/// A builder scenario name in the verify knob must die loudly (exit 2), never replay a
/// build-result document as a verify report — that shape fails schema validation downstream and
/// reads as a loop bug instead of a harness typo.
#[test]
fn a_builder_scenario_name_in_the_verify_knob_dies_with_exit_2() {
    let dir = TempDir::new().unwrap();
    let output = run(
        "pass",
        dir.path(),
        &["-p", "verify", "--agent", "verifier"],
        &[
            ("ACP_FAKE_VERIFY_HASH", A_HASH),
            ("ACP_FAKE_VERIFY_SCENARIO", "pass"),
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr_of(&output).contains("unknown ACP_FAKE_VERIFY_SCENARIO"));
}

#[test]
fn a_verifier_invoked_with_no_hash_dies_with_exit_2() {
    let dir = TempDir::new().unwrap();
    let output = run("pass", dir.path(), &["-p", "verify", "--agent", "verifier"], &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr_of(&output).contains("ACP_FAKE_VERIFY_HASH"));
}
