//! Self-check for the fake `codex` binary (T06). Every assertion compares against the **checked-in**
//! fixture read at runtime, never the `include_str!`-embedded copy, so a copy-paste bug inside
//! `src/bin/fake-codex.rs` cannot make these tests trivially pass.
//!
//! The `hang` scenario is deliberately not exercised here (it would block the suite); it is covered
//! against a timeout in T23.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use tempfile::TempDir;

/// Cargo defines this only because `fake-codex` is a `[[bin]]` target of *this same package* — the
/// single-package layout is what makes the macro available (`reports/03-design.md` § Migration).
/// It breaks the day a cargo workspace is introduced; this test and its `fake-claude` twin are the
/// two places that must then be revisited.
const BIN: &str = env!("CARGO_BIN_EXE_fake-codex");

const PROMPT: &str = "review the frozen diff";

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/jsonl/codex")
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// The last `agent_message.text` of a transcript — what the real CLI writes to `-o`.
fn last_agent_message(transcript: &str) -> String {
    transcript
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["item"]["type"] == "agent_message")
        .filter_map(|event| event["item"]["text"].as_str().map(str::to_string))
        .next_back()
        .expect("fixture carries an agent_message")
}

/// A scratch cwd plus the record/state files the fake is configured with.
struct Fake {
    dir: TempDir,
    record: PathBuf,
    state: PathBuf,
}

impl Fake {
    fn new() -> Self {
        let dir = TempDir::new().expect("tempdir");
        let record = dir.path().join("record.jsonl");
        let state = dir.path().join("fake-state.json");
        Self { dir, record, state }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The reviewer's fresh argv from `reports/03-design.md` § Provider argv, minus the prompt body.
    fn reviewer_argv(&self, last_message: &Path) -> Vec<String> {
        vec![
            "exec".to_string(),
            "--json".to_string(),
            "--strict-config".to_string(),
            "-m".to_string(),
            "gpt-5.5".to_string(),
            "-s".to_string(),
            "read-only".to_string(),
            "-c".to_string(),
            "approval_policy=\"never\"".to_string(),
            "-c".to_string(),
            "sandbox_mode=\"read-only\"".to_string(),
            "-c".to_string(),
            "mcp_servers={}".to_string(),
            "--output-schema".to_string(),
            self.path().join("output-schema.json").display().to_string(),
            "-o".to_string(),
            last_message.display().to_string(),
            PROMPT.to_string(),
        ]
    }

    /// `env_clear` mirrors the supervisor's scrub, so `envSubset.acpEnvKeys` is exactly the set of
    /// `ACP_*` variables this test passes through. stdin is `/dev/null`: the fake must never read it.
    fn command(&self, scenario: &str, args: &[String]) -> Command {
        let mut command = Command::new(BIN);
        command
            .args(args)
            .current_dir(self.path())
            .stdin(Stdio::null())
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.path())
            .env("ACP_FAKE_SCENARIO", scenario)
            .env("ACP_FAKE_RECORD", &self.record)
            .env("ACP_FAKE_STATE", &self.state)
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "remote.origin.url")
            .env("GIT_CONFIG_VALUE_0", "");
        command
    }

    fn run(&self, scenario: &str, args: &[String]) -> Output {
        self.command(scenario, args)
            .output()
            .expect("spawn fake-codex")
    }

    fn records(&self) -> Vec<Value> {
        fs::read_to_string(&self.record)
            .expect("record file")
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).expect("record line is JSON"))
            .collect()
    }

    fn state(&self) -> Value {
        serde_json::from_str(&fs::read_to_string(&self.state).expect("state file"))
            .expect("state file is JSON")
    }
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

#[test]
fn pass_replays_review_pass_1_then_review_pass_2_and_records_each_call() {
    let fake = Fake::new();
    let last_message = fake.path().join("last-message.txt");
    let argv = fake.reviewer_argv(&last_message);

    let first = fake.run("pass", &argv);
    assert_eq!(first.status.code(), Some(0), "{}", stdout_of(&first));
    assert_eq!(stdout_of(&first), fixture("review-pass-1.jsonl"));
    assert_eq!(
        fs::read_to_string(&last_message).unwrap(),
        last_agent_message(&fixture("review-pass-1.jsonl"))
    );
    assert_eq!(fake.state(), serde_json::json!({ "codex:pass": 1 }));

    let second = fake.run("pass", &argv);
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(stdout_of(&second), fixture("review-pass-2.jsonl"));
    assert_eq!(
        fs::read_to_string(&last_message).unwrap(),
        last_agent_message(&fixture("review-pass-2.jsonl"))
    );
    assert_eq!(fake.state(), serde_json::json!({ "codex:pass": 2 }));

    let records = fake.records();
    assert_eq!(records.len(), 2, "one record line per call");
    let entry = &records[0];
    assert_eq!(entry["argv"], serde_json::json!(argv));
    assert_eq!(
        entry["cwd"].as_str().unwrap(),
        fake.path().canonicalize().unwrap().display().to_string()
    );
    assert!(entry["invocation"].as_u64().unwrap() > 0);
}

#[test]
fn record_env_subset_carries_the_git_config_trio_and_every_acp_key() {
    let fake = Fake::new();
    let last_message = fake.path().join("last-message.txt");
    let output = fake
        .command("pass", &fake.reviewer_argv(&last_message))
        .env("ACP_FAKE_X", "1")
        .env("ACP_STATE_DIR", "/should/never/reach/a/worker")
        .output()
        .expect("spawn fake-codex");
    assert_eq!(output.status.code(), Some(0));

    let env_subset = fake.records()[0]["envSubset"].clone();
    let fields: Vec<&str> = env_subset
        .as_object()
        .expect("envSubset is an object")
        .keys()
        .map(String::as_str)
        .collect();
    // Same field names as the fake-claude record line (T04) — cross-provider consistency.
    assert_eq!(
        fields,
        vec![
            "acpEnvKeys",
            "gitConfigCount",
            "gitConfigKey0",
            "gitConfigValue0"
        ]
    );
    assert_eq!(env_subset["gitConfigCount"], "1");
    assert_eq!(env_subset["gitConfigKey0"], "remote.origin.url");
    assert_eq!(env_subset["gitConfigValue0"], "");
    // Every `ACP_*` key is reported, sorted — that is what lets a supervisor test assert the scrub
    // passed through exactly the `ACP_FAKE_*` set and leaked nothing else.
    assert_eq!(
        env_subset["acpEnvKeys"],
        serde_json::json!([
            "ACP_FAKE_RECORD",
            "ACP_FAKE_SCENARIO",
            "ACP_FAKE_STATE",
            "ACP_FAKE_X",
            "ACP_STATE_DIR"
        ])
    );
}

#[test]
fn fail_then_pass_replays_the_fail_transcript_first() {
    let fake = Fake::new();
    let last_message = fake.path().join("last-message.txt");
    let argv = fake.reviewer_argv(&last_message);

    let first = fake.run("fail_then_pass", &argv);
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(stdout_of(&first), fixture("review-fail-1.jsonl"));
    let verdict = fs::read_to_string(&last_message).unwrap();
    assert_eq!(verdict, last_agent_message(&fixture("review-fail-1.jsonl")));
    assert_eq!(
        serde_json::from_str::<Value>(&verdict).unwrap()["verdict"],
        "FAIL"
    );

    let second = fake.run("fail_then_pass", &argv);
    assert_eq!(stdout_of(&second), fixture("review-pass-2.jsonl"));
    assert_eq!(
        fake.state(),
        serde_json::json!({ "codex:fail_then_pass": 2 })
    );
}

#[test]
fn invalid_streams_turn_failed_and_leaves_the_output_file_absent() {
    let fake = Fake::new();
    let last_message = fake.path().join("last-message.txt");

    let output = fake.run("invalid", &fake.reviewer_argv(&last_message));

    // The turn failed inside the stream; the CLI itself still exits 0.
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout_of(&output), fixture("turn-failed-1.jsonl"));
    assert!(
        !last_message.exists(),
        "no agent_message in the transcript, so -o must stay unwritten"
    );
}

#[test]
fn split_line_writes_the_agent_message_in_two_pieces_that_reassemble() {
    let fake = Fake::new();
    let last_message = fake.path().join("last-message.txt");
    let mut command = fake.command("split_line", &fake.reviewer_argv(&last_message));
    let mut child = command
        .env("ACP_FAKE_DELAY_MS", "50")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn fake-codex");
    let mut stdout = child.stdout.take().expect("piped stdout");

    // Record where each `read()` landed: a boundary inside line 3 proves it took two writes.
    let mut seen: Vec<u8> = Vec::new();
    let mut boundaries: Vec<usize> = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = stdout.read(&mut buffer).expect("read stdout");
        if read == 0 {
            break;
        }
        seen.extend_from_slice(&buffer[..read]);
        boundaries.push(seen.len());
    }
    assert!(child.wait().expect("wait").success());

    let expected = fixture("split_line-1.jsonl");
    assert_eq!(String::from_utf8(seen).expect("stdout is UTF-8"), expected);

    // `fixtures/jsonl/README.md` § Invariants: Codex splits line 3, the agent_message (not line 2).
    let lines: Vec<&str> = expected.lines().collect();
    let start: usize = lines[..2].iter().map(|line| line.len() + 1).sum();
    let end = start + lines[2].len();
    assert!(
        boundaries.iter().any(|&at| at > start && at < end),
        "expected a read boundary inside line 3 (bytes {start}..{end}), got {boundaries:?}"
    );
    assert_eq!(
        fs::read_to_string(&last_message).unwrap(),
        last_agent_message(&fixture("split_line-1.jsonl"))
    );
}

/// Rev 25 made the reviewer echo the frozen diff's `diffHash`, so a loop test has to be able to
/// make the fake echo the hash of a diff it froze a moment ago — or a deliberately wrong one, to
/// drive the mismatch path. `ACP_FAKE_DIFF_HASH` is that knob, and it must reach **both** channels
/// the supervisor reads: the stream it tails and the `-o` file it opens after exit.
#[test]
fn diff_hash_override_rewrites_the_verdict_in_the_stream_and_in_the_output_file() {
    let fake = Fake::new();
    let last_message = fake.path().join("last-message.txt");
    let hash = "b".repeat(64);

    let output = fake
        .command("pass", &fake.reviewer_argv(&last_message))
        .env("ACP_FAKE_DIFF_HASH", &hash)
        .output()
        .expect("spawn fake-codex");
    assert_eq!(output.status.code(), Some(0), "{}", stdout_of(&output));

    let transcript = fixture("review-pass-1.jsonl");
    let placeholder = last_agent_message(&transcript);
    let placeholder_hash = serde_json::from_str::<Value>(&placeholder).expect("fixture verdict")
        ["diffHash"]
        .as_str()
        .expect("the fixture carries a placeholder diffHash")
        .to_string();

    let echoed = fs::read_to_string(&last_message).expect("-o file");
    let verdict: Value =
        serde_json::from_str(&echoed).expect("the -o body is still a JSON verdict");
    assert_eq!(verdict["diffHash"], hash);

    // Only the hash moves: the rest of the verdict is the fixture's, and so is the rest of the
    // transcript — byte for byte.
    let mut expected: Value = serde_json::from_str(&placeholder).expect("fixture verdict");
    expected["diffHash"] = Value::from(hash.clone());
    assert_eq!(verdict, expected);
    assert_eq!(
        stdout_of(&output),
        transcript.replace(&placeholder_hash, &hash)
    );
    assert_eq!(last_agent_message(&stdout_of(&output)), echoed);

    // The knob is an `ACP_FAKE_*` key, so the supervisor's env scrub is allowed to pass it through.
    let keys = fake.records()[0]["envSubset"]["acpEnvKeys"].clone();
    assert!(
        keys.as_array()
            .expect("acpEnvKeys is an array")
            .contains(&Value::from("ACP_FAKE_DIFF_HASH")),
        "the fake must report the key it read, got {keys}"
    );
}

/// The value is spliced into the transcript verbatim, so one carrying a quote would emit invalid
/// JSON on the stream. That is a broken test, not a scenario: it exits 2 before anything is written.
#[test]
fn a_diff_hash_that_would_corrupt_the_transcript_is_fake_misuse() {
    let fake = Fake::new();
    let last_message = fake.path().join("last-message.txt");

    let output = fake
        .command("pass", &fake.reviewer_argv(&last_message))
        .env("ACP_FAKE_DIFF_HASH", r#"a"b"#)
        .output()
        .expect("spawn fake-codex");

    assert_eq!(output.status.code(), Some(2), "{}", stdout_of(&output));
    assert!(output.stdout.is_empty(), "{}", stdout_of(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("ACP_FAKE_DIFF_HASH"),
        "stderr must name the offending variable"
    );
    assert!(!last_message.exists(), "-o must stay unwritten");
    assert!(!fake.state.exists(), "no counter is bumped");
}

#[test]
fn auth_fail_exits_1_with_empty_stdout_and_an_auth_message() {
    let fake = Fake::new();
    let last_message = fake.path().join("last-message.txt");

    let output = fake.run("auth_fail", &fake.reviewer_argv(&last_message));

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "{}", stdout_of(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .to_lowercase()
            .contains("auth"),
        "stderr must name the auth failure"
    );
    assert!(!last_message.exists());
}

#[test]
fn no_session_exits_1_without_emitting_a_thread_id() {
    let fake = Fake::new();
    let last_message = fake.path().join("last-message.txt");

    let output = fake.run("no_session", &fake.reviewer_argv(&last_message));

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "{}", stdout_of(&output));
    assert_eq!(fake.records().len(), 1, "the call is still recorded");
}

/// `denylist` and `dirty_retry` are builder-only: the design escalates (or retries the builder)
/// before a reviewer is ever spawned. The fake refuses to fabricate a verdict there, so a loop bug
/// that wrongly continues into review fails loudly instead of looking green.
fn assert_builder_only_tripwire(scenario: &str) {
    let fake = Fake::new();
    let last_message = fake.path().join("last-message.txt");

    let output = fake.run(scenario, &fake.reviewer_argv(&last_message));

    assert_eq!(
        output.status.code(),
        Some(2),
        "{scenario}: expected the fake-misuse exit code"
    );
    assert!(output.stdout.is_empty(), "{}", stdout_of(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("reviewer invoked") && stderr.contains(scenario),
        "stderr must name the scenario, got: {stderr}"
    );
    // No verdict, no counter — the invocation is still ledgered so the stray call is diagnosable.
    assert!(!last_message.exists(), "{scenario}: -o must stay unwritten");
    assert!(!fake.state.exists(), "{scenario}: no counter is bumped");
    assert_eq!(fake.records().len(), 1, "the stray call is still recorded");
}

#[test]
fn denylist_never_reaches_the_reviewer() {
    assert_builder_only_tripwire("denylist");
}

#[test]
fn dirty_retry_never_reaches_the_reviewer() {
    assert_builder_only_tripwire("dirty_retry");
}

// ---------------------------------------------------------------------------
// C1: the argv-selected writing modes (T68 review) — builder vs verifier, and the source guard
// ---------------------------------------------------------------------------

/// The workspace-write argv shape the adapter emits, minimally: the mode pair plus the trailing
/// positionals a fresh `exec` carries.
fn workspace_write_args(schema_path: &str) -> Vec<String> {
    [
        "exec",
        "--json",
        "--strict-config",
        "--ignore-user-config",
        "-m",
        "gpt-5.5",
        "-s",
        "workspace-write",
        "-c",
        r#"sandbox_mode="workspace-write""#,
        "--output-schema",
        schema_path,
        "-o",
        "last-message.txt",
        "build the adder",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[test]
fn a_workspace_write_argv_without_a_verify_schema_builds_and_writes_the_source() {
    let fx = Fake::new();
    let schema = fx.path().join("output-schema.json");
    fs::write(&schema, r#"{"type":"object"}"#).expect("schema file");
    let out = fx.run("pass", &workspace_write_args(&schema.display().to_string()));
    assert!(out.status.success());
    let written = fs::read_to_string(fx.path().join("src/adder.ts"))
        .expect("the builder writes the source for real");
    assert!(written.contains("return a + b"));
    let last = fs::read_to_string(fx.path().join("last-message.txt")).expect("-o file");
    let doc: Value = serde_json::from_str(&last).expect("a JSON document");
    assert_eq!(doc["status"], "succeeded", "a build-result, not a verdict");
}

#[test]
fn a_workspace_write_argv_with_a_verify_schema_verifies_and_writes_nothing() {
    let fx = Fake::new();
    let schema = fx.path().join("output-schema.json");
    // The discriminator the fake keys on: only the verify-report schema carries this enum value.
    fs::write(&schema, r#"{"enum":["pass","fail","nothing-to-run"]}"#).expect("schema file");
    let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let out = fx
        .command("pass", &workspace_write_args(&schema.display().to_string()))
        .env("ACP_FAKE_DIFF_HASH", hash)
        .output()
        .expect("spawn fake-codex");
    assert!(out.status.success());
    assert!(
        !fx.path().join("src/adder.ts").exists(),
        "a verifier must never mutate the tree it verifies"
    );
    let last = fs::read_to_string(fx.path().join("last-message.txt")).expect("-o file");
    let doc: Value = serde_json::from_str(&last).expect("a JSON document");
    assert_eq!(doc["status"], "pass", "a verify-report");
    assert_eq!(doc["diffHash"], hash, "echoing the supplied hash");
}

/// The drift guard the two fakes' shared side effect needs (T68 review N4): fake-codex's
/// written source must stay byte-identical to fake-claude's, or a codex builder's frozen diff
/// silently diverges from every claude-builder assertion in the suite.
#[test]
fn the_two_fakes_write_byte_identical_sources() {
    let codex_fx = Fake::new();
    let schema = codex_fx.path().join("output-schema.json");
    fs::write(&schema, r#"{"type":"object"}"#).expect("schema file");
    codex_fx.run("pass", &workspace_write_args(&schema.display().to_string()));
    let codex_source =
        fs::read(codex_fx.path().join("src/adder.ts")).expect("codex wrote the source");

    let claude_dir = tempfile::tempdir().expect("claude cwd");
    let status = Command::new(env!("CARGO_BIN_EXE_fake-claude"))
        .args(["-p", "build the adder"])
        .current_dir(claude_dir.path())
        .env_clear()
        .env("ACP_FAKE_SCENARIO", "pass")
        .status()
        .expect("spawn fake-claude");
    assert!(status.success());
    let claude_source =
        fs::read(claude_dir.path().join("src/adder.ts")).expect("claude wrote the source");
    assert_eq!(codex_source, claude_source, "the copies must not drift");
}
