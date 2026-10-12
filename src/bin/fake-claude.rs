//! Fake `claude` CLI (T03): replays the recorded transcripts in `fixtures/jsonl/claude/` and
//! performs each scenario's filesystem side effect, so no test that uses it spends a token.
//!
//! Contract: `reports/03-design.md` § `src/bin/fake-claude.rs, fake-codex.rs` and
//! `fixtures/jsonl/README.md` § "Scenario → fixture map". Tests prepend a directory holding a
//! `claude` symlink to this binary to `PATH`, and configure it **only** through these vars — the
//! `ACP_FAKE_*` prefix is the one thing the supervisor's env scrub passes through:
//!
//! * `ACP_FAKE_SCENARIO` — one of the 12 scenario names (default `pass`)
//! * `ACP_FAKE_RECORD` — file that receives one `{argv, cwd, envSubset, invocation}` JSON line per call
//! * `ACP_FAKE_STATE` — JSON file holding the invocation counter, keyed `"claude:<scenario>"`
//! * `ACP_FAKE_DELAY_MS` — pause between emitted lines (default 0)
//! * `ACP_FAKE_WAIT_FILE` — for `lead_messages` and verifier invocations, pause after
//!   `system/init` until this file exists (the deterministic daemon-restart barrier)
//! * `ACP_FAKE_VERIFY_HASH` — the `diffHash` a verifier invocation echoes (B1); the test wrapper
//!   lifts it from the prompt by default, so it is the hash of the diff the loop actually froze
//! * `ACP_FAKE_VERIFY_SCENARIO` — which verify transcript a verifier invocation replays
//!   (default `verify_pass`; `verify_fail`, `verify_nothing`, `verify_fail_then_pass`,
//!   behavioural `verify_crash`) — separate from `ACP_FAKE_SCENARIO`, which keeps steering
//!   the builder
//!
//! Only `std` + `serde_json`, and the transcripts are `include_str!`-embedded, so the binary works
//! when invoked through a symlink named `claude` from any cwd. `cargo install --bin acp` ships
//! neither fake.

use std::collections::BTreeSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{self, Command};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

const PROVIDER: &str = "claude";

/// Every transcript this bin can replay, embedded at compile time and keyed `<base>-<n>`.
/// `max_turns-1` is replayed by no scenario — it is a parser-only fixture (`fixtures/jsonl/README.md`)
/// exercised directly by the provider tests — but it is embedded here so the table matches the
/// README's file list.
const FIXTURES: &[(&str, &str)] = &[
    (
        "pass-1",
        include_str!("../../fixtures/jsonl/claude/pass-1.jsonl"),
    ),
    (
        "invalid-1",
        include_str!("../../fixtures/jsonl/claude/invalid-1.jsonl"),
    ),
    (
        "worker_commits-1",
        include_str!("../../fixtures/jsonl/claude/worker_commits-1.jsonl"),
    ),
    (
        "max_turns-1",
        include_str!("../../fixtures/jsonl/claude/max_turns-1.jsonl"),
    ),
    (
        "split_line-1",
        include_str!("../../fixtures/jsonl/claude/split_line-1.jsonl"),
    ),
    (
        "lead_messages-1",
        include_str!("../../fixtures/jsonl/claude/lead-messages-1.jsonl"),
    ),
    (
        "lead-chat-1",
        include_str!("../../fixtures/jsonl/claude/lead-chat-1.jsonl"),
    ),
    (
        "verify-pass-1",
        include_str!("../../fixtures/jsonl/claude/verify-pass-1.jsonl"),
    ),
    (
        "verify-fail-1",
        include_str!("../../fixtures/jsonl/claude/verify-fail-1.jsonl"),
    ),
    (
        "verify-nothing-1",
        include_str!("../../fixtures/jsonl/claude/verify-nothing-1.jsonl"),
    ),
    (
        "verify-ftp-1",
        include_str!("../../fixtures/jsonl/claude/verify-ftp-1.jsonl"),
    ),
    (
        "verify-ftp-2",
        include_str!("../../fixtures/jsonl/claude/verify-ftp-2.jsonl"),
    ),
];

/// Scenario → transcript basename. Scenarios absent from this table emit no transcript of their own.
const TRANSCRIPTS: &[(&str, &str)] = &[
    ("pass", "pass"),
    ("fail_then_pass", "pass"), // the builder always succeeds; the FAIL comes from the reviewer
    ("worker_commits", "worker_commits"), // byte-identical to pass-1; the commit is the side effect
    ("denylist", "pass"),
    ("no_changes", "pass"), // the transcript claims a change; the bin deliberately makes none
    ("invalid", "invalid"),
    ("split_line", "split_line"),
    ("lead_messages", "lead_messages"),
    ("lead_chat", "lead-chat"),
    ("missing_bin", "pass"), // reproduced by an empty PATH dir; harmless if this bin is reached anyway
    // B1: selected by argv (`--agent verifier`) + `ACP_FAKE_VERIFY_SCENARIO`, never by
    // `ACP_FAKE_SCENARIO` — see `main`. `verify_fail_then_pass` has two numbered fixtures, so
    // the second verifier invocation (after the repair) passes.
    ("verify_pass", "verify-pass"),
    ("verify_fail", "verify-fail"),
    ("verify_nothing", "verify-nothing"),
    ("verify_fail_then_pass", "verify-ftp"),
];

/// Scenarios defined purely by process behaviour or a filesystem side effect.
const BEHAVIOUR_SCENARIOS: &[&str] = &[
    "hang",
    "hang_ignore_term",
    "no_session",
    "dirty_retry",
    "auth_fail",
];

/// Answer to the `--version` probe `acp doctor`/preflight makes; the real CLI's format.
const VERSION: &str = "2.1.221 (Claude Code)";

/// The `diffHash` key in the two forms one Claude transcript line carries it (B1): escaped inside
/// the `result`/assistant-text JSON strings, and plain inside the `structured_output` object.
const DIFF_HASH_MARKERS: [(&str, &str); 2] =
    [(r#"\"diffHash\":\""#, r#"\""#), (r#""diffHash":""#, r#"""#)];

/// Replaces every `diffHash` value on `line` with `hash`, in both forms. Mirrors the codex fake's
/// substitution; a hex digest never contains a quote or backslash, so the scan cannot misparse.
fn substitute_diff_hash(line: &str, hash: &str) -> String {
    let mut out = line.to_string();
    for (marker, close) in DIFF_HASH_MARKERS {
        let mut built = String::with_capacity(out.len());
        let mut rest = out.as_str();
        while let Some(at) = rest.find(marker) {
            let value_at = at + marker.len();
            built.push_str(&rest[..value_at]);
            rest = &rest[value_at..];
            let Some(end) = rest.find(close) else { break };
            built.push_str(hash);
            rest = &rest[end..];
        }
        built.push_str(rest);
        out = built;
    }
    out
}

/// The worktree change every replayed transcript describes: `src/adder.ts` holding the exact
/// `content` of the transcript's `Write` tool_use input (whose `file_path` is that path under the
/// `/tmp/acp-fixture-worktree` placeholder — see `fixtures/jsonl/README.md`). The fake makes the
/// change for real, so the loop's `changed_files`/`frozen_diff` have something to see.
/// `split_line-1.jsonl` is a trimmed two-line transcript with no `Write` block, but it replays the
/// same task, so it makes the same change. A test guards this copy against fixture drift.
const SOURCE_PATH: &str = "src/adder.ts";
const SOURCE_TEXT: &str =
    "export function add(a: number, b: number): number {\n  return a + b;\n}\n";

/// Shape of the real CLI's 401: a login hint plus the API error body, exit 1, nothing on stdout.
const AUTH_FAIL_STDERR: &str = concat!(
    "fake claude: authentication required - run /login\n",
    r#"API Error: 401 {"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#,
    "\n",
);

/// `fixtures/jsonl/README.md` § Invariants pins the split: the Claude line written in two pieces is
/// line 2, the `result` line (the Codex fake splits line 3, its `agent_message`, instead).
const SPLIT_LINE_INDEX: usize = 1;
/// Byte offset the split line is cut at — mid-object, never on a newline.
const SPLIT_OFFSET: usize = 40;
/// Floor for the gap between those two writes, so a tailer always observes the partial line (C6).
const SPLIT_GAP_MS: u64 = 50;

/// The two argv shapes the Claude adapter emits. Which one arrived never selects behaviour — the
/// scenario is env-driven — but it travels verbatim in the record line's `argv`, and a call matching
/// neither shape is a contract violation worth failing loudly on.
enum Shape {
    Fresh,
    Resume,
    Unknown,
}

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    record(&argv);

    // A `--version` probe is not a session: it replays nothing, and it must not count as a call of
    // the scenario, so it short-circuits before the counter is touched. It is still recorded.
    if argv.iter().any(|arg| arg == "--version") {
        println!("{VERSION}");
        process::exit(0);
    }

    let scenario = env::var("ACP_FAKE_SCENARIO").unwrap_or_else(|_| "pass".to_string());
    let known = TRANSCRIPTS.iter().any(|(name, _)| *name == scenario)
        || BEHAVIOUR_SCENARIOS.contains(&scenario.as_str());
    if !known {
        die(&format!("unknown ACP_FAKE_SCENARIO \"{scenario}\""), 2);
    }

    match invocation_shape(&argv) {
        Shape::Fresh | Shape::Resume => {}
        Shape::Unknown => die(
            "argv is neither the fresh (-p <prompt>) nor the resume (-p <msg> --resume <id>) shape",
            2,
        ),
    }

    let delay_ms = env::var("ACP_FAKE_DELAY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    if argv.windows(2).any(|w| w[0] == "--agent" && w[1] == "security") {
        let hash = env::var("ACP_FAKE_SECURITY_HASH").ok()
            .or_else(|| env::var("ACP_FAKE_VERIFY_HASH").ok()).unwrap_or_default();
        if hash.is_empty() { die("security invoked without a lifted diff hash", 2); }
        let verdict = serde_json::json!({"verdict":"PASS","diffHash":hash,"findings":[]});
        let session = "eeeeeeee-1111-4111-8111-eeeeeeeeeeee";
        let init = serde_json::json!({"type":"system","subtype":"init","session_id":session}).to_string();
        let result = serde_json::json!({"type":"result","subtype":"success","is_error":false,
            "session_id":session,"num_turns":1,"total_cost_usd":0.01,"duration_ms":1,
            "result":verdict.to_string(),"structured_output":verdict}).to_string();
        stream(&[&init, &result], delay_ms, None);
        process::exit(0);
    }

    // B1: a verifier invocation is selected by the argv the adapter built (`--agent verifier`),
    // not by `ACP_FAKE_SCENARIO` — the scenario keeps steering the *builder* (and its own
    // invocation counter, which a verifier call must not consume, or `fail_then_pass`-style
    // replays would shift). It echoes the diffHash the wrapper lifted from the prompt and makes
    // NO worktree change: a verifier that dirtied the tree would poison the frozen diff.
    let is_verifier = argv
        .windows(2)
        .any(|w| w[0] == "--agent" && w[1] == "verifier");
    if is_verifier {
        let verify_scenario =
            env::var("ACP_FAKE_VERIFY_SCENARIO").unwrap_or_else(|_| "verify_pass".to_string());
        // `verify_crash` is behavioural: dies before any output, like `no_session` — the loop
        // reads it as a verifier that told us nothing (one replacement, then the run blocks).
        if verify_scenario == "verify_crash" {
            let _ = next_invocation("verify_crash");
            process::exit(1);
        }
        // Only `verify_*` names: a builder scenario here would replay a build-result document
        // as a verify report — schema-invalid, two invalid_output verifiers, a blocked run, and
        // a misdiagnosis pointing at the loop. Die loudly instead.
        if !verify_scenario.starts_with("verify_")
            || !TRANSCRIPTS.iter().any(|(name, _)| *name == verify_scenario)
        {
            die(
                &format!("unknown ACP_FAKE_VERIFY_SCENARIO \"{verify_scenario}\""),
                2,
            );
        }
        let invocation = next_invocation(&verify_scenario);
        let hash = env::var("ACP_FAKE_VERIFY_HASH").unwrap_or_default();
        if hash.is_empty() {
            // Harness misconfiguration, not a loop condition: without the lifted hash the report
            // echoes "" and the run "blocks after 2 verifiers" — a misdiagnosis magnet. Die loud.
            die(
                "verifier invoked with no ACP_FAKE_VERIFY_HASH (wrapper hash-lift missing?)",
                2,
            );
        }
        let lines: Vec<String> = transcript(&verify_scenario, invocation)
            .iter()
            .map(|line| substitute_diff_hash(line, &hash))
            .collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        // `ACP_FAKE_WAIT_FILE` is the deterministic daemon-restart barrier, exactly as for
        // `lead_messages`: the session announces itself, then nothing else lands until the test
        // says the replacement daemon is up — so "restart across a live verify step" tests what
        // its name says instead of whatever the scheduler happened to allow.
        if let Ok(wait_file) = env::var("ACP_FAKE_WAIT_FILE") {
            let (init, rest) = refs.split_at(1.min(refs.len()));
            stream(init, delay_ms, None);
            while !PathBuf::from(&wait_file).exists() {
                thread::sleep(Duration::from_millis(10));
            }
            stream(rest, delay_ms, None);
        } else {
            stream(&refs, delay_ms, None);
        }
        process::exit(0);
    }
    let invocation = next_invocation(&scenario);

    match scenario.as_str() {
        "auth_fail" => {
            eprint!("{AUTH_FAIL_STDERR}");
            process::exit(1);
        }
        // Dies before any event, so no session id ever exists.
        "no_session" => process::exit(1),
        "dirty_retry" => {
            write_in_cwd("dirty.txt", "uncommitted");
            process::exit(1);
        }
        "hang" => {
            // Only the `system/init` line, then block until SIGTERM/SIGKILL.
            stream(&transcript("pass", 1)[..1], delay_ms, None);
            loop {
                thread::sleep(Duration::from_secs(3600));
            }
        }
        // `hang`, but deaf to SIGTERM: only SIGKILL can end it. It exists so a test can tell a
        // shutdown that *sends* the first rung from one that actually waits for the process to be
        // gone — a worker that ignores SIGTERM is the only thing that distinguishes them.
        "hang_ignore_term" => {
            // Safe: `signal(2)` with `SIG_IGN`, on a single-threaded process, before any handler
            // exists. SIGKILL cannot be ignored, which is the whole point of the scenario.
            unsafe {
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
            }
            stream(&transcript("pass", 1)[..1], delay_ms, None);
            loop {
                thread::sleep(Duration::from_secs(3600));
            }
        }
        _ => {
            if scenario == "worker_commits" {
                worker_commit();
            }
            if scenario == "denylist" {
                write_in_cwd("App.xcconfig", "x");
            }
            // `no_changes` replays the happy-path transcript — a `build-result` claiming
            // `src/adder.ts` was written — while leaving the worktree untouched, so the frozen diff
            // is empty and the attempt is `invalid_output{no_changed_files}` (Rev 25).
            if !matches!(
                scenario.as_str(),
                "no_changes" | "lead_chat" | "lead_messages"
            ) {
                write_source();
            }
            let split = if scenario == "split_line" {
                Some(SPLIT_LINE_INDEX)
            } else {
                None
            };
            let transcript = transcript(&scenario, invocation);
            if scenario == "lead_messages" {
                stream_lead_messages(&transcript, delay_ms);
            } else {
                stream(&transcript, delay_ms, split);
            }
            process::exit(0);
        }
    }
}

/// Appends one `{argv, cwd, envSubset, invocation}` line to `$ACP_FAKE_RECORD`. The fresh/resume
/// shape is observable from `argv` itself; the line keeps exactly these four keys so the codex fake
/// records the same shape.
fn record(argv: &[String]) {
    let Ok(path) = env::var("ACP_FAKE_RECORD") else {
        return;
    };
    // Every `ACP_*` key this process can see, sorted: a test asserts the set is exactly the
    // supervisor's `ACP_FAKE_*` pass-through (design § Worker environment).
    let acp_env_keys: BTreeSet<String> = env::vars_os()
        .filter_map(|(key, _)| key.into_string().ok())
        .filter(|key| key.starts_with("ACP_"))
        .collect();
    let entry = json!({
        "argv": argv,
        "cwd": cwd().display().to_string(),
        "envSubset": {
            "gitConfigCount": env::var("GIT_CONFIG_COUNT").ok(),
            "gitConfigKey0": env::var("GIT_CONFIG_KEY_0").ok(),
            "gitConfigValue0": env::var("GIT_CONFIG_VALUE_0").ok(),
            "acpEnvKeys": acp_env_keys,
        },
        "invocation": unix_ms(),
    });
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap_or_else(|err| die(&format!("open {path} failed: {err}"), 2));
    // One call = one line, appended in a single write so concurrent fakes never interleave.
    writeln!(file, "{entry}").unwrap_or_else(|err| die(&format!("write {path} failed: {err}"), 2));
}

/// Nth call of this scenario, persisted per provider so both fake bins can share one state file.
fn next_invocation(scenario: &str) -> u64 {
    let Ok(path) = env::var("ACP_FAKE_STATE") else {
        return 1;
    };
    let key = format!("{PROVIDER}:{scenario}");
    let mut state: Map<String, Value> = fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| match value {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();
    let n = state.get(&key).and_then(Value::as_u64).unwrap_or(0) + 1;
    state.insert(key, json!(n));
    fs::write(&path, format!("{}\n", Value::Object(state)))
        .unwrap_or_else(|err| die(&format!("write {path} failed: {err}"), 2));
    n
}

fn invocation_shape(argv: &[String]) -> Shape {
    match (flag_value(argv, "-p"), flag_value(argv, "--resume")) {
        (Some(_), Some(_)) => Shape::Resume,
        (Some(_), None) => Shape::Fresh,
        _ => Shape::Unknown,
    }
}

fn flag_value<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    argv.iter()
        .position(|arg| arg == flag)
        .and_then(|i| argv.get(i + 1))
        .map(String::as_str)
}

/// The scenario's transcript for its Nth call, clamped to the highest fixture recorded for it
/// (claude has a single numbered fixture per scenario today; the clamp exists for parity with codex).
fn transcript(scenario: &str, n: u64) -> Vec<&'static str> {
    let base = TRANSCRIPTS
        .iter()
        .find(|(name, _)| *name == scenario)
        .map(|(_, base)| *base)
        .unwrap_or_else(|| die(&format!("scenario \"{scenario}\" replays no transcript"), 2));
    for i in (1..=n).rev() {
        let name = format!("{base}-{i}");
        if let Some((_, text)) = FIXTURES.iter().find(|(fixture, _)| *fixture == name) {
            return text.lines().filter(|line| !line.is_empty()).collect();
        }
    }
    die(
        &format!(
            "no transcript for scenario \"{scenario}\" (looked for {base}-{n}.jsonl and below)"
        ),
        2,
    )
}

fn stream(lines: &[&str], delay_ms: u64, split_index: Option<usize>) {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            sleep_ms(delay_ms);
        }
        if split_index == Some(i) {
            // Two write+flush calls with a gap, so the supervisor's tailer sees a partial line (C6).
            let cut = split_offset(line);
            emit(&mut out, &line[..cut]);
            sleep_ms(delay_ms.max(SPLIT_GAP_MS));
            emit_line(&mut out, &line[cut..]);
        } else {
            emit_line(&mut out, line);
        }
    }
}

/// Replays the captured lead-message fixture. Tests may replace its assistant line with a large
/// number of text blocks without checking in a 500-entry fixture; the system/result lines remain
/// the captured wire shape and the production tailer still sees one real provider JSONL line.
/// `ACP_FAKE_WAIT_FILE` is a deterministic daemon-restart barrier: the session is visible and the
/// provider stays alive, but no assistant/result line can race ahead of the replacement daemon.
fn stream_lead_messages(lines: &[&str], delay_ms: u64) {
    let count = env::var("ACP_FAKE_MESSAGE_COUNT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    let owned: Vec<String> = lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            if index == 1 {
                if let Some(count) = count {
                    let content: Vec<Value> = (0..count)
                        .map(|i| json!({"type": "text", "text": format!("message {i}")}))
                        .collect();
                    return json!({
                        "type": "assistant",
                        "message": {"role": "assistant", "content": content}
                    })
                    .to_string();
                }
            }
            (*line).to_string()
        })
        .collect();
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    if let Ok(wait_file) = env::var("ACP_FAKE_WAIT_FILE") {
        let (init, rest) = refs.split_at(1.min(refs.len()));
        stream(init, delay_ms, None);
        while !PathBuf::from(&wait_file).exists() {
            thread::sleep(Duration::from_millis(10));
        }
        stream(rest, delay_ms, None);
    } else {
        stream(&refs, delay_ms, None);
    }
}

/// A cut mid-object, moved back to the nearest char boundary so the split never lands inside a
/// multi-byte character.
fn split_offset(line: &str) -> usize {
    let mut cut = SPLIT_OFFSET.min(line.len());
    while cut > 0 && !line.is_char_boundary(cut) {
        cut -= 1;
    }
    cut
}

fn emit(out: &mut impl Write, chunk: &str) {
    write!(out, "{chunk}")
        .and_then(|()| out.flush())
        .unwrap_or_else(|err| die(&format!("stdout write failed: {err}"), 2));
}

fn emit_line(out: &mut impl Write, line: &str) {
    writeln!(out, "{line}")
        .and_then(|()| out.flush())
        .unwrap_or_else(|err| die(&format!("stdout write failed: {err}"), 2));
}

/// The `worker_commits` side effect: a real commit in the worktree, which the loop must detect as a
/// worker violation. Identity is passed inline because the worktree under test may have no local,
/// global or system identity configured.
fn worker_commit() {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=ACP Fake",
            "-c",
            "user.email=acp-fake@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "fake-worker-commit",
        ])
        .current_dir(cwd())
        // `output()` captures git's stdout: the transcript is the only thing allowed on ours.
        .output()
        .unwrap_or_else(|err| die(&format!("git commit failed to spawn: {err}"), 2));
    if !output.status.success() {
        die(
            &format!(
                "git commit failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            2,
        );
    }
}

/// The change the transcript claims the worker made, written under cwd (creating `src/`), before a
/// single line is streamed — the tailer must never see the result before the file exists.
///
/// With `ACP_FAKE_SOURCE_SALT_FROM_PROMPT=1`, a comment derived from this call's own prompt is
/// appended, so two builders with *different tasks* write *different bytes*. The B3 sequence
/// e2e needs that: its second item bases on the first item's integrated commit, and an identical
/// write there would be an empty diff — a `NoChangedFiles` strike the real world would not have.
fn write_source() {
    let path = cwd().join(SOURCE_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|err| die(&format!("create {} failed: {err}", parent.display()), 2));
    }
    let mut text = SOURCE_TEXT.to_string();
    if env::var("ACP_FAKE_SOURCE_SALT_FROM_PROMPT").as_deref() == Ok("1") {
        let prompt = env::args()
            .skip(1)
            .skip_while(|a| a != "-p")
            .nth(1)
            .unwrap_or_default();
        // FNV-1a over the whole prompt: any prompt difference — a different task, a repair turn —
        // yields different bytes. A prefix would not: every builder prompt opens with the same
        // preamble (T75-T79 review, finding 1).
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in prompt.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        text.push_str(&format!("// {hash:016x}\n"));
    }
    fs::write(&path, text)
        .unwrap_or_else(|err| die(&format!("write {} failed: {err}", path.display()), 2));
}

fn write_in_cwd(name: &str, contents: &str) {
    let path = cwd().join(name);
    fs::write(&path, contents)
        .unwrap_or_else(|err| die(&format!("write {} failed: {err}", path.display()), 2));
}

fn cwd() -> PathBuf {
    env::current_dir().unwrap_or_else(|err| die(&format!("cwd unavailable: {err}"), 2))
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}

fn sleep_ms(ms: u64) {
    if ms > 0 {
        thread::sleep(Duration::from_millis(ms));
    }
}

fn die(message: &str, code: i32) -> ! {
    eprintln!("fake {PROVIDER}: {message}");
    process::exit(code);
}
