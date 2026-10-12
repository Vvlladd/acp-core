//! Fake `codex` CLI (T05). Replays the recorded transcripts in `fixtures/jsonl/codex/`, so no test
//! that uses it spends a token. **Never reads stdin** — matching the `</dev/null` requirement of
//! `codex exec`; there is no `io::stdin()` call anywhere in this file.
//!
//! Contract: `reports/03-design.md` § `src/bin/fake-claude.rs, fake-codex.rs` and
//! `fixtures/jsonl/README.md` § "Scenario → fixture map". Fixtures are `include_str!`-embedded so the
//! binary works when invoked through a symlink named `codex`. Tests prepend that symlink's directory
//! to `PATH` and configure the fake with these — and only these — variables:
//!   `ACP_FAKE_SCENARIO`  one of the 11 scenario names (default: `pass`) — steers the REVIEWER;
//!                        a workspace-write argv selects the writing mode instead (builder or,
//!                        by the verify-report schema document, verifier), C1
//!   `ACP_FAKE_VERSION`   overrides the `--version` answer (doctor's version-pin warn branch)
//!   `ACP_FAKE_RECORD`    file that receives one `{argv, cwd, envSubset, invocation}` JSON line per call
//!   `ACP_FAKE_STATE`     JSON file holding the per-scenario invocation counter (`"codex:<scenario>": n`)
//!   `ACP_FAKE_DELAY_MS`  pause between emitted lines (default 0)
//!   `ACP_FAKE_DIFF_HASH` replaces the `diffHash` the reviewer transcripts echo (Rev 25), in the
//!                        stream and in `-o`, so a loop test can make the fake echo the real hash
//!                        of the frozen diff — or a wrong one, to exercise the mismatch path
//!
//! Uses only `std` + `serde_json`; `cargo install --bin acp` ships neither fake.

use std::collections::BTreeSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::process;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

const PROVIDER: &str = "codex";
const VERSION: &str = "codex-cli 0.132.0";

/// `ACP_FAKE_VERSION` overrides the `--version` answer, so `doctor`'s version-pin warn branch
/// (C1) is testable without rebuilding the fake.
fn version() -> String {
    env::var("ACP_FAKE_VERSION").unwrap_or_else(|_| VERSION.to_string())
}

const REVIEW_PASS_1: &str = include_str!("../../fixtures/jsonl/codex/review-pass-1.jsonl");
const REVIEW_PASS_2: &str = include_str!("../../fixtures/jsonl/codex/review-pass-2.jsonl");
const REVIEW_FAIL_1: &str = include_str!("../../fixtures/jsonl/codex/review-fail-1.jsonl");
const TURN_FAILED_1: &str = include_str!("../../fixtures/jsonl/codex/turn-failed-1.jsonl");
const SPLIT_LINE_1: &str = include_str!("../../fixtures/jsonl/codex/split_line-1.jsonl");
/// C1: the codex **builder** transcript — an `apply_patch` command item and a `build-result`
/// `agent_message`. Selected by the argv (workspace-write tokens), never by the scenario.
const BUILD_PASS_1: &str = include_str!("../../fixtures/jsonl/codex/build-pass-1.jsonl");
/// C1/B1: the codex **verifier** transcript — a `verify-report` `agent_message` echoing
/// `ACP_FAKE_DIFF_HASH` through the same substitution as the reviewer fixtures. A verifier
/// makes NO worktree change: it must never mutate the frozen tree.
const VERIFY_PASS_1: &str = include_str!("../../fixtures/jsonl/codex/verify-pass-1.jsonl");

/// `fixtures/jsonl/README.md` § Invariants pins the split: the Codex line written in two pieces is
/// **line 3, the `agent_message`** (Claude splits line 2 instead).
const SPLIT_LINE_INDEX: usize = 2;
/// Floor for the gap between those two writes, so the tailer always observes the partial line (C6).
const SPLIT_GAP_MS: u64 = 50;

/// The `diffHash` key as it appears **inside** a transcript line, where the verdict document is a
/// JSON string and its quotes are therefore escaped: `…,\"diffHash\":\"<placeholder>\"}`.
const DIFF_HASH_MARKER: &str = r#"\"diffHash\":\""#;
/// What closes that value: the same escaped quote. A hex digest never contains a backslash.
const ESCAPED_QUOTE: &str = r#"\""#;

/// Flags that consume the next argv element. `--output-schema` is parsed and ignored: the
/// transcripts already carry the JSON verdict as the final `agent_message`.
const VALUE_FLAGS: &[&str] = &[
    "-m",
    "--model",
    "-s",
    "--sandbox",
    "-c",
    "--config",
    "-C",
    "--cd",
    "-o",
    "--output-last-message",
    "--output-schema",
    "-p",
    "--profile",
    "-i",
    "--image",
    "-a",
    "--ask-for-approval",
    "--color",
];

/// Scenario → transcripts, one per call; the last entry repeats for further calls. The same
/// `ACP_FAKE_SCENARIO` value reaches both fakes, so scenarios whose defining behaviour is
/// builder-side either replay a `pass` transcript here (the reviewer legitimately runs) or trip the
/// builder-only guard below (the reviewer must never run — see `is_builder_only`).
fn transcripts(scenario: &str) -> Option<&'static [&'static str]> {
    Some(match scenario {
        "pass" => &[REVIEW_PASS_1, REVIEW_PASS_2],
        "fail_then_pass" => &[REVIEW_FAIL_1, REVIEW_PASS_2],
        // No `agent_message`: the `-o` file is left unwritten and the exit code stays 0.
        "invalid" => &[TURN_FAILED_1],
        "split_line" => &[SPLIT_LINE_1],
        // The commit is the builder's side effect; the review that follows it is a normal pass.
        "worker_commits" => &[REVIEW_PASS_1, REVIEW_PASS_2],
        // Reproduced by leaving this bin off `PATH`, so reaching it at all is already the anomaly.
        "missing_bin" => &[REVIEW_PASS_1],
        _ => return None,
    })
}

/// Scenarios defined purely by process behaviour: they emit no transcript.
fn is_silent(scenario: &str) -> bool {
    matches!(scenario, "hang" | "no_session" | "auth_fail")
}

/// Scenarios the design never lets a reviewer see: a `denylist` hit escalates before any review is
/// spawned, and a dirty builder worktree is retried fresh. Replaying a PASS transcript here would
/// let a loop bug that wrongly continues into review look green, so the fake trips instead — zero
/// stdout, no `-o` file, exit 2 (the fake-misuse code).
fn is_builder_only(scenario: &str) -> bool {
    matches!(scenario, "denylist" | "dirty_retry")
}

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    record(&argv);

    if argv.iter().any(|arg| arg == "--version") {
        emit(format!("{}\n", version()).as_bytes());
        process::exit(0);
    }

    if argv.iter().any(|a| a.starts_with("model_catalog_json=")) {
        lead(&argv);
        return;
    }

    let security = argv.iter().any(|a| a.starts_with("developer_instructions=") && a.contains("selected security reviewer"));
    let scenario = match env::var(if security { "ACP_FAKE_SECURITY_SCENARIO" } else { "ACP_FAKE_SCENARIO" }) {
        Ok(value) if !value.is_empty() => value,
        _ => "pass".to_string(),
    };
    let diff_hash = if security { env::var("ACP_FAKE_SECURITY_HASH").ok().or_else(diff_hash_override) }
        else { diff_hash_override() };

    // C1: a workspace-write argv is a WRITING codex call — checked BEFORE the builder-only
    // tripwire, whose "fake-codex is only ever the reviewer" premise C1 retired for writing
    // calls. Which writing role is decided by the schema document the supervisor wrote for this
    // attempt: a verify-report schema (its status enum carries `nothing-to-run`) is a verifier —
    // it replays the verify transcript, echoes the diffHash, and makes NO worktree change; any
    // other schema is a builder — it makes the change for real (mirroring fake-claude's
    // `write_source`) and replays the build transcript. Neither consumes the reviewer scenario's
    // replay counter.
    if argv
        .iter()
        .any(|t| t == r#"sandbox_mode="workspace-write""#)
    {
        let parsed = parse_argv(&argv);
        if parsed.prompt.is_none() {
            die("missing trailing <PROMPT>", 2);
        }
        let delay_ms: u64 = env::var("ACP_FAKE_DELAY_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        // Fail LOUD when the role cannot be determined: a fake that guesses defaults to the
        // builder arm and writes into the worktree — the one action a verifier must never take.
        let Some(schema) = parsed
            .output_schema
            .as_deref()
            .and_then(|path| fs::read_to_string(path).ok())
        else {
            die("workspace-write call without a readable --output-schema", 2);
        };
        let is_verifier = schema.contains("nothing-to-run");
        if is_verifier {
            let _ = next_invocation("codex_verify");
            // The verify knob first (mirroring fake-claude's separation), so a reviewer
            // wrong-hash test's static ACP_FAKE_DIFF_HASH cannot poison a codex verifier in
            // the same run.
            let verify_hash = env::var("ACP_FAKE_VERIFY_HASH")
                .ok()
                .filter(|v| !v.is_empty())
                .or(diff_hash.clone());
            let lines = transcript_lines(&[VERIFY_PASS_1], 1, verify_hash.as_deref());
            stream(&lines, delay_ms, None);
            write_last_message(parsed.last_message_file.as_deref(), &lines);
        } else {
            let _ = next_invocation("codex_build");
            write_source();
            let lines = transcript_lines(&[BUILD_PASS_1], 1, None);
            stream(&lines, delay_ms, None);
            write_last_message(parsed.last_message_file.as_deref(), &lines);
        }
        process::exit(0);
    }

    // Checked before argv parsing and before the counter is bumped, so the tripwire is the only
    // thing this call can report — and `--version` (handled above) still works for preflight.
    if is_builder_only(&scenario) {
        die(
            &format!("reviewer invoked under builder-only scenario {scenario}"),
            2,
        );
    }

    let files: &[&str] = match transcripts(&scenario) {
        Some(files) => files,
        None if is_silent(&scenario) => &[],
        None => die(&format!("unknown ACP_FAKE_SCENARIO \"{scenario}\""), 2),
    };

    let parsed = parse_argv(&argv);
    if parsed.resume && parsed.thread_id.is_none() {
        die("missing <threadId> after `exec resume`", 2);
    }
    if parsed.prompt.is_none() {
        die("missing trailing <PROMPT>", 2);
    }

    let delay_ms: u64 = env::var("ACP_FAKE_DELAY_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let invocation = next_invocation(&if security { format!("security:{scenario}") } else { scenario.clone() });

    match scenario.as_str() {
        "auth_fail" => {
            // Shape of the real CLI's 401: a login hint plus the API error body, nothing on stdout.
            eprintln!("ERROR: 401 Unauthorized · run `codex login`");
            eprintln!(
                "stream error: {{\"error\":{{\"type\":\"authentication_error\",\"message\":\"missing or expired credentials in CODEX_HOME/auth.json\"}}}}"
            );
            process::exit(1);
        }
        // Dies before any event, so no thread id ever exists.
        "no_session" => process::exit(1),
        "hang" => {
            let started = transcript_lines(&[REVIEW_PASS_1], 1, diff_hash.as_deref());
            stream(&started[..1], delay_ms, None); // the `thread.started` line only
            loop {
                thread::sleep(Duration::from_secs(3600)); // dies only via SIGTERM/SIGKILL
            }
        }
        _ => {
            let lines = transcript_lines(files, invocation, diff_hash.as_deref());
            let split = (scenario == "split_line").then_some(SPLIT_LINE_INDEX);
            stream(&lines, delay_ms, split);
            write_last_message(parsed.last_message_file.as_deref(), &lines);
            process::exit(0);
        }
    }
}

/// `codex exec [FLAGS] <PROMPT>` (fresh) vs `codex exec resume [FLAGS] <threadId> <PROMPT>` (resume:
/// no `-s`, no `-C`). Parsed for the record line only — scenario selection is env-driven.
#[derive(Default)]
struct Parsed {
    resume: bool,
    thread_id: Option<String>,
    prompt: Option<String>,
    last_message_file: Option<String>,
    /// Captured for parity with the real CLI: the value must be consumed so it is never mistaken
    /// for the trailing prompt positional. The verdict comes from the transcript, so the schema
    /// file itself is never read.
    output_schema: Option<String>,
}

/// Flags may appear in any position; unknown boolean flags are ignored.
fn parse_argv(argv: &[String]) -> Parsed {
    let mut parsed = Parsed::default();
    let mut positionals: Vec<String> = Vec::new();
    let mut i = 0;

    if argv.first().map(String::as_str) == Some("exec") {
        i += 1;
        if argv.get(i).map(String::as_str) == Some("resume") {
            parsed.resume = true;
            i += 1;
        }
    }
    while i < argv.len() {
        let arg = argv[i].as_str();
        if arg == "--" {
            positionals.extend(argv[i + 1..].iter().cloned());
            break;
        }
        if arg.starts_with("--") {
            if let Some(eq) = arg.find('=') {
                set_option(&mut parsed, &arg[..eq], &arg[eq + 1..]);
                i += 1;
                continue;
            }
        }
        if VALUE_FLAGS.contains(&arg) {
            let value = argv.get(i + 1).map(String::as_str).unwrap_or_default();
            set_option(&mut parsed, arg, value);
            i += 2;
            continue;
        }
        if arg.starts_with('-') && arg != "-" {
            i += 1; // boolean flag (--json, --strict-config, …)
            continue;
        }
        positionals.push(argv[i].clone());
        i += 1;
    }

    if parsed.resume {
        parsed.thread_id = positionals.first().cloned();
        parsed.prompt = positionals.get(1).cloned();
    } else {
        parsed.prompt = positionals.first().cloned();
    }
    parsed
}

fn set_option(parsed: &mut Parsed, flag: &str, value: &str) {
    match flag {
        "-o" | "--output-last-message" => parsed.last_message_file = Some(value.to_string()),
        "--output-schema" => parsed.output_schema = Some(value.to_string()),
        _ => {}
    }
}

/// One call = one appended line. `acpEnvKeys` is every `ACP_*` variable this process can see, sorted,
/// so a test can assert the supervisor's env scrub passed through exactly the `ACP_FAKE_*` set.
fn record(argv: &[String]) {
    let Ok(file) = env::var("ACP_FAKE_RECORD") else {
        return;
    };
    if file.is_empty() {
        return;
    }
    let acp_env_keys: BTreeSet<String> = env::vars_os()
        .filter_map(|(key, _)| key.into_string().ok())
        .filter(|key| key.starts_with("ACP_"))
        .collect();
    let entry = json!({
        "argv": argv,
        "cwd": env::current_dir().map(|dir| dir.display().to_string()).unwrap_or_default(),
        "envSubset": {
            "gitConfigCount": env::var("GIT_CONFIG_COUNT").ok(),
            "gitConfigKey0": env::var("GIT_CONFIG_KEY_0").ok(),
            "gitConfigValue0": env::var("GIT_CONFIG_VALUE_0").ok(),
            "acpEnvKeys": acp_env_keys,
        },
        "invocation": unix_ms(),
    });
    let mut handle = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file)
        .unwrap_or_else(|error| die(&format!("open {file} failed: {error}"), 2));
    // One call = one line, appended in a single write so concurrent fakes never interleave.
    writeln!(handle, "{entry}")
        .unwrap_or_else(|error| die(&format!("write {file} failed: {error}"), 2));
}

/// Nth call of this scenario, persisted per provider so the two fake bins can share one state file.
fn next_invocation(scenario: &str) -> u64 {
    let Ok(file) = env::var("ACP_FAKE_STATE") else {
        return 1;
    };
    if file.is_empty() {
        return 1;
    }
    let key = format!("{PROVIDER}:{scenario}");
    let mut state: Map<String, Value> = fs::read_to_string(&file)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| match value {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();
    let n = state.get(&key).and_then(Value::as_u64).unwrap_or(0) + 1;
    state.insert(key, json!(n));
    fs::write(&file, format!("{}\n", Value::Object(state)))
        .unwrap_or_else(|error| die(&format!("write {file} failed: {error}"), 2));
    n
}

/// `exec resume` is just the next call, so it picks the next transcript; clamp to the last one.
fn transcript_lines(
    files: &[&'static str],
    invocation: u64,
    diff_hash: Option<&str>,
) -> Vec<String> {
    let index = invocation.min(files.len() as u64).saturating_sub(1) as usize;
    files
        .get(index)
        .copied()
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| match diff_hash {
            Some(hash) => substitute_diff_hash(line, hash),
            None => line.to_string(),
        })
        .collect()
}

/// `ACP_FAKE_DIFF_HASH`, rejected as fake misuse (exit 2) when it carries a character that would
/// corrupt the transcript it is spliced into. Any other value passes through verbatim — a test
/// exercising the Rev-25 mismatch path needs to be able to supply a *wrong* hash.
fn diff_hash_override() -> Option<String> {
    let value = env::var("ACP_FAKE_DIFF_HASH")
        .ok()
        .filter(|v| !v.is_empty())?;
    if value.contains('"') || value.contains('\\') {
        die(
            "ACP_FAKE_DIFF_HASH must not contain a quote or a backslash",
            2,
        );
    }
    Some(value)
}

/// Replaces the placeholder digest after every `diffHash` marker in one raw transcript line.
///
/// Hand-rolled rather than a regex: `regex` is not a dependency of this crate (design, § Stack).
/// The value is taken to run to the closing escaped quote rather than a fixed 64 characters, so a
/// fixture whose placeholder is re-cut cannot be silently truncated.
fn substitute_diff_hash(line: &str, hash: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(at) = rest.find(DIFF_HASH_MARKER) {
        let value_at = at + DIFF_HASH_MARKER.len();
        out.push_str(&rest[..value_at]);
        rest = &rest[value_at..];
        let Some(end) = rest.find(ESCAPED_QUOTE) else {
            break; // unterminated value: leave the rest of the line untouched
        };
        out.push_str(hash);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// One write + flush per line. `split_index` is written in two pieces instead, cut mid-object.
fn stream(lines: &[String], delay_ms: u64, split_index: Option<usize>) {
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            sleep_ms(delay_ms);
        }
        if Some(i) == split_index {
            let bytes = line.as_bytes();
            let cut = bytes.len() / 2; // mid-object, never on a newline
            emit(&bytes[..cut]);
            sleep_ms(delay_ms.max(SPLIT_GAP_MS));
            emit(&[&bytes[cut..], b"\n"].concat());
        } else {
            emit(&[line.as_bytes(), b"\n"].concat());
        }
    }
}

/// `-o <file>` receives only the last `agent_message` text, as the real CLI does. A transcript
/// without one (`turn-failed-1.jsonl`) leaves the file absent.
fn write_last_message(path: Option<&str>, lines: &[String]) {
    let Some(path) = path else {
        return;
    };
    let mut text: Option<String> = None;
    for line in lines {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if event["item"]["type"] == "agent_message" {
            if let Some(value) = event["item"]["text"].as_str() {
                text = Some(value.to_string());
            }
        }
    }
    if let Some(text) = text {
        let _ = fs::write(path, text);
    }
}

fn emit(bytes: &[u8]) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let mut rest = bytes;
    while !rest.is_empty() {
        match handle.write(rest) {
            Ok(0) => process::exit(0), // reader went away mid-transcript
            Ok(written) => rest = &rest[written..],
            Err(error) => match error.kind() {
                io::ErrorKind::Interrupted => continue,
                // stdout can be a non-blocking pipe; retry instead of dying mid-transcript.
                io::ErrorKind::WouldBlock => sleep_ms(5),
                io::ErrorKind::BrokenPipe => process::exit(0),
                _ => die(&format!("stdout write failed: {error}"), 3),
            },
        }
    }
    let _ = handle.flush();
}

fn sleep_ms(ms: u64) {
    if ms > 0 {
        thread::sleep(Duration::from_millis(ms));
    }
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis())
        .unwrap_or(0)
}

fn die(message: &str, code: i32) -> ! {
    eprintln!("fake {PROVIDER}: {message}");
    process::exit(code);
}

/// The worktree change the build transcript describes — the same file and content the Claude
/// fake writes (`SOURCE_PATH`/`SOURCE_TEXT` there; an equality test in `tests/fake_codex.rs`
/// guards the copy), so every loop assertion about the frozen diff holds for either builder.
fn write_source() {
    let path = std::path::Path::new("src/adder.ts");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::write(
        path,
        "export function add(a: number, b: number): number {\n  return a + b;\n}\n",
    )
    .is_err()
    {
        die("could not write src/adder.ts in the cwd", 2);
    }
}

/// Coordination-only transcript: no schema, source mutation or checker scenario counter.
fn lead(argv: &[String]) {
    let parsed = parse_argv(argv);
    if parsed.prompt.is_none() || parsed.output_schema.is_some() {
        die("lead requires a prompt and no structured output schema", 2);
    }
    let session = parsed.thread_id.as_deref().unwrap_or("01a02001-0001-7001-8001-000000000099");
    emit(format!("{}\n", json!({"type":"thread.started","thread_id":session})).as_bytes());
    if let Ok(path) = env::var("ACP_FAKE_WAIT_FILE") {
        while !std::path::Path::new(&path).exists() { sleep_ms(20); }
    }
    let text = if parsed.resume { "Codex follow-up answer." } else { "Codex planning answer." };
    let lines = vec![
        json!({"type":"item.completed","item":{"type":"agent_message","text":text}}).to_string(),
        json!({"type":"turn.completed","usage":{"input_tokens":0,"output_tokens":0,"cached_input_tokens":0}}).to_string(),
    ];
    stream(&lines, 0, None);
    write_last_message(parsed.last_message_file.as_deref(), &lines);
}
