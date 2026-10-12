# Provider JSONL fixtures

Recorded provider transcripts replayed by the fake CLIs in `test/fixtures/bin/{claude,codex}` and parsed
directly by the provider unit tests. **No test that uses these files spends a token.**

Shapes are taken from real output captured on this machine on 2026-08-22 (Claude Code 2.1.221,
`codex-cli` 0.132.0) and documented in `reports/02-exploration.md` § "Provider event schemas". Every key
name and event shape is verbatim; the transcripts are **trimmed** (huge `tools`/`agents`/`plugins`/
`slash_commands` arrays cut down, `memory_paths` dropped, `usage.iterations` reduced to one entry) and all
machine-specific values are replaced by stable placeholders:

| Placeholder | Meaning |
|---|---|
| `aaaaaaaa-1111-…`, `bbbbbbbb-2222-…`, `cccccccc-3333-…`, `dddddddd-4444-…` | Claude `session_id` (one per fixture) |
| `01a02001-…` … `01a02005-…` | Codex `thread_id` (UUIDv7-shaped, one per fixture) |
| `/tmp/acp-fixture-worktree` | the builder worktree (`system/init.cwd`, `Write` tool paths) |
| `/tmp/acp-fixture-state/diffs/att-0001.patch` | the frozen diff handed to the reviewer |
| `a1a1…` / `a2a2…` / `f1f1…` / `5b5b…` (64 hex) | the reviewer's `diffHash` — sha256 of that frozen diff, one per codex fixture (`review-pass-1`, `review-pass-2`, `review-fail-1`, `split_line-1`) |
| `msg_01Fixture…` / `req_01Fixture…` / `toolu_01Fixture…` / `item_N` | provider-internal ids |

The task under review in every transcript is the same toy change: add `src/adder.ts` exporting
`add(a, b)`.

## `claude/` — `claude -p … --output-format stream-json --verbose`

One JSON object per line; the last line is the `result` object (`session_id`, `total_cost_usd`, `usage`,
`is_error`, `subtype`, `permission_denials`, and — because the adapter always passes `--json-schema` —
`structured_output`).

| File | Lines | Contents |
|---|---|---|
| `pass-1.jsonl` | 6 | The happy path: `system/init` → `system/thinking_tokens` (ignorable noise) → `assistant` with a `tool_use` block (`Write src/adder.ts`) → `user` with the matching `tool_result` → `assistant` whose single `text` block is the build-result JSON → `result` `subtype:"success"`, `is_error:false`, `structured_output` = a valid `build-result` document (`{status:"succeeded", filesChanged, summary}`). |
| `worker_commits-1.jsonl` | 6 | Byte-identical to `pass-1.jsonl`. The scenario's defining behaviour is a side effect (`git commit --allow-empty`) performed by the fake `claude` bin, not anything in the transcript; the file exists so the bin can resolve `<scenario>-<n>.jsonl` uniformly. |
| `invalid-1.jsonl` | 5 | Same flow, but the final message is prose and `structured_output` is **malformed** (`{"status":"done","files":"src/adder.ts"}` — `status` outside the enum, `filesChanged` missing, wrong key with the wrong type). `is_error` is still `false` and the exit code is still 0: the failure is schema validation, not the CLI. Drives `invalid_output`. |
| `max_turns-1.jsonl` | 4 | `system/init` → `tool_use` → `tool_result` → `result` `subtype:"error_max_turns"`, `is_error:true`, `terminal_reason:"max_turns"`, `errors:[…]`, and — matching the real capture — **no `result` / `structured_output` keys at all**. Parser-only fixture: no fake-CLI scenario replays it; it exists so `parseLine` can be tested for `errorCode === 'max_turns'`. |
| `split_line-1.jsonl` | 2 | A complete minimal transcript — `system/init` → `result` success (same content as `pass-1.jsonl`'s, own `session_id`), so the session id and the final result are both observable. The fake bin writes the **`result` line (line 2)** in two `appendFileSync` calls, splitting it mid-object so the supervisor's tailer sees a partial line (C6). |
| `lead-messages-1.jsonl` | 3 | A5 lead stream: `system/init` → one assistant line containing two text blocks around a `Read` tool call → successful result. `ACP_FAKE_MESSAGE_COUNT` replaces the assistant line with that many text blocks for the 500-event cap regression. |
| `verify-pass-1.jsonl` | 5 | B1 verifier happy path: `system/init` (agents `["verifier"]`) → `Bash` `tool_use`/`tool_result` (`cargo build && cargo test`) → final `text` = a `verify-report` JSON (`status:"pass"`) → `result` with the same `structured_output`. The `diffHash` value is a 64×`f` placeholder in **both** its forms (escaped inside the JSON strings, plain inside `structured_output`); the fake bin substitutes `ACP_FAKE_VERIFY_HASH` — lifted from the verifier's own prompt by the test wrapper — into every occurrence, mirroring the codex reviewer mechanism. |
| `verify-fail-1.jsonl` | 5 | Same shape, `status:"fail"`, two `failures` lines (a failing test name and a compiler error) that the strike's repair prompt must deliver verbatim. |
| `verify-nothing-1.jsonl` | 5 | Same shape, `status:"nothing-to-run"`, empty `commands`/`failures` — the repo-declares-no-test-command edge that must never fail a run. |
| `verify-ftp-1.jsonl` / `verify-ftp-2.jsonl` | 5 each | `verify_fail_then_pass`: the first verifier invocation replays the fail report, the second (after the builder's repair) the pass — the numbered-fixture walk the fake bins already use for `fail_then_pass` reviews. `verify-ftp-1` carries the same report content as `verify-fail-1` (its `session_id` differs), the way `worker_commits-1` mirrors `pass-1`. The verify fixtures' session ids form their own `aaaaaaaa-2222…6666` family. |

## `codex/` — `codex exec --json …`

Line 1 is always `{"type":"thread.started","thread_id":…}`. Every real capture also carries an
`item.completed` whose `item.type` is `error` (a config-deprecation warning) **before** `turn.started` —
it is kept deliberately, because it is a non-fatal `error` item that the parser must not mistake for a
failed turn. `turn.completed.usage` always has exactly the four keys `input_tokens`,
`cached_input_tokens`, `output_tokens`, `reasoning_output_tokens`. Because the adapter passes
`--output-schema`, the final `agent_message.text` is a schema-bound JSON document — a
`review-verdict` for the reviewer fixtures, a `build-result` for the argv-selected builder
(`build-pass-1`), a `verify-report` for the argv-selected verifier (`verify-pass-1`). Reviewer and
verifier documents since Rev 25 **must echo the frozen diff's `diffHash`**, so those fixtures carry one. `ACP_FAKE_DIFF_HASH`
makes the fake bin substitute that placeholder in both the stream and the `-o` file, which is how a loop
test supplies the real hash (or a deliberately wrong one) without editing a fixture.

| File | Lines | Contents |
|---|---|---|
| `review-pass-1.jsonl` | 7 | `thread.started` → deprecation `error` item → `turn.started` → `item.started`/`item.completed` `command_execution` (`command`, `exit_code`, `aggregated_output` = the frozen diff) → `agent_message` with `{"verdict":"PASS","findings":[],"diffHash":"a1a1…"}` → `turn.completed` with usage. |
| `review-pass-2.jsonl` | 7 | Second PASS (`diffHash` `a2a2…`), distinct `thread_id` and usage numbers, one non-blocking `suggestion` finding. Replayed on the **second** reviewer call (`pass` counter = 2, and the PASS half of `fail_then_pass`). |
| `review-fail-1.jsonl` | 7 | Same shape; the `command_execution` output shows `return a - b` and the `agent_message` carries `{"verdict":"FAIL","findings":[…],"diffHash":"f1f1…"}` with one `blocking` and one `suggestion` finding. |
| `turn-failed-1.jsonl` | 5 | `thread.started` → deprecation `error` item → `turn.started` → top-level `{"type":"error","message":…}` → `turn.failed{error:{message}}`. **No `agent_message`, no `turn.completed`** — the transcript ends without a result. Exit code stays 0, so the failure is only visible in the stream. |
| `build-pass-1.jsonl` | 7 | C1, **argv-selected** (a `workspace-write` argv, any scenario): the codex **builder** — `apply_patch` command item, then an `agent_message` carrying a `build-result` document. The summary's phrase "under the codex workspace-write seatbelt" is **load-bearing**: quoted into the reviewer's prompt it regression-guards the chokepoint against substring-scanning untrusted text (found live, T68). The fake bin also writes `src/adder.ts` for real. |
| `verify-pass-1.jsonl` | 6 | C1/B1, argv-selected + a `verify-report` `--output-schema`: the codex **verifier** — reports `pass`, echoes `ACP_FAKE_DIFF_HASH` through the standard substitution, makes **no** worktree change. |
| `split_line-1.jsonl` | 4 | A complete minimal transcript — `thread.started` → `turn.started` → `agent_message` (PASS verdict, `diffHash` `5b5b…`) → `turn.completed` with the four usage keys, so the thread id and the usage are both observable. The fake bin writes the **`agent_message` line (line 3)** in two `appendFileSync` calls, splitting it mid-object (C6). |

## Scenario → fixture map

`ACP_FAKE_SCENARIO` accepts the names below (the original set plus A5's lead scenarios). Five are defined purely by process
behaviour or a filesystem side effect and therefore have **no fixture file** — they are produced by the
fake bins in T03/T04.

| Scenario | `claude` fixture | `codex` fixture | Notes |
|---|---|---|---|
| `pass` | `pass-1.jsonl` | `review-pass-1.jsonl`, then `review-pass-2.jsonl` | Nth call picked by the counter in `$ACP_FAKE_STATE`. |
| `lead_messages` | `lead-messages-1.jsonl` | — | A5 lead-only assistant prose and message-cap scenario. |
| `lead_chat` | `lead-chat-1.jsonl` | — | Spawned lead succeeds with free text and no structured output, without writing the repository. |
| `verify_pass` (argv-selected: `--agent verifier` + `ACP_FAKE_VERIFY_SCENARIO`, default) | `verify-pass-1.jsonl` | — | B1 verifier reports `pass`, echoing `ACP_FAKE_VERIFY_HASH`; makes no worktree change. |
| `verify_fail` | `verify-fail-1.jsonl` | — | Verifier reports `fail` with two failure lines; drives the 17b strike with the failure text. |
| `verify_nothing` | `verify-nothing-1.jsonl` | — | Verifier reports `nothing-to-run`; the loop proceeds to review. |
| `verify_fail_then_pass` | `verify-ftp-1.jsonl`, `verify-ftp-2.jsonl` | — | First verify fails, the post-repair verify passes — the full strike-and-recover arc. |
| `verify_crash` | — | — | Behavioural: the verifier dies before any output (one replacement, then the run blocks). |
| `fail_then_pass` | `pass-1.jsonl` | `review-fail-1.jsonl`, then `review-pass-2.jsonl` | The builder always succeeds; the FAIL comes from the reviewer. |
| `invalid` | `invalid-1.jsonl` | `turn-failed-1.jsonl` | Exit code 0 in both cases. |
| `worker_commits` | `worker_commits-1.jsonl` (== `pass-1.jsonl`) | — | Bin runs `git commit --allow-empty` in cwd first. Reviewer side uses `pass`. |
| `denylist` | `pass-1.jsonl` | — | **No fixture.** Bin writes `App.xcconfig` in cwd, then streams the `pass` transcript. |
| `no_changes` | `pass-1.jsonl` | — | **No fixture.** Replays the `pass` transcript — whose `build-result` claims `src/adder.ts` was written — but makes **no worktree change at all**, so the frozen diff is empty and the attempt is `invalid_output{no_changed_files}` (Rev 25). Builder-only: no reviewer is ever started for an empty diff, so `codex` does not know this name. |
| `split_line` | `split_line-1.jsonl` | `split_line-1.jsonl` | Complete transcripts; exactly one line per file is emitted in two writes — the Claude `result` line (line 2) and the Codex `agent_message` line (line 3). |
| `hang` | — | — | **No fixture.** Claude writes only `pass-1.jsonl`'s `system/init` line, Codex only a `thread.started` line, then both block forever; they die only on SIGTERM/SIGKILL. |
| `hang_ignore_term` | — | — | **No fixture.** `hang`, plus `signal(SIGTERM, SIG_IGN)` before the stream: only SIGKILL ends it. Claude-only — it exists to prove the fatal-shutdown ladder waits for the second rung rather than merely scheduling it. |
| `no_session` | — | — | **No fixture.** Exit 1 with zero stdout lines, so no session/thread id is ever emitted. |
| `dirty_retry` | — | — | **No fixture.** Writes `dirty.txt` into cwd, then exits 1 with zero stdout — an uncommitted change and no session id. |
| `auth_fail` | — | — | **No fixture.** Exit 1, zero stdout, stderr mentioning authentication. |
| `missing_bin` | — | — | **No fixture and no bin.** Reproduced by prepending an empty directory to `PATH` so `preflight` reports `provider_missing`. |

## Consumers

`test/fixtures/bin/claude` (T03) and `test/fixtures/bin/codex` (T04) replay them;
`test/providers/claude.test.ts` (T10) and `test/providers/codex.test.ts` (T12) parse them directly;
`test/core/supervisor.test.ts` and the loop tests (T32–T36) drive the fake bins over them.

## Invariants

- Every line is a single complete JSON object, compact (no whitespace between tokens), terminated by `\n`
  — exactly as the CLIs write them.
- No absolute home path, real session/thread id, or account-specific value appears in any file.
- `pass-1.jsonl` contains exactly one `system/init` line and exactly one `result` line.
- Every Codex fixture starts with a `thread.started` line carrying a `thread_id`.
- `split_line-1.jsonl` is a complete transcript on both sides; the line the fake bin splits is fixed by
  this README (Claude line 2, the `result`; Codex line 3, the `agent_message`) so T04 and T18 agree.
  Re-ordering or inserting lines in those two files breaks the supervisor's C6 test.
- `pass-1.jsonl`'s `structured_output` must stay valid against `schemas/build-result.json`, and the codex
  `agent_message` verdicts valid against `schemas/review-verdict.json` (T28) — those three files are (build-pass-1's against `build-result.json`, verify-pass-1's against `verify-report.json` — `codex_build_and_verify_fixtures_validate_against_their_schemas`)
  written together and must be kept in sync. `diffHash` is **required** by that schema and must match
  `^[0-9a-f]{64}$`, so a reviewer fixture without one no longer validates.
