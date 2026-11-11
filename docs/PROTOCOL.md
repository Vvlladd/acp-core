# Runtime contract

The agent interface is MCP over stdio. The human/client interface is local Unix-socket NDJSON
JSON-RPC 2.0 with `protocolVersion: 1`. See `src/mcp/server.rs` and `src/ipc/socket.rs` for the
implemented methods and `schemas/` for checked-in structured worker outputs.

Choose one entry model: a host owns `acp serve` on stdio, or `acp up --managed --repo ...` owns a
detached `serve --no-mcp` and clients attach through CLI/socket or `acp mcp-proxy`. The skill uses
the latter. An attach result does not grant ownership of another session's daemon lifetime.

Team changes and integration approval are socket-only human operations. MCP may deny a gate but
cannot approve integration. Tasks retain their recorded team/execution settings across replay;
editing the saved team does not silently change an in-flight run. The daemon's closed catalog is
in `roles/roles.json`; arbitrary CLI flag passthrough is not supported.

A build run also retains the base commit resolved for its first builder. Every automatic
replacement lineage, including one reissued during restart reconciliation, creates its clean
worktree directly at that recorded full commit SHA. It does not resolve the original ref again,
consult a changed default, or infer a base from a worker worktree. If the durable run and initial
worktree records do not contain valid, consistent base provenance, replacement fails closed and
the run is blocked with its existing drafts, checks, usage, strikes and gates preserved.

## Run-budget design

`defaults.runBudgetUsd` is either a finite, non-negative JSON number or `null`; `null` is the
explicit unlimited value and is the default for newly created runs. It is not represented by
infinity or a large sentinel. Older roles files containing a number remain finite. Historical
`run.created` events which predate per-run capture continue to use that legacy configured cap (the
public catalog's was $15); an unlimited new default cannot remove that historical cap. Every
new run atomically includes its authoritative `runBudgetUsd` in `run.created`, so later
catalog edits do not change an in-flight run. Status continues to report cumulative `spendUsd` even
when the cap is unlimited.

The socket-only `run.budget.get`, `run.budget.set` and `run.budget.remove` operations inspect, set a
finite cap, or select unlimited. Mutations carry `runId`, `expectedSeq`, and optional
`continueBlocked`; `set` additionally carries numeric `runBudgetUsd`. A mutation requires the
caller's fresh expected run sequence and may optionally continue work stopped by the exact current
budget denial. Continuation is explicit: changing a cap alone starts nothing. Durable
`run.budget_changed` records the nullable cap, actor, and (only for an explicit continuation) the
typed continuation action. `run.budget_blocked` records that same action plus spend, attempt
reservation and finite cap. Actions distinguish a completed loop decision, an already-created
agent owed its exact attempt, and a replacement owed from a named closed lineage and checker
attempt. Continuation replays only that action on the same run, team, effort, draft and lineage; a later
attempt, gate, cancellation, terminal state, or unrelated block makes it stale. Historical logs
lack the creation field and keep using their finite legacy configuration (or the former $15
default when the loaded configuration is unlimited). MCP exposes no budget method.

Run caps are admission controls, distinct from the finite per-attempt provider limits. ACP reserves
the selected attempt cap before spawning and rechecks it at actual process admission after an
asynchronous worktree or restart; it records provider-reported usage, but neither an
admission estimate nor the cumulative projection is a guaranteed provider billing ceiling;
interrupted attempts can have incomplete usage. Concurrency, depth, attempt/time, lineage and
integration-gate rules are unchanged.

## Reasoning effort

A team assignment may carry an optional `effort`. It is checked against the closed catalog in
`roles/roles.json` (`providers.<name>.efforts`, narrowed per model by `modelEfforts`) before any
spawn; an effort for a model whose list is empty is `effort_unsupported`, and a value outside the
model's list is `effort_not_allowed`. Omitting `effort` stays valid and leaves the provider on its
own default, so teams saved before efforts existed keep working unchanged.

- **Codex** spends it as `-c model_reasoning_effort=<level>` on a fresh spawn only; its resume
  argv is unchanged and carries no effort.
- **Claude** accepts exactly `medium`, and only for the `opus` alias; `fable`, `sonnet` and `haiku`
  take none. The catalog is intentionally minimal. Claude Code 2.1.322 `--help` lists
  `--effort <level>` (`low, medium, high, xhigh, max`), and the CLI reference says the flag applies
  to the current session and does not persist. Because of that, ACP emits the checked pair
  `--effort medium` directly after `--model opus` on fresh **and** resume argv. No environment
  variable (such as `CLAUDE_CODE_EFFORT_LEVEL`) or other flag is passed through.
- The effort a run was started with is recorded in its execution assignments. Replays, fresh
  re-spawns, builder recovery, and lead **and** worker resumes reuse that recorded value, and
  only while the agent still runs the recorded provider and model. Editing the saved team later
  does not change it.

## Follow-ups and resumes

`send_message` (`acp send`, the socket and MCP doors) and a delegation with a resume session do
not deliver a message into a running process. Each launches a **new** provider attempt on the
agent's recorded session and worktree, and is accepted only while that agent is idle. At most one
accepted attempt owns an agent's session and writable worktree at a time, from the moment it is
accepted until the loop has processed its result:

- a spawn being prepared, an attempt that is running, being cancelled or being finalized, or a
  finished attempt whose loop step has not been recorded yet all make the agent busy;
- an overlapping follow-up is refused with the stable code `agent_busy` (detail: `agentId`,
  `state` = `preparing` | `running` | `result_pending`, `attemptId`). The refusal records no
  attempt, strike, spend or transcript turn; there is no queue, so retry once the agent is idle;
- a lead's own live attempt still answers `lead_busy` first; gate, budget and cancelled-run
  refusals are unchanged;
- an idle session whose last attempt finished — including one a human cancelled — accepts one
  follow-up, which makes it busy again until that attempt is processed.

A blocked or failed run does not accept an ordinary follow-up, even when its provider session is
otherwise resumable. The actionable route is a human-confirmed `run.recover`, which atomically
returns the run to `running`, keeps its preserved worktree and recorded execution/check selection,
and then starts the recovered builder. A deliberately cancelled whole run remains terminal and
cannot be recovered. Terminal cancelled or lost attempts do not need a synthetic loop-dispatch
marker, but live attempts, spawn/worktree preparation, cancellation, finalization, and pending
plan or integration decisions still make recovery unavailable.

Each recovery candidate reports an `allowance` computed from the recorded lineage and current
policy: retained strikes and strike limit, the one immediate builder attempt, same-lineage repair
attempts, automatic replacement lineages and their builder attempts, and the maximum builder
attempts in that recovery round. The counters are not reset. In particular, a candidate with no
repair or replacement capacity is explicitly `oneShot`: its next strike returns to human
escalation. A larger or unlimited spending choice is separate and never increases these counters.

Events and state remain local. Output schemas are validated and free text is bounded/untrusted.
Frozen evidence identifies the attempt and exact diff, with an assembled 8 MiB diff budget.
Integration checks those bytes under the same worktree lock used for finalization. This is distinct
from host-composer delivery, which uses bounded-history heuristics rather than an unconditional
exactly-once guarantee.

Schema-invalid worker output remains invalid; ACP does not relax the checked-in schemas. A missing
final output, malformed JSON, and a parsed document that violates the schema are reported
distinctly. Schema diagnostics contain only bounded field paths, constraint names, and safe counts
or observed lengths—never the rejected value or raw provider output. At most four violations and
1,024 diagnostic bytes are recorded. When output exists, the raw draft remains at the attempt's
recorded `resultPath`; an envelope for absent output carries an empty `resultPath` and creates no
artifact. Retry prompts keep
the existing worktree and counters. A replacement receives a clean worktree, but its handoff names
the retired worktree that preserves the implementation draft and distinguishes an output-format
rejection from a review or verification failure. Independent checks and the human integration gate
remain required after any successful retry or replacement.

A builder's process/schema outcome and task outcome are separate. A provider turn can finish
successfully with a schema-valid build result whose `status` is `failed`; ACP preserves that result
and any draft, records a `builder_failed` loop decision, and blocks with its bounded `summary`
before starting verification, review, security, or an integration gate. ACP does not infer an
environment failure from prose. After the underlying problem is fixed, the human-confirmed
recovery operation continues from the preserved draft without resetting spend, strikes, team,
effort, or selected checks; a successful recovered draft runs every recorded selected check.

## History compatibility

Event histories are executable only by builds that understand every well-formed event record.
Daemon startup, append paths and pruning fail closed when JSON data does not match this build's
event schema. Only a final, unterminated, syntactically incomplete fragment left by an interrupted
append is tolerated. Arbitrary newline-terminated syntax damage, trailing garbage, invalid UTF-8
and schema mismatches are incompatible records and cannot authorize execution or pruning.

Before appending past a known interrupted event fragment, the writer preserves every original
byte and appends byte 0x1e, "ACP-TAIL-V1:", the fragment's lowercase SHA-256 digest, and a newline.
This annotation identifies the exact discarded fragment on subsequent replays, so recovery does
not make the next restart reject its own history. A final partial annotation is accepted only if
it is an exact prefix of the expected annotation; the next append completes that suffix. A changed
fragment or annotation fails closed. The original fragment must be syntactically incomplete,
not a complete incompatible event, and fragment plus annotation are bounded to 8 MiB. Completed
events missing only a newline and whitespace tails need no annotation. Annotated fragments stay
visible in skipped-record counts; they never become operational events. The digest establishes
byte identity, not authenticity against someone who can rewrite the state directory.

`acp status` is a read-only inspection path. For incompatible history it labels the ordinary
projection incomplete and separately reports bounded compatibility metadata: aggregate record
counts and limited run, attempt and agent identifiers, with explicit omission markers. Those
identifiers are not reconstructed into runnable state, and inspection cannot append events or
audit entries. Use the CLI and daemon build that wrote the history before continuing execution.

A historical `execution.limits` object and string `"unlimited"` attempt limits are not supported
for execution. Status can identify affected `run.created` and `attempt.started` records, but this
build never converts those values into current numeric limits or authorizes execution from them.

## Lifecycle and host routes

`acp stop` waits for safe idle. `acp stop --cancel-work` cancels and drains when explicitly requested.
`acp down` stops the daemon but may leave workers alive for recovery. Never delete resumable
worktrees merely because supervision stopped. See CLI help for human commands.

The optional private app is another socket client. `acp app` task links do not install that app
or transfer a host's entire conversation. Standalone `acp review` works through the public CLI
and helper; automatic builder checks and direct lead/MCP review are still future work.

## Usage accounting

Persisted `TokenUsage` records use disjoint categories: `input` is fresh, uncached input and
`cachedInput` is cache-read input. Rate-table estimates charge each category once at its own rate.
Provider adapters normalize native counters at the boundary; in particular, Codex reports cached
input as a subset of total input, so ACP subtracts that subset for newly processed attempts.
If a Codex event reports cached input greater than total input, fresh input safely saturates at zero
and the reported cached count is retained rather than hidden.

This normalization is prospective. Raw provider stdout remains verbatim, and ACP does not rewrite
persisted token or spend records. Historical attempts, including blocked runs, therefore retain the
accounting recorded by the version that executed them.

## Provider admission failures

Provider adapters may classify a validated native refusal as `provider_usage_limit` or
`provider_model_unavailable`. These mean the provider declined the recorded account/model before
worker work began; they are not review findings. ACP records the attempt and its bounded provider
message, blocks the run without a lineage strike, and does not start an equivalent replacement.
Unknown and transient provider failures remain under the normal finite retry and checker limits.

After access changes, a human may deliberately recover the preserved draft. Recovery retains the
recorded execution profile, usage, historical strikes, selected verify/review/security steps and
human integration gate; it does not probe accounts, switch providers/models, or treat an unavailable
check as passing.
