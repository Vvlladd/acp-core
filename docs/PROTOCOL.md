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

Events and state remain local. Output schemas are validated and free text is bounded/untrusted.
Frozen evidence identifies the attempt and exact diff, with an assembled 8 MiB diff budget.
Integration checks those bytes under the same worktree lock used for finalization. This is distinct
from host-composer delivery, which uses bounded-history heuristics rather than an unconditional
exactly-once guarantee.

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
