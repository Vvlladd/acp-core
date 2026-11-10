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
