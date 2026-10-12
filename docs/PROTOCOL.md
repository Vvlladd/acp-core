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
