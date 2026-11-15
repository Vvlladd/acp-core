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

When a human denies an integration gate, append order binds its `gate.created` record to the newest
durable frozen builder attempt, lineage and diff hash; `gate.resolving` records the feedback and
actor provenance. Later verifier, reviewer and security prompts reconstruct applicable repair
criteria from those append-only records, not from the mutable gate payload. Removing or replacing
the payload after denial therefore cannot change the criterion or block replay. A later MCP denial
remains advisory and cannot supersede the newest applicable socket-originated human criterion.

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

## Blocked verification and human host evidence

Verification has four outcomes. `fail` means a command ran and found a code/build/test failure;
`blocked` means a required command could not run because the worker environment lacked a concrete
capability; `pass` and `nothing-to-run` retain their existing meanings. A blocked report has
non-empty, bounded `blockers`, no `failures`, consumes no builder repair strike and starts no
equivalent verifier retry. It remains a blocked record: neither a worker nor ACP may relabel it as
pass or authorize a different environment. Failed, missing and skipped checks never count as
passing. Verification prerequisites such as temporary paths, local sockets, process inspection or
a named toolchain are declarative diagnostics only; they are not blanket network/process-access
guarantees.

Finalization records `diff.frozen.sourceInventoryHash` only when bounded full-source captures
before and after freezing agree under the existing worktree lock. External evidence must match
that durable baseline as well as the submission-time capture, including changes made before the
host's first capture. Legacy diffs or unavailable/unstable capture retain ordinary verification
and review behavior but cannot use host evidence; no baseline is invented from the current tree.
Old `verify.report` events default missing commands/blockers to empty and old stored verifier
results default missing blockers to empty. The current worker-output schema still requires blockers.

A human first runs `acp external-inventory <request-json>` immediately before and after the named
host commands. Both captures name the current run sequence, builder attempt and diff hash; the
daemon derives the recorded builder worktree and, under its existing per-worktree mutex, hashes a
bounded canonical inventory of the actual checkout root, directories and ordinary files, including
tracked, ignored and untracked inputs and empty directories. The inventory binds names, file kinds,
permission bits, complete file content, symlink targets and tracked deletions, including unchanged
tracked files. It excludes Git administrative metadata only at known repository roots, refuses
unsupported nested repository boundaries and special files, enforces path/file/aggregate/directory-
and submodule-depth bounds, and never follows a symlink. For an
initialized tracked submodule it binds the index gitlink, checked-out HEAD, and the recursively
bounded tracked, ignored and untracked source actually visible to the host. A missing checkout
is recorded distinctly; a present but uninitialized checkout, escape or cycle is refused. The
human then submits
host-side evidence with `acp external-verify <json-file>`. The daemon repeats that same inventory
capture at submission, so a wrong checkout, added/removed file or changed source is refused. The
socket-only `verification.external` action requires the current `runId`, `expectedRunSeq`, exact
builder attempt and frozen `diffHash`, every occurrence of a blocked-report command paired once with its host argv,
successful exit statuses,
toolchain identity and provenance, equal before/after source-inventory hashes matching ACP's
current full-checkout capture, limitations and an
explicit attestation. Toolchain identity, provenance and attestation each require nonblank text
without control characters. Denying a pending host-evidence gate keeps the run blocked for fresh evidence. ACP refuses stale state, changed source inventory, mismatched/tampered hashes,
active/finalizing attempts, pending/resolving gates, skipped/failed commands and evidence not
preceded by an environment-blocked report for those bytes. MCP has no corresponding action and
cannot approve this gate.

Host commands must put generated build products, caches and test output outside the tested
checkout (for example by selecting a toolchain-specific output directory elsewhere). Ignored paths
and directory structure are inputs too: creating or changing an ignored file or empty directory,
or changing relevant file/directory permission bits, between the before and after captures
invalidates the evidence. An ignored output tree that exceeds an inventory bound is refused rather
than partly attested. Inventory identities created before directories and their modes were covered
remain readable history, but cannot authorize new evidence; capture a fresh before/after pair with
the current daemon.

Before the gate is exposed, the complete validated evidence and daemon-captured inventory identity
are copied into an append-only preparation event. Approval requires the mutable payload to equal
that record exactly and a live source inventory under the shared worktree lock. The immediate
submission uses the capture whose lock is still held. If a crash leaves `gate.created` pending,
a later socket approval reacquires that lock, recaptures the checkout off the actor, and checks
the current gate, run, worktree and frozen baseline again before appending `gate.resolving`.
Changed source leaves the gate pending, without accepting evidence or starting a checker.
Only the accepted record is copied into `gate.resolving`; the payload is never an authority for
later prompts or predecessor checks. Approval is replay-safe: continuation
reconstructs only the next selected reviewer/security intent and does so at most once after a
restart. Reviewer and security prompts receive external evidence only when both builder attempt
and diff hash match their current frozen input; a repair makes older evidence invisible. The
blocked worker report remains alongside the host record, and the normal independent checks and
separate integration gate remain mandatory. Human attestation records provenance and intent; it is
not cryptographic proof that a test actually ran.

## Lifecycle and host routes

## Offline source evidence

The socket-only host workflow `acp evidence import <manifest.json>` copies a bounded local source
snapshot into an ACP-owned store outside daemon state and repositories; `acp evidence show
<bundle-id>` revalidates and displays it.
Core performs no network fetch. A version-1 import manifest has this shape:

```json
{
  "version": 1,
  "title": "Product 4.2 API references",
  "sources": [{
    "url": "https://docs.example.test/product/4.2/api",
    "retrievedAt": "2026-11-10T12:30:00Z",
    "sourceDate": "2026-11-09",
    "provenance": "installed_version",
    "sha256": "<64 lowercase hex characters>",
    "file": "api/index.md"
  }]
}
```

`provenance` is exactly `installed_version` or `current_documentation`; this distinction is part
of bundle identity. Files are relative to the manifest, copied under a separate `files/` directory,
and re-hashed whenever referenced. Limits are 64 KiB for both input and the exact installed
manifest, 64 files, 8 MiB per file and 32 MiB total. Safe relative paths, unique URLs/names, regular
non-symlink files and hashes are mandatory. A SHA-256 over ACP's compact canonical metadata is the
immutable bundle ID. Updating metadata or content means importing a new bundle, never modifying an
old one. The installed store is `.acp-evidence/<opaque namespace>/<bundle ID>` outside the
state directory (beside `~/.acp` in the default layout). For a custom state beneath a repository
or `.acp/worktrees`, ACP resolves the store beyond the outermost enclosing checkout, or refuses
when no disjoint external location exists. The opaque namespace binds the daemon's canonical
repository and state roots, so another repository/state pair cannot attach it. Evidence navigation
does not reveal the daemon state path or its human socket.
Store directories must be owner-only; source files and bundle directories are read-only. Legacy
unpublished references beneath the state directory fail closed and require explicit reimport.
Those modes are tamper detection and defense in depth, not isolation from a same-user provider.

Attach an installed ID to a new CLI delegation with `--evidence <bundle-id>`, or pass
`evidenceBundleId` to socket `delegate`/`lead.start`. The daemon resolves the ID into an ACP-owned
reference before writing `run.created`; callers cannot supply a path. Replay therefore preserves
the same identity. Prompts list concise URLs, dates, provenance, hashes and read-only paths without
inlining source text. Evidence navigation has its own 8 KiB prompt allowance: bundle identity,
network capability and the complete manifest location survive ordinary prompt truncation. Large
bundles show a bounded prefix of entries and an explicit omission count. They label imported text
untrusted and network capability
`unverified_provider_controlled`: a host-supplied bundle is not evidence that a worker can browse.

Before the prompt path reaches a process, admission requires an enforced provider write boundary.
Sandboxed writers and verifiers retain their checked worktree-only write profile. A non-writing
Codex role must positively carry the checked `read-only` sandbox mode on fresh and resume argv.
ACP does not currently have a verified read-only filesystem route for a non-writing Claude role;
attaching evidence to that configuration is blocked before provider preflight/launch with a remedy
to choose a supported confined Codex worker or remove the attachment. This applies to leads,
review/security roles, automatic checks and restart replay from their recorded provider settings;
catalog overrides do not bypass it. Tasks without evidence keep their ordinary provider behavior.

Evidence updates are admitted only as new task input using a new ID. An idle continuation first
records `task.evidence_updated`, so restart, retry and replacement prompts use the same accepted
reference. Updates do not expand sandbox permissions or inject data into an active attempt; use an
idle supported continuation/new delegation and preserve the existing checks, history and gate rules. Optional private-client
acceptance for these additive socket fields is pending.

Offline evidence is revalidated before every provider process starts, including resumed, automatic
retry/replacement/check and restart-reissued attempts. Full file hashing runs in a bounded helper;
the actor rechecks run state and cancellation before admitting the provider. Changed, missing or
unreadable content blocks the run with a zero-PID diagnostic attempt, no provider usage and no
builder strike. Prompt rendering validates only bounded metadata and never substitutes a warning
for this admission check. A cancelled or stopped run cannot launch after the helper completes.

`acp stop` waits for safe idle. `acp stop --cancel-work` cancels and drains when explicitly requested.
`acp down` stops the daemon but may leave workers alive for recovery. Never delete resumable
worktrees merely because supervision stopped. See CLI help for human commands.

## Retained worktrees and deliberate cleanup

Successful integration retains its ACP worktree so the recorded provider session remains
resumable. `acp worktree list` asks the actor for at most 128 registered lineages and explains each
as `retained`, `eligible`, `stale`, or `unavailable`; the response says when it was truncated.
The socket method `retention.inventory` and `acp worktree list` accept optional `runId`/`--run-id`
and `lineageId`/`--lineage-id` selectors. Selection happens before the same 128-item bound, so a
known lineage remains addressable beyond the unfiltered page. Retirement always requests a
run-scoped inventory. If that scoped run itself is truncated, the CLI requires an explicit lineage
instead of choosing from an incomplete result.
Ordinary `acp gc` keeps its existing narrow selection: only closed lineages that already carry a
`worktree.retired` event. Its removal now shares the exact identity, ignored-aware cleanliness,
Trash handoff, and preserved-ref checks, so an unsafe candidate is reported and retained. A
historically integrated lineage is bound to its recorded integration commit; an exhausted,
non-integrated lineage is instead bound to the base commit in its exact `worktree.created` record.
An advanced branch, dirty/untracked/ignored content, missing ownership, or an unavailable recovery
receipt is preserved rather than treated as an absent candidate.

`acp worktree retire <runId>` previews the exact repository, run, lineage, sequence, path, branch,
and integrated commit and prints a `confirmationToken` bound to all of them. Repeating it with
`--confirm <confirmationToken>` is a deliberate human socket action. The token carries the
original preview sequence; the CLI does not substitute a newly fetched sequence during confirmation. The daemon
rechecks the current actor state and refuses active work, pending/finalizing integration,
recoverable drafts, omitted/mismatched/stale preview tokens, and paths without the matching durable `worktree.created` and
`integrate.committed` records. This socket is same-user authentication, not proof of physical human
presence. No MCP tool exposes confirmation, and an MCP actor is rejected by the core. After any
state change, request a fresh preview and use its new token; deterministic tokens remain valid
across a daemon restart only while the exact recorded preview remains current.

Under the same per-worktree lock used by attempts and integration, confirmation verifies the exact
registered ACP branch and Git administration identity, the integrated commit, and an empty Git
status that includes modified, untracked, and ignored entries. Ignored content is therefore user
data and causes preservation, not removal. A `refs/acp/retained/<runId>/<lineageId>` ref preserves
the commit outside the linked worktree. Only then is `worktree.retired{resumable:false}` recorded.

Cleanup asks the supported macOS service for the Trash directory on the worktree's volume, chooses
an exclusive destination there, and durably records that destination and both filesystem
identities before the first rename. The source and destination parents are held as non-following
directory descriptors; the leaf is checked through the source descriptor and moved with macOS's
descriptor-relative, no-replace rename. That syscall makes destination exclusion atomic, but does
not condition the rename on filesystem identity. ACP therefore checks the moved identity through
the destination descriptor and, on a mismatch, attempts a no-replace restoration and reports the
exact path it could preserve. It then reports the recovery location. No file is unlinked by ACP,
and the result explicitly says disk space has not been reclaimed; space is reclaimed only if the
user later empties Trash. Automated tests
inject a private, same-filesystem no-replace destination and never touch a user's Trash. Platforms
without a supported Trash route preserve the worktree and report that limitation.

The bounded cleanup receipt is stored under the daemon-owned ACP state directory, outside the
repository and worker-controlled source. ACP refuses state layouts overlapping the repository or
resolved Git common directory. Malformed, redirected, oversized, or symlinked receipts fail
closed. A legacy receipt can be replaced with the current same-filesystem plan only while the
original registered worktree remains available for complete identity and content revalidation;
after a move it fails closed and preserves both the recovery item and registration for explicit
recovery.

After the handoff ACP verifies the moved directory's device/inode, `.git` file, and canonical Git
administration identity. Before every move and recovery step it resolves the repository's Git
common directory, derives the registration from that anchor and the registered worktree identity,
and cross-checks the receipt's filesystem identity. It moves that exact administration directory—including
Git's existing worktree lock metadata—into a deterministic, symlink-resistant recovery journal
anchored in the Git common directory, outside Git's `worktrees` registration directory. The source
and journal are therefore on the same filesystem even when private ACP state is on another volume;
the authority and receipt remain in private ACP state. The no-replace move and exact directory
identity check prevent destination reuse, and a reused public path is never passed to a destructive Git command.
It never runs repository-wide prune. Repeats and restarts recover before or after either rename,
verify the recovery item and retained ref, and refuse a new tree at the old path. If the public
path is already absent, inventory and confirmation require a bounded regular cleanup receipt that
names this run/lineage's retained ref and planned Trash and Git-administration recovery paths; a
missing, malformed, redirected, or mismatched receipt is stale and cannot authorize cleanup. A
missing Trash item is reported as incomplete until registration retirement is durable; afterward
it means the user emptied Trash and disk space was reclaimed. History, frozen evidence, integration events,
the preserved ref, the recoverable Trash item, and every unrelated worktree registration remain
intact.

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
