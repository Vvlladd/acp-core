# Design proposal: validated Claude effort selection (acp-core #8)

Status: proposal for human review. Nothing here is integrated until a human approves the gate.

## Evidence

- Installed CLI: `claude --version` printed `2.1.322 (Claude Code)`. `claude --help` lists
  `--effort <level>  Effort level for the current session (low, medium, high, xhigh, max)`.
- Host-captured docs (2026-11-10, worker egress denied; reference data only, not proof about older
  installed versions):
  `model-config.md` sha256 `0c49809e…4013`, `cli-reference.md` sha256 `f6223158…072d`. The
  model-config effort table lists `low`…`max` for current Opus models. Opus 5.5 defaults to
  `medium`. `--effort` is resolved per session and is not persisted, including on resume. The
  `CLAUDE_CODE_EFFORT_LEVEL` environment variable would override it.

## Closed catalog

`roles/roles.json` → `providers.claude.efforts = ["medium"]`, and `modelEfforts` narrows
`fable`, `sonnet` and `haiku` to `[]`. Only `opus` + `medium` is selectable. No new models or levels.
The existing loader rule (a narrowing must be a subset of the provider list and name a listed
model) still applies.

## Validation (`src/core/team.rs`)

- If a model's narrowed list is empty, setting an effort returns `effort_unsupported`, the same
  code a provider with no efforts returns. So `sonnet` + `high` keeps its current code.
- `opus` + `high` (or any level other than `medium`) returns `effort_not_allowed`.
- An unknown string still fails to deserialize into the closed `Effort` enum.
- A team that omits `effort` validates as before and gets byte-identical argv.

## Argv (`src/providers/claude.rs`)

When effort is set, the argv gets exactly two tokens, `--effort` and `<level>`, straight after
`--model <model>`. The value comes from a match over the enum that covers every case, so no
free-form string reaches it. `Minimal` is not a Claude level and is never emitted. When effort is
`None`, no token is added. The argv still passes through `assert_safe_argv`. The worker
environment allowlist stays as it is, so `CLAUDE_CODE_EFFORT_LEVEL` is never inherited.

## Lifecycle

- Fresh spawn: the recorded assignment's effort, as before.
- Resume (`--resume <id>`): Claude does not persist `--effort`, so the claude adapter emits the
  same `--effort` on resume. In the loop, a send-message resume now takes the recorded execution
  effort for workers too, not only for the lead. It only does this while the recorded assignment
  still names the agent's provider and model. Codex's resume argv still ignores `effort`.
- Recovery/retry (`spawn_for_agent`): already re-derives from the recorded execution. No change.
- Saved team edits do not alter a recorded execution (existing behaviour).
