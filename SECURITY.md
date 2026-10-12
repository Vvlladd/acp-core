# Security and trust boundaries

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/Vvlladd/acp-core/security/advisories/new).
Do not post credentials, customer code or raw private agent logs in public issues.

ACP validates roles, provider/model choices and argv; writing workers use isolated Git worktrees
and provider-specific sandboxing. It records review evidence against the exact attempt/diff and
refuses agent integration approval through MCP. These controls reduce specific risks; they do not
establish that arbitrary generated code is safe.

The local Unix socket accepts the owning OS user. A same-user process with shell/socket access
can impersonate a CLI client. The skill's human-approval rule is an instruction boundary on that
path, not a kernel-enforced physical-human test. Protect the account, runtime and host configuration.

Claude and Codex sandbox behavior is provider/version-specific. The spawned Codex lead is pinned
to codex-cli 0.153.0; writing-worker measurements in this release were made at 0.132.0 and Doctor
warns on drift. A newer CLI is not automatically proven compatible. Dated rates are estimates,
not live billing guarantees. Consult the executable catalog and Doctor before provider work.

Swift Review uses a bounded source-only request to its fixed local helper and remains advisory.
Disabled, unavailable, interrupted or failed checks must stay distinguishable from successful ones.
Downloaded previews are currently ad hoc signed, not notarized. Preserve quarantine and do not
use this project's installer to disable OS protection. Official signed distribution is pending.
