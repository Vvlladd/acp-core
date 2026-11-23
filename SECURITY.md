# Security and trust boundaries

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/Vvlladd/acp-core/security/advisories/new).
Do not post credentials, customer code or raw private agent logs in public issues.

ACP validates roles, provider/model choices and argv; writing workers use isolated Git worktrees
and provider-specific sandboxing. It records review evidence against the exact attempt and diff.
Ordinary integration requires human approval. For an authorized run, only its designated lead
can use the lead decision path and only for plans or eligible local integration. Direct MCP
cannot approve. Escalations, external verification and native access grants remain human decisions.

The local Unix socket accepts the owning OS user. Same-user shell access can impersonate an
ordinary CLI client. For a lead opt-in and human decisions on an opted-in run, the daemon uses a
macOS system dialog with Cancel as the default. It binds the affirmative response to the exact
operation and rechecks the actor state before recording a decision. Systems without interactive
macOS confirmation refuse these operations. This is a local interaction boundary. Protect the OS
account, trusted desktop automation, runtime and state directory.

Claude and Codex sandbox behavior is provider- and version-specific. The spawned Codex lead is
pinned to `codex-cli 0.171.0-alpha.13`. The writing-worker sandbox has a separate measurement
baseline at `codex-cli 0.132.0` and Doctor warns on drift. Use the executable catalog and Doctor
before provider work. Dated rates are estimates,
and a model with no rate may have incomplete dollar accounting.

Swift Review uses a bounded source-only request to its fixed local helper and remains advisory.
Disabled, unavailable, interrupted or failed checks must stay distinguishable from successful ones.
Downloaded previews are currently ad hoc signed, not notarized. Preserve quarantine and do not
use this project's installer to disable OS protection. Official signed distribution is pending.
