# ACP Core contributor instructions

Read README.md, CONTRIBUTING.md, SECURITY.md and ROADMAP.md before changing behavior. This is the
public MIT core; the optional Mac app and internal planning records are maintained separately.
AGENTS.md is a symlink to this file. Edit this single source and preserve the symlink.

Keep changes scoped to the requested task. Do not run paid/live provider probes without explicit
human authorization. Tests use fake binaries. Never approve integration gates or change a saved
team without confirmation of the exact setup. Preserve the one-owner, worker isolation, checked
argv, bounded evidence and human-approval rules documented in CONTRIBUTING.md.

Provider/platform code stays outside src/core. Avoid new dependencies or protocol/profile changes
without a reviewed design. Cargo builds only Rust; the matching Swift helper is built separately
and installed beside resolved acp. Do not present missing/skipped/failed checks as passes.

Validate behavior with focused regressions and the relevant documented gates. Check Markdown
links and Mermaid diagrams for documentation changes. Report evidence and limitations accurately.
