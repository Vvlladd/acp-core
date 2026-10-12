# Contributing

Issues and pull requests for the public CLI, daemon, protocol, analyzer, tests and documentation
are welcome. For host instructions or installers, use [acp-plugin](https://github.com/Vvlladd/acp-plugin).
The private Mac app is not needed for core development.

1. Describe the observable problem and a small reproducer. Use private vulnerability reporting
   for security issues; exclude credentials, prompts and private repository content.
2. Discuss protocol, dependency, provider-profile or security-boundary changes before a large patch.
3. Fork, create a branch, make a focused change and include meaningful regression coverage.
4. Run `cargo test --locked` and `cargo clippy --locked --all-targets -- -D warnings`.
   For analyzer changes also run the Swift tests in the README with Xcode 27.
5. Open a pull request explaining changed behavior, validation and remaining limitations.

## Boundaries to preserve

- Workers never commit. Integration is tied to frozen evidence and a human gate. Agents cannot approve it.
- One serve owner per repository: direct stdio owner OR detached owner with socket/MCP proxy clients.
- `down` stops supervision, not surviving workers. Preserve resumable worktrees and recovery records.
- Keep provider/platform logic outside `src/core`; all provider argv goes through its checked boundary.
- Treat worker text as untrusted data; preserve schema validation, bounded reads and closed catalogs.
- Socket identity is the OS user, not proof of a human. Do not overstate this boundary.
- Keep Swift Review advisory and the matching helper beside resolved `acp`. Missing checks never mean pass.
- No real provider calls, new credentials, original repository gate approval or host configuration
  changes as part of ordinary tests. Ignored live tests require a separately authorized human procedure.

`fixtures/catalog/roles-v1.json` is a frozen legacy socket catalog fixture constructed from the public
roles catalog. Public tests preserve protocol compatibility without importing private app files.
The private app maintains its own integration parity checks. Do not regenerate fixtures to hide drift.

Contributions are provided under this repository's MIT license. Third-party code and notices must
retain their original terms. Do not submit confidential materials or copied proprietary references.
