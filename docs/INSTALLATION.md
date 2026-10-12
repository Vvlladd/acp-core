# Install ACP Core

## Compiled runtime and skill

Use the [public plugin installation guide](https://github.com/Vvlladd/acp-plugin/blob/main/docs/INSTALLATION.md).
It installs a pinned CLI and matching analyzer, then the skill for your chosen host. Provider
accounts are your own. The Mac app is optional and not included. See that guide for current
architecture, macOS, signing and fresh-host limitations.

## Build from source

Requirements: native Apple Silicon macOS 26+, Git, Rust/Cargo 1.94 or newer, and Xcode 27 with its
command-line toolchain selected. Other platform combinations are not accepted by this installer
until verified. The Swift package pins SwiftSyntax 603.0.1 in Package.resolved. Dependencies are
fetched from the locked Cargo/Swift package sources on the first build. No dependency installer,
sudo command or shell-profile edit is performed.

```sh
git clone https://github.com/Vvlladd/acp-core.git
cd acp-core
bash scripts/install-source.sh
```

To select a non-default Xcode, set `DEVELOPER_DIR=/absolute/path/to/Xcode.app/Contents/Developer`
for that command. For a new custom destination outside Git, use
`bash scripts/install-source.sh --install-dir /absolute/new/runtime-directory`.

The script builds native release binaries, ad hoc signs the locally built executables and places
both beside each other in a new directory. It also retains the MIT and SwiftSyntax notices. This
local installation is not a redistributable release package; maintainers use the notice-complete
[release process](RELEASING.md). `cargo install` alone omits the analyzer and is not the complete
installation route.

Use the PATH line printed by the script in your terminal, then run:

```sh
command -v acp
acp --version
acp doctor --repo /absolute/path/to/your/repository
```

Install the [free host skill](https://github.com/Vvlladd/acp-plugin/blob/main/docs/INSTALLATION.md#2-install-the-skill-in-your-preferred-host)
and start a fresh host conversation with this PATH. Building locally does not configure provider
credentials, change the lead model or start workers. Official downloaded binaries still need
Developer ID signing/notarization for the intended trusted distribution experience.

Ask the host to inspect readiness and your saved team before a small task. Do not register a
second `acp serve` while a detached owner already runs. Human approval remains human-only.
