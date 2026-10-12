#!/bin/bash
# MIT. Explicit local build/install; no provider calls, sudo, hooks or profile edits.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
revision="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || printf local)"
destination="$HOME/Library/Application Support/ACP/runtimes/source-0.1.0-$revision"
fail() { printf 'ACP source install: %s\n' "$*" >&2; exit 1; }
while [ "$#" -gt 0 ]; do
    case "$1" in
        --install-dir) [ "$#" -ge 2 ] || fail 'Missing --install-dir value'; destination="$2"; shift 2 ;;
        --help|-h) printf 'Usage: bash scripts/install-source.sh [--install-dir /absolute/new/directory]\nRequires native Apple Silicon macOS 26+, Rust 1.94+ and selected Xcode 27. Builds both binaries.\n'; exit 0 ;;
        *) fail "Unknown argument: $1" ;;
    esac
done
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || fail 'This verified installer targets native Apple Silicon macOS.'
[ "$(sw_vers -productVersion | cut -d. -f1)" -ge 26 ] || fail 'macOS 26 or newer is required.'
command -v cargo >/dev/null || fail 'Install Rust/Cargo 1.94+ first.'
xcode_version="$(xcodebuild -version 2>/dev/null)" || fail 'Select Xcode 27 with its command-line tools first.'
case "$xcode_version" in 'Xcode 27'*) ;; *) fail 'Select Xcode 27 (DEVELOPER_DIR may point to its Contents/Developer).';; esac
case "$destination" in /*) ;; *) fail 'Install directory must be absolute.';; esac
case "$destination" in *$'\n'*|*$'\r'*|/) fail 'Choose a dedicated directory without line breaks.';; esac
[ ! -e "$destination" ] && [ ! -L "$destination" ] || fail 'Install directory already exists; nothing replaced.'
parent="$(dirname "$destination")"
mkdir -p "$parent"
parent="$(cd "$parent" && pwd -P)"
[ "$(git -C "$parent" rev-parse --is-inside-work-tree 2>/dev/null || true)" != true ] || fail 'Install outside a Git checkout.'
destination="$parent/$(basename "$destination")"
build="$ROOT/target/source-install"
mkdir -p "$build"
cargo build --manifest-path "$ROOT/Cargo.toml" --locked --release --bin acp --target-dir "$build/rust"
swift build --package-path "$ROOT/tools/acp-swift-checks" --scratch-path "$build/swift" \
    --configuration release --force-resolved-versions
swift_bin="$(swift build --package-path "$ROOT/tools/acp-swift-checks" --scratch-path "$build/swift" \
    --configuration release --force-resolved-versions --show-bin-path)"
stage="$(mktemp -d "$parent/.acp-source.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
cp "$build/rust/release/acp" "$stage/acp"
cp "$swift_bin/acp-swift-checks" "$stage/acp-swift-checks"
cp "$ROOT/LICENSE" "$stage/LICENSE"
cp "$build/swift/checkouts/swift-syntax/LICENSE.txt" "$stage/SwiftSyntax-LICENSE.txt"
chmod 755 "$stage/acp" "$stage/acp-swift-checks"
codesign --force --sign - "$stage/acp"
codesign --force --sign - "$stage/acp-swift-checks"
codesign --verify --strict "$stage/acp"
codesign --verify --strict "$stage/acp-swift-checks"
mkdir "$destination" # Exclusive; never replace an existing or concurrently created install.
ditto "$stage" "$destination"
printf 'Built and installed ACP and matching helper in: %s\n' "$destination"
printf 'Local ad hoc signatures; not a Developer ID signed/notarized release.\n'
printf 'Activate in this terminal:\nexport PATH=%q:"$PATH"\n' "$destination"
printf 'Then: acp --version and acp doctor --repo /absolute/path/to/your/repository\n'
printf 'Install the free skill: https://github.com/Vvlladd/acp-plugin/blob/main/docs/INSTALLATION.md\n'
printf 'No daemon, provider work, host configuration or shell-profile changes were started.\n'
