#!/bin/bash
# Build a self-contained universal analyzer; SwiftSyntax is linked into the executable.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${1:?Usage: tools/build-swift-review.sh OUTPUT_DIRECTORY [BUILD_CACHE_DIRECTORY]}"
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd)"
CACHE="${2:-$OUTPUT}"
mkdir -p "$CACHE"
CACHE="$(cd "$CACHE" && pwd)"
BINARIES=()
for ARCH in arm64 x86_64; do
    swift build --package-path "$ROOT/tools/acp-swift-checks" \
        --scratch-path "$CACHE/build-$ARCH" --configuration release \
        --triple "$ARCH-apple-macosx13.0" --force-resolved-versions
    BIN_DIR="$(swift build --package-path "$ROOT/tools/acp-swift-checks" \
        --scratch-path "$CACHE/build-$ARCH" --configuration release \
        --triple "$ARCH-apple-macosx13.0" --force-resolved-versions --show-bin-path)"
    BINARIES+=("$BIN_DIR/acp-swift-checks")
done
lipo -create "${BINARIES[@]}" \
    -output "$OUTPUT/acp-swift-checks"
codesign --force --sign - "$OUTPUT/acp-swift-checks"
"$OUTPUT/acp-swift-checks" --version
cp "$CACHE/build-arm64/checkouts/swift-syntax/LICENSE.txt" "$OUTPUT/SwiftSyntax-LICENSE.txt"
