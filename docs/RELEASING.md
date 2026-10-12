# Release the MIT runtime

A release contains `acp`, its matching `acp-swift-checks`, the MIT license and dependency notices.
The Mac app is not a dependency or payload. Never edit published release assets in place; create
a new release ID and update the plugin's pinned installer URL/hash after verifying the new archive.

1. Review the complete public file inventory and source diff. Run the documented Rust and Swift
   tests. Build from the committed public core, with Rust source path remapping and stripped symbols:

   ```sh
   CARGO_PROFILE_RELEASE_STRIP=symbols \
   RUSTFLAGS="--remap-path-prefix=$PWD=acp-core --remap-path-prefix=$HOME=/build" \
   bash scripts/install-source.sh --install-dir /absolute/new/staging-directory
   ```

2. Package that CLI/helper with `tools/package-free-runtime.py --cli ... --analyzer ...
   --swift-checkout ... --output /absolute/new/package-directory --release-id VERSION
   --public-preview`. The Swift checkout is in `target/source-install/swift/checkouts/swift-syntax`.
   The packager verifies pinned notices and source paths, includes the dependency licenses and
   writes checksums. It supports the initial arm64 CLI distribution. It applies ad hoc signatures;
   it does not produce a notarized release or upload anything.
3. Verify archive checksums, install in a disposable location, check versions and Doctor, and run
   the advisory Swift Review acceptance/sandbox checks. Provider probes require separate explicit
   authorization. Record skipped and pending checks accurately.
4. Publish an explicitly labeled prerelease only after review. Download it anonymously and verify
   the exact advertised hash. Update `acp-plugin`'s installer and `docs/runtime-release.json`
   together, then rerun its package and installer checks.

## Developer ID distribution remains pending

For a future trusted downloaded release, sign both executables with Developer ID Application,
a secure timestamp and hardened runtime; submit using a configured notarytool credential profile.
The present ad hoc packager must be changed to preserve and verify those signatures first.
A Developer ID Installer identity is needed only if a `.pkg` is introduced. A text skill needs
no Apple signature. Source publication does not authorize bypassing account permissions or
Gatekeeper. Keep signing keys and profiles out of this repository and release assets.
