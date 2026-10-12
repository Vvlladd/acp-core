# Third-party dependencies

Original ACP code is MIT. Dependencies retain their own licenses; the root MIT license does not
relicense them. Cargo.lock pins Rust dependencies. The Swift analyzer pins SwiftSyntax 603.0.1,
licensed under Apache-2.0 with the Swift exception. Dependency source is fetched by Cargo/SwiftPM
and is not vendored in this repository.

The release packager gathers normal/build Rust dependency notices, Rust standard-library notices
and the exact SwiftSyntax license. `docs/distribution/upstream-licenses/` holds provenance-checked
license texts for crates whose packaged copies omit them. Keep these notices with redistributions.
See [release instructions](docs/RELEASING.md).
