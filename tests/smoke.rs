//! Proves the crate and its full dependency graph compile and link under `cargo test` — including
//! `jsonschema` with `default-features = false`, the `rmcp` `macros` feature and `tokio-util`'s
//! `codec` feature.

#[test]
fn crate_compiles_and_links() {
    assert_eq!(2 + 2, 4);
}
