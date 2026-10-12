//! T32: `roles/loader.rs` — embedded config, prompt hash pinning (S8), rate estimates
//! (`reports/03-design.md` § Test Strategy, row `roles/loader.rs`).
//!
//! Two of these tests are load-bearing rather than illustrative:
//!
//! - `embedded_prompt_bodies_hash_to_their_pinned_values` runs against the **checked-in**
//!   `roles/` files, not a copy, so editing a prompt without updating its `promptSha256` fails the
//!   build. That is what keeps the pin a live drift guard instead of dead configuration.
//! - `a_mutated_external_prompt_is_rejected` proves the pin actually rejects: it loads the
//!   untouched copy first (green), mutates one prompt body, and asserts the same call now fails
//!   with `RolePromptTampered`.
//!
//! The frontmatter rule is re-implemented here line-by-line rather than imported, so the loader's
//! substring-based version is checked against an independent oracle.

use std::fs;
use std::path::{Path, PathBuf};

use agent_control_plane::core::types::{
    ProviderName, RoleName, SandboxMode, SchemaName, TokenUsage,
};
use agent_control_plane::roles::loader::{
    estimate_cost_usd, load_roles, role_prompt, role_spec, RolesError, MAX_PROMPT_BYTES,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const ROLES_JSON: &str = "roles/roles.json";
const LEAD_PROMPT: &str = "roles/prompts/lead.md";
const BUILDER_PROMPT: &str = "roles/prompts/builder-worker.md";
const REVIEWER_PROMPT: &str = "roles/prompts/reviewer-worker.md";
const VERIFIER_PROMPT: &str = "roles/prompts/verifier-worker.md";

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_repo(rel: &str) -> String {
    fs::read_to_string(repo_path(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Everything after the second `---` line — the loader's rule, derived independently by walking
/// lines instead of searching for a delimiter substring.
fn body_after_frontmatter(raw: &str) -> &str {
    let mut delimiters = 0;
    let mut offset = 0;
    for line in raw.split_inclusive('\n') {
        offset += line.len();
        if line.strip_suffix('\n').unwrap_or(line) == "---" {
            delimiters += 1;
            if delimiters == 2 {
                return &raw[offset..];
            }
        }
    }
    panic!("prompt has no closing frontmatter delimiter");
}

/// A writable copy of the checked-in `roles/` tree, for the external (`$ACP_ROLES_FILE`) path.
fn roles_copy() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("prompts")).expect("prompts dir");
    fs::write(dir.path().join("roles.json"), read_repo(ROLES_JSON)).expect("roles.json");
    for (rel, name) in [
        (LEAD_PROMPT, "lead.md"),
        (BUILDER_PROMPT, "builder-worker.md"),
        (REVIEWER_PROMPT, "reviewer-worker.md"),
        (VERIFIER_PROMPT, "verifier-worker.md"),
        ("roles/prompts/security-worker.md", "security-worker.md"),
    ] {
        fs::write(dir.path().join("prompts").join(name), read_repo(rel)).expect("prompt");
    }
    dir
}

fn write_external(dir: &TempDir, cfg: &Value) -> PathBuf {
    let path = dir.path().join("roles.json");
    fs::write(&path, serde_json::to_string_pretty(cfg).expect("cfg")).expect("write roles.json");
    path
}

fn external_cfg(dir: &TempDir) -> Value {
    serde_json::from_str(&fs::read_to_string(dir.path().join("roles.json")).expect("roles.json"))
        .expect("parse roles.json")
}

// ---------------------------------------------------------------------------
// The embedded config
// ---------------------------------------------------------------------------

#[test]
fn the_embedded_config_loads_and_describes_every_role() {
    let cfg = load_roles(None).expect("embedded roles config");

    assert_eq!(cfg.version, 1);
    assert!(!cfg.gates.allow_agent_approve, "S2: agents cannot approve");
    assert_eq!(cfg.limits.max_concurrent_attempts, 2);
    assert_eq!(cfg.defaults.max_depth, 2);
    assert_eq!(cfg.defaults.run_budget_usd, 15.0);
    assert_eq!(cfg.defaults.spawn_budget_usd, 2.0);
    assert_eq!(cfg.defaults.attempt_timeout_sec, 1800);
    assert_eq!(cfg.defaults.await_result_max_sec, 300);
    assert!(cfg
        .defaults
        .denylist_globs
        .iter()
        .any(|g| g == "**/*.entitlements"));

    let builder = role_spec(&cfg, RoleName::Builder).expect("builder spec");
    assert_eq!(builder.role, RoleName::Builder);
    assert_eq!(builder.provider, ProviderName::Claude);
    assert!(builder.writes);
    assert_eq!(builder.max_turns, 40);
    assert_eq!(builder.spawn_budget_usd, 2.0);
    assert_eq!(builder.default_model, "sonnet");
    // Rev 26: a role's allowlist spans both providers, so a team can move the builder to codex;
    // `defaultModel` is what it is spawned with when no team says otherwise.
    assert_eq!(
        builder.models,
        vec![
            "fable",
            "opus",
            "sonnet",
            "haiku",
            "gpt-6-astra",
            "gpt-5.6-sol",
            "gpt-5.6-terra",
            "gpt-5.6-luna",
            "gpt-5.5",
            "gpt-5.3-codex-spark"
        ]
    );
    assert_eq!(builder.result_schema, SchemaName::BuildResult);
    assert!(
        builder.allowed_delegations.is_empty(),
        "workers never spawn"
    );

    let reviewer = role_spec(&cfg, RoleName::Reviewer).expect("reviewer spec");
    assert_eq!(reviewer.provider, ProviderName::Codex);
    assert!(!reviewer.writes);
    assert_eq!(reviewer.sandbox_mode, Some(SandboxMode::ReadOnly));
    assert_eq!(reviewer.max_turns, 12);
    assert_eq!(reviewer.result_schema, SchemaName::ReviewVerdict);
    assert!(reviewer.allowed_delegations.is_empty());

    // A lead's turns are conversation, validated against nothing: the catalog says so instead of
    // borrowing the builder's document (B3 walkthrough: "build-result — invalid structured result").
    let lead = role_spec(&cfg, RoleName::Lead).expect("lead spec");
    assert_eq!(lead.result_schema, SchemaName::FreeText);

    // Rev 26: the provider catalog every team assignment is checked against.
    let claude = cfg
        .providers
        .get(&ProviderName::Claude)
        .expect("claude catalog");
    assert!(claude.models.contains(&"sonnet".to_string()));
    assert!(
        claude.efforts.is_empty(),
        "claude takes no reasoning effort"
    );
    let codex = cfg
        .providers
        .get(&ProviderName::Codex)
        .expect("codex catalog");
    assert!(codex.models.contains(&"gpt-5.5".to_string()));
    // low, medium, high, xhigh, max — `minimal` was dropped 2026-08-26 (rejected upstream with
    // default-on tools) and `max` added 2026-09-11 (Revision 28); `ultra` is never listed.
    assert_eq!(codex.efforts.len(), 5);
    // Revision 28: a model may narrow the provider's list; the rest take the whole list.
    assert_eq!(codex.efforts_for("gpt-5.5").len(), 4);
    assert_eq!(codex.efforts_for("gpt-5.3-codex-spark").len(), 4);
    assert_eq!(codex.efforts_for("gpt-6-astra"), codex.efforts.as_slice());
    assert!(!codex.efforts_for("gpt-5.5").iter().any(|e| e.as_str() == "max"));

    let lead = role_spec(&cfg, RoleName::Lead).expect("lead spec");
    assert!(!lead.writes);
    assert_eq!(lead.provider, ProviderName::Claude);
    assert_eq!(
        lead.models,
        ["fable", "opus", "sonnet", "haiku", "gpt-6-astra", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.5", "gpt-5.3-codex-spark"]
    );
    assert_eq!(lead.default_model, "haiku");
    assert_eq!(lead.max_turns, 100);
    assert_eq!(lead.spawn_budget_usd, 2.0);
    assert_eq!(lead.tools.as_ref().map(Vec::len), Some(9));
    // B1: the loop's internal start_verifier resolves through the same delegation policy as
    // start_reviewer (caller_role Lead), so the lead spec must allow it — the DOORS still can't
    // name a verifier (DelegatableRole is unchanged), so this opens nothing to agents.
    assert_eq!(
        lead.allowed_delegations,
        vec![RoleName::Builder, RoleName::Reviewer, RoleName::Verifier, RoleName::Security]
    );

    // B1: the verifier ships in the embedded config — sandboxed-not-writer, haiku by default.
    let verifier = role_spec(&cfg, RoleName::Verifier).expect("verifier spec");
    assert!(!verifier.writes, "the verifier owns no deliverable");
    assert!(
        verifier.requires_sandbox(),
        "but it builds and tests, so it runs inside the kernel sandbox"
    );
    assert_eq!(verifier.provider, ProviderName::Claude);
    assert_eq!(verifier.default_model, "haiku");
    assert_eq!(verifier.max_turns, 24);
    assert_eq!(verifier.result_schema, SchemaName::VerifyReport);
    assert!(
        verifier.allowed_delegations.is_empty(),
        "workers never spawn"
    );
}

/// B1 compat: a custom roles file WITHOUT a verifier entry still loads — the verify step is
/// optional per config; the loop (T64) skips it when the role is absent. Nothing in the loader
/// may require the role to exist.
#[test]
fn an_external_config_without_a_verifier_still_loads() {
    let dir = roles_copy();
    let mut cfg = external_cfg(&dir);
    let removed = cfg["roles"]
        .as_object_mut()
        .expect("roles is an object")
        .remove("verifier");
    assert!(
        removed.is_some(),
        "the copied config carries a verifier to remove"
    );
    let roles = write_external(&dir, &cfg);
    let loaded = load_roles(Some(&roles)).expect("a verifier-less config is valid");
    let err = role_spec(&loaded, RoleName::Verifier).expect_err("absent, not defaulted");
    assert!(
        matches!(
            err,
            RolesError::UnknownRole {
                role: RoleName::Verifier
            }
        ),
        "expected UnknownRole, got {err:?}"
    );
}

/// S8's drift guard, run against the files that actually ship.
#[test]
fn embedded_prompt_bodies_hash_to_their_pinned_values() {
    let cfg: Value = serde_json::from_str(&read_repo(ROLES_JSON)).expect("roles.json is JSON");

    for (role, rel) in [
        ("lead", LEAD_PROMPT),
        ("builder", BUILDER_PROMPT),
        ("reviewer", REVIEWER_PROMPT),
        ("verifier", VERIFIER_PROMPT),
    ] {
        let pinned = cfg["roles"][role]["promptSha256"]
            .as_str()
            .unwrap_or_else(|| panic!("{role} pins no promptSha256"));
        assert_eq!(pinned.len(), 64, "{role}: promptSha256 is not a sha256");

        let raw = read_repo(rel);
        let actual = sha256_hex(body_after_frontmatter(&raw).as_bytes());
        assert_eq!(
            actual, pinned,
            "{rel} changed without its promptSha256 in {ROLES_JSON}: repin it to {actual}"
        );
    }
}

#[test]
fn role_prompt_returns_the_body_without_its_frontmatter() {
    let cfg = load_roles(None).expect("embedded roles config");

    let builder = role_prompt(&cfg, RoleName::Builder).expect("builder prompt");
    assert!(
        builder.starts_with("# Builder worker"),
        "frontmatter leaked into the prompt: {:?}",
        &builder[..builder.len().min(80)]
    );
    assert!(
        !builder.contains("name: builder-worker"),
        "frontmatter leaked into the prompt"
    );
    assert!(
        !builder.lines().any(|line| line == "---"),
        "a frontmatter delimiter line survived stripping"
    );
    assert_eq!(builder, body_after_frontmatter(&read_repo(BUILDER_PROMPT)));

    // The contract each prompt exists to carry (design, § `src/roles/loader.rs`).
    assert!(
        builder.contains("git commit"),
        "builder must be told not to commit"
    );
    assert!(builder.contains("filesChanged"));

    let reviewer = role_prompt(&cfg, RoleName::Reviewer).expect("reviewer prompt");
    assert!(reviewer.starts_with("# Reviewer worker"));
    assert!(
        reviewer.contains("diffHash"),
        "Rev 25: the verdict is diff-bound"
    );
    assert!(reviewer.contains("read-only") || reviewer.contains("read only"));

    let lead = role_prompt(&cfg, RoleName::Lead).expect("lead prompt");
    assert!(lead.starts_with("# ACP lead"));
    assert_eq!(lead, body_after_frontmatter(&read_repo(LEAD_PROMPT)));
    for tool in [
        "delegate",
        "send_message",
        "await_result",
        "get_status",
        "cancel",
        "request_human_gate",
        "resolve_gate",
    ] {
        assert!(lead.contains(&format!("`{tool}`")), "lead omits {tool}");
    }
    assert!(lead.contains("Only a human may approve"));
    assert!(lead.contains("Never run `git commit`"));
}

// ---------------------------------------------------------------------------
// The external override — the path an attacker would reach for (S8)
// ---------------------------------------------------------------------------

#[test]
fn a_mutated_external_prompt_is_rejected() {
    let dir = roles_copy();
    let roles = dir.path().join("roles.json");

    // Proven green first: the untouched copy loads, so the failure below is the mutation's doing.
    load_roles(Some(&roles)).expect("pristine copy loads");

    let prompt = dir.path().join("prompts/builder-worker.md");
    let mutated = fs::read_to_string(&prompt)
        .expect("prompt")
        .replace("Never run `git commit`", "Feel free to run `git commit`");
    assert!(
        mutated.contains("Feel free to run"),
        "the mutation did not apply — the prompt's wording changed"
    );
    fs::write(&prompt, mutated).expect("mutate prompt");

    let err = load_roles(Some(&roles)).expect_err("a mutated prompt must not load");
    assert!(
        matches!(
            err,
            RolesError::RolePromptTampered {
                role: RoleName::Builder,
                ..
            }
        ),
        "expected RolePromptTampered, got {err:?}"
    );
}

#[test]
fn an_oversized_external_prompt_is_rejected() {
    let dir = roles_copy();
    let prompt = dir.path().join("prompts/builder-worker.md");
    let mut padded = fs::read_to_string(&prompt).expect("prompt");
    padded.push_str(&"padding\n".repeat(MAX_PROMPT_BYTES / 8 + 1));
    assert!(padded.len() > MAX_PROMPT_BYTES);
    fs::write(&prompt, padded).expect("pad prompt");

    let err = load_roles(Some(&dir.path().join("roles.json")))
        .expect_err("an oversized prompt must not load");
    assert!(
        matches!(
            err,
            RolesError::RolePromptTooLarge {
                role: RoleName::Builder,
                ..
            }
        ),
        "expected RolePromptTooLarge, got {err:?}"
    );
}

/// Dropping the pin must not be a way to skip the check.
#[test]
fn an_external_role_with_a_prompt_but_no_pin_is_rejected() {
    let dir = roles_copy();
    let mut cfg = external_cfg(&dir);
    cfg["roles"]["builder"]
        .as_object_mut()
        .expect("builder spec")
        .remove("promptSha256");
    let roles = write_external(&dir, &cfg);

    let err = load_roles(Some(&roles)).expect_err("an unpinned prompt must not load");
    assert!(
        matches!(
            err,
            RolesError::PromptPinMissing {
                role: RoleName::Builder
            }
        ),
        "expected PromptPinMissing, got {err:?}"
    );
}

/// A `promptFile` that climbs out of the roles directory is input, not configuration.
#[test]
fn an_external_prompt_path_that_escapes_the_roles_directory_is_rejected() {
    let dir = roles_copy();
    let mut cfg = external_cfg(&dir);
    cfg["roles"]["builder"]["promptFile"] = json!("../../../etc/passwd");
    let roles = write_external(&dir, &cfg);

    let err = load_roles(Some(&roles)).expect_err("an escaping promptFile must not load");
    assert!(
        matches!(
            err,
            RolesError::PromptPathInvalid {
                role: RoleName::Builder,
                ..
            }
        ),
        "expected PromptPathInvalid, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Closed enums — rejected while parsing, never at spawn time
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_role_name_is_rejected_at_parse_time() {
    let dir = roles_copy();
    let mut cfg = external_cfg(&dir);
    let mut smuggled = cfg["roles"]["builder"].clone();
    smuggled["role"] = json!("hacker");
    cfg["roles"]["hacker"] = smuggled;
    let roles = write_external(&dir, &cfg);

    let err = load_roles(Some(&roles)).expect_err("an unknown role must not load");
    assert!(
        matches!(err, RolesError::Parse { .. }),
        "expected a parse failure, got {err:?}"
    );
}

#[test]
fn a_provider_outside_the_closed_set_is_rejected_at_parse_time() {
    let dir = roles_copy();
    let mut cfg = external_cfg(&dir);
    cfg["roles"]["builder"]["provider"] = json!("openai");
    let roles = write_external(&dir, &cfg);

    let err = load_roles(Some(&roles)).expect_err("an unknown provider must not load");
    assert!(
        matches!(err, RolesError::Parse { .. }),
        "expected a parse failure, got {err:?}"
    );
}

#[test]
fn a_role_whose_key_and_role_field_disagree_is_rejected() {
    let dir = roles_copy();
    let mut cfg = external_cfg(&dir);
    cfg["roles"]["builder"]["role"] = json!("reviewer");
    let roles = write_external(&dir, &cfg);

    let err = load_roles(Some(&roles)).expect_err("a mislabelled role must not load");
    assert!(
        matches!(
            err,
            RolesError::RoleKeyMismatch {
                key: RoleName::Builder,
                declared: RoleName::Reviewer,
                ..
            }
        ),
        "expected RoleKeyMismatch, got {err:?}"
    );
}

#[test]
fn a_missing_external_roles_file_is_an_error_not_a_fallback() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = load_roles(Some(&dir.path().join("nope.json")))
        .expect_err("a missing roles file must not fall back to the embedded config");
    assert!(matches!(err, RolesError::Io { .. }), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Rate table
// ---------------------------------------------------------------------------

#[test]
fn estimate_cost_usd_matches_the_hand_computed_gpt_5_5_price() {
    let cfg = load_roles(None).expect("embedded roles config");
    let usage = TokenUsage {
        input: 1_000_000,
        cached_input: 500_000,
        output: 200_000,
        reasoning: Some(64),
    };

    // 2026-09-11 card: 1.0 Mtok × $5 + 0.5 Mtok × $0.50 + 0.2 Mtok × $30 = 5 + 0.25 + 6 = $11.25.
    let cost = estimate_cost_usd(&cfg, "gpt-5.5", &usage);
    assert!(
        (cost - 11.25).abs() < 1e-9,
        "gpt-5.5 estimate was {cost}, expected 11.25"
    );

    // An unpriced model is worth nothing to the estimator — it never blocks or authorises a spawn.
    assert_eq!(estimate_cost_usd(&cfg, "sonnet", &usage), 0.0);
    assert_eq!(
        estimate_cost_usd(&cfg, "gpt-5.5", &TokenUsage::default()),
        0.0
    );
}

// ---------------------------------------------------------------------------
// Per-model efforts (Revision 28)
// ---------------------------------------------------------------------------

#[test]
fn a_model_effort_entry_for_a_model_the_provider_does_not_list_is_rejected() {
    let dir = roles_copy();
    let mut cfg = external_cfg(&dir);
    cfg["providers"]["codex"]["modelEfforts"]["gpt-9"] = json!(["low"]);
    let roles = write_external(&dir, &cfg);
    let err = load_roles(Some(&roles)).expect_err("an unlisted model cannot narrow efforts");
    assert!(
        matches!(err, RolesError::ModelEffortsForUnlistedModel { ref model, .. } if model == "gpt-9"),
        "{err}"
    );
}

#[test]
fn a_model_effort_outside_the_providers_list_is_rejected() {
    let dir = roles_copy();
    let mut cfg = external_cfg(&dir);
    // `minimal` is a closed-enum value the codex catalog no longer lists.
    cfg["providers"]["codex"]["modelEfforts"]["gpt-5.5"] = json!(["low", "minimal"]);
    let roles = write_external(&dir, &cfg);
    let err = load_roles(Some(&roles)).expect_err("a model cannot take an effort its provider does not");
    assert!(
        matches!(err, RolesError::ModelEffortNotInProvider { ref model, ref effort, .. } if model == "gpt-5.5" && effort == "minimal"),
        "{err}"
    );
}
