//! Loads and validates `roles/roles.json` + `roles/prompts/*.md`, pinning each prompt by hash.
//! Implemented in T31 (`reports/03-design.md` § `src/roles/loader.rs`).
//!
//! The default config and both prompt bodies are `include_str!`-embedded at compile time, so an
//! installed `acp` binary has **no package root to find and no file to tamper with**: the role set,
//! the budgets and the exact words every worker is started with ship inside the executable.
//!
//! `$ACP_ROLES_FILE` still points [`load_roles`] at an external config for development and tests.
//! That path is the one an attacker would reach for, so it is the one that is checked: each
//! referenced prompt file must sit under the roles file's own directory, must be at most
//! [`MAX_PROMPT_BYTES`], and must hash to the `promptSha256` pinned in the config — otherwise the
//! load fails with [`RolesError::RolePromptTampered`] (S8). A role that names a `promptFile` with
//! no pin at all is rejected too ([`RolesError::PromptPinMissing`]): dropping the pin must not be a
//! way to skip the check.
//!
//! The same verification runs over the *embedded* pair, where it is a drift guard rather than a
//! defence — it fails the moment a prompt is edited without its `promptSha256` being updated.
//!
//! **Only the body is pinned.** The YAML frontmatter — everything up to and including the second
//! `---` line — is stripped textually, with no YAML parser (design, § `src/roles/loader.rs`), and
//! the body is the only part a worker is ever shown, so the pin covers exactly what reaches the
//! model.
//!
//! [`RolesConfig`] itself lives in `core::types` (T20's choice, so `core::policy` can take
//! `&RolesConfig` without `core` depending on `roles`); this module is the only thing that builds
//! one.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::core::types::{ProviderName, RoleName, RoleSpec, RolesConfig, TokenUsage};

/// Largest prompt file an external (`$ACP_ROLES_FILE`) config may reference, in bytes. The
/// embedded prompts are compiled in and need no cap; this one bounds what a config found on disk
/// can make the daemon read into memory and hand to a worker.
pub const MAX_PROMPT_BYTES: usize = 100 * 1024;

/// The line that opens a prompt's frontmatter, and the one that closes it.
const FRONTMATTER_OPEN: &str = "---\n";
const FRONTMATTER_CLOSE: &str = "\n---\n";

/// What error messages call the compiled-in config — there is no path to name.
const EMBEDDED_LABEL: &str = "<embedded roles.json>";

const EMBEDDED_ROLES_JSON: &str = include_str!("../../roles/roles.json");

/// Every prompt compiled into the binary, keyed by the `promptFile` value that selects it. The
/// embedded config may not reference anything else.
const EMBEDDED_PROMPTS: &[(&str, &str)] = &[
    (
        "prompts/security-worker.md",
        include_str!("../../roles/prompts/security-worker.md"),
    ),
    (
        "prompts/lead.md",
        include_str!("../../roles/prompts/lead.md"),
    ),
    (
        "prompts/builder-worker.md",
        include_str!("../../roles/prompts/builder-worker.md"),
    ),
    (
        "prompts/reviewer-worker.md",
        include_str!("../../roles/prompts/reviewer-worker.md"),
    ),
    (
        "prompts/verifier-worker.md",
        include_str!("../../roles/prompts/verifier-worker.md"),
    ),
];

/// The embedded config, parsed and hash-verified once (design: "cached in `OnceLock`"). Only a
/// success is cached: a failure is fatal and re-deriving it costs one hash of two small strings.
static EMBEDDED: OnceLock<Arc<RolesConfig>> = OnceLock::new();

/// Verified prompt bodies, keyed by their own sha256 — the identity [`role_prompt`] resolves.
///
/// [`RolesConfig`] has nowhere to put a prompt body (it mirrors `roles.json` exactly), and
/// `role_prompt` returns a `&str` with no way to do I/O, so the verified bodies live here instead.
/// Keying on the content hash means two configs that pin the same prompt share one copy and
/// reloading the same file adds nothing. An external body is interned with [`Box::leak`]: at most
/// [`MAX_PROMPT_BYTES`] per *distinct* prompt an explicit `$ACP_ROLES_FILE` override introduced,
/// which is what buys the `&'static str` the signature needs.
static PROMPT_BODIES: RwLock<BTreeMap<String, &'static str>> = RwLock::new(BTreeMap::new());

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every way loading the role config can fail. [`RolesError::RolePromptTampered`] is the one the
/// design names (S8); `core::policy` surfaces it as `PolicyCode::RolePromptTampered`.
#[derive(Debug, Error)]
pub enum RolesError {
    #[error("roles config {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("roles config {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("roles config {path}: role {key:?} declares itself {declared:?}")]
    RoleKeyMismatch {
        path: PathBuf,
        key: RoleName,
        declared: RoleName,
    },
    #[error("role {role:?} is not in this roles config")]
    UnknownRole { role: RoleName },
    #[error("role {role:?} has no prompt")]
    PromptNotConfigured { role: RoleName },
    #[error("role {role:?} names a promptFile but pins no promptSha256")]
    PromptPinMissing { role: RoleName },
    #[error("role {role:?}: promptFile {path:?} {reason}")]
    PromptPathInvalid {
        role: RoleName,
        path: String,
        reason: &'static str,
    },
    #[error("role {role:?}: prompt {path} is larger than the {max}-byte cap")]
    RolePromptTooLarge {
        role: RoleName,
        path: PathBuf,
        max: usize,
    },
    #[error(
        "role {role:?}: prompt {path} does not match its pinned sha256 (pinned {expected}, got {actual})"
    )]
    RolePromptTampered {
        role: RoleName,
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error("roles config {path}: role {role:?} names provider {provider:?}, which has no `providers` entry")]
    UnknownProvider {
        path: PathBuf,
        role: RoleName,
        provider: ProviderName,
    },
    #[error(
        "roles config {path}: role {role:?} defaults to model {model:?}, which provider {provider:?} does not offer"
    )]
    DefaultModelNotInProvider {
        path: PathBuf,
        role: RoleName,
        provider: ProviderName,
        model: String,
    },
    #[error("roles config {path}: role {role:?} allows model {model:?}, which no provider offers")]
    ModelNotInAnyProvider {
        path: PathBuf,
        role: RoleName,
        model: String,
    },
    #[error(
        "roles config {path}: provider {provider:?} narrows efforts for model {model:?}, which it does not list"
    )]
    ModelEffortsForUnlistedModel {
        path: PathBuf,
        provider: ProviderName,
        model: String,
    },
    #[error(
        "roles config {path}: provider {provider:?} gives model {model:?} effort {effort:?}, which the provider does not take"
    )]
    ModelEffortNotInProvider {
        path: PathBuf,
        provider: ProviderName,
        model: String,
        effort: String,
    },
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Loads the role config: the embedded one when `path` is `None` (production), the file at `path`
/// when it is `Some` (the `$ACP_ROLES_FILE` development override).
///
/// Either way every configured prompt is verified against its pin before the config is returned,
/// so a caller holding an `Arc<RolesConfig>` holds one whose prompts are known-good.
pub fn load_roles(path: Option<&Path>) -> Result<Arc<RolesConfig>, RolesError> {
    match path {
        None => load_embedded(),
        Some(path) => load_external(path),
    }
}

fn load_embedded() -> Result<Arc<RolesConfig>, RolesError> {
    if let Some(cfg) = EMBEDDED.get() {
        return Ok(Arc::clone(cfg));
    }
    let label = || PathBuf::from(EMBEDDED_LABEL);
    let cfg: RolesConfig =
        serde_json::from_str(EMBEDDED_ROLES_JSON).map_err(|source| RolesError::Parse {
            path: label(),
            source,
        })?;
    check_role_keys(&cfg, &label())?;
    check_providers(&cfg, &label())?;
    for (role, spec) in &cfg.roles {
        let Some(file) = spec.prompt_file.as_deref() else {
            continue;
        };
        let raw = EMBEDDED_PROMPTS
            .iter()
            .find(|(name, _)| *name == file)
            .map(|(_, body)| *body)
            .ok_or_else(|| RolesError::PromptPathInvalid {
                role: *role,
                path: file.to_owned(),
                reason: "is not one of the prompts compiled into this binary",
            })?;
        verify_prompt(*role, spec, PathBuf::from(file), Cow::Borrowed(raw))?;
    }
    Ok(Arc::clone(EMBEDDED.get_or_init(|| Arc::new(cfg))))
}

fn load_external(path: &Path) -> Result<Arc<RolesConfig>, RolesError> {
    let text = fs::read_to_string(path).map_err(|source| RolesError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let cfg: RolesConfig = serde_json::from_str(&text).map_err(|source| RolesError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    check_role_keys(&cfg, path)?;
    check_providers(&cfg, path)?;
    // `promptFile` is package-relative (design, § Security), i.e. relative to the roles file.
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    for (role, spec) in &cfg.roles {
        let Some(file) = spec.prompt_file.as_deref() else {
            continue;
        };
        let full = dir.join(relative_prompt_path(*role, file)?);
        let raw = read_capped(*role, &full)?;
        verify_prompt(*role, spec, full, Cow::Owned(raw))?;
    }
    Ok(Arc::new(cfg))
}

/// The map key and the spec's own `role` field must agree — otherwise `role_spec(cfg, Builder)`
/// would hand back a spec that believes it is something else.
fn check_role_keys(cfg: &RolesConfig, path: &Path) -> Result<(), RolesError> {
    for (key, spec) in &cfg.roles {
        if spec.role != *key {
            return Err(RolesError::RoleKeyMismatch {
                path: path.to_path_buf(),
                key: *key,
                declared: spec.role,
            });
        }
    }
    Ok(())
}

/// Ties the role set to the provider catalog (Rev 26).
///
/// Two rules, and between them they are what lets `core::team` treat both lists as closed
/// allowlists: a role's `defaultModel` must be one its own provider offers, and every model a role
/// allows must exist in *some* provider's catalog — a role's `models` may span providers (that is
/// how a team moves the builder to codex), but it may not invent a model.
///
/// Every spawnable role must name a provider model. Empty lists remain syntactically tolerated so
/// an external configuration gets the specific default-model error below rather than a special
/// case tied to a role name; the embedded lead is now checked exactly like the workers.
fn check_providers(cfg: &RolesConfig, path: &Path) -> Result<(), RolesError> {
    // Revision 28: a per-model effort list may only narrow the provider's own, and only for a
    // model the provider lists — otherwise `efforts_for` would answer for a model that cannot
    // spawn, or with a value the adapter's closed argv never learned to spell.
    for (provider, catalog) in &cfg.providers {
        for (model, efforts) in &catalog.model_efforts {
            if !catalog.models.contains(model) {
                return Err(RolesError::ModelEffortsForUnlistedModel {
                    path: path.to_path_buf(),
                    provider: *provider,
                    model: model.clone(),
                });
            }
            if let Some(effort) = efforts.iter().find(|e| !catalog.efforts.contains(e)) {
                return Err(RolesError::ModelEffortNotInProvider {
                    path: path.to_path_buf(),
                    provider: *provider,
                    model: model.clone(),
                    effort: effort.as_str().to_owned(),
                });
            }
        }
    }
    for (role, spec) in &cfg.roles {
        let catalog =
            cfg.providers
                .get(&spec.provider)
                .ok_or_else(|| RolesError::UnknownProvider {
                    path: path.to_path_buf(),
                    role: *role,
                    provider: spec.provider,
                })?;

        if !spec.default_model.is_empty() && !catalog.models.contains(&spec.default_model) {
            return Err(RolesError::DefaultModelNotInProvider {
                path: path.to_path_buf(),
                role: *role,
                provider: spec.provider,
                model: spec.default_model.clone(),
            });
        }

        for model in &spec.models {
            if !cfg
                .providers
                .values()
                .any(|provider| provider.models.contains(model))
            {
                return Err(RolesError::ModelNotInAnyProvider {
                    path: path.to_path_buf(),
                    role: *role,
                    model: model.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Rejects a `promptFile` that could escape the roles file's directory. The value comes out of the
/// same file whose integrity is in question, so it is treated as input: no absolute path, no `..`.
fn relative_prompt_path(role: RoleName, file: &str) -> Result<&Path, RolesError> {
    let path = Path::new(file);
    let contained = !file.is_empty()
        && path
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
    if !contained {
        return Err(RolesError::PromptPathInvalid {
            role,
            path: file.to_owned(),
            reason: "must be a relative path, with no `..`, inside the roles file's directory",
        });
    }
    Ok(path)
}

/// Reads at most [`MAX_PROMPT_BYTES`] + 1 bytes, so an oversized file is never held in memory in
/// full — and without the metadata-then-read race a `len()` check would have.
fn read_capped(role: RoleName, path: &Path) -> Result<String, RolesError> {
    let io_err = |source| RolesError::Io {
        path: path.to_path_buf(),
        source,
    };
    let file = File::open(path).map_err(io_err)?;
    let mut buf = Vec::new();
    file.take(MAX_PROMPT_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(io_err)?;
    if buf.len() > MAX_PROMPT_BYTES {
        return Err(RolesError::RolePromptTooLarge {
            role,
            path: path.to_path_buf(),
            max: MAX_PROMPT_BYTES,
        });
    }
    String::from_utf8(buf).map_err(|_| {
        io_err(io::Error::new(
            io::ErrorKind::InvalidData,
            "prompt file is not valid UTF-8",
        ))
    })
}

/// Hashes the prompt's body, compares it with the role's pin, and — only if they match — makes the
/// body available to [`role_prompt`].
fn verify_prompt(
    role: RoleName,
    spec: &RoleSpec,
    path: PathBuf,
    raw: Cow<'static, str>,
) -> Result<(), RolesError> {
    let expected = spec
        .prompt_sha256
        .as_deref()
        .ok_or(RolesError::PromptPinMissing { role })?;
    let body: Cow<'static, str> = match raw {
        Cow::Borrowed(raw) => Cow::Borrowed(strip_frontmatter(raw)),
        Cow::Owned(raw) => Cow::Owned(strip_frontmatter(&raw).to_owned()),
    };
    let actual = sha256_hex(body.as_bytes());
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(RolesError::RolePromptTampered {
            role,
            path,
            expected: expected.to_owned(),
            actual,
        });
    }
    remember_prompt(&actual, body);
    Ok(())
}

fn remember_prompt(sha256: &str, body: Cow<'static, str>) {
    let mut bodies = PROMPT_BODIES
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    bodies
        .entry(sha256.to_ascii_lowercase())
        .or_insert_with(|| match body {
            Cow::Borrowed(body) => body,
            Cow::Owned(body) => Box::leak(body.into_boxed_str()),
        });
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Returns everything after a prompt's YAML frontmatter — the text after the second `---` line.
///
/// Purely textual, no YAML parser (design, § `src/roles/loader.rs`): the frontmatter is metadata
/// for humans, nothing reads it, and it is deliberately outside the hash. A file with no
/// frontmatter, or with an unterminated one, is returned whole — better to hash more than the body
/// than to silently hash nothing.
#[must_use]
pub fn strip_frontmatter(src: &str) -> &str {
    let Some(rest) = src.strip_prefix(FRONTMATTER_OPEN) else {
        return src;
    };
    if let Some(body) = rest.strip_prefix(FRONTMATTER_OPEN) {
        return body; // empty frontmatter: the two delimiter lines are adjacent
    }
    match rest.find(FRONTMATTER_CLOSE) {
        Some(at) => &rest[at + FRONTMATTER_CLOSE.len()..],
        None => src,
    }
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

/// The configuration of one role.
pub fn role_spec(cfg: &RolesConfig, role: RoleName) -> Result<&RoleSpec, RolesError> {
    cfg.roles.get(&role).ok_or(RolesError::UnknownRole { role })
}

/// The verified prompt body a worker in `role` is started with — frontmatter already stripped.
///
/// Only a body that passed its pin during [`load_roles`] can be found here, so a caller cannot
/// reach unverified prompt text through this function.
pub fn role_prompt(cfg: &RolesConfig, role: RoleName) -> Result<&str, RolesError> {
    let spec = role_spec(cfg, role)?;
    let sha256 = spec
        .prompt_sha256
        .as_deref()
        .ok_or(RolesError::PromptNotConfigured { role })?
        .to_ascii_lowercase();
    let bodies = PROMPT_BODIES
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    bodies
        .get(&sha256)
        .copied()
        .ok_or(RolesError::PromptNotConfigured { role })
}

/// What one turn cost according to our own rate table, in US dollars — used when the provider does
/// not report a cost itself (`CostSource::RateTable`). An unpriced model costs 0.0: the rate table
/// is an estimate for the human, never the thing that authorises a spawn.
#[must_use]
pub fn estimate_cost_usd(cfg: &RolesConfig, model: &str, u: &TokenUsage) -> f64 {
    let Some(rate) = cfg.rates.get(model) else {
        return 0.0;
    };
    (u.input as f64 / 1e6) * rate.input_per_m_tok_usd
        + (u.cached_input as f64 / 1e6) * rate.cached_input_per_m_tok_usd
        + (u.output as f64 / 1e6) * rate.output_per_m_tok_usd
}
