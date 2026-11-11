//! Bounded, immutable host-supplied source snapshots for workers without verified egress.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Component, Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_FILES: usize = 64;
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_TITLE_BYTES: usize = 200;
const MAX_URL_BYTES: usize = 2048;
const MAX_NAME_BYTES: usize = 400;
const MAX_DATE_BYTES: usize = 64;
const EVIDENCE_DIR: &str = ".acp-evidence";
const PAYLOAD_DIR: &str = "files";
const MANIFEST_FILE: &str = "manifest.json";

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("evidence I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid evidence manifest: {0}")]
    Invalid(String),
    #[error("evidence content changed: {0}")]
    Changed(String),
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    InstalledVersion,
    CurrentDocumentation,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceEntry {
    pub url: String,
    pub retrieved_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_date: Option<String>,
    pub provenance: Provenance,
    pub sha256: String,
    pub file: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImportManifest {
    version: u32,
    title: String,
    sources: Vec<SourceEntry>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstalledManifest {
    pub version: u32,
    pub bundle_id: String,
    pub title: String,
    pub sources: Vec<SourceEntry>,
}

/// Durable task reference. `root` is created by ACP, never accepted from task input.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceReference {
    pub bundle_id: String,
    pub root: PathBuf,
    pub title: String,
    pub sources: Vec<SourceEntry>,
    pub network_capability: String,
}

impl InstalledManifest {
    pub fn reference(
        &self,
        repo_root: &Path,
        state_dir: &Path,
    ) -> Result<EvidenceReference, EvidenceError> {
        Ok(self.reference_at(layout(repo_root, state_dir)?.bundle(&self.bundle_id)))
    }

    fn reference_at(&self, root: PathBuf) -> EvidenceReference {
        EvidenceReference {
            bundle_id: self.bundle_id.clone(),
            root,
            title: self.title.clone(),
            sources: self.sources.clone(),
            network_capability: "unverified_provider_controlled".into(),
        }
    }
}

impl EvidenceReference {
    /// Bounded in-memory validation for prompt rendering; installed bytes are checked off the
    /// actor immediately before every worker admission, including automatic and replay routes.
    pub fn validate_metadata(&self) -> Result<(), EvidenceError> {
        validate_hash("bundleId", &self.bundle_id)?;
        if self.network_capability != "unverified_provider_controlled"
            || !self.root.is_absolute()
            || self.root.as_os_str().len() > 4096
            || self
                .root
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(EvidenceError::Invalid(
                "invalid evidence navigation metadata".into(),
            ));
        }
        let namespace = self
            .root
            .parent()
            .ok_or_else(|| EvidenceError::Invalid("missing evidence namespace".into()))?;
        let store = namespace
            .parent()
            .ok_or_else(|| EvidenceError::Invalid("missing evidence store".into()))?;
        if self.root.file_name().and_then(|n| n.to_str()) != Some(self.bundle_id.as_str())
            || store.file_name().and_then(|n| n.to_str()) != Some(EVIDENCE_DIR)
        {
            return invalid("evidence must use the separate worker-readable store; reimport legacy draft evidence");
        }
        validate_hash(
            "evidence namespace",
            namespace.file_name().and_then(|n| n.to_str()).unwrap_or(""),
        )?;
        let manifest = ImportManifest {
            version: 1,
            title: self.title.clone(),
            sources: self.sources.clone(),
        };
        validate_manifest(&manifest)?;
        let bytes = serde_json::to_vec(&manifest)
            .map_err(|error| EvidenceError::Invalid(format!("manifest serialization: {error}")))?;
        if bytes.len() > MAX_MANIFEST_BYTES || hex_sha256(&bytes) != self.bundle_id {
            return Err(EvidenceError::Changed(
                "task metadata does not match its bundle identity".into(),
            ));
        }
        Ok(())
    }

    /// Revalidates the durable reference and every installed byte at process admission.
    pub fn validate_for(
        &self,
        repo_root: &Path,
        state_dir: &Path,
    ) -> Result<InstalledManifest, EvidenceError> {
        self.validate_metadata()?;
        let expected = layout(repo_root, state_dir)?.bundle(&self.bundle_id);
        if self.root != expected {
            return invalid(format!(
                "evidence reference is outside this daemon's host-owned namespace; reimport bundle {} for this repository",
                self.bundle_id
            ));
        }
        let installed = load_bundle(&self.root, &self.bundle_id)?;
        if installed.reference_at(self.root.clone()) != *self {
            return Err(EvidenceError::Changed(
                "task evidence metadata does not match the installed bundle".into(),
            ));
        }
        Ok(installed)
    }
}

pub fn import(
    repo_root: &Path,
    state_dir: &Path,
    manifest_path: &Path,
) -> Result<InstalledManifest, EvidenceError> {
    let layout = layout(repo_root, state_dir)?;
    let (source_root, mut manifest_file) = open_absolute_parent_file(manifest_path, "manifest")?;
    let bytes = bounded_read_file(&mut manifest_file, MAX_MANIFEST_BYTES, "manifest")?;
    let mut input: ImportManifest = serde_json::from_slice(&bytes)
        .map_err(|e| EvidenceError::Invalid(format!("manifest JSON: {e}")))?;
    validate_manifest(&input)?;
    input.sources.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.url.cmp(&right.url))
    });

    let canonical = serde_json::to_vec(&input)
        .map_err(|e| EvidenceError::Invalid(format!("manifest serialization: {e}")))?;
    let bundle_id = hex_sha256(&canonical);
    let installed = InstalledManifest {
        version: input.version,
        bundle_id: bundle_id.clone(),
        title: input.title,
        sources: input.sources,
    };
    // Bound the exact representation that load() will later read, including bundleId.
    let installed_bytes = serde_json::to_vec(&installed)
        .map_err(|e| EvidenceError::Invalid(format!("installed manifest serialization: {e}")))?;
    if installed_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(EvidenceError::Invalid(format!(
            "installed manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }

    let final_dir = layout.bundle(&bundle_id);
    if final_dir.exists() {
        let existing = load(repo_root, state_dir, &bundle_id)?;
        if existing != installed {
            return Err(EvidenceError::Changed(format!(
                "bundle identity collision for {bundle_id}"
            )));
        }
        return Ok(existing);
    }

    let evidence_root = layout.namespace;
    create_dir(evidence_root.parent().expect("store parent"), 0o700)?;
    create_dir(&evidence_root, 0o700)?;
    let staging = evidence_root.join(format!(".import-{}", Uuid::new_v4()));
    create_dir(&staging, 0o700)?;
    let result = (|| {
        let payload = staging.join(PAYLOAD_DIR);
        create_dir(&payload, 0o700)?;
        let mut total = 0u64;
        for source in &installed.sources {
            let relative = Path::new(&source.file);
            let to = payload.join(relative);
            let copied = copy_verified(&source_root, &to, source)?;
            total = total
                .checked_add(copied)
                .ok_or_else(|| EvidenceError::Invalid("aggregate source size overflow".into()))?;
            if total > MAX_TOTAL_BYTES {
                return invalid(format!("aggregate sources exceed {MAX_TOTAL_BYTES} bytes"));
            }
        }
        write_new(&staging.join(MANIFEST_FILE), &installed_bytes, 0o400)?;
        make_read_only_tree(&payload)?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o500))
            .map_err(|e| io_at(&staging, e))?;
        fs::rename(&staging, &final_dir).map_err(|e| io_at(&final_dir, e))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = make_writable_tree(&staging);
        let _ = fs::remove_dir_all(&staging);
    }
    result?;
    load(repo_root, state_dir, &bundle_id)
}

pub fn load(
    repo_root: &Path,
    state_dir: &Path,
    bundle_id: &str,
) -> Result<InstalledManifest, EvidenceError> {
    let layout = layout(repo_root, state_dir)?;
    validate_hash("bundleId", bundle_id)?;
    let dir = layout.bundle(bundle_id);
    load_bundle(&dir, bundle_id)
}

fn load_bundle(dir: &Path, bundle_id: &str) -> Result<InstalledManifest, EvidenceError> {
    validate_hash("bundleId", bundle_id)?;
    let namespace = dir
        .parent()
        .ok_or_else(|| EvidenceError::Invalid("missing evidence namespace".into()))?;
    let store = namespace
        .parent()
        .ok_or_else(|| EvidenceError::Invalid("missing evidence store".into()))?;
    let name = namespace
        .file_name()
        .ok_or_else(|| EvidenceError::Invalid("missing namespace name".into()))?;
    let store = open_absolute_dir(store, "evidence store")?;
    let namespace = open_dir_at(&store, Path::new(name), "evidence namespace")?;
    let bundle = open_dir_at(&namespace, Path::new(bundle_id), "installed bundle")?;
    for directory in [&store, &namespace] {
        if !private_directory(
            &directory
                .metadata()
                .map_err(|e| io_at("evidence directory", e))?,
        ) {
            return invalid("evidence directories must remain owner-only");
        }
    }
    if !immutable_directory(
        &bundle
            .metadata()
            .map_err(|e| io_at("installed bundle", e))?,
    ) {
        return invalid("installed bundle must remain owner-owned and read-only");
    }
    let mut manifest_file =
        open_regular_at(&bundle, Path::new(MANIFEST_FILE), "installed manifest")?;
    if !immutable_file(
        &manifest_file
            .metadata()
            .map_err(|e| io_at("installed manifest", e))?,
    ) {
        return invalid("installed manifest must remain owner-owned and read-only");
    }
    let bytes = bounded_read_file(&mut manifest_file, MAX_MANIFEST_BYTES, "installed manifest")?;
    let manifest: InstalledManifest = serde_json::from_slice(&bytes)
        .map_err(|e| EvidenceError::Invalid(format!("installed manifest JSON: {e}")))?;
    if manifest.bundle_id != bundle_id {
        return Err(EvidenceError::Changed(
            "installed bundleId does not match its directory".into(),
        ));
    }
    let input = ImportManifest {
        version: manifest.version,
        title: manifest.title.clone(),
        sources: manifest.sources.clone(),
    };
    validate_manifest(&input)?;
    let canonical = serde_json::to_vec(&input)
        .map_err(|e| EvidenceError::Invalid(format!("manifest serialization: {e}")))?;
    if hex_sha256(&canonical) != bundle_id {
        return Err(EvidenceError::Changed(
            "manifest metadata no longer matches bundleId".into(),
        ));
    }
    check_directory_entries(
        &bundle,
        [OsStr::new(MANIFEST_FILE), OsStr::new(PAYLOAD_DIR)]
            .into_iter()
            .collect(),
    )?;
    let payload = open_dir_at(&bundle, Path::new(PAYLOAD_DIR), "installed payload")?;
    if !immutable_directory(
        &payload
            .metadata()
            .map_err(|e| io_at("installed payload", e))?,
    ) {
        return invalid("installed payload must remain owner-owned and read-only");
    }
    // All expected names come from the already bounded and validated manifest.
    let mut directories: BTreeMap<&Path, BTreeSet<&OsStr>> = BTreeMap::new();
    for source in &manifest.sources {
        let mut path = Path::new(&source.file);
        while let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
            directories.entry(parent).or_default().insert(name);
            path = parent;
        }
    }
    for (path, children) in directories {
        let directory = open_dir_at(&payload, path, "installed payload directory")?;
        if !immutable_directory(&directory.metadata().map_err(|e| io_at(path, e))?) {
            return invalid("installed payload directories must remain owner-owned and read-only");
        }
        check_directory_entries(&directory, children)?;
    }

    let mut total = 0u64;
    for source in &manifest.sources {
        let relative = Path::new(&source.file);
        let size = verify_file(&payload, relative, source)?;
        total = total
            .checked_add(size)
            .ok_or_else(|| EvidenceError::Changed("aggregate installed size overflow".into()))?;
        if total > MAX_TOTAL_BYTES {
            return Err(EvidenceError::Changed(
                "aggregate installed sources exceed their bound".into(),
            ));
        }
    }
    Ok(manifest)
}

/// Enumerate a held directory and stop at its first unlisted entry. No untrusted names are
/// stored and no descent is driven by the on-disk inventory.
fn check_directory_entries(
    directory: &File,
    mut expected: BTreeSet<&OsStr>,
) -> Result<(), EvidenceError> {
    let descriptor = directory
        .try_clone()
        .map_err(|e| io_at("evidence directory", e))?;
    let entries =
        nix::dir::Dir::from(descriptor).map_err(|e| io_at("evidence directory", e.into()))?;
    for entry in entries {
        let entry = entry.map_err(|e| io_at("evidence directory", e.into()))?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." && !expected.remove(OsStr::from_bytes(name)) {
            return Err(EvidenceError::Changed(
                "bundle contains an undeclared entry".into(),
            ));
        }
    }
    if !expected.is_empty() {
        return Err(EvidenceError::Changed(
            "bundle is missing a declared entry".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct EvidenceLayout {
    namespace: PathBuf,
}

impl EvidenceLayout {
    fn bundle(&self, bundle_id: &str) -> PathBuf {
        self.namespace.join(bundle_id)
    }
}

/// Resolve the one host-owned namespace for this exact daemon repository and state pair.  Both
/// roots already exist at every daemon entry point, so canonicalization also collapses macOS's
/// `/var` -> `/private/var` alias before either placement or identity is decided.
fn layout(repo_root: &Path, state_dir: &Path) -> Result<EvidenceLayout, EvidenceError> {
    let repo = canonical_directory(repo_root, "repository root")?;
    let state = canonical_directory(state_dir, "state directory")?;
    if state
        .components()
        .any(|component| component.as_os_str() == EVIDENCE_DIR)
    {
        return invalid("daemon state must not be inside an evidence store");
    }
    let parent = state.parent().unwrap_or(&state);
    // The default repository state is ~/.acp/<key>; do not point workers inside ~/.acp at all.
    let anchor = if parent.file_name().is_some_and(|name| name == ".acp") {
        parent.parent().unwrap_or(parent)
    } else {
        parent
    };
    // A custom state may be under the daemon repository or even another ACP checkout.  Move the
    // evidence store outside the outermost enclosing checkout rather than ever publishing into a
    // writable worker tree.  This affects evidence placement only; daemon state stays untouched.
    let mut store_anchor = anchor.to_path_buf();
    for _ in 0..64 {
        let candidate = store_anchor.join(EVIDENCE_DIR);
        let mut unsafe_roots = Vec::new();
        if candidate.starts_with(&repo) {
            unsafe_roots.push(repo.clone());
        } else if repo.starts_with(&candidate) {
            return invalid(
                "unsafe evidence layout: the repository is inside the proposed evidence store",
            );
        }
        if let Some(host) = acp_worktrees_host(&candidate) {
            unsafe_roots.push(host);
        }
        unsafe_roots.extend(candidate.ancestors().skip(1).filter_map(|ancestor| {
            fs::symlink_metadata(ancestor.join(".git"))
                .ok()
                .map(|_| ancestor.to_path_buf())
        }));
        if unsafe_roots.is_empty() {
            if paths_overlap(&candidate, &state) {
                return invalid("evidence store must be disjoint from the daemon state directory");
            }
            store_anchor = candidate;
            break;
        }
        let outermost = unsafe_roots
            .into_iter()
            .min_by_key(|path| path.components().count())
            .expect("an unsafe root");
        store_anchor = outermost
            .parent()
            .ok_or_else(|| {
                EvidenceError::Invalid(
                    "no safe external evidence store exists for this layout".into(),
                )
            })?
            .to_path_buf();
    }
    let store = if store_anchor
        .file_name()
        .is_some_and(|name| name == EVIDENCE_DIR)
    {
        store_anchor
    } else {
        return invalid("could not resolve a safe external evidence store");
    };
    if paths_overlap(&store, &state) || paths_overlap(&store, &repo) || inside_acp_worktrees(&store)
    {
        return invalid(format!(
            "unsafe evidence layout at {}; use state outside repositories",
            store.display()
        ));
    }
    let mut identity = Vec::new();
    identity.extend_from_slice(repo.as_os_str().as_encoded_bytes());
    identity.push(0);
    identity.extend_from_slice(state.as_os_str().as_encoded_bytes());
    Ok(EvidenceLayout {
        namespace: store.join(hex_sha256(&identity)),
    })
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, EvidenceError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return invalid(format!("evidence requires an absolute, non-root {label}"));
    }
    let canonical = path.canonicalize().map_err(|e| io_at(path, e))?;
    open_absolute_dir(&canonical, label)?;
    Ok(canonical)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn inside_acp_worktrees(path: &Path) -> bool {
    let parts: Vec<_> = path.components().map(|part| part.as_os_str()).collect();
    parts
        .windows(2)
        .any(|pair| pair[0] == ".acp" && pair[1] == "worktrees")
}

fn acp_worktrees_host(path: &Path) -> Option<PathBuf> {
    let mut prefix = PathBuf::new();
    let mut previous_acp = false;
    for component in path.components() {
        prefix.push(component.as_os_str());
        if previous_acp && component.as_os_str() == "worktrees" {
            return prefix
                .parent()
                .and_then(Path::parent)
                .map(Path::to_path_buf);
        }
        previous_acp = component.as_os_str() == ".acp";
    }
    None
}

#[cfg(test)]
fn storage_root(repo_root: &Path, state_dir: &Path) -> PathBuf {
    layout(repo_root, state_dir).unwrap().namespace
}

#[cfg(test)]
fn bundle_dir(repo_root: &Path, state_dir: &Path, bundle_id: &str) -> PathBuf {
    layout(repo_root, state_dir).unwrap().bundle(bundle_id)
}

fn validate_manifest(manifest: &ImportManifest) -> Result<(), EvidenceError> {
    if manifest.version != 1 {
        return invalid("version must be 1");
    }
    bounded_text("title", &manifest.title, 1, MAX_TITLE_BYTES)?;
    if manifest.sources.is_empty() || manifest.sources.len() > MAX_FILES {
        return invalid(format!("sources must contain 1..={MAX_FILES} entries"));
    }
    let mut names = BTreeSet::new();
    let mut urls = BTreeSet::new();
    for source in &manifest.sources {
        bounded_text("url", &source.url, 1, MAX_URL_BYTES)?;
        validate_url(&source.url)?;
        if !urls.insert(&source.url) {
            return invalid(format!("duplicate source URL: {}", source.url));
        }
        validate_date("retrievedAt", &source.retrieved_at, true)?;
        if let Some(date) = &source.source_date {
            validate_date("sourceDate", date, false)?;
        }
        validate_hash("sha256", &source.sha256)?;
        validate_relative_name(&source.file)?;
        if !names.insert(&source.file) {
            return invalid(format!("duplicate source file: {}", source.file));
        }
    }
    let paths: Vec<&Path> = names.iter().map(Path::new).collect();
    for (index, left) in paths.iter().enumerate() {
        if paths[index + 1..]
            .iter()
            .any(|right| right.starts_with(left))
        {
            return invalid(format!(
                "source paths have a file/directory prefix collision at {}",
                left.display()
            ));
        }
    }
    Ok(())
}

fn validate_relative_name(name: &str) -> Result<(), EvidenceError> {
    bounded_text("file", name, 1, MAX_NAME_BYTES)?;
    if name.contains('\\') || name.contains("//") || name.ends_with('/') {
        return invalid(format!(
            "source file contains an empty or non-canonical path component: {name}"
        ));
    }
    let path = Path::new(name);
    if path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return invalid(format!("source file must be a safe relative path: {name}"));
    }
    Ok(())
}

fn validate_date(field: &str, value: &str, timestamp: bool) -> Result<(), EvidenceError> {
    bounded_text(field, value, 10, MAX_DATE_BYTES)?;
    let bytes = value.as_bytes();
    let date_shape = bytes.len() >= 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[..4]
            .iter()
            .chain(&bytes[5..7])
            .chain(&bytes[8..10])
            .all(u8::is_ascii_digit);
    let number = |slice: &[u8]| {
        slice
            .iter()
            .fold(0u32, |n, digit| n * 10 + u32::from(digit - b'0'))
    };
    let (year, month, day) = if date_shape {
        (
            number(&bytes[..4]),
            number(&bytes[5..7]),
            number(&bytes[8..10]),
        )
    } else {
        (0, 0, 0)
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    let date = date_shape && year != 0 && day != 0 && day <= max_day;
    let time = if timestamp {
        let shape = bytes.len() >= 20
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':'
            && bytes[11..13]
                .iter()
                .chain(&bytes[14..16])
                .chain(&bytes[17..19])
                .all(u8::is_ascii_digit)
            && number(&bytes[11..13]) <= 23
            && number(&bytes[14..16]) <= 59
            && number(&bytes[17..19]) <= 60;
        let mut suffix = if bytes.len() >= 19 { &bytes[19..] } else { &[] };
        if suffix.first() == Some(&b'.') {
            let digits = suffix[1..]
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            suffix = if digits == 0 {
                &[]
            } else {
                &suffix[1 + digits..]
            };
        }
        let zone = suffix == b"Z"
            || (suffix.len() == 6
                && matches!(suffix[0], b'+' | b'-')
                && suffix[3] == b':'
                && suffix[1..3]
                    .iter()
                    .chain(&suffix[4..6])
                    .all(u8::is_ascii_digit)
                && number(&suffix[1..3]) <= 23
                && number(&suffix[4..6]) <= 59);
        shape && zone
    } else {
        bytes.len() == 10
    };
    if !date || !time {
        return invalid(format!(
            "{field} must be an ISO-8601 {}",
            if timestamp { "timestamp" } else { "date" }
        ));
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<(), EvidenceError> {
    if !url.starts_with("https://")
        || !url.is_ascii()
        || url
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        || url.contains(['#', '?', '%', '\\'])
    {
        return invalid(format!("source URL must be canonical https without a query, fragment, or percent encoding: {url}"));
    }
    let remainder = &url[8..];
    let Some((authority, path)) = remainder.split_once('/') else {
        return invalid(format!(
            "source URL must carry an explicit canonical path: {url}"
        ));
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let host_ok = !host.is_empty()
        && !host.ends_with('.')
        && !host.contains("..")
        && host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    // Without a URL normalization dependency, reject every all-numeric/dotted-numeric host.
    // This closes integer, short, octal-looking and hex-looking IPv4 aliases conservatively.
    let numeric_host = host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        || host.starts_with("0x")
        || host.split('.').any(|label| label.starts_with("0x"));
    let port_ok = port.is_none_or(|port| {
        !port.is_empty()
            && !port.starts_with('0')
            && port.bytes().all(|b| b.is_ascii_digit())
            && port
                .parse::<u16>()
                .is_ok_and(|port| port != 443 && port != 0)
    });
    if !host_ok
        || numeric_host
        || !port_ok
        || authority.contains('@')
        || path.contains("//")
        || path.split('/').any(|part| matches!(part, "." | ".."))
    {
        return invalid(format!(
            "source URL has an ambiguous/non-canonical authority or path: {url}"
        ));
    }
    Ok(())
}

fn validate_hash(field: &str, value: &str) -> Result<(), EvidenceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return invalid(format!(
            "{field} must be 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn bounded_text(field: &str, value: &str, min: usize, max: usize) -> Result<(), EvidenceError> {
    if value.len() < min || value.len() > max || value.chars().any(char::is_control) {
        return invalid(format!("{field} must be {min}..={max} safe UTF-8 bytes"));
    }
    Ok(())
}

fn copy_verified(root: &File, to: &Path, source: &SourceEntry) -> Result<u64, EvidenceError> {
    let mut input = open_regular_at(root, Path::new(&source.file), "source")?;
    if input.metadata().map_err(|e| io_at(&source.file, e))?.len() > MAX_FILE_BYTES {
        return invalid(format!(
            "source must be no larger than {MAX_FILE_BYTES} bytes: {}",
            source.file
        ));
    }
    if let Some(parent) = to.parent() {
        create_dir_all(parent, 0o700)?;
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(to)
        .map_err(|e| io_at(to, e))?;
    let (count, hash) = copy_hash(&mut input, &mut output, MAX_FILE_BYTES)?;
    if hash != source.sha256 {
        return Err(EvidenceError::Changed(format!(
            "{} did not match its declared hash",
            source.file
        )));
    }
    Ok(count)
}

fn verify_file(root: &File, relative: &Path, source: &SourceEntry) -> Result<u64, EvidenceError> {
    let mut file = open_immutable_regular_at(root, relative, "installed source")?;
    let mut sink = io::sink();
    let (count, hash) = copy_hash(&mut file, &mut sink, MAX_FILE_BYTES)?;
    if hash != source.sha256 {
        return Err(EvidenceError::Changed(format!(
            "{} no longer matches its declared hash",
            source.file
        )));
    }
    Ok(count)
}

fn copy_hash(
    input: &mut impl Read,
    output: &mut impl Write,
    limit: u64,
) -> Result<(u64, String), EvidenceError> {
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 32 * 1024];
    loop {
        let n = input.read(&mut buffer).map_err(|e| io_at("source", e))?;
        if n == 0 {
            break;
        }
        count = count.saturating_add(n as u64);
        if count > limit {
            return invalid(format!("source exceeds {limit} bytes"));
        }
        hash.update(&buffer[..n]);
        output
            .write_all(&buffer[..n])
            .map_err(|e| io_at("destination", e))?;
    }
    Ok((count, format!("{:x}", hash.finalize())))
}

fn bounded_read_file(file: &mut File, limit: usize, label: &str) -> Result<Vec<u8>, EvidenceError> {
    let mut bytes = Vec::new();
    Read::by_ref(file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_at(label, e))?;
    if bytes.len() > limit {
        return invalid(format!("{label} exceeds {limit} bytes"));
    }
    Ok(bytes)
}

fn open_absolute_parent_file(path: &Path, label: &str) -> Result<(File, File), EvidenceError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| io_at(".", e))?
            .join(path)
    };
    let name = absolute
        .file_name()
        .ok_or_else(|| EvidenceError::Invalid(format!("{label} path has no file name")))?;
    let parent = absolute
        .parent()
        .ok_or_else(|| EvidenceError::Invalid(format!("{label} path has no parent")))?;
    let dir = open_absolute_dir(parent, label)?;
    let file = open_regular_at(&dir, Path::new(name), label)?;
    Ok((dir, file))
}

fn open_absolute_dir(path: &Path, label: &str) -> Result<File, EvidenceError> {
    if !path.is_absolute() {
        return invalid(format!("{label} path must be absolute"));
    }
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open("/")
        .map_err(|e| io_at("/", e))?;
    let relative = path
        .strip_prefix("/")
        .map_err(|_| EvidenceError::Invalid(format!("invalid {label} path")))?;
    open_dir_at(&root, relative, label)
}

fn open_dir_at(root: &File, relative: &Path, label: &str) -> Result<File, EvidenceError> {
    let mut current = root.try_clone().map_err(|e| io_at(label, e))?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return invalid(format!("unsafe {label} path"));
        };
        current = openat(
            &current,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            label,
        )?;
        if !current
            .metadata()
            .map_err(|e| io_at(label, e))?
            .file_type()
            .is_dir()
        {
            return invalid(format!("{label} component is not a directory"));
        }
    }
    Ok(current)
}

fn open_regular_at(root: &File, relative: &Path, label: &str) -> Result<File, EvidenceError> {
    let name = relative
        .file_name()
        .ok_or_else(|| EvidenceError::Invalid(format!("{label} path has no file name")))?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let dir = open_dir_at(root, parent, label)?;
    let file = openat(
        &dir,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        label,
    )?;
    if !file
        .metadata()
        .map_err(|e| io_at(label, e))?
        .file_type()
        .is_file()
    {
        return invalid(format!("{label} must be a regular non-symlink file"));
    }
    Ok(file)
}

fn open_immutable_regular_at(
    root: &File,
    relative: &Path,
    label: &str,
) -> Result<File, EvidenceError> {
    let name = relative
        .file_name()
        .ok_or_else(|| EvidenceError::Invalid(format!("{label} path has no file name")))?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let mut dir = root.try_clone().map_err(|e| io_at(label, e))?;
    for component in parent.components() {
        let Component::Normal(name) = component else {
            return invalid(format!("unsafe {label} path"));
        };
        dir = openat(
            &dir,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            label,
        )?;
        if !immutable_directory(&dir.metadata().map_err(|e| io_at(label, e))?) {
            return invalid(format!(
                "{label} directory must remain owner-owned and read-only"
            ));
        }
    }
    let file = openat(
        &dir,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        label,
    )?;
    if !immutable_file(&file.metadata().map_err(|e| io_at(label, e))?) {
        return invalid(format!(
            "{label} must remain an owner-owned read-only regular file"
        ));
    }
    Ok(file)
}

fn openat(
    dir: &File,
    name: &std::ffi::OsStr,
    flags: i32,
    label: &str,
) -> Result<File, EvidenceError> {
    use std::os::unix::ffi::OsStrExt as _;
    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| EvidenceError::Invalid(format!("{label} path contains NUL")))?;
    // SAFETY: `dir` remains open, `name` is NUL-terminated, and ownership of a successful fd is
    // transferred immediately to File. O_NONBLOCK prevents a swapped FIFO/device from blocking.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io_at(label, io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn invalid<T>(message: impl Into<String>) -> Result<T, EvidenceError> {
    Err(EvidenceError::Invalid(message.into()))
}
fn io_at(path: impl AsRef<Path>, source: io::Error) -> EvidenceError {
    EvidenceError::Io {
        path: path.as_ref().to_path_buf(),
        source,
    }
}

fn private_directory(metadata: &fs::Metadata) -> bool {
    // SAFETY: geteuid has no arguments and no memory-safety preconditions.
    let owned = metadata.uid() == unsafe { libc::geteuid() };
    metadata.file_type().is_dir()
        && !metadata.file_type().is_symlink()
        && owned
        && metadata.permissions().mode() & 0o077 == 0
}

fn immutable_directory(metadata: &fs::Metadata) -> bool {
    private_directory(metadata) && metadata.permissions().mode() & 0o777 == 0o500
}

fn immutable_file(metadata: &fs::Metadata) -> bool {
    // SAFETY: geteuid has no arguments and no memory-safety preconditions.
    let owned = metadata.uid() == unsafe { libc::geteuid() };
    metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && owned
        && metadata.permissions().mode() & 0o777 == 0o400
}

fn create_dir(path: &Path, mode: u32) -> Result<(), EvidenceError> {
    match fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| io_at(path, e))
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|e| io_at(path, e))?;
            if private_directory(&metadata) {
                Ok(())
            } else {
                invalid(format!("{} is not a safe directory", path.display()))
            }
        }
        Err(e) => Err(io_at(path, e)),
    }
}
fn create_dir_all(path: &Path, mode: u32) -> Result<(), EvidenceError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .map_err(|e| io_at(path, e))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| io_at(path, e))
}
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), EvidenceError> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| io_at(path, e))?;
    f.write_all(bytes).map_err(|e| io_at(path, e))?;
    f.sync_all().map_err(|e| io_at(path, e))
}
fn make_read_only_tree(path: &Path) -> Result<(), EvidenceError> {
    for entry in fs::read_dir(path).map_err(|e| io_at(path, e))? {
        let path = entry.map_err(|e| io_at(path, e))?.path();
        if path.is_dir() {
            make_read_only_tree(&path)?;
        } else {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
                .map_err(|e| io_at(&path, e))?;
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o500)).map_err(|e| io_at(path, e))
}
fn make_writable_tree(path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    for entry in fs::read_dir(path)? {
        let p = entry?.path();
        if p.is_dir() {
            make_writable_tree(&p)?;
        } else {
            fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::handoff::{build_builder_prompt, build_lead_prompt};
    use crate::core::types::Task;
    use std::os::unix::fs::symlink;

    // macOS's default TMPDIR may begin with /var, itself a system symlink. Allocate these
    // fixtures under its canonical directory so no-follow tests reach the component under test.
    fn canonical_tempdir() -> tempfile::TempDir {
        tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
    }

    struct WritableTemp {
        owner: tempfile::TempDir,
        state: PathBuf,
        repo: PathBuf,
    }
    impl WritableTemp {
        fn path(&self) -> &Path {
            &self.state
        }
        fn repo(&self) -> &Path {
            &self.repo
        }
    }
    impl Drop for WritableTemp {
        fn drop(&mut self) {
            let _ = make_writable_tree(self.owner.path());
        }
    }
    fn writable_tempdir() -> WritableTemp {
        let owner = canonical_tempdir();
        let state = owner.path().join("state");
        let repo = owner.path().join("repo");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&repo).unwrap();
        WritableTemp { owner, state, repo }
    }

    fn source(file: &str, url: &str, text: &[u8], provenance: Provenance) -> SourceEntry {
        SourceEntry {
            url: url.into(),
            retrieved_at: "2026-11-10T12:30:00Z".into(),
            source_date: Some("2026-11-09".into()),
            provenance,
            sha256: hex_sha256(text),
            file: file.into(),
        }
    }

    fn write_manifest(root: &Path, title: &str, sources: Vec<SourceEntry>) -> PathBuf {
        let path = root.join("bundle.json");
        let bytes = serde_json::to_vec(&ImportManifest {
            version: 1,
            title: title.into(),
            sources,
        })
        .unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn layout_uses_canonical_daemon_roots_and_escapes_worker_checkouts() {
        let owner = canonical_tempdir();
        let host = owner.path().join("host");
        let repo = host.join(".acp/worktrees/foreign/run/repo");
        let state = repo.join("custom-state");
        fs::create_dir_all(&state).unwrap();
        fs::write(repo.join(".git"), "gitdir: elsewhere").unwrap();

        let resolved = layout(&repo, &state).unwrap();
        assert!(!resolved.namespace.starts_with(&repo));
        assert!(!inside_acp_worktrees(&resolved.namespace));
        assert!(
            !resolved.namespace.exists(),
            "layout validation must not create a store"
        );

        let repo_alias = owner.path().join("repo-alias");
        let state_alias = owner.path().join("state-alias");
        symlink(&repo, &repo_alias).unwrap();
        symlink(&state, &state_alias).unwrap();
        assert_eq!(
            layout(&repo_alias, &state_alias).unwrap().namespace,
            resolved.namespace
        );
    }

    #[test]
    fn layout_refuses_a_repository_inside_the_proposed_store_before_creation() {
        let owner = canonical_tempdir();
        let state = owner.path().join("state");
        let repo = owner.path().join(EVIDENCE_DIR).join("repository");
        fs::create_dir(&state).unwrap();
        fs::create_dir_all(&repo).unwrap();
        let err = layout(&repo, &state).unwrap_err();
        assert!(err.to_string().contains("repository is inside"));
        assert!(!owner
            .path()
            .join(EVIDENCE_DIR)
            .join("manifest.json")
            .exists());
    }

    #[test]
    fn imports_multiple_documents_with_metadata_and_reserved_payload_name() {
        let source_dir = canonical_tempdir();
        let state = writable_tempdir();
        fs::write(source_dir.path().join("manifest.json"), b"installed API").unwrap();
        fs::create_dir(source_dir.path().join("guide")).unwrap();
        fs::write(source_dir.path().join("guide/current.md"), b"current guide").unwrap();
        let source_mode = fs::metadata(source_dir.path().join("manifest.json"))
            .unwrap()
            .permissions()
            .mode();
        let manifest = write_manifest(
            source_dir.path(),
            "API sources",
            vec![
                source(
                    "manifest.json",
                    "https://example.test/v1/api",
                    b"installed API",
                    Provenance::InstalledVersion,
                ),
                source(
                    "guide/current.md",
                    "https://example.test/docs/api",
                    b"current guide",
                    Provenance::CurrentDocumentation,
                ),
            ],
        );

        let installed = import(state.repo(), state.path(), &manifest).unwrap();
        assert_eq!(
            installed.sources[0].source_date.as_deref(),
            Some("2026-11-09")
        );
        assert_ne!(
            installed.sources[0].provenance,
            installed.sources[1].provenance
        );
        assert_eq!(
            fs::read(
                bundle_dir(state.repo(), state.path(), &installed.bundle_id)
                    .join("files/manifest.json")
            )
            .unwrap(),
            b"installed API"
        );
        assert_eq!(
            fs::metadata(source_dir.path().join("manifest.json"))
                .unwrap()
                .permissions()
                .mode(),
            source_mode
        );
        assert_eq!(
            fs::metadata(
                bundle_dir(state.repo(), state.path(), &installed.bundle_id)
                    .join("files/manifest.json")
            )
            .unwrap()
            .permissions()
            .mode()
                & 0o777,
            0o400
        );
        assert_eq!(
            load(state.repo(), state.path(), &installed.bundle_id).unwrap(),
            installed
        );
    }

    #[test]
    fn provenance_update_creates_a_new_identity_and_old_bundle_stays_read_only() {
        let source_dir = canonical_tempdir();
        let state = writable_tempdir();
        fs::write(source_dir.path().join("doc.txt"), b"same bytes").unwrap();
        let first_path = write_manifest(
            source_dir.path(),
            "one",
            vec![source(
                "doc.txt",
                "https://example.test/doc",
                b"same bytes",
                Provenance::InstalledVersion,
            )],
        );
        let first = import(state.repo(), state.path(), &first_path).unwrap();
        let second_path = write_manifest(
            source_dir.path(),
            "one",
            vec![source(
                "doc.txt",
                "https://example.test/doc",
                b"same bytes",
                Provenance::CurrentDocumentation,
            )],
        );
        let second = import(state.repo(), state.path(), &second_path).unwrap();
        assert_ne!(first.bundle_id, second.bundle_id);
        assert_eq!(
            load(state.repo(), state.path(), &first.bundle_id)
                .unwrap()
                .sources[0]
                .provenance,
            Provenance::InstalledVersion
        );
    }

    #[test]
    fn recursive_staging_directories_are_owner_only_from_creation() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("one/two/three");
        create_dir_all(&nested, 0o700).unwrap();
        for path in [root.path().join("one"), root.path().join("one/two"), nested] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn rejects_changed_hash_traversal_symlink_and_prefix_collision() {
        let source_dir = canonical_tempdir();
        let state = writable_tempdir();
        fs::write(source_dir.path().join("doc"), b"changed").unwrap();
        let wrong = write_manifest(
            source_dir.path(),
            "bad",
            vec![source(
                "doc",
                "https://example.test/wrong",
                b"declared",
                Provenance::CurrentDocumentation,
            )],
        );
        assert!(matches!(
            import(state.repo(), state.path(), &wrong),
            Err(EvidenceError::Changed(_))
        ));

        let traversal = ImportManifest {
            version: 1,
            title: "bad".into(),
            sources: vec![source(
                "../doc",
                "https://example.test/traversal",
                b"declared",
                Provenance::CurrentDocumentation,
            )],
        };
        assert!(validate_manifest(&traversal).is_err());
        for file in ["nested//doc", "nested/doc/"] {
            let ambiguous = ImportManifest {
                version: 1,
                title: "bad".into(),
                sources: vec![source(
                    file,
                    "https://example.test/ambiguous",
                    b"declared",
                    Provenance::CurrentDocumentation,
                )],
            };
            assert!(validate_manifest(&ambiguous).is_err());
        }

        symlink(
            source_dir.path().join("doc"),
            source_dir.path().join("link"),
        )
        .unwrap();
        let linked = write_manifest(
            source_dir.path(),
            "bad",
            vec![source(
                "link",
                "https://example.test/link",
                b"changed",
                Provenance::CurrentDocumentation,
            )],
        );
        assert!(import(state.repo(), state.path(), &linked).is_err());

        let manifest_link = source_dir.path().join("manifest-link.json");
        symlink(&linked, &manifest_link).unwrap();
        assert!(import(state.repo(), state.path(), &manifest_link).is_err());

        let collision = ImportManifest {
            version: 1,
            title: "bad".into(),
            sources: vec![
                source(
                    "a",
                    "https://example.test/a",
                    b"a",
                    Provenance::CurrentDocumentation,
                ),
                source(
                    "a/b",
                    "https://example.test/b",
                    b"b",
                    Provenance::CurrentDocumentation,
                ),
            ],
        };
        assert!(validate_manifest(&collision).is_err());
    }

    #[test]
    fn rejects_ambiguous_urls_and_impossible_or_malformed_dates() {
        for url in [
            "https://example.test/a/%62",
            "https://example.test:0443/a",
            "https://example.test:443/a",
            "https://Example.test/a",
            "https://example.test/a?version=1",
            "https://example.test/a/../b",
            "https://example.test/a\\b",
            "https://127.000.000.001/a",
            "https://127.1/a",
            "https://2130706433/a",
            "https://0x7f000001/a",
        ] {
            assert!(validate_url(url).is_err(), "accepted {url}");
        }
        assert!(validate_url("https://example.test:8443/a").is_ok());
        assert!(validate_url("https://example.test/").is_ok());

        for date in ["2026-02-29", "2026-02-31", "2026-13-01", "0000-01-01"] {
            assert!(
                validate_date("sourceDate", date, false).is_err(),
                "accepted {date}"
            );
        }
        assert!(validate_date("sourceDate", "2024-02-29", false).is_ok());
        for timestamp in [
            "2026-11-10T12:30:00+garbage",
            "2026-11-10T12:30:00+24:00",
            "2026-11-10T12:30:00Ztail",
            "2026-11-10T25:30:00Z",
        ] {
            assert!(
                validate_date("retrievedAt", timestamp, true).is_err(),
                "accepted {timestamp}"
            );
        }
        assert!(validate_date("retrievedAt", "2026-11-10T12:30:00.123+02:30", true).is_ok());
    }

    #[test]
    fn import_and_load_refuse_fifo_and_symlink_components_without_accepting_partial_data() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        let source_dir = canonical_tempdir();
        let state = writable_tempdir();
        let fifo = source_dir.path().join("pipe");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let manifest = write_manifest(
            source_dir.path(),
            "fifo",
            vec![source(
                "pipe",
                "https://example.test/fifo",
                b"",
                Provenance::CurrentDocumentation,
            )],
        );
        assert!(import(state.repo(), state.path(), &manifest).is_err());
        assert!(!storage_root(state.repo(), state.path())
            .read_dir()
            .unwrap()
            .any(|entry| { entry.unwrap().file_name().to_string_lossy().len() == 64 }));

        fs::remove_file(&fifo).unwrap();
        fs::create_dir(source_dir.path().join("nested")).unwrap();
        fs::write(source_dir.path().join("nested/doc"), b"ok").unwrap();
        let manifest = write_manifest(
            source_dir.path(),
            "ok",
            vec![source(
                "nested/doc",
                "https://example.test/ok",
                b"ok",
                Provenance::CurrentDocumentation,
            )],
        );
        let installed = import(state.repo(), state.path(), &manifest).unwrap();
        let payload =
            bundle_dir(state.repo(), state.path(), &installed.bundle_id).join(PAYLOAD_DIR);
        make_writable_tree(&payload).unwrap();
        fs::remove_file(payload.join("nested/doc")).unwrap();
        let fifo = payload.join("nested/doc");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(load(state.repo(), state.path(), &installed.bundle_id).is_err());

        fs::remove_file(&fifo).unwrap();
        symlink(source_dir.path(), payload.join("nested/doc")).unwrap();
        assert!(load(state.repo(), state.path(), &installed.bundle_id).is_err());
    }

    #[test]
    fn later_tampering_is_detected() {
        let source_dir = canonical_tempdir();
        let state = writable_tempdir();
        fs::write(source_dir.path().join("doc"), b"original").unwrap();
        let manifest = write_manifest(
            source_dir.path(),
            "tamper",
            vec![source(
                "doc",
                "https://example.test/tamper",
                b"original",
                Provenance::CurrentDocumentation,
            )],
        );
        let installed = import(state.repo(), state.path(), &manifest).unwrap();
        let path = bundle_dir(state.repo(), state.path(), &installed.bundle_id).join("files/doc");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            load(state.repo(), state.path(), &installed.bundle_id),
            Err(EvidenceError::Invalid(_))
        ));
        fs::write(&path, b"tampered").unwrap();
        assert!(load(state.repo(), state.path(), &installed.bundle_id).is_err());
    }

    #[test]
    fn load_rejects_undeclared_entries_at_every_bundle_depth() {
        let sources = canonical_tempdir();
        let state = writable_tempdir();
        fs::create_dir(sources.path().join("nested")).unwrap();
        fs::write(sources.path().join("nested/doc"), b"ok").unwrap();
        let manifest = write_manifest(
            sources.path(),
            "known files",
            vec![source(
                "nested/doc",
                "https://example.test/doc",
                b"ok",
                Provenance::CurrentDocumentation,
            )],
        );
        let installed = import(state.repo(), state.path(), &manifest).unwrap();
        let reference = installed.reference(state.repo(), state.path()).unwrap();
        for parent in [
            &reference.root,
            &reference.root.join(PAYLOAD_DIR),
            &reference.root.join(PAYLOAD_DIR).join("nested"),
        ] {
            let extra = parent.join("unlisted");
            for directory in [false, true] {
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
                if directory {
                    fs::create_dir(&extra).unwrap();
                } else {
                    fs::write(&extra, b"not in the manifest").unwrap();
                }
                fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
                assert!(
                    load(state.repo(), state.path(), &reference.bundle_id).is_err(),
                    "extra entry accepted under {parent:?}"
                );
                assert!(reference.validate_for(state.repo(), state.path()).is_err());
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
                if directory {
                    fs::remove_dir(&extra).unwrap();
                } else {
                    fs::remove_file(&extra).unwrap();
                }
                fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            }
        }
        assert!(reference.validate_for(state.repo(), state.path()).is_ok());
    }

    #[test]
    fn task_roundtrip_and_prompt_preserve_identity_without_inlining_text() {
        let source_dir = canonical_tempdir();
        let state = writable_tempdir();
        fs::write(source_dir.path().join("doc"), b"secret source body").unwrap();
        let manifest = write_manifest(
            source_dir.path(),
            "navigation",
            vec![source(
                "doc",
                "https://example.test/nav",
                b"secret source body",
                Provenance::InstalledVersion,
            )],
        );
        let installed = import(state.repo(), state.path(), &manifest).unwrap();
        let task = Task {
            id: "offline".into(),
            title: "Read evidence".into(),
            description: "Compare the supplied source snapshot".into(),
            files: vec![],
            acceptance: vec!["cite provenance".into()],
            evidence: Some(Box::new(
                installed.reference(state.repo(), state.path()).unwrap(),
            )),
        };
        let replayed: Task = serde_json::from_slice(&serde_json::to_vec(&task).unwrap()).unwrap();
        assert_eq!(replayed, task);
        let prompt = build_builder_prompt(&replayed, "{}");
        assert!(prompt.contains(&installed.bundle_id));
        assert!(prompt.contains("unverified_provider_controlled"));
        assert!(prompt.contains("installed version"));
        assert!(prompt.contains("files/doc"));
        assert!(!prompt.contains("secret source body"));
        assert!(
            !prompt.contains(state.path().to_str().unwrap()),
            "worker evidence navigation leaks the daemon state directory"
        );
        let lead_prompt = build_lead_prompt("Compare these docs", &replayed);
        assert!(lead_prompt.contains(&installed.bundle_id));
        assert!(lead_prompt.contains("files/doc"));
        assert!(!lead_prompt.contains("secret source body"));
        assert!(!lead_prompt.contains(state.path().to_str().unwrap()));
        let reference = task.evidence.as_ref().unwrap();
        assert!(!reference.root.starts_with(state.path()));
        assert!(reference.validate_for(state.repo(), state.path()).is_ok());
        let mut legacy = task.clone();
        legacy.evidence.as_mut().unwrap().root =
            state.path().join("evidence").join(&installed.bundle_id);
        assert!(legacy
            .evidence
            .as_ref()
            .unwrap()
            .validate_metadata()
            .is_err());
        assert!(!build_builder_prompt(&legacy, "{}").contains(state.path().to_str().unwrap()));
    }

    #[test]
    fn separate_store_rejects_symlinks_and_shared_write_permissions() {
        let source_dir = canonical_tempdir();
        let state = writable_tempdir();
        fs::write(source_dir.path().join("doc"), b"source").unwrap();
        let manifest = write_manifest(
            source_dir.path(),
            "separate store",
            vec![source(
                "doc",
                "https://example.test/source",
                b"source",
                Provenance::InstalledVersion,
            )],
        );
        let store = storage_root(state.repo(), state.path())
            .parent()
            .unwrap()
            .to_path_buf();
        symlink(state.path(), &store).unwrap();
        assert!(import(state.repo(), state.path(), &manifest).is_err());
        fs::remove_file(&store).unwrap();
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(import(state.repo(), state.path(), &manifest).is_err());
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        let first = import(state.repo(), state.path(), &manifest).unwrap();
        let other = state.owner.path().join("other-state");
        fs::create_dir(&other).unwrap();
        let second = import(state.repo(), &other, &manifest).unwrap();
        assert_eq!(first.bundle_id, second.bundle_id);
        assert_ne!(
            first.reference(state.repo(), state.path()).unwrap().root,
            second.reference(state.repo(), &other).unwrap().root
        );
        assert!(first
            .reference(state.repo(), state.path())
            .unwrap()
            .validate_for(state.repo(), state.path())
            .is_ok());
        assert!(second
            .reference(state.repo(), &other)
            .unwrap()
            .validate_for(state.repo(), &other)
            .is_ok());
        assert!(
            import(state.repo(), &store, &manifest).is_err(),
            "a custom state cannot coincide with the evidence store"
        );
        let nested_state = store.join("custom-state");
        fs::create_dir(&nested_state).unwrap();
        assert!(
            import(state.repo(), &nested_state, &manifest).is_err(),
            "a custom state cannot be nested anywhere inside an evidence store"
        );
        let control = state.owner.path().join(".acp");
        let standard_state = control.join("repository-key");
        fs::create_dir_all(&standard_state).unwrap();
        let standard = import(state.repo(), &standard_state, &manifest)
            .unwrap()
            .reference(state.repo(), &standard_state)
            .unwrap();
        assert!(!standard.root.starts_with(&control));
        assert!(standard.validate_for(state.repo(), &standard_state).is_ok());
        fs::set_permissions(&store, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(load(state.repo(), state.path(), &first.bundle_id).is_err());
        assert!(first
            .reference(state.repo(), state.path())
            .unwrap()
            .validate_for(state.repo(), state.path())
            .is_err());
    }

    #[test]
    fn large_navigation_keeps_identity_and_capability_in_every_prompt_route() {
        use crate::core::handoff::*;
        use crate::core::types::{AttemptError, ErrorCode, VerifyReport, VerifyStatus};
        let source_dir = canonical_tempdir();
        let state = writable_tempdir();
        let mut sources = Vec::new();
        for i in 0..MAX_FILES {
            let file = format!("{i}-{}.txt", "x".repeat(180));
            fs::write(source_dir.path().join(&file), b"never inline this body").unwrap();
            sources.push(source(
                &file,
                &format!("https://example.test/{i}/{}", "q".repeat(500)),
                b"never inline this body",
                Provenance::CurrentDocumentation,
            ));
        }
        let manifest = write_manifest(source_dir.path(), "large navigation", sources);
        let installed = import(state.repo(), state.path(), &manifest).unwrap();
        let huge = "Unicode 🦀 input ".repeat(MAX_PROMPT_BYTES / 4);
        let task = Task {
            id: "large-evidence".into(),
            title: "Retain evidence".into(),
            description: huge.clone(),
            files: vec![],
            acceptance: vec!["preserve labels".into()],
            evidence: Some(Box::new(
                installed.reference(state.repo(), state.path()).unwrap(),
            )),
        };
        let error = AttemptError {
            code: ErrorCode::ProviderError,
            message: huge.clone(),
        };
        let report = VerifyReport {
            status: VerifyStatus::Fail,
            summary: huge.clone(),
            commands: vec![],
            failures: vec![],
            diff_hash: "f".repeat(64),
        };
        let prompts = [
            build_builder_prompt(&task, &huge),
            build_lead_prompt(&huge, &task),
            build_repair_prompt(&[], &task),
            build_failure_repair_prompt(&error, &task),
            build_retry_prompt(&task, &huge, Some(&error)),
            build_replacement_prompt(&task, &[], std::slice::from_ref(&huge), Some(Path::new("/retired-draft"))),
            build_verifier_prompt(&task, Path::new("/diff"), &"f".repeat(64), None),
            build_verify_repair_prompt(&report, &task),
            build_reviewer_prompt(
                &task,
                Path::new("/diff"),
                &"f".repeat(64),
                None,
                Some(&report),
            ),
        ];
        for prompt in prompts {
            assert!(prompt.len() <= MAX_PROMPT_BYTES);
            assert!(prompt.contains(&installed.bundle_id));
            assert!(prompt.contains("unverified_provider_controlled"));
            assert!(prompt.contains("manifest.json"));
            assert!(prompt.contains("source entries omitted"));
            assert!(!prompt.contains("never inline this body"));
            assert!(!prompt.contains(state.path().to_str().unwrap()));
            assert_eq!(
                prompt.matches(ADVISORY_OPEN).count(),
                prompt.matches(ADVISORY_CLOSE).count()
            );
        }
    }

    #[test]
    fn rejects_when_compact_installed_manifest_would_exceed_load_limit() {
        let root = canonical_tempdir();
        let state = writable_tempdir();
        let mut sources = Vec::new();
        for index in 0..MAX_FILES {
            let url = format!("https://example.test/{index}/{}", "x".repeat(760));
            sources.push(source(
                &format!("f{index}"),
                &url,
                b"x",
                Provenance::CurrentDocumentation,
            ));
        }
        let mut input = ImportManifest {
            version: 1,
            title: "edge".into(),
            sources,
        };
        let target = MAX_MANIFEST_BYTES - 40;
        let mut needed = target.saturating_sub(serde_json::to_vec(&input).unwrap().len());
        for source in &mut input.sources {
            let add = needed.min(MAX_URL_BYTES - source.url.len());
            source.url.push_str(&"x".repeat(add));
            needed -= add;
            if needed == 0 {
                break;
            }
        }
        let bytes = serde_json::to_vec(&input).unwrap();
        assert_eq!(bytes.len(), target);
        assert!(bytes.len() <= MAX_MANIFEST_BYTES);
        let path = root.path().join("edge.json");
        fs::write(&path, bytes).unwrap();
        assert!(
            matches!(import(state.repo(), state.path(), &path), Err(EvidenceError::Invalid(message)) if message.contains("installed manifest exceeds"))
        );
    }

    #[test]
    fn rejects_a_file_over_the_per_file_bound() {
        let root = canonical_tempdir();
        let state = writable_tempdir();
        let path = root.path().join("huge");
        File::create(&path)
            .unwrap()
            .set_len(MAX_FILE_BYTES + 1)
            .unwrap();
        let manifest = write_manifest(
            root.path(),
            "oversized",
            vec![SourceEntry {
                url: "https://example.test/huge".into(),
                retrieved_at: "2026-11-10T12:30:00Z".into(),
                source_date: None,
                provenance: Provenance::CurrentDocumentation,
                sha256: "0".repeat(64),
                file: "huge".into(),
            }],
        );
        assert!(
            matches!(import(state.repo(), state.path(), &manifest), Err(EvidenceError::Invalid(message)) if message.contains("no larger"))
        );
    }
}
