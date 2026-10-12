//! Local source inspection. The core owns admission/cancellation; this module owns Swift details.
pub mod rules;
pub mod runner;
use crate::workspace::git;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_SOURCE: usize = 2 * 1024 * 1024;
const MAX_REPORT: usize = 4 * 1024 * 1024;
pub const ANALYZER: &str = "1.0.0-swiftsyntax603.0.1";
const EXCLUDED: &[&str] = &[
    ".build",
    "DerivedData",
    "Pods",
    "Carthage",
    ".swiftpm",
    "vendor",
    "Vendor",
    "Generated",
    "node_modules",
    ".acp",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub id: Uuid,
    pub scope: Scope,
    pub base_ref: String,
    pub revision: Option<String>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Scope {
    Changes,
    Project,
    Revision,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Summary {
    pub id: Uuid,
    pub request: Request,
    pub created_at: String,
    pub status: String,
    pub detail: String,
    pub file_count: usize,
    pub finding_count: usize,
    pub report_hash: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceFile {
    pub path: String,
    pub hash: String,
    pub parsed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub rule: String,
    pub file: String,
    pub offset: usize,
    pub length: usize,
    pub line: usize,
    pub column: usize,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    pub version: u32,
    pub analyzer: String,
    pub analyzer_hash: String,
    pub base_sha: String,
    pub tree_sha: String,
    pub diff_hash: String,
    pub manifest_hash: String,
    pub rules_hash: String,
    pub rules: Vec<rules::Rule>,
    pub files: Vec<SourceFile>,
    pub findings: Vec<Finding>,
    pub excluded: usize,
    pub partial: bool,
}
#[derive(Debug, Serialize)]
struct InputFile {
    path: String,
    source: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    version: u32,
    analyzer: String,
    files: Vec<ParsedFile>,
    findings: Vec<Finding>,
    truncated: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParsedFile {
    path: String,
    parsed: bool,
}

pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn directory(state: &Path, id: Uuid) -> PathBuf {
    state.join("checks").join(id.to_string())
}
pub fn validate(request: &Request) -> Result<(), String> {
    if request.base_ref.is_empty()
        || request.base_ref.len() > 256
        || request.base_ref.starts_with('-')
    {
        return Err("Choose a valid base revision (1–256 bytes)".into());
    }
    if matches!(request.scope, Scope::Revision) != request.revision.is_some() {
        return Err("Revision scope requires an explicit target revision".into());
    }
    if request
        .revision
        .as_ref()
        .is_some_and(|s| s.is_empty() || s.len() > 256 || s.starts_with('-'))
    {
        return Err("Invalid target revision".into());
    }
    Ok(())
}
fn regular(path: &Path, cap: usize) -> Result<Vec<u8>, String> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| e.to_string())?;
    let metadata = f.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > cap as u64 {
        return Err("Artifact is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    (&mut f)
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > cap {
        return Err("Artifact exceeded its limit".into());
    }
    Ok(bytes)
}
fn safe_directory(path: &Path) -> Result<(), String> {
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part);
        if fs::symlink_metadata(&prefix)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("Symlinked review directory refused".into());
        }
    }
    Ok(())
}
pub fn read_summary(state: &Path, id: Uuid) -> Result<Summary, String> {
    let dir = directory(state, id);
    safe_directory(&dir)?;
    let bytes = regular(&dir.join("events.jsonl"), 64 * 1024)?;
    let mut last = None;
    for line in bytes.split(|b| *b == b'\n').filter(|s| !s.is_empty()) {
        let summary: Summary = serde_json::from_slice(line).map_err(|e| e.to_string())?;
        if summary.id != id || summary.request.id != id {
            return Err("Review identity mismatch".into());
        }
        last = Some(summary);
    }
    last.ok_or("Review history is empty".into())
}
pub fn append(state: &Path, summary: &Summary) -> Result<(), String> {
    let root = state.join("checks");
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    safe_directory(&root)?;
    let dir = directory(state, summary.id);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    safe_directory(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let mut bytes = serde_json::to_vec(summary).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > 8192 {
        return Err("Review summary exceeded its limit".into());
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join("events.jsonl"))
        .map_err(|e| e.to_string())?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_data())
        .map_err(|e| e.to_string())
}
pub fn list(state: &Path) -> Result<Vec<Summary>, String> {
    let root = state.join("checks");
    if !root.exists() {
        return Ok(vec![]);
    }
    safe_directory(&root)?;
    let entries = fs::read_dir(root).map_err(|e| e.to_string())?;
    let mut summaries = Vec::new();
    for (count, entry) in entries.enumerate() {
        if count >= 1000 {
            return Err("Review history exceeds the supported 1,000 entries".into());
        }
        let entry = entry.map_err(|e| e.to_string())?;
        if let Ok(id) = Uuid::parse_str(&entry.file_name().to_string_lossy()) {
            summaries.push(read_summary(state, id)?);
        }
    }
    summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(summaries)
}
pub fn report(state: &Path, summary: &Summary) -> Result<Report, String> {
    let dir = directory(state, summary.id);
    safe_directory(&dir)?;
    let bytes = regular(&dir.join("report.json"), MAX_REPORT)?;
    if summary.report_hash.as_deref() != Some(&hash(&bytes)) {
        return Err("Review report hash does not match its recorded evidence".into());
    }
    let report: Report = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if report.version != 1
        || hash(&serde_json::to_vec(&report.rules).map_err(|e| e.to_string())?) != report.rules_hash
    {
        return Err("Unsupported report version or recorded rule library mismatch".into());
    }
    Ok(report)
}
pub fn page(state: &Path, summary: &Summary, offset: usize) -> Result<Value, String> {
    let r = report(state, summary)?;
    if offset > r.findings.len() {
        return Err("Invalid finding offset".into());
    }
    let end = (offset + 50).min(r.findings.len());
    Ok(
        json!({"summary":summary, "analyzer":r.analyzer,"analyzerHash":r.analyzer_hash,"manifestHash":r.manifest_hash,
        "rulesHash":r.rules_hash,"diffHash":r.diff_hash,"baseSha":r.base_sha,"treeSha":r.tree_sha,
        "partial":r.partial,"excluded":r.excluded,"parseErrors":r.files.iter().filter(|f| !f.parsed).map(|f| &f.path).take(50).collect::<Vec<_>>(),
        "findings":r.findings[offset..end],"nextOffset":(end < r.findings.len()).then_some(end),"rules":r.rules}),
    )
}
pub fn source(state: &Path, summary: &Summary, file: &str, line: usize) -> Result<Value, String> {
    let r = report(state, summary)?;
    let (index, info) = r
        .files
        .iter()
        .enumerate()
        .find(|(_, f)| f.path == file)
        .ok_or("File was not part of this review")?;
    let bytes = regular(
        &directory(state, summary.id).join(format!("source-{index}.swift")),
        MAX_SOURCE,
    )?;
    if hash(&bytes) != info.hash {
        return Err("Captured source hash mismatch".into());
    }
    let text = String::from_utf8(bytes).map_err(|e| e.to_string())?;
    let lines: Vec<_> = text.lines().collect();
    if line == 0 || line > lines.len() {
        return Err("Invalid source line".into());
    }
    let start = line.saturating_sub(5);
    let mut size = 0;
    let excerpt: Vec<_> = lines
        .iter()
        .enumerate()
        .skip(start)
        .take(10)
        .map(|(i, s)| {
            let text: String = s.chars().take(2000).collect();
            size += text.len();
            json!({"number":i+1,"text":text,"truncated":text.len() < s.len()})
        })
        .collect();
    if size > 80_000 {
        return Err("Source excerpt exceeded its limit".into());
    }
    Ok(json!({"file":file,"hash":info.hash,"lines":excerpt}))
}

/// Prepares task text only. No worker starts and no source is edited.
pub fn prepare_fix(
    state: &Path,
    repo: &Path,
    id: Uuid,
    indices: &[usize],
) -> Result<Value, String> {
    if indices.is_empty() || indices.len() > 10 {
        return Err("Choose between one and ten findings".into());
    }
    let summary = read_summary(state, id)?;
    if summary.request.scope == Scope::Revision {
        return Err(
            "Review the current working tree before preparing fixes for a historical revision"
                .into(),
        );
    }
    let report = report(state, &summary)?;
    for file in &report.files {
        let relative = Path::new(&file.path);
        if relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err("Invalid captured source path".into());
        }
        let path = repo.join(relative);
        safe_directory(path.parent().ok_or("Missing source parent")?)?;
        if hash(&regular(&path, MAX_SOURCE)?) != file.hash {
            return Err(
                "Source changed after this review. Run a new review before requesting fixes."
                    .into(),
            );
        }
    }
    let mut prompt = format!("Assess and address these selected Swift Review findings in the current project. Preserve intended behavior; recommendations may be intentional. Source manifest: {}. Re-run Swift Review after edits and report any remaining findings.\n", report.manifest_hash);
    for index in indices {
        let finding = report.findings.get(*index).ok_or("Unknown finding")?;
        let rule = report
            .rules
            .iter()
            .find(|r| r.id == finding.rule)
            .ok_or("Unknown recorded rule")?;
        prompt.push_str(&format!(
            "\n{}:{} — {}\n{}\n{}\n",
            finding.file, finding.line, rule.title, rule.explanation, rule.guidance
        ));
    }
    if prompt.chars().count() > 16000 {
        return Err("Selected findings exceed the task prompt limit".into());
    }
    Ok(json!({"prompt":prompt,"manifestHash":report.manifest_hash}))
}

pub async fn execute(
    repo: PathBuf,
    state: PathBuf,
    request: Request,
    cancel: CancellationToken,
) -> Result<Report, String> {
    let helper = runner::helper()?;
    let helper_path = helper.path().to_owned();
    let analyzer_hash = tokio::task::spawn_blocking(move || {
        regular(&helper_path, 64 * 1024 * 1024).map(|bytes| hash(&bytes))
    })
    .await
    .map_err(|e| e.to_string())??;
    let dir = directory(&state, request.id);
    let worktree = repo
        .join(".acp/worktrees")
        .join(request.id.to_string())
        .join("check");
    let selection = git::audit::Selection {
        base_ref: request.base_ref.clone(),
        target: match &request.revision {
            Some(revision) => git::audit::Target::Revision {
                revision: revision.clone(),
            },
            None => git::audit::Target::WorkingTree {},
        },
    };
    // Capture finishes even after cancellation so temporary indexes/worktrees are not abandoned
    // halfway through a Git operation. Every Git operation has the existing timeout.
    let captured = git::audit::capture_for_inspection(
        &repo,
        selection,
        &dir,
        &worktree,
        &format!("acp/{}/check", request.id),
        true,
    )
    .await;
    let snapshot = match captured {
        Ok(snapshot) => snapshot,
        Err(error) => {
            if worktree.exists() {
                let _ = git::remove_worktree(&repo, &worktree, true).await;
            }
            return Err(error.to_string());
        }
    };
    let result = async {
        if cancel.is_cancelled() {
            return Err("Review cancelled".into());
        }
        git::audit::validate(&snapshot)
            .await
            .map_err(|e| e.to_string())?;
        let root = worktree.clone();
        let scope = request.scope;
        let changed = snapshot.files.clone();
        let artifact = dir.clone();
        let (files, mut info, excluded) =
            tokio::task::spawn_blocking(move || capture_sources(&root, scope, &changed, &artifact))
                .await
                .map_err(|e| e.to_string())??;
        let identities: Vec<_> = info.iter().map(|f| (&f.path, &f.hash)).collect();
        let manifest_hash = hash(&serde_json::to_vec(&identities).map_err(|e| e.to_string())?);
        let mut findings = vec![];
        let mut partial = false;
        if !files.is_empty() {
            let input = serde_json::to_vec(&json!({"version":1,"files":files}))
                .map_err(|e| e.to_string())?;
            let output = runner::analyze(&helper, input, &cancel).await?;
            let output: Output = serde_json::from_slice(&output)
                .map_err(|e| format!("Invalid analyzer response: {e}"))?;
            if output.version != 1
                || output.analyzer != ANALYZER
                || output.files.len() != files.len()
                || output.findings.len() > 1000
            {
                return Err("Analyzer schema/version mismatch".into());
            }
            for (index, parsed) in output.files.iter().enumerate() {
                if parsed.path != files[index].path {
                    return Err("Analyzer source identity mismatch".into());
                }
                info[index].parsed = parsed.parsed;
                partial |= !parsed.parsed;
            }
            for f in &output.findings {
                let file = files
                    .iter()
                    .find(|s| s.path == f.file)
                    .ok_or("Analyzer returned an unknown file")?;
                let end = f
                    .offset
                    .checked_add(f.length)
                    .ok_or("Invalid source span")?;
                if rules::find(&f.rule).is_none()
                    || f.length == 0
                    || end > file.source.len()
                    || !file.source.is_char_boundary(f.offset)
                    || !file.source.is_char_boundary(end)
                {
                    return Err("Invalid finding location or rule".into());
                }
                let prefix = &file.source[..f.offset];
                let line = prefix.bytes().filter(|b| *b == b'\n').count() + 1;
                let column = prefix.rsplit('\n').next().map_or(1, |s| s.len() + 1);
                if line != f.line || column != f.column {
                    return Err("Finding line does not match its source span".into());
                }
            }
            if output
                .findings
                .iter()
                .any(|f| info.iter().any(|i| i.path == f.file && !i.parsed))
            {
                return Err("Analyzer returned findings for unparsed source".into());
            }
            findings = output.findings;
            partial |= output.truncated;
        }
        git::audit::validate(&snapshot)
            .await
            .map_err(|e| e.to_string())?;
        if cancel.is_cancelled() {
            return Err("Review cancelled".into());
        }
        let helper_path = helper.path().to_owned();
        let final_hash = tokio::task::spawn_blocking(move || {
            regular(&helper_path, 64 * 1024 * 1024).map(|bytes| hash(&bytes))
        })
        .await
        .map_err(|e| e.to_string())??;
        if final_hash != analyzer_hash {
            return Err("Analyzer changed during this review; run a new review".into());
        }
        Ok(Report {
            version: 1,
            analyzer: ANALYZER.into(),
            analyzer_hash,
            base_sha: snapshot.base_sha,
            tree_sha: snapshot.tree_sha,
            diff_hash: snapshot.diff_hash,
            manifest_hash,
            rules: serde_json::from_value(
                serde_json::to_value(rules::RULES).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?,
            rules_hash: hash(&serde_json::to_vec(rules::RULES).map_err(|e| e.to_string())?),
            files: info,
            findings,
            excluded,
            partial,
        })
    }
    .await;
    // No provider session ever owns this read-only snapshot.
    let cleanup = git::remove_worktree(&repo, &worktree, true).await;
    if let Err(error) = cleanup {
        return Err(format!("Review snapshot cleanup failed: {error}"));
    }
    result
}

fn capture_sources(
    root: &Path,
    scope: Scope,
    changed: &[String],
    artifact: &Path,
) -> Result<(Vec<InputFile>, Vec<SourceFile>, usize), String> {
    let mut queue = vec![root.to_path_buf()];
    let mut paths = vec![];
    let mut excluded = 0;
    let mut entries = 0;
    while let Some(dir) = queue.pop() {
        for entry in fs::read_dir(&dir).map_err(|e| e.to_string())? {
            entries += 1;
            if entries > 20_000 {
                return Err("Project exceeds the review file limit".into());
            }
            let entry = entry.map_err(|e| e.to_string())?;
            let ty = entry.file_type().map_err(|e| e.to_string())?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("Non-UTF-8 source path")?
                .to_string();
            if relative.len() > 1024 {
                return Err("Source path exceeds 1,024 bytes".into());
            }
            if Path::new(&relative).components().any(|p| matches!(p,Component::Normal(s) if EXCLUDED.contains(&s.to_string_lossy().as_ref()))) || entry.file_name() == ".git" { excluded+=1; continue; }
            if ty.is_symlink() {
                if path.extension().is_some_and(|s| s == "swift") {
                    return Err("Symlinked Swift source cannot be reviewed".into());
                }
                excluded += 1;
                continue;
            }
            if ty.is_dir() {
                queue.push(path);
                continue;
            }
            if path.extension().is_some_and(|s| s == "swift")
                && (scope == Scope::Project || changed.contains(&relative))
            {
                paths.push((relative, path));
            }
        }
    }
    paths.sort();
    if paths.len() > 2000 {
        return Err("Review exceeds 2,000 Swift files; choose a smaller scope".into());
    }
    let mut files = vec![];
    let mut manifest = vec![];
    let mut total = 0;
    for (index, (path, absolute)) in paths.into_iter().enumerate() {
        let bytes = regular(&absolute, MAX_SOURCE)?;
        total += bytes.len();
        if total > 32 * 1024 * 1024 {
            return Err("Review exceeds 32 MiB of Swift source".into());
        }
        let source = String::from_utf8(bytes.clone())
            .map_err(|_| format!("Swift source is not UTF-8: {path}"))?;
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(artifact.join(format!("source-{index}.swift")))
            .map_err(|e| e.to_string())?;
        f.write_all(&bytes)
            .and_then(|_| f.sync_data())
            .map_err(|e| e.to_string())?;
        manifest.push(SourceFile {
            path: path.clone(),
            hash: hash(&bytes),
            parsed: false,
        });
        files.push(InputFile { path, source });
    }
    Ok((files, manifest, excluded))
}

pub fn persist_report(state: &Path, id: Uuid, report: &Report) -> Result<String, String> {
    let bytes = serde_json::to_vec(report).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_REPORT {
        return Err("Review report exceeds its limit".into());
    }
    let dir = directory(state, id);
    safe_directory(&dir)?;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(dir.join("report.json"))
        .map_err(|e| e.to_string())?;
    f.write_all(&bytes)
        .and_then(|_| f.sync_data())
        .map_err(|e| e.to_string())?;
    Ok(hash(&bytes))
}

pub fn mark_interrupted(value: &mut Summary) {
    if value.status == "running" {
        value.status = "interrupted".into();
        value.detail =
            "The daemon stopped before this review completed. Start a new review.".into();
    }
}

/// On restart in-flight reviews are displayed as interrupted, never silently retried.
pub fn restored(state: &Path, active: &HashSet<Uuid>) -> Result<Vec<Summary>, String> {
    let mut values = list(state)?;
    for value in &mut values {
        if value.status == "running" && !active.contains(&value.id) {
            mark_interrupted(value);
        }
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tempdir() -> std::io::Result<tempfile::TempDir> {
        tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)
    }
    fn request() -> Request {
        Request {
            id: Uuid::new_v4(),
            scope: Scope::Project,
            base_ref: "HEAD".into(),
            revision: None,
        }
    }
    #[test]
    fn explicit_revision_and_bounded_refs() {
        let mut r = request();
        assert!(validate(&r).is_ok());
        r.scope = Scope::Revision;
        assert!(validate(&r).is_err());
        r.revision = Some("HEAD~1".into());
        assert!(validate(&r).is_ok());
        r.base_ref = "--upload-pack=anything".into();
        assert!(validate(&r).is_err());
        r.base_ref = "x".repeat(257);
        assert!(validate(&r).is_err());
    }
    #[test]
    fn source_capture_is_scoped_sorted_and_excludes_build_output() {
        let temp = tempdir().unwrap();
        let root = temp.path().join(".acp/worktrees/review");
        let artifact = temp.path().join("artifact");
        fs::create_dir_all(root.join(".build")).unwrap();
        fs::create_dir(&artifact).unwrap();
        fs::write(root.join("B.swift"), "struct B {}").unwrap();
        fs::write(root.join("A.swift"), "struct A {}").unwrap();
        fs::write(root.join(".build/Generated.swift"), "struct G {}").unwrap();
        let (files, manifest, excluded) =
            capture_sources(&root, Scope::Changes, &["B.swift".into()], &artifact).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "B.swift");
        assert_eq!(excluded, 1);
        assert_eq!(manifest[0].hash, hash(b"struct B {}"));
    }
    #[test]
    fn symlink_and_oversized_sources_are_refused() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("repo");
        let art = temp.path().join("art");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&art).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("Link.swift")).unwrap();
        assert!(capture_sources(&root, Scope::Project, &[], &art)
            .unwrap_err()
            .contains("Symlinked"));
        fs::remove_file(root.join("Link.swift")).unwrap();
        fs::write(root.join("Large.swift"), vec![b' '; MAX_SOURCE + 1]).unwrap();
        assert!(capture_sources(&root, Scope::Project, &[], &art).is_err());
    }
    #[test]
    fn durable_history_restarts_as_interrupted_and_rejects_identity_mismatch() {
        let temp = tempdir().unwrap();
        let r = request();
        let mut summary = Summary {
            id: r.id,
            request: r,
            created_at: "now".into(),
            status: "running".into(),
            detail: "capturing".into(),
            file_count: 0,
            finding_count: 0,
            report_hash: None,
        };
        append(temp.path(), &summary).unwrap();
        assert_eq!(
            restored(temp.path(), &HashSet::new()).unwrap()[0].status,
            "interrupted"
        );
        assert_eq!(
            restored(temp.path(), &HashSet::from([summary.id])).unwrap()[0].status,
            "running"
        );
        summary.status = "cancelled".into();
        append(temp.path(), &summary).unwrap();
        assert_eq!(list(temp.path()).unwrap()[0].status, "cancelled");
        summary.request.id = Uuid::new_v4();
        append(temp.path(), &summary).unwrap();
        assert!(read_summary(temp.path(), summary.id).is_err());
    }
    #[test]
    fn saved_guidance_uses_the_recorded_library_and_checks_its_hash() {
        let temp = tempdir().unwrap();
        let request = request();
        let mut summary = Summary {
            id: request.id,
            request,
            created_at: "now".into(),
            status: "completed".into(),
            detail: "done".into(),
            file_count: 0,
            finding_count: 0,
            report_hash: None,
        };
        append(temp.path(), &summary).unwrap();
        let mut recorded: Vec<rules::Rule> =
            serde_json::from_value(serde_json::to_value(rules::RULES).unwrap()).unwrap();
        recorded[0].title = "Guidance from this particular release".into();
        let report = Report {
            version: 1,
            analyzer: "historical-analyzer".into(),
            analyzer_hash: "binary".into(),
            base_sha: "base".into(),
            tree_sha: "tree".into(),
            diff_hash: "diff".into(),
            manifest_hash: "source".into(),
            rules_hash: hash(&serde_json::to_vec(&recorded).unwrap()),
            rules: recorded,
            files: vec![],
            findings: vec![],
            excluded: 0,
            partial: false,
        };
        summary.report_hash = Some(persist_report(temp.path(), summary.id, &report).unwrap());
        append(temp.path(), &summary).unwrap();
        let page = page(temp.path(), &summary, 0).unwrap();
        assert_eq!(
            page["rules"][0]["title"],
            "Guidance from this particular release"
        );
        assert_eq!(page["analyzer"], "historical-analyzer");
        let mut changed = report;
        changed.rules[0].title = "Changed without updating the library identity".into();
        let bytes = serde_json::to_vec(&changed).unwrap();
        fs::write(
            directory(temp.path(), summary.id).join("report.json"),
            &bytes,
        )
        .unwrap();
        summary.report_hash = Some(hash(&bytes));
        assert!(super::report(temp.path(), &summary)
            .unwrap_err()
            .contains("library mismatch"));
    }
    #[test]
    fn artifacts_must_be_regular_and_report_hash_must_match() {
        let temp = tempdir().unwrap();
        let r = request();
        let summary = Summary {
            id: r.id,
            request: r,
            created_at: "now".into(),
            status: "completed".into(),
            detail: "done".into(),
            file_count: 0,
            finding_count: 0,
            report_hash: Some("wrong".into()),
        };
        append(temp.path(), &summary).unwrap();
        fs::write(directory(temp.path(), summary.id).join("report.json"), "{}").unwrap();
        assert!(report(temp.path(), &summary).unwrap_err().contains("hash"));
        let path = temp.path().join("link");
        std::os::unix::fs::symlink("/etc/passwd", &path).unwrap();
        assert!(regular(&path, 10000).is_err());
    }
}
