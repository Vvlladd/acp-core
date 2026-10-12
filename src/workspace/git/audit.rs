//! Immutable audit input, captured without changing the source branch or staging area.
//! These helpers run outside the core actor and use its existing per-worktree lock.
use super::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;

const OP: &str = "audit_snapshot";
const MAX_PATH_BYTES: usize = 1024 * 1024;
const MAX_FILES: usize = 10_000;
/// Bounds raw tracked checkout validation, independently of the diff's 8 MiB budget.
const MAX_SOURCE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_SUMMARY_BYTES: usize = 24 * 1024;

/// An explicit comparison base and the existing work to inspect. No implied base selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Selection {
    pub base_ref: String,
    pub target: Target,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Target {
    WorkingTree {},
    Revision { revision: String },
}

/// All later checks use these immutable object names and this exact diff. Moving the input
/// branch or editing the source worktree never changes a captured task's meaning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Snapshot {
    pub version: u32,
    pub selection: Selection,
    pub base_sha: String,
    pub tree_sha: String,
    pub worktree: PathBuf,
    pub diff_path: PathBuf,
    pub diff_hash: String,
    pub files: Vec<String>,
    pub manifest_path: PathBuf,
    pub manifest_hash: String,
    pub source_hash: String,
}

fn rejected(reason: impl Into<String>) -> GitError {
    GitError::Failed {
        op: OP,
        status: "refused".into(),
        message: reason.into(),
    }
}

/// Capture includes nonignored untracked files. A temporary index is the only index staged;
/// source HEAD, branch and the human's partially staged choices are unchanged. A snapshot is
/// fixed once captured, but does not claim a filesystem-wide transaction during concurrent edits.
pub async fn capture(
    repo: &Path,
    selection: Selection,
    artifact_dir: &Path,
    worktree: &Path,
    branch: &str,
) -> Result<Snapshot, GitError> {
    capture_for_inspection(repo, selection, artifact_dir, worktree, branch, false).await
}

/// Local whole-project inspections need a materialized snapshot even without a changed file.
/// Existing provider audits keep their original empty-input behavior through `capture`.
pub async fn capture_for_inspection(
    repo: &Path, selection: Selection, artifact_dir: &Path, worktree: &Path,
    branch: &str, include_unchanged: bool,
) -> Result<Snapshot, GitError> {
    let base_sha = resolve_ref(repo, &selection.base_ref).await?;
    tokio::fs::create_dir_all(artifact_dir)
        .await
        .map_err(|source| GitError::Io { op: OP, source })?;
    let tree_sha = match &selection.target {
        Target::Revision { revision } => {
            let commit = resolve_ref(repo, revision).await?;
            let tree = format!("{commit}^{{tree}}");
            let out = git_stdout_capped(
                OP,
                repo,
                ["rev-parse", "--verify", "--end-of-options", &tree],
                128,
            )
            .await?;
            checked_sha(OP, out.stdout().trim())?
        }
        Target::WorkingTree {} => {
            // Never reuse an index left by an interrupted capture. The path is daemon-created.
            let index = artifact_dir.join(format!("capture-{}.index", uuid::Uuid::new_v4()));
            let result = capture_working_tree(repo, &index).await;
            let _ = tokio::fs::remove_file(&index).await;
            let _ = tokio::fs::remove_file(index.with_extension("index.lock")).await;
            result?
        }
    };
    // Gitlinks cannot represent modified nested source, and a linked worktree does not populate
    // their contents. Refuse both baseline and target gitlinks, including unchanged ones.
    tracked_paths(repo, &base_sha).await?;
    let tracked_paths = tracked_paths(repo, &tree_sha).await?;
    // Binary data, symlinks and new files are represented by Git's object-to-object diff. No
    // external diff driver/textconv, no lossy path parsing and no silently truncated review.
    let diff = git_stdout_capped(
        OP,
        repo,
        [
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--no-renames",
            "--binary",
            base_sha.as_str(),
            tree_sha.as_str(),
            "--",
        ],
        MAX_FROZEN_DIFF_BYTES,
    )
    .await?;
    if diff.truncated || diff.raw.len() > MAX_FROZEN_DIFF_BYTES {
        return Err(rejected("audit input exceeds the 8 MiB diff budget"));
    }
    let names = git_stdout_capped(
        OP,
        repo,
        [
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--name-only",
            "-z",
            base_sha.as_str(),
            tree_sha.as_str(),
            "--",
        ],
        MAX_PATH_BYTES,
    )
    .await?;
    if names.truncated || names.raw.len() > MAX_PATH_BYTES {
        return Err(rejected("audit input has too many path bytes"));
    }
    let names = String::from_utf8(names.raw).map_err(|_| rejected("audit paths must be UTF-8"))?;
    let files: Vec<_> = names
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if files.len() > MAX_FILES {
        return Err(rejected("audit input has too many files"));
    }
    let diff_path = artifact_dir.join("audit.diff");
    // Keep the complete tracked-file manifest off the socket. Only its bounded artifact
    // reference and digest travel in runs/events; unchanged repository paths do not bloat status.
    let manifest_path = artifact_dir.join("tracked-files.json");
    let manifest =
        serde_json::to_vec(&tracked_paths).map_err(|error| rejected(error.to_string()))?;
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(rejected("audit manifest exceeds 2 MiB"));
    }
    let manifest_hash = format!("{:x}", Sha256::digest(&manifest));
    tokio::fs::write(&manifest_path, &manifest)
        .await
        .map_err(|source| GitError::Io { op: OP, source })?;
    let diff_hash = format!("{:x}", Sha256::digest(&diff.raw));
    tokio::fs::write(&diff_path, &diff.raw)
        .await
        .map_err(|source| GitError::Io { op: OP, source })?;
    let mut snapshot = Snapshot {
        version: 1,
        selection,
        base_sha,
        tree_sha,
        worktree: worktree.into(),
        diff_path,
        diff_hash,
        files,
        manifest_path,
        manifest_hash,
        source_hash: String::new(),
    };
    if serde_json::to_vec(&snapshot)
        .map_err(|error| rejected(error.to_string()))?
        .len()
        + 64
        > MAX_SUMMARY_BYTES
    {
        return Err(rejected(
            "audit changed-file summary exceeds the 24 KiB transport budget",
        ));
    }
    // An empty diff is an honest no-change result, and needs no check process or worktree.
    if include_unchanged || !snapshot.files.is_empty() {
        add_worktree(repo, worktree, branch, &snapshot.base_sha).await?;
        git(
            OP,
            worktree,
            ["read-tree", "--reset", "-u", &snapshot.tree_sha],
        )
        .await?;
        snapshot.source_hash = source_hash(&snapshot).await?;
        validate(&snapshot).await?;
    }
    Ok(snapshot)
}

async fn capture_working_tree(repo: &Path, index: &Path) -> Result<String, GitError> {
    let head = head_sha(repo).await?;
    indexed(repo, index, &["read-tree", &head]).await?;
    indexed(repo, index, &["add", "--all", "--", "."]).await?;
    let out = indexed(repo, index, &["write-tree"]).await?;
    checked_sha(OP, out.stdout().trim())
}

async fn indexed(repo: &Path, index: &Path, args: &[&str]) -> Result<CappedGitOut, GitError> {
    let mut command = git_command(OP, repo)?;
    command
        .env("GIT_INDEX_FILE", index)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    let result = git_command_capped(OP, command, 128).await?;
    if result.truncated {
        return Err(rejected("unexpected index command output"));
    }
    Ok(result)
}

/// Run before and after checks and during recovery. Tests may generate untracked build output,
/// but cannot change the snapshot's tracked source, staging area, HEAD or frozen diff artifact.
pub async fn validate(snapshot: &Snapshot) -> Result<(), GitError> {
    if snapshot.version != 1 {
        return Err(rejected("unknown audit snapshot version"));
    }
    checked_sha(OP, &snapshot.base_sha)?;
    checked_sha(OP, &snapshot.tree_sha)?;
    let root = snapshot
        .diff_path
        .parent()
        .ok_or_else(|| rejected("missing artifact directory"))?
        .canonicalize()
        .map_err(|source| GitError::Io { op: OP, source })?;
    let name = snapshot
        .diff_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| rejected("invalid artifact name"))?;
    let dir = open_root_dir(&root).map_err(|source| GitError::Io { op: OP, source })?;
    let file =
        open_under_root(dir.as_fd(), name).map_err(|source| GitError::Io { op: OP, source })?;
    let (diff, truncated) = read_capped(file, MAX_FROZEN_DIFF_BYTES)
        .await
        .map_err(|source| GitError::Io { op: OP, source })?;
    if truncated || format!("{:x}", Sha256::digest(&diff)) != snapshot.diff_hash {
        return Err(rejected(
            "the frozen audit diff changed or exceeds its bound",
        ));
    }
    if snapshot.files.is_empty() && snapshot.source_hash.is_empty() {
        return Ok(());
    }
    if source_hash(snapshot).await? != snapshot.source_hash {
        return Err(rejected(
            "a check modified the audit snapshot's tracked source bytes, type or mode",
        ));
    }
    if head_sha(&snapshot.worktree).await? != snapshot.base_sha {
        return Err(rejected("the audit snapshot HEAD changed"));
    }
    let tree = git_stdout_capped(OP, &snapshot.worktree, ["write-tree"], 128).await?;
    if tree.truncated || checked_sha(OP, tree.stdout().trim())? != snapshot.tree_sha {
        return Err(rejected("the audit snapshot index changed"));
    }
    // A check could set assume-unchanged/skip-worktree bits in its index. Compare through a
    // freshly populated private index so those hints cannot hide tracked-source mutation.
    let index = snapshot
        .diff_path
        .with_file_name(format!("validate-{}.index", uuid::Uuid::new_v4()));
    let result = async {
        indexed(
            &snapshot.worktree,
            &index,
            &["read-tree", &snapshot.tree_sha],
        )
        .await?;
        let mut command = git_command(OP, &snapshot.worktree)?;
        command
            .env("GIT_INDEX_FILE", &index)
            .args([
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--name-only",
                "-z",
                &snapshot.tree_sha,
                "--",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped());
        git_command_capped(OP, command, MAX_PATH_BYTES).await
    }
    .await;
    let _ = tokio::fs::remove_file(&index).await;
    let _ = tokio::fs::remove_file(index.with_extension("index.lock")).await;
    let changes = result?;
    if changes.truncated || !changes.raw.is_empty() {
        return Err(rejected(
            "a check modified the audit snapshot's tracked source",
        ));
    }
    Ok(())
}

async fn tracked_paths(repo: &Path, tree: &str) -> Result<Vec<String>, GitError> {
    let out = git_stdout_capped(OP, repo, ["ls-tree", "-rz", tree, "--"], MAX_PATH_BYTES).await?;
    if out.truncated || out.raw.len() > MAX_PATH_BYTES {
        return Err(rejected("audit tracked paths exceed their bound"));
    }
    let text = String::from_utf8(out.raw).map_err(|_| rejected("audit paths must be UTF-8"))?;
    let mut paths = Vec::new();
    for entry in text.split('\0').filter(|s| !s.is_empty()) {
        let (header, path) = entry
            .split_once('\t')
            .ok_or_else(|| rejected("invalid tree entry"))?;
        if header.starts_with("160000 ") {
            return Err(rejected(
                "audit snapshots do not support submodules or embedded repositories",
            ));
        }
        if !["100644 blob ", "100755 blob ", "120000 blob "]
            .iter()
            .any(|mode| header.starts_with(mode))
        {
            return Err(rejected("unsupported audit tree entry"));
        }
        paths.push(path.to_string());
    }
    if paths.len() > MAX_FILES {
        return Err(rejected("audit tracked files exceed their bound"));
    }
    Ok(paths)
}

/// Hash raw checkout bytes/types/modes, not Git-cleaned blobs. Clean filters, EOL conversion,
/// filemode=false and index hints cannot hide changes to what the check actually read.
async fn source_hash(snapshot: &Snapshot) -> Result<String, GitError> {
    let operation = async {
        let paths = read_manifest(snapshot).await?;
        let root = snapshot
            .worktree
            .canonicalize()
            .map_err(|source| GitError::Io { op: OP, source })?;
        let dir = open_root_dir(&root).map_err(|source| GitError::Io { op: OP, source })?;
        let mut hash = Sha256::new();
        let mut remaining = MAX_SOURCE_BYTES;
        let mut buffer = vec![0_u8; 64 * 1024];
        // The worktree's .git pointer is part of its identity, even though Git does not track it.
        for path in paths.iter().map(String::as_str).chain([".git"]) {
            hash.update((path.len() as u64).to_le_bytes());
            hash.update(path.as_bytes());
            match open_under_root(dir.as_fd(), path) {
                Ok(file) => {
                    let meta = file
                        .metadata()
                        .map_err(|source| GitError::Io { op: OP, source })?;
                    hash.update(b"file");
                    hash.update((meta.permissions().mode() & 0o777).to_le_bytes());
                    hash.update(meta.len().to_le_bytes());
                    let mut reader = tokio::fs::File::from_std(file).take(remaining + 1);
                    loop {
                        let size = reader
                            .read(&mut buffer)
                            .await
                            .map_err(|source| GitError::Io { op: OP, source })?;
                        if size == 0 {
                            break;
                        }
                        remaining = remaining
                            .checked_sub(size as u64)
                            .ok_or_else(|| rejected("audit tracked source exceeds 256 MiB"))?;
                        hash.update(&buffer[..size]);
                    }
                }
                Err(_) => {
                    let target = link_under_root(dir.as_fd(), path)
                        .map_err(|source| GitError::Io { op: OP, source })?;
                    hash.update(b"link");
                    hash.update((target.len() as u64).to_le_bytes());
                    hash.update(target);
                }
            }
        }
        Ok(format!("{:x}", hash.finalize()))
    };
    tokio::time::timeout(GIT_OP_TIMEOUT, operation)
        .await
        .map_err(|_| GitError::Timeout {
            op: OP,
            secs: GIT_OP_TIMEOUT.as_secs(),
        })?
}

async fn read_manifest(snapshot: &Snapshot) -> Result<Vec<String>, GitError> {
    let root = snapshot
        .manifest_path
        .parent()
        .ok_or_else(|| rejected("missing manifest directory"))?
        .canonicalize()
        .map_err(|source| GitError::Io { op: OP, source })?;
    let name = snapshot
        .manifest_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| rejected("invalid manifest name"))?;
    let dir = open_root_dir(&root).map_err(|source| GitError::Io { op: OP, source })?;
    let file =
        open_under_root(dir.as_fd(), name).map_err(|source| GitError::Io { op: OP, source })?;
    let (bytes, truncated) = read_capped(file, MAX_MANIFEST_BYTES)
        .await
        .map_err(|source| GitError::Io { op: OP, source })?;
    if truncated || format!("{:x}", Sha256::digest(&bytes)) != snapshot.manifest_hash {
        return Err(rejected(
            "audit tracked-file manifest changed or exceeds its bound",
        ));
    }
    let paths: Vec<String> =
        serde_json::from_slice(&bytes).map_err(|error| rejected(error.to_string()))?;
    if paths.len() > MAX_FILES || paths.iter().map(String::len).sum::<usize>() > MAX_PATH_BYTES {
        return Err(rejected(
            "audit tracked-file manifest exceeds its path bounds",
        ));
    }
    Ok(paths)
}

/// Read a link target by descriptor without traversing any symlinked parent or opening its target.
fn link_under_root(root: BorrowedFd<'_>, path: &str) -> std::io::Result<Vec<u8>> {
    let parts: Vec<_> = Path::new(path).components().collect();
    let mut parent: Option<OwnedFd> = None;
    for (i, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            return Err(std::io::Error::other("invalid snapshot path"));
        };
        let name = CString::new(name.as_bytes()).map_err(std::io::Error::other)?;
        let fd = parent.as_ref().map_or(root.as_raw_fd(), AsRawFd::as_raw_fd);
        if i + 1 == parts.len() {
            let mut bytes = vec![0_u8; 4097];
            // SAFETY: the directory fd and C name remain live; bytes is writable for its length.
            let size = unsafe {
                libc::readlinkat(fd, name.as_ptr(), bytes.as_mut_ptr().cast(), bytes.len())
            };
            if size < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if size as usize == bytes.len() {
                return Err(std::io::Error::other("link target exceeds bound"));
            }
            bytes.truncate(size as usize);
            return Ok(bytes);
        }
        // SAFETY: fd/name remain live. Every parent must be a directory, never a symlink.
        let next = unsafe {
            libc::openat(
                fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: next is a new successful openat descriptor, owned exactly once here.
        parent = Some(unsafe { OwnedFd::from_raw_fd(next) });
    }
    Err(std::io::Error::other("empty snapshot path"))
}
